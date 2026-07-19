//! MCP method dispatch and the three tools.
//!
//! The server is a single-threaded read-dispatch-write loop over stdin/stdout. Single-threaded
//! on purpose: the span map is the most sensitive structure in the product, and the cheapest
//! way to reason about who can reach it is for the answer to be "one thread, one owner, no
//! sharing". Concurrency in an MCP server is the client's business -- it multiplexes requests
//! and it may hold many sessions open at once, which is why the isolation between sessions is
//! tested even though the loop is serial.

use std::io::{BufRead, Write};
use std::time::Duration;

use serde_json::{json, Value};

use deid_tr_core::surrogate::SALT_LEN;
use deid_tr_core::{EntityLabel, Pipeline, Salt, SurrogateEngine, Tier};

use crate::error::{ArgumentName, GatewayError, Result};
use crate::jsonrpc::{self, Request};
use crate::session::{SessionStore, DEFAULT_MAX_SESSIONS, DEFAULT_TTL_SECONDS};
use crate::surrogate;
use crate::telemetry::{Event, Telemetry};
use crate::{PROTOCOL_VERSION, SERVER_NAME, VERSION};

/// The default ceiling on a single document, in bytes.
///
/// A span map is resident for the whole session lifetime, so document size is the multiplier on
/// how much PHI sits in memory. One megabyte is far larger than any clinical note and small
/// enough that a hostile or looping client cannot pin hundreds of megabytes of identifiers.
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// How the gateway was configured.
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// The assurance tier the pipeline runs at.
    pub tier: Tier,
    /// The session retention window.
    pub ttl: Duration,
    /// The ceiling on concurrently live sessions.
    pub max_sessions: usize,
    /// The ceiling on one document.
    pub max_document_bytes: usize,
    /// `--no-medical-allowlist`: run L4 with an EMPTY class C vocabulary.
    ///
    /// An opt-OUT, defaulting to `false`, and named for what it costs:
    /// `carcinoma`, `costa` and `Adalat` are masked whenever a detector
    /// proposes them, so the model on the other side of the gateway is asked to
    /// reason about a note whose clinical vocabulary has been redacted. This
    /// was the UNCONDITIONAL behaviour of every build before the vocabulary was
    /// wired in, because `Pipeline::new` used to install nothing.
    pub no_medical_allowlist: bool,
    /// `--placeholder-labels`: run without L5.
    ///
    /// See the module header of `surrogate.rs` for why the gateway re-renders
    /// the pipeline's output with its own reversible tokens either way. L5 is
    /// installed by default nonetheless, because "the safe configuration is the
    /// one you get by default" must hold in every binding without exception --
    /// a binding that is the exception is the binding whose wiring is forgotten
    /// when the tool that consumes the raw pipeline output is added.
    pub placeholder_labels: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tier: Tier::SafeHarbor,
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            no_medical_allowlist: false,
            placeholder_labels: false,
        }
    }
}

/// The gateway.
pub struct Server {
    config: ServerConfig,
    pipeline: Pipeline,
    sessions: SessionStore,
    log: Telemetry,
}

impl Server {
    /// Build a gateway.
    ///
    /// # Errors
    ///
    /// [`GatewayError::EntropyUnavailable`] when the operating system will not
    /// produce key material for the L5 salt. FATAL RATHER THAN A SILENT
    /// DEGRADATION: a gateway that quietly dropped L5 would still answer, and
    /// the operator would find out by reading output rather than by being told.
    /// There is no honest fallback either, because a salt derived from a clock
    /// is a salt an attacker can reconstruct.
    pub fn new(config: ServerConfig, log: Telemetry) -> Result<Self> {
        let mut pipeline = Pipeline::new(config.tier);
        if config.no_medical_allowlist {
            pipeline = pipeline.without_medical_allowlist();
        }
        if !config.placeholder_labels {
            let mut key = [0u8; SALT_LEN];
            getrandom::fill(&mut key).map_err(|_| GatewayError::EntropyUnavailable)?;
            // One salt for the process, which is `SaltScope::Document`'s
            // guarantee applied at the granularity this binary actually has:
            // the span map is per session and never leaves, and a salt that
            // outlived the process would make two sessions' surrogates
            // linkable by anyone who saw both.
            pipeline = pipeline.with_surrogates(SurrogateEngine::new(Salt::from_bytes(key)));
        }
        Ok(Self {
            pipeline,
            sessions: SessionStore::new(config.ttl, config.max_sessions),
            config,
            log,
        })
    }

    /// The configured pipeline.
    ///
    /// Exposed so a test can assert what the SHIPPED gateway was built with.
    /// The gateway re-renders masked spans with its own reversible tokens, so
    /// whether L4 held a vocabulary is not visible in the tool output for a
    /// span that was masked -- only for one that was KEPT. This getter is how
    /// the other half is checkable.
    #[must_use]
    pub const fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    /// Read newline-delimited JSON-RPC from `reader`, write responses to `writer`.
    ///
    /// Returns when the peer closes stdin. Every session is destroyed on the way out, so a
    /// clean shutdown leaves no span map behind even for the moment between the last request
    /// and process exit.
    pub fn run(&mut self, reader: impl BufRead, writer: &mut impl Write) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle(&line) {
                writeln!(writer, "{response}")?;
                writer.flush()?;
            }
        }
        let destroyed = self.sessions.clear();
        self.log
            .emit(&Event::new("shutdown").count("sessions_destroyed", destroyed));
        Ok(())
    }

    /// Handle one transport line. `None` for a notification.
    #[must_use]
    pub fn handle(&mut self, line: &str) -> Option<String> {
        let request = match jsonrpc::parse(line) {
            Ok(request) => request,
            Err(error) => {
                self.log
                    .emit(&Event::new("reject").tag("reason", "malformed_request"));
                // A malformed envelope has no id to answer, so JSON-RPC says reply with a null
                // one rather than staying silent -- silence looks like a hang to the client.
                return Some(jsonrpc::failure(&Value::Null, &error).to_string());
            }
        };
        if request.is_notification() {
            return None;
        }
        let id = request.id.clone().unwrap_or(Value::Null);
        let response = match self.dispatch(&request) {
            Ok(result) => jsonrpc::success(&id, result),
            Err(error) => jsonrpc::failure(&id, &error),
        };
        Some(response.to_string())
    }

    fn dispatch(&mut self, request: &Request) -> Result<Value> {
        match request.method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": SERVER_NAME, "version": VERSION },
                "instructions": INSTRUCTIONS,
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tool_schemas() })),
            "tools/call" => self.call_tool(request),
            _ => Err(GatewayError::UnknownMethod),
        }
    }

    fn call_tool(&mut self, request: &Request) -> Result<Value> {
        let name = request
            .string_arg("name", ArgumentName::ToolName)?
            .to_owned();
        let arguments = request
            .params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let call = Request {
            id: None,
            method: name.clone(),
            params: arguments,
        };
        let outcome = match name.as_str() {
            "deidentify" => self.deidentify(&call),
            "reidentify" => self.reidentify(&call),
            "forget" => self.forget(&call),
            "health" => self.health(),
            _ => return Err(GatewayError::UnknownMethod),
        };
        match outcome {
            Ok(payload) => Ok(tool_result(&payload, false)),
            // MCP wants a TOOL failure reported inside a successful result with `isError`, so a
            // model can see and react to it. The payload is the same closed vocabulary the
            // JSON-RPC error would have carried -- in particular `session_not_found` is emitted
            // identically whether the handle expired or never existed.
            Err(error) => Ok(tool_result(
                &json!({ "error": error_slug(&error), "message": error.to_string() }),
                true,
            )),
        }
    }

    fn deidentify(&mut self, call: &Request) -> Result<Value> {
        let source = call.string_arg("text", ArgumentName::Body)?;
        if source.len() > self.config.max_document_bytes {
            return Err(GatewayError::DocumentTooLarge {
                request_len: source.len(),
                limit: self.config.max_document_bytes,
            });
        }
        let result = self.pipeline.deidentify(source)?;
        let masked = surrogate::mint(source, &result)?;

        let histogram = histogram(masked.entries.iter().map(|entry| entry.label));
        let spans: Vec<Value> = masked
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "label": entry.label.as_str(),
                    "start": entry.start,
                    "end": entry.end,
                    "placeholder": entry.placeholder,
                })
            })
            .collect();
        let masked_len = masked.body.len();
        let span_count = masked.entries.len();
        let handle = self.sessions.insert(masked.entries)?;
        let sequence = self.sessions.get(&handle)?.sequence();

        self.log.emit(
            &Event::new("deidentify")
                .tag("tier", tier_slug(self.config.tier))
                .sequence(sequence)
                .count("source_bytes", source.len())
                .count("masked_bytes", masked_len)
                .count("masked_spans", span_count)
                .labels(&histogram),
        );

        Ok(json!({
            "session": handle,
            "text": masked.body,
            "masked_spans": span_count,
            "spans": spans,
            "tier": tier_slug(self.config.tier),
            "expires_in_seconds": self.config.ttl.as_secs(),
        }))
    }

    fn reidentify(&mut self, call: &Request) -> Result<Value> {
        let body = call.string_arg("text", ArgumentName::Body)?;
        let handle = call.string_arg("session", ArgumentName::Session)?;
        let session = self.sessions.get(handle)?;
        let sequence = session.sequence();
        let available = session.len();
        let restored = surrogate::restore(body, session.entries());

        self.log.emit(
            &Event::new("reidentify")
                .sequence(sequence)
                .count("response_bytes", body.len())
                .count("substitutions", restored.substitutions)
                .count("entities_available", available)
                .count("entities_seen", restored.entities_seen),
        );

        Ok(json!({
            "text": restored.body,
            "substitutions": restored.substitutions,
            "entities_available": available,
            "entities_restored": restored.entities_seen,
        }))
    }

    fn forget(&mut self, call: &Request) -> Result<Value> {
        let handle = call.string_arg("session", ArgumentName::Session)?;
        let destroyed = self.sessions.forget(handle)?;
        self.log
            .emit(&Event::new("forget").count("entities_destroyed", destroyed));
        Ok(json!({ "forgotten": true, "entities_destroyed": destroyed }))
    }

    fn health(&mut self) -> Result<Value> {
        let live = self.sessions.live();
        Ok(json!({
            "name": SERVER_NAME,
            "version": VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "tier": tier_slug(self.config.tier),
            // The transport is reported so an operator can confirm from the outside that
            // nothing is listening on a socket (I3). There is no address field because there
            // is no address.
            "transport": "stdio",
            "listening": false,
            "layers": self.layer_status(),
            // The loaded detector count IS the model inventory: an ensemble member is a loaded
            // model. Reported as an empty list rather than omitted when there are none,
            // because "no models" is the honest answer and a missing field reads as unknown.
            "models_loaded": self.loaded_models(),
            "sessions": {
                "live": live,
                "max": self.sessions.max_sessions(),
                "ttl_seconds": self.sessions.ttl().as_secs(),
                "storage": "memory-only",
            },
            "max_document_bytes": self.config.max_document_bytes,
        }))
    }
}

impl Server {
    /// Which layers actually run, READ FROM THE PIPELINE rather than hardcoded.
    ///
    /// An operator calling `health` is deciding whether to trust this process with a note, so
    /// the answer has to describe the process they are talking to. A hardcoded list is a claim
    /// about the code as it stood when someone last edited this function: it said "L2 is a stub,
    /// milestone M3" for as long as that was true and would have gone on saying it after L2
    /// landed, telling an operator that names were unmasked when they were masked -- or, far
    /// worse in the other direction, the reverse. Every `live` below is derived from what is
    /// actually installed.
    fn layer_status(&self) -> Value {
        let detectors = self.pipeline.ensemble().len();
        json!([
            { "id": "L1", "name": "rules", "live": true },
            {
                "id": "L2",
                "name": "ner-ensemble",
                // No detector registered means the ensemble contributes nothing, so NAMES ARE
                // NOT MASKED. That is the single most consequential fact in this response.
                "live": detectors > 0,
                "detectors": detectors,
            },
            {
                "id": "L3",
                "name": "contextual-sweep",
                "live": self.config.tier == Tier::ExpertDetermination,
                "enabled_by_tier": self.config.tier == Tier::ExpertDetermination,
            },
            { "id": "L4", "name": "router-adjudication", "live": true },
            // L5 exists in core and is deliberately NOT installed here. Its surrogates are
            // format-preserving, which is right for producing a de-identified corpus and wrong
            // for a round trip: restoring means searching a model's free-text answer for the
            // surrogate, and a plausible-looking fake name cannot be searched for safely. The
            // gateway mints unmistakable bracketed tokens instead. See surrogate.rs.
            {
                "id": "L5",
                "name": "surrogates",
                "live": self.pipeline.surrogate().is_some(),
                "note": "not installed: gateway mints reversible bracketed tokens for the round trip",
            },
        ])
    }

    /// The loaded model inventory. An ensemble member is a loaded model.
    fn loaded_models(&self) -> Value {
        let detectors = self.pipeline.ensemble().len();
        json!((0..detectors)
            .map(|index| json!({ "layer": "L2", "slot": index }))
            .collect::<Vec<_>>())
    }
}

/// A stable machine-readable slug for each failure, so a client never string-matches a message.
const fn error_slug(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::SessionNotFound => "session_not_found",
        GatewayError::MalformedRequest { .. } => "malformed_request",
        GatewayError::BadArgument { .. } => "bad_argument",
        GatewayError::UnknownMethod => "unknown_tool",
        GatewayError::DocumentTooLarge { .. } => "document_too_large",
        GatewayError::SessionStoreFull { .. } => "session_store_full",
        GatewayError::SurrogateCollision { .. } => "surrogate_collision",
        GatewayError::EntropyUnavailable => "entropy_unavailable",
        GatewayError::Core(_) => "pipeline_error",
    }
}

const fn tier_slug(tier: Tier) -> &'static str {
    match tier {
        Tier::SafeHarbor => "safe_harbor",
        Tier::ExpertDetermination => "expert_determination",
    }
}

/// Parse the tier argument. Unknown values are refused rather than defaulted.
///
/// Defaulting would be the dangerous direction: a caller who asked for Expert Determination and
/// typoed it would silently receive a Safe Harbor run and believe quasi-identifiers were swept.
pub fn parse_tier(value: &str) -> Result<Tier> {
    match value {
        "safe_harbor" | "safe-harbor" => Ok(Tier::SafeHarbor),
        "expert_determination" | "expert-determination" | "expert" => Ok(Tier::ExpertDetermination),
        _ => Err(GatewayError::BadArgument {
            argument: ArgumentName::Tier,
        }),
    }
}

/// Count labels without retaining anything the labels describe.
fn histogram(labels: impl Iterator<Item = EntityLabel>) -> Vec<(EntityLabel, usize)> {
    let mut counts: Vec<(EntityLabel, usize)> = Vec::new();
    for label in labels {
        match counts.iter_mut().find(|(seen, _)| *seen == label) {
            Some((_, count)) => *count += 1,
            None => counts.push((label, 1)),
        }
    }
    counts
}

/// Wrap a payload in the MCP tool-result shape.
fn tool_result(payload: &Value, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": payload.to_string() }],
        "structuredContent": payload,
        "isError": is_error,
    })
}

/// Guidance handed to the model at `initialize`.
const INSTRUCTIONS: &str = "\
Call deidentify before sending Turkish clinical text to any model outside this machine. \
It returns masked text and a session handle. Send only the masked text onward. When the \
model answers, pass its reply and the same session handle to reidentify to restore the real \
identifiers locally. Placeholders look like [PATIENT_NAME_4f1a2b7c_1]; keep them verbatim in \
any prompt so they can be restored. Session handles are credentials for a table of real \
patient identifiers: never write one into a prompt, a file, or a message to another service.";

/// The tool declarations returned by `tools/list`.
fn tool_schemas() -> Vec<Value> {
    vec![
        json!({
            "name": "deidentify",
            "title": "De-identify Turkish clinical text",
            "description": "Mask PHI in Turkish clinical text and open a session holding the \
                             span map needed to restore it. Returns masked text plus a session \
                             handle. The span map stays in memory on this machine.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "The clinical text to mask." },
                },
                "required": ["text"],
            },
        }),
        json!({
            "name": "reidentify",
            "title": "Restore identifiers in a model response",
            "description": "Replace placeholders in a model response with the real identifiers \
                             they stand for, using the span map held under the given session \
                             handle. Fails if the session has expired.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "The model response to restore." },
                    "session": { "type": "string", "description": "Handle from deidentify." },
                },
                "required": ["text", "session"],
            },
        }),
        json!({
            "name": "forget",
            "title": "Destroy a session now",
            "description": "Destroy a span map before its deadline, zeroising it. Call this as \
                             soon as a round trip is finished.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Handle from deidentify." },
                },
                "required": ["session"],
            },
        }),
        json!({
            "name": "health",
            "title": "Server status",
            "description": "Version, assurance tier, which pipeline layers are live, which \
                             models are loaded, the transport in use, and the session \
                             retention policy.",
            "inputSchema": { "type": "object", "properties": {} },
        }),
    ]
}
