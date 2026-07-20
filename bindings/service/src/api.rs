//! The endpoints, and the pipeline behind them.
//!
//! # Route table
//!
//! ```text
//! POST /analyze      detected entities: label, byte offsets, confidence, decision
//! POST /deidentify   masked text + span map + session handle
//! POST /reidentify   the original document, from a session handle
//! POST /batch        many documents, one result per document, never fewer
//! GET  /health       version, tier, which layers are live, which models are loaded
//! GET  /entities     the entity catalog from eval/schema.yaml
//! ```
//!
//! # What a response deliberately does not contain
//!
//! `/analyze` returns offsets and labels and NOT the covered text. The caller
//! already holds the document, so the surface adds nothing they cannot slice for
//! themselves -- and omitting it means an `/analyze` response is metadata rather
//! than PHI, so it can be cached, diffed and pasted into a ticket. The incumbent
//! returns the entity text; this is a deliberate divergence and the reason is
//! this paragraph.
//!
//! `/deidentify` returns the masked document and the surrogate that replaced
//! each span. It does NOT return the originals: those live only in the session
//! store, behind a handle, expiring and zeroised.
//!
//! # Offsets
//!
//! Every `start` and `end` in every response is a BYTE offset into the UTF-8
//! request text, and every one lands on a character boundary. Not a character
//! index. Turkish is multi-byte in almost every clinical sentence -- `ş`, `ğ`,
//! `İ` are two bytes each -- so the two numbers diverge constantly, and a client
//! that slices by character index will cut a name in half. The `offsets` field
//! on every response says so, in the payload, because a client author reads the
//! payload.
//!
//! # The tier is a process setting, not a request field
//!
//! Expert Determination adds L3, a full-document sweep by a LOCAL LLM, which
//! needs a host that can run one. That is a deployment decision, so it is
//! `--tier` at startup and is reported by `/health`. Accepting it per request
//! would let a caller ask for a tier the process cannot serve and receive either
//! an error they cannot fix or, far worse, a silent downgrade: an unswept
//! document that looks like a swept one.

use std::time::Duration;

use deid_tr_core::surrogate::SALT_LEN;
use deid_tr_core::{
    Decision, DeidResult, EntityLabel, Layer, Pipeline, Salt, SurrogateEngine, Tier,
};
use serde_json::{json, Map, Value};

use crate::catalog::{self, LiveLayers};
use crate::session::{restorations, SessionError, SessionStore};

/// The running version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The largest number of documents one `/batch` call may carry.
///
/// A ceiling rather than unbounded, for the same reason the body has one: a
/// single request must not be able to make this process allocate without bound.
pub const MAX_BATCH_ITEMS: usize = 256;

/// The sentence attached to every `confidence_threshold` response.
///
/// I2 SAYS RECALL IS THE PRODUCT. A threshold that suppressed spans from MASKING
/// would trade a breach for a tidier report, so this service does not offer that
/// and this string says so rather than leaving a caller to infer it from
/// behaviour they did not test.
pub const THRESHOLD_WARNING: &str = concat!(
    "confidence_threshold filters what is REPORTED and never what is masked. Raising it hides ",
    "low-confidence detections from this response; it does not make the pipeline miss them, and ",
    "it must never be used as a masking control. A missed identifier is a breach and an ",
    "over-masked term is a papercut, so recall wins when they trade (invariant I2)."
);

/// The sentence attached to every response carrying offsets.
pub const OFFSET_NOTE: &str =
    "start/end are BYTE offsets into the UTF-8 request text, on character boundaries. \
     Not character indices: Turkish is multi-byte, so the two differ in almost every note.";

/// Why a request could not be served.
///
/// CARRIES NO DOCUMENT BYTES (I4). Every variant is a unit variant or holds a
/// count, so there is no field a fragment of a note could travel in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// The body was not JSON.
    #[error("the request body is not valid JSON")]
    NotJson,
    /// A required field is missing or the wrong type.
    #[error("the request is missing a required field, or a field has the wrong type")]
    BadRequest,
    /// `confidence_threshold` was outside the unit interval.
    #[error("confidence_threshold must be a number between 0.0 and 1.0")]
    ThresholdOutOfRange,
    /// `/batch` carried more documents than [`MAX_BATCH_ITEMS`].
    #[error("a batch may carry at most {MAX_BATCH_ITEMS} documents")]
    BatchTooLarge,
    /// No route matched.
    #[error("no such endpoint")]
    NotFound,
    /// The route exists but not for that method.
    #[error("that endpoint does not accept this HTTP method")]
    MethodNotAllowed,
    /// The session handle is expired, released, or was never issued.
    #[error("no such session; it may have expired, been released, or never existed")]
    SessionNotFound,
    /// The session store is at its ceiling.
    #[error("the session store is full; retry after an existing session expires")]
    SessionStoreFull,
    /// The OS entropy source failed.
    #[error("the operating system entropy source is unavailable")]
    EntropyUnavailable,
    /// The pipeline refused the document.
    ///
    /// Deliberately does not wrap `deid_tr_core::Error`: that type is careful
    /// about offsets, but a byte offset in an HTTP response body is a position
    /// inside a clinical note handed to whoever can read the response. The
    /// operator gets the detail on stderr; the caller gets the classification.
    #[error("de-identification failed")]
    PipelineFailed,
}

impl ApiError {
    /// The HTTP status this failure is reported as.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::NotJson | Self::BadRequest | Self::ThresholdOutOfRange => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::BatchTooLarge => 413,
            Self::SessionNotFound => 404,
            Self::SessionStoreFull => 429,
            Self::EntropyUnavailable | Self::PipelineFailed => 500,
        }
    }

    /// A stable machine-readable code, from a closed vocabulary.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotJson => "not_json",
            Self::BadRequest => "bad_request",
            Self::ThresholdOutOfRange => "threshold_out_of_range",
            Self::BatchTooLarge => "batch_too_large",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::SessionNotFound => "session_not_found",
            Self::SessionStoreFull => "session_store_full",
            Self::EntropyUnavailable => "entropy_unavailable",
            Self::PipelineFailed => "pipeline_failed",
        }
    }

    /// The JSON body for this failure.
    #[must_use]
    pub fn body(self) -> Value {
        json!({ "error": { "code": self.code(), "message": self.to_string() } })
    }
}

impl From<SessionError> for ApiError {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::NotFound => Self::SessionNotFound,
            SessionError::Full => Self::SessionStoreFull,
            SessionError::EntropyUnavailable => Self::EntropyUnavailable,
        }
    }
}

/// How the service was configured at startup.
#[derive(Debug, Clone, Copy)]
pub struct ServiceConfig {
    /// The assurance tier. `SafeHarbor` unless the operator opted in.
    pub tier: Tier,
    /// `--no-medical-allowlist`: run L4 with an EMPTY class C vocabulary, so
    /// `carcinoma`, `costa` and `Adalat` are masked whenever a detector proposes
    /// them and the note stops saying what it said. An opt-OUT, defaulting to
    /// false.
    pub no_medical_allowlist: bool,
    /// `--placeholder-labels`: skip L5 and write `[PATIENT_NAME]` instead of a
    /// surrogate. Every patient in the note collapses onto one token. An
    /// opt-OUT, defaulting to false.
    pub placeholder_labels: bool,
    /// The session retention window.
    pub ttl: Duration,
    /// The ceiling on concurrently live sessions.
    pub max_sessions: usize,
    /// Whether a bearer token is enforced on every request.
    pub auth_required: bool,
    /// Whether the listener is reachable from beyond this machine.
    pub exposed: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            tier: Tier::SafeHarbor,
            no_medical_allowlist: false,
            placeholder_labels: false,
            ttl: Duration::from_secs(crate::session::DEFAULT_TTL_SECONDS),
            max_sessions: crate::session::DEFAULT_MAX_SESSIONS,
            auth_required: false,
            exposed: false,
        }
    }
}

/// The pipeline, the session store, and the routing.
pub struct Service {
    pipeline: Pipeline,
    sessions: SessionStore,
    config: ServiceConfig,
}

/// What one handled request produced.
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body.
    pub body: Value,
    /// The route that matched, from a CLOSED vocabulary, for the log.
    ///
    /// `&'static str` so an unrouted request logs `unmatched` and the URL it
    /// asked for is never written down.
    pub route: &'static str,
    /// The session correlation number, when a session was touched. Never the
    /// handle.
    pub sequence: Option<u64>,
    /// Masked-span counts by label, for the log. Metadata, never text.
    pub labels: Vec<(EntityLabel, usize)>,
}

impl Service {
    /// Build the service the operator asked for.
    ///
    /// THE DEFAULT PATH IS THE SAFE ONE: `Pipeline::new` carries the audited
    /// class C medical vocabulary, and L5 is installed here from a per-process
    /// salt drawn from the operating system. Both degradations are opt-outs
    /// named for what they cost.
    ///
    /// # Errors
    ///
    /// [`ApiError::EntropyUnavailable`] when the OS will not produce a salt.
    /// FATAL RATHER THAN A DEGRADATION to label placeholders: a run that
    /// silently drops L5 produces output the operator has to read to discover,
    /// and there is no honest fallback, because a salt derived from a clock is a
    /// salt an attacker can reconstruct.
    pub fn new(config: ServiceConfig) -> Result<Self, ApiError> {
        let mut pipeline = Pipeline::new(config.tier);
        if config.no_medical_allowlist {
            pipeline = pipeline.without_medical_allowlist();
        }
        if !config.placeholder_labels {
            let mut key = [0u8; SALT_LEN];
            getrandom::fill(&mut key).map_err(|_| ApiError::EntropyUnavailable)?;
            // ONE SALT FOR THE PROCESS, not one per request. Within a process,
            // the same identifier gets the same surrogate across documents,
            // which is what makes a batch of one patient's notes internally
            // consistent. Across processes it does not, so two runs are not
            // linkable. A caller who needs longitudinal linkage across restarts
            // needs a salt that outlives the process, and that is a key
            // management decision this binary must not make on their behalf.
            pipeline = pipeline.with_surrogates(SurrogateEngine::new(Salt::from_bytes(key)));
        }
        Ok(Self {
            pipeline,
            sessions: SessionStore::new(config.ttl, config.max_sessions),
            config,
        })
    }

    /// Which layers this process actually has.
    ///
    /// Read from the pipeline rather than from the configuration, so `/health`
    /// and `/entities` report what is installed rather than what was asked for.
    #[must_use]
    pub fn live_layers(&self) -> LiveLayers {
        LiveLayers {
            rules: true,
            ner: !self.pipeline.ensemble().is_empty(),
            context: self.config.tier == Tier::ExpertDetermination,
        }
    }

    /// Release every session. Called at shutdown.
    pub fn shutdown(&mut self) -> usize {
        self.sessions.clear()
    }

    /// Dispatch one request.
    pub fn handle(&mut self, method: &str, path: &str, body: &str) -> Reply {
        let (route, result) = match (method, path) {
            ("GET", "/health") => ("/health", Ok(self.health())),
            ("GET", "/entities") => ("/entities", Ok(catalog::body(self.live_layers()))),
            ("POST", "/analyze") => ("/analyze", self.analyze(body).map(|(v, _)| v)),
            ("POST", "/deidentify") => ("/deidentify", self.deidentify(body)),
            ("POST", "/reidentify") => ("/reidentify", self.reidentify(body)),
            ("POST", "/batch") => ("/batch", self.batch(body)),
            // A known route with the wrong method is distinguished from an
            // unknown one, because 405 tells a client author what to fix and 404
            // sends them looking for a typo in a path that was correct.
            (
                _,
                "/health" | "/entities" | "/analyze" | "/deidentify" | "/reidentify" | "/batch",
            ) => ("unmatched", Err(ApiError::MethodNotAllowed)),
            _ => ("unmatched", Err(ApiError::NotFound)),
        };

        // The label histogram and the sequence number are re-derived from the
        // response body rather than threaded through every handler, so a new
        // handler cannot forget to report them and cannot report anything the
        // response does not already contain.
        match result {
            Ok(body) => Reply {
                status: 200,
                labels: label_histogram(&body),
                sequence: body
                    .get("session_sequence")
                    .and_then(serde_json::Value::as_u64),
                route,
                body,
            },
            Err(error) => Reply {
                status: error.status(),
                body: error.body(),
                route,
                sequence: None,
                labels: Vec::new(),
            },
        }
    }

    /// `GET /health`.
    fn health(&mut self) -> Value {
        let layers = self.live_layers();
        json!({
            "status": "ok",
            "name": "deid-tr",
            "service": "deid-serve",
            "version": VERSION,
            "schema_version": catalog::schema_version(),
            "tier": tier_name(self.config.tier),
            // WHICH LAYERS ARE LIVE, stated per layer with the consequence of an
            // absent one. An operator reading `"ner": false` needs to be told
            // what that costs in the same breath, or they will read it as an
            // implementation detail.
            "layers": {
                "l1_rules":      { "live": layers.rules,   "detail": "deterministic regex plus checksum: TCKN, VKN, SGK, IBAN, phone, MRN, email, dates" },
                "l2_ner":        { "live": layers.ner,     "detail": "NO TRAINED MODEL IS LOADED. deid-tr therefore masks ZERO names: PATIENT_NAME, CLINICIAN_NAME and RELATIVE_NAME are never detected by this build." },
                "l3_contextual": { "live": layers.context, "detail": "tier-gated full-document sweep by a LOCAL LLM; requires --tier expert AND an installed local model" },
                "l4_router":     { "live": true,           "detail": "confidence router plus allowlist adjudication; may only demote, never invent" },
                "l5_surrogates": { "live": !self.config.placeholder_labels, "detail": "format-preserving, document-consistent surrogates keyed by a per-process salt" },
            },
            // Empty, and it is a list rather than a boolean so that it stays the
            // same shape once weights exist. There is no lazy download path: a
            // model is bundled or fetched by an explicit `deid pull`, never
            // acquired at inference time (I1).
            "models_loaded": Vec::<String>::new(),
            "medical_allowlist": !self.config.no_medical_allowlist,
            "sessions": {
                "live": self.sessions.live(),
                "max": self.sessions.max_sessions(),
                "ttl_seconds": self.sessions.ttl().as_secs(),
                "storage": "memory only; never written to disk, never logged, zeroised on expiry",
            },
            "bind": {
                "exposed": self.config.exposed,
                "auth_required": self.config.auth_required,
                "detail": "loopback by default; a non-loopback bind requires --expose AND a bearer token AND a startup warning, and an all-interfaces address is refused unconditionally",
            },
            "honesty_note": "Coverage today is RULE-DETECTABLE IDENTIFIERS ONLY. See GET /entities for the per-label breakdown.",
        })
    }

    /// `POST /analyze`.
    ///
    /// Returns the body and the count of masked spans, the latter so `/batch`
    /// can summarise without re-walking the JSON.
    fn analyze(&mut self, body: &str) -> Result<(Value, usize), ApiError> {
        let request = parse_object(body)?;
        let source = required_str(&request, "text")?;
        let threshold = optional_threshold(&request)?;
        let result = self
            .pipeline
            .deidentify(source)
            .map_err(|_| ApiError::PipelineFailed)?;

        let mut entities = Vec::new();
        let mut withheld = 0usize;
        for mapped in &result.span_map {
            if threshold.is_some_and(|floor| mapped.span.confidence() < floor) {
                withheld += 1;
                continue;
            }
            entities.push(json!({
                "label": mapped.span.label().as_str(),
                "start": mapped.span.start(),
                "end": mapped.span.end(),
                "confidence": mapped.span.confidence(),
                "layer": layer_name(mapped.span.source()),
                "checksum_validated": mapped.span.is_checksum_validated(),
                "decision": decision_name(mapped.decision),
                "rationale": format!("{:?}", mapped.rationale),
            }));
        }
        let masked = result
            .span_map
            .iter()
            .filter(|mapped| mapped.decision == Decision::Mask)
            .count();

        let mut payload = Map::new();
        payload.insert("count".to_owned(), json!(result.span_map.len()));
        payload.insert("reported".to_owned(), json!(entities.len()));
        payload.insert("withheld_by_threshold".to_owned(), json!(withheld));
        payload.insert("masked".to_owned(), json!(masked));
        payload.insert("entities".to_owned(), Value::Array(entities));
        payload.insert("routing".to_owned(), routing(&result));
        payload.insert("offsets".to_owned(), json!(OFFSET_NOTE));
        // The surface text is absent on purpose; see the module header.
        payload.insert(
            "entity_text".to_owned(),
            json!("omitted deliberately: the caller already holds the document, so returning the covered text would make this response PHI for no gain. Slice it with the byte offsets above."),
        );
        if threshold.is_some() {
            payload.insert("confidence_threshold".to_owned(), json!(threshold));
            payload.insert("threshold_warning".to_owned(), json!(THRESHOLD_WARNING));
        }
        Ok((Value::Object(payload), masked))
    }

    /// `POST /deidentify`.
    fn deidentify(&mut self, body: &str) -> Result<Value, ApiError> {
        let request = parse_object(body)?;
        let source = required_str(&request, "text")?;
        let result = self
            .pipeline
            .deidentify(source)
            .map_err(|_| ApiError::PipelineFailed)?;
        self.store_and_render(result)
    }

    /// Store a result under a fresh handle and render the response.
    fn store_and_render(&mut self, result: DeidResult) -> Result<Value, ApiError> {
        let spans: Vec<Value> = result
            .span_map
            .iter()
            .map(|mapped| {
                json!({
                    "label": mapped.span.label().as_str(),
                    "start": mapped.span.start(),
                    "end": mapped.span.end(),
                    "output_start": mapped.output_start,
                    "output_end": mapped.output_end,
                    "confidence": mapped.span.confidence(),
                    "layer": layer_name(mapped.span.source()),
                    "checksum_validated": mapped.span.is_checksum_validated(),
                    "decision": decision_name(mapped.decision),
                    "rationale": format!("{:?}", mapped.rationale),
                    // The surrogate, which is not PHI. The ORIGINAL is not here
                    // and is not returned by any endpoint: it lives in the
                    // session store, behind the handle, and comes back only
                    // through /reidentify.
                    "replacement": mapped.replacement,
                })
            })
            .collect();
        let masked = result
            .span_map
            .iter()
            .filter(|mapped| mapped.decision == Decision::Mask)
            .count();
        let kept = result.span_map.len() - masked;
        let routing = routing(&result);
        let entries = restorations(&result);
        let ttl = self.sessions.ttl().as_secs();
        let handle = self.sessions.insert(result.text.clone(), entries)?;
        let sequence = self.sessions.get(&handle)?.sequence();

        Ok(json!({
            "text": result.text,
            "session": handle,
            "session_sequence": sequence,
            "session_expires_in_seconds": ttl,
            "session_note": "The span map behind this handle is the table from each surrogate back to the real identifier. It is held in memory only, never written to disk, never logged, and zeroised when it expires. Treat the handle as a credential.",
            "masked": masked,
            "kept": kept,
            "spans": spans,
            "routing": routing,
            "offsets": OFFSET_NOTE,
        }))
    }

    /// `POST /reidentify`.
    fn reidentify(&mut self, body: &str) -> Result<Value, ApiError> {
        let request = parse_object(body)?;
        let handle = required_str(&request, "session")?.to_owned();
        // `release` defaults to FALSE: a client whose connection dropped before
        // it read the response must be able to ask again, and the TTL is the
        // backstop that stops a forgotten session living forever.
        let release = request.get("release").map_or(Ok(false), |value| {
            value.as_bool().ok_or(ApiError::BadRequest)
        })?;

        let session = self.sessions.get(&handle)?;
        let sequence = session.sequence();
        let restored = session.restore();
        let entities = session.len();
        let released = if release {
            self.sessions.forget(&handle)?;
            true
        } else {
            false
        };
        Ok(json!({
            "text": restored,
            "session_sequence": sequence,
            "restored_entities": entities,
            "session_released": released,
        }))
    }

    /// `POST /batch`.
    ///
    /// EVERY INPUT DOCUMENT PRODUCES EXACTLY ONE ITEM IN THE RESPONSE, in
    /// request order, whether it succeeded or failed. There is no filtering step
    /// and no early return: a document that is silently absent from a
    /// de-identification result is an unredacted document that someone believes
    /// is redacted.
    fn batch(&mut self, body: &str) -> Result<Value, ApiError> {
        let request = parse_object(body)?;
        let documents = request
            .get("documents")
            .and_then(Value::as_array)
            .ok_or(ApiError::BadRequest)?;
        if documents.len() > MAX_BATCH_ITEMS {
            return Err(ApiError::BatchTooLarge);
        }
        let operation = request
            .get("operation")
            .map_or(Ok("deidentify"), |value| {
                value.as_str().ok_or(ApiError::BadRequest)
            })?
            .to_owned();
        if operation != "analyze" && operation != "deidentify" {
            return Err(ApiError::BadRequest);
        }

        let mut items = Vec::with_capacity(documents.len());
        let mut successful = 0usize;
        let mut failed = 0usize;
        for (index, entry) in documents.iter().enumerate() {
            // The caller's id when they gave one, the index otherwise. NEVER a
            // filename or anything derived from content: an id is echoed back
            // and may be logged by the client.
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .map_or_else(|| index.to_string(), str::to_owned);
            let outcome = entry
                .get("text")
                .and_then(Value::as_str)
                .ok_or(ApiError::BadRequest)
                .and_then(|source| self.run_one(&operation, source));
            match outcome {
                Ok(result) => {
                    successful += 1;
                    items.push(json!({
                        "index": index,
                        "id": id,
                        "success": true,
                        "result": result,
                    }));
                }
                Err(error) => {
                    failed += 1;
                    items.push(json!({
                        "index": index,
                        "id": id,
                        "success": false,
                        "error": { "code": error.code(), "message": error.to_string() },
                    }));
                }
            }
        }

        Ok(json!({
            "operation": operation,
            "total": documents.len(),
            "successful": successful,
            "failed": failed,
            "items": items,
            "completeness_note": "items has exactly one entry per submitted document, in request order, whether it succeeded or failed. A batch never skips a document: a skipped file in a de-identification run is an unredacted document someone believes is redacted.",
        }))
    }

    /// One batch item, dispatched by operation name.
    fn run_one(&mut self, operation: &str, source: &str) -> Result<Value, ApiError> {
        match operation {
            // Re-uses the same rendering as `/analyze` by round-tripping the
            // request shape, so the two can never drift into reporting different
            // fields for the same document.
            "analyze" => self
                .analyze(&json!({ "text": source }).to_string())
                .map(|(value, _)| value),
            _ => {
                let result = self
                    .pipeline
                    .deidentify(source)
                    .map_err(|_| ApiError::PipelineFailed)?;
                self.store_and_render(result)
            }
        }
    }
}

/// The routing statistics, which are counts and therefore safe to return.
fn routing(result: &DeidResult) -> Value {
    let stats = &result.routing;
    json!({
        "total": stats.total,
        "checksum_validated": stats.checksum_validated,
        "detector_agreement": stats.detector_agreement,
        "high_confidence": stats.high_confidence,
        "escalated": stats.escalated,
        "adjudicator_calls": stats.adjudicator_calls,
        "demoted": stats.demoted,
    })
}

/// Count masked spans by label in a rendered response, for the log.
///
/// Reads the response rather than the pipeline result so that whatever a handler
/// reports is what gets logged, and a handler that reports nothing logs nothing.
fn label_histogram(body: &Value) -> Vec<(EntityLabel, usize)> {
    let mut counts: Vec<(EntityLabel, usize)> = Vec::new();
    let spans = body
        .get("spans")
        .or_else(|| body.get("entities"))
        .and_then(Value::as_array);
    for span in spans.into_iter().flatten() {
        if span.get("decision").and_then(Value::as_str) != Some("mask") {
            continue;
        }
        let Some(label) = span
            .get("label")
            .and_then(Value::as_str)
            .and_then(|id| EntityLabel::from_id(id).ok())
        else {
            continue;
        };
        match counts.iter_mut().find(|(seen, _)| *seen == label) {
            Some((_, count)) => *count += 1,
            None => counts.push((label, 1)),
        }
    }
    counts.sort_by_key(|(label, _)| *label);
    counts
}

/// Parse a request body into a JSON object.
fn parse_object(body: &str) -> Result<Map<String, Value>, ApiError> {
    match serde_json::from_str::<Value>(body).map_err(|_| ApiError::NotJson)? {
        Value::Object(map) => Ok(map),
        _ => Err(ApiError::BadRequest),
    }
}

/// A required string field.
fn required_str<'a>(request: &'a Map<String, Value>, key: &str) -> Result<&'a str, ApiError> {
    request
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ApiError::BadRequest)
}

/// The optional `confidence_threshold`, validated into the unit interval.
fn optional_threshold(request: &Map<String, Value>) -> Result<Option<f32>, ApiError> {
    let Some(value) = request.get("confidence_threshold") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let number = value.as_f64().ok_or(ApiError::ThresholdOutOfRange)?;
    if !(0.0..=1.0).contains(&number) {
        return Err(ApiError::ThresholdOutOfRange);
    }
    // A cast rather than a parse: span confidence is f32, and comparing an f64
    // threshold against an f32 confidence would reject a span whose confidence
    // is exactly the threshold about half the time.
    Ok(Some(number as f32))
}

/// The tier, as the closed vocabulary `/health` publishes.
const fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::SafeHarbor => "safe_harbor",
        Tier::ExpertDetermination => "expert_determination",
    }
}

/// The layer that proposed a span.
const fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::Rules => "rules",
        Layer::Ner => "ner",
        Layer::Context => "context",
    }
}

/// What L4 decided.
const fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Mask => "mask",
        Decision::Keep => "keep",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{note, tckn};

    fn service() -> Service {
        Service::new(ServiceConfig::default()).expect("service")
    }

    fn post(service: &mut Service, path: &str, body: Value) -> Reply {
        service.handle("POST", path, &body.to_string())
    }

    #[test]
    fn health_reports_the_tier_the_layers_and_the_bind_posture() {
        let mut service = service();
        let reply = service.handle("GET", "/health", "");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["status"], json!("ok"));
        assert_eq!(reply.body["tier"], json!("safe_harbor"));
        assert_eq!(reply.body["version"], json!(VERSION));
        assert_eq!(reply.body["layers"]["l1_rules"]["live"], json!(true));
        assert_eq!(reply.body["layers"]["l4_router"]["live"], json!(true));
        assert_eq!(reply.body["layers"]["l5_surrogates"]["live"], json!(true));
        assert_eq!(reply.body["models_loaded"], json!([]));
        assert_eq!(reply.body["bind"]["exposed"], json!(false));
        assert_eq!(reply.body["sessions"]["ttl_seconds"], json!(900));
    }

    #[test]
    fn health_says_plainly_that_no_name_is_masked() {
        // THE honesty gate on this endpoint. L2 has no trained model, so the
        // layer must report false AND say what that costs, in the same field an
        // operator is reading.
        let mut service = service();
        let reply = service.handle("GET", "/health", "");
        assert_eq!(reply.body["layers"]["l2_ner"]["live"], json!(false));
        let detail = reply.body["layers"]["l2_ner"]["detail"]
            .as_str()
            .expect("detail");
        assert!(detail.contains("ZERO names"));
        assert!(detail.contains("PATIENT_NAME"));
    }

    #[test]
    fn entities_serves_the_schema_catalog() {
        let mut service = service();
        let reply = service.handle("GET", "/entities", "");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["source"], json!("eval/schema.yaml"));
        let direct = reply.body["direct_identifiers"]
            .as_array()
            .expect("direct identifiers");
        assert_eq!(direct.len(), EntityLabel::DIRECT.len());
        assert!(reply.body["honesty_note"]
            .as_str()
            .expect("note")
            .contains("ZERO names"));
    }

    #[test]
    fn analyze_reports_offsets_labels_and_confidence_but_not_the_covered_text() {
        let mut service = service();
        let source = note();
        let reply = post(&mut service, "/analyze", json!({ "text": source }));
        assert_eq!(reply.status, 200);
        let entities = reply.body["entities"].as_array().expect("entities");
        assert!(
            !entities.is_empty(),
            "L1 found nothing in a note with a TCKN"
        );

        let reported = entities
            .iter()
            .find(|entity| entity["label"] == json!("TCKN"))
            .expect("the TCKN reached the report");
        assert_eq!(reported["layer"], json!("rules"));
        assert_eq!(reported["checksum_validated"], json!(true));
        assert_eq!(reported["decision"], json!("mask"));
        assert_eq!(reported["confidence"], json!(1.0));

        // The byte offsets address the identifier in the ORIGINAL text.
        let start = reported["start"].as_u64().expect("start") as usize;
        let end = reported["end"].as_u64().expect("end") as usize;
        assert_eq!(&source[start..end], tckn());

        // And no entity carries its own surface.
        let rendered = reply.body.to_string();
        assert!(!rendered.contains(&tckn()));
        assert!(!rendered.contains("Ayşe"));
    }

    #[test]
    fn a_confidence_threshold_filters_the_report_and_never_the_masking() {
        // I2: recall is the product. The threshold must be a reporting control
        // only, and the response must say so.
        let mut service = service();
        let source = note();
        let unfiltered = post(&mut service, "/analyze", json!({ "text": source }));
        let filtered = post(
            &mut service,
            "/analyze",
            json!({ "text": source, "confidence_threshold": 1.0 }),
        );
        assert_eq!(
            filtered.body["count"], unfiltered.body["count"],
            "the threshold changed how many spans the pipeline found"
        );
        assert_eq!(
            filtered.body["masked"], unfiltered.body["masked"],
            "the threshold changed how many spans were masked"
        );
        assert!(filtered.body["threshold_warning"]
            .as_str()
            .expect("warning")
            .contains("never what is masked"));

        // And a threshold above every confidence withholds everything from the
        // report while the pipeline still masked the same set.
        let all_out = post(
            &mut service,
            "/analyze",
            json!({ "text": source, "confidence_threshold": 1.0 }),
        );
        let reported = all_out.body["reported"].as_u64().expect("reported");
        let withheld = all_out.body["withheld_by_threshold"]
            .as_u64()
            .expect("withheld");
        assert_eq!(
            reported + withheld,
            all_out.body["count"].as_u64().expect("count")
        );
    }

    #[test]
    fn an_out_of_range_threshold_is_refused() {
        let mut service = service();
        for bad in [json!(1.5), json!(-0.1), json!("high")] {
            let reply = post(
                &mut service,
                "/analyze",
                json!({ "text": "x", "confidence_threshold": bad }),
            );
            assert_eq!(reply.status, 400);
            assert_eq!(reply.body["error"]["code"], json!("threshold_out_of_range"));
        }
    }

    #[test]
    fn deidentify_masks_the_rule_detectable_identifiers_and_issues_a_handle() {
        let mut service = service();
        let source = note();
        let reply = post(&mut service, "/deidentify", json!({ "text": source }));
        assert_eq!(reply.status, 200);
        let masked = reply.body["text"].as_str().expect("masked text");
        assert!(!masked.contains(&tckn()), "the TCKN survived masking");
        assert!(masked.contains("carcinoma'lı"), "a medical term was masked");
        // The honest boundary: L2 has no model, so the name is still there.
        assert!(
            masked.contains("Ayşe Yılmaz"),
            "this build masks no names; if that changed, this test is the place to say so"
        );
        assert!(reply.body["masked"].as_u64().expect("masked") >= 1);
        let handle = reply.body["session"].as_str().expect("handle");
        assert_eq!(handle.len(), 32, "a handle is 128 bits of hex");
        assert_eq!(reply.body["session_expires_in_seconds"], json!(900));
    }

    #[test]
    fn no_response_ever_carries_an_original_identifier() {
        let mut service = service();
        let source = note();
        let reply = post(&mut service, "/deidentify", json!({ "text": source }));
        let spans = reply.body["spans"].as_array().expect("spans");
        for span in spans {
            assert!(span.get("original").is_none());
        }
        // The surrogate is present and is not the original.
        let replacement = spans
            .iter()
            .find(|span| span["label"] == json!("TCKN"))
            .and_then(|span| span["replacement"].as_str())
            .expect("a surrogate for the TCKN");
        assert_ne!(replacement, tckn());
    }

    #[test]
    fn a_round_trip_through_the_service_is_byte_exact() {
        // THE property /reidentify sells, on a document that contains
        // multi-byte Turkish before, between and after every replacement, and a
        // surrogate that is a different length from the identifier it replaced.
        let mut service = service();
        let source = note();
        let masked = post(&mut service, "/deidentify", json!({ "text": source }));
        let handle = masked.body["session"].as_str().expect("handle").to_owned();
        assert_ne!(masked.body["text"].as_str().expect("masked"), source);

        let restored = post(&mut service, "/reidentify", json!({ "session": handle }));
        assert_eq!(restored.status, 200);
        assert_eq!(
            restored.body["text"].as_str().expect("restored"),
            source,
            "the round trip was not byte-exact"
        );
    }

    #[test]
    fn a_round_trip_agrees_with_the_pipelines_own_reidentification() {
        // The service stores its own span map so it can zeroise the originals,
        // which means it has a SECOND implementation of the restoration walk.
        // Asserting the two agree is what stops them drifting apart.
        let mut service = service();
        let source = note();
        let direct = service.pipeline.deidentify(&source).expect("pipeline");
        let expected = direct.reidentify();
        let masked = post(&mut service, "/deidentify", json!({ "text": source }));
        let handle = masked.body["session"].as_str().expect("handle").to_owned();
        let restored = post(&mut service, "/reidentify", json!({ "session": handle }));
        assert_eq!(restored.body["text"].as_str().expect("restored"), expected);
        assert_eq!(expected, source);
    }

    #[test]
    fn a_session_can_be_released_and_is_then_gone() {
        let mut service = service();
        let masked = post(&mut service, "/deidentify", json!({ "text": note() }));
        let handle = masked.body["session"].as_str().expect("handle").to_owned();

        let first = post(
            &mut service,
            "/reidentify",
            json!({ "session": handle, "release": true }),
        );
        assert_eq!(first.status, 200);
        assert_eq!(first.body["session_released"], json!(true));

        let second = post(&mut service, "/reidentify", json!({ "session": handle }));
        assert_eq!(second.status, 404);
        assert_eq!(second.body["error"]["code"], json!("session_not_found"));
    }

    #[test]
    fn an_unknown_handle_is_indistinguishable_from_an_expired_one() {
        let mut service = service();
        let reply = post(
            &mut service,
            "/reidentify",
            json!({ "session": "00000000000000000000000000000000" }),
        );
        assert_eq!(reply.status, 404);
        assert_eq!(reply.body["error"]["code"], json!("session_not_found"));
    }

    #[test]
    fn a_batch_returns_one_item_per_document_including_the_failures() {
        // CONTINUE-ON-ERROR, and every failure reported. The second document is
        // missing its text field, which is a per-item failure and must not stop
        // the third from being processed or reported.
        let mut service = service();
        let reply = post(
            &mut service,
            "/batch",
            json!({
                "operation": "deidentify",
                "documents": [
                    { "id": "a", "text": note() },
                    { "id": "b" },
                    { "id": "c", "text": "TCKN yok." },
                ],
            }),
        );
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["total"], json!(3));
        assert_eq!(reply.body["successful"], json!(2));
        assert_eq!(reply.body["failed"], json!(1));

        let items = reply.body["items"].as_array().expect("items");
        assert_eq!(items.len(), 3, "a batch dropped a document");
        assert_eq!(items[0]["id"], json!("a"));
        assert_eq!(items[0]["success"], json!(true));
        assert_eq!(items[1]["id"], json!("b"));
        assert_eq!(items[1]["success"], json!(false));
        assert_eq!(items[1]["error"]["code"], json!("bad_request"));
        assert_eq!(items[2]["id"], json!("c"));
        assert_eq!(items[2]["success"], json!(true));
        for (index, item) in items.iter().enumerate() {
            assert_eq!(
                item["index"],
                json!(index),
                "items are not in request order"
            );
        }
    }

    #[test]
    fn a_batch_item_gets_its_own_session_handle() {
        let mut service = service();
        let reply = post(
            &mut service,
            "/batch",
            json!({ "documents": [{ "id": "a", "text": note() }, { "id": "b", "text": note() }] }),
        );
        let items = reply.body["items"].as_array().expect("items");
        let first = items[0]["result"]["session"].as_str().expect("handle");
        let second = items[1]["result"]["session"].as_str().expect("handle");
        assert_ne!(first, second, "two documents shared one span map");

        let restored = post(&mut service, "/reidentify", json!({ "session": first }));
        assert_eq!(restored.body["text"].as_str().expect("restored"), note());
    }

    #[test]
    fn a_batch_can_analyze_instead_of_deidentify() {
        let mut service = service();
        let reply = post(
            &mut service,
            "/batch",
            json!({ "operation": "analyze", "documents": [{ "text": note() }] }),
        );
        assert_eq!(reply.body["operation"], json!("analyze"));
        let result = &reply.body["items"][0]["result"];
        assert!(result.get("entities").is_some());
        // An analyze batch mints no sessions, because it masks nothing.
        assert!(result.get("session").is_none());
    }

    #[test]
    fn a_document_with_no_id_is_still_reported_under_its_index() {
        let mut service = service();
        let reply = post(
            &mut service,
            "/batch",
            json!({ "documents": [{ "text": "bir" }, { "text": "iki" }] }),
        );
        let items = reply.body["items"].as_array().expect("items");
        assert_eq!(items[0]["id"], json!("0"));
        assert_eq!(items[1]["id"], json!("1"));
    }

    #[test]
    fn an_oversized_batch_is_refused_whole() {
        let mut service = service();
        let documents: Vec<Value> = (0..=MAX_BATCH_ITEMS)
            .map(|_| json!({ "text": "x" }))
            .collect();
        let reply = post(&mut service, "/batch", json!({ "documents": documents }));
        assert_eq!(reply.status, 413);
        assert_eq!(reply.body["error"]["code"], json!("batch_too_large"));
    }

    #[test]
    fn every_endpoint_refuses_a_body_that_is_not_json() {
        let mut service = service();
        for path in ["/analyze", "/deidentify", "/reidentify", "/batch"] {
            let reply = service.handle("POST", path, "not json at all");
            assert_eq!(reply.status, 400, "{path}");
            assert_eq!(reply.body["error"]["code"], json!("not_json"), "{path}");
        }
    }

    #[test]
    fn a_missing_required_field_is_a_bad_request_that_names_no_content() {
        let mut service = service();
        for path in ["/analyze", "/deidentify", "/reidentify", "/batch"] {
            let reply = service.handle("POST", path, "{}");
            assert_eq!(reply.status, 400, "{path}");
            assert_eq!(reply.body["error"]["code"], json!("bad_request"), "{path}");
        }
    }

    #[test]
    fn an_unknown_route_is_a_404_and_a_wrong_method_is_a_405() {
        let mut service = service();
        let missing = service.handle("GET", "/pii/extract", "");
        assert_eq!(missing.status, 404);
        assert_eq!(missing.route, "unmatched");

        let wrong = service.handle("GET", "/deidentify", "");
        assert_eq!(wrong.status, 405);
        assert_eq!(wrong.body["error"]["code"], json!("method_not_allowed"));
    }

    #[test]
    fn an_unrouted_path_is_never_written_into_the_log_vocabulary() {
        // I4 by construction: `route` is a `&'static str` from a closed match,
        // so a request for /../../etc/passwd or for a URL containing a name
        // cannot reach a log line.
        let mut service = service();
        let reply = service.handle("GET", "/Ayşe%20Yılmaz", "");
        assert_eq!(reply.route, "unmatched");
        assert!(!reply.route.contains("Ay"));
    }

    #[test]
    fn the_log_histogram_counts_masked_labels_and_nothing_else() {
        let mut service = service();
        let reply = post(&mut service, "/deidentify", json!({ "text": note() }));
        assert!(!reply.labels.is_empty());
        assert!(reply
            .labels
            .iter()
            .any(|(label, count)| *label == EntityLabel::Tckn && *count == 1));
    }

    #[test]
    fn shutdown_destroys_every_live_session() {
        let mut service = service();
        post(&mut service, "/deidentify", json!({ "text": note() }));
        post(&mut service, "/deidentify", json!({ "text": note() }));
        assert_eq!(service.shutdown(), 2);
        assert_eq!(service.sessions.live(), 0);
    }

    #[test]
    fn the_medical_allowlist_opt_out_is_visible_in_health() {
        let mut service = Service::new(ServiceConfig {
            no_medical_allowlist: true,
            ..ServiceConfig::default()
        })
        .expect("service");
        let reply = service.handle("GET", "/health", "");
        assert_eq!(reply.body["medical_allowlist"], json!(false));
    }

    #[test]
    fn placeholder_labels_are_reported_as_l5_being_absent() {
        let mut service = Service::new(ServiceConfig {
            placeholder_labels: true,
            ..ServiceConfig::default()
        })
        .expect("service");
        let reply = service.handle("GET", "/health", "");
        assert_eq!(reply.body["layers"]["l5_surrogates"]["live"], json!(false));

        // And the round trip still works, because it walks output offsets
        // rather than searching for a surrogate.
        let source = note();
        let masked = post(&mut service, "/deidentify", json!({ "text": source }));
        assert!(masked.body["text"]
            .as_str()
            .expect("masked")
            .contains("[TCKN]"));
        let handle = masked.body["session"].as_str().expect("handle").to_owned();
        let restored = post(&mut service, "/reidentify", json!({ "session": handle }));
        assert_eq!(restored.body["text"].as_str().expect("restored"), source);
    }

    #[test]
    fn an_empty_document_is_served_rather_than_refused() {
        // An empty note is a legitimate degenerate input -- a batch of files
        // will contain one eventually -- and refusing it would push the caller
        // into skipping it, which is the failure the batch semantics exist to
        // prevent.
        let mut service = service();
        let reply = post(&mut service, "/deidentify", json!({ "text": "" }));
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["text"], json!(""));
        assert_eq!(reply.body["masked"], json!(0));
    }
}
