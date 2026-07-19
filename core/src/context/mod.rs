//! L3 -- the contextual sweep.
//!
//! The layer that catches what no NER model can: "Merkez Bankası'nda müfettiş
//! olarak çalışıyor", "eşi ilçedeki tek kadın hâkim", "yazlığı Bodrum'da". None
//! of these is an entity. Each of them is a MEANING that narrows the candidate
//! population, sometimes to one person, and finding them needs a model
//! reasoning over the whole document rather than a classifier labelling tokens.
//!
//! # The model is local. This is not a configuration choice.
//!
//! Sending clinical text to a cloud model in order to find the PHI in it hands
//! the entire document to a third party in exchange for a list of the parts of
//! it that were sensitive. That is not a de-identification pipeline, it is a
//! disclosure with extra steps, and it defeats the only reason this tool exists
//! (I1). `core/` therefore contains no invocation at all: it builds the prompt,
//! parses the response and re-anchors the quotes, and the forward pass sits
//! behind [`LocalModel`], implemented in `bindings/` against a local runtime.
//! `scripts/hooks/guard_invariants.sh` refuses any edit in this repository that
//! names a cloud SDK or a remote host, in this directory or any other.
//!
//! # What this module guarantees, and what it does not
//!
//! GUARANTEED: every span it emits covers bytes that are actually in the
//! document, because [`anchor`] searches for the model's quote rather than
//! trusting a reported position, and drops what it cannot find. A hallucinating
//! model costs recall here; it cannot cause the wrong bytes to be masked.
//!
//! GUARANTEED: nothing in this path writes document text, a quote or a
//! rationale into an error, a log or a `Debug` rendering (I4). What is recorded
//! for audit is a HASH of the prompt and a HASH of the response, plus counts.
//!
//! NOT GUARANTEED, and this is a known open issue rather than an oversight:
//! BITWISE DETERMINISM ACROSS EXECUTION PROVIDERS. Temperature is pinned to
//! zero and the seed is fixed and recorded, which makes a run reproducible on
//! ONE build of one runtime on one device. It does not make it reproducible
//! across the backend matrix the project targets -- CPU, CUDA, CoreML, NNAPI
//! and WebGPU reduce floating point in different orders, produce different
//! logits in the last bits, and a greedy decode flips whenever two candidate
//! tokens are near-tied. The flipped token changes the wording of a quote, the
//! quote then fails to anchor, and one finding disappears. So the hashes
//! recorded by [`SweepRecord`] pin a (model, backend, quantization) TRIPLE, not
//! a universal result: two runs are comparable only when all three match, and
//! the config records all three for exactly that reason. This collides with the
//! `eval_sha` reproducibility gate for any L3-dependent metric, which is why
//! L3's success metric is the red team's re-identification RATE rather than an
//! exact-match score.

pub mod anchor;
pub mod parse;
pub mod prompt;

use core::cell::RefCell;

use crate::error::Result;
use crate::pipeline::Contextual;
use crate::span::Span;

pub use anchor::{AnchoredFinding, CONTEXTUAL_CONFIDENCE};
pub use parse::Finding;

/// The local model invocation, and the only thing this layer cannot do itself.
///
/// One method, taking a prompt and returning the completion. Deliberately
/// minimal: everything else -- what to ask, how to read the answer, how to
/// verify it -- is single-sourced in this module so that the native, mobile and
/// browser implementations cannot each invent their own prompt, their own
/// tolerance for malformed JSON, or their own idea of where a span starts.
///
/// IMPLEMENTATIONS MUST BE LOCAL. See the module header.
pub trait LocalModel {
    /// Run the model over one prompt and return its completion.
    ///
    /// Implementations honour [`SweepConfig::temperature`] and
    /// [`SweepConfig::seed`], which is why the config is passed rather than
    /// left to the runtime's defaults.
    fn generate(&self, prompt: &str, config: &SweepConfig) -> Result<String>;
}

/// What was asked of which model, recorded so a run can be reproduced.
///
/// The three identity fields are strings supplied by the caller rather than
/// anything this crate can detect, because `core/` performs no I/O and cannot
/// look at a weights file. A binding that leaves them empty produces an audit
/// record that pins nothing, which is a failure the eval harness can see.
#[derive(Debug, Clone, PartialEq)]
pub struct SweepConfig {
    model_id: String,
    backend: String,
    quantization: String,
    seed: u64,
    temperature: f32,
}

impl SweepConfig {
    /// The only constructor, and it pins temperature to zero.
    ///
    /// There is no setter for temperature. A sampling temperature above zero
    /// makes the same document produce different findings on different runs,
    /// which turns a compliance artifact into a lottery ticket: a note that
    /// passed review yesterday can leak today with no change to the code, the
    /// weights or the note. If a future decision genuinely needs sampling it
    /// needs an ADR, not a field.
    #[must_use]
    pub fn deterministic(
        model_id: impl Into<String>,
        backend: impl Into<String>,
        quantization: impl Into<String>,
        seed: u64,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            backend: backend.into(),
            quantization: quantization.into(),
            seed,
            temperature: 0.0,
        }
    }

    /// The model identity, e.g. a repository name plus a revision.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// The execution provider, e.g. `cpu`, `cuda`, `coreml`, `webgpu`.
    ///
    /// Recorded because it is one third of what the response hash actually
    /// pins; see the module header on bitwise determinism.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// The weight quantization, e.g. `q4_k_m`, `fp16`.
    #[must_use]
    pub fn quantization(&self) -> &str {
        &self.quantization
    }

    /// The fixed decode seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Always `0.0`. See [`SweepConfig::deterministic`].
    #[must_use]
    pub const fn temperature(&self) -> f32 {
        self.temperature
    }

    /// A hash over everything that identifies the run.
    ///
    /// Two sweeps whose config fingerprints differ are not comparable, whatever
    /// their response hashes say.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut hash = FNV_OFFSET_BASIS;
        for part in [
            self.model_id.as_str(),
            self.backend.as_str(),
            self.quantization.as_str(),
        ] {
            hash = fnv1a64_from(hash, part.as_bytes());
            // A separator, so ("ab", "c") and ("a", "bc") do not collide.
            hash = fnv1a64_from(hash, &[0]);
        }
        hash = fnv1a64_from(hash, &self.seed.to_le_bytes());
        fnv1a64_from(hash, &self.temperature.to_bits().to_le_bytes())
    }
}

/// What one sweep did, in numbers only.
///
/// EVERY FIELD IS A HASH OR A COUNT, and that is the point. This is the record
/// that a compliance reviewer reads, that an eval run stores, and that a
/// support ticket eventually carries, so it is designed for someone who is not
/// allowed to see the document. `Debug` is derived here precisely because there
/// is nothing to redact -- which is a property worth being able to see at a
/// glance in the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepRecord {
    /// Hash of the exact prompt sent to the model.
    pub prompt_hash: u64,
    /// Hash of the exact completion received.
    pub response_hash: u64,
    /// [`SweepConfig::fingerprint`] at the time of the call.
    pub config_fingerprint: u64,
    /// The prompt revision; see [`prompt::PROMPT_VERSION`].
    pub prompt_version: u32,
    /// How many findings the model claimed.
    pub claimed: usize,
    /// How many survived verbatim re-anchoring.
    ///
    /// `claimed - anchored` is the hallucination count for this document, and
    /// it is the single most useful number this layer produces: a model whose
    /// gap grows is a model that has started inventing quotes.
    pub anchored: usize,
}

/// L3, assembled.
///
/// Generic over the model rather than boxed so that the browser build can
/// monomorphise a WebGPU implementation and the CLI a native one, with no
/// dynamic dispatch and no allocation in the hot path.
pub struct ContextualSweep<M: LocalModel> {
    model: M,
    config: SweepConfig,
    /// The audit trail, behind interior mutability because [`Contextual::sweep`]
    /// takes `&self` -- the pipeline holds the layer immutably and calls it once
    /// per document. `RefCell` rather than a lock: `core/` compiles to wasm and
    /// a sweep is not shared across threads.
    records: RefCell<Vec<SweepRecord>>,
    /// The verified findings of the most recent sweep, so a caller that wants
    /// the rationale for the audit log can retrieve it. Replaced, not appended:
    /// a rationale is model free text about a document, and holding every
    /// document's rationales for the life of the process is the kind of quiet
    /// accumulation I4 exists to prevent.
    last: RefCell<Vec<AnchoredFinding>>,
}

impl<M: LocalModel> ContextualSweep<M> {
    /// Assemble the layer around a local model.
    pub fn new(model: M, config: SweepConfig) -> Self {
        Self {
            model,
            config,
            records: RefCell::new(Vec::new()),
            last: RefCell::new(Vec::new()),
        }
    }

    /// The configuration this layer runs with.
    pub const fn config(&self) -> &SweepConfig {
        &self.config
    }

    /// The local model behind this layer.
    ///
    /// Exposed so a binding's tests can assert on what was actually invoked --
    /// with a mock runtime that is how "the document never reached the process
    /// argument list" becomes an assertion instead of a claim.
    pub const fn model(&self) -> &M {
        &self.model
    }

    /// Every sweep performed by this instance, in order.
    pub fn records(&self) -> Vec<SweepRecord> {
        self.records.borrow().clone()
    }

    /// The verified findings of the most recent sweep, with their rationales.
    ///
    /// The bridge between the [`Contextual`] contract, which can only return
    /// spans, and the audit log, which wants to know why. In memory only.
    pub fn last_findings(&self) -> Vec<AnchoredFinding> {
        self.last.borrow().clone()
    }
}

impl<M: LocalModel> Contextual for ContextualSweep<M> {
    fn sweep(&self, doc: &str) -> Result<Vec<Span>> {
        let prompt = prompt::build(doc);
        let response = self.model.generate(&prompt, &self.config)?;

        // Recorded BEFORE parsing, so a malformed response still leaves a trace
        // a reviewer can correlate with the run that produced it. An error path
        // that records nothing is how an intermittent model failure becomes
        // invisible.
        let record = SweepRecord {
            prompt_hash: fnv1a64(prompt.as_bytes()),
            response_hash: fnv1a64(response.as_bytes()),
            config_fingerprint: self.config.fingerprint(),
            prompt_version: prompt::PROMPT_VERSION,
            claimed: 0,
            anchored: 0,
        };

        let claimed = match parse::findings(&response) {
            Ok(found) => found,
            Err(error) => {
                self.records.borrow_mut().push(record);
                return Err(error);
            }
        };
        let verified = anchor::anchor(doc, &claimed)?;

        self.records.borrow_mut().push(SweepRecord {
            claimed: claimed.len(),
            anchored: verified.len(),
            ..record
        });
        let spans = verified.iter().map(|found| *found.span()).collect();
        *self.last.borrow_mut() = verified;
        Ok(spans)
    }
}

/// A model that returns a canned response, so the whole L3 path is testable.
///
/// WHY THIS SHIPS IN THE LIBRARY AND NOT ONLY IN `#[cfg(test)]`: every binding,
/// the eval harness and the MCP gateway need to exercise prompt construction,
/// parsing, anchoring, the union and the audit trail without a multi-gigabyte
/// weights file. A test that can only run where a model is installed is a test
/// that stops running.
pub struct MockContextual {
    response: String,
    /// Prompts this mock was given, so a test can assert on what was asked.
    prompts: RefCell<Vec<String>>,
}

impl MockContextual {
    /// A mock that answers every prompt with the same JSON.
    #[must_use]
    pub fn new(response: impl Into<String>) -> Self {
        Self {
            response: response.into(),
            prompts: RefCell::new(Vec::new()),
        }
    }

    /// How many times the mock was asked for a completion.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.prompts.borrow().len()
    }

    /// Hash of the prompt of the n-th call, for determinism assertions.
    ///
    /// A hash rather than the prompt itself, because the prompt contains the
    /// whole document and this method exists for tests that also run against
    /// fixtures nobody should be printing (I4).
    #[must_use]
    pub fn prompt_hash(&self, index: usize) -> Option<u64> {
        self.prompts
            .borrow()
            .get(index)
            .map(|asked| fnv1a64(asked.as_bytes()))
    }
}

impl LocalModel for MockContextual {
    fn generate(&self, prompt: &str, _config: &SweepConfig) -> Result<String> {
        self.prompts.borrow_mut().push(prompt.to_owned());
        Ok(self.response.clone())
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a, 64-bit, continued from an existing state.
///
/// Chosen for the same reason `span.rs` chose it: the recorded hashes have to
/// mean the same thing across compiler and standard-library versions, and
/// `DefaultHasher` explicitly does not promise that. An audit record whose
/// hashes change when the toolchain changes pins nothing at all.
///
/// NOT A SECURITY PRIMITIVE. These hashes exist to detect that two runs saw
/// different bytes, not to withhold the bytes from an attacker: 64 bits of
/// unkeyed hash over a short prompt is brute-forceable by anyone who can guess
/// the document, exactly as the `Span::text_hash` open issue records. The
/// mitigation is the same one -- a keyed HMAC with a per-run salt -- and it is
/// tracked for M5.
fn fnv1a64_from(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_from(FNV_OFFSET_BASIS, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, ResponseDefect};
    use crate::label::{EntityLabel, QuasiCategory};
    use crate::pipeline::{Pipeline, Tier};
    use crate::span::Layer;

    /// Synthetic Turkish narrative. No real PHI (I8).
    const BODY: &str = "Hasta Merkez Bankası'nda müfettiş olarak çalışıyor. \
Eşi ilçedeki tek kadın hâkim.";

    /// A canned response: one quote that is really in `BODY`, one invented.
    const CANNED: &str = r#"Bulgular aşağıdadır:
```json
[
  {"quote": "Merkez Bankası'nda müfettiş olarak çalışıyor",
   "category": "EMPLOYER_ROLE",
   "reason": "küçük bir popülasyonda mesleği tekilleştirici"},
  {"quote": "eşi Ankara'da savcı",
   "category": "RELATIONSHIP_REF",
   "reason": "yakın referansı artı unvan"}
]
```"#;

    fn config() -> SweepConfig {
        SweepConfig::deterministic("deid-tr/test-model@abc123", "cpu", "q4_k_m", 42)
    }

    fn sweep_of(response: &str) -> ContextualSweep<MockContextual> {
        ContextualSweep::new(MockContextual::new(response), config())
    }

    #[test]
    fn the_whole_path_runs_against_a_mock_with_no_model() {
        let layer = sweep_of(CANNED);
        let spans = layer.sweep(BODY).expect("sweep");
        assert_eq!(layer.config().temperature(), 0.0);
        assert_eq!(spans.len(), 1, "the invented quote must not become a span");
        assert_eq!(spans[0].source(), Layer::Context);
        assert_eq!(
            spans[0].label(),
            EntityLabel::Quasi(QuasiCategory::EmployerRole)
        );
        assert_eq!(
            BODY.get(spans[0].start()..spans[0].end()),
            Some("Merkez Bankası'nda müfettiş olarak çalışıyor")
        );
    }

    #[test]
    fn the_record_counts_the_hallucination_gap() {
        let layer = sweep_of(CANNED);
        layer.sweep(BODY).expect("sweep");
        let records = layer.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].claimed, 2);
        assert_eq!(records[0].anchored, 1);
        assert_eq!(records[0].prompt_version, prompt::PROMPT_VERSION);
        assert_eq!(records[0].config_fingerprint, config().fingerprint());
    }

    #[test]
    fn the_record_carries_hashes_and_never_the_prompt_or_the_response() {
        let layer = sweep_of(CANNED);
        layer.sweep(BODY).expect("sweep");
        let record = layer.records()[0];
        assert_eq!(
            Some(record.prompt_hash),
            layer.model.prompt_hash(0),
            "the recorded hash must be of the prompt actually sent"
        );
        assert_ne!(record.prompt_hash, record.response_hash);

        // The Debug rendering is what reaches a log, and it must be numbers.
        let rendered = format!("{record:?}");
        assert!(!rendered.contains("Merkez"));
        assert!(!rendered.contains("müfettiş"));
        assert!(!rendered.contains("Bulgular"));
    }

    #[test]
    fn a_repeated_sweep_of_the_same_document_is_reproducible() {
        // The determinism that IS achievable: same document, same config, same
        // runtime -- same prompt, same hashes, same offsets. See the module
        // header for the determinism that is not.
        let layer = sweep_of(CANNED);
        let first = layer.sweep(BODY).expect("sweep");
        let second = layer.sweep(BODY).expect("sweep");
        assert_eq!(first, second);
        let records = layer.records();
        assert_eq!(records[0], records[1]);
        assert_eq!(layer.model.call_count(), 2);
    }

    #[test]
    fn a_malformed_response_is_an_error_that_still_leaves_an_audit_record() {
        let layer = sweep_of("Üzgünüm, yardımcı olamam.");
        let error = layer.sweep(BODY).expect_err("no array in the response");
        assert!(matches!(
            error,
            Error::MalformedContextualResponse {
                defect: ResponseDefect::NoArrayFound,
                ..
            }
        ));
        let records = layer.records();
        assert_eq!(records.len(), 1, "a failed sweep must still be traceable");
        assert_eq!((records[0].claimed, records[0].anchored), (0, 0));
        assert!(!error.to_string().contains("Üzgünüm"));
    }

    #[test]
    fn an_empty_finding_list_is_a_successful_sweep() {
        let layer = sweep_of("[]");
        assert!(layer.sweep(BODY).expect("sweep").is_empty());
        assert_eq!(layer.records()[0].claimed, 0);
    }

    #[test]
    fn the_rationale_is_available_for_the_audit_log_after_a_sweep() {
        let layer = sweep_of(CANNED);
        layer.sweep(BODY).expect("sweep");
        let found = layer.last_findings();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].category(), QuasiCategory::EmployerRole);
        assert!(!found[0].rationale().is_empty());
        let entry = found[0]
            .audit_entry(crate::span::Decision::Mask)
            .expect("L3 may explain itself");
        assert_eq!(entry.layer, Layer::Context);
        assert!(entry.has_rationale());
    }

    #[test]
    fn a_sweep_replaces_the_previous_documents_rationales() {
        // Rationales are model free text about ONE document. Accumulating them
        // across documents is the quiet growth I4 is written against.
        let layer = sweep_of(CANNED);
        layer.sweep(BODY).expect("sweep");
        layer.sweep("Şikayeti yok.").expect("sweep");
        assert!(layer.last_findings().is_empty());
        assert_eq!(layer.records().len(), 2);
    }

    #[test]
    fn the_config_fingerprint_separates_backends_and_quantizations() {
        // The recorded hash pins a (model, backend, quantization) triple, so
        // the triple must actually change the fingerprint. Two runs that agree
        // on a response hash but disagree here are not the same experiment.
        let base = config().fingerprint();
        let cases = [
            SweepConfig::deterministic("deid-tr/test-model@abc123", "cuda", "q4_k_m", 42),
            SweepConfig::deterministic("deid-tr/test-model@abc123", "cpu", "fp16", 42),
            SweepConfig::deterministic("deid-tr/other-model@abc123", "cpu", "q4_k_m", 42),
            SweepConfig::deterministic("deid-tr/test-model@abc123", "cpu", "q4_k_m", 43),
        ];
        for case in cases {
            assert_ne!(case.fingerprint(), base);
        }
        assert_eq!(config().fingerprint(), config().fingerprint());
    }

    #[test]
    fn the_fingerprint_does_not_collide_on_field_boundaries() {
        let joined = SweepConfig::deterministic("ab", "c", "d", 1);
        let split = SweepConfig::deterministic("a", "bc", "d", 1);
        assert_ne!(joined.fingerprint(), split.fingerprint());
    }

    #[test]
    fn the_sweep_plugs_into_the_expert_determination_tier() {
        // The end-to-end statement: L3 reaches the orchestrator, its span is
        // masked at byte offsets, and the Turkish suffix on the far side of a
        // multi-byte letter survives.
        let result = Pipeline::new(Tier::ExpertDetermination)
            .with_context(Box::new(sweep_of(CANNED)))
            .deidentify(BODY)
            .expect("expert determination run");
        assert!(!result.text.contains("Merkez Bankası'nda müfettiş"));
        assert!(result.text.contains("[EMPLOYER_ROLE]"));
        assert!(
            result.text.contains("Eşi ilçedeki tek kadın hâkim."),
            "the invented finding must leave the narrative untouched"
        );
        assert!(
            result.audit.is_redacted(),
            "the pipeline's own audit log carries no rationale"
        );
    }
}
