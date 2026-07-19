#![forbid(unsafe_code)]

//! `deid-tr-wasm` -- the browser binding.
//!
//! # What runs inside this module, and what the host must supply
//!
//! The split is not an implementation detail. It decides which layers a PWA
//! can promise on a machine with no GPU and no model files, so it is stated
//! here rather than in a README nobody reads next to the code.
//!
//! | Layer | Where it runs | Why |
//! |---|---|---|
//! | L1 deterministic rules | HERE, in wasm | pure regex plus checksums, no runtime needed |
//! | span algebra (union, merge, protection) | HERE, in wasm | pure `core/`, single-sourced with the CLI |
//! | L4 router and adjudication | HERE, in wasm | the allowlist and the demotion guardrail are pure |
//! | L5 surrogates | HERE, in wasm | keyed hashing and format-preserving rewrite are pure |
//! | L2 NER ensemble | HOST, via `onnxruntime-web` | `ort` dropped `wasm32-unknown-unknown`; the forward pass cannot live here |
//! | L3 contextual sweep | HOST, via WebGPU | a quantized local LLM needs a GPU runtime this crate does not contain |
//!
//! So a browser with neither runtime still gets a real, complete Safe Harbor
//! L1 pass over the 18 direct identifiers -- not a degraded imitation of one,
//! because the rules, the merge, the guardrail and the surrogates are the exact
//! same Rust that the CLI runs.
//!
//! # Why the two host-backed layers are shaped as data, not as callbacks
//!
//! [`Contextual::sweep`] is a SYNCHRONOUS Rust method. Every browser inference
//! runtime -- `onnxruntime-web`, WebGPU, WebNN -- is ASYNCHRONOUS. A JS
//! callback handed to a synchronous Rust trait therefore cannot await its own
//! model, so the seam is inverted: this crate hands the host a prompt, the host
//! awaits its model in JS, and the host hands the completion back.
//!
//! [`contextual_prompt`] then [`deidentify_with_contextual_response`] is that
//! two-phase call. It also happens to be the safer shape, because the host
//! cannot accidentally satisfy L3 with a network call it forgot it made -- it
//! has to produce the completion itself, in JS, where its own devtools show it.
//!
//! # The network claim, and how it is checked rather than asserted
//!
//! `Cargo.toml` does not depend on `js-sys` or `web-sys`, so this module has no
//! way to name `fetch`, `XMLHttpRequest`, `WebSocket` or `sendBeacon`, and the
//! compiled wasm module's import table cannot contain them.
//! `tests/no_network.mjs` loads the built artifact with every networking global
//! replaced by a throwing stub, runs a full de-identification, and asserts that
//! none of the stubs fired. That is the check behind "open devtools and watch
//! the network tab stay empty": a claim about the artifact, verified against the
//! artifact.
//!
//! # I4
//!
//! Every error returned to JS is a `core` [`Error`] rendered through its
//! `Display`, and that enum is structurally forbidden from carrying document
//! text. No path in this module puts a document, a covered span, or a model
//! rationale into a `JsError`, a `console` call or a panic message.
//!
//! [`Contextual::sweep`]: deid_tr_core::Contextual::sweep
//! [`Error`]: deid_tr_core::Error

use deid_tr_core::context::{prompt, ContextualSweep, LocalModel, SweepConfig};
use deid_tr_core::surrogate::SurrogateError;
use deid_tr_core::{
    Decision, DeidResult as CoreResult, Pipeline, Result, Salt, SurrogateEngine, Tier as CoreTier,
};
use wasm_bindgen::prelude::*;

/// Everything this binding can fail with.
///
/// A second error family exists because the salt is the browser's problem, not
/// `core`'s: `core/` performs no I/O (I1) so it cannot draw key material, and
/// this crate cannot either -- `getrandom` on `wasm32-unknown-unknown` reaches
/// entropy through `js-sys`/`web-sys`, which are BANNED here (see the manifest:
/// linking them is what would put `fetch` in the module's import table). So the
/// host calls `crypto.getRandomValues` and passes the bytes in, and a host that
/// passes too few gets this rather than a quietly weaker salt.
///
/// Both variants render through a `Display` that is structurally incapable of
/// carrying document text: `core::Error` by construction, and `SurrogateError`
/// by carrying only lengths, labels and offsets (I4).
enum WasmError {
    Core(deid_tr_core::Error),
    Salt(SurrogateError),
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => error.fmt(f),
            Self::Salt(error) => error.fmt(f),
        }
    }
}

// `Debug` DELEGATES TO `Display` rather than being derived. A derive would
// print the inner enum's fields structurally, which for `core::Error` is
// exactly the offsets-and-labels vocabulary it already renders -- but a derive
// also silently starts printing whatever a future variant carries. Forwarding
// keeps the I4 surface equal to the one that was reviewed. It exists because
// `Result::expect` requires it.
impl std::fmt::Debug for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<deid_tr_core::Error> for WasmError {
    fn from(error: deid_tr_core::Error) -> Self {
        Self::Core(error)
    }
}

impl From<SurrogateError> for WasmError {
    fn from(error: SurrogateError) -> Self {
        Self::Salt(error)
    }
}

/// A pipeline with the audited vocabulary and, when key material is supplied,
/// L5.
///
/// THE SAFE CONFIGURATION IS THE DEFAULT ONE, which in this binding means the
/// exported entry points REQUIRE `saltKeyMaterial` and the label-placeholder
/// behaviour has its own, longer, explicitly-named export. The browser cannot
/// generate a salt for itself (see [`WasmError`]), so the alternative shape --
/// an optional argument that silently disables L5 when omitted -- would make
/// forgetting one parameter the way to ship placeholders, which is the exact
/// failure this whole change exists to undo.
fn configured(
    tier: CoreTier,
    key_material: Option<&[u8]>,
) -> std::result::Result<Pipeline, WasmError> {
    let pipeline = Pipeline::new(tier);
    match key_material {
        Some(material) => {
            Ok(pipeline.with_surrogates(SurrogateEngine::new(Salt::derive(material)?)))
        }
        None => Ok(pipeline),
    }
}

/// The assurance tier, which is a legal standard made into a product setting.
///
/// Exported as an enum with no default and required at every entry point,
/// because both defaults are wrong in a different direction: silently choosing
/// Safe Harbor hands back an un-swept document to a caller who wanted
/// quasi-identifiers gone, and silently choosing Expert Determination masks
/// prose a caller wanted readable. The tier is a decision, so the API makes the
/// caller take it.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// L1 + L2 + L4 + L5. The 18 direct identifiers.
    SafeHarbor = 0,
    /// Adds L3, the full-document contextual sweep. Requires a host-supplied
    /// local model completion; see [`deidentify_with_contextual_response`].
    ExpertDetermination = 1,
}

impl From<Tier> for CoreTier {
    fn from(tier: Tier) -> Self {
        match tier {
            Tier::SafeHarbor => Self::SafeHarbor,
            Tier::ExpertDetermination => Self::ExpertDetermination,
        }
    }
}

/// One span as it appears in both the original and the de-identified text.
///
/// A flat, JS-shaped projection of `core`'s `MappedSpan`. It deliberately
/// carries offsets, a label, a layer and a decision -- never the covered text.
/// A caller that needs the original bytes already holds the document and can
/// slice it with `start` and `end`; a caller that does not hold the document
/// has no business receiving the identifier.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct MaskedSpan {
    start: usize,
    end: usize,
    output_start: usize,
    output_end: usize,
    label: String,
    layer: String,
    decision: String,
    confidence: f32,
    checksum_validated: bool,
    replacement: Option<String>,
}

#[wasm_bindgen]
impl MaskedSpan {
    /// Inclusive byte offset into the ORIGINAL document.
    ///
    /// Bytes, never UTF-16 code units, and the distinction bites in JS harder
    /// than anywhere else: `"ş".length` is 1 in JavaScript and 2 here, so
    /// `original.slice(span.start, span.end)` is WRONG for any Turkish note.
    /// A JS caller that needs the covered text must slice a `Uint8Array` of the
    /// UTF-8 encoding and decode the result.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn start(&self) -> usize {
        self.start
    }

    /// Exclusive byte offset into the ORIGINAL document.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn end(&self) -> usize {
        self.end
    }

    /// Inclusive byte offset into the DE-IDENTIFIED document.
    ///
    /// Masking changes byte lengths, so this cannot be derived from `start`.
    /// It is what makes the span map a round-trip table.
    #[wasm_bindgen(getter, js_name = outputStart)]
    #[must_use]
    pub fn output_start(&self) -> usize {
        self.output_start
    }

    /// Exclusive byte offset into the DE-IDENTIFIED document.
    #[wasm_bindgen(getter, js_name = outputEnd)]
    #[must_use]
    pub fn output_end(&self) -> usize {
        self.output_end
    }

    /// The schema label, e.g. `TCKN`, `PATIENT_NAME`, `EMPLOYER_ROLE`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn label(&self) -> String {
        self.label.clone()
    }

    /// Which layer proposed the span: `rules`, `ner` or `context`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn layer(&self) -> String {
        self.layer.clone()
    }

    /// What L4 decided: `mask` or `keep`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn decision(&self) -> String {
        self.decision.clone()
    }

    /// Combined confidence at the point of decision.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    /// True when an arithmetic check actually passed on the covered bytes.
    ///
    /// Surfaced to JS because it is the strongest thing a reviewer can be told
    /// about a masked identifier: this one was not a model's opinion.
    #[wasm_bindgen(getter, js_name = checksumValidated)]
    #[must_use]
    pub fn checksum_validated(&self) -> bool {
        self.checksum_validated
    }

    /// The text substituted, when the decision was to mask.
    ///
    /// A surrogate is synthetic by construction, so returning it is not an
    /// egress of anything.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn replacement(&self) -> Option<String> {
        self.replacement.clone()
    }
}

/// The output of one de-identification run.
///
/// HOLDS THE ORIGINAL DOCUMENT, deliberately and with a cost. [`DeidResult::reidentify`]
/// is an exact inverse, and an exact inverse needs the bytes that were removed;
/// `core` stores only a hash of them, so the original has to live somewhere for
/// the round trip to exist at all. It lives here, in the caller's own tab, for
/// as long as the caller holds the object -- the same lifetime and the same
/// blast radius as the string they passed in. Nothing in this crate writes it
/// to a log, a `Debug` rendering, an error or a sink of any kind, and there is
/// no getter for it: a caller who wants the document already has it.
#[wasm_bindgen]
pub struct DeidResult {
    doc: String,
    inner: CoreResult,
}

#[wasm_bindgen]
impl DeidResult {
    /// The de-identified document.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn text(&self) -> String {
        self.inner.text.clone()
    }

    /// How many spans reached the span map.
    #[wasm_bindgen(getter, js_name = spanCount)]
    #[must_use]
    pub fn span_count(&self) -> usize {
        self.inner.span_map.len()
    }

    /// One entry of the round-trip table.
    ///
    /// Indexed rather than returned as an array so a caller can page through a
    /// long note without materialising every span at once, and so the shape of
    /// the export does not depend on which `Vec<T>` conversions the pinned
    /// wasm-bindgen happens to support.
    #[must_use]
    pub fn span(&self, index: usize) -> Option<MaskedSpan> {
        self.inner.span_map.get(index).map(|mapped| MaskedSpan {
            start: mapped.span.start(),
            end: mapped.span.end(),
            output_start: mapped.output_start,
            output_end: mapped.output_end,
            label: mapped.span.label().to_string(),
            layer: mapped.span.source().to_string(),
            decision: mapped.decision.to_string(),
            confidence: mapped.span.confidence(),
            checksum_validated: mapped.span.is_checksum_validated(),
            replacement: mapped.replacement.clone(),
        })
    }

    /// How many decisions the audit log recorded.
    #[wasm_bindgen(getter, js_name = auditLength)]
    #[must_use]
    pub fn audit_length(&self) -> usize {
        self.inner.audit.len()
    }

    /// True when no audit entry carries model-generated free text.
    ///
    /// The predicate a host must check before persisting or transmitting an
    /// audit log: an L3 rationale is written by quoting the quasi-identifier,
    /// so an unredacted log is PHI (I4).
    #[wasm_bindgen(getter, js_name = auditIsRedacted)]
    #[must_use]
    pub fn audit_is_redacted(&self) -> bool {
        self.inner.audit.is_redacted()
    }

    /// Restore the original document from the de-identified one.
    ///
    /// THE EXACT INVERSE, not a fuzzy surrogate lookup, and the difference
    /// matters at this milestone: until L5 lands, every masked span of a given
    /// label is replaced by the SAME placeholder, so a document with two
    /// different TCKNs contains two identical `[TCKN]` strings and a
    /// surrogate-keyed reverse map cannot tell them apart. Walking the span
    /// map's OUTPUT offsets is unambiguous no matter how many spans share a
    /// replacement, which is why the round trip is defined this way and why it
    /// stays correct when L5 makes surrogates distinct.
    #[must_use]
    pub fn reidentify(&self) -> String {
        let mut restored = String::with_capacity(self.doc.len());
        let mut cursor = 0usize;
        for mapped in &self.inner.span_map {
            // Unmasked bytes are byte-identical in both texts, so the gap can
            // be taken from either. It is taken from the OUTPUT because that is
            // what the output offsets address.
            restored.push_str(
                self.inner
                    .text
                    .get(cursor..mapped.output_start)
                    .unwrap_or_default(),
            );
            restored.push_str(
                self.doc
                    .get(mapped.span.start()..mapped.span.end())
                    .unwrap_or_default(),
            );
            cursor = mapped.output_end;
        }
        restored.push_str(self.inner.text.get(cursor..).unwrap_or_default());
        restored
    }
}

/// De-identify a document at an explicitly chosen tier.
///
/// [`Tier::ExpertDetermination`] fails here rather than degrading to Safe
/// Harbor, because L3 needs a host-supplied model completion that this entry
/// point has no way to obtain. Use [`contextual_prompt`] and
/// [`deidentify_with_contextual_response`] for that tier.
///
/// # Errors
///
/// Returns the `core` error's `Display` rendering, which carries offsets,
/// labels and layers and never document text (I4).
#[wasm_bindgen]
pub fn deidentify(
    doc: &str,
    tier: Tier,
    salt_key_material: &[u8],
) -> std::result::Result<DeidResult, JsError> {
    to_js(deidentify_inner(doc, tier.into(), Some(salt_key_material)))
}

/// [`deidentify`] with L5 switched OFF.
///
/// Named at length because the name is the warning. Each masked span is
/// replaced by its LABEL, so every patient in the note collapses onto
/// `[PATIENT_NAME]`, the document stops reading as clinical prose, and the
/// span map can no longer distinguish the entities it maps. Useful for a
/// preview panel that must not hold key material; wrong for anything a
/// clinician reads.
#[wasm_bindgen(js_name = deidentifyWithLabelPlaceholders)]
pub fn deidentify_with_label_placeholders(
    doc: &str,
    tier: Tier,
) -> std::result::Result<DeidResult, JsError> {
    to_js(deidentify_inner(doc, tier.into(), None))
}

/// [`deidentify`] without the JS error wrapping.
///
/// THE SPLIT EXISTS SO THE FAILURE PATHS ARE TESTABLE. `JsError::new` panics on
/// a non-wasm target -- "cannot call wasm-bindgen imported functions on
/// non-wasm targets" -- so every error case of an exported function is
/// unreachable from a host-target test. Since this machine has no wasm32
/// toolchain installed, that would have left the two most safety-relevant
/// behaviours in this crate (Expert Determination refusing to degrade, and a
/// malformed completion not quoting itself) permanently unexercised. The logic
/// lives here, the exported function is the two-line adapter.
fn deidentify_inner(
    doc: &str,
    tier: CoreTier,
    key_material: Option<&[u8]>,
) -> std::result::Result<DeidResult, WasmError> {
    run(doc, configured(tier, key_material)?)
}

/// The exact prompt L3 would send, for the host to run on its own local model.
///
/// Phase one of the two-phase contextual sweep. The host awaits WebGPU (or
/// WebNN, or a worker) in JS and returns the completion to
/// [`deidentify_with_contextual_response`].
///
/// THE PROMPT CONTAINS THE WHOLE DOCUMENT. That is inherent to L3 -- the layer
/// reasons over the full note -- and it is why the model it is handed to must
/// be local. A host that posts this string anywhere has uploaded the clinical
/// note, which is the one failure this project exists to prevent.
#[wasm_bindgen(js_name = contextualPrompt)]
#[must_use]
pub fn contextual_prompt(doc: &str) -> String {
    prompt::build(doc)
}

/// The prompt format version, so a host can pin the completion it cached.
#[wasm_bindgen(js_name = contextualPromptVersion)]
#[must_use]
pub fn contextual_prompt_version() -> u32 {
    prompt::PROMPT_VERSION
}

/// Phase two: de-identify at Expert Determination using a host-run completion.
///
/// `response` is what the host's LOCAL model returned for
/// [`contextual_prompt`]. The identity triple (`model_id`, `backend`,
/// `quantization`) and `seed` are recorded rather than detected, because a pure
/// core cannot look at a weights file and an audit record that pins nothing is
/// worse than none.
///
/// Findings whose quote cannot be located verbatim in the document are dropped
/// by `core`'s anchoring step, so a hallucinating model costs recall and can
/// never cause the wrong bytes to be masked.
///
/// # Errors
///
/// A malformed completion produces a `core` error carrying a defect
/// classification, a byte position and a length -- never the completion itself,
/// which quotes the document by design (I4).
#[wasm_bindgen(js_name = deidentifyWithContextualResponse)]
pub fn deidentify_with_contextual_response(
    doc: &str,
    response: &str,
    model_id: &str,
    backend: &str,
    quantization: &str,
    seed: u64,
    salt_key_material: &[u8],
) -> std::result::Result<DeidResult, JsError> {
    to_js(contextual_inner(
        doc,
        response,
        model_id,
        backend,
        quantization,
        seed,
        Some(salt_key_material),
    ))
}

/// [`deidentify_with_contextual_response`] without the JS error wrapping.
/// See [`deidentify_inner`] for why the split exists.
fn contextual_inner(
    doc: &str,
    response: &str,
    model_id: &str,
    backend: &str,
    quantization: &str,
    seed: u64,
    key_material: Option<&[u8]>,
) -> std::result::Result<DeidResult, WasmError> {
    let config = SweepConfig::deterministic(model_id, backend, quantization, seed);
    let sweep = ContextualSweep::new(HostCompletion::new(response), config);
    run(
        doc,
        configured(CoreTier::ExpertDetermination, key_material)?.with_context(Box::new(sweep)),
    )
}

/// The crate version, so a PWA can show which build produced an output.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// A [`LocalModel`] that returns a completion the host already produced.
///
/// This is the whole of the L3 runtime in the browser, and it is intentionally
/// incapable of producing a completion itself. Everything that decides a
/// masking outcome -- the prompt, the JSON grammar, the anchoring, the
/// hallucination filter -- stays in `core/`, single-sourced with the native
/// build, so the browser cannot drift into a more permissive reading of a
/// model's answer than the CLI applies.
struct HostCompletion {
    response: String,
}

impl HostCompletion {
    fn new(response: &str) -> Self {
        Self {
            response: response.to_owned(),
        }
    }
}

impl LocalModel for HostCompletion {
    fn generate(&self, _prompt: &str, _config: &SweepConfig) -> Result<String> {
        Ok(self.response.clone())
    }
}

/// Run a configured pipeline and keep the document alongside its result.
fn run(doc: &str, pipeline: Pipeline) -> std::result::Result<DeidResult, WasmError> {
    pipeline
        .deidentify(doc)
        .map(|inner| DeidResult {
            doc: doc.to_owned(),
            inner,
        })
        .map_err(WasmError::Core)
}

/// The one place a `core` error becomes a JS exception.
///
/// `Display` on a core error is the I4 boundary: it renders offsets, lengths,
/// labels, layers and closed-vocabulary defect codes, and the enum has no
/// variant that can hold document text, a covered span or a model rationale.
/// Formatting it is therefore safe in a way that formatting an arbitrary error
/// would not be, and routing every failure through this single function is what
/// keeps that true as variants are added.
fn to_js<T>(outcome: std::result::Result<T, WasmError>) -> std::result::Result<T, JsError> {
    outcome.map_err(|error| JsError::new(&error.to_string()))
}

/// True when the run produced no `Keep` decision.
///
/// Exported because a compliance panel wants to state "every candidate was
/// masked" without materialising the span map in JS.
#[wasm_bindgen(js_name = allSpansMasked)]
#[must_use]
pub fn all_spans_masked(result: &DeidResult) -> bool {
    result
        .inner
        .span_map
        .iter()
        .all(|mapped| mapped.decision == Decision::Mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic Turkish clinical prose. No TCKN is written into this file;
    /// the valid one is COMPUTED at runtime below (I8).
    const NOTE: &str = "Hasta Merkez Bankası'nda çalışıyor.";

    /// A checksum-valid TCKN, derived rather than written down.
    ///
    /// I8 forbids a checksum-valid national id anywhere in a committed file,
    /// and the pre-commit hook enforces it by scanning for exactly that. So the
    /// two check digits are computed here from a fixed nine-digit stem instead:
    /// `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`, `d11 = sum(d1..d10)
    /// mod 10`. `core`'s own helper is `pub(crate)` and unavailable across the
    /// crate boundary, which is why this is duplicated rather than imported.
    fn valid_tckn() -> String {
        const STEM: [u32; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let odd: u32 = STEM.iter().step_by(2).sum();
        let even: u32 = STEM.iter().skip(1).step_by(2).sum();
        let tenth = (odd * 7 + 100 - even) % 10;
        let eleventh = (STEM.iter().sum::<u32>() + tenth) % 10;
        let mut digits = STEM.to_vec();
        digits.push(tenth);
        digits.push(eleventh);
        digits.iter().map(|digit| digit.to_string()).collect()
    }

    fn safe_harbor_note() -> String {
        format!(
            "Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00.",
            valid_tckn()
        )
    }

    #[test]
    fn safe_harbor_masks_a_checksum_valid_identifier_in_the_browser_path() {
        let doc = safe_harbor_note();
        let tckn = valid_tckn();
        let result = deidentify_inner(&doc, CoreTier::SafeHarbor, None).expect("safe harbor run");
        assert!(!result.text().contains(&tckn), "the TCKN survived masking");
        assert!(result.text().contains("[TCKN]"));
        assert!(result.span_count() >= 1);
    }

    #[test]
    fn the_round_trip_restores_the_original_document_exactly() {
        // THE round-trip property, and the reason `reidentify` walks output
        // offsets: the masked text alone is not invertible, because two
        // different TCKNs both render as `[TCKN]` until L5 lands.
        let doc = safe_harbor_note();
        let result = deidentify_inner(&doc, CoreTier::SafeHarbor, None).expect("safe harbor run");
        assert_ne!(
            result.text(),
            doc,
            "nothing was masked, so nothing is proven"
        );
        assert_eq!(result.reidentify(), doc);
    }

    #[test]
    fn the_round_trip_survives_multi_byte_turkish_offsets() {
        // `ş`, `ı` and `ğ` are two bytes each. A round trip built on char
        // indices truncates here and lands inside a letter; one built on byte
        // offsets does not.
        let doc = format!("Ayşe Yılmaz'ın TCKN'si {}.", valid_tckn());
        let result = deidentify_inner(&doc, CoreTier::SafeHarbor, None).expect("run");
        assert_eq!(result.reidentify(), doc);
        let span = result.span(0).expect("one span");
        assert!(doc.is_char_boundary(span.start()));
        assert!(doc.is_char_boundary(span.end()));
    }

    #[test]
    fn a_document_with_nothing_to_mask_round_trips_unchanged() {
        let result = deidentify_inner(NOTE, CoreTier::SafeHarbor, None).expect("run");
        assert_eq!(result.text(), NOTE);
        assert_eq!(result.span_count(), 0);
        assert_eq!(result.reidentify(), NOTE);
    }

    #[test]
    fn expert_determination_without_a_completion_fails_rather_than_degrading() {
        // The single most dangerous silent failure this binding could have: a
        // caller asks for the tier that sweeps quasi-identifiers and receives
        // an un-swept document that looks swept.
        assert!(deidentify_inner(NOTE, CoreTier::ExpertDetermination, None).is_err());
    }

    #[test]
    fn the_two_phase_contextual_seam_masks_a_quasi_identifier() {
        let prompt = contextual_prompt(NOTE);
        assert!(
            prompt.contains(NOTE),
            "the prompt must carry the document L3 reasons over"
        );
        let response =
            r#"[{"quote":"Merkez Bankası","category":"EMPLOYER_ROLE","reason":"employer"}]"#;
        let result = contextual_inner(NOTE, response, "test-model", "webgpu", "q4_0", 7, None)
            .expect("expert determination run");
        assert!(result.text().contains("[EMPLOYER_ROLE]"));
        assert!(!result.text().contains("Merkez Bankası"));
        assert_eq!(result.reidentify(), NOTE);
    }

    /// The brief's canonical medical-register document, synthetic (I8).
    const COSTA_NOTE: &str = "\
GÖĞÜS CERRAHİSİ KONSÜLTASYON NOTU
Konsültan: Prof. Dr. Marco Costa

Tetkikler: Toraks BT'de sol 5. costa'da deplase olmayan fraktür izlendi.
Hasta carcinoma'lı değil; MRI'da ek patoloji yok.
";

    #[test]
    fn the_browser_build_carries_the_real_vocabulary_and_resolves_the_costa_collision() {
        // THE FINDING THIS TEST EXISTS FOR: `core/`'s collision tests all
        // passed while every binding built `Pipeline::new` with an EMPTY
        // allowlist, so the browser bundle shipped without the vocabulary the
        // whole product is sold on. This drives the binding's own entry point.
        //
        // The candidate spans come from the L3 seam, which is the only span
        // source a browser build actually has: L1 has no name rule and L2
        // ships with no weights. A contextual span is deliberately below the
        // escalation ceiling, so both of these reach L4 and are decided by the
        // vocabulary plus the surrounding evidence -- which is precisely the
        // mechanism under test.
        let response = concat!(
            r#"[{"quote":"Costa","category":"RELATIONSHIP_REF","reason":"person"},"#,
            r#"{"quote":"costa'da","category":"RELATIONSHIP_REF","reason":"unclear"}]"#
        );
        let result = contextual_inner(
            COSTA_NOTE,
            response,
            "test-model",
            "webgpu",
            "q4_0",
            7,
            Some(&[0x5au8; 32]),
        )
        .expect("expert determination run");

        let text = result.text();
        // The surname: masked, because the title and the capitalised
        // neighbour are decisive person evidence despite `costa` being
        // vocabulary.
        assert!(!text.contains("Marco Costa"), "{text}");
        // The rib: kept, same surface form, no person evidence.
        assert!(text.contains("costa'da deplase"), "{text}");
        // And the rest of the medical register is untouched.
        assert!(text.contains("carcinoma'lı"), "{text}");
        assert!(text.contains("MRI'da"), "{text}");
        assert_eq!(result.reidentify(), COSTA_NOTE);
    }

    #[test]
    fn the_same_document_without_the_vocabulary_masks_the_anatomy_too() {
        // The A/B that makes the vocabulary the CAUSE rather than a
        // coincidence. There is no exported way to reach this state -- the
        // binding has no allowlist opt-out, because a browser panel has no
        // plausible reason to want one -- so it is built here directly.
        let response = r#"[{"quote":"costa'da","category":"RELATIONSHIP_REF","reason":"unclear"}]"#;
        let config = SweepConfig::deterministic("test-model", "webgpu", "q4_0", 7);
        let sweep = ContextualSweep::new(HostCompletion::new(response), config);
        let result = run(
            COSTA_NOTE,
            Pipeline::new(CoreTier::ExpertDetermination)
                .without_medical_allowlist()
                .with_context(Box::new(sweep)),
        )
        .expect("run");
        assert!(!result.text().contains("costa'da"), "{}", result.text());
    }

    #[test]
    fn key_material_produces_a_surrogate_and_its_absence_produces_a_label() {
        let doc = safe_harbor_note();
        let tckn = valid_tckn();

        // WITH key material: L5 is installed, so what replaces the TCKN is
        // itself a checksum-valid TCKN rather than the string `[TCKN]`.
        let surrogated = deidentify_inner(&doc, CoreTier::SafeHarbor, Some(&[0x5au8; 32]))
            .expect("safe harbor run");
        let text = surrogated.text();
        assert!(!text.contains("[TCKN]"), "{text}");
        assert!(!text.contains(&tckn), "{text}");
        let replacement: String = text
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(char::is_ascii_digit)
            .collect();
        assert_eq!(replacement.len(), 11, "{text}");
        assert_eq!(surrogated.reidentify(), doc);

        // WITHOUT it: the explicitly-named opt-out, and the placeholder it
        // costs. This is what every browser build produced before L5 was
        // wired in, unconditionally and with no way to ask for anything else.
        let placeholders = deidentify_inner(&doc, CoreTier::SafeHarbor, None).expect("run");
        assert!(placeholders.text().contains("[TCKN]"));
    }

    #[test]
    fn key_material_the_host_did_not_take_seriously_is_refused() {
        // A short salt is not a weak salt, it is a guessable one, so it is an
        // error rather than a silent stretch of whatever the host sent.
        let outcome = deidentify_inner(NOTE, CoreTier::SafeHarbor, Some(b"tooshort"));
        assert!(outcome.is_err());
        // I4: the refusal names a length and nothing else.
        let rendered = format!("{}", outcome.err().expect("an error"));
        assert!(!rendered.contains(NOTE));
    }

    #[test]
    fn a_quote_that_is_not_in_the_document_is_dropped_rather_than_masked() {
        // The hallucination filter, asserted at the binding boundary because
        // this is where a host's model output enters the pipeline.
        let response =
            r#"[{"quote":"Ziraat Bankası","category":"EMPLOYER_ROLE","reason":"hallucinated"}]"#;
        let result =
            contextual_inner(NOTE, response, "test-model", "webgpu", "q4_0", 7, None).expect("run");
        assert_eq!(result.span_count(), 0);
        assert_eq!(result.text(), NOTE);
    }

    #[test]
    fn a_malformed_completion_errors_without_quoting_itself() {
        // I4 at the JS boundary: the model's completion quotes the document by
        // design, so it must never reach the error a host will console.log.
        const LEAKED: &str = "Merkez Bankası";
        let response = format!(r#"[{{"quote":"{LEAKED}","category":"NOT_A_CATEGORY"}}]"#);
        // `expect_err` is unavailable because `DeidResult` has no `Debug`, and
        // it must not acquire one: the struct holds the original document, so a
        // derived `Debug` would print the whole clinical note. That absence is
        // the I4 guarantee, so the test matches by hand rather than weakening it.
        let outcome = contextual_inner(NOTE, &response, "test-model", "webgpu", "q4_0", 7, None);
        let Err(error) = outcome else {
            panic!("an unknown category must fail");
        };
        // `JsError` has no accessor on the host target, so the assertion is made
        // against the rendering that produced it, which is the same string.
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains(LEAKED),
            "the error egressed the model's quote of the document"
        );
    }

    #[test]
    fn the_audit_log_handed_to_a_host_carries_no_rationale() {
        let response =
            r#"[{"quote":"Merkez Bankası","category":"EMPLOYER_ROLE","reason":"employer"}]"#;
        let result =
            contextual_inner(NOTE, response, "test-model", "webgpu", "q4_0", 7, None).expect("run");
        assert_eq!(result.audit_length(), 1);
        assert!(result.audit_is_redacted());
    }

    #[test]
    fn masked_spans_report_provenance_but_never_covered_text() {
        let doc = safe_harbor_note();
        let result = deidentify_inner(&doc, CoreTier::SafeHarbor, None).expect("run");
        let span = result.span(0).expect("one span");
        assert_eq!(span.layer(), "rules");
        assert_eq!(span.decision(), "mask");
        assert!(span.replacement().is_some());
        assert!(all_spans_masked(&result));
        assert!(result.span(result.span_count()).is_none());
        // The projection has no accessor that could return the identifier.
        let rendered = format!("{span:?}");
        assert!(!rendered.contains(&valid_tckn()));
    }

    #[test]
    fn output_offsets_address_the_replacement_in_the_output_text() {
        let doc = safe_harbor_note();
        let result = deidentify_inner(&doc, CoreTier::SafeHarbor, None).expect("run");
        let text = result.text();
        for index in 0..result.span_count() {
            let span = result.span(index).expect("span in range");
            let replacement = span.replacement().expect("a masked span replaces bytes");
            assert_eq!(
                text.get(span.output_start()..span.output_end()),
                Some(replacement.as_str())
            );
        }
    }

    #[test]
    fn the_prompt_version_is_reported_so_a_cached_completion_can_be_pinned() {
        assert_eq!(contextual_prompt_version(), prompt::PROMPT_VERSION);
        assert!(!version().is_empty());
    }
}
