#![forbid(unsafe_code)]

//! `deid_tr` -- the Python binding.
//!
//! # The tier is a required argument, everywhere
//!
//! `Pipeline()` does not exist. `Pipeline(Tier.SAFE_HARBOR)` and
//! `Pipeline(Tier.EXPERT_DETERMINATION, local_model=...)` do. There is no
//! default and there will not be one, because BOTH defaults are wrong and they
//! are wrong in opposite directions:
//!
//! - defaulting to Safe Harbor hands an un-swept document to a caller who
//!   wanted quasi-identifiers gone, and the output looks identical to one that
//!   was swept;
//! - defaulting to Expert Determination masks narrative prose for a caller who
//!   wanted a readable note, and buries the change in a library default.
//!
//! Asking for Expert Determination without a local model is an error rather
//! than a silent fall back to Safe Harbor, for the same reason.
//!
//! # No network, at import or at inference (I1)
//!
//! Importing this module loads a compiled extension and nothing else. There is
//! no registry lookup, no license check, no version ping and no lazy weight
//! download at first call. `deid-tr-core` has no network dependency, this crate
//! adds only `pyo3`, and the L3 model is a Python callable the CALLER supplies
//! -- so the only way a clinical note reaches a socket is if the caller's own
//! code puts it there, in their own file, where their own review can see it.
//!
//! # Errors carry no document text (I4)
//!
//! Every exception below is raised from a `deid-tr-core` error, and that enum
//! is structurally forbidden from holding document text, covered spans or model
//! rationales. It carries offsets, lengths, labels, layers and closed-vocabulary
//! defect codes. So a traceback can be pasted into a bug report, and a log
//! handler can capture these exceptions, without either becoming a disclosure.
//! The one exception that carries caller-authored text is the one re-raised
//! from the caller's own `local_model` callable, which never left their process.

use std::cell::RefCell;

use deid_tr_core::context::{prompt, ContextualSweep, LocalModel, SweepConfig};
use deid_tr_core::surrogate::SALT_LEN;
use deid_tr_core::{
    Decision, DeidResult as CoreResult, Error, ModelFailure, Pipeline as CorePipeline,
    Result as CoreOutcome, Salt, SurrogateEngine, Tier as CoreTier,
};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyType;

create_exception!(
    _deid_tr,
    DeidError,
    pyo3::exceptions::PyException,
    "Base class for every error this library raises."
);
create_exception!(
    _deid_tr,
    SpanError,
    DeidError,
    "A span was not a valid range over the document it was built against."
);
create_exception!(
    _deid_tr,
    OffsetError,
    SpanError,
    "A byte offset was out of bounds or split a multi-byte character."
);
create_exception!(
    _deid_tr,
    GuardrailError,
    DeidError,
    "L4 attempted something it is forbidden to do."
);
create_exception!(
    _deid_tr,
    ProtectedSpanDemotionError,
    GuardrailError,
    "L4 tried to demote a checksum-validated or multi-detector span."
);
create_exception!(
    _deid_tr,
    ConfigurationError,
    DeidError,
    "The pipeline was assembled in a way that cannot produce a correct result."
);
create_exception!(
    _deid_tr,
    ContextualLayerMissingError,
    ConfigurationError,
    "Expert Determination was requested without a local model to sweep with."
);
create_exception!(
    _deid_tr,
    ContextualModelError,
    DeidError,
    "The local L3 model failed or answered with something unusable."
);
create_exception!(
    _deid_tr,
    MalformedContextualResponseError,
    ContextualModelError,
    "The local model's completion was not the requested JSON."
);
create_exception!(
    _deid_tr,
    LocalModelFailedError,
    ContextualModelError,
    "The local model could not be run at all."
);
create_exception!(
    _deid_tr,
    SchemaError,
    DeidError,
    "A label id did not match the committed entity schema."
);

/// Map a core error onto the typed hierarchy.
///
/// A HIERARCHY RATHER THAN ONE EXCEPTION, because the remedies differ and a
/// caller has to be able to write the distinction down: a
/// `ContextualLayerMissingError` is a wiring mistake in their own code, a
/// `MalformedContextualResponseError` means their local model needs a better
/// grammar or a bigger context window, and a `ProtectedSpanDemotionError` is a
/// bug in ours. Collapsing all three into `RuntimeError` forces a caller to
/// match on message text, which is how a library ends up with an accidental
/// public API made of English sentences.
///
/// The message is the core error's `Display`, unmodified. That is the I4
/// boundary: the enum has no variant that can hold document text, so rendering
/// it is safe in a way that rendering an arbitrary error would not be. Nothing
/// here appends context, because the only context available at this point is
/// the document.
fn to_py_err(error: &Error) -> PyErr {
    let message = error.to_string();
    match error {
        Error::SpanNotOrdered { .. } | Error::DisjointUnion { .. } => SpanError::new_err(message),
        Error::SpanOutOfBounds { .. } | Error::SpanNotCharBoundary { .. } => {
            OffsetError::new_err(message)
        }
        Error::ConfidenceOutOfRange { .. } => SpanError::new_err(message),
        Error::ProtectedSpanDemotion { .. } => ProtectedSpanDemotionError::new_err(message),
        Error::RationaleNotPermitted { .. } => GuardrailError::new_err(message),
        Error::ContextualLayerMissing => ContextualLayerMissingError::new_err(message),
        Error::MalformedContextualResponse { .. } => {
            MalformedContextualResponseError::new_err(message)
        }
        Error::LocalModelFailed { .. } => LocalModelFailedError::new_err(message),
        Error::UnknownEntityLabel { .. } => SchemaError::new_err(message),
        // `Error` is `#[non_exhaustive]`. A new variant lands on the base class
        // rather than failing to compile, so adding one in `core/` cannot break
        // this binding, and a caller's `except DeidError` still catches it.
        _ => DeidError::new_err(message),
    }
}

/// The assurance tier, which is a legal standard made into a product setting.
#[pyclass(eq, eq_int, module = "deid_tr")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// L1 + L2 + L4 + L5. The 18 enumerated direct identifiers. On-device,
    /// fast, and the only tier that needs no model.
    SAFE_HARBOR,
    /// Adds L3, the full-document contextual sweep for quasi-identifiers.
    /// Requires a LOCAL model; see `Pipeline(..., local_model=...)`.
    EXPERT_DETERMINATION,
}

impl From<Tier> for CoreTier {
    fn from(tier: Tier) -> Self {
        match tier {
            Tier::SAFE_HARBOR => Self::SafeHarbor,
            Tier::EXPERT_DETERMINATION => Self::ExpertDetermination,
        }
    }
}

/// A candidate identifier located in the original document.
///
/// Read-only, and it has no accessor for the covered text. A caller holding the
/// document can slice it with `start` and `end`; a caller not holding the
/// document has no business receiving the identifier, and `core` does not store
/// it anyway -- only a hash, for surrogate consistency.
#[pyclass(frozen, module = "deid_tr")]
#[derive(Debug, Clone)]
pub struct Span {
    #[pyo3(get)]
    start: usize,
    #[pyo3(get)]
    end: usize,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    layer: String,
    #[pyo3(get)]
    detector: String,
    #[pyo3(get)]
    confidence: f32,
    #[pyo3(get)]
    checksum_validated: bool,
}

#[pymethods]
impl Span {
    /// Length of the covered range IN BYTES.
    ///
    /// Bytes, not characters, and in Python the difference is silent until it
    /// is catastrophic: `len("Ayşe")` is 4 in Python and 5 here, so
    /// `doc[span.start : span.end]` on a `str` is WRONG for any Turkish note.
    /// Slice `doc.encode("utf-8")` and decode the result.
    #[getter]
    fn byte_len(&self) -> usize {
        self.end - self.start
    }

    /// Offsets, provenance and confidence. Never the covered text -- this
    /// object does not hold it, and a `repr` reaches REPL transcripts and
    /// notebook checkpoints.
    fn __repr__(&self) -> String {
        format!(
            "Span(start={}, end={}, label='{}', layer='{}', confidence={:.3})",
            self.start, self.end, self.label, self.layer, self.confidence
        )
    }
}

/// One span as it appears in both the original and the de-identified text.
#[pyclass(frozen, module = "deid_tr")]
#[derive(Debug, Clone)]
pub struct MappedSpan {
    #[pyo3(get)]
    span: Span,
    /// `"mask"` or `"keep"`.
    #[pyo3(get)]
    decision: String,
    /// The synthetic text substituted, when the decision was to mask.
    #[pyo3(get)]
    replacement: Option<String>,
    /// Inclusive byte offset in the OUTPUT text. Masking changes byte lengths,
    /// so this cannot be derived from `span.start`.
    #[pyo3(get)]
    output_start: usize,
    /// Exclusive byte offset in the OUTPUT text.
    #[pyo3(get)]
    output_end: usize,
}

/// One decision about one span, as it appears in the audit log.
///
/// Carries no rationale. An L3 rationale is written by quoting the
/// quasi-identifier it describes, so `core` keeps it behind an accessor this
/// binding does not expose (I4).
#[pyclass(frozen, module = "deid_tr")]
#[derive(Debug, Clone)]
pub struct AuditEntry {
    #[pyo3(get)]
    layer: String,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    start: usize,
    #[pyo3(get)]
    end: usize,
    #[pyo3(get)]
    confidence: f32,
    #[pyo3(get)]
    decision: String,
}

/// The output of one de-identification run.
///
/// HOLDS THE ORIGINAL DOCUMENT, deliberately. `reidentify()` is an exact
/// inverse, and an exact inverse needs the bytes that were removed; `core`
/// stores only a hash of them. The document therefore lives here, in the
/// caller's own process, for exactly as long as they hold this object -- the
/// same lifetime and the same blast radius as the string they passed in.
/// There is no accessor for it, nothing writes it to a log or a `__repr__`,
/// and a caller who wants the document already has it.
#[pyclass(frozen, module = "deid_tr")]
pub struct DeidResult {
    doc: String,
    text: String,
    span_map: Vec<MappedSpan>,
    audit: Vec<AuditEntry>,
    audit_is_redacted: bool,
    raw: Vec<(usize, usize, usize, usize)>,
}

#[pymethods]
impl DeidResult {
    /// The de-identified document.
    #[getter]
    fn text(&self) -> &str {
        &self.text
    }

    /// The round-trip table. Local, never logged, never transmitted.
    #[getter]
    fn span_map(&self) -> Vec<MappedSpan> {
        self.span_map.clone()
    }

    /// What was decided about each span, with no model free text attached.
    #[getter]
    fn audit(&self) -> Vec<AuditEntry> {
        self.audit.clone()
    }

    /// True when no audit entry carries model-generated free text.
    ///
    /// The predicate to check before persisting or transmitting an audit log.
    #[getter]
    fn audit_is_redacted(&self) -> bool {
        self.audit_is_redacted
    }

    /// Restore the original document from the de-identified one.
    ///
    /// THE EXACT INVERSE, not a surrogate lookup, and at this milestone the
    /// difference is the whole correctness argument: until L5 lands, every
    /// masked span of a given label is replaced by the SAME placeholder, so a
    /// note with two different TCKNs contains two identical `[TCKN]` strings
    /// and a reverse map keyed on the replacement cannot tell them apart.
    /// Walking the span map's OUTPUT offsets is unambiguous however many spans
    /// share a replacement, and stays correct once L5 makes them distinct.
    fn reidentify(&self) -> String {
        let mut restored = String::with_capacity(self.doc.len());
        let mut cursor = 0usize;
        for &(start, end, output_start, output_end) in &self.raw {
            // Unmasked bytes are byte-identical in both texts, so the gap can
            // be taken from either. It comes from the OUTPUT because that is
            // what the output offsets address.
            restored.push_str(self.text.get(cursor..output_start).unwrap_or_default());
            restored.push_str(self.doc.get(start..end).unwrap_or_default());
            cursor = output_end;
        }
        restored.push_str(self.text.get(cursor..).unwrap_or_default());
        restored
    }

    /// How many spans were masked rather than kept.
    #[getter]
    fn masked_count(&self) -> usize {
        self.span_map
            .iter()
            .filter(|mapped| mapped.decision == "mask")
            .count()
    }

    /// Deliberately does NOT render the text.
    ///
    /// `repr()` reaches a REPL transcript, a notebook checkpoint, a `print()`
    /// in a loop and the `!r` of a f-string in somebody's log call. Rendering
    /// the de-identified text there would be defensible; rendering it next to
    /// an object that also holds the original is how a notebook checkpoint
    /// becomes a disclosure.
    fn __repr__(&self) -> String {
        format!(
            "DeidResult(spans={}, masked={}, audit={})",
            self.span_map.len(),
            self.masked_count(),
            self.audit.len()
        )
    }
}

/// A [`LocalModel`] backed by a Python callable.
///
/// The callable receives the prompt and returns the completion. It MUST run a
/// local model: handing this prompt to a hosted API uploads the entire clinical
/// note in order to be told which parts of it were sensitive, which is a
/// disclosure with extra steps. `core/` cannot enforce that from here -- the
/// callable is the caller's code -- so the binding does the two things it can:
/// it never provides a network client of its own, and it says this in the
/// docstring the caller reads.
struct PyLocalModel {
    callable: Py<PyAny>,
    /// The caller's own exception, held so it can be re-raised unchanged.
    ///
    /// `LocalModel::generate` returns a `core` error, and `core`'s error enum
    /// has no variant for "a Python callable raised" -- correctly, since it
    /// knows nothing about Python. Flattening the caller's `TimeoutError` into
    /// a generic model failure would destroy the one piece of information they
    /// need, so it is parked here and restored at the boundary.
    raised: RefCell<Option<PyErr>>,
}

impl LocalModel for PyLocalModel {
    fn generate(&self, prompt: &str, _config: &SweepConfig) -> CoreOutcome<String> {
        Python::with_gil(|py| match self.callable.call1(py, (prompt,)) {
            Ok(value) => value.extract::<String>(py).map_err(|error| {
                *self.raised.borrow_mut() = Some(error);
                Error::LocalModelFailed {
                    kind: ModelFailure::OutputNotUtf8,
                }
            }),
            Err(error) => {
                *self.raised.borrow_mut() = Some(error);
                Err(Error::LocalModelFailed {
                    kind: ModelFailure::ExitedWithError,
                })
            }
        })
    }
}

/// The de-identification pipeline.
///
/// The tier is required at construction. See the module docstring for why there
/// is no default.
#[pyclass(module = "deid_tr")]
pub struct Pipeline {
    tier: Tier,
    local_model: Option<Py<PyAny>>,
    model_id: String,
    backend: String,
    quantization: String,
    seed: u64,
    /// Caller-supplied L5 key material, if any.
    ///
    /// `None` means "draw a fresh one per document", which is
    /// `SaltScope::Document`: two calls produce unlinkable surrogates. A caller
    /// who needs one patient's notes to share surrogates across calls -- the
    /// longitudinal-research case, which is also the cross-document linkage an
    /// attacker wants -- supplies their own bytes and takes that decision
    /// explicitly.
    salt_key_material: Option<Vec<u8>>,
    /// The one opt-OUT: replace each identifier with its LABEL instead of a
    /// surrogate. Every patient in the note then collapses onto
    /// `[PATIENT_NAME]`.
    label_placeholders: bool,
}

#[pymethods]
impl Pipeline {
    /// Build a pipeline at an explicitly chosen tier.
    ///
    /// `local_model` is required for `Tier.EXPERT_DETERMINATION` and rejected
    /// for `Tier.SAFE_HARBOR`. REJECTED, not ignored: a caller who passes a
    /// model to the Safe Harbor tier believes their quasi-identifiers are being
    /// swept, and silently accepting the argument would let them keep believing
    /// it for as long as the code lives.
    ///
    /// The identity triple and the seed are recorded rather than detected,
    /// because a pure core cannot look at a weights file, and an audit record
    /// that pins nothing is worse than no audit record at all.
    #[new]
    #[pyo3(signature = (
        tier,
        *,
        local_model = None,
        model_id = "unspecified",
        backend = "unspecified",
        quantization = "unspecified",
        seed = 0,
        salt_key_material = None,
        label_placeholders = false,
    ))]
    fn new(
        tier: Tier,
        local_model: Option<Py<PyAny>>,
        model_id: &str,
        backend: &str,
        quantization: &str,
        seed: u64,
        salt_key_material: Option<Vec<u8>>,
        label_placeholders: bool,
    ) -> PyResult<Self> {
        match (tier, local_model.is_some()) {
            (Tier::EXPERT_DETERMINATION, false) => {
                return Err(ContextualLayerMissingError::new_err(
                    "Tier.EXPERT_DETERMINATION requires local_model=<callable>; \
                     it will not silently degrade to Safe Harbor",
                ))
            }
            (Tier::SAFE_HARBOR, true) => {
                return Err(PyValueError::new_err(
                    "local_model is only used by Tier.EXPERT_DETERMINATION; \
                     passing it to Tier.SAFE_HARBOR would be ignored, and a \
                     silently ignored contextual model is an un-swept document",
                ))
            }
            _ => {}
        }
        if let Some(material) = salt_key_material.as_ref() {
            // Refused here rather than at the first `deidentify`, so a
            // deployment that mis-sized its key finds out when it configures
            // the pipeline and not halfway through a corpus.
            Salt::derive(material).map_err(|error| PyValueError::new_err(error.to_string()))?;
        }
        Ok(Self {
            tier,
            local_model,
            model_id: model_id.to_owned(),
            backend: backend.to_owned(),
            quantization: quantization.to_owned(),
            seed,
            salt_key_material,
            label_placeholders,
        })
    }

    /// The Safe Harbor tier, spelled out.
    ///
    /// A named constructor rather than a default argument: it reads as a
    /// decision at the call site, which is the whole point.
    #[classmethod]
    fn safe_harbor(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        Self::new(
            Tier::SAFE_HARBOR,
            None,
            "unspecified",
            "unspecified",
            "unspecified",
            0,
            None,
            false,
        )
    }

    /// The Expert Determination tier, spelled out.
    #[classmethod]
    #[pyo3(signature = (
        local_model,
        *,
        model_id = "unspecified",
        backend = "unspecified",
        quantization = "unspecified",
        seed = 0,
    ))]
    fn expert_determination(
        _cls: &Bound<'_, PyType>,
        local_model: Py<PyAny>,
        model_id: &str,
        backend: &str,
        quantization: &str,
        seed: u64,
    ) -> PyResult<Self> {
        Self::new(
            Tier::EXPERT_DETERMINATION,
            Some(local_model),
            model_id,
            backend,
            quantization,
            seed,
            None,
            false,
        )
    }

    /// The configured tier.
    #[getter]
    fn tier(&self) -> Tier {
        self.tier
    }

    /// De-identify a document.
    ///
    /// The whole run is on-device. Nothing is fetched, no weights are lazily
    /// downloaded, and the only model involved is the callable the caller
    /// supplied (I1).
    fn deidentify(&self, py: Python<'_>, doc: &str) -> PyResult<DeidResult> {
        // `CorePipeline::new` now carries the audited class C vocabulary, so
        // L4 has something to consult. It did not, for the whole of M4: this
        // binding built a bare pipeline and the medical-term collision
        // resolution the product is sold on never ran.
        let mut pipeline = CorePipeline::new(self.tier.into());
        if !self.label_placeholders {
            pipeline = pipeline.with_surrogates(SurrogateEngine::new(self.salt()?));
        }
        // The adapter is rebuilt per call rather than stored, because
        // `core`'s `Pipeline` holds a `Box<dyn Contextual>` that is not `Send`,
        // and a `#[pyclass]` must be. Construction is a handful of moves, so
        // the cost of doing it here is nothing next to the cost of making the
        // whole binding single-threaded to avoid it.
        let model = self.local_model.as_ref().map(|callable| {
            std::rc::Rc::new(PyLocalModel {
                callable: callable.clone_ref(py),
                raised: RefCell::new(None),
            })
        });
        if let Some(model) = model.clone() {
            let config = SweepConfig::deterministic(
                &self.model_id,
                &self.backend,
                &self.quantization,
                self.seed,
            );
            pipeline = pipeline.with_context(Box::new(ContextualSweep::new(
                RcModel(model),
                config,
            )));
        }

        match pipeline.deidentify(doc) {
            Ok(result) => Ok(project(doc, &result)),
            Err(error) => {
                // The caller's own exception outranks our classification of it.
                if let Some(model) = model {
                    if let Some(raised) = model.raised.borrow_mut().take() {
                        return Err(raised);
                    }
                }
                Err(to_py_err(&error))
            }
        }
    }

    fn __repr__(&self) -> String {
        let tier = match self.tier {
            Tier::SAFE_HARBOR => "SAFE_HARBOR",
            Tier::EXPERT_DETERMINATION => "EXPERT_DETERMINATION",
        };
        format!("Pipeline(tier=Tier.{tier})")
    }
}

impl Pipeline {
    /// The L5 salt for one call.
    ///
    /// NOT A `#[pymethods]` MEMBER: a getter would hand the key material back
    /// to Python, and the salt is the one value in this binding that must not
    /// be readable from the process that holds the document.
    ///
    /// `core/` cannot produce this. It performs no I/O (I1), so it has no route
    /// to an operating-system CSPRNG, and a salt derived from a counter or a
    /// clock is a salt an attacker can reconstruct -- which would make the
    /// surrogate mapping recoverable from the de-identified text alone. Drawing
    /// it is therefore the binding's job, and `getrandom` is the syscall and
    /// nothing else.
    fn salt(&self) -> PyResult<Salt> {
        if let Some(material) = self.salt_key_material.as_ref() {
            return Salt::derive(material)
                .map_err(|error| PyValueError::new_err(error.to_string()));
        }
        let mut key = [0u8; SALT_LEN];
        getrandom::fill(&mut key).map_err(|_| {
            // Fatal rather than a degradation to label placeholders: a run that
            // silently dropped L5 would produce output the caller has to read
            // to discover, which is exactly how this defect shipped once.
            PyValueError::new_err("the operating system entropy source is unavailable")
        })?;
        Ok(Salt::from_bytes(key))
    }
}

/// `ContextualSweep` takes its model by value; the adapter is shared with the
/// error-recovery path, so it is handed over behind an `Rc`.
struct RcModel(std::rc::Rc<PyLocalModel>);

impl LocalModel for RcModel {
    fn generate(&self, prompt: &str, config: &SweepConfig) -> CoreOutcome<String> {
        self.0.generate(prompt, config)
    }
}

/// Flatten a core result into the Python-facing projection.
fn project(doc: &str, result: &CoreResult) -> DeidResult {
    let span_map: Vec<MappedSpan> = result
        .span_map
        .iter()
        .map(|mapped| MappedSpan {
            span: Span {
                start: mapped.span.start(),
                end: mapped.span.end(),
                label: mapped.span.label().to_string(),
                layer: mapped.span.source().to_string(),
                detector: mapped.span.detector_id().to_string(),
                confidence: mapped.span.confidence(),
                checksum_validated: mapped.span.is_checksum_validated(),
            },
            decision: mapped.decision.to_string(),
            replacement: mapped.replacement.clone(),
            output_start: mapped.output_start,
            output_end: mapped.output_end,
        })
        .collect();
    let raw = result
        .span_map
        .iter()
        .map(|mapped| {
            (
                mapped.span.start(),
                mapped.span.end(),
                mapped.output_start,
                mapped.output_end,
            )
        })
        .collect();
    // `redacted()` rather than `entries()`: this projection is what a caller
    // will pickle, print and ship to a compliance reviewer, and an L3 rationale
    // quotes the quasi-identifier it describes (I4).
    let audit = result
        .audit
        .redacted()
        .entries()
        .iter()
        .map(|entry| AuditEntry {
            layer: entry.layer.to_string(),
            label: entry.label.to_string(),
            start: entry.start,
            end: entry.end,
            confidence: entry.confidence,
            decision: entry.decision.to_string(),
        })
        .collect();
    DeidResult {
        doc: doc.to_owned(),
        text: result.text.clone(),
        span_map,
        audit,
        audit_is_redacted: result.audit.is_redacted(),
        raw,
    }
}

/// The exact prompt L3 sends, for a caller wiring their own local runtime.
///
/// THE PROMPT CONTAINS THE WHOLE DOCUMENT. That is inherent to L3 -- the layer
/// reasons over the full note to find meanings rather than tokens -- and it is
/// why the model it goes to must be local. Anything that posts this string has
/// uploaded the clinical note.
#[pyfunction]
fn contextual_prompt(doc: &str) -> String {
    prompt::build(doc)
}

/// The prompt format version, so a cached completion can be pinned to it.
#[pyfunction]
fn contextual_prompt_version() -> u32 {
    prompt::PROMPT_VERSION
}

/// True when every candidate span in a result was masked rather than kept.
#[pyfunction]
fn all_spans_masked(result: &DeidResult) -> bool {
    result
        .span_map
        .iter()
        .all(|mapped| mapped.decision == Decision::Mask.to_string())
}

#[pymodule]
fn _deid_tr(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<Tier>()?;
    module.add_class::<Span>()?;
    module.add_class::<MappedSpan>()?;
    module.add_class::<AuditEntry>()?;
    module.add_class::<DeidResult>()?;
    module.add_class::<Pipeline>()?;
    module.add_function(wrap_pyfunction!(contextual_prompt, module)?)?;
    module.add_function(wrap_pyfunction!(contextual_prompt_version, module)?)?;
    module.add_function(wrap_pyfunction!(all_spans_masked, module)?)?;

    let py = module.py();
    module.add("DeidError", py.get_type::<DeidError>())?;
    module.add("SpanError", py.get_type::<SpanError>())?;
    module.add("OffsetError", py.get_type::<OffsetError>())?;
    module.add("GuardrailError", py.get_type::<GuardrailError>())?;
    module.add(
        "ProtectedSpanDemotionError",
        py.get_type::<ProtectedSpanDemotionError>(),
    )?;
    module.add("ConfigurationError", py.get_type::<ConfigurationError>())?;
    module.add(
        "ContextualLayerMissingError",
        py.get_type::<ContextualLayerMissingError>(),
    )?;
    module.add(
        "ContextualModelError",
        py.get_type::<ContextualModelError>(),
    )?;
    module.add(
        "MalformedContextualResponseError",
        py.get_type::<MalformedContextualResponseError>(),
    )?;
    module.add(
        "LocalModelFailedError",
        py.get_type::<LocalModelFailedError>(),
    )?;
    module.add("SchemaError", py.get_type::<SchemaError>())?;
    Ok(())
}
