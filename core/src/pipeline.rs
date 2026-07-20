//! The orchestrator: the one place the six layers are composed.
//!
//! The aggregation rules are the architecture and the detectors are replaceable
//! parts, so the rules live here and nothing below is allowed to invent its own.
//! There are exactly two, one per error type:
//!
//! * **L1 + L2 + L3 UNION, for recall.** Every layer proposes independently,
//!   nothing is filtered on the way in, and [`union_widest`] drops nothing --
//!   including a span exactly one detector saw. A converging council that
//!   majority-votes a lone proposal away is a breach machine (I2).
//! * **L4 CONSENSUS, for precision**, over already-flagged spans only. It may
//!   only ever move `Mask -> Keep`, never invent, and never touch a
//!   checksum-validated or multi-detector-agreed span.
//!
//! L5 then replaces the masked bytes and the span map records both offset
//! systems, which is what makes the rewrite reversible.
//!
//! # What lives outside this crate, and why
//!
//! Three seams cross the `core/` boundary: [`Detector`] (the L2 forward pass),
//! [`Tokenizer`] (L2's vocabulary) and [`Contextual`] (the L3 local model).
//! All three are traits because all three need a file or a runtime, and `core/`
//! performs no I/O and has no network dependency (I1). Everything else --
//! rules, span algebra, BIOES decode, allowlist, adjudication, surrogates,
//! audit -- is single-sourced here and compiles to `wasm32`, so the browser
//! build runs the same pipeline as the CLI.

use core::fmt;

use crate::audit::{AuditEntry, AuditLog};
use crate::detect::{NerEnsemble, NerError, Normalization, Normalized, Tokenized};
use crate::error::{DetectionFailure, Error, RedactionFailure, Result, SurrogateFailure};
use crate::redact::{HashKey, RedactionMethod, RedactionPolicy, Redactor, Rendered};
use crate::route::{route_all, Adjudicator, MedicalAllowlist, Rationale, RoutingStats};
use crate::span::{union_widest, Decision, Merged, Span};
use crate::surrogate::{SurrogateEngine, SurrogateError};

/// The assurance tier, which is a legal standard made into a product setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    /// Remove the 18 enumerated direct identifiers. L1 + L2 + L4 + L5.
    ///
    /// The default, because it is the tier that runs everywhere including the
    /// browser and because the expensive tier trades readability for privacy.
    /// Opting into that trade is the caller's decision to make explicitly.
    #[default]
    SafeHarbor,
    /// Adds L3, the full-document local-LLM contextual sweep.
    ExpertDetermination,
}

/// L2: one fine-tuned token classifier.
///
/// Inference is behind a trait because the forward pass is the only part of
/// the pipeline that cannot be single-sourced across targets -- `ort` dropped
/// `wasm32-unknown-unknown`, so the browser needs a different implementation
/// of exactly this and nothing else. Rules, span algebra, decode and
/// surrogates stay in this crate for every target.
pub trait Detector {
    /// Per-token label logits for a tokenized document.
    fn infer(&self, ids: &[u32]) -> Result<Vec<Vec<f32>>>;
}

/// L2's vocabulary, which is a file and therefore not this crate's business.
///
/// Takes the NORMALISED text and returns ids paired with byte offsets INTO THAT
/// NORMALISED TEXT. Both halves of that sentence are load-bearing: the model
/// sees whatever [`Normalization`] the ensemble was configured with, and
/// [`Normalized`] owns the index that maps those offsets back onto the
/// original document. A tokenizer that reported offsets into the original would
/// be reporting them against a string the model never saw, and after an İ/ı
/// fold the two strings differ.
pub trait Tokenizer {
    /// Encode the normalised document.
    fn encode(&self, normalized: &str) -> Result<Tokenized>;
}

/// L3: the contextual sweep over the whole document.
///
/// The implementation MUST be a local model. Sending clinical text to a cloud
/// LLM in order to find the PHI in it defeats the entire purpose of the tool
/// (I1), which is why this trait takes the document by reference and lives
/// behind a crate with no network dependency.
pub trait Contextual {
    /// Quasi-identifier spans found by reasoning over the whole document.
    fn sweep(&self, doc: &str) -> Result<Vec<Span>>;
}

/// L1: deterministic regex plus checksum rules.
///
/// Re-exported here so the orchestrator seam still names every layer it
/// composes in one place. The implementation is `core/src/rules/`.
pub use crate::rules::RuleSet;

/// A layer-local L2 failure, flattened for a caller that only speaks
/// [`Error`].
///
/// WHY THE CONVERSION LIVES AT THE SEAM and not in `detect/`: `NerError` is
/// deliberately layer-local -- it names logit widths and detector indices,
/// which are meaningful to whoever is wiring a checkpoint and noise to everyone
/// else. The orchestrator is the boundary where that detail stops being
/// actionable, so it is the boundary where the classification is taken and the
/// numbers are dropped. `NerError::Span` is passed through unchanged rather
/// than reclassified: it is already a crate error that happened to travel
/// through L2, and wrapping it would hide an offset bug behind a layer name.
impl From<NerError> for Error {
    fn from(error: NerError) -> Self {
        let kind = match error {
            NerError::Span(inner) => return inner,
            NerError::LogitRowCount { .. } => DetectionFailure::LogitRowCount,
            NerError::LogitWidth { .. } => DetectionFailure::LogitWidth,
            NerError::NonFiniteLogit { .. } => DetectionFailure::NonFiniteLogit,
            NerError::TokenSpanCount { .. } => DetectionFailure::TokenSpanCount,
            NerError::TokenSpanNotAligned { .. } => DetectionFailure::TokenSpanNotAligned,
            NerError::TooManyDetectors { .. } => DetectionFailure::TooManyDetectors,
            NerError::WordIndexOutOfRange { .. } => DetectionFailure::WordIndexOutOfRange,
            NerError::EmptyScheme => DetectionFailure::EmptyScheme,
        };
        Self::DetectionFailed { kind }
    }
}

/// The same flattening for the redaction layer.
///
/// `SpanOutOfBounds` and the nested `SurrogateError` are passed through rather
/// than reclassified, for the same reason `NerError::Span` is: an offset defect
/// or a pool exhaustion renamed "redaction failure" is a defect nobody will
/// look for where it actually is. `OverlappingSpans` is unreachable on this
/// path -- the pipeline renders one span at a time and its candidates come out
/// of `union_widest` already non-overlapping -- and is mapped to the offset
/// error rather than given a variant that could never be observed.
impl From<crate::redact::RedactError> for Error {
    fn from(error: crate::redact::RedactError) -> Self {
        use crate::redact::RedactError as R;
        let kind = match error {
            R::Surrogate(inner) => return inner.into(),
            R::SpanOutOfBounds { offset, doc_len } => {
                return Self::SpanOutOfBounds { offset, doc_len }
            }
            R::OverlappingSpans {
                left_start,
                left_end,
                ..
            } => {
                return Self::SpanNotOrdered {
                    start: left_start,
                    end: left_end,
                }
            }
            R::HashKeyRequired => RedactionFailure::HashKeyRequired,
            R::SurrogateEngineRequired { .. } => RedactionFailure::SurrogateEngineRequired,
            R::HashKeyTooShort { .. } => RedactionFailure::HashKeyTooShort,
            R::BlackoutWidthOutOfRange { .. } | R::BlackoutFillNotVisible => {
                RedactionFailure::BlackoutRejected
            }
        };
        Self::RedactionFailed { kind }
    }
}

/// The same flattening for L5.
///
/// `SurrogateError::SpanOutOfBounds` is passed through for the same reason
/// `NerError::Span` is: it is an offset defect, and an offset defect renamed
/// "surrogate failure" is an offset defect nobody will look for.
impl From<SurrogateError> for Error {
    fn from(error: SurrogateError) -> Self {
        let kind = match error {
            SurrogateError::SpanOutOfBounds { offset, doc_len } => {
                return Self::SpanOutOfBounds { offset, doc_len }
            }
            SurrogateError::KeyMaterialTooShort { .. } => SurrogateFailure::KeyMaterialTooShort,
            SurrogateError::OverlappingSpans { .. } => SurrogateFailure::OverlappingSpans,
            SurrogateError::Exhausted { .. } => SurrogateFailure::PoolExhausted,
        };
        Self::SurrogateFailed { kind }
    }
}

/// One span as it appears in both the original and the de-identified text.
///
/// The output offsets are what makes the map a round-trip table: masking
/// changes byte lengths, so a caller re-identifying a masked document cannot
/// derive them from the input offsets.
#[derive(Clone, PartialEq)]
pub struct MappedSpan {
    /// The span in the ORIGINAL document.
    pub span: Span,
    /// What L4 decided.
    pub decision: Decision,
    /// Why L4 decided it. Counts and classifications, never text.
    pub rationale: Rationale,
    /// The text substituted, when the decision was to mask. Not PHI.
    pub replacement: Option<String>,
    /// The redaction method actually applied, when the decision was to mask.
    ///
    /// RECORDED RATHER THAN INFERRED FROM THE POLICY, because the policy states
    /// what was asked for and this states what happened -- and the two differ on
    /// `DateShift` against a non-date label. A caller auditing a run needs the
    /// second number, not the first.
    pub applied_method: Option<RedactionMethod>,
    /// Inclusive byte offset in the OUTPUT text.
    pub output_start: usize,
    /// Exclusive byte offset in the OUTPUT text.
    pub output_end: usize,
    /// THE PHI. Private, and readable only through [`MappedSpan::original`],
    /// so every read is a place a reviewer can point at.
    ///
    /// It has to be here: re-identification is impossible without remembering
    /// which original stood where the surrogate stands, and a `text_hash` is a
    /// one-way function. That makes a span map a document-equivalent secret --
    /// local, never logged, never persisted by this crate.
    original: String,
}

/// Hand-written so `{:?}` can never egress an original (I4).
///
/// Same construction and same reason as `AuditEntry`'s and `SurrogateEntry`'s.
/// The offsets, the label, the decision and the surrogate stay visible: they
/// are what makes the map debuggable and none of them is the identifier. The
/// original renders as a fixed literal, so the rendering does not vary with its
/// length either -- printing `original: 11 bytes` would leak the length tell
/// that the whole of L5 exists to destroy.
impl fmt::Debug for MappedSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappedSpan")
            .field("span", &self.span)
            .field("decision", &self.decision)
            .field("rationale", &self.rationale)
            .field("replacement", &self.replacement)
            .field("applied_method", &self.applied_method)
            .field("output_start", &self.output_start)
            .field("output_end", &self.output_end)
            .field("original", &format_args!("<redacted>"))
            .finish()
    }
}

impl MappedSpan {
    /// The original text this span covered.
    ///
    /// PHI. Every caller of this is holding an identifier and is responsible
    /// for it.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }
}

/// The output of one de-identification run.
#[derive(Clone, PartialEq)]
pub struct DeidResult {
    /// The de-identified document.
    pub text: String,
    /// The round-trip table. Local, never logged, never transmitted.
    pub span_map: Vec<MappedSpan>,
    /// What was decided and why.
    pub audit: AuditLog,
    /// How many candidates took which path through L4.
    ///
    /// Counts only, so this is the one part of the result that is safe to log.
    /// It is here because the escalation rate is the claim that makes the Safe
    /// Harbor tier cheap, and a bound nobody measures is a hope -- which is
    /// exactly what the 2-5% in the brief turned out to be. Measured over the
    /// committed corpus it is 40.0% of routed candidates (D-027).
    pub routing: RoutingStats,
}

/// Hand-written because this struct contains an [`AuditLog`], which can carry
/// an LLM rationale that quotes the quasi-identifier verbatim, and a span map,
/// which holds every original.
///
/// WHY it matters here specifically: `DeidResult` is the value every binding
/// hands back, so it is the value most likely to appear in a `{:?}`, in an
/// `assert_eq!` failure, or in a panic message. Deriving Debug on it would
/// egress PHI through a path nobody deliberately took (I4). The delegation to
/// [`AuditLog`]'s and [`MappedSpan`]'s own Debug is what redacts.
impl fmt::Debug for DeidResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeidResult")
            .field("text", &self.text)
            .field("span_map", &self.span_map)
            .field("audit", &self.audit)
            .field("routing", &self.routing)
            .finish()
    }
}

impl DeidResult {
    /// Put the originals back, reversing this run exactly.
    ///
    /// THE POINT OF THE SPAN MAP, and the property M2's gateway depends on: a
    /// model answers about the de-identified text, and the clinician has to
    /// read the answer about their own patient. Walking `output_start` rather
    /// than recomputing offsets is what makes it exact -- a surrogate
    /// deliberately does not preserve the original's length, so every
    /// replacement shifts everything after it and no arithmetic on the input
    /// offsets can recover the output ones.
    ///
    /// Kept spans are copied through untouched: their output bytes ARE their
    /// original bytes, so substituting them would be a no-op that only risks
    /// getting the offsets wrong.
    #[must_use]
    pub fn reidentify(&self) -> String {
        let mut out = String::with_capacity(self.text.len());
        let mut cursor = 0usize;
        for mapped in &self.span_map {
            if mapped.decision != Decision::Mask {
                continue;
            }
            // `get` rather than indexing: this method is infallible by
            // contract, and a map that has been edited by hand must degrade to
            // a wrong string rather than to a panic in a clinical tool.
            let Some(prefix) = self.text.get(cursor..mapped.output_start) else {
                continue;
            };
            out.push_str(prefix);
            out.push_str(&mapped.original);
            cursor = mapped.output_end;
        }
        if let Some(tail) = self.text.get(cursor..) {
            out.push_str(tail);
        }
        out
    }
}

/// Above this confidence a span is masked without adjudication.
///
/// The router exists for cost, not for accuracy: L1 and L2 run on every note,
/// but the adjudicator is expensive, so only the small minority of low
/// confidence single-source spans is escalated. Raising this constant sends
/// more spans to the adjudicator, which is slower but never less safe;
/// lowering it is a recall decision and needs an ADR.
pub const ESCALATION_CONFIDENCE_MAX: f32 = 0.60;

/// The L4 guardrail, as a checked function.
///
/// L4 exists to argue down false positives, so it may only ever move
/// `Mask -> Keep`. It can never invent a span, and it can never demote one
/// that is protected: a checksum-validated identifier is arithmetic rather
/// than inference, and independent agreement between detectors is the
/// strongest evidence the pipeline produces.
///
/// A refusal is an `Err`, deliberately, rather than a silent no-op. If an
/// adjudicator believes it kept a span that was actually masked, the guardrail
/// and the caller disagree about what happened, and a guardrail nobody can
/// observe failing is a guardrail that has already rotted.
pub fn demote_to_keep(candidate: &Merged) -> Result<Decision> {
    if candidate.is_protected() {
        let span = candidate.span();
        return Err(Error::ProtectedSpanDemotion {
            start: span.start(),
            end: span.end(),
            label: span.label(),
            layer: span.source(),
        });
    }
    Ok(Decision::Keep)
}

/// The de-identification pipeline.
///
/// No `Debug`: it holds a [`SurrogateEngine`], which holds a salt.
pub struct Pipeline {
    rules: RuleSet,
    ensemble: NerEnsemble,
    tokenizer: Option<Box<dyn Tokenizer>>,
    normalization: Normalization,
    context: Option<Box<dyn Contextual>>,
    allowlist: MedicalAllowlist,
    adjudicator: Option<Box<dyn Adjudicator>>,
    surrogate: Option<SurrogateEngine>,
    redaction: Option<RedactionPolicy>,
    hash_key: Option<HashKey>,
    tier: Tier,
}

impl Pipeline {
    /// A pipeline at the given tier: L1 and L4 only, with the audited class C
    /// vocabulary already installed.
    ///
    /// Every other layer is absent rather than stubbed, and absent means
    /// "proposes nothing" rather than "guesses". A pipeline with no ensemble
    /// and no contextual layer still de-identifies every direct identifier L1
    /// can prove, which is the honest floor.
    ///
    /// THE ALLOWLIST IS NOT OPTIONAL HERE, and that is a deliberate reversal.
    /// This constructor used to install `MedicalAllowlist::new()` -- an EMPTY
    /// vocabulary -- and leave it to each binding to call
    /// [`Self::with_allowlist`]. No binding did, so every shipped binary ran L4
    /// with nothing to consult and the entire D-010/D-023 collision resolution
    /// was dead code outside the test harness. A default that is safe only when
    /// the caller remembers something is a default that is unsafe. The
    /// vocabulary is compiled in (`crate::route::vocabulary`), so this costs no
    /// I/O and cannot fail; a caller with their own vocabulary still overrides
    /// it with [`Self::with_allowlist`], and a caller who genuinely wants none
    /// says so with [`Self::without_medical_allowlist`].
    #[must_use]
    pub fn new(tier: Tier) -> Self {
        Self {
            rules: RuleSet,
            ensemble: NerEnsemble::new(),
            tokenizer: None,
            normalization: Normalization::default(),
            context: None,
            allowlist: crate::route::vocabulary::bundled().clone(),
            adjudicator: None,
            surrogate: None,
            redaction: None,
            hash_key: None,
            tier,
        }
    }

    /// Strip the class C vocabulary out of L4.
    ///
    /// NAMED FOR WHAT IT COSTS. Without a vocabulary, L4 has no deterministic
    /// answer to "is this a Latin medical term or a person?", so `carcinoma`,
    /// `costa` and `Adalat` are masked whenever any detector proposes them and
    /// the note stops saying what it said. That is a readability catastrophe,
    /// not a privacy one -- I2's ordering means it can never be the reverse --
    /// which is precisely why it must be typed out rather than reached by
    /// forgetting a builder call.
    #[must_use]
    pub fn without_medical_allowlist(mut self) -> Self {
        self.allowlist = MedicalAllowlist::new();
        self
    }

    /// Install the L2 ensemble.
    #[must_use]
    pub fn with_ensemble(mut self, ensemble: NerEnsemble) -> Self {
        self.ensemble = ensemble;
        self
    }

    /// Install L2's tokenizer, and the normalization the checkpoints expect.
    ///
    /// The two arrive together because they are one decision: a checkpoint
    /// trained on İ/ı-folded text needs both a tokenizer built for that
    /// vocabulary and the matching fold, and setting one without the other
    /// silently feeds the model text it was not trained on.
    #[must_use]
    pub fn with_tokenizer(
        mut self,
        tokenizer: Box<dyn Tokenizer>,
        normalization: Normalization,
    ) -> Self {
        self.tokenizer = Some(tokenizer);
        self.normalization = normalization;
        self
    }

    /// Install the L3 contextual layer. Must be a LOCAL model (I1).
    #[must_use]
    pub fn with_context(mut self, context: Box<dyn Contextual>) -> Self {
        self.context = Some(context);
        self
    }

    /// Install the class C medical vocabulary L4 consults.
    #[must_use]
    pub fn with_allowlist(mut self, allowlist: MedicalAllowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Install L4's consensus model. Must be LOCAL (I1).
    ///
    /// Optional, and its absence is safe by construction: with no adjudicator
    /// an ambiguous span keeps masking (`Rationale::AdjudicatorUnavailable`),
    /// so the missing model costs precision and never recall.
    #[must_use]
    pub fn with_adjudicator(mut self, adjudicator: Box<dyn Adjudicator>) -> Self {
        self.adjudicator = Some(adjudicator);
        self
    }

    /// Install L5, keyed by a caller-supplied salt.
    ///
    /// Without it, a masked span is replaced by its LABEL rather than by a
    /// format-preserving surrogate. That fallback is safe -- it reveals the
    /// entity type and nothing else -- but it is not L5, and the difference is
    /// visible in the output rather than assumed: `core/` cannot generate a
    /// salt because it has no CSPRNG (I1), so an engine is something a binding
    /// hands in, never something this crate quietly invents from a counter.
    #[must_use]
    pub fn with_surrogates(mut self, surrogate: SurrogateEngine) -> Self {
        self.surrogate = Some(surrogate);
        self
    }

    /// Choose what happens to a masked span, PER ENTITY TYPE.
    ///
    /// Without this the pipeline applies one method to everything: surrogates
    /// when L5 is installed, the label placeholder when it is not. That is the
    /// right default and it cannot express what a real deployment wants --
    /// names masked so a clinician sees that a name stood there, dates shifted
    /// so research intervals survive, IBANs removed because a bank account has
    /// no clinical value. See [`RedactionPolicy`].
    ///
    /// SELECTING A METHOD DOES NOT INSTALL ITS DEPENDENCIES. A policy naming
    /// [`RedactionMethod::Hash`] needs [`Self::with_hash_key`] and one naming
    /// [`RedactionMethod::Surrogate`] or [`RedactionMethod::DateShift`] needs
    /// [`Self::with_surrogates`]; without them `deidentify` returns
    /// [`Error::RedactionFailed`] rather than silently applying something else.
    #[must_use]
    pub fn with_redaction_policy(mut self, policy: RedactionPolicy) -> Self {
        self.redaction = Some(policy);
        self
    }

    /// Install the key [`RedactionMethod::Hash`] needs.
    ///
    /// `core/` cannot generate one -- it has no CSPRNG (I1) -- so the key
    /// arrives from a binding or it does not exist.
    #[must_use]
    pub fn with_hash_key(mut self, key: HashKey) -> Self {
        self.hash_key = Some(key);
        self
    }

    /// The redaction policy in force, INCLUDING the implicit default.
    ///
    /// Returned by value rather than by reference because the default is
    /// DERIVED from whether L5 is installed rather than stored. A caller
    /// auditing a configuration needs the effective policy, not the one that
    /// was typed.
    #[must_use]
    pub fn redaction_policy(&self) -> RedactionPolicy {
        self.redaction.clone().unwrap_or_else(|| {
            // The behaviour that predates this seam, written out as a policy so
            // there is exactly ONE rendering path in the crate: surrogates when
            // an engine is installed, the label placeholder when it is not.
            // `Mask` renders `[LABEL]`, byte-identical to the old placeholder.
            RedactionPolicy::new(if self.surrogate.is_some() {
                RedactionMethod::Surrogate
            } else {
                RedactionMethod::Mask
            })
        })
    }

    /// The configured tier.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        self.tier
    }

    /// The L2 ensemble.
    #[must_use]
    pub const fn ensemble(&self) -> &NerEnsemble {
        &self.ensemble
    }

    /// The class C allowlist L4 consults.
    #[must_use]
    pub const fn allowlist(&self) -> &MedicalAllowlist {
        &self.allowlist
    }

    /// The L5 surrogate engine, if one is installed.
    #[must_use]
    pub const fn surrogate(&self) -> Option<&SurrogateEngine> {
        self.surrogate.as_ref()
    }

    /// De-identify a document.
    ///
    /// # Errors
    ///
    /// [`Error::ContextualLayerMissing`] or [`Error::TokenizerMissing`] when a
    /// configured tier or layer cannot run, whatever a layer itself returns,
    /// and [`Error::ProtectedSpanDemotion`] if the L4 guardrail ever fires.
    pub fn deidentify(&self, doc: &str) -> Result<DeidResult> {
        let proposals = self.propose(doc)?;
        let merged = union_widest(doc, &proposals)?;
        self.apply(doc, &merged)
    }

    /// L1 + L2 + L3, combined by UNION.
    ///
    /// Every layer contributes independently and nothing is filtered here.
    /// Anything flagged by any layer reaches the merge, and the merge drops
    /// nothing -- that is the whole recall argument (I2). In particular the
    /// three extends are unconditional appends: there is no path on which one
    /// layer's proposal suppresses another's.
    fn propose(&self, doc: &str) -> Result<Vec<Span>> {
        let mut proposals = self.rules.detect(doc);
        proposals.extend(self.ner_spans(doc)?);

        if self.tier == Tier::ExpertDetermination {
            // Failing loudly beats degrading to Safe Harbor in silence: a
            // caller who asked for Expert Determination would otherwise
            // receive an unswept document that looks like a swept one.
            let context = self.context.as_ref().ok_or(Error::ContextualLayerMissing)?;
            proposals.extend(context.sweep(doc)?);
        }
        Ok(proposals)
    }

    /// L2, when an ensemble is configured.
    ///
    /// RAW PER-DETECTOR PROPOSALS, via [`NerEnsemble::propose`] rather than
    /// [`NerEnsemble::detect`]. The distinction is the L4 guardrail: `detect`
    /// merges inside L2, and a merge keeps only the dominant parent's detector
    /// id, so five agreeing members would arrive here as one id, `support`
    /// would count 1, and the span the whole ensemble agreed on would become
    /// demotable. Layers propose; the orchestrator merges exactly once.
    fn ner_spans(&self, doc: &str) -> Result<Vec<Span>> {
        if self.ensemble.is_empty() {
            return Ok(Vec::new());
        }
        let tokenizer = self.tokenizer.as_ref().ok_or(Error::TokenizerMissing)?;
        let normalized = Normalized::new(doc, self.normalization);
        let tokenized = tokenizer.encode(normalized.text())?;
        Ok(self.ensemble.propose(&normalized, &tokenized)?)
    }

    /// Rewrite the document and build the round-trip map and audit log.
    ///
    /// L4 runs over the WHOLE candidate set in one call rather than per span,
    /// because the routing statistics are a property of the document and
    /// accumulating them here would be a second copy of the router's own
    /// bookkeeping.
    fn apply(&self, doc: &str, merged: &[Merged]) -> Result<DeidResult> {
        let (routed, routing) =
            route_all(doc, merged, &self.allowlist, self.adjudicator.as_deref())?;

        let mut text = String::with_capacity(doc.len());
        let mut span_map = Vec::with_capacity(routed.len());
        let mut audit = AuditLog::new();
        let mut cursor = 0usize;
        // One assigner for the whole document, which is what makes the same
        // entity get the same surrogate everywhere in it (L5 property (b)).
        let mut assigner = self.surrogate.as_ref().map(SurrogateEngine::assigner);

        // Policy and redactor are built once per document, so the per-entity
        // method lookup is a map read and the effective default is computed in
        // exactly one place.
        let policy = self.redaction_policy();
        let mut redactor = Redactor::new(&policy);
        if let Some(key) = self.hash_key.as_ref() {
            redactor = redactor.with_hash_key(key);
        }

        for outcome in &routed {
            let span = outcome.span;
            let original = slice(doc, span.start(), span.end())?;
            text.push_str(slice(doc, cursor, span.start())?);

            let output_start = text.len();
            let rendered = match outcome.decision {
                Decision::Mask => {
                    Some(redactor.replacement_for(span.label(), original, assigner.as_mut())?)
                }
                Decision::Keep => None,
            };
            match rendered.as_ref() {
                Some(Rendered { replacement, .. }) => text.push_str(replacement),
                None => text.push_str(original),
            }
            let output_end = text.len();

            cursor = span.end();
            audit.record(AuditEntry::new(&span, outcome.decision));
            span_map.push(MappedSpan {
                span,
                decision: outcome.decision,
                rationale: outcome.rationale,
                applied_method: rendered.as_ref().map(|r| r.applied),
                replacement: rendered.map(|r| r.replacement),
                output_start,
                output_end,
                original: original.to_owned(),
            });
        }
        text.push_str(slice(doc, cursor, doc.len())?);

        Ok(DeidResult {
            text,
            span_map,
            audit,
            routing,
        })
    }
}

/// Slice without panicking on a bad range.
fn slice(doc: &str, start: usize, end: usize) -> Result<&str> {
    doc.get(start..end).ok_or(Error::SpanOutOfBounds {
        offset: end,
        doc_len: doc.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::{EntityLabel, QuasiCategory};
    use crate::span::{union_widest, DetectorId, Layer, CHECKSUM_CONFIDENCE};
    use std::cell::Cell;
    use std::rc::Rc;

    /// Synthetic quasi-identifier prose.
    const DOC: &str = "Hasta Merkez Bankası'nda çalışıyor.";

    /// Counts how many times L3 was asked to sweep.
    struct SpyContextual {
        calls: Rc<Cell<usize>>,
        spans: Vec<Span>,
    }

    impl Contextual for SpyContextual {
        fn sweep(&self, _doc: &str) -> Result<Vec<Span>> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.spans.clone())
        }
    }

    fn employer_span(confidence: f32) -> Span {
        let start = DOC.find("Merkez").expect("fixture");
        let end = start + "Merkez Bankası".len();
        Span::new(
            DOC,
            start,
            end,
            EntityLabel::Quasi(QuasiCategory::EmployerRole),
            DetectorId::Context,
            confidence,
        )
        .expect("valid span")
    }

    /// A narrower proposal over the same employer phrase, from a chosen
    /// detector, so agreement can be BUILT rather than asserted.
    fn quasi_span(detector: DetectorId, confidence: f32) -> Span {
        let start = DOC.find("Merkez").expect("fixture");
        let end = start + "Merkez".len();
        Span::new(
            DOC,
            start,
            end,
            EntityLabel::Quasi(QuasiCategory::EmployerRole),
            detector,
            confidence,
        )
        .expect("valid span")
    }

    fn spy(spans: Vec<Span>) -> (Rc<Cell<usize>>, Box<dyn Contextual>) {
        let calls = Rc::new(Cell::new(0));
        let layer = SpyContextual {
            calls: Rc::clone(&calls),
            spans,
        };
        (calls, Box::new(layer))
    }

    #[test]
    fn safe_harbor_never_invokes_the_contextual_layer() {
        let (calls, context) = spy(vec![employer_span(0.9)]);
        let pipeline = Pipeline::new(Tier::SafeHarbor).with_context(context);
        let result = pipeline.deidentify(DOC).expect("safe harbor run");
        assert_eq!(calls.get(), 0, "L3 ran in the Safe Harbor tier");
        assert_eq!(
            result.text, DOC,
            "no layer proposed a span, so nothing masks"
        );
        assert!(result.span_map.is_empty());
    }

    #[test]
    fn expert_determination_invokes_the_contextual_layer() {
        let (calls, context) = spy(vec![employer_span(0.9)]);
        let pipeline = Pipeline::new(Tier::ExpertDetermination).with_context(context);
        let result = pipeline.deidentify(DOC).expect("expert determination run");
        assert_eq!(calls.get(), 1);
        assert_eq!(result.span_map.len(), 1);
    }

    #[test]
    fn expert_determination_without_a_contextual_layer_fails_loudly() {
        let pipeline = Pipeline::new(Tier::ExpertDetermination);
        assert_eq!(
            pipeline.deidentify(DOC),
            Err(Error::ContextualLayerMissing),
            "silently degrading to Safe Harbor would hand back an unswept document"
        );
    }

    #[test]
    fn a_configured_ensemble_without_a_tokenizer_fails_loudly() {
        // The same argument one layer down. An ensemble that proposed nothing
        // because nothing could turn the document into ids would hand back a
        // document that looks L2-swept and was never seen by L2.
        use crate::detect::{LabelSet, MockDetector};
        let ensemble = NerEnsemble::new()
            .with_member(
                Box::new(MockDetector::default()),
                LabelSet::new(&[EntityLabel::PatientName]),
            )
            .expect("one member");
        let pipeline = Pipeline::new(Tier::SafeHarbor).with_ensemble(ensemble);
        assert_eq!(pipeline.deidentify(DOC), Err(Error::TokenizerMissing));
    }

    #[test]
    fn the_default_tier_is_safe_harbor() {
        assert_eq!(Tier::default(), Tier::SafeHarbor);
        assert_eq!(Pipeline::new(Tier::default()).tier(), Tier::SafeHarbor);
    }

    #[test]
    fn masking_rewrites_at_byte_offsets_and_records_the_round_trip() {
        let span = employer_span(0.9);
        let (_, context) = spy(vec![span]);
        let pipeline = Pipeline::new(Tier::ExpertDetermination).with_context(context);
        let result = pipeline.deidentify(DOC).expect("run");

        // The suffix `'nda` survives on the far side of a multi-byte `ı`,
        // which only happens if the rewrite used byte offsets throughout.
        assert_eq!(result.text, "Hasta [EMPLOYER_ROLE]'nda çalışıyor.");

        let mapped = result.span_map.first().expect("one mapped span");
        assert_eq!(mapped.decision, Decision::Mask);
        assert_eq!(mapped.span.start(), span.start());
        assert_eq!(mapped.span.end(), span.end());
        assert_eq!(mapped.replacement.as_deref(), Some("[EMPLOYER_ROLE]"));
        assert_eq!(mapped.original(), "Merkez Bankası");
        assert_eq!(
            result.text.get(mapped.output_start..mapped.output_end),
            Some("[EMPLOYER_ROLE]"),
            "output offsets must address the replacement in the OUTPUT text"
        );
        assert_eq!(result.reidentify(), DOC);
    }

    #[test]
    fn every_decision_reaches_the_audit_log_without_a_rationale() {
        let (_, context) = spy(vec![employer_span(0.9)]);
        let pipeline = Pipeline::new(Tier::ExpertDetermination).with_context(context);
        let result = pipeline.deidentify(DOC).expect("run");
        assert_eq!(result.audit.len(), 1);
        assert!(result.audit.is_redacted());
        let entry = result.audit.entries().first().expect("one entry");
        assert_eq!(entry.decision, Decision::Mask);
        assert_eq!(entry.layer, Layer::Context);
    }

    #[test]
    fn a_single_source_low_confidence_span_can_be_demoted() {
        let candidate = Merged::single(employer_span(0.25));
        assert!(!candidate.is_protected());
        assert_eq!(demote_to_keep(&candidate), Ok(Decision::Keep));
    }

    #[test]
    fn a_checksum_valid_span_can_never_be_demoted() {
        let span = Span::checksum_validated(DOC, 0, 5, EntityLabel::Tckn).expect("valid span");
        assert!((span.confidence() - CHECKSUM_CONFIDENCE).abs() < f32::EPSILON);
        let candidate = Merged::single(span);
        assert!(candidate.is_protected());
        assert_eq!(
            demote_to_keep(&candidate),
            Err(Error::ProtectedSpanDemotion {
                start: 0,
                end: 5,
                label: EntityLabel::Tckn,
                layer: Layer::Rules,
            }),
            "refusal must be an error, not a silent no-op"
        );
    }

    #[test]
    fn a_span_agreed_by_multiple_detectors_can_never_be_demoted() {
        // Built by merging real proposals rather than by writing the support
        // count into a literal: the guardrail must be shown reacting to
        // evidence the merge counted, not to a number a test handed it.
        let merged = union_widest(
            DOC,
            &[quasi_span(DetectorId::Ner(0), 0.2), employer_span(0.2)],
        )
        .expect("merge");
        let candidate = &merged[0];
        assert_eq!(candidate.support(), 2);
        assert!(candidate.is_protected());
        assert!(matches!(
            demote_to_keep(candidate),
            Err(Error::ProtectedSpanDemotion { .. })
        ));
    }

    #[test]
    fn a_protected_span_is_masked_without_consulting_the_adjudicator() {
        let merged = union_widest(
            DOC,
            &[
                quasi_span(DetectorId::Ner(0), 0.1),
                quasi_span(DetectorId::Ner(1), 0.1),
                employer_span(0.1),
            ],
        )
        .expect("merge");
        assert_eq!(merged[0].support(), 3);
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let result = pipeline.apply(DOC, &merged).expect("apply");
        assert_eq!(result.span_map[0].decision, Decision::Mask);
        assert_eq!(result.span_map[0].rationale, Rationale::Protected);
        assert_eq!(result.routing.escalated, 0);
    }

    #[test]
    fn two_ensemble_members_at_identical_bounds_cannot_be_demoted() {
        // The end-to-end statement of the L4 guardrail: exact boundary
        // agreement between two DIFFERENT models is the strongest signal the
        // pipeline produces, and it must reach `demote_to_keep` as a refusal.
        let start = DOC.find("Merkez").expect("fixture");
        let end = start + "Merkez Bankası".len();
        let from = |detector| {
            Span::new(DOC, start, end, EntityLabel::PatientName, detector, 0.3).expect("valid span")
        };
        let merged = union_widest(DOC, &[from(DetectorId::Ner(0)), from(DetectorId::Ner(1))])
            .expect("merge");
        assert_eq!(merged[0].support(), 2);
        assert!(matches!(
            demote_to_keep(&merged[0]),
            Err(Error::ProtectedSpanDemotion { .. })
        ));

        // The same model twice is not corroboration and stays demotable.
        let alone = union_widest(DOC, &[from(DetectorId::Ner(0)), from(DetectorId::Ner(0))])
            .expect("merge");
        assert_eq!(alone[0].support(), 1);
        assert_eq!(demote_to_keep(&alone[0]), Ok(Decision::Keep));
    }

    #[test]
    fn debug_on_a_result_never_prints_a_rationale_or_an_original() {
        // WHY a test and not a review note: `DeidResult` is what every binding
        // returns, so it is the value most likely to reach a `{:?}`, a failing
        // assertion or a panic message. Deriving Debug on it would egress the
        // LLM's verbatim quote of the quasi-identifier AND every original in
        // the span map (I4).
        const QUOTED_PHI: &str = "works at the Merkez Bankası branch in Kadıköy";
        let mut audit = AuditLog::new();
        audit.record(
            AuditEntry::with_rationale(&employer_span(0.9), Decision::Mask, QUOTED_PHI.to_owned())
                .expect("L3 rationale"),
        );
        let result = DeidResult {
            text: "Hasta [EMPLOYER_ROLE]'nda çalışıyor.".to_owned(),
            span_map: vec![MappedSpan {
                span: employer_span(0.9),
                decision: Decision::Mask,
                rationale: Rationale::Protected,
                applied_method: Some(RedactionMethod::Mask),
                replacement: Some("[EMPLOYER_ROLE]".to_owned()),
                output_start: 6,
                output_end: 21,
                original: "Merkez Bankası".to_owned(),
            }],
            audit,
            routing: RoutingStats::default(),
        };
        let rendered = format!("{result:?}");
        assert!(
            !rendered.contains(QUOTED_PHI),
            "Debug on a DeidResult egressed the rationale"
        );
        assert!(
            !rendered.contains("Merkez Bankası"),
            "Debug on a DeidResult egressed a span map original"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("EMPLOYER_ROLE"),
            "the de-identified text must stay visible"
        );
    }

    #[test]
    fn the_rules_layer_is_live_in_the_safe_harbor_path() {
        // M1's end-to-end statement: L1 runs inside `deidentify`, its spans
        // reach the union, and a checksum-validated identifier is masked
        // WITHOUT consulting the adjudicator. The TCKN is built here at
        // runtime, never written into this file (I8).
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let doc = format!("Hasta Ayşe Yılmaz, TCKN {tckn}, tel 0(532) 000 00 00.");
        let result = Pipeline::new(Tier::SafeHarbor)
            .deidentify(&doc)
            .expect("safe harbor run");

        assert!(!result.text.contains(&tckn), "the TCKN survived masking");
        assert!(result.text.contains("[TCKN]"));
        assert!(result.text.contains("[PHONE]"));
        // The Turkish name is still there: no ensemble is configured, and L1
        // does not guess at names. Recording it so the boundary stays honest.
        assert!(result.text.contains("Ayşe Yılmaz"));

        let masked = result
            .span_map
            .iter()
            .find(|m| m.span.label() == EntityLabel::Tckn)
            .expect("the TCKN reached the span map");
        assert_eq!(masked.decision, Decision::Mask);
        assert_eq!(masked.rationale, Rationale::Protected);
        assert!(masked.span.is_checksum_validated());
        assert_eq!(masked.span.source(), Layer::Rules);
        assert!(Merged::single(masked.span).is_protected());
        assert_eq!(&doc[masked.span.start()..masked.span.end()], tckn);
        assert_eq!(result.reidentify(), doc);
    }

    #[test]
    fn the_redaction_policy_is_honoured_per_entity_type_through_the_pipeline() {
        // The seam this exists for: one run, two entity types, two methods.
        // L1 proves both identifiers, so this exercises the shipped path rather
        // than a hand-built span set.
        use crate::redact::Blackout;
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let doc = format!("TCKN {tckn}, tel 0(532) 000 00 00.");
        let policy = RedactionPolicy::new(RedactionMethod::Mask).with(
            EntityLabel::Tckn,
            RedactionMethod::Redact(Blackout::new('#', 6).expect("valid blackout")),
        );
        let result = Pipeline::new(Tier::SafeHarbor)
            .with_redaction_policy(policy)
            .deidentify(&doc)
            .expect("run");

        assert!(!result.text.contains(&tckn), "the TCKN survived masking");
        assert!(result.text.contains("######"));
        assert!(result.text.contains("[PHONE]"));

        let method = |label| {
            result
                .span_map
                .iter()
                .find(|m| m.span.label() == label)
                .and_then(|m| m.applied_method)
        };
        assert_eq!(
            method(EntityLabel::Tckn),
            Some(RedactionMethod::Redact(
                Blackout::new('#', 6).expect("valid blackout")
            ))
        );
        assert_eq!(method(EntityLabel::Phone), Some(RedactionMethod::Mask));
        assert_eq!(result.reidentify(), doc);
    }

    #[test]
    fn a_policy_naming_hash_without_a_key_fails_rather_than_hashing_unkeyed() {
        // The whole reason the key exists: an unkeyed digest of a short Turkish
        // name is brute-forceable by enumeration, and a silent fallback to one
        // produces output that looks identical.
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let doc = format!("TCKN {tckn}.");
        assert_eq!(
            Pipeline::new(Tier::SafeHarbor)
                .with_redaction_policy(RedactionPolicy::new(RedactionMethod::Hash))
                .deidentify(&doc),
            Err(Error::RedactionFailed {
                kind: RedactionFailure::HashKeyRequired
            })
        );
        // With a key installed the same run succeeds and the token is keyed.
        let token = |byte: u8| {
            Pipeline::new(Tier::SafeHarbor)
                .with_redaction_policy(RedactionPolicy::new(RedactionMethod::Hash))
                .with_hash_key(HashKey::from_bytes([byte; crate::redact::HASH_KEY_LEN]))
                .deidentify(&doc)
                .expect("run")
                .text
        };
        assert!(!token(1).contains(&tckn));
        assert_ne!(token(1), token(2), "the digest did not depend on the key");
        assert_eq!(token(1), token(1));
    }

    #[test]
    fn the_default_policy_is_the_behaviour_that_predates_the_seam() {
        // No policy, no engine: the label placeholder, exactly as before.
        assert_eq!(
            Pipeline::new(Tier::SafeHarbor)
                .redaction_policy()
                .default_method(),
            RedactionMethod::Mask
        );
        // No policy, engine installed: surrogates, exactly as before.
        assert_eq!(
            Pipeline::new(Tier::SafeHarbor)
                .with_surrogates(SurrogateEngine::new(crate::surrogate::Salt::from_bytes(
                    [3u8; crate::surrogate::SALT_LEN]
                )))
                .redaction_policy()
                .default_method(),
            RedactionMethod::Surrogate
        );
    }

    #[test]
    fn an_absent_layer_proposes_nothing_rather_than_guessing() {
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        assert!(pipeline.ensemble().is_empty());
        assert!(pipeline.surrogate().is_none());
        // The class C vocabulary is the ONE capability the default constructor
        // does install, because its absence is not the safe direction: with no
        // vocabulary L4 masks `carcinoma` and the note stops saying what it
        // said. Absence here is what shipped for the whole of M4 and made the
        // collision tests unreachable from every binary.
        assert!(pipeline.allowlist().contains("carcinoma"));
        // The opt-out exists, is spelled out, and is the only way to get the
        // old behaviour.
        let bare = Pipeline::new(Tier::SafeHarbor).without_medical_allowlist();
        assert!(!bare.allowlist().contains("carcinoma"));
    }

    #[test]
    fn a_layer_local_detection_failure_loses_its_numbers_at_the_seam() {
        // I4 at the boundary: the layer error names a detector index and a row
        // count, and neither survives into the crate-wide error a binding logs.
        assert_eq!(
            Error::from(NerError::LogitRowCount {
                detector: 3,
                rows: 2,
                tokens: 7,
            }),
            Error::DetectionFailed {
                kind: DetectionFailure::LogitRowCount
            }
        );
        // An offset defect is passed through rather than renamed, or nobody
        // would look for it where it actually is.
        let inner = Error::SpanNotOrdered { start: 5, end: 5 };
        assert_eq!(Error::from(NerError::Span(inner.clone())), inner);
    }
}
