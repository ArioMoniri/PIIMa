//! L4 consensus over the escalated spans only.
//!
//! One question: is this real PHI, or a Latin/English medical term, drug or
//! anatomy? Everything the router auto-masked never arrives here, so the cost
//! of this stage is the escalation rate times the cost of one adjudication.
//!
//! THE GUARDRAIL, which is the entire safety property of this layer. L4 may
//! only DEMOTE, `Mask -> Keep`. It may never invent a span; the output is a
//! decision per input candidate and nothing else. It may demote only when the
//! span is on the allowlist AND the context does not independently mark it as a
//! person. A checksum-validated span or a multi-detector-agreed span is never
//! demoted: [`crate::pipeline::demote_to_keep`] returns
//! `Err(ProtectedSpanDemotion)` for those and this module routes every demotion
//! through it rather than reimplementing the check.
//!
//! WHEN IN DOUBT, KEEP MASKING. A missing adjudicator, an undecided verdict and
//! an adjudicator error all land on `Mask`. I2 settles ties in one direction: a
//! missed identifier is a breach, an over-masked term is a papercut.

use core::fmt;

use crate::error::{Error, Result};
use crate::label::EntityLabel;
use crate::pipeline::demote_to_keep;
use crate::route::allowlist::{AllowlistCategory, MedicalAllowlist};
use crate::route::evidence::{Assessment, PersonEvidence, PersonSignal};
use crate::span::{Decision, Merged};

/// How many bytes of document either side of the span the adjudicator sees.
///
/// A window rather than the whole note, because the question is local -- "is
/// this token a person here" -- and because a smaller window is less PHI held
/// in one place. It is a target, not a guarantee: the actual slice is trimmed
/// outward to the nearest UTF-8 character boundary, since Turkish is
/// multi-byte and a window cut mid-`ş` is not a `&str`.
pub const CONTEXT_WINDOW_BYTES: usize = 160;

/// What the adjudicator concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Legitimate class C vocabulary here. The only verdict that can demote.
    MedicalTerm,
    /// A person, place or other identifier. Mask.
    Person,
    /// The adjudicator could not tell. Mask, per I2.
    Undecided,
}

/// One question put to the adjudicator.
///
/// The lifetime is deliberate: this borrows the document rather than owning a
/// copy, so no PHI outlives the call.
#[derive(Clone)]
pub struct AdjudicationQuery<'a> {
    surface: &'a str,
    context: &'a str,
    surface_in_context: (usize, usize),
    label: EntityLabel,
    categories: Vec<AllowlistCategory>,
    signals: Vec<PersonSignal>,
}

/// Hand-written, and this is invariant I4 rather than taste.
///
/// `surface` IS the candidate identifier and `context` is a verbatim window of
/// clinical text. A derived `Debug` would print both, and this type is exactly
/// the value that reaches a `{:?}` in a failing test, a panic message or a
/// binding author's trace. What is safe to print is the shape of the question:
/// lengths, the label, the categories, the signals.
impl fmt::Debug for AdjudicationQuery<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdjudicationQuery")
            .field("surface", &"<redacted>")
            .field("surface_len", &self.surface.len())
            .field("context", &"<redacted>")
            .field("context_len", &self.context.len())
            .field("label", &self.label)
            .field("categories", &self.categories)
            .field("signals", &self.signals)
            .finish()
    }
}

impl<'a> AdjudicationQuery<'a> {
    /// The candidate's covered text.
    #[must_use]
    pub const fn surface(&self) -> &'a str {
        self.surface
    }

    /// A window of surrounding document text.
    #[must_use]
    pub const fn context(&self) -> &'a str {
        self.context
    }

    /// Where `surface` sits inside `context`, in BYTE offsets into `context`.
    #[must_use]
    pub const fn surface_in_context(&self) -> (usize, usize) {
        self.surface_in_context
    }

    /// The label the detector proposed.
    #[must_use]
    pub const fn label(&self) -> EntityLabel {
        self.label
    }

    /// Which allowlist categories the surface matched, if any.
    #[must_use]
    pub fn categories(&self) -> &[AllowlistCategory] {
        &self.categories
    }

    /// The person signals that made this ambiguous rather than settled.
    #[must_use]
    pub fn signals(&self) -> &[PersonSignal] {
        &self.signals
    }
}

/// The consensus step: a local model, or a rule set, that answers one question.
///
/// The implementation MUST be local (I1). It is a trait for the same reason
/// [`crate::pipeline::Contextual`] is: the forward pass is the only part of the
/// pipeline that cannot be single-sourced across native and `wasm32`.
pub trait Adjudicator {
    /// Is the queried surface class C vocabulary, or PHI?
    fn adjudicate(&self, query: &AdjudicationQuery<'_>) -> Result<Verdict>;
}

/// Why L4 decided what it decided.
///
/// Recorded so the escalation rate and the demotion rate are measurable rather
/// than asserted. Carries no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rationale {
    /// Protected: checksum-validated or agreed by several detectors.
    Protected,
    /// Not on the allowlist, so there is no positive reason to believe it is
    /// vocabulary.
    NotVocabulary,
    /// On the allowlist and the context is silent. Demoted deterministically.
    VocabularyUncontested,
    /// On the allowlist, but a title, honorific or name field marks a person.
    PersonEvidenceDecisive,
    /// Escalated, and the adjudicator agreed it is vocabulary.
    AdjudicatorAgreed,
    /// Escalated, and the adjudicator said person or could not tell.
    AdjudicatorDisagreed,
    /// Escalated with no adjudicator installed. Keeps masking.
    AdjudicatorUnavailable,
}

/// The outcome for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjudication {
    /// Mask or Keep.
    pub decision: Decision,
    /// Why.
    pub rationale: Rationale,
    /// The person signals weighed, for the audit trail.
    pub signals: Vec<PersonSignal>,
}

/// Decide one escalated candidate.
///
/// THE ORDER OF THESE CHECKS IS THE ADR. Protection first, so no path can
/// reach a demotion for a checksum-valid or agreed span. Allowlist membership
/// second, because without it there is no argument for demotion at all.
/// Evidence third, and only then the adjudicator -- which is consulted for the
/// ambiguous middle and nothing else.
///
/// # Errors
///
/// [`Error::SpanOutOfBounds`] if the span does not address `text`, and
/// [`Error::ProtectedSpanDemotion`] if a demotion is somehow attempted on a
/// protected span, which is the guardrail firing.
pub fn adjudicate(
    text: &str,
    candidate: &Merged,
    allowlist: &MedicalAllowlist,
    adjudicator: Option<&dyn Adjudicator>,
) -> Result<Adjudication> {
    let span = candidate.span();
    if candidate.is_protected() {
        return Ok(settled(Decision::Mask, Rationale::Protected));
    }
    let surface = text
        .get(span.start()..span.end())
        .ok_or(Error::SpanOutOfBounds {
            offset: span.end(),
            doc_len: text.len(),
        })?;

    let entries = allowlist.lookup(surface);
    if entries.is_empty() {
        // WHY membership is REQUIRED and the adjudicator cannot demote on its
        // own: the allowlist is an audited, append-only artifact that the
        // medical-term FP gate is scored against. Letting a small local model
        // demote a span no list vouches for makes recall a function of model
        // judgment, and I2 puts recall out of reach of that.
        return Ok(settled(Decision::Mask, Rationale::NotVocabulary));
    }

    let evidence = PersonEvidence::gather(text, span.start(), span.end(), allowlist);
    let signals = evidence.signals().to_vec();
    match evidence.assessment() {
        Assessment::Decisive => Ok(Adjudication {
            decision: Decision::Mask,
            rationale: Rationale::PersonEvidenceDecisive,
            signals,
        }),
        Assessment::Absent => Ok(Adjudication {
            decision: demote_to_keep(candidate)?,
            rationale: Rationale::VocabularyUncontested,
            signals,
        }),
        Assessment::Suggestive => {
            let Some(adjudicator) = adjudicator else {
                return Ok(Adjudication {
                    decision: Decision::Mask,
                    rationale: Rationale::AdjudicatorUnavailable,
                    signals,
                });
            };
            let mut categories: Vec<AllowlistCategory> = entries
                .iter()
                .map(super::allowlist::AllowlistEntry::category)
                .collect();
            categories.sort_unstable();
            categories.dedup();
            let (context, offset) = window(text, span.start(), span.end());
            let query = AdjudicationQuery {
                surface,
                context,
                surface_in_context: (span.start() - offset, span.end() - offset),
                label: span.label(),
                categories,
                signals: signals.clone(),
            };
            // An adjudicator that FAILS must not take the document down with
            // it, and must not be able to cause a demotion by failing. The
            // error is swallowed into `Mask`, which is the safe direction.
            let verdict = adjudicator.adjudicate(&query).unwrap_or(Verdict::Undecided);
            match verdict {
                Verdict::MedicalTerm => Ok(Adjudication {
                    decision: demote_to_keep(candidate)?,
                    rationale: Rationale::AdjudicatorAgreed,
                    signals,
                }),
                Verdict::Person | Verdict::Undecided => Ok(Adjudication {
                    decision: Decision::Mask,
                    rationale: Rationale::AdjudicatorDisagreed,
                    signals,
                }),
            }
        }
    }
}

fn settled(decision: Decision, rationale: Rationale) -> Adjudication {
    Adjudication {
        decision,
        rationale,
        signals: Vec::new(),
    }
}

/// A context window around the span, trimmed to character boundaries.
///
/// Returns the window and its byte offset in `text`, so the caller can report
/// where the surface sits inside it without re-searching -- re-searching would
/// find the wrong occurrence whenever the term repeats, which for `costa` in a
/// trauma note is every time.
fn window(text: &str, start: usize, end: usize) -> (&str, usize) {
    let mut from = start.saturating_sub(CONTEXT_WINDOW_BYTES);
    let mut to = (end + CONTEXT_WINDOW_BYTES).min(text.len());
    while from < start && !text.is_char_boundary(from) {
        from += 1;
    }
    while to > end && !text.is_char_boundary(to) {
        to -= 1;
    }
    (text.get(from..to).unwrap_or(""), from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::allowlist::AllowlistCategory;
    use crate::span::{DetectorId, Span};
    use std::cell::RefCell;

    const MODEL_A: DetectorId = DetectorId::Ner(0);

    fn vocabulary() -> MedicalAllowlist {
        MedicalAllowlist::from_sources(&[
            (AllowlistCategory::Anatomy, "costa\ncostae\n"),
            (AllowlistCategory::Drug, "Adalat\nAdalat Crono\nDeva\n"),
        ])
    }

    fn candidate(text: &str, needle: &str, confidence: f32) -> Merged {
        let start = text.find(needle).expect("fixture contains the needle");
        Merged::single(
            Span::new(
                text,
                start,
                start + needle.len(),
                EntityLabel::PatientName,
                MODEL_A,
                confidence,
            )
            .expect("valid span"),
        )
    }

    /// Records what it was asked and answers a fixed verdict.
    struct SpyAdjudicator {
        verdict: Verdict,
        calls: RefCell<usize>,
    }

    impl SpyAdjudicator {
        fn new(verdict: Verdict) -> Self {
            Self {
                verdict,
                calls: RefCell::new(0),
            }
        }
    }

    impl Adjudicator for SpyAdjudicator {
        fn adjudicate(&self, _query: &AdjudicationQuery<'_>) -> Result<Verdict> {
            *self.calls.borrow_mut() += 1;
            Ok(self.verdict)
        }
    }

    struct FailingAdjudicator;

    impl Adjudicator for FailingAdjudicator {
        fn adjudicate(&self, _query: &AdjudicationQuery<'_>) -> Result<Verdict> {
            Err(Error::ContextualLayerMissing)
        }
    }

    fn decide(text: &str, needle: &str) -> Adjudication {
        adjudicate(text, &candidate(text, needle, 0.4), &vocabulary(), None).expect("adjudication")
    }

    #[test]
    fn an_uncontested_vocabulary_term_is_kept() {
        let text = "Toraks BT'de sol 4. ve 5. costa'da fraktür izlendi.";
        let outcome = decide(text, "costa");
        assert_eq!(outcome.decision, Decision::Keep);
        assert_eq!(outcome.rationale, Rationale::VocabularyUncontested);
    }

    #[test]
    fn a_span_that_is_not_vocabulary_is_masked() {
        let text = "Hasta Adı: Adalet Sarıkaya";
        let outcome = decide(text, "Adalet");
        assert_eq!(outcome.decision, Decision::Mask);
        assert_eq!(outcome.rationale, Rationale::NotVocabulary);
    }

    #[test]
    fn decisive_person_evidence_beats_the_allowlist() {
        let text = "Konsültan: Op. Dr. Andrea Costa\n";
        let outcome = decide(text, "Costa");
        assert_eq!(outcome.decision, Decision::Mask);
        assert_eq!(outcome.rationale, Rationale::PersonEvidenceDecisive);
        assert!(outcome.signals.contains(&PersonSignal::TitlePrefix));
    }

    #[test]
    fn an_ambiguous_span_with_no_adjudicator_keeps_masking() {
        // I2 in one test: an unavailable adjudicator must never be an excuse
        // to demote.
        let text = "İlaç kutularını refakatçi kızı Deva Çınar getirmiştir.";
        let outcome = decide(text, "Deva");
        assert_eq!(outcome.decision, Decision::Mask);
        assert_eq!(outcome.rationale, Rationale::AdjudicatorUnavailable);
    }

    #[test]
    fn an_ambiguous_span_is_demoted_only_when_the_adjudicator_agrees() {
        let text = "İlaç kutularını refakatçi kızı Deva Çınar getirmiştir.";
        let allowlist = vocabulary();
        let merged = candidate(text, "Deva", 0.4);

        let agrees = SpyAdjudicator::new(Verdict::MedicalTerm);
        let outcome = adjudicate(text, &merged, &allowlist, Some(&agrees)).expect("run");
        assert_eq!(outcome.decision, Decision::Keep);
        assert_eq!(outcome.rationale, Rationale::AdjudicatorAgreed);
        assert_eq!(*agrees.calls.borrow(), 1);

        for verdict in [Verdict::Person, Verdict::Undecided] {
            let spy = SpyAdjudicator::new(verdict);
            let outcome = adjudicate(text, &merged, &allowlist, Some(&spy)).expect("run");
            assert_eq!(outcome.decision, Decision::Mask);
            assert_eq!(outcome.rationale, Rationale::AdjudicatorDisagreed);
        }
    }

    #[test]
    fn a_failing_adjudicator_masks_rather_than_propagating() {
        let text = "İlaç kutularını refakatçi kızı Deva Çınar getirmiştir.";
        let outcome = adjudicate(
            text,
            &candidate(text, "Deva", 0.4),
            &vocabulary(),
            Some(&FailingAdjudicator),
        )
        .expect("a failing adjudicator must not take the document down");
        assert_eq!(outcome.decision, Decision::Mask);
        assert_eq!(outcome.rationale, Rationale::AdjudicatorDisagreed);
    }

    #[test]
    fn the_adjudicator_is_never_consulted_for_a_settled_span() {
        let allowlist = vocabulary();
        for (text, needle) in [
            ("Toraks BT'de 5. costa'da fraktür.", "costa"),
            ("Konsültan: Op. Dr. Andrea Costa\n", "Costa"),
            ("Hasta Adı: Adalet Sarıkaya", "Adalet"),
        ] {
            let spy = SpyAdjudicator::new(Verdict::Person);
            adjudicate(text, &candidate(text, needle, 0.4), &allowlist, Some(&spy)).expect("run");
            assert_eq!(
                *spy.calls.borrow(),
                0,
                "a settled span reached the adjudicator: {needle}"
            );
        }
    }

    #[test]
    fn a_protected_span_is_masked_without_touching_the_allowlist() {
        let text = "Toraks BT'de sol 4. ve 5. costa'da fraktür izlendi.";
        let start = text.find("costa").expect("fixture");
        let from = |detector| {
            Span::new(
                text,
                start,
                start + "costa".len(),
                EntityLabel::PatientName,
                detector,
                0.2,
            )
            .expect("valid span")
        };
        let merged =
            crate::span::union_widest(text, &[from(DetectorId::Ner(0)), from(DetectorId::Ner(1))])
                .expect("merge");
        assert_eq!(merged[0].support(), 2);
        let outcome = adjudicate(text, &merged[0], &vocabulary(), None).expect("run");
        assert_eq!(outcome.decision, Decision::Mask);
        assert_eq!(outcome.rationale, Rationale::Protected);
    }

    #[test]
    fn the_query_context_locates_the_right_occurrence() {
        // `costa` occurs three times; the window offsets must address the one
        // that was escalated, not the first match in the document.
        let text = "hastanın costa'nın kırığı; ayrıca costa ve costa görüldü.";
        let third = text.rfind("costa").expect("fixture");
        let (context, offset) = window(text, third, third + 5);
        assert_eq!(&context[third - offset..third - offset + 5], "costa");
    }

    #[test]
    fn the_context_window_never_splits_a_turkish_letter() {
        let text = "ş".repeat(400);
        let (context, offset) = window(&text, 200, 202);
        assert!(text.is_char_boundary(offset));
        assert!(!context.is_empty());
    }

    #[test]
    fn debug_on_a_query_never_prints_the_surface_or_the_context() {
        // I4: this type holds the candidate identifier and a verbatim window of
        // clinical text, and it is the value most likely to reach a `{:?}`.
        let text = "İlaç kutularını refakatçi kızı Deva Çınar getirmiştir.";
        let (context, offset) = window(text, 0, 4);
        let query = AdjudicationQuery {
            surface: "Deva",
            context,
            surface_in_context: (0 - offset, 4 - offset),
            label: EntityLabel::PatientName,
            categories: vec![AllowlistCategory::Drug],
            signals: vec![PersonSignal::CapitalisedNeighbour],
        };
        let rendered = format!("{query:?}");
        assert!(!rendered.contains("Deva"));
        assert!(!rendered.contains("Çınar"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("CapitalisedNeighbour"));
    }
}
