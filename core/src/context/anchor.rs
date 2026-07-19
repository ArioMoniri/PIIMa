//! THE HALLUCINATION FILTER.
//!
//! A language model asked to quote a document will sometimes quote a document
//! it invented. The quote reads plausibly, it is in the right register, it
//! names a plausible employer -- and it is not in the note. If such a claim
//! became a span, the pipeline would mask bytes chosen by a model's imagination
//! and leave the real phrase standing. This module is the single point where a
//! model's claim is converted into a fact about the document, and it converts
//! by SEARCHING RATHER THAN TRUSTING: every quote is re-located verbatim in the
//! original text, and a quote that is not found is dropped.
//!
//! WHY THE MATCH IS EXACT AND WHY IT WILL STAY EXACT. The obvious improvement
//! is a fuzzy match: a quote differing by one character is "clearly" the same
//! phrase, so align it and take the closest region. That improvement is a
//! defect, and a dangerous one. A near-match resolves to a span the model did
//! not report, so the pipeline masks a region nobody verified while REPORTING
//! that it masked the model's finding -- the audit trail becomes false, and a
//! one-character difference near a boundary silently shifts the span onto the
//! neighbouring token. The failure modes are not symmetric. Dropping a quote
//! loses one contextual finding, which the L6 red team measures as a re-ID
//! rate. Anchoring a quote to the wrong bytes masks the wrong text AND leaves
//! the identifier in place, which is a breach plus a corruption, and neither is
//! visible in any metric. So: exact, or dropped.
//!
//! WHY EVERY OCCURRENCE IS ANCHORED, NOT JUST THE FIRST. A quote that appears
//! twice in a note is re-identifying twice. Masking the first and leaving the
//! second is a leak with a clean audit log, so the resolution rule is "all
//! occurrences, scanned left to right, non-overlapping" rather than the more
//! obvious "leftmost". It is fully deterministic -- same document, same
//! findings, same spans, same order -- and it errs in the direction I2 requires.
//! The alternative, matching one occurrence per finding and pairing repeats
//! with repeats, needs the model to report a repeat it usually does not report,
//! and fails closed in the wrong direction when it does not.

use core::fmt;

use crate::audit::AuditEntry;
use crate::error::Result;
use crate::label::{EntityLabel, QuasiCategory};
use crate::span::{Decision, DetectorId, Span};

use super::parse::Finding;

/// The confidence an L3 span carries.
///
/// DELIBERATELY BELOW [`ESCALATION_CONFIDENCE_MAX`], which is what keeps L4
/// able to argue an L3 span down. A single local model asserting that a phrase
/// narrows the candidate population is the weakest evidence this pipeline
/// produces: there is no checksum, no second model, and no annotator-defined
/// denominator to measure it against. Raising this above the escalation ceiling
/// would auto-mask every contextual finding, which is over-masking narrative
/// prose -- the readability cost the Expert Determination tier already warns
/// about, applied without review. A contextual span still reaches the output
/// unless L4 actively demotes it, so this number costs no recall.
///
/// [`ESCALATION_CONFIDENCE_MAX`]: crate::pipeline::ESCALATION_CONFIDENCE_MAX
pub const CONTEXTUAL_CONFIDENCE: f32 = 0.55;

/// A model finding that has been proven to exist in the document.
///
/// The span is the fact; the rationale is the model's account of it. They are
/// kept together because the audit log needs both and the [`Contextual`] trait
/// can only return spans.
///
/// [`Contextual`]: crate::pipeline::Contextual
#[derive(Clone, PartialEq)]
pub struct AnchoredFinding {
    span: Span,
    category: QuasiCategory,
    rationale: String,
}

/// Hand-written, like every `Debug` on a type that can hold model free text.
/// The rationale is the sentence in which the model explains why a phrase
/// identifies someone, and the natural way to write that sentence is to quote
/// the phrase (I4).
impl fmt::Debug for AnchoredFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnchoredFinding")
            .field("category", &self.category)
            .field("start", &self.span.start())
            .field("end", &self.span.end())
            .field("rationale", &format_args!("<redacted>"))
            .finish()
    }
}

impl AnchoredFinding {
    /// The verified span, in original-document byte offsets.
    #[must_use]
    pub const fn span(&self) -> &Span {
        &self.span
    }

    /// The quasi-identifier category the model assigned.
    #[must_use]
    pub const fn category(&self) -> QuasiCategory {
        self.category
    }

    /// The model's one-line reason. In memory only; see [`AuditEntry`].
    #[must_use]
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// The audit entry for this finding, carrying the rationale.
    ///
    /// Fallible only because [`AuditEntry::with_rationale`] refuses a rationale
    /// from any layer but L3; every span built here is `DetectorId::Context`,
    /// so the error is unreachable in practice and is propagated rather than
    /// unwrapped so that it stays unreachable if that ever changes.
    pub fn audit_entry(&self, decision: Decision) -> Result<AuditEntry> {
        AuditEntry::with_rationale(&self.span, decision, self.rationale.clone())
    }
}

/// Re-locate every finding in the original document, dropping what is not there.
///
/// `body` MUST be the exact string that was put in the prompt. Anchoring
/// against a normalised or trimmed copy would produce offsets into a document
/// the caller does not hold, which is the offset-drift failure the whole
/// project is built to avoid.
pub fn anchor(body: &str, findings: &[Finding]) -> Result<Vec<AnchoredFinding>> {
    let mut anchored = Vec::new();
    for finding in findings {
        let quote = finding.quote();
        let mut from = 0usize;
        while let Some(rest) = body.get(from..) {
            let Some(offset) = rest.find(quote) else {
                break;
            };
            let start = from + offset;
            let end = start + quote.len();
            // `str::find` returns a char-boundary offset and the quote's own
            // length lands on one too, so `Span::new`'s boundary check cannot
            // fail here -- it is still run, because the alternative is trusting
            // an argument instead of checking a value.
            let span = Span::new(
                body,
                start,
                end,
                EntityLabel::Quasi(finding.category()),
                DetectorId::Context,
                CONTEXTUAL_CONFIDENCE,
            )?;
            anchored.push(AnchoredFinding {
                span,
                category: finding.category(),
                rationale: finding.reason().to_owned(),
            });
            // Non-overlapping: advance past the match. A self-overlapping quote
            // ("aa" in "aaa") therefore yields one span, not two, which is the
            // conservative direction -- the two candidate spans would overlap
            // and the union would merge them into the same bytes anyway.
            from = end;
        }
    }
    Ok(anchored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::ESCALATION_CONFIDENCE_MAX;
    use crate::span::Layer;

    /// Synthetic Turkish narrative. No real PHI (I8).
    const BODY: &str = "Hasta Merkez Bankası'nda müfettiş olarak çalışıyor. \
Eşi ilçedeki tek kadın hâkim. Yazlığı Bodrum'da.";

    /// Build findings from (quote, category) pairs without going near a model.
    fn findings_of(pairs: &[(&str, QuasiCategory)]) -> Vec<Finding> {
        let mut json = String::from("[");
        for (index, (quote, category)) in pairs.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            json.push_str("{\"quote\": \"");
            json.push_str(quote);
            json.push_str("\", \"category\": \"");
            json.push_str(category.as_str());
            json.push_str("\", \"reason\": \"gerekçe\"}");
        }
        json.push(']');
        crate::context::parse::findings(&json).expect("fixture json must parse")
    }

    #[test]
    fn a_real_quote_anchors_to_the_correct_byte_offsets() {
        let quote = "Merkez Bankası'nda müfettiş olarak çalışıyor";
        let anchored =
            anchor(BODY, &findings_of(&[(quote, QuasiCategory::EmployerRole)])).expect("anchor");
        assert_eq!(anchored.len(), 1);
        let span = anchored[0].span();
        assert_eq!(
            BODY.get(span.start()..span.end()),
            Some(quote),
            "the span must address the quote in the ORIGINAL bytes"
        );
        // Byte offsets, not char indices. `ı` and `ş` are two bytes each, so a
        // caller who measured the quote in CHARACTERS and used that as a byte
        // length would stop short of the end and land inside a letter.
        let as_if_chars_were_bytes = span.start() + quote.chars().count();
        assert!(
            as_if_chars_were_bytes < span.end(),
            "a char count used as a byte length must truncate the span"
        );
        assert_eq!(span.source(), Layer::Context);
        assert_eq!(
            span.label(),
            EntityLabel::Quasi(QuasiCategory::EmployerRole)
        );
    }

    #[test]
    fn a_hallucinated_quote_is_dropped() {
        // The model invents a plausible employer that is nowhere in the note.
        // It must produce no span at all -- not a nearby span, not a span at
        // offset zero, nothing.
        let invented = "Ziraat Bankası'nda şube müdürü";
        assert!(!BODY.contains(invented));
        let anchored = anchor(
            BODY,
            &findings_of(&[(invented, QuasiCategory::EmployerRole)]),
        )
        .expect("anchor");
        assert!(anchored.is_empty());
    }

    #[test]
    fn a_quote_differing_by_one_character_is_dropped_and_not_fuzzy_matched() {
        // THE test that pins the design decision in the module header. The
        // model wrote `s` where the note has `ş` -- one character, and exactly
        // the kind of transliteration drift a model trained mostly on English
        // produces. Fuzzy matching would anchor it to the real phrase, and the
        // audit log would then claim the model reported something it did not.
        let almost = "Merkez Bankası'nda müfettis olarak çalışıyor";
        assert!(!BODY.contains(almost));
        let anchored =
            anchor(BODY, &findings_of(&[(almost, QuasiCategory::EmployerRole)])).expect("anchor");
        assert!(
            anchored.is_empty(),
            "a near-match anchored: fuzzy matching masks the wrong span"
        );
    }

    #[test]
    fn a_casing_difference_is_a_difference() {
        // Casing is the strongest name signal in Turkish and the one thing
        // naive normalisation destroys: İ/I and i/ı are four distinct letters,
        // so a model that "helpfully" lowercases has changed the text, not
        // tidied it. A case-insensitive match here would accept that silently
        // and hand back a span over bytes the model never saw.
        let folded = "eşi ilçedeki tek kadın hâkim";
        assert!(!BODY.contains(folded), "fixture must differ only in casing");
        let anchored = anchor(
            BODY,
            &findings_of(&[(folded, QuasiCategory::RelationshipRef)]),
        )
        .expect("anchor");
        assert!(anchored.is_empty());
    }

    #[test]
    fn a_quote_occurring_twice_anchors_at_every_occurrence_in_order() {
        let twice = "Hastanın işi: kondüktör. Sonra yine kondüktör olarak geçti.";
        let anchored = anchor(
            twice,
            &findings_of(&[("kondüktör", QuasiCategory::EmployerRole)]),
        )
        .expect("anchor");
        assert_eq!(anchored.len(), 2, "the second occurrence leaks if dropped");
        let first = anchored[0].span();
        let second = anchored[1].span();
        assert!(
            first.start() < second.start(),
            "order must be left to right"
        );
        assert!(!first.overlaps(second));
        for span in [first, second] {
            assert_eq!(twice.get(span.start()..span.end()), Some("kondüktör"));
        }
        // Deterministic: the same inputs give the same offsets every time.
        let again = anchor(
            twice,
            &findings_of(&[("kondüktör", QuasiCategory::EmployerRole)]),
        )
        .expect("anchor");
        assert_eq!(anchored, again);
    }

    #[test]
    fn a_self_overlapping_quote_yields_one_span_per_non_overlapping_match() {
        let repeated = "aaa";
        let anchored = anchor(
            repeated,
            &findings_of(&[("aa", QuasiCategory::RareAttributeCombo)]),
        )
        .expect("anchor");
        assert_eq!(anchored.len(), 1);
        assert_eq!(
            (anchored[0].span().start(), anchored[0].span().end()),
            (0, 2)
        );
    }

    #[test]
    fn an_anchored_span_stays_demotable_by_the_adjudicator() {
        let anchored = anchor(
            BODY,
            &findings_of(&[("Yazlığı Bodrum'da", QuasiCategory::AssetLocation)]),
        )
        .expect("anchor");
        let span = anchored[0].span();
        assert!(
            span.confidence() <= ESCALATION_CONFIDENCE_MAX,
            "a lone LLM assertion must remain arguable by L4"
        );
        assert!(!span.is_checksum_validated());
    }

    #[test]
    fn the_rationale_reaches_the_audit_log_and_never_a_debug_rendering() {
        let anchored = anchor(
            BODY,
            &findings_of(&[(
                "Eşi ilçedeki tek kadın hâkim",
                QuasiCategory::RelationshipRef,
            )]),
        )
        .expect("anchor");
        let entry = anchored[0]
            .audit_entry(Decision::Mask)
            .expect("an L3 span may carry a rationale");
        assert_eq!(entry.rationale(), Some("gerekçe"));
        assert_eq!(entry.layer, Layer::Context);

        let rendered = format!("{:?}", anchored[0]);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("gerekçe"));
        assert!(!rendered.contains("hâkim"));
    }

    #[test]
    fn nothing_in_nothing_out() {
        assert!(anchor(BODY, &[]).expect("anchor").is_empty());
        assert!(
            anchor("", &findings_of(&[("x", QuasiCategory::EmployerRole)]))
                .expect("anchor")
                .is_empty()
        );
    }
}
