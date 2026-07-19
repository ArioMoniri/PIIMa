//! The audit log: what was decided about which bytes, and why.

use core::fmt;

use crate::error::{Error, Result};
use crate::label::EntityLabel;
use crate::span::{Decision, Layer, Span};

/// What a `Debug` rendering prints where a rationale would be.
const REDACTED: &str = "<redacted>";

/// One decision about one span.
///
/// The fields are the offsets and the metadata, never the covered text. An
/// audit log is the artifact most likely to be written to disk, shipped to a
/// compliance reviewer, or attached to a support ticket, so it is designed on
/// the assumption that it will be read by someone who is not allowed to see
/// the document (I4).
#[derive(Clone, PartialEq)]
pub struct AuditEntry {
    /// The layer that proposed the span.
    pub layer: Layer,
    /// The schema label assigned to it.
    pub label: EntityLabel,
    /// Inclusive byte offset into the original document.
    pub start: usize,
    /// Exclusive byte offset into the original document.
    pub end: usize,
    /// Combined confidence at the point of decision.
    pub confidence: f32,
    /// What L4 decided.
    pub decision: Decision,

    /// A model-generated explanation, available for L3 spans only.
    ///
    /// THIS FIELD IS THE ONE UNSAFE THING IN THIS MODULE, which is why it is
    /// private and why every constructor that sets it is fallible. A rationale
    /// is free text written by a language model to justify why a phrase is
    /// re-identifying, and the most natural way for a model to write that
    /// sentence is to QUOTE THE PHRASE -- "flagged because the patient is
    /// described as the spouse of a well-known judge in <district>". That
    /// sentence is the quasi-identifier it was describing.
    ///
    /// Rules therefore: a rationale is retained only in memory, only for the
    /// interactive review path, and must be reviewed by a human before it is
    /// persisted or transmitted anywhere. Every logging, export or telemetry
    /// path takes [`AuditLog::redacted`] first, which strips rationales
    /// unconditionally. Nothing in this crate writes one to a sink.
    rationale: Option<String>,
}

/// Hand-written so that `{:?}` can never egress a rationale.
///
/// WHY this is not `#[derive(Debug)]`: a derived Debug renders every field,
/// including the LLM free text that quotes the quasi-identifier verbatim. An
/// audit entry reaches stderr, then a log aggregator, then a bug report, then a
/// support ticket -- and a panic message in a binding renders it without anyone
/// choosing to. The one derive attribute would make every one of those paths a
/// PHI egress, which is exactly the "breach with a `#[derive(Debug)]` on it"
/// that `error.rs` refuses to be (I4).
///
/// Everything else stays visible. Offsets, labels, layers, confidences and
/// decisions are what makes an audit log worth having, and none of them is PHI.
/// The rationale renders as the literal `<redacted>` unconditionally, so the
/// rendering does not vary with whether one is present either.
impl fmt::Debug for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEntry")
            .field("layer", &self.layer)
            .field("label", &self.label)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("confidence", &self.confidence)
            .field("decision", &self.decision)
            .field("rationale", &format_args!("{REDACTED}"))
            .finish()
    }
}

impl AuditEntry {
    /// Record a decision with no rationale.
    pub fn new(span: &Span, decision: Decision) -> Self {
        Self {
            layer: span.source(),
            label: span.label(),
            start: span.start(),
            end: span.end(),
            confidence: span.confidence(),
            decision,
            rationale: None,
        }
    }

    /// Record a decision with an L3 rationale attached.
    ///
    /// Fails for any other layer. L1 has nothing to explain -- a checksum
    /// either passed or it did not -- and L2 emits logits, not sentences, so a
    /// rationale on a non-L3 span means text has been attached to a span by
    /// something that had no business generating text.
    pub fn with_rationale(span: &Span, decision: Decision, rationale: String) -> Result<Self> {
        if span.source() != Layer::Context {
            return Err(Error::RationaleNotPermitted {
                layer: span.source(),
            });
        }
        Ok(Self {
            rationale: Some(rationale),
            ..Self::new(span, decision)
        })
    }

    /// The rationale, if this entry carries one.
    pub fn rationale(&self) -> Option<&str> {
        self.rationale.as_deref()
    }

    /// True when this entry carries model-generated free text.
    pub fn has_rationale(&self) -> bool {
        self.rationale.is_some()
    }

    /// A copy with the rationale removed.
    pub fn redacted(&self) -> Self {
        Self {
            rationale: None,
            ..self.clone()
        }
    }
}

/// The ordered record of every decision taken over one document.
#[derive(Clone, Default, PartialEq)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

/// Hand-written for the same reason as [`AuditEntry`]'s, and not left to the
/// derive even though the derive would delegate correctly today: the guarantee
/// has to survive someone adding a field to this struct later.
impl fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog")
            .field("entries", &self.entries)
            .finish()
    }
}

impl AuditLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a decision.
    pub fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    /// Every recorded decision, in the order taken.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Number of recorded decisions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The view every logging, export and persistence path must use.
    ///
    /// Strips all rationales. Offsets, labels, layers, confidences and
    /// decisions survive, which is everything a compliance reviewer needs to
    /// audit the pipeline's behaviour and nothing an attacker needs to
    /// reconstruct the patient.
    pub fn redacted(&self) -> Self {
        Self {
            entries: self.entries.iter().map(AuditEntry::redacted).collect(),
        }
    }

    /// True when no entry carries model-generated free text.
    pub fn is_redacted(&self) -> bool {
        !self.entries.iter().any(AuditEntry::has_rationale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::DetectorId;

    const DOC: &str = "Eşi tanınmış bir hâkim.";

    fn context_span() -> Span {
        Span::new(
            DOC,
            0,
            DOC.find(" bir").expect("fixture"),
            EntityLabel::Quasi(crate::label::QuasiCategory::RelationshipRef),
            DetectorId::Context,
            0.72,
        )
        .expect("valid span")
    }

    fn rules_span() -> Span {
        Span::checksum_validated(DOC, 0, 3, EntityLabel::Tckn).expect("valid span")
    }

    #[test]
    fn an_entry_records_offsets_and_metadata() {
        let span = rules_span();
        let entry = AuditEntry::new(&span, Decision::Mask);
        assert_eq!(entry.start, span.start());
        assert_eq!(entry.end, span.end());
        assert_eq!(entry.label, EntityLabel::Tckn);
        assert_eq!(entry.layer, Layer::Rules);
        assert_eq!(entry.decision, Decision::Mask);
        assert!(!entry.has_rationale());
    }

    #[test]
    fn only_the_contextual_layer_may_attach_a_rationale() {
        let allowed = AuditEntry::with_rationale(
            &context_span(),
            Decision::Mask,
            "spouse described by a distinguishing public role".to_owned(),
        )
        .expect("L3 may explain itself");
        assert!(allowed.has_rationale());

        assert_eq!(
            AuditEntry::with_rationale(&rules_span(), Decision::Mask, "checksum".to_owned()),
            Err(Error::RationaleNotPermitted {
                layer: Layer::Rules
            })
        );
    }

    #[test]
    fn redacted_strips_every_rationale_but_keeps_the_decisions() {
        let mut log = AuditLog::new();
        log.record(AuditEntry::new(&rules_span(), Decision::Mask));
        log.record(
            AuditEntry::with_rationale(
                &context_span(),
                Decision::Mask,
                "quotes the identifying phrase".to_owned(),
            )
            .expect("L3 rationale"),
        );
        assert!(!log.is_redacted());

        let redacted = log.redacted();
        assert_eq!(redacted.len(), log.len());
        assert!(redacted.is_redacted());
        assert!(redacted.entries().iter().all(|e| e.rationale().is_none()));
        for (before, after) in log.entries().iter().zip(redacted.entries()) {
            assert_eq!((before.start, before.end), (after.start, after.end));
            assert_eq!(before.decision, after.decision);
            assert_eq!(before.label, after.label);
        }
    }

    /// A rationale that quotes the quasi-identifier, which is what a model
    /// actually writes. Synthetic (I8).
    const QUOTED_PHI: &str = "spouse is a well-known judge in Kadıköy";

    #[test]
    fn debug_on_an_entry_never_prints_the_rationale() {
        let entry =
            AuditEntry::with_rationale(&context_span(), Decision::Mask, QUOTED_PHI.to_owned())
                .expect("L3 rationale");
        let rendered = format!("{entry:?}");
        assert!(
            !rendered.contains(QUOTED_PHI),
            "Debug egressed the rationale"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("Mask"), "the decision must stay visible");
    }

    #[test]
    fn debug_on_a_log_never_prints_a_rationale() {
        let mut log = AuditLog::new();
        log.record(AuditEntry::new(&rules_span(), Decision::Mask));
        log.record(
            AuditEntry::with_rationale(&context_span(), Decision::Mask, QUOTED_PHI.to_owned())
                .expect("L3 rationale"),
        );
        let rendered = format!("{log:?}");
        assert!(
            !rendered.contains(QUOTED_PHI),
            "Debug on a log egressed the rationale"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("Tckn"), "labels must stay visible");
    }

    #[test]
    fn a_fresh_log_is_empty_and_redacted() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert!(log.is_redacted());
    }
}
