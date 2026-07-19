//! The confidence router: which spans are worth arguing about.
//!
//! This stage exists for COST, not for accuracy. L1 and L2 run on every note in
//! about ten milliseconds; the adjudicator is a local model and is orders of
//! magnitude more expensive. So a span is auto-masked whenever the pipeline
//! already has strong evidence for it, and only the low-confidence,
//! single-source minority reaches [`crate::route::adjudicate`].
//!
//! THE DESIGN TARGET WAS 2-5% OF ROUTED CANDIDATES AND THE MEASURED RATE IS
//! 40.0% (268 of 670 on the committed corpus, `crate::route` test module,
//! printed on every run). D-027 corrects the claim and states the
//! qualifications -- chiefly that I8 forbids a checksum-valid TCKN in a
//! fixture, so every committed one escalates, and that L2 is a stub, so
//! nothing is yet multi-detector. The number is REPORTED and not gated on
//! purpose: the two ways to make it look like the claim are lowering
//! [`ESCALATION_CONFIDENCE_MAX`] and raising the confidence L1 emits for a
//! failed checksum, and both are tuning a metric rather than measuring one.
//!
//! Routing is never a recall decision. Every branch here ends in `Mask` or in
//! "ask a question"; none of them ends in `Keep`. Raising
//! [`crate::pipeline::ESCALATION_CONFIDENCE_MAX`] sends more spans to the
//! adjudicator, which is slower but never less safe.

use crate::error::Result;
use crate::pipeline::ESCALATION_CONFIDENCE_MAX;
use crate::route::adjudicate::{adjudicate, Adjudication, Adjudicator, Rationale};
use crate::route::allowlist::MedicalAllowlist;
use crate::span::{Decision, Merged, Span};

/// What the router decided to do with a candidate, before any adjudication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Mask without asking. The reason is recorded so the escalation rate can
    /// be attributed rather than merely counted.
    AutoMask(AutoMaskReason),
    /// Low confidence and a single source: worth the question.
    Escalate,
}

/// Why a span skipped adjudication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoMaskReason {
    /// An arithmetic check passed on the covered bytes. Not inference.
    ChecksumValidated,
    /// More than one DISTINCT detector proposed the region. The strongest
    /// agreement signal the pipeline can produce.
    DetectorAgreement,
    /// One detector, but above the escalation ceiling.
    HighConfidence,
}

/// Route one candidate.
///
/// Reads `is_protected` rather than reconstructing it from `(source,
/// confidence)`: protection is RECORDED by the code that ran the checksum and
/// COUNTED by the merge, and the two derived quantities it used to be inferred
/// from no longer mean what such an inference would assume.
#[must_use]
pub fn route(candidate: &Merged) -> Route {
    if candidate.span().is_checksum_validated() {
        return Route::AutoMask(AutoMaskReason::ChecksumValidated);
    }
    if candidate.support() > 1 {
        return Route::AutoMask(AutoMaskReason::DetectorAgreement);
    }
    if candidate.span().confidence() > ESCALATION_CONFIDENCE_MAX {
        return Route::AutoMask(AutoMaskReason::HighConfidence);
    }
    Route::Escalate
}

/// Counts for one document, so the cost bound is measured and not asserted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoutingStats {
    /// Candidates routed.
    pub total: usize,
    /// Auto-masked because a checksum passed.
    pub checksum_validated: usize,
    /// Auto-masked because detectors agreed.
    pub detector_agreement: usize,
    /// Auto-masked because confidence cleared the ceiling.
    pub high_confidence: usize,
    /// Entered adjudication.
    pub escalated: usize,
    /// Reached the adjudicator MODEL, which is the part that actually costs.
    ///
    /// Strictly fewer than `escalated`: an escalated span that is not on the
    /// allowlist, or whose context decisively marks a person, is settled by
    /// the allowlist lookup alone and never invokes a model.
    pub adjudicator_calls: usize,
    /// Demoted from `Mask` to `Keep`.
    pub demoted: usize,
}

impl RoutingStats {
    /// The fraction of candidates that entered adjudication.
    ///
    /// The denominator is ROUTED CANDIDATES, not vocabulary occurrences and not
    /// documents. D-023 and D-027 report escalation against two different
    /// denominators and the numbers differ by a factor of ten; whoever quotes
    /// this method's output must say which one it is.
    ///
    /// `f64` and not `f32`: this number is reported over a whole corpus, where
    /// `f32` accumulation of a ratio of large counts starts to lie in the third
    /// decimal.
    #[must_use]
    pub fn escalation_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.escalated as f64 / self.total as f64
    }

    /// The fraction of candidates that invoked the adjudicator model.
    #[must_use]
    pub fn adjudication_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.adjudicator_calls as f64 / self.total as f64
    }

    /// Fold another document's counts in.
    pub fn merge(&mut self, other: Self) {
        self.total += other.total;
        self.checksum_validated += other.checksum_validated;
        self.detector_agreement += other.detector_agreement;
        self.high_confidence += other.high_confidence;
        self.escalated += other.escalated;
        self.adjudicator_calls += other.adjudicator_calls;
        self.demoted += other.demoted;
    }

    fn record(&mut self, route: Route) {
        self.total += 1;
        match route {
            Route::AutoMask(AutoMaskReason::ChecksumValidated) => self.checksum_validated += 1,
            Route::AutoMask(AutoMaskReason::DetectorAgreement) => self.detector_agreement += 1,
            Route::AutoMask(AutoMaskReason::HighConfidence) => self.high_confidence += 1,
            Route::Escalate => self.escalated += 1,
        }
    }
}

/// One routed candidate: the span, the decision, and how it was reached.
#[derive(Debug, Clone, PartialEq)]
pub struct Routed {
    /// The span, unchanged. L4 never alters bounds and never invents one.
    pub span: Span,
    /// Mask or Keep.
    pub decision: Decision,
    /// What the router did before adjudication.
    pub route: Route,
    /// Why the decision came out the way it did.
    pub rationale: Rationale,
}

/// L4 end to end: route every candidate, adjudicate only the escalated ones.
///
/// This is the layer's contract from the brief -- input is the union of L1, L2
/// and L3 spans plus the text plus the allowlist, output is a decision per
/// span. The output has exactly one entry per input candidate, in input order:
/// L4 cannot invent a span and the type makes that checkable.
///
/// # Errors
///
/// Propagates [`crate::error::Error::SpanOutOfBounds`] when a candidate does
/// not address `text`, and [`crate::error::Error::ProtectedSpanDemotion`] if a
/// demotion is ever attempted on a protected span.
pub fn route_all(
    text: &str,
    candidates: &[Merged],
    allowlist: &MedicalAllowlist,
    adjudicator: Option<&dyn Adjudicator>,
) -> Result<(Vec<Routed>, RoutingStats)> {
    let mut stats = RoutingStats::default();
    let mut routed = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let route = route(candidate);
        stats.record(route);
        let outcome = match route {
            Route::AutoMask(_) => Adjudication {
                decision: Decision::Mask,
                rationale: Rationale::Protected,
                signals: Vec::new(),
            },
            Route::Escalate => adjudicate(text, candidate, allowlist, adjudicator)?,
        };
        if matches!(
            outcome.rationale,
            Rationale::AdjudicatorAgreed | Rationale::AdjudicatorDisagreed
        ) {
            stats.adjudicator_calls += 1;
        }
        if outcome.decision == Decision::Keep {
            stats.demoted += 1;
        }
        routed.push(Routed {
            span: *candidate.span(),
            decision: outcome.decision,
            route,
            rationale: outcome.rationale,
        });
    }
    Ok((routed, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::EntityLabel;
    use crate::route::allowlist::AllowlistCategory;
    use crate::span::{union_widest, DetectorId, Span};

    const DOC: &str = "Toraks BT'de sol 5. costa'da fraktür; Op. Dr. Andrea Costa değerlendirdi.";

    fn vocabulary() -> MedicalAllowlist {
        MedicalAllowlist::from_sources(&[(AllowlistCategory::Anatomy, "costa\n")])
    }

    fn span_at(needle: &str, detector: DetectorId, confidence: f32) -> Span {
        let start = DOC.find(needle).expect("fixture");
        Span::new(
            DOC,
            start,
            start + needle.len(),
            EntityLabel::PatientName,
            detector,
            confidence,
        )
        .expect("valid span")
    }

    #[test]
    fn a_checksum_validated_span_never_escalates() {
        let start = DOC.find("costa").expect("fixture");
        let span =
            Span::checksum_validated(DOC, start, start + 5, EntityLabel::Tckn).expect("valid span");
        assert_eq!(
            route(&Merged::single(span)),
            Route::AutoMask(AutoMaskReason::ChecksumValidated)
        );
    }

    #[test]
    fn agreement_between_two_detectors_never_escalates() {
        let merged = union_widest(
            DOC,
            &[
                span_at("costa", DetectorId::Ner(0), 0.05),
                span_at("costa", DetectorId::Ner(1), 0.05),
            ],
        )
        .expect("merge");
        assert_eq!(merged[0].support(), 2);
        assert_eq!(
            route(&merged[0]),
            Route::AutoMask(AutoMaskReason::DetectorAgreement)
        );
    }

    #[test]
    fn one_detector_repeating_itself_does_not_buy_its_way_out_of_escalation() {
        // The mirror of the span-algebra test: routing must read the same
        // `support` set the guardrail does, or a retry would look like
        // agreement here even though it does not there.
        let merged = union_widest(
            DOC,
            &[
                span_at("costa", DetectorId::Ner(0), 0.05),
                span_at("costa", DetectorId::Ner(0), 0.05),
            ],
        )
        .expect("merge");
        assert_eq!(merged[0].support(), 1);
        assert_eq!(route(&merged[0]), Route::Escalate);
    }

    #[test]
    fn confidence_above_the_ceiling_auto_masks() {
        let over = Merged::single(span_at("costa", DetectorId::Ner(0), 0.61));
        assert_eq!(
            route(&over),
            Route::AutoMask(AutoMaskReason::HighConfidence)
        );
        let under = Merged::single(span_at("costa", DetectorId::Ner(0), 0.59));
        assert_eq!(route(&under), Route::Escalate);
        // Exactly at the ceiling escalates: the constant is the ESCALATION
        // maximum, so the boundary belongs to the cheaper-to-be-wrong side.
        let at = Merged::single(span_at(
            "costa",
            DetectorId::Ner(0),
            ESCALATION_CONFIDENCE_MAX,
        ));
        assert_eq!(route(&at), Route::Escalate);
    }

    #[test]
    fn the_output_has_exactly_one_decision_per_input_candidate() {
        // L4 may only DEMOTE. It can never invent a span, and the cardinality
        // of the output is where that is checkable.
        let merged = union_widest(
            DOC,
            &[
                span_at("costa", DetectorId::Ner(0), 0.2),
                span_at("Andrea Costa", DetectorId::Ner(0), 0.2),
            ],
        )
        .expect("merge");
        let (routed, stats) = route_all(DOC, &merged, &vocabulary(), None).expect("route");
        assert_eq!(routed.len(), merged.len());
        assert_eq!(stats.total, merged.len());
        for (out, candidate) in routed.iter().zip(&merged) {
            assert_eq!(out.span, *candidate.span());
        }
    }

    #[test]
    fn only_escalated_spans_can_be_demoted() {
        let merged = union_widest(
            DOC,
            &[
                span_at("costa", DetectorId::Ner(0), 0.2),
                span_at("Andrea Costa", DetectorId::Ner(0), 0.9),
            ],
        )
        .expect("merge");
        let (routed, _) = route_all(DOC, &merged, &vocabulary(), None).expect("route");
        for out in &routed {
            if out.decision == Decision::Keep {
                assert_eq!(out.route, Route::Escalate);
            }
        }
    }

    #[test]
    fn stats_report_the_escalation_rate_and_merge_across_documents() {
        let mut stats = RoutingStats::default();
        for _ in 0..96 {
            stats.record(Route::AutoMask(AutoMaskReason::HighConfidence));
        }
        for _ in 0..4 {
            stats.record(Route::Escalate);
        }
        assert_eq!(stats.total, 100);
        assert!((stats.escalation_rate() - 0.04).abs() < 1e-12);

        let mut total = RoutingStats::default();
        total.merge(stats);
        total.merge(stats);
        assert_eq!(total.total, 200);
        assert_eq!(total.escalated, 8);
        assert!((total.escalation_rate() - 0.04).abs() < 1e-12);
        assert!((RoutingStats::default().escalation_rate() - 0.0).abs() < 1e-12);
    }

    #[test]
    fn an_auto_masked_span_never_reaches_the_allowlist_lookup() {
        // The cost argument, stated as a test: `adjudicator_calls` counts the
        // expensive path, and it must stay zero when nothing escalates.
        let merged =
            union_widest(DOC, &[span_at("costa", DetectorId::Ner(0), 0.95)]).expect("merge");
        let (routed, stats) = route_all(DOC, &merged, &vocabulary(), None).expect("route");
        assert_eq!(routed[0].decision, Decision::Mask);
        assert_eq!(stats.escalated, 0);
        assert_eq!(stats.adjudicator_calls, 0);
        assert_eq!(stats.demoted, 0);
    }
}
