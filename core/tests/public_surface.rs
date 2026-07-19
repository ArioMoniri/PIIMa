//! What a caller OUTSIDE this crate can actually do with a [`Span`].
//!
//! WHY this file exists rather than another `mod tests` block: an in-crate test
//! module is a child of the crate and inherits its privileges. It can write
//! `Span { checksum_validated: true, ..other }` whether or not the field is
//! private, so it can never observe the difference between "the constructor
//! validates" and "the constructor is the only way in". Every re-audit finding
//! about the public API surface stayed invisible for exactly that reason. An
//! integration test compiles as a separate crate against the published surface
//! only, which is the vantage point a binding author and a downstream user
//! actually occupy.
//!
//! LIMIT OF THIS FILE, stated so nobody mistakes it for the stronger claim: a
//! test can only assert about code that compiles. It cannot assert that a
//! struct literal is REJECTED, because a rejected literal is a compile error
//! and this file would not build. A `trybuild` compile-fail suite expresses
//! that directly -- it asserts on rustc's diagnostics -- and it is the right
//! tool here. It is not used because adding the dependency means fetching a
//! crate over the network, which this task may not do. What the file below
//! asserts instead is the observable consequence: every span a caller can
//! obtain satisfies the invariants, and no reachable path produces a protected
//! span the caller did not earn. If the fields were made public again, every
//! assertion here would still pass while the guarantee was gone -- so treat
//! this as a floor and replace it with `trybuild` the next time the dependency
//! set is allowed to grow.

use deid_tr_core::error::Error;
use deid_tr_core::pipeline::demote_to_keep;
use deid_tr_core::span::{union_widest, CHECKSUM_CONFIDENCE};
use deid_tr_core::{Decision, DetectorId, EntityLabel, Layer, Merged, Span};

/// Synthetic. The TCKN is deliberately checksum-INVALID (I8).
const DOC: &str = "Hasta Ayşe Yılmaz, TCKN 12345678951, Dr. Şükrü Gökçe tarafından görüldü.";

const MODEL_A: DetectorId = DetectorId::Ner(0);
const MODEL_B: DetectorId = DetectorId::Ner(1);

fn at(needle: &str) -> (usize, usize) {
    let start = DOC.find(needle).expect("fixture must contain the needle");
    (start, start + needle.len())
}

fn span_over(needle: &str, label: EntityLabel, detector: DetectorId, confidence: f32) -> Span {
    let (start, end) = at(needle);
    Span::new(DOC, start, end, label, detector, confidence).expect("fixture span must be valid")
}

// ---------------------------------------------------------------------------
// F1: the invariants Span::new enforces are the only ones a caller can obtain.
// ---------------------------------------------------------------------------

#[test]
fn every_field_is_readable_from_outside_the_crate() {
    // The accessors a binding needs. If this stops compiling, the bindings
    // stop compiling, which is the whole reason the fields cannot simply be
    // removed from the surface.
    let span = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.91);
    let (start, end) = at("Ayşe Yılmaz");
    assert_eq!(span.start(), start);
    assert_eq!(span.end(), end);
    assert_eq!(span.byte_len(), end - start);
    assert_eq!(span.label(), EntityLabel::PatientName);
    assert_eq!(span.source(), Layer::Ner);
    assert_eq!(span.detector_id(), MODEL_A);
    assert!((span.confidence() - 0.91).abs() < 1e-6);
    assert!(!span.is_checksum_validated());
    assert_ne!(span.text_hash(), 0);
}

#[test]
fn the_checksum_flag_is_reachable_only_through_the_arithmetic_constructor() {
    // BREACH DIRECTION, which is the worse one: a binding author writing a
    // span for a genuinely checksum-valid identifier cannot forget the flag,
    // because there is no field to forget -- the constructor that takes no
    // detector and no confidence is the only way to describe that span.
    let (start, end) = at("12345678951");
    let checksum = Span::checksum_validated(DOC, start, end, EntityLabel::Tckn).expect("valid");
    assert!(checksum.is_checksum_validated());
    assert_eq!(checksum.detector_id(), DetectorId::Rules);
    assert_eq!(checksum.source(), Layer::Rules);
    assert!((checksum.confidence() - CHECKSUM_CONFIDENCE).abs() < f32::EPSILON);

    // FORGERY DIRECTION: the general constructor cannot set the flag at any
    // detector, any confidence, any label. `Span::new` is total over the
    // parameters a caller controls, and none of them is the flag.
    for detector in [DetectorId::Rules, MODEL_A, DetectorId::Context] {
        for confidence in [0.0_f32, 0.01, 0.5, 1.0] {
            let span = Span::new(DOC, start, end, EntityLabel::Tckn, detector, confidence)
                .expect("valid span");
            assert!(
                !span.is_checksum_validated(),
                "a caller-supplied confidence of {confidence} from {detector} claimed arithmetic"
            );
        }
    }
}

#[test]
fn a_low_confidence_ner_span_is_never_protected_from_outside() {
    // The forged case from the re-audit, stated as the property it violated:
    // an `Ner(3)` span at confidence 0.01 is demotable, and no public path
    // turns it into a protected one on its own.
    let span = span_over("Ayşe", EntityLabel::PatientName, DetectorId::Ner(3), 0.01);
    let merged = union_widest(DOC, &[span]).expect("merge");
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].support(), 1);
    assert!(!merged[0].is_protected());
    assert_eq!(demote_to_keep(&merged[0]), Ok(Decision::Keep));
}

#[test]
fn the_three_invariants_new_enforces_hold_for_every_obtainable_span() {
    // Mid-character start: `ş` is two bytes and its second byte is not a
    // boundary. Unrepresentable, not merely discouraged.
    let mid_s = DOC.find('ş').expect("fixture contains s-cedilla") + 1;
    assert!(!DOC.is_char_boundary(mid_s));
    assert!(matches!(
        Span::new(
            DOC,
            mid_s,
            mid_s + 4,
            EntityLabel::PatientName,
            MODEL_A,
            0.8
        ),
        Err(Error::SpanNotCharBoundary { .. })
    ));

    // Confidence outside the unit interval.
    let (start, end) = at("Ayşe");
    assert_eq!(
        Span::new(DOC, start, end, EntityLabel::PatientName, MODEL_A, 42.0),
        Err(Error::ConfidenceOutOfRange { confidence: 42.0 })
    );

    // `source` disagreeing with `detector_id`: the re-audit forged
    // `source: Rules` onto `detector_id: Ner(0)`, which is a rules-layer claim
    // made by a model. Derived, so it cannot disagree.
    for detector in [DetectorId::Rules, MODEL_A, MODEL_B, DetectorId::Context] {
        let span =
            Span::new(DOC, start, end, EntityLabel::PatientName, detector, 0.5).expect("valid");
        assert_eq!(span.source(), detector.layer());
    }
}

// ---------------------------------------------------------------------------
// F4: `Merged::support` cannot be handed to the type from outside.
// ---------------------------------------------------------------------------

#[test]
fn support_can_only_be_earned_by_merging_distinct_detectors() {
    // The one public constructor a caller can call directly yields the
    // weakest possible value: one contributor, unprotected. Everything above
    // that is produced by `union_widest` from actual proposals.
    let lone = Merged::single(span_over(
        "Ayşe Yılmaz",
        EntityLabel::PatientName,
        MODEL_A,
        0.2,
    ));
    assert_eq!(lone.support(), 1);
    assert_eq!(lone.contributors(), &[MODEL_A]);
    assert!(!lone.is_protected());

    let earned = union_widest(
        DOC,
        &[
            span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.2),
            span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.2),
        ],
    )
    .expect("merge");
    assert_eq!(earned[0].support(), 2);
    assert!(earned[0].is_protected());
    assert!(matches!(
        demote_to_keep(&earned[0]),
        Err(Error::ProtectedSpanDemotion { .. })
    ));
}

// ---------------------------------------------------------------------------
// F2: support counts DISTINCT detectors, from outside the crate.
// ---------------------------------------------------------------------------

#[test]
fn one_detector_overlapping_itself_is_not_agreement() {
    let merged = union_widest(
        DOC,
        &[
            span_over("Ayşe Yıl", EntityLabel::PatientName, MODEL_A, 0.3),
            span_over("şe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.3),
        ],
    )
    .expect("merge");
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].support(), 1);
    assert_eq!(merged[0].contributors(), &[MODEL_A]);
    assert!(!merged[0].is_protected());
}

#[test]
fn one_detector_at_identical_bounds_under_two_labels_is_not_agreement() {
    let merged = union_widest(
        DOC,
        &[
            span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.3),
            span_over("Ayşe Yılmaz", EntityLabel::OtherUniqueId, MODEL_A, 0.3),
        ],
    )
    .expect("merge");
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].support(), 1);
    assert!(!merged[0].is_protected());
}

#[test]
fn three_distinct_detectors_chained_through_overlaps_count_as_three() {
    // DOCUMENTED SEMANTICS (see `Merged::support`): support is the number of
    // distinct detectors that contributed to the merged region. It does NOT
    // assert a byte range all of them agreed on -- here MODEL_A and Context
    // share no byte -- and it deliberately over-approximates, because the
    // alternative reading makes a chained span demotable, and demotion is the
    // breach direction (I2).
    let merged = union_widest(
        DOC,
        &[
            span_over("Ayşe", EntityLabel::PatientName, MODEL_A, 0.3),
            span_over("şe Yılmaz", EntityLabel::PatientName, MODEL_B, 0.3),
            span_over(
                "maz, TCKN",
                EntityLabel::PatientName,
                DetectorId::Context,
                0.3,
            ),
        ],
    )
    .expect("merge");
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].support(), 3);
    assert_eq!(
        merged[0].contributors(),
        &[MODEL_A, MODEL_B, DetectorId::Context]
    );
    // The over-approximation, made explicit: no single byte carries all three.
    let (a_start, a_end) = at("Ayşe");
    let (c_start, c_end) = at("maz, TCKN");
    assert!(a_end <= c_start || c_end <= a_start);
    assert!(merged[0].is_protected());

    // The same chain from ONE detector is one detector, however long it is.
    let alone = union_widest(
        DOC,
        &[
            span_over("Ayşe", EntityLabel::PatientName, MODEL_A, 0.3),
            span_over("şe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.3),
            span_over("maz, TCKN", EntityLabel::PatientName, MODEL_A, 0.3),
        ],
    )
    .expect("merge");
    assert_eq!(alone[0].support(), 1);
    assert!(!alone[0].is_protected());
}

// ---------------------------------------------------------------------------
// F3: the surviving span names the detector that produced its label.
// ---------------------------------------------------------------------------

#[test]
fn merged_provenance_names_the_detector_whose_label_and_bounds_survived() {
    let narrow = span_over("Ayşe", EntityLabel::PatientName, MODEL_A, 0.5);
    let wide = span_over("Ayşe Yılmaz", EntityLabel::OtherUniqueId, MODEL_B, 0.5);
    for pair in [[narrow, wide], [wide, narrow]] {
        let merged = union_widest(DOC, &pair).expect("merge");
        assert_eq!(merged.len(), 1);
        // The wider span wins the label, so it must also own the provenance.
        assert_eq!(merged[0].span().label(), EntityLabel::OtherUniqueId);
        assert_eq!(merged[0].span().detector_id(), MODEL_B);
        assert_eq!(merged[0].span().start(), wide.start());
        assert_eq!(merged[0].span().end(), wide.end());
        // The parent that lost the label is still counted as a contributor.
        assert_eq!(merged[0].contributors(), &[MODEL_A, MODEL_B]);
    }
}
