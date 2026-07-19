//! The guardrail I8 keeps unarmed everywhere else, armed here.
//!
//! # The tension this file exists to resolve
//!
//! `Merged::is_protected()` is the single most safety-critical predicate in the
//! crate: it is what stops L4 demoting a checksum-validated identifier to
//! `Keep`. It is armed by exactly two things, a checksum result or agreement
//! between detectors, and on the evaluated corpus it is armed by NEITHER.
//! Invariant I8 forbids a checksum-VALID Turkish national ID from existing
//! anywhere in this repository - the pre-commit hook refuses the commit - so
//! all 128 eleven-digit runs in the corpus fail their check digits
//! by construction, every TCKN span therefore arrives at L4 at confidence 0.50
//! with `checksum_validated == false`, and no evaluated document has ever
//! exercised the protection path. The release gate that reads
//! `checksum_id_precision` is unmeasurable for the same reason, and now reports
//! `n/a` instead of a number computed over spans selected by label. ADR D-030.
//!
//! So the identifiers here are GENERATED AT RUNTIME and never written to disk
//! inside the repository. They exist for microseconds inside a test process,
//! which satisfies I8's actual concern (a checksum-valid TCKN in a committed
//! file could belong to a real person) while still proving the guardrail fires.
//!
//! Nothing below may be turned into a fixture. If a future change needs one of
//! these values on disk, the change is wrong.

use deid_tr_core::pipeline::demote_to_keep;
use deid_tr_core::rules::RuleSet;
use deid_tr_core::span::{union_widest, Decision, DetectorId, Span, CHECKSUM_CONFIDENCE};
use deid_tr_core::{EntityLabel, Pipeline, Tier};

/// Complete a nine-digit prefix into a checksum-VALID TCKN.
///
/// The arithmetic is the brief's, restated rather than imported so that this
/// test would still catch a change to the implementation that made both sides
/// agree on the wrong rule.
fn valid_tckn(prefix: [u8; 9]) -> String {
    assert!(prefix[0] != 0, "d1 != 0 is part of the format");
    let odd: u32 = [prefix[0], prefix[2], prefix[4], prefix[6], prefix[8]]
        .iter()
        .map(|d| u32::from(*d))
        .sum();
    let even: u32 = [prefix[1], prefix[3], prefix[5], prefix[7]]
        .iter()
        .map(|d| u32::from(*d))
        .sum();
    // (odd * 7 - even) mod 10. `even` is at most 36, so adding 40 - a multiple
    // of 10, which cannot change the result - keeps the unsigned subtraction
    // from underflowing for any prefix, not just the ones used below.
    let d10 = (odd * 7 + 40 - even) % 10;
    let first_ten: u32 = prefix.iter().map(|d| u32::from(*d)).sum::<u32>() + d10;
    let d11 = first_ten % 10;

    let mut out = String::with_capacity(11);
    for digit in prefix {
        out.push(char::from(b'0' + digit));
    }
    out.push(char::from(b'0' + u8::try_from(d10).expect("single digit")));
    out.push(char::from(b'0' + u8::try_from(d11).expect("single digit")));
    out
}

/// Break a valid TCKN's last check digit. The corpus is entirely made of these.
fn invalidated(valid: &str) -> String {
    let mut chars: Vec<char> = valid.chars().collect();
    let last = chars.pop().expect("11 digits");
    let digit = last.to_digit(10).expect("digit");
    chars.push(char::from_digit((digit + 1) % 10, 10).expect("digit"));
    chars.into_iter().collect()
}

/// A handful of prefixes, so a single lucky value cannot carry the test.
fn generated_ids() -> Vec<String> {
    (0..8u8)
        .map(|n| {
            valid_tckn([
                1,
                n % 10,
                4,
                (n + 3) % 10,
                7,
                (n + 5) % 10,
                2,
                9,
                (n + 1) % 10,
            ])
        })
        .collect()
}

#[test]
fn a_runtime_generated_valid_tckn_is_checksum_validated_by_l1() {
    for id in generated_ids() {
        let text = format!("Hasta kimlik numarasi {id} olarak kaydedildi.");
        let spans = RuleSet.detect(&text);
        let tckn = spans
            .iter()
            .find(|span| span.label() == EntityLabel::Tckn)
            .unwrap_or_else(|| panic!("L1 found no TCKN in a generated valid id"));
        assert!(tckn.is_checksum_validated());
        assert_eq!(tckn.confidence(), CHECKSUM_CONFIDENCE);
    }
}

#[test]
fn the_corpus_shaped_invalid_form_is_the_one_that_leaves_the_guardrail_unarmed() {
    // The contrast that makes the ADR concrete: same digits, one check digit
    // different, and the protection predicate flips. Every TCKN in eval/gold is
    // on the wrong side of this line, by invariant.
    for id in generated_ids() {
        let broken = invalidated(&id);
        let text = format!("Hasta kimlik numarasi {broken} olarak kaydedildi.");
        let spans = RuleSet.detect(&text);
        let tckn = spans
            .iter()
            .find(|span| span.label() == EntityLabel::Tckn)
            .expect("L1 over-matches at regex and rejects at checksum");
        assert!(!tckn.is_checksum_validated());
        assert!(tckn.confidence() < CHECKSUM_CONFIDENCE);

        let merged = union_widest(&text, &spans).expect("merge");
        let candidate = merged
            .iter()
            .find(|m| m.span().label() == EntityLabel::Tckn)
            .expect("candidate");
        assert!(
            !candidate.is_protected(),
            "a checksum-INVALID id is demotable, which is exactly why the \
             corpus cannot exercise the guardrail"
        );
    }
}

#[test]
fn merged_is_protected_is_armed_by_the_checksum() {
    for id in generated_ids() {
        let text = format!("TCKN: {id}");
        let merged = union_widest(&text, &RuleSet.detect(&text)).expect("merge");
        let candidate = merged
            .iter()
            .find(|m| m.span().label() == EntityLabel::Tckn)
            .expect("candidate");
        assert!(candidate.is_protected());
        // Single detector: the protection came from arithmetic, not agreement.
        assert_eq!(candidate.support(), 1);
    }
}

#[test]
fn l4_cannot_demote_a_checksum_validated_span() {
    for id in generated_ids() {
        let text = format!("TCKN: {id}");
        let merged = union_widest(&text, &RuleSet.detect(&text)).expect("merge");
        let candidate = merged
            .iter()
            .find(|m| m.span().label() == EntityLabel::Tckn)
            .expect("candidate");
        let refused = demote_to_keep(candidate);
        assert!(
            refused.is_err(),
            "the L4 guardrail must refuse, not merely decline, to demote a \
             checksum-validated identifier"
        );
        // And the refusal names offsets and a label, never the digits (I4).
        let rendered = format!("{}", refused.expect_err("refusal"));
        assert!(!rendered.contains(&id));
    }
}

#[test]
fn the_full_pipeline_masks_a_checksum_validated_id_and_records_it_protected() {
    let pipeline = Pipeline::new(Tier::SafeHarbor);
    for id in generated_ids() {
        let text = format!("Hasta {id} numarali kayit ile geldi.");
        let result = pipeline.deidentify(&text).expect("deidentify");

        assert!(
            !result.text.contains(&id),
            "a checksum-validated identifier survived the pipeline"
        );
        let mapped = result
            .span_map
            .iter()
            .find(|m| m.span.label() == EntityLabel::Tckn)
            .expect("the span map records the TCKN");
        assert_eq!(mapped.decision, Decision::Mask);
        assert!(mapped.span.is_checksum_validated());
    }
}

#[test]
fn a_second_detector_cannot_claim_a_checksum() {
    // The other half of the predicate's contract: `Span::checksum_validated` is
    // constructible only from the rules layer, so no model can assert one. If
    // this ever compiles differently the guardrail becomes forgeable.
    let text = "TCKN: 00000000000";
    let inferred =
        Span::new(text, 6, 17, EntityLabel::Tckn, DetectorId::Ner(0), 0.99).expect("span");
    assert!(!inferred.is_checksum_validated());
}
