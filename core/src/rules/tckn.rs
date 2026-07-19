//! TCKN -- Turkish national identification number.
//!
//! ALGORITHM, from the brief and from `eval/schema.yaml` (both restate the
//! published rule, and `scripts/hooks/pre_commit_phi.sh` implements the same
//! arithmetic independently in awk, which is a second copy this module is
//! checked against by construction): eleven digits, `d1 != 0`,
//! `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`,
//! `d11 = (d1+..+d10) mod 10`.
//!
//! NO REGEX. Sliding an eleven-wide window across every maximal digit run is
//! what catches an id glued inside a longer number -- the failure mode the
//! brief names -- and it is also what makes suffixes and word-adjacency
//! irrelevant, because the run boundary is where the digits stop, not where
//! the word does.

use crate::label::EntityLabel;
use crate::span::Span;

use super::{digit_runs, digit_values, Doc, CHECKSUM_FAILED};

const LEN: usize = 11;

/// Test-only. This module has no regex -- it slides a window over maximal digit
/// runs -- so there is nothing to fail to compile and the answer is
/// unconditionally true. It exists so `mod.rs`'s sweep can name every module
/// uniformly and a future regex here is covered the day it is added.
#[cfg(test)]
pub(super) fn pattern_ok() -> bool {
    true
}

pub(super) fn is_valid(digits: &[u8]) -> bool {
    if digits.len() != LEN {
        return false;
    }
    // Both rejections are issuing rules, not checksum arithmetic: no TCKN is
    // ever allocated with a leading zero, and the all-same sequences are
    // reserved. Neither could be a real person's id, so they are dropped rather
    // than emitted at a lower confidence.
    if digits[0] == 0 || digits.iter().all(|digit| *digit == digits[0]) {
        return false;
    }
    let odd: u32 = (0..9).step_by(2).map(|i| u32::from(digits[i])).sum();
    let even: u32 = (1..9).step_by(2).map(|i| u32::from(digits[i])).sum();
    // `+ 100` keeps the subtraction inside u32: `even` never exceeds 36, so the
    // added multiple of ten cannot change the result modulo ten.
    if u32::from(digits[9]) != (odd * 7 + 100 - even) % 10 {
        return false;
    }
    let total: u32 = digits[..10].iter().map(|digit| u32::from(*digit)).sum();
    u32::from(digits[10]) == total % 10
}

pub(super) fn detect(doc: &Doc<'_>, out: &mut Vec<Span>) {
    let text = doc.text();
    for (start, end) in digit_runs(text) {
        let Some(run) = text.get(start..end) else {
            continue;
        };
        if run.len() < LEN {
            continue;
        }
        let digits = digit_values(run);
        let mut validated = false;
        for offset in 0..=(run.len() - LEN) {
            if !is_valid(&digits[offset..offset + LEN]) {
                continue;
            }
            if let Some(span) =
                doc.emit_checksum(start + offset, start + offset + LEN, EntityLabel::Tckn)
            {
                out.push(span);
                validated = true;
            }
        }
        // RECALL DECISION (I2). A run of EXACTLY eleven digits that failed the
        // check is still emitted, below the escalation ceiling so L4 may argue
        // it down. In hand-typed clinical text a failed check digit is at least
        // as likely to be a transcription slip on a real national id as it is
        // to be a coincidence, and a missed identifier is a breach while an
        // over-masked accession number is a papercut.
        //
        // PRECISION DECISION, the other half of the same trade: inside a run
        // LONGER than eleven digits only passing windows are emitted. A
        // 64-character digest carries fifty-four windows, and emitting them all
        // would bury the note in spans that nothing vouches for.
        if validated || run.len() != LEN {
            continue;
        }
        if digits[0] == 0 || digits.iter().all(|digit| *digit == digits[0]) {
            continue;
        }
        if let Some(span) = doc.emit(start, end, EntityLabel::Tckn, CHECKSUM_FAILED) {
            out.push(span);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::valid_tckn;
    use super::*;
    use crate::rules::RuleSet;

    fn tckn_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::Tckn)
            .collect()
    }

    /// Nine prefixes, so nine independently generated valid vectors.
    const PREFIXES: [[u8; 9]; 9] = [
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
        [9, 8, 7, 6, 5, 4, 3, 2, 1],
        [2, 4, 6, 8, 1, 3, 5, 7, 9],
        [3, 1, 4, 1, 5, 9, 2, 6, 5],
        [5, 5, 5, 5, 5, 5, 5, 5, 5],
        [1, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 7, 0, 7, 0, 7, 0, 7],
        [4, 8, 2, 0, 0, 0, 0, 0, 1],
        [6, 1, 2, 3, 4, 5, 6, 7, 8],
    ];

    /// Right-length numbers that must be REJECTED. All checksum-invalid, so
    /// they are safe to write as literals (I8).
    const INVALID: [&str; 8] = [
        "12345678901", // right length, wrong check digits
        "00000000000", // d1 == 0
        "11111111111", // all-same
        "99999999999", // all-same
        "98765432101", // wrong check digits
        "10000000000", // d1 != 0 but checksum fails
        "22222222222", // all-same
        "12345678900", // wrong check digits
    ];

    #[test]
    fn generated_vectors_pass_and_every_single_digit_mutation_fails() {
        for prefix in PREFIXES {
            let valid = valid_tckn(prefix);
            let digits = digit_values(&valid);
            assert!(is_valid(&digits), "generated {valid} must validate");
            for position in 0..LEN {
                for replacement in 0..10u8 {
                    if replacement == digits[position] {
                        continue;
                    }
                    let mut mutated = digits.clone();
                    mutated[position] = replacement;
                    if mutated[0] == 0 || mutated.iter().all(|d| *d == mutated[0]) {
                        continue;
                    }
                    assert!(
                        !is_valid(&mutated),
                        "a single-digit mutation at {position} still validated"
                    );
                }
            }
        }
    }

    #[test]
    fn known_invalid_vectors_are_rejected() {
        for candidate in INVALID {
            assert!(
                !is_valid(&digit_values(candidate)),
                "{candidate} must not validate"
            );
        }
        assert!(!is_valid(&digit_values("1234567890")), "ten digits");
        assert!(!is_valid(&digit_values("123456789012")), "twelve digits");
    }

    #[test]
    fn a_bare_valid_tckn_is_checksum_validated() {
        let tckn = valid_tckn(PREFIXES[0]);
        let doc = format!("TCKN: {tckn}");
        let spans = tckn_spans(&doc);
        assert_eq!(spans.len(), 1);
        assert!(spans[0].is_checksum_validated());
        assert!((spans[0].confidence() - 1.0).abs() < f32::EPSILON);
        assert_eq!(&doc[spans[0].start()..spans[0].end()], tckn);
    }

    #[test]
    fn genitive_and_other_suffixed_forms_are_caught() {
        // Vowel harmony surfaces the same suffix four ways, so hardcoding one
        // variant misses the other three.
        for suffix in [
            "'in", "'ın", "'un", "'ün", "'nin", "'e", "'a", "'den", "'dan",
        ] {
            let tckn = valid_tckn(PREFIXES[1]);
            let doc = format!("{tckn}{suffix} kaydı incelendi.");
            let spans = tckn_spans(&doc);
            assert_eq!(spans.len(), 1, "suffix {suffix} lost the id");
            assert!(spans[0].is_checksum_validated());
            assert_eq!(&doc[spans[0].start()..spans[0].end()], tckn);
        }
    }

    #[test]
    fn an_id_glued_inside_a_longer_digit_run_is_still_found() {
        let tckn = valid_tckn(PREFIXES[2]);
        let doc = format!("Kayit 99{tckn}77 satiri");
        let spans = tckn_spans(&doc);
        let found = spans
            .iter()
            .find(|s| doc[s.start()..s.end()] == tckn)
            .expect("a glued id must still be found");
        assert!(found.is_checksum_validated());
    }

    #[test]
    fn an_id_glued_to_a_word_is_still_found() {
        let tckn = valid_tckn(PREFIXES[3]);
        for doc in [
            format!("TCKN{tckn}"),
            format!("{tckn}nolu"),
            format!("ref{tckn}x"),
        ] {
            let spans = tckn_spans(&doc);
            assert_eq!(spans.len(), 1, "word-adjacent id lost in {doc}");
            assert!(spans[0].is_checksum_validated());
        }
    }

    #[test]
    fn a_right_length_checksum_invalid_number_is_emitted_but_never_validated() {
        // RECALL DECISION (I2): an exactly-11-digit run that fails the check is
        // still emitted, at a confidence below the escalation ceiling so L4 may
        // argue it down. A checksum failure in a hand-typed clinical note is at
        // least as likely to be a transcription slip on a real national ID as
        // it is to be a coincidence, and a missed identifier is a breach while
        // an over-masked accession number is a papercut.
        let doc = "Kayit no 12345678901 numarali islem.";
        let spans = tckn_spans(doc);
        assert_eq!(spans.len(), 1);
        assert!(!spans[0].is_checksum_validated());
        assert!(spans[0].confidence() < crate::pipeline::ESCALATION_CONFIDENCE_MAX);
    }

    #[test]
    fn structurally_impossible_numbers_are_dropped_entirely() {
        // Not a recall trade: `d1 == 0` and an all-same run cannot be a TCKN
        // under the issuing rule itself, so emitting them would be noise with
        // no recall to buy.
        for candidate in ["00000000000", "11111111111", "99999999999"] {
            let doc = format!("Deger {candidate} okundu.");
            assert!(tckn_spans(&doc).is_empty(), "{candidate} was emitted");
        }
    }

    #[test]
    fn a_checksum_valid_window_inside_a_long_run_survives_but_a_failing_one_does_not() {
        // PRECISION DECISION: inside a run longer than 11 digits every window
        // is tried, but only the ones that PASS are emitted. A 30-digit hash
        // has twenty windows and emitting all of them would drown the note.
        let doc = "Islem 123456789012345678901234567890 tamamlandi.";
        for span in tckn_spans(doc) {
            assert!(span.is_checksum_validated());
        }
    }
}
