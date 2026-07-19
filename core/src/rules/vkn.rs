//! VKN -- Turkish tax identification number, 10 digits.
//!
//! THE ALGORITHM IS NOT THE TCKN ALGORITHM. For each of the nine leading
//! digits, indexed `i` from 0:
//!
//! ```text
//! t = (d[i] + 9 - i) mod 10
//! v = 9                       if t == 9
//! v = (t * 2^(9-i)) mod 9      otherwise
//! check = (10 - (sum(v) mod 10)) mod 10
//! ```
//!
//! PROVENANCE. The arithmetic above is the algorithm published for the Turkish
//! Revenue Administration's ten-digit `Vergi Kimlik Numarası`. It HAS been
//! checked step for step against a published statement of the algorithm and
//! against the specimen `1729171602`, which this implementation accepts; the
//! earlier caveat in this header, saying the algorithm had never been checked
//! against published vectors, was true when it was written and is not true now,
//! and it is retracted rather than left standing. A safety caveat that has
//! stopped being accurate is worse than none: it teaches the next reader that
//! the caveats in this crate are decoration. `eval/schema.yaml`'s three `VKN`
//! examples are synthetic and deliberately fail this arithmetic (I8), so they
//! remain no evidence either way. The tests below add internal consistency:
//! eight generated vectors validate, every single-digit mutation of every one
//! of them fails, wrong lengths are rejected, and the check digits are pinned
//! so the arithmetic cannot drift silently.
//!
//! ISSUING RULES -- WHICH EXIST, AND WHICH DO NOT. `tckn.rs` rejects two shapes
//! before it ever runs its checksum, because the published issuing rule for a
//! national id forbids them: a leading zero, and an all-same sequence. NEITHER
//! RULE HAS A PUBLISHED COUNTERPART FOR VKN, and none is invented here. A
//! leading zero is not forbidden for a tax number, and no all-same ten-digit
//! string is reserved. What can be said is arithmetic rather than policy: of
//! the ten all-same strings, nine already fail the check digit, and the tenth
//! (`4444444444`) passes it and is therefore accepted, because rejecting it
//! would mean asserting a reservation this module cannot cite.
//!
//! WHY A ONE-DIGIT CHECK IS NOT EVIDENCE ON ITS OWN. This is the whole reason
//! [`detect`] below is not a plain sliding window. TCKN has TWO check digits
//! plus the two issuing-rule rejections, so a random eleven-digit string passes
//! roughly once in a thousand. VKN has ONE check digit and no issuing rule, so
//! a random ten-digit window passes ONE TIME IN TEN. Every eleven-digit TCKN
//! contains two ten-digit windows, so about one TCKN in five used to mint a
//! spurious VKN -- and it minted it through [`Doc::emit_checksum`], which sets
//! the flag L4 is STRUCTURALLY FORBIDDEN to demote. Measured on the 178-document
//! corpus that was 44 undemotable false positives (26 sitting on a gold TCKN, 8
//! on an SGK number, 8 on a phone number) against 4 true positives. A
//! ten-digit window found strictly inside a longer digit run therefore needs
//! corroboration before it may claim arithmetic: either a RUN BOUNDARY on both
//! sides, or a `Vergi`/`VKN` cue in the same line.
//!
//! WHY DROPPING THE UNCORROBORATED INTERIOR WINDOW IS NOT AN I2 RECALL TRADE.
//! A run boundary is where the DIGITS stop, not where the word does, so every
//! surface form a VKN actually takes in a note still has the run to itself: it
//! is bare, punctuated, suffixed (`4820000001'in`), or glued to letters
//! (`VKN4820000001`) -- letters end a digit run. The only shape lost is a VKN
//! concatenated to further digits with no separator at all, which is a barcode
//! or log artifact rather than clinical text, and even there the enclosing run
//! is still emitted by whichever module owns it (TCKN at eleven, SGK at
//! thirteen) so the bytes are not left unmasked. Recall on the corpus is
//! unchanged at 1.0000.
//!
//! A ten-digit run that FAILS the check is still emitted, at [`CHECKSUM_FAILED`]
//! and demotable -- unchanged, and the reason the four genuine VKNs in the
//! corpus are found at all, since all four are synthetic and checksum-invalid.

use crate::label::EntityLabel;
use crate::span::Span;

use super::{digit_runs, digit_values, Doc, CHECKSUM_FAILED};

const LEN: usize = 10;

/// Test-only. Same as `tckn`: pure digit-run arithmetic, no regex to compile. Present
/// so the layer-wide sweep in `mod.rs` covers every module by name.
#[cfg(test)]
pub(super) fn pattern_ok() -> bool {
    true
}

pub(super) fn is_valid(digits: &[u8]) -> bool {
    if digits.len() != LEN {
        return false;
    }
    let mut sum: u32 = 0;
    for (index, digit) in digits[..9].iter().enumerate() {
        let Ok(index) = u32::try_from(index) else {
            return false;
        };
        let shifted = (u32::from(*digit) + 9 - index) % 10;
        // `t == 9` is special-cased because `9 * 2^k mod 9` is zero, which would
        // silently erase the largest contribution instead of recording it.
        sum += if shifted == 9 {
            9
        } else {
            (shifted << (9 - index)) % 9
        };
    }
    u32::from(digits[9]) == (10 - (sum % 10)) % 10
}

/// The cue token that corroborates a window with digits on both sides of it.
///
/// Every casing is written out for the same reason `date.rs` writes its month
/// names out: Turkish uppercases `i` to dotted `İ`, and Unicode simple case
/// folding does not relate the two, so `(?i)vergi` does not match `VERGİ`. The
/// ASCII-drift form is listed too, because a hospital export that stripped
/// diacritics writes `VERGI`. Matching the bare token `Vergi` rather than the
/// full phrase is deliberate: it covers `Vergi No`, `Vergi Kimlik No` and
/// `Vergi Kimlik No (serbest meslek)` without enumerating them.
const CUES: [&str; 8] = [
    "VKN", "vkn", "Vkn", "Vergi", "VERGİ", "VERGI", "vergi", "V.K.N",
];

/// How far back a cue may sit and still corroborate.
///
/// Bounded, and clipped to the current line by [`cue_precedes`], because a cue
/// two lines up belongs to a different field: in a header block
/// `Vergi Kimlik No: ...` is followed by `Dosya No: ...`, and an unbounded
/// backward search would lend the tax-number cue to the file number.
const CUE_REACH: usize = 48;

/// True when a `Vergi`/`VKN` cue sits within reach on the same line.
fn cue_precedes(text: &str, start: usize) -> bool {
    let Some(before) = text.get(..start) else {
        return false;
    };
    let line = before.rfind('\n').map_or(before, |at| &before[at + 1..]);
    let mut cut = line.len().saturating_sub(CUE_REACH);
    // Walk forward to a character boundary rather than back: the window only
    // shrinks, and slicing mid-character would panic.
    while cut < line.len() && !line.is_char_boundary(cut) {
        cut += 1;
    }
    let window = line.get(cut..).unwrap_or(line);
    CUES.iter().any(|cue| window.contains(cue))
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
        // The run has exactly ten digits, so the single window IS the run and
        // both of its boundaries are non-digits. That is the corroboration a
        // one-digit check cannot supply on its own; see the module header.
        let window_owns_the_run = run.len() == LEN;
        let corroborated = window_owns_the_run || cue_precedes(text, start);
        let mut validated = false;
        for offset in 0..=(run.len() - LEN) {
            if !is_valid(&digits[offset..offset + LEN]) {
                continue;
            }
            if !corroborated {
                continue;
            }
            if let Some(span) =
                doc.emit_checksum(start + offset, start + offset + LEN, EntityLabel::Vkn)
            {
                out.push(span);
                validated = true;
            }
        }
        // Same two-sided trade as `tckn`: a run of EXACTLY ten digits that
        // failed the check is emitted anyway, below the escalation ceiling so
        // L4 may argue it down. In hand-typed clinical text a failed check
        // digit is at least as likely to be a transcription slip on a real tax
        // number as a coincidence, and a missed identifier is a breach while an
        // over-masked figure is a papercut.
        if !validated && window_owns_the_run {
            if let Some(span) = doc.emit(start, end, EntityLabel::Vkn, CHECKSUM_FAILED) {
                out.push(span);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn vkn_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::Vkn)
            .collect()
    }

    /// Derive the tenth digit from a nine-digit prefix, so valid vectors are
    /// generated at runtime rather than written down.
    fn valid_vkn(prefix: [u8; 9]) -> String {
        let mut out = String::with_capacity(LEN);
        for digit in prefix {
            out.push(char::from(b'0' + digit));
        }
        out.push(char::from(b'0' + check_digit(&prefix)));
        out
    }

    fn check_digit(prefix: &[u8; 9]) -> u8 {
        let mut sum: u32 = 0;
        for (index, digit) in prefix.iter().enumerate() {
            let shifted = (u32::from(*digit) + 9 - u32::try_from(index).expect("index fits")) % 10;
            sum += if shifted == 9 {
                9
            } else {
                (shifted << (9 - index)) % 9
            };
        }
        u8::try_from((10 - (sum % 10)) % 10).expect("single digit")
    }

    const PREFIXES: [[u8; 9]; 8] = [
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
        [9, 8, 7, 6, 5, 4, 3, 2, 1],
        [4, 8, 2, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 1, 1, 1, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 1],
        [7, 3, 5, 1, 9, 2, 4, 6, 8],
        [5, 5, 5, 5, 5, 5, 5, 5, 5],
        [2, 9, 0, 4, 7, 1, 3, 8, 6],
    ];

    #[test]
    fn generated_vectors_pass_and_every_single_digit_mutation_fails() {
        for prefix in PREFIXES {
            let valid = valid_vkn(prefix);
            let digits = digit_values(&valid);
            assert!(is_valid(&digits), "generated {valid} must validate");
            for position in 0..LEN {
                for replacement in 0..10u8 {
                    if replacement == digits[position] {
                        continue;
                    }
                    let mut mutated = digits.clone();
                    mutated[position] = replacement;
                    assert!(
                        !is_valid(&mutated),
                        "a single-digit mutation at {position} of {valid} still validated"
                    );
                }
            }
        }
    }

    /// The check digit this implementation produces for each prefix above.
    ///
    /// A REGRESSION LOCK, not an external validation. The algorithm could not
    /// be checked against published valid/invalid vectors offline, so this
    /// table pins what the code does today; if the arithmetic is ever edited,
    /// this test goes red and the change has to be argued for rather than
    /// slipping in. It is NOT evidence that the arithmetic is correct.
    const EXPECTED_CHECK_DIGITS: [u8; 8] = [0, 7, 9, 4, 9, 8, 3, 9];

    #[test]
    fn the_check_digit_table_is_pinned_against_silent_drift() {
        let produced: Vec<u8> = PREFIXES.iter().map(check_digit).collect();
        assert_eq!(produced, EXPECTED_CHECK_DIGITS.to_vec());
    }

    #[test]
    fn the_vkn_algorithm_is_not_the_tckn_algorithm() {
        // Guards the exact mistake the brief warns about: reusing the 11-digit
        // national-ID arithmetic on a 10-digit tax number. The two check digits
        // are computed from the same nine leading digits and must not agree on
        // every prefix, which they would if one had been copied from the other.
        let tckn_style: Vec<u8> = PREFIXES
            .iter()
            .map(|prefix| {
                let odd: u32 = (0..9).step_by(2).map(|i| u32::from(prefix[i])).sum();
                let even: u32 = (1..9).step_by(2).map(|i| u32::from(prefix[i])).sum();
                u8::try_from((odd * 7 + 100 - even) % 10).expect("single digit")
            })
            .collect();
        let vkn_style: Vec<u8> = PREFIXES.iter().map(check_digit).collect();
        assert_ne!(tckn_style, vkn_style);
    }

    #[test]
    fn wrong_length_input_is_rejected() {
        assert!(!is_valid(&digit_values("123456789")));
        assert!(!is_valid(&digit_values("12345678901")));
        assert!(!is_valid(&[]));
    }

    #[test]
    fn a_valid_vkn_is_checksum_validated() {
        let vkn = valid_vkn(PREFIXES[0]);
        let doc = format!("Vergi No: {vkn}");
        let spans = vkn_spans(&doc);
        let found = spans
            .iter()
            .find(|s| doc[s.start()..s.end()] == vkn)
            .expect("valid VKN must be found");
        assert!(found.is_checksum_validated());
        assert!((found.confidence() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn a_suffixed_vkn_is_caught() {
        let vkn = valid_vkn(PREFIXES[1]);
        for suffix in ["'nin", "'nın", "'ye", "'ya"] {
            let doc = format!("{vkn}{suffix} beyani");
            let found = vkn_spans(&doc)
                .into_iter()
                .find(|s| doc[s.start()..s.end()] == vkn)
                .expect("suffixed VKN must be found");
            assert!(found.is_checksum_validated());
        }
    }

    #[test]
    fn a_right_length_checksum_invalid_number_is_emitted_but_never_validated() {
        // RECALL DECISION (I2), and it carries extra weight here: the
        // algorithm below could not be verified against published vectors
        // offline, so a checksum FAILURE is the one outcome that might be the
        // implementation's fault rather than the number's. Emitting the
        // failures at a demotable confidence means a wrong algorithm can cost
        // precision but can never cost recall.
        let doc = "Fatura 1111111111 numarali kayit.";
        let spans = vkn_spans(doc);
        assert_eq!(spans.len(), 1);
        assert!(!spans[0].is_checksum_validated());
        assert!(spans[0].confidence() < crate::pipeline::ESCALATION_CONFIDENCE_MAX);
    }

    #[test]
    fn a_valid_vkn_glued_to_letters_keeps_the_run_and_is_validated() {
        // Letters end a digit run, so `VKN{vkn}kaydi` still gives the window
        // the whole run and the boundary corroboration that comes with it.
        // This is the shape the brief names as a failure mode, and it is
        // untouched by the interior-window rule below.
        let vkn = valid_vkn(PREFIXES[5]);
        for doc in [
            format!("VKN{vkn}kaydi"),
            format!("Vergi No:{vkn}."),
            format!("{vkn}'nin beyani"),
        ] {
            let found = vkn_spans(&doc)
                .into_iter()
                .find(|s| doc[s.start()..s.end()] == vkn)
                .expect("word-adjacent VKN must be found");
            assert!(found.is_checksum_validated(), "{doc}");
        }
    }

    #[test]
    fn a_window_inside_a_longer_run_needs_a_cue_before_it_may_claim_arithmetic() {
        let vkn = valid_vkn(PREFIXES[5]);
        // Digits on both sides: one check digit is a one-in-ten coincidence, so
        // nothing here is evidence and nothing is emitted.
        let bare = format!("ref77{vkn}88");
        assert!(
            vkn_spans(&bare).is_empty(),
            "an uncorroborated interior window claimed a checksum"
        );
        // The same window with the field label that names it. The cue is the
        // corroboration the arithmetic lacks.
        let cued = format!("Vergi Kimlik No: 77{vkn}88");
        let found = vkn_spans(&cued)
            .into_iter()
            .find(|s| cued[s.start()..s.end()] == vkn)
            .expect("a cued interior window must still be found");
        assert!(found.is_checksum_validated());
    }

    #[test]
    fn a_checksum_valid_tckn_does_not_mint_a_checksum_validated_vkn() {
        // THE D1 REGRESSION. Every 11-digit TCKN carries two 10-digit windows
        // and VKN's single check digit passes one in ten of them, so roughly
        // one TCKN in five used to produce an undemotable VKN sitting on top of
        // a real national id. The TCKN is generated at run time: a
        // checksum-valid one may never be a literal in a committed file (I8).
        for prefix in [
            [1, 2, 3, 4, 5, 6, 7, 8, 9],
            [9, 8, 7, 6, 5, 4, 3, 2, 1],
            [2, 4, 6, 8, 1, 3, 5, 7, 9],
            [3, 1, 4, 1, 5, 9, 2, 6, 5],
            [6, 1, 2, 3, 4, 5, 6, 7, 8],
        ] {
            let tckn = super::super::tests::valid_tckn(prefix);
            let digits = digit_values(&tckn);
            // The fixture only proves anything when a window actually passes,
            // so assert that at least one of the two does before asserting the
            // detector declines it.
            let windows_passing = (0..=1).filter(|o| is_valid(&digits[*o..o + LEN])).count();
            let doc = format!("T.C. Kimlik No: {tckn}\nProtokol No: 2026-0041873");
            for span in vkn_spans(&doc) {
                assert!(
                    !span.is_checksum_validated(),
                    "a TCKN window minted a checksum-validated VKN ({windows_passing} windows pass)"
                );
            }
        }
    }
}
