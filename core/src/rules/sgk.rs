//! SGK -- Turkish social security registration / beneficiary number.
//!
//! NO CHECKSUM IS IMPLEMENTED, DELIBERATELY. There is no publicly documented,
//! verifiable check-digit algorithm for the SGK sicil number, and this module
//! could not obtain one offline. Inventing arithmetic here would be worse than
//! having none: [`Span::checksum_validated`] is what makes a span undemotable
//! for the rest of the pipeline, so a fabricated checksum would either protect
//! numbers nothing verified or -- far worse -- reject real SGK numbers as
//! "invalid" and hand a breach to a compliance officer with an arithmetic proof
//! attached.
//!
//! CONSEQUENCE, stated so it is not rediscovered later: detection here is
//! FORMAT plus CONTEXT CUE only, confidence is [`CONTEXT_CUED`], and
//! `checksum_validated` is never set. The schema agrees --  `SGK_NO` carries
//! `checksum_validatable: false` and no `precision_threshold`. If a verifiable
//! algorithm is ever published, this module gains a `is_valid` and the recall
//! floor does not move.

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::Span;

use super::{Doc, CONTEXT_CUED};

/// A cue word, at most a short run of non-digits, then the number.
///
/// The non-digit gap is lazy and bounded so the cue binds to the NEAREST
/// following number: `SGK sicil no 1000000000001` must attach to the digits
/// after `no`, and an unbounded gap would let a cue at the top of a note claim
/// a number three sentences later.
const PATTERN: &str = r"(?i)(?:sgk|ssk|sicil|sosyal\s+g[üu]venlik)[^0-9\n]{0,24}?([0-9]{8,26})";

fn pattern() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    super::compiled(&CELL, PATTERN)
}

/// Test-only: proves the module's pattern actually compiled.
///
/// `#[cfg(test)]` rather than a lint allowance, because outside the test
/// build there is genuinely no caller -- `detect` reads the same `OnceLock`
/// directly and returns early rather than asking a question it cannot act on.
#[cfg(test)]
pub(super) fn pattern_ok() -> bool {
    pattern().is_some()
}

pub(super) fn detect(doc: &Doc<'_>, out: &mut Vec<Span>) {
    let Some(pattern) = pattern() else {
        return;
    };
    for found in pattern.captures_iter(doc.text()) {
        let Some(number) = found.get(1) else {
            continue;
        };
        // Never `emit_checksum`: see the module header. There is no arithmetic
        // here, so nothing may claim the flag that makes a span undemotable.
        out.extend(doc.emit(
            number.start(),
            number.end(),
            EntityLabel::SgkNo,
            CONTEXT_CUED,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn sgk_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::SgkNo)
            .collect()
    }

    #[test]
    fn cued_numbers_are_detected_at_a_demotable_confidence_and_never_validated() {
        for (doc, expected) in [
            ("SGK No: 0000123456789012345678", "0000123456789012345678"),
            ("sicil 2200000000123 kayitli", "2200000000123"),
            ("SGK sicil no 1000000000001", "1000000000001"),
            ("SSK numarasi: 1234567890123", "1234567890123"),
            ("Sosyal Guvenlik No 987654321012", "987654321012"),
        ] {
            let spans = sgk_spans(doc);
            assert_eq!(spans.len(), 1, "no SGK number found in {doc}");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], expected);
            assert!(
                !spans[0].is_checksum_validated(),
                "SGK has no checksum; nothing may claim one"
            );
            assert!((spans[0].confidence() - CONTEXT_CUED).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn an_uncued_digit_run_is_not_an_sgk_number() {
        // Without a cue the format alone says nothing: a bare 13-digit run is
        // just as likely an accession number, and SGK is the one type here with
        // no arithmetic to fall back on.
        assert!(sgk_spans("Deger 2200000000123 olarak olculdu.").is_empty());
    }

    #[test]
    fn the_cue_is_case_insensitive_across_turkish_casing() {
        for doc in ["SGK NO: 1234567890123", "sgk no: 1234567890123"] {
            assert_eq!(sgk_spans(doc).len(), 1, "{doc}");
        }
    }
}
