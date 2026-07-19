//! Turkish telephone numbers, mobile and landline.
//!
//! NO CHECKSUM EXISTS for a phone number, so confidence is [`CHECKSUM_ABSENT`]
//! and `checksum_validated` is never set. What replaces the checksum as the
//! precision mechanism is the TRUNK PREFIX: every Turkish number is written
//! with a leading `0` or `+90`, and requiring it is what keeps this module from
//! swallowing every 10- or 11-digit accession number in a note.

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::Span;

use super::{digit_free_after, digit_free_before, Doc, CHECKSUM_ABSENT};

/// Trunk prefix, area code, then 3-2-2, with any mix of the separators that
/// occur in Turkish notes.
///
/// The alternation is ordered longest-first because the crate matches
/// alternations leftmost-FIRST, not leftmost-longest: with `0` leading, the
/// international `0090` form would match only its first zero and then fail on
/// the area code.
///
/// `[2-5]` is the area-code filter and it is the whole precision story of this
/// module. Turkish geographic codes are 2xx-4xx and mobile codes are 5xx, so
/// `0912` and `0132` are rejected on the first digit after the trunk prefix,
/// and a bare ten- or eleven-digit accession number is rejected because it has
/// no trunk prefix at all.
const PATTERN: &str = concat!(
    r"(?:\+\s?9\s?0|0090|0)",
    r"[\s.\-/]*\(?\s*[2-5][0-9]{2}\s*\)?",
    r"[\s.\-/]*[0-9]{3}",
    r"[\s.\-/]*[0-9]{2}",
    r"[\s.\-/]*[0-9]{2}",
);

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
    let text = doc.text();
    for found in pattern.find_iter(text) {
        // A digit on either side means the trunk prefix was an accident of a
        // longer number rather than the start of a phone number. Recall is
        // untouched: a real note writes a phone number with separators or on
        // its own, never welded into a twenty-digit run.
        if !digit_free_before(text, found.start()) || !digit_free_after(text, found.end()) {
            continue;
        }
        out.extend(doc.emit(
            found.start(),
            found.end(),
            EntityLabel::Phone,
            CHECKSUM_ABSENT,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn phone_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::Phone)
            .collect()
    }

    /// Surface forms that must all be caught. Synthetic ranges throughout.
    const VALID: [&str; 14] = [
        "+90 532 000 00 00",
        "+905320000000",
        "+90 (532) 000 00 00",
        "0(532) 000 00 00",
        "0 532 000 00 00",
        "05320000000",
        "0532 000 00 00",
        "0532.000.00.00",
        "0532-000-00-00",
        "0212 000 00 00",
        "02120000000",
        "0(312) 000 00 00",
        "0424-000-00-00",
        "00905320000000",
    ];

    #[test]
    fn every_surface_form_is_matched_whole() {
        for surface in VALID {
            let doc = format!("Iletisim: {surface} numarasindan saglandi.");
            let spans = phone_spans(&doc);
            assert_eq!(spans.len(), 1, "{surface} was not matched exactly once");
            assert_eq!(
                &doc[spans[0].start()..spans[0].end()],
                surface,
                "the span must cover the whole surface form"
            );
            assert!(!spans[0].is_checksum_validated());
            assert!((spans[0].confidence() - CHECKSUM_ABSENT).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn numbers_that_are_not_phone_shaped_are_rejected() {
        for doc in [
            "Islem 12345678901 numarali.",      // 11 digits, no trunk prefix
            "Deger 1234567890 olarak.",         // 10 digits, no trunk prefix
            "Kod 0912 3456 789 kayitli.",       // 0 then area 912, not 2-5
            "Referans 0132000000 satiri.",      // 0 then area 132, not 2-5
            "Tarih 2024-03-12 olarak girildi.", // a date, not a number
        ] {
            assert!(phone_spans(doc).is_empty(), "false positive in {doc}");
        }
    }

    #[test]
    fn a_phone_glued_inside_a_longer_digit_run_is_not_emitted() {
        // PRECISION DECISION: a trunk prefix in the middle of a 20-digit run is
        // an accident of the digits, not a phone number, and the digit-boundary
        // guard is what separates the two. Recall is unaffected because a real
        // note writes a phone number with separators or on its own.
        assert!(phone_spans("Kayit 9905320000000123456 satiri.").is_empty());
    }

    #[test]
    fn a_suffixed_phone_number_keeps_its_bounds() {
        let doc = "0532 000 00 00'dan arandi.";
        let spans = phone_spans(doc);
        assert_eq!(spans.len(), 1);
        assert_eq!(&doc[spans[0].start()..spans[0].end()], "0532 000 00 00");
    }
}
