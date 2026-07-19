//! TR IBAN -- 26 characters, ISO 7064 mod-97 == 1.

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::Span;

use super::{Doc, CHECKSUM_FAILED};

const LEN: usize = 26;

/// `TR`, two check digits, then exactly 22 more characters, each optionally
/// preceded by one grouping separator.
///
/// THE COUNT IS THE LENGTH CHECK. Requiring exactly 22 trailing characters is
/// what rejects a short IBAN outright; a long one is rejected by the
/// alphanumeric guard in [`detect`], because the regex would otherwise happily
/// take the first 26 characters of a 28-character string and call it valid.
/// `(?i)` covers both the lowercase country code and lowercase BBAN letters.
const PATTERN: &str = r"(?i)\bTR[ .\-]?[0-9]{2}(?:[ .\-]?[0-9A-Z]){22}";

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

/// ISO 7064 mod-97 over the rearranged, letter-expanded string.
///
/// Computed incrementally rather than by building a ~50-digit decimal string,
/// because the whole point of the rules layer is that it costs microseconds.
pub(super) fn mod97(compact: &str) -> Option<u32> {
    let head = compact.get(..4)?;
    let tail = compact.get(4..)?;
    let mut remainder: u32 = 0;
    for ch in tail.chars().chain(head.chars()) {
        // `to_digit(36)` is exactly the A=10..Z=35 expansion ISO 13616 defines.
        let value = ch.to_digit(36)?;
        remainder = if value < 10 {
            remainder * 10 + value
        } else {
            remainder * 100 + value
        };
        remainder %= 97;
    }
    Some(remainder)
}

pub(super) fn detect(doc: &Doc<'_>, out: &mut Vec<Span>) {
    let Some(pattern) = pattern() else {
        return;
    };
    let text = doc.text();
    for found in pattern.find_iter(text) {
        // A 27th alphanumeric immediately after the match means the document
        // held a longer string than a TR IBAN can be, so the 26 characters the
        // regex took are a prefix of something else.
        if text[found.end()..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        {
            continue;
        }
        let compact: String = found
            .as_str()
            .chars()
            .filter(|ch| !matches!(ch, ' ' | '.' | '-'))
            .flat_map(char::to_uppercase)
            .collect();
        if compact.len() != LEN || !compact.starts_with("TR") {
            continue;
        }
        let span = if mod97(&compact) == Some(1) {
            doc.emit_checksum(found.start(), found.end(), EntityLabel::Iban)
        } else {
            // RECALL DECISION (I2). `TR` followed by 24 characters in IBAN
            // grouping is not a shape that occurs by accident in clinical
            // prose, so a mod-97 failure is far more likely to be a
            // transcription error on a real account number than a coincidence.
            // Emitted below the escalation ceiling, so L4 can still argue it
            // down -- which is right, because no arithmetic vouches for it.
            doc.emit(
                found.start(),
                found.end(),
                EntityLabel::Iban,
                CHECKSUM_FAILED,
            )
        };
        out.extend(span);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn iban_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::Iban)
            .collect()
    }

    /// Published ISO 13616 / SWIFT registry example IBANs for Turkey. These are
    /// the registry's own specimen values, not anyone's account.
    const VALID: [&str; 2] = ["TR330006100519786457841326", "TR320010009999901234567890"];

    /// Same shape, deliberately broken check digits.
    const INVALID_CHECKSUM: [&str; 2] =
        ["TR340006100519786457841326", "TR330006100519786457841327"];

    #[test]
    fn published_vectors_validate_and_broken_ones_do_not() {
        for candidate in VALID {
            assert_eq!(mod97(candidate), Some(1), "{candidate} must validate");
        }
        for candidate in INVALID_CHECKSUM {
            assert_ne!(mod97(candidate), Some(1), "{candidate} must not validate");
        }
    }

    #[test]
    fn a_grouped_iban_is_checksum_validated_and_spans_the_whole_surface_form() {
        let grouped = "TR33 0006 1005 1978 6457 8413 26";
        let doc = format!("IBAN: {grouped} hesabina yatirildi.");
        let spans = iban_spans(&doc);
        assert_eq!(spans.len(), 1);
        assert!(spans[0].is_checksum_validated());
        assert_eq!(&doc[spans[0].start()..spans[0].end()], grouped);
    }

    #[test]
    fn lowercase_and_dotted_and_hyphenated_forms_are_caught() {
        for surface in [
            "tr33 0006 1005 1978 6457 8413 26",
            "TR33.0006.1005.1978.6457.8413.26",
            "TR33-0006-1005-1978-6457-8413-26",
            "TR330006100519786457841326",
        ] {
            let doc = format!("Hesap {surface} olarak kayitli.");
            let spans = iban_spans(&doc);
            assert_eq!(spans.len(), 1, "{surface} was not matched");
            assert!(spans[0].is_checksum_validated(), "{surface} not validated");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], surface);
        }
    }

    #[test]
    fn a_non_tr_country_code_is_rejected() {
        // DE89 3704 0044 0532 0130 00 is the published German specimen: valid
        // mod-97, wrong country, and out of scope for a Turkish rule set.
        for doc in ["IBAN DE89370400440532013000", "IBAN GB82WEST12345698765432"] {
            assert!(iban_spans(doc).is_empty(), "{doc} must not match a TR rule");
        }
    }

    #[test]
    fn wrong_length_is_rejected() {
        for doc in [
            "TR3300061005197864578413",     // 24, too short
            "TR33000610051978645784132699", // 28, too long
        ] {
            assert!(iban_spans(doc).is_empty(), "{doc} is not 26 characters");
        }
    }

    #[test]
    fn a_checksum_invalid_tr_iban_is_emitted_but_never_validated() {
        // RECALL DECISION (I2): `TR` plus 24 characters in IBAN grouping is
        // not a shape that occurs by accident in a clinical note, so a mod-97
        // failure is far more likely to be a transcription error on a real
        // account number than a coincidence. Emitted below the escalation
        // ceiling so L4 can still argue it down.
        let doc = "IBAN TR34 0006 1005 1978 6457 8413 26";
        let spans = iban_spans(doc);
        assert_eq!(spans.len(), 1);
        assert!(!spans[0].is_checksum_validated());
        assert!((spans[0].confidence() - CHECKSUM_FAILED).abs() < f32::EPSILON);
    }
}
