//! Email addresses -- RFC-PRAGMATIC, not RFC-complete.
//!
//! WHY NOT RFC 5322: the full grammar admits quoted local parts, comments and
//! folding whitespace, none of which occur in a clinical note, and a regex that
//! accepts them also accepts most of a sentence. The trade this module makes is
//! the recall-safe one for the shapes that actually appear -- Turkish
//! second-level domains (`.com.tr`, `.gov.tr`), hyphenated hospital domains,
//! and dotted local parts -- while refusing to swallow the punctuation that
//! follows an address in prose.

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::Span;

use super::{Doc, CHECKSUM_ABSENT};

/// Local part, `@`, then one or more labels ending in an all-letter TLD.
///
/// THE TRAILING-PUNCTUATION FIX IS THE LAST TERM. Ending the pattern on
/// `\.[A-Za-z]{2,}` rather than on a general label class means the match cannot
/// finish on a separator, so `ayse@ornek.example.` at the end of a sentence and
/// `ayse@ornek.example'dan` with a Turkish ablative suffix both stop at the
/// TLD. Requiring at least two letters there is also what rejects
/// `hasta@ornek.e`.
const PATTERN: &str = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}";

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
    for found in pattern.find_iter(doc.text()) {
        out.extend(doc.emit(
            found.start(),
            found.end(),
            EntityLabel::Email,
            CHECKSUM_ABSENT,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn email_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::Email)
            .collect()
    }

    const VALID: [&str; 7] = [
        "ayse.yilmaz@ornek-eposta.example",
        "hasta0431@ornek-hastane.example",
        "a.b+etiket@ornek.com.tr",
        "kayit_2026@alt.ornek.gov.tr",
        "DR.SUKRU@ORNEK-HASTANE.EXAMPLE",
        "x@y.tr",
        "hasta-1@ornek.example",
    ];

    #[test]
    fn every_valid_address_is_matched_whole() {
        for surface in VALID {
            let doc = format!("E-posta {surface} adresine gonderildi.");
            let spans = email_spans(&doc);
            assert_eq!(spans.len(), 1, "{surface} was not matched");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], surface);
            assert!(!spans[0].is_checksum_validated());
            assert!((spans[0].confidence() - CHECKSUM_ABSENT).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn trailing_punctuation_is_not_swallowed() {
        for (doc, expected) in [
            ("Adres: ayse@ornek.example.", "ayse@ornek.example"),
            ("Adres: ayse@ornek.example,", "ayse@ornek.example"),
            ("(ayse@ornek.com.tr)", "ayse@ornek.com.tr"),
            ("<ayse@ornek.example>;", "ayse@ornek.example"),
            ("ayse@ornek.example'dan geldi", "ayse@ornek.example"),
        ] {
            let spans = email_spans(doc);
            assert_eq!(spans.len(), 1, "{doc}");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], expected);
        }
    }

    #[test]
    fn non_addresses_are_rejected() {
        for doc in [
            "hasta@ ornek.example",   // space after the at sign
            "hasta@ornek",            // no dot in the domain
            "hasta@ornek.e",          // one-character TLD
            "sadece bir cumle @ var", // a bare at sign
            "12.03.2024 tarihinde",   // a date
        ] {
            assert!(email_spans(doc).is_empty(), "false positive in {doc}");
        }
    }
}
