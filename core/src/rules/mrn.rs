//! MRN -- hospital medical record, protocol and file numbers.
//!
//! NO CHECKSUM AND NO NATIONAL FORMAT. An MRN is whatever the hospital
//! information system mints, so there is nothing to validate against and
//! nothing to recognise by shape alone: `2026-0004312` is indistinguishable
//! from a lot number, an order number or a version string. The only usable
//! signal is the LABEL PRINTED NEXT TO IT -- `Protokol No`, `Dosya No`,
//! `Hasta No` -- so this module is entirely context-cued.
//!
//! FALSE-POSITIVE RISK, documented because it is real and not fixable here: a
//! cue plus a number will also fire on `Dosya No: 12` in an administrative
//! header, on a form field left as a template, and on any sentence where those
//! words precede an unrelated figure. That is why the confidence is
//! [`CONTEXT_CUED`], the lowest band this layer emits and below the escalation
//! ceiling, so every MRN reaches L4 as a demotable single-source span rather
//! than as a fact. Under I2 the trade is taken in this direction on purpose: an
//! over-masked administrative number is a papercut, a leaked record number is a
//! breach.

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::Span;

use super::{Doc, CONTEXT_CUED};

/// The record-number surface form: an optional alphabetic department prefix,
/// then digits with internal hyphens or slashes.
///
/// THE PREFIX IS UP TO FOUR LETTERS, not one, and that single character class
/// was 15 of the 24 record numbers this module used to miss. Turkish hospital
/// information systems mint department-stamped numbers -- `ACL-2026-004212`
/// (acil), `RIS-2026-0431-77` (radyoloji), `OZL-0004312`, `MRK-0000884`,
/// `MG-2026-00431` -- and `[A-Za-z]?-?` matched none of them: at `ACL-` the
/// optional letter takes `A`, the digit class then meets `C`, and every
/// backtrack fails the same way, so the WHOLE cued match failed and the number
/// was not merely mis-bounded but invisible.
///
/// The separator is optional so `PROT20260011907` is reached too; the digits
/// still have to start somewhere, so a bare word cannot match.
const VALUE: &str = r"((?:[A-Za-z]{1,4}-?)?[0-9][0-9\-/]{0,15})";

/// Cue word, optionally the word `no`/`numarası`, then the value.
///
/// `kay[ıi]t` and `numaras[ıi]` are written with a character class instead of
/// relying on `(?i)`: Turkish uppercases dotless `ı` to ASCII `I`, and Unicode
/// simple case folding does not relate the two, so `(?i)kayıt` does not match
/// `KAYIT`. The class covers both letters and `(?i)` then covers their cases.
/// The alternation puts `numaras[ıi]` before `nu` for the same leftmost-first
/// reason the phone module orders its trunk prefixes.
///
/// TWO THINGS WIDENED HERE, both measured against the 24 misses.
///
/// `istem` joins the cue list: a radiology or lab order form heads its record
/// number `İstem No:`, and that is a record number by every definition the
/// module already uses. It carries a LEADING `\b` for a reason that cost a
/// false positive to find: without it the alternation matches inside
/// `sistemde`, and the module claimed the number in "sistemde 12345678901
/// biçiminde".
///
/// The number-word became OPTIONAL, because narrative Turkish drops it --
/// `protokol 2026-0055418`, `kayıt ACL-2026-005842`, `protokolü ...` -- and
/// eight misses were exactly that shape. Dropping a required token is a
/// precision risk, so it is paid for three ways. The captured value must clear
/// [`is_record_shaped`] when no number-word was present, or `Hasta 45 yaşında`
/// becomes a record number. The suffix the bare form may carry is the
/// accusative `-ü`/`-u` and nothing else: a permissive `\w{0,3}` also admits the
/// LOCATIVE, and `dosyada PM-0000-4312` ("in the file") is a sentence about
/// where a device serial is written, not a record-number label. And `numara`
/// is deliberately absent from the number-word alternation while `numarası` is
/// present, because `kayıtlı numara 05327740198` is a phone line.
fn cued() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)\b(?:protokol|dosya|hasta|kay[ıi]t|başvuru|[İIi]stem)(?:ü|u)?\s*(no|numaras[ıi]|nu)?\.?\s*[:#]?\s*{VALUE}"
        ))
        .ok()
    })
    .as_ref()
}

/// Does this value look like something a hospital system minted?
///
/// Only consulted when the cue arrived WITHOUT a number-word, where the cue
/// alone is weak evidence and the shape has to carry the rest. Three
/// sufficient signals, each of which a plain quantity in prose ("Hasta 45
/// yaşında", "Doz 500 mg") does not have: a department prefix, an internal
/// separator, or a run of at least six digits.
fn is_record_shaped(value: &str) -> bool {
    value.bytes().any(|b| b.is_ascii_alphabetic())
        || value.bytes().any(|b| b == b'-' || b == b'/')
        || value.bytes().filter(u8::is_ascii_digit).count() >= 6
}

/// The bare `MRN` label, which carries no Turkish cue word.
fn mrn_prefix() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(&format!(r"(?i)\bMRN\.?\s*[:#]?\s*{VALUE}")).ok())
        .as_ref()
}

/// Test-only: proves the module's pattern actually compiled.
///
/// `#[cfg(test)]` rather than a lint allowance, because outside the test
/// build there is genuinely no caller -- `detect` reads the same `OnceLock`
/// directly and returns early rather than asking a question it cannot act on.
#[cfg(test)]
pub(super) fn pattern_ok() -> bool {
    cued().is_some() && mrn_prefix().is_some()
}

pub(super) fn detect(doc: &Doc<'_>, out: &mut Vec<Span>) {
    if let Some(pattern) = cued() {
        for found in pattern.captures_iter(doc.text()) {
            let Some(value) = found.get(2) else {
                continue;
            };
            // Group 1 is the optional `no`/`numarası`. Absent, the cue word is
            // carrying the match alone and the shape has to vouch for the rest.
            if found.get(1).is_none() && !is_record_shaped(value.as_str()) {
                continue;
            }
            out.extend(doc.emit(value.start(), value.end(), EntityLabel::Mrn, CONTEXT_CUED));
        }
    }
    if let Some(pattern) = mrn_prefix() {
        for found in pattern.captures_iter(doc.text()) {
            let Some(value) = found.get(1) else {
                continue;
            };
            // Never `emit_checksum`: an MRN is whatever the hospital system
            // minted and there is nothing to verify it against.
            out.extend(doc.emit(value.start(), value.end(), EntityLabel::Mrn, CONTEXT_CUED));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn mrn_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| s.label() == EntityLabel::Mrn)
            .collect()
    }

    #[test]
    fn cued_record_numbers_are_detected_at_the_lowest_band() {
        for (doc, expected) in [
            ("Protokol No: 2026-0004312", "2026-0004312"),
            ("Dosya No 000884-21", "000884-21"),
            ("MRN P-0000431", "P-0000431"),
            ("Hasta No: 4312", "4312"),
            ("PROTOKOL NO 99001234", "99001234"),
            ("protokol no: 2026/0004312", "2026/0004312"),
            ("Kayıt No: 884213", "884213"),
            ("Başvuru numarası 77120", "77120"),
        ] {
            let spans = mrn_spans(doc);
            assert_eq!(spans.len(), 1, "no MRN found in {doc}");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], expected);
            assert!(
                !spans[0].is_checksum_validated(),
                "an MRN has no checksum; nothing may claim one"
            );
            assert!((spans[0].confidence() - CONTEXT_CUED).abs() < f32::EPSILON);
            assert!(spans[0].confidence() < crate::pipeline::ESCALATION_CONFIDENCE_MAX);
        }
    }

    #[test]
    fn an_uncued_number_is_not_a_record_number() {
        for doc in [
            "Hasta 45 yasinda kadin.",
            "Deger 2026-0004312 olarak girildi.",
            "Doz 500 mg olarak ayarlandi.",
        ] {
            assert!(mrn_spans(doc).is_empty(), "false positive in {doc}");
        }
    }

    #[test]
    fn the_cue_survives_turkish_uppercasing_of_dotless_i() {
        // `Kayıt` uppercases to `KAYIT` with ASCII `I`, and `numarası` to
        // `NUMARASI`. A naive case-insensitive match on the dotless forms alone
        // loses both.
        for doc in ["KAYIT NO: 884213", "BAŞVURU NUMARASI 77120"] {
            assert_eq!(mrn_spans(doc).len(), 1, "{doc}");
        }
    }
}
