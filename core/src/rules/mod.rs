//! L1 -- the deterministic rules layer.
//!
//! GOVERNING PRINCIPLE, applied in every module below: OVER-MATCH AT THE REGEX
//! STAGE, REJECT AT THE CHECKSUM STAGE. The regex exists to find candidates,
//! not to be right about them. A candidate that passes an arithmetic check is
//! emitted through [`Span::checksum_validated`], which is the only path that
//! sets the flag L4 is forbidden to demote. A candidate that is the right shape
//! but fails the check is a per-module decision, recorded in that module's
//! header, and I2 decides ties in one direction: when in doubt, emit at a lower
//! confidence rather than drop.
//!
//! WHY NORMALISATION IS SEPARATE FROM MATCHING: the brief names full-width and
//! non-ASCII digits as a failure mode, and the obvious fix -- rewrite the
//! document and match on the rewrite -- silently breaks the offset contract,
//! because `１` is three bytes and `1` is one. [`Doc`] keeps both strings and a
//! per-byte index from the normalised form back to the ORIGINAL, so every span
//! this layer emits is anchored to bytes the caller actually holds.

mod date;
mod email;
mod iban;
mod mrn;
mod phone;
mod sgk;
mod tckn;
mod vkn;

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::{DetectorId, Span};

/// Confidence for a format whose type has NO checksum in existence.
///
/// Above [`ESCALATION_CONFIDENCE_MAX`], deliberately: an email address or a
/// `+90 5XX XXX XX XX` string is its own evidence, there is no arithmetic that
/// could raise it further, and sending it to an adjudicator would spend the
/// expensive path on the one class of span nothing can add information to.
///
/// [`ESCALATION_CONFIDENCE_MAX`]: crate::pipeline::ESCALATION_CONFIDENCE_MAX
pub(crate) const CHECKSUM_ABSENT: f32 = 0.90;

/// Confidence for a candidate that had a checksum and FAILED it.
///
/// Emitted rather than dropped wherever the surface form is distinctive enough
/// that a failure is more likely to be a typo in the note than a coincidence
/// (I2: when in doubt, emit). Below the escalation ceiling, so L4 may argue it
/// down -- which is exactly right, because nothing arithmetic vouches for it.
pub(crate) const CHECKSUM_FAILED: f32 = 0.50;

/// Confidence for a candidate matched only because a nearby keyword said so.
///
/// The lowest band this layer emits. A `Protokol No` or `SGK No` cue makes the
/// digits that follow an identifier by context, not by shape, and the same
/// digits without the cue would be nothing. Demotable by construction.
pub(crate) const CONTEXT_CUED: f32 = 0.45;

/// Compile a pattern exactly once.
///
/// `None` on a compile failure rather than a panic, because this crate forbids
/// `unwrap`/`expect` outside tests. A silently absent detector would be far
/// worse than a panic in a masking pipeline -- it is a missed identifier, which
/// is a breach -- so the possibility is closed at build time instead: the test
/// `every_pattern_in_the_layer_compiles` fails the build if any pattern here is
/// ever edited into something that does not compile.
fn compiled(cell: &'static OnceLock<Option<Regex>>, pattern: &str) -> Option<&'static Regex> {
    cell.get_or_init(|| Regex::new(pattern).ok()).as_ref()
}

/// A document in both the form the caller holds and the form the rules match.
///
/// `origin` has one entry per byte of `normalized`, plus a terminating entry:
/// `origin[i]` is the byte offset in `original` of the character whose
/// normalised form begins at byte `i`. Because every entry names the START of
/// an original character, a normalised offset always maps to a valid UTF-8
/// character boundary in the original -- which is the property [`Span::new`]
/// refuses to build a span without.
pub(crate) struct Doc<'a> {
    original: &'a str,
    normalized: String,
    origin: Vec<usize>,
}

/// Map one character to its ASCII decimal equivalent.
///
/// Explicit ranges rather than `char::to_digit`, which is ASCII-only, and
/// rather than a general Unicode decomposition, which would also fold letters
/// and change the shape of the very tokens the rules key on.
fn ascii_digit(ch: char) -> Option<char> {
    let value = match ch {
        '0'..='9' => return Some(ch),
        // Fullwidth forms, which is how a digit arrives from a CJK-locale IME
        // or a badly transcoded hospital export.
        '\u{FF10}'..='\u{FF19}' => ch as u32 - 0xFF10,
        // Arabic-Indic and its Extended (Persian/Urdu) variant.
        '\u{0660}'..='\u{0669}' => ch as u32 - 0x0660,
        '\u{06F0}'..='\u{06F9}' => ch as u32 - 0x06F0,
        // Devanagari, present in multilingual EHR exports.
        '\u{0966}'..='\u{096F}' => ch as u32 - 0x0966,
        _ => return None,
    };
    char::from_digit(value, 10)
}

impl<'a> Doc<'a> {
    pub(crate) fn new(original: &'a str) -> Self {
        let mut normalized = String::with_capacity(original.len());
        let mut origin = Vec::with_capacity(original.len() + 1);
        for (offset, ch) in original.char_indices() {
            normalized.push(ascii_digit(ch).unwrap_or(ch));
            // Every byte of the normalised character anchors to the START of
            // the original character. A three-byte `１` collapses to a
            // one-byte `1` and a two-byte `ş` stays two bytes; in both cases
            // the mapped offset is where the original character begins.
            origin.resize(normalized.len(), offset);
        }
        origin.push(original.len());
        Self {
            original,
            normalized,
            origin,
        }
    }

    /// The text the rules match against: digits ASCII, everything else intact.
    pub(crate) fn text(&self) -> &str {
        &self.normalized
    }

    /// Re-anchor a normalised range onto the original document.
    fn anchor(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        Some((*self.origin.get(start)?, *self.origin.get(end)?))
    }

    /// Emit an unvalidated candidate at the given confidence.
    ///
    /// Returns `None` rather than an error because every rejection here is
    /// structurally impossible -- the offsets came from a match on a string
    /// this type built -- and a detector has no error channel to report an
    /// impossibility through. The alternative, `expect`, is banned in library
    /// paths.
    pub(crate) fn emit(
        &self,
        start: usize,
        end: usize,
        label: EntityLabel,
        confidence: f32,
    ) -> Option<Span> {
        let (start, end) = self.anchor(start, end)?;
        Span::new(
            self.original,
            start,
            end,
            label,
            DetectorId::Rules,
            confidence,
        )
        .ok()
    }

    /// Emit a candidate that PASSED its arithmetic check.
    ///
    /// The only constructor in the crate that sets `checksum_validated`, so
    /// this is the single line that decides a span is undemotable. It is
    /// reachable only from a module that has just run the check.
    pub(crate) fn emit_checksum(
        &self,
        start: usize,
        end: usize,
        label: EntityLabel,
    ) -> Option<Span> {
        let (start, end) = self.anchor(start, end)?;
        Span::checksum_validated(self.original, start, end, label).ok()
    }
}

/// Every maximal run of ASCII digits, as normalised byte ranges.
///
/// MAXIMAL, and that is the point: the brief names "IDs glued inside a longer
/// digit run" as a failure mode, so the modules that own checksummed types
/// slide a window across each run instead of demanding that the run be exactly
/// the right length.
pub(crate) fn digit_runs(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut runs = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            runs.push((start, index));
        } else {
            index += 1;
        }
    }
    runs
}

/// True when the byte before `start` is not an ASCII digit.
pub(crate) fn digit_free_before(text: &str, start: usize) -> bool {
    start == 0 || !text.as_bytes()[start - 1].is_ascii_digit()
}

/// True when the byte at `end` is not an ASCII digit.
pub(crate) fn digit_free_after(text: &str, end: usize) -> bool {
    text.as_bytes().get(end).is_none_or(|b| !b.is_ascii_digit())
}

/// Numeric values of an ASCII digit slice.
pub(crate) fn digit_values(run: &str) -> Vec<u8> {
    run.bytes().map(|b| b - b'0').collect()
}

/// L1: deterministic regex plus checksum rules.
///
/// One instance, no state: every pattern is compiled once into a process-wide
/// `OnceLock` (the layer has a ~1ms budget, and compiling a regex per call
/// spends all of it), so the type stays `Copy` and free to construct.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleSet;

impl RuleSet {
    /// Every direct identifier matchable by regex and confirmable by checksum.
    ///
    /// Offsets are BYTE offsets into `text`, the ORIGINAL string, on character
    /// boundaries. Overlaps are NOT resolved here -- two modules disagreeing
    /// about the same bytes is evidence, and discarding it before L4 sees it
    /// would be this layer voting, which I2 forbids. Only byte-identical
    /// duplicates are collapsed.
    pub fn detect(&self, text: &str) -> Vec<Span> {
        let doc = Doc::new(text);
        let mut spans = Vec::new();
        tckn::detect(&doc, &mut spans);
        vkn::detect(&doc, &mut spans);
        iban::detect(&doc, &mut spans);
        sgk::detect(&doc, &mut spans);
        phone::detect(&doc, &mut spans);
        date::detect(&doc, &mut spans);
        email::detect(&doc, &mut spans);
        mrn::detect(&doc, &mut spans);
        dedup(&mut spans);
        spans
    }
}

/// A checksum-valid TCKN, derived at run time for tests in other modules.
///
/// I8: a checksum-valid national id may never be a literal in a committed
/// file, and the pre-commit hook enforces it. Any test outside this module that
/// needs one -- the pipeline's end-to-end masking test, for instance -- calls
/// this rather than writing digits down.
#[cfg(test)]
pub(crate) fn checksum_valid_tckn_for_tests() -> String {
    tests::valid_tckn([1, 2, 3, 4, 5, 6, 7, 8, 9])
}

/// Collapse byte-identical proposals, keeping the most confident.
///
/// Only EXACT duplicates. `union_widest` downstream counts distinct detector
/// ids, so nothing here can manufacture agreement -- every span in this vector
/// carries [`DetectorId::Rules`] -- but a repeated identical span would still
/// noisy-OR its own confidence upward, and two modules recognising the same
/// bytes as the same label at the same confidence is one finding.
fn dedup(spans: &mut Vec<Span>) {
    spans.sort_by(|a, b| {
        a.start()
            .cmp(&b.start())
            .then(a.end().cmp(&b.end()))
            .then(a.label().cmp(&b.label()))
            .then(b.confidence().total_cmp(&a.confidence()))
            .then(b.is_checksum_validated().cmp(&a.is_checksum_validated()))
    });
    spans.dedup_by(|a, b| a == b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::Layer;

    /// Build a checksum-valid TCKN AT RUNTIME.
    ///
    /// I8: a checksum-valid national ID may never appear as a literal in a
    /// committed file, and the pre-commit hook enforces it. Every test in this
    /// layer that needs a valid one derives it here.
    pub(super) fn valid_tckn(prefix: [u8; 9]) -> String {
        let odd: u32 = (0..9).step_by(2).map(|i| u32::from(prefix[i])).sum();
        let even: u32 = (1..9).step_by(2).map(|i| u32::from(prefix[i])).sum();
        let tenth = (odd * 7 + 100 - even) % 10;
        let total: u32 = prefix.iter().map(|d| u32::from(*d)).sum::<u32>() + tenth;
        let mut out = String::with_capacity(11);
        for digit in prefix {
            out.push(char::from(b'0' + digit));
        }
        out.push(char::from(
            b'0' + u8::try_from(tenth).expect("single digit"),
        ));
        out.push(char::from(
            b'0' + u8::try_from(total % 10).expect("single digit"),
        ));
        out
    }

    #[test]
    fn every_pattern_in_the_layer_compiles() {
        // WHY this test carries weight: `compiled` returns None instead of
        // panicking on a bad pattern, so a typo in a regex literal would turn
        // a whole detector off in silence, and a detector that is off is a
        // missed identifier. This is the check that makes the silence a build
        // failure instead.
        assert!(tckn::pattern_ok(), "tckn");
        assert!(vkn::pattern_ok(), "vkn");
        assert!(iban::pattern_ok(), "iban");
        assert!(sgk::pattern_ok(), "sgk");
        assert!(phone::pattern_ok(), "phone");
        assert!(date::pattern_ok(), "date");
        assert!(email::pattern_ok(), "email");
        assert!(mrn::pattern_ok(), "mrn");
    }

    #[test]
    fn every_emitted_span_is_a_rules_span_on_a_char_boundary() {
        let tckn = valid_tckn([1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let doc = format!(
            "Hasta Ayşe Yılmaz, TCKN {tckn}, tel 0(532) 000 00 00, \
             e-posta ayse@ornek-hastane.example, doğum 12.03.1968, \
             IBAN TR33 0006 1005 1978 6457 8413 26, Protokol No: 2026-0004312."
        );
        let spans = RuleSet.detect(&doc);
        assert!(
            !spans.is_empty(),
            "the layer found nothing in a loaded note"
        );
        for span in &spans {
            assert_eq!(span.source(), Layer::Rules);
            assert_eq!(span.detector_id(), DetectorId::Rules);
            assert!(doc.is_char_boundary(span.start()));
            assert!(doc.is_char_boundary(span.end()));
            assert!(span.end() <= doc.len());
        }
    }

    #[test]
    fn offsets_survive_multibyte_turkish_before_the_match() {
        // The failure this guards: a detector that counted CHARACTERS would
        // land short of the identifier and inside a letter, because `ş`, `ğ`
        // and `İ` are two bytes each.
        let tckn = valid_tckn([9, 8, 7, 6, 5, 4, 3, 2, 1]);
        let doc = format!("Şükrü Gökçe'nin İş yeri kaydı, TCKN {tckn}.");
        let spans = RuleSet.detect(&doc);
        let found = spans
            .iter()
            .find(|s| s.label() == EntityLabel::Tckn)
            .expect("the TCKN must be found after multi-byte text");
        assert_eq!(&doc[found.start()..found.end()], tckn);
        let char_index = doc
            .char_indices()
            .position(|(i, _)| i == found.start())
            .expect("char index");
        assert_ne!(
            found.start(),
            char_index,
            "fixture must place the id after multi-byte characters"
        );
    }

    #[test]
    fn fullwidth_digits_are_matched_and_offsets_map_to_the_original() {
        let tckn = valid_tckn([2, 4, 6, 8, 1, 3, 5, 7, 9]);
        let wide: String = tckn
            .chars()
            .map(|c| char::from_u32(c as u32 - '0' as u32 + 0xFF10).unwrap_or(c))
            .collect();
        let doc = format!("TCKN {wide} kayıtlıdır.");
        let spans = RuleSet.detect(&doc);
        let found = spans
            .iter()
            .find(|s| s.label() == EntityLabel::Tckn)
            .expect("a full-width TCKN must be detected");
        assert!(found.is_checksum_validated());
        assert_eq!(
            &doc[found.start()..found.end()],
            wide,
            "offsets must address the ORIGINAL full-width digits, not the normalised copy"
        );
        assert_eq!(found.byte_len(), wide.len());
        assert!(
            found.byte_len() > 11,
            "full-width digits are three bytes each"
        );
    }

    #[test]
    fn arabic_indic_digits_normalise_too() {
        let tckn = valid_tckn([3, 1, 4, 1, 5, 9, 2, 6, 5]);
        let arabic: String = tckn
            .chars()
            .map(|c| char::from_u32(c as u32 - '0' as u32 + 0x0660).unwrap_or(c))
            .collect();
        let doc = format!("Kimlik {arabic}");
        let found = RuleSet
            .detect(&doc)
            .into_iter()
            .find(|s| s.label() == EntityLabel::Tckn)
            .expect("an Arabic-Indic TCKN must be detected");
        assert!(found.is_checksum_validated());
        assert_eq!(&doc[found.start()..found.end()], arabic);
    }

    #[test]
    fn identical_spans_are_deduplicated() {
        let doc = "e-posta: ayse@ornek.example";
        let spans = RuleSet.detect(doc);
        let emails: Vec<_> = spans
            .iter()
            .filter(|s| s.label() == EntityLabel::Email)
            .collect();
        assert_eq!(emails.len(), 1);
    }

    #[test]
    fn an_empty_document_yields_nothing() {
        assert!(RuleSet.detect("").is_empty());
        assert!(RuleSet
            .detect("Hasta genel durumu iyi, taburcu edildi.")
            .is_empty());
    }

    #[test]
    fn digit_runs_are_maximal() {
        assert_eq!(digit_runs("ab12cd345"), vec![(2, 4), (6, 9)]);
        assert_eq!(digit_runs("nodigits"), Vec::new());
    }
}
