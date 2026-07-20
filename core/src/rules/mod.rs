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
//! because `１` is three bytes and `1` is one. [`Doc`] keeps both strings and an
//! index from the matching form back to the ORIGINAL, so every span this layer
//! emits is anchored to bytes the caller actually holds.
//!
//! WHY THERE IS EXACTLY ONE NORMALISER: [`Doc`] does not implement its own. It
//! is a thin wrapper over [`crate::text::Skeleton`], which folds digit systems,
//! neutralises zero-width characters and bidi controls, folds exotic spaces to
//! ASCII space and folds homoglyphs onto Latin -- in ONE pass over ONE index.
//! Running a second normaliser after it would mean two offset maps that stack
//! rather than compose, which is the bug class the offset index exists to close.
//! A digit-folding-only `Doc` is why a TCKN split by a soft hyphen or a
//! zero-width joiner used to reach L4 as nothing at all.

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
use crate::text::{Fold, Skeleton};

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
/// A THIN WRAPPER, deliberately: the matching buffer and the index back to the
/// original are [`Skeleton`]'s, not this type's. What `Doc` adds is the two
/// emit constructors, which are the only sanctioned way for an offset found in
/// the matching buffer to become a [`Span`] -- so a rule module cannot build a
/// span against skeleton offsets even by accident.
pub(crate) struct Doc<'a> {
    skeleton: Skeleton<'a>,
}

impl<'a> Doc<'a> {
    pub(crate) fn new(original: &'a str) -> Self {
        Self {
            // Fold::Skeleton and not Fold::Compose: the evasions this layer has
            // to survive are the ones that split a digit run without changing
            // what a human reads, and only the full fold neutralises them.
            skeleton: Skeleton::new(original, Fold::Skeleton),
        }
    }

    /// The text the rules match against. NEVER emitted as document text.
    pub(crate) fn text(&self) -> &str {
        self.skeleton.text()
    }

    /// Re-anchor a matching-buffer range onto the original document.
    fn anchor(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        self.skeleton.original_range(start, end)
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
            self.skeleton.original(),
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
        Span::checksum_validated(self.skeleton.original(), start, end, label).ok()
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

    /// Every character class that used to split a digit run past this layer.
    ///
    /// ONE TEST PER CLASS RATHER THAN ONE OVER A LIST, in a loop that names the
    /// code point in the failure message: each of these was independently
    /// measured as `masked=false, spans=0` against the live pipeline, and a
    /// single aggregated assertion would let four of them regress silently
    /// while the fifth kept the test green.
    ///
    /// NBSP is here with the others even though it is FOLDED to an ASCII space
    /// rather than dropped -- the fold has to leave the digit run contiguous, or
    /// a note pasted out of a word processor loses its national ID.
    #[test]
    fn an_invisible_character_inside_an_id_does_not_hide_it_from_this_layer() {
        let tckn = valid_tckn([4, 8, 2, 0, 0, 0, 0, 0, 1]);
        for (name, separator) in [
            ("U+200D ZERO WIDTH JOINER", '\u{200D}'),
            ("U+00AD SOFT HYPHEN", '\u{00AD}'),
            ("U+200B ZERO WIDTH SPACE", '\u{200B}'),
            ("U+FEFF BYTE ORDER MARK", '\u{FEFF}'),
            ("U+00A0 NO-BREAK SPACE", '\u{00A0}'),
            ("U+2060 WORD JOINER", '\u{2060}'),
        ] {
            let split = format!("{}{separator}{}", &tckn[..4], &tckn[4..]);
            let doc = format!("T.C. Kimlik No: {split}\nServis: Kardiyoloji");
            let found = RuleSet
                .detect(&doc)
                .into_iter()
                .find(|s| s.label() == EntityLabel::Tckn)
                .unwrap_or_else(|| panic!("{name} hid the identifier from L1"));
            assert!(
                found.is_checksum_validated(),
                "{name} lost the checksum flag"
            );
            assert_eq!(
                &doc[found.start()..found.end()],
                split,
                "{name}: the span must cover the ORIGINAL bytes, interior \
                 invisible character included, or L5 leaves a fragment behind"
            );
            assert!(doc.is_char_boundary(found.start()) && doc.is_char_boundary(found.end()));
        }
    }

    #[test]
    fn a_bidi_wrapper_neither_hides_an_id_nor_gets_swallowed_by_its_span() {
        // The already-passing class, asserted here so the integration cannot
        // regress it: the overrides sit at the EDGES of the run, so they must
        // stay OUTSIDE the span even though the matcher never sees them.
        let tckn = valid_tckn([6, 1, 2, 3, 4, 5, 6, 7, 8]);
        let doc = format!("Kimlik: \u{202E}{tckn}\u{202C} kaydı açıldı.");
        let found = RuleSet
            .detect(&doc)
            .into_iter()
            .find(|s| s.label() == EntityLabel::Tckn)
            .expect("a bidi-wrapped id must be detected");
        assert!(found.is_checksum_validated());
        assert_eq!(&doc[found.start()..found.end()], tckn);
    }

    #[test]
    fn the_four_turkish_i_letters_survive_the_layers_normalisation() {
        // I6's signal, checked at the layer that now owns the fold. `İ` U+0130
        // decomposes under NFD to `I` + U+0307 and `ı` U+0131 does not
        // decompose at all, so any decomposing step followed by any
        // mark-dropping step collapses two of the four into one and the
        // strongest name signal in Turkish is gone.
        let doc = Doc::new("İIıi İnci Işık ılık için");
        assert_eq!(doc.text(), "İIıi İnci Işık ılık için");
        let distinct: std::collections::BTreeSet<char> = doc.text().chars().take(4).collect();
        assert_eq!(distinct.len(), 4, "two of the four i letters collapsed");
        // And a decomposed note is put back together rather than stripped: the
        // wrong direction would leave a bare `I`, which is the capital of `ı`.
        assert_eq!(Doc::new("I\u{0307}zmir").text(), "İzmir");
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
