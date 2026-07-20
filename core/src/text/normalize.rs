//! The normalisation pass, and the index that maps every offset back.
//!
//! # The contract this exists to keep
//!
//! Every span the pipeline emits is a BYTE OFFSET INTO THE ORIGINAL TEXT
//! (`core/src/span.rs`). Every transform in this module changes byte lengths:
//! stripping a zero-width space removes three bytes, folding an Arabic-Indic
//! digit turns two bytes into one, composing `I` + U+0307 turns three into two,
//! skeletoning `ﬁ` turns three into two while turning one character into two.
//! So the normalised buffer and the original agree on nothing, and the index
//! back is not an implementation detail of this module -- it IS this module. A
//! matcher runs on [`Skeleton::text`], and [`Skeleton::original_range`] is the
//! only sanctioned way for what it found to become a span.
//!
//! # Turkish safety, which decides the normalisation form
//!
//! `İ` U+0130 HAS a canonical decomposition: under NFD and NFKD it becomes `I`
//! U+0049 + U+0307 COMBINING DOT ABOVE. `ı` U+0131 has NO decomposition -- it is
//! atomic in every form. That asymmetry is the trap. Decompose, and any later
//! step that drops or reorders combining marks (a diacritic stripper, a subword
//! tokenizer trained on stripped text, a font that cannot render U+0307) leaves
//! a bare `I`, which is the capital of `ı`. Two of Turkish's four `i` letters
//! collapse into one and the dotted/dotless distinction is gone -- the signal
//! I6 protects when it bans `*-uncased` backbones for Turkish outright.
//!
//! **This pass therefore only ever COMPOSES. It never decomposes.** A note that
//! arrives already decomposed is put back together (`I` + U+0307 becomes `İ`);
//! a note that arrives composed is left alone. The direction is the safety
//! property, and [`the_four_turkish_i_letters_survive_the_pass`] is the test
//! that fails if it is ever reversed.
//!
//! Two further bans, for the same reason one layer out:
//!
//! * **NFKC/NFKD are never applied as a blanket transform.** They are lossy by
//!   design and irreversible. Their effect on fullwidth digits and letterlike
//!   forms is wanted, so that effect is reproduced by an explicit table in
//!   [`super::confusables`] and [`super::digits`], on the MATCHING buffer only.
//! * **Default Unicode case folding is never applied.** It maps both `İ` and `I`
//!   to `i`, where Turkish requires `I` -> `ı`. The crate's one correct fold is
//!   `detect::align::Normalization::TurkishDottedI`, and this module deliberately
//!   does not introduce a second lowercaser.
//!
//! # What this is NOT
//!
//! This closes an evasion class for the identifiers L1 can PROVE -- TCKN, VKN,
//! IBAN, phone, email, MRN, date. It does not make the pipeline detect names.
//! `deid-tr` masks zero person names today, because L2 has no trained model, and
//! folding a Cyrillic homoglyph out of `Аyşe` produces a clean `Ayşe` that
//! nothing is currently looking for. The fold is what a gazetteer or a
//! checkpoint will need in order to work at all; it is not itself a detector.

use super::{confusables, digits, invisible};

/// How far to normalise.
///
/// Two levels rather than a bag of flags, because the combinations that are safe
/// are not obvious and a caller assembling their own is a caller who will
/// eventually assemble "strip combining marks without composing first".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fold {
    /// Leave the text exactly as it is. The index is the identity.
    ///
    /// The default, so that a caller who has not thought about normalisation
    /// gets the behaviour that changes nothing.
    #[default]
    Identity,
    /// Composition only: put decomposed Latin and Turkish letters back together.
    ///
    /// The one level whose output is still faithful text rather than a matching
    /// artefact. Safe to reason about as "the same note, canonically written".
    Compose,
    /// The full matching skeleton.
    ///
    /// Compose, then drop zero-width characters and bidi controls, fold exotic
    /// spaces to ASCII space, fold every decimal digit system to ASCII, and fold
    /// Cyrillic/Greek/fullwidth homoglyphs onto Latin.
    ///
    /// FOR MATCHING ONLY. This buffer is never emitted, never persisted, and
    /// never hashed into a `Span`. It exists so that a rule, a gazetteer or an
    /// allowlist can be run against it and the result mapped back.
    Skeleton,
}

/// The document as a matcher sees it, plus the exact index back to the original.
///
/// Holds a BORROW of the original rather than a copy, so a caller cannot map
/// offsets against one string and slice them out of another: the borrow makes
/// "the original" one object with a lifetime instead of a convention.
#[derive(Debug, Clone)]
pub struct Skeleton<'a> {
    original: &'a str,
    text: String,
    /// `starts[i]` is the offset in `original` where the character that produced
    /// byte `i` of `text` BEGINS. Length `text.len() + 1`.
    starts: Vec<usize>,
    /// `ends[i]` is the offset in `original` where the character that produced
    /// byte `i - 1` of `text` ENDS. Length `text.len() + 1`, and `ends[0]` is 0.
    ///
    /// TWO INDICES AND NOT ONE, which is the fix for the deletion-boundary bug.
    /// With a single start index, mapping the exclusive end of `12` in
    /// `12<ZWSP>34` looks up the start of `3` -- which is on the far side of the
    /// deleted character, so the span silently swallows the ZWSP that sat
    /// outside it. A deleted character INSIDE a span must be covered; one at its
    /// EDGE must not; and only a start index and an end index together can tell
    /// those two apart. Both edges are tested.
    ends: Vec<usize>,
    /// True when the fold rewrote nothing, so the two strings coincide.
    identity: bool,
}

/// What one input unit folds to. No allocation: a fold is at most a few bytes.
enum Folded {
    /// Removed from the skeleton entirely.
    Drop,
    /// Exactly one output character.
    One(char),
    /// One input character, several output characters (`ﬁ` -> `fi`).
    Many(&'static str),
}

impl<'a> Skeleton<'a> {
    /// Fold a document and record the index back to it.
    #[must_use]
    pub fn new(original: &'a str, fold: Fold) -> Self {
        let mut text = String::with_capacity(original.len());
        let mut starts = Vec::with_capacity(original.len() + 1);
        let mut ends = Vec::with_capacity(original.len() + 1);
        ends.push(0);
        let mut buffer = [0_u8; 4];
        let mut characters = original.char_indices().peekable();
        // Half of the context an exotic space needs before it can be dropped
        // rather than folded; the other half is a peek at the next character.
        let mut previous_was_digit = false;

        while let Some((start, character)) = characters.next() {
            let mut unit_end = start + character.len_utf8();
            let mut base = character;
            // COMPOSITION IS A LOOK-AHEAD, and it runs before anything else can
            // see the combining mark. `I` + U+0307 must become `İ` here, or the
            // mark reaches the skeleton stage as a stray and is dropped, leaving
            // a bare `I` -- the exact collapse this module exists to prevent.
            // Looping rather than pairing once handles a base carrying two
            // marks, which a badly transcoded export does produce.
            if fold != Fold::Identity {
                while let Some(&(mark_start, mark)) = characters.peek() {
                    let Some(composed) = compose(base, mark) else {
                        break;
                    };
                    base = composed;
                    unit_end = mark_start + mark.len_utf8();
                    characters.next();
                }
            }

            // AN EXOTIC SPACE BETWEEN TWO DIGITS SEPARATES NOTHING, and that is
            // the one case where the "fold, never drop" rule for spaces is
            // wrong. Spaces are folded rather than deleted because they divide
            // TOKENS, and deleting one glues `Ayşe` to `Yılmaz`. Two digits of
            // one number are not two tokens: a NO-BREAK SPACE is what a word
            // processor inserts precisely to say "these digits belong together
            // and must not wrap", and a PDF extractor hands it straight through
            // mid-identifier. Folding it to an ASCII space there splits an
            // eleven-digit run into 4 and 7, which is a missed national ID.
            //
            // Deliberately NOT extended to the ASCII space: `0532 123 45 67` is
            // how a phone number is written on purpose, and bridging real spaces
            // is a detection-tolerance decision for the rule modules to make, not
            // something a normaliser should impose on every matcher in the crate.
            let digit_bridge = fold == Fold::Skeleton
                && previous_was_digit
                && invisible::ascii_space(base).is_some()
                && characters
                    .peek()
                    .is_some_and(|(_, next)| digits::ascii_digit(*next).is_some());

            let written: &str = if digit_bridge {
                ""
            } else {
                match fold_character(base, fold) {
                    Folded::Drop => "",
                    Folded::One(one) => one.encode_utf8(&mut buffer),
                    Folded::Many(many) => many,
                }
            };
            // A dropped character leaves the flag alone, so a digit run stays
            // "previous was a digit" across a zero-width character too.
            if let Some(is_digit) = (!written.is_empty()).then(|| digits::ascii_digit(base)) {
                previous_was_digit = is_digit.is_some();
            }
            text.push_str(written);
            // Every byte of the output maps to the START of the original unit,
            // and every output position maps back to that unit's END. An
            // interior byte of a multi-byte original character is therefore
            // never reachable as a mapped boundary, which is what keeps every
            // offset this type hands out on a UTF-8 character boundary of the
            // original -- the property `Span::new` refuses to build without.
            starts.extend(core::iter::repeat_n(start, written.len()));
            ends.extend(core::iter::repeat_n(unit_end, written.len()));
        }
        starts.push(original.len());

        let identity = text == original;
        Self {
            original,
            text,
            starts,
            ends,
            identity,
        }
    }

    /// The buffer a matcher runs against. NEVER emit this as document text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The document the caller holds and every span is anchored to.
    #[must_use]
    pub fn original(&self) -> &'a str {
        self.original
    }

    /// True when the fold changed nothing, so the two strings coincide.
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        self.identity
    }

    /// Map a byte range in the skeleton to ORIGINAL byte offsets.
    ///
    /// Returns `None` when the range is out of bounds, inverted, or does not lie
    /// on character boundaries of the skeleton. A mid-character offset is
    /// REFUSED rather than rounded, because the index maps an interior byte to
    /// the start of its character, so rounding would silently produce a
    /// truncated range -- and a truncated range is a partially masked
    /// identifier, which reads as a success and is a breach.
    ///
    /// Also returns `None` for a range that maps to an empty original range,
    /// which is what slicing the interior of a one-to-many fold produces. The
    /// caller gets "no span" rather than a `SpanNotOrdered` error surfacing from
    /// deep inside span construction.
    #[must_use]
    pub fn original_range(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if start > end || end > self.text.len() {
            return None;
        }
        if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
            return None;
        }
        let mapped_start = *self.starts.get(start)?;
        let mapped_end = *self.ends.get(end)?;
        // Defensive rather than expected: the two indices are built in lockstep,
        // so an inversion here would be a bug in the builder. Reporting it as
        // "no span" keeps a bug from becoming a wrong span.
        (mapped_start < mapped_end).then_some((mapped_start, mapped_end))
    }

    /// The original text a skeleton range covers.
    #[must_use]
    pub fn original_slice(&self, start: usize, end: usize) -> Option<&'a str> {
        let (from, to) = self.original_range(start, end)?;
        self.original.get(from..to)
    }
}

/// Compose a base character and a following combining mark, if they compose.
///
/// A CURATED SUBSET OF CANONICAL COMPOSITION, not NFC. Full NFC is a Unicode
/// data table this crate does not carry (see `super::confusables` for why the
/// dependency is not taken), so what is here is the Latin and Turkish set that
/// actually occurs in Turkish clinical text and its code-switched Latin/English
/// medical register. A base-plus-mark pair outside this table is left as two
/// characters; that is a stated limitation, and it fails safe -- an uncomposed
/// pair is still two visible characters, not a collapsed letter.
///
/// The FIRST entry is the one the module exists for.
const fn compose(base: char, mark: char) -> Option<char> {
    Some(match (base, mark) {
        // COMBINING DOT ABOVE onto a capital I. This single line is what makes
        // a decomposed `İ` survive: without it the mark is dropped downstream
        // and `İstanbul` becomes `Istanbul`, whose lowercase in Turkish is
        // `ıstanbul`. Two different letters, one of them wrong.
        ('I', '\u{0307}') => '\u{0130}',
        // The rest of the Turkish alphabet, as base plus mark.
        ('c', '\u{0327}') => 'ç',
        ('C', '\u{0327}') => 'Ç',
        ('s', '\u{0327}') => 'ş',
        ('S', '\u{0327}') => 'Ş',
        ('g', '\u{0306}') => 'ğ',
        ('G', '\u{0306}') => 'Ğ',
        ('o', '\u{0308}') => 'ö',
        ('O', '\u{0308}') => 'Ö',
        ('u', '\u{0308}') => 'ü',
        ('U', '\u{0308}') => 'Ü',
        // Turkish circumflex, which survives in words of Arabic/Persian origin
        // and in a handful of proper nouns.
        ('a', '\u{0302}') => 'â',
        ('A', '\u{0302}') => 'Â',
        ('i', '\u{0302}') => 'î',
        ('u', '\u{0302}') => 'û',
        // Latin/English medical register and transliterated foreign names.
        ('a', '\u{0301}') => 'á',
        ('e', '\u{0301}') => 'é',
        ('i', '\u{0301}') => 'í',
        ('o', '\u{0301}') => 'ó',
        ('u', '\u{0301}') => 'ú',
        ('a', '\u{0300}') => 'à',
        ('e', '\u{0300}') => 'è',
        ('n', '\u{0303}') => 'ñ',
        ('a', '\u{0308}') => 'ä',
        ('e', '\u{0308}') => 'ë',
        ('i', '\u{0308}') => 'ï',
        _ => return None,
    })
}

/// Apply the per-character stage of a fold, after composition has run.
fn fold_character(character: char, fold: Fold) -> Folded {
    if fold != Fold::Skeleton {
        return Folded::One(character);
    }
    // ORDER MATTERS AND IS NOT ARBITRARY.
    //
    // Removal first: a zero-width character or a bidi control has no skeleton,
    // no digit value and no script, so asking the later stages about it wastes
    // the question. A stray combining mark is dropped HERE and only here --
    // composition has already run, so anything still standing alone is
    // decoration on a letter with no precomposed form.
    if invisible::is_zero_width(character)
        || invisible::is_bidi_control(character)
        || invisible::is_stray_combining_mark(character)
    {
        return Folded::Drop;
    }
    if let Some(space) = invisible::ascii_space(character) {
        return Folded::One(space);
    }
    // Digits before confusables: a fullwidth `１` is both a digit and a
    // fullwidth form, and it must arrive at a checksum as `1`, not as a letter
    // table's idea of it.
    if let Some(digit) = digits::ascii_digit(character) {
        return Folded::One(digit);
    }
    match confusables::skeleton(character) {
        Some(folded) => Folded::Many(folded),
        None => Folded::One(character),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic. No real PHI, and no checksum-valid national ID (I8).
    const DOC: &str = "Hasta Ayşe Yılmaz, Dr. Şükrü Gökçe tarafından görüldü.";

    #[test]
    fn the_identity_fold_maps_every_offset_to_itself() {
        let skeleton = Skeleton::new(DOC, Fold::Identity);
        assert!(skeleton.is_identity());
        assert_eq!(skeleton.text(), DOC);
        let start = DOC.find("Ayşe").expect("fixture");
        let end = start + "Ayşe".len();
        assert_eq!(skeleton.original_range(start, end), Some((start, end)));
        assert_eq!(skeleton.original_slice(start, end), Some("Ayşe"));
    }

    #[test]
    fn the_four_turkish_i_letters_survive_the_pass() {
        // THE Turkish safety test, stated for every fold level. NFD would turn
        // `İ` into `I` + U+0307 and any later mark-stripper would leave `I`,
        // which is the capital of `ı`: four letters would become three, and the
        // dotted/dotless distinction that I6 protects would be gone.
        const FOUR: &str = "İIıi";
        for fold in [Fold::Identity, Fold::Compose, Fold::Skeleton] {
            let skeleton = Skeleton::new(FOUR, fold);
            assert_eq!(skeleton.text(), FOUR, "{fold:?} rewrote the four letters");
            let characters: Vec<char> = skeleton.text().chars().collect();
            assert_eq!(characters.len(), 4, "{fold:?} changed the character count");
            let mut distinct = characters.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(
                distinct.len(),
                4,
                "{fold:?} made two of the four letters equal"
            );
            // And specifically: neither pair collapsed.
            assert_ne!(characters[0], characters[1], "İ and I must differ");
            assert_ne!(characters[2], characters[3], "ı and i must differ");
            assert_ne!(characters[1], characters[2], "I and ı must differ");
        }
    }

    #[test]
    fn a_decomposed_dotted_capital_is_recomposed_rather_than_stripped() {
        // The direction of the whole module. A note that arrives NFD-normalised
        // is put back together; nothing in this crate ever takes it apart.
        const DECOMPOSED: &str = "I\u{0307}stanbul";
        let skeleton = Skeleton::new(DECOMPOSED, Fold::Compose);
        assert_eq!(skeleton.text(), "İstanbul");
        assert!(!skeleton.is_identity());
        // Three bytes in, two bytes out: the fold shortens here, and the offsets
        // must still address the original pair.
        let end = "İ".len();
        assert_eq!(skeleton.original_slice(0, end), Some("I\u{0307}"));
        assert_eq!(skeleton.original_range(0, end), Some((0, 3)));
        // The composed form is left exactly as it is.
        assert!(Skeleton::new("İstanbul", Fold::Compose).is_identity());
    }

    #[test]
    fn composition_runs_before_stray_marks_are_dropped() {
        // The ordering bug this guards: drop combining marks first and
        // `I` + U+0307 becomes `I`, which is the capital of `ı`.
        let skeleton = Skeleton::new("I\u{0307}nci", Fold::Skeleton);
        assert_eq!(skeleton.text(), "İnci");
        assert_ne!(
            skeleton.text(),
            "Inci",
            "the dot was stripped, not composed"
        );
    }

    #[test]
    fn a_mark_with_no_precomposed_form_is_dropped_only_from_the_skeleton() {
        // U+0304 MACRON has no entry in the composition table, so it survives
        // `Compose` as itself and is dropped by `Skeleton`. The original bytes
        // are untouched either way.
        const MARKED: &str = "Ayse\u{0304}";
        assert_eq!(Skeleton::new(MARKED, Fold::Compose).text(), MARKED);
        let skeleton = Skeleton::new(MARKED, Fold::Skeleton);
        assert_eq!(skeleton.text(), "Ayse");
        assert_eq!(
            skeleton.original(),
            MARKED,
            "the original is never rewritten"
        );
    }

    #[test]
    fn round_tripping_holds_where_normalisation_changes_byte_length() {
        // Turkish text whose fold moves lengths in BOTH directions: the
        // decomposed `İ` shortens 3 bytes to 2, the fullwidth `Ａ` shortens 3 to
        // 1, the Cyrillic `е` shortens 2 to 1, and the ligature `ﬁ` turns one
        // 3-byte character into two 1-byte ones. Every original slice must still
        // come back exactly.
        const MIXED: &str = "I\u{0307}nci \u{FF21}li \u{0435}ren \u{FB01}kir Şükrü";
        let skeleton = Skeleton::new(MIXED, Fold::Skeleton);
        assert_eq!(skeleton.text(), "İnci Ali eren fikir Şükrü");
        assert_ne!(
            skeleton.text().len(),
            MIXED.len(),
            "the fixture must actually change byte length"
        );

        for (needle, expected) in [
            ("İnci", "I\u{0307}nci"),
            ("Ali", "\u{FF21}li"),
            ("eren", "\u{0435}ren"),
            ("Şükrü", "Şükrü"),
        ] {
            let start = skeleton.text().find(needle).expect("skeleton contains it");
            let end = start + needle.len();
            assert_eq!(
                skeleton.original_slice(start, end),
                Some(expected),
                "{needle} did not map back"
            );
        }
    }

    #[test]
    fn every_mapped_offset_lands_on_a_character_boundary_of_the_original() {
        // The property `Span::new` refuses to build a span without, asserted
        // exhaustively over a string full of multi-byte and folded characters.
        const MIXED: &str = "İIıi şğü \u{FF21}\u{0430}\u{03BF} 1\u{200B}2\u{0661} I\u{0307}z";
        let skeleton = Skeleton::new(MIXED, Fold::Skeleton);
        for start in 0..=skeleton.text().len() {
            if !skeleton.text().is_char_boundary(start) {
                assert_eq!(
                    skeleton.original_range(start, skeleton.text().len()),
                    None,
                    "a mid-character offset must be refused, not rounded"
                );
                continue;
            }
            for end in start..=skeleton.text().len() {
                if !skeleton.text().is_char_boundary(end) {
                    continue;
                }
                let Some((from, to)) = skeleton.original_range(start, end) else {
                    continue;
                };
                assert!(
                    MIXED.is_char_boundary(from),
                    "skeleton {start} mapped to {from}, inside a character"
                );
                assert!(
                    MIXED.is_char_boundary(to),
                    "skeleton {end} mapped to {to}, inside a character"
                );
                assert!(from < to && to <= MIXED.len());
                // And the range is sliceable, which is the only thing a caller
                // will actually do with it.
                assert!(MIXED.get(from..to).is_some());
            }
        }
    }

    #[test]
    fn a_deleted_character_at_a_span_edge_does_not_extend_the_span() {
        // PITFALL 1, and the reason this type carries two indices. `12<ZWSP>34`
        // skeletons to `1234`. The span over `12` must map to `12` and must NOT
        // swallow the zero-width space that sits immediately after it; the span
        // over `34` must not swallow it either; the span over `1234` must cover
        // it, because it is interior.
        const SPLIT: &str = "12\u{200B}34";
        let skeleton = Skeleton::new(SPLIT, Fold::Skeleton);
        assert_eq!(skeleton.text(), "1234");
        assert_eq!(skeleton.original_slice(0, 2), Some("12"));
        assert_eq!(skeleton.original_slice(2, 4), Some("34"));
        assert_eq!(skeleton.original_slice(0, 4), Some(SPLIT));
        // Stated as offsets too, because the slice comparison alone would pass
        // for a range that happened to cover the same characters differently.
        assert_eq!(skeleton.original_range(0, 2), Some((0, 2)));
        assert_eq!(skeleton.original_range(2, 4), Some((5, 7)));
    }

    #[test]
    fn a_deleted_character_at_the_very_start_or_end_is_excluded() {
        // The same rule at the document edges, where an off-by-one is easiest.
        const WRAPPED: &str = "\u{FEFF}Ayşe\u{00AD}";
        let skeleton = Skeleton::new(WRAPPED, Fold::Skeleton);
        assert_eq!(skeleton.text(), "Ayşe");
        assert_eq!(
            skeleton.original_slice(0, skeleton.text().len()),
            Some("Ayşe"),
            "the BOM and the soft hyphen sit outside the name and must stay outside it"
        );
    }

    #[test]
    fn slicing_the_interior_of_a_one_to_many_fold_covers_the_whole_character() {
        // PITFALL 2. `ﬁ` is one original character and two skeleton bytes, so a
        // boundary between `f` and `i` has no counterpart in the original. It
        // must widen to the whole ligature rather than produce an empty range
        // that surfaces as a span-construction error somewhere far away.
        const LIGATURE: &str = "\u{FB01}kir";
        let skeleton = Skeleton::new(LIGATURE, Fold::Skeleton);
        assert_eq!(skeleton.text(), "fikir");
        assert_eq!(skeleton.original_slice(0, 1), Some("\u{FB01}"));
        assert_eq!(skeleton.original_slice(1, 2), Some("\u{FB01}"));
        assert_eq!(skeleton.original_slice(0, 2), Some("\u{FB01}"));
    }

    #[test]
    fn an_out_of_range_or_inverted_lookup_is_refused() {
        let skeleton = Skeleton::new(DOC, Fold::Skeleton);
        let len = skeleton.text().len();
        assert_eq!(skeleton.original_range(0, len + 1), None);
        assert_eq!(skeleton.original_range(5, 4), None);
        assert_eq!(
            skeleton.original_range(3, 3),
            None,
            "an empty range is no span"
        );
    }

    #[test]
    fn a_skeleton_of_an_empty_document_is_empty_and_maps_nothing() {
        let skeleton = Skeleton::new("", Fold::Skeleton);
        assert_eq!(skeleton.text(), "");
        assert!(skeleton.is_identity());
        assert_eq!(skeleton.original_range(0, 0), None);
    }

    #[test]
    fn exotic_spaces_fold_to_a_space_and_do_not_glue_two_names_together() {
        let skeleton = Skeleton::new("Ayşe\u{00A0}Yılmaz", Fold::Skeleton);
        assert_eq!(skeleton.text(), "Ayşe Yılmaz");
        let start = skeleton.text().find("Yılmaz").expect("second token");
        assert_eq!(
            skeleton.original_slice(start, start + "Yılmaz".len()),
            Some("Yılmaz")
        );
    }

    #[test]
    fn an_exotic_space_between_two_digits_is_dropped_rather_than_folded() {
        // The narrow exception to "spaces are folded, never dropped", and both
        // halves of it are asserted here because getting one right and the
        // other wrong is the whole risk: between digits an NBSP separates
        // nothing and must vanish, between letters it separates two names and
        // must survive as a space.
        let skeleton = Skeleton::new("4567\u{00A0}8901234", Fold::Skeleton);
        assert_eq!(skeleton.text(), "45678901234");
        assert_eq!(
            skeleton.original_slice(0, skeleton.text().len()),
            Some("4567\u{00A0}8901234"),
            "the span must still cover the original bytes, NBSP included"
        );
        for exotic in ['\u{202F}', '\u{2007}', '\u{3000}'] {
            let doc = format!("12{exotic}34");
            assert_eq!(Skeleton::new(&doc, Fold::Skeleton).text(), "1234");
        }

        // A REAL ASCII space is left alone. `0532 123 45 67` is how a phone
        // number is deliberately written, and bridging it is a rule-module
        // decision, not something this pass may impose on every matcher.
        assert_eq!(Skeleton::new("12 34", Fold::Skeleton).text(), "12 34");
        // And an exotic space with a digit on only ONE side is still a
        // separator: `Ayşe 12` is two tokens whichever space is used.
        assert_eq!(
            Skeleton::new("Ayşe\u{00A0}12", Fold::Skeleton).text(),
            "Ayşe 12"
        );
        assert_eq!(
            Skeleton::new("12\u{00A0}Ayşe", Fold::Skeleton).text(),
            "12 Ayşe"
        );
    }

    #[test]
    fn a_digit_run_stays_bridgeable_across_a_zero_width_character() {
        // The two rules composing: the ZWSP is dropped and must not reset the
        // "previous character was a digit" state, or the NBSP that follows it
        // would be read as sitting after nothing and be folded to a space.
        let skeleton = Skeleton::new("12\u{200B}\u{00A0}34", Fold::Skeleton);
        assert_eq!(skeleton.text(), "1234");
    }

    #[test]
    fn the_skeleton_is_never_the_document_and_the_original_is_never_rewritten() {
        // The output policy, asserted rather than left to a comment: this crate
        // hands back the original bytes, invisible characters and all. Stripping
        // them would be an unrequested edit to a clinical note and would break
        // the reidentify round trip.
        const TAMPERED: &str = "TCKN 123\u{200B}45678901\u{202E}";
        let skeleton = Skeleton::new(TAMPERED, Fold::Skeleton);
        assert_ne!(skeleton.text(), TAMPERED);
        assert_eq!(skeleton.original(), TAMPERED);
        assert!(!skeleton.is_identity());
    }
}
