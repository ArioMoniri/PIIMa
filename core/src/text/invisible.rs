//! Invisible and formatting characters, and what to do with each class.
//!
//! An attacker -- or, far more often in real clinical data, a word processor --
//! puts a character between two digits that renders as nothing. `123<ZWSP>45678901`
//! is eleven digits to a human and to a checksum, and is not eleven digits to
//! `[0-9]{11}`. The same trick splits a name past a gazetteer. A soft hyphen
//! inside a word is not an attack at all: it is what Word inserts at a line
//! break and what a PDF text extractor hands back, so this class has to be
//! handled for a pipeline that never meets an adversary.
//!
//! # Two policies, and the difference is the whole point
//!
//! **For MATCHING, these characters are removed** -- into the parallel skeleton
//! buffer in [`super::normalize`], with the offset index recording where they
//! were, so every span still lands on ORIGINAL bytes.
//!
//! **For OUTPUT, the original bytes are preserved.** Stripping them from the
//! document would be an unrequested edit to a clinical note, and it would break
//! `DeidResult::reidentify`, whose whole contract is that the original bytes
//! come back exactly. `core/` never rewrites a document to make its own matching
//! easier.
//!
//! # Removed versus folded
//!
//! Zero-width characters are REMOVED, because they separate nothing: a reader
//! sees one token and the matcher must too. Exotic spaces are FOLDED TO ASCII
//! SPACE rather than removed, because they genuinely do separate tokens, and
//! deleting a non-breaking space would glue `Ayşe` to `Yılmaz` into a token
//! neither a gazetteer nor a tokenizer has ever seen. Deleting what separates is
//! as much a recall loss as keeping what does not.
//!
//! # The property, not a hand-maintained list
//!
//! UTS #39 covers this class as `Identifier_Type=Default_Ignorable`, and the
//! principled predicate is Unicode's `Default_Ignorable_Code_Point`. That
//! property is a data table this crate cannot pull in without a dependency, so
//! what follows is the curated subset of it that plausibly appears in Turkish
//! clinical text -- plus the bidi controls, which are not all default-ignorable
//! and matter more than the rest. The subset is a stated limitation, not an
//! implicit claim of completeness: a default-ignorable code point outside these
//! ranges survives into the skeleton and can still split a token.

/// True for a character that renders as nothing and separates nothing.
///
/// Removed from the matching skeleton. Never removed from the document.
#[must_use]
pub const fn is_zero_width(character: char) -> bool {
    matches!(
        character,
        // ZERO WIDTH SPACE, and the joiners. ZWNJ/ZWJ are legitimate in some
        // scripts, and none of those scripts is Turkish or Latin medical
        // register, so inside a Turkish clinical note they are noise at best.
        '\u{200B}' | '\u{200C}' | '\u{200D}'
        // MONGOLIAN VOWEL SEPARATOR, WORD JOINER, and the invisible operators
        // U+2061..U+2064.
        | '\u{180E}' | '\u{2060}'..='\u{2064}'
        // ZERO WIDTH NO-BREAK SPACE / BOM. Survives copy-paste out of Windows
        // tooling constantly, so it reaches real notes without any adversary.
        | '\u{FEFF}'
        // SOFT HYPHEN. The single most common member of this class in real
        // input: word processors insert it at a line break and PDF extraction
        // hands it straight through, mid-word.
        | '\u{00AD}'
        // COMBINING GRAPHEME JOINER. Zero-width, and defeats naive equality.
        | '\u{034F}'
        // Variation selectors, which attach invisibly to the preceding
        // character: VS1..VS16 and the supplement.
        | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
        // Tag characters, deprecated and invisible.
        | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
    )
}

/// True for an explicit bidirectional formatting control.
///
/// Kept separate from [`is_zero_width`] because the SIGNAL is different even
/// though the treatment is the same. A soft hyphen inside a digit run is weak
/// evidence of formatting. A RIGHT-TO-LEFT OVERRIDE inside a Turkish clinical
/// note is essentially never innocent: it reverses displayed order, so a stored
/// `10987654321` displays as `12345678901` and the matcher sees the string
/// nobody read.
#[must_use]
pub const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        // LRE, RLE, PDF, LRO, RLO -- the embedding and override controls.
        '\u{202A}'..='\u{202E}'
        // LRI, RLI, FSI, PDI -- the isolates, same class of problem.
        | '\u{2066}'..='\u{2069}'
        // LRM, RLM, ALM -- the implicit marks.
        | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// True for a non-spacing combining mark this pass drops from the skeleton.
///
/// Only marks that did NOT compose onto a base character reach here --
/// [`super::normalize`] composes first, precisely so that the combining dot of a
/// decomposed `İ` is turned back into `İ` rather than discarded. What is left is
/// a mark decorating a letter that has no precomposed form, which for matching
/// purposes is invisible decoration.
///
/// THE ORDER IS THE SAFETY PROPERTY. Dropping combining marks BEFORE composing
/// is exactly the "strip diacritics" step that destroys `İ`: NFD turns U+0130
/// into `I` + U+0307, and a stripper then leaves `I`, which is the capital of
/// `ı`. Two of Turkish's four `i` letters collapse into one, and the strongest
/// name signal in the language is gone. See [`super::normalize`].
#[must_use]
pub const fn is_stray_combining_mark(character: char) -> bool {
    matches!(
        character,
        // Combining Diacritical Marks, and the Supplement/Extended blocks.
        '\u{0300}'..='\u{036F}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20F0}' | '\u{FE20}'..='\u{FE2F}'
    )
}

/// The ASCII space an exotic space character stands in for.
///
/// Folded rather than dropped: these separate tokens, and gluing two tokens
/// together loses as much recall as splitting one.
#[must_use]
pub const fn ascii_space(character: char) -> Option<char> {
    match character {
        // NO-BREAK SPACE, NARROW NO-BREAK SPACE, MEDIUM MATHEMATICAL SPACE.
        '\u{00A0}' | '\u{202F}' | '\u{205F}'
        // The general punctuation spaces, EN QUAD through HAIR SPACE.
        | '\u{2000}'..='\u{200A}'
        // OGHAM SPACE MARK and IDEOGRAPHIC SPACE.
        | '\u{1680}' | '\u{3000}' => Some(' '),
        _ => None,
    }
}

/// True when the text contains any character this module neutralises.
///
/// A SIGNAL for the caller, not a decision. Under I2 the presence of these
/// characters can only ever raise suspicion about a span -- it is never grounds
/// to drop one.
#[must_use]
pub fn contains_invisible(text: &str) -> bool {
    text.chars()
        .any(|c| is_zero_width(c) || is_bidi_control(c) || ascii_space(c).is_some())
}

/// True when the text contains an explicit bidi embedding, override or isolate.
///
/// Reported separately from [`contains_invisible`] because it is the one member
/// of this family that has no innocent explanation in a Turkish clinical note.
#[must_use]
pub fn contains_bidi_control(text: &str) -> bool {
    text.chars().any(is_bidi_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_characters_that_split_an_identifier_are_all_recognised() {
        for character in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{00AD}', '\u{2060}', '\u{034F}',
            '\u{FE0F}',
        ] {
            assert!(is_zero_width(character), "U+{:04X}", character as u32);
        }
    }

    #[test]
    fn every_bidi_control_is_recognised_and_kept_apart_from_the_rest() {
        for character in [
            '\u{202A}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2069}', '\u{200F}',
        ] {
            assert!(is_bidi_control(character), "U+{:04X}", character as u32);
            assert!(
                !is_zero_width(character),
                "a bidi control must not be classified as ordinary zero-width: \
                 the two carry different evidence"
            );
        }
    }

    #[test]
    fn turkish_letters_are_never_treated_as_invisible() {
        // The failure that would make this module a recall bug rather than a
        // recall fix. Every one of these is a letter a Turkish name is made of.
        for character in [
            'İ', 'ı', 'I', 'i', 'ş', 'Ş', 'ğ', 'Ğ', 'ö', 'ü', 'ç', ' ', 'A',
        ] {
            assert!(!is_zero_width(character), "{character:?}");
            assert!(!is_bidi_control(character), "{character:?}");
            assert!(!is_stray_combining_mark(character), "{character:?}");
        }
    }

    #[test]
    fn an_exotic_space_folds_to_a_space_rather_than_vanishing() {
        for character in ['\u{00A0}', '\u{2007}', '\u{3000}', '\u{202F}'] {
            assert_eq!(
                ascii_space(character),
                Some(' '),
                "U+{:04X}",
                character as u32
            );
            assert!(
                !is_zero_width(character),
                "deleting a separator glues two tokens into one nothing has seen"
            );
        }
        assert_eq!(ascii_space(' '), None, "ASCII space needs no fold");
        assert_eq!(ascii_space('\u{200B}'), None, "ZWSP separates nothing");
    }

    #[test]
    fn the_document_level_signals_report_what_they_are_named_for() {
        assert!(contains_invisible("1234\u{200B}5678901"));
        assert!(!contains_bidi_control("1234\u{200B}5678901"));
        assert!(contains_bidi_control("\u{202E}Ayşe\u{202C}"));
        assert!(!contains_invisible("Hasta Ayşe Yılmaz, TCKN yok."));
    }
}
