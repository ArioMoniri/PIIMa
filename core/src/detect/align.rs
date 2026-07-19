//! Mapping subword token spans back to ORIGINAL-TEXT BYTE OFFSETS.
//!
//! THIS IS THE #1 CORRECTNESS TRAP IN THE PROJECT, and every design choice here
//! is a response to one of its faces.
//!
//! **A tokenizer's reported offsets are not offsets into the caller's string.**
//! They are offsets into whatever string the tokenizer was handed, which is the
//! NORMALISED text if the checkpoint wanted one. Trusting them directly masks
//! the wrong bytes the moment normalisation changes a single byte length -- and
//! the Turkish fold changes them in BOTH directions: `İ` is two bytes and folds
//! to a one-byte `i`, `I` is one byte and folds to a two-byte `ı`. A span that
//! is late by one byte in one place and early by one in another cannot be
//! detected by a length check, only by an offset map.
//!
//! **The mapping must not be recomputed by searching.** Finding the covered
//! text again in the original is the obvious repair and it is wrong twice
//! over: a short name occurs many times in a clinical note, so the search
//! anchors to the wrong occurrence; and normalisation is not identity, so the
//! normalised surface form frequently is not present in the original at all.
//! [`Normalized`] therefore carries a per-byte index built at fold time,
//! which makes the mapping exact rather than probable.
//!
//! **A Turkish name and a Latin medical term take the same suffix.** `Ayşe'nin`
//! must mask `Ayşe` and leave `'nin` -- masking the suffix destroys the
//! sentence's grammar and leaks nothing in return -- while `carcinoma'lı` must
//! present `carcinoma` to L4's allowlist, because `carcinoma'lı` is not on it
//! and the term would be masked. [`trim_to_entity`] is the one place that
//! boundary is decided.

use super::NerError;

/// How the document was rewritten before the tokenizer saw it.
///
/// The fold is deliberately CHAR-TO-CHAR: exactly one output character per
/// input character. That invariant is what lets [`Normalized`] map an exclusive
/// end offset by looking up the byte the next character starts at, and it is
/// why `str::to_lowercase` is not usable here even leaving Turkish aside --
/// it maps `İ` to the TWO characters `i` + U+0307, so one input character
/// becomes two output characters and the index no longer describes a bijection
/// on characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Normalization {
    /// Feed the model the document verbatim.
    ///
    /// The default, and the right answer for every backbone this project may
    /// publish: I6 forbids an `*-uncased` backbone for Turkish outright,
    /// because casing is the strongest name signal there is.
    #[default]
    Identity,
    /// Fold only the dotted/dotless `I` pair, the Turkish-correct way.
    ///
    /// `İ` -> `i` and `I` -> `ı`, which are the mappings Turkish orthography
    /// actually specifies. Naive lowercasing maps `I` -> `i` and destroys the
    /// distinction between two different letters; this preserves it. Exists for
    /// checkpoints trained on text that was folded this way, and for nothing
    /// else -- it is not a general lowercaser and must not become one.
    TurkishDottedI,
}

impl Normalization {
    /// The replacement for one character. Must return exactly one character.
    const fn fold(self, character: char) -> char {
        match self {
            Self::Identity => character,
            Self::TurkishDottedI => match character {
                '\u{0130}' => 'i', // LATIN CAPITAL LETTER I WITH DOT ABOVE
                'I' => '\u{0131}', // LATIN SMALL LETTER DOTLESS I
                other => other,
            },
        }
    }
}

/// A byte range in the NORMALISED text, as a tokenizer reports it.
///
/// A distinct type from a byte range in the original, because confusing the
/// two is precisely the bug this module exists to prevent and a bare
/// `(usize, usize)` makes the confusion unnoticeable at a call site. A special
/// token (`[CLS]`, `[SEP]`, padding) is represented by an EMPTY range: it
/// occupies a logit row but covers no document bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenSpan {
    /// Inclusive byte offset into the normalised text.
    pub start: usize,
    /// Exclusive byte offset into the normalised text.
    pub end: usize,
}

impl TokenSpan {
    /// A token covering document bytes.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// The marker for a token that covers no document bytes.
    #[must_use]
    pub const fn special() -> Self {
        Self { start: 0, end: 0 }
    }

    /// True when this token covers no document bytes.
    #[must_use]
    pub const fn is_special(self) -> bool {
        self.start >= self.end
    }
}

/// The document as the model sees it, plus the index back to the original.
///
/// Holds a borrow of the original rather than a copy so that a caller cannot
/// end up mapping offsets against a different string than the one the spans
/// will be sliced from -- the borrow makes "the original" a single object with
/// a lifetime rather than a convention.
#[derive(Debug, Clone)]
pub struct Normalized<'a> {
    original: &'a str,
    text: String,
    /// `to_original[i]` is the byte offset in `original` corresponding to byte
    /// `i` of `text`. Length is `text.len() + 1`; the final entry is
    /// `original.len()` so an exclusive end offset at the very end maps.
    ///
    /// A FULL PER-BYTE INDEX rather than a list of edit points. The compact
    /// form is a run-length table plus a binary search, which is smaller and
    /// is exactly the kind of thing that gets an off-by-one on the boundary
    /// between two runs. A clinical note is kilobytes; the index is not the
    /// cost centre, and correctness here is the product.
    to_original: Vec<usize>,
}

impl<'a> Normalized<'a> {
    /// Fold a document and record the index back to it.
    #[must_use]
    pub fn new(original: &'a str, normalization: Normalization) -> Self {
        let mut text = String::with_capacity(original.len());
        let mut to_original = Vec::with_capacity(original.len() + 1);
        let mut buffer = [0_u8; 4];
        for (offset, character) in original.char_indices() {
            let folded = normalization.fold(character).encode_utf8(&mut buffer);
            text.push_str(folded);
            // Every byte of the folded character maps to the byte the ORIGINAL
            // character starts at. An interior byte can therefore never be
            // handed back as a span boundary, which is what keeps every mapped
            // offset on a UTF-8 character boundary of the original.
            to_original.extend(core::iter::repeat_n(offset, folded.len()));
        }
        to_original.push(original.len());
        Self {
            original,
            text,
            to_original,
        }
    }

    /// The text the tokenizer and the model see.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The document the caller holds and the spans are anchored to.
    #[must_use]
    pub fn original(&self) -> &'a str {
        self.original
    }

    /// True when the fold changed nothing, so the two strings coincide.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.text == self.original
    }

    /// Map a byte range in the normalised text to ORIGINAL byte offsets.
    ///
    /// Rejects a range whose ends do not lie on character boundaries of the
    /// normalised text. That is not pedantry: the index maps an interior byte
    /// to the START of its character, so a mid-character offset would map to a
    /// silently truncated range instead of failing, and a silently truncated
    /// range is a partially masked identifier.
    pub fn original_range(&self, start: usize, end: usize) -> Result<(usize, usize), NerError> {
        let mis_aligned = |()| NerError::TokenSpanNotAligned {
            start,
            end,
            len: self.text.len(),
        };
        if start > end || end > self.text.len() {
            return Err(mis_aligned(()));
        }
        if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
            return Err(mis_aligned(()));
        }
        let mapped_start = self
            .to_original
            .get(start)
            .copied()
            .ok_or_else(|| mis_aligned(()))?;
        let mapped_end = self
            .to_original
            .get(end)
            .copied()
            .ok_or_else(|| mis_aligned(()))?;
        Ok((mapped_start, mapped_end))
    }

    /// Map a run of tokens onto an ORIGINAL byte range, then trim it.
    ///
    /// Special tokens inside the run are skipped rather than allowed to drag a
    /// boundary to zero: `[CLS]` carries an empty range, and taking the run's
    /// first token's `start` unconditionally would anchor every chunk that
    /// begins at token 0 to the start of the document.
    ///
    /// Returns `None` when the run covers no document bytes at all, which is
    /// what a chunk decoded entirely over special tokens looks like.
    pub fn anchor(&self, tokens: &[TokenSpan]) -> Result<Option<(usize, usize)>, NerError> {
        let mut covering = tokens.iter().filter(|token| !token.is_special());
        let Some(first) = covering.next() else {
            return Ok(None);
        };
        let last = covering.next_back().unwrap_or(first);
        let (start, end) = self.original_range(first.start, last.end)?;
        Ok(trim_to_entity(self.original, start, end))
    }
}

/// Characters that mark a Turkish suffix attached to a proper noun or a
/// code-switched foreign root.
///
/// Three code points and not one: a note typed in a word processor carries the
/// typographic apostrophe U+2019, a note typed on a phone carries the modifier
/// letter apostrophe U+02BC, and only a note typed in a terminal carries the
/// ASCII one. Hardcoding ASCII means the suffix survives on two thirds of real
/// input, and a surviving `'nin` on a masked name is a grammar error that also
/// tells a reader the masked token was a name in the genitive.
const SUFFIX_MARKS: [char; 3] = ['\'', '\u{2019}', '\u{02BC}'];

/// True for a character that is never part of an entity's surface form.
fn is_trimmable(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            ',' | ';' | ':' | '.' | '!' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '/'
        )
}

/// Narrow an original-text byte range down to the entity itself.
///
/// Two jobs, in order:
///
/// 1. Drop leading and trailing whitespace and punctuation a subword tokenizer
///    glued onto the chunk.
/// 2. Cut at a Turkish case suffix. `Ayşe'nin` yields `Ayşe`; `carcinoma'lı`
///    yields `carcinoma`. The SECOND case is why this runs on every span and
///    not only on name labels: L4 checks the allowlist by surface form, and
///    `carcinoma'lı` is not on the allowlist while `carcinoma` is, so a span
///    that keeps its suffix is a masked diagnosis.
///
/// THE CUT IS THE LAST MARK, NOT THE FIRST, and the tail after it must be all
/// letters. Both conditions are the same fact about Turkish: a case suffix is
/// WORD-FINAL morphology. Cutting at the first mark instead truncates every
/// multi-token entity at its first suffixed word -- `Ayşe Yılmaz'ın` would mask
/// only `Ayşe` and leak the surname, which is the exact failure this whole
/// module exists to prevent. Requiring an all-letter tail is what stops a
/// closing quote (`'Ayşe'`) or a possessive followed by punctuation from being
/// read as morphology; in those cases the range is left alone rather than
/// emptied.
///
/// Returns `None` when nothing is left, which the caller must treat as "no
/// span" rather than as an error: a chunk over pure punctuation is a model
/// artefact, not a failure.
#[must_use]
pub fn trim_to_entity(original: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let covered = original.get(start..end)?;

    let leading: usize = covered
        .chars()
        .take_while(|&character| is_trimmable(character))
        .map(char::len_utf8)
        .sum();
    let trailing: usize = covered
        .chars()
        .rev()
        .take_while(|&character| is_trimmable(character))
        .map(char::len_utf8)
        .sum();
    if leading + trailing >= covered.len() {
        return None;
    }
    let start = start + leading;
    let end = end - trailing;

    // Re-slice rather than reuse `covered`: the suffix search must run on the
    // already-trimmed range, or a trailing comma would count as the character
    // that precedes the mark.
    let trimmed = original.get(start..end)?;
    let last_mark = trimmed
        .char_indices()
        .rfind(|&(_, character)| SUFFIX_MARKS.contains(&character));
    let end = match last_mark {
        // Offset 0 means the range opens with the mark, so there is no root in
        // front of it to keep.
        None | Some((0, _)) => end,
        Some((offset, mark)) => {
            let tail = trimmed.get(offset + mark.len_utf8()..).unwrap_or_default();
            if !tail.is_empty() && tail.chars().all(char::is_alphabetic) {
                start + offset
            } else {
                end
            }
        }
    };

    (start < end).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic. Turkish name in the genitive, plus a code-switched Latin term
    /// carrying a Turkish suffix -- the two boundaries this module decides.
    const DOC: &str = "Hasta Ayşe'nin carcinoma'lı akciğer grafisi Dr. Şükrü tarafından okundu.";

    fn at(needle: &str) -> (usize, usize) {
        let start = DOC.find(needle).expect("fixture contains the needle");
        (start, start + needle.len())
    }

    #[test]
    fn a_byte_offset_is_not_a_char_index_in_turkish_text() {
        // The premise of the whole module, asserted rather than assumed.
        let (start, end) = at("Şükrü");
        assert_ne!(
            start,
            DOC.chars().take_while(|_| false).count() + DOC[..start].chars().count(),
            "fixture must place the name after multi-byte characters"
        );
        assert!(
            DOC[..start].chars().count() < start,
            "byte offset must exceed the char index"
        );
        assert!(end - start > DOC[start..end].chars().count());
    }

    #[test]
    fn the_identity_fold_maps_every_offset_to_itself() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        assert!(normalized.is_identity());
        assert_eq!(normalized.text(), DOC);
        let (start, end) = at("Ayşe");
        assert_eq!(normalized.original_range(start, end), Ok((start, end)));
    }

    #[test]
    fn the_turkish_fold_shifts_byte_offsets_in_both_directions() {
        // `İ` is two bytes and folds to a one-byte `i`; `I` is one byte and
        // folds to a two-byte `ı`. A pipeline that assumed normalisation
        // preserves length, or even that it only ever shortens, is wrong on
        // this one string -- which is why an offset map is not optional.
        const CASED: &str = "İzmir'de MRI çekildi";
        let normalized = Normalized::new(CASED, Normalization::TurkishDottedI);
        assert_eq!(normalized.text(), "izmir'de MRı çekildi");
        assert!(!normalized.is_identity());

        let start = normalized.text().find("izmir").expect("folded name");
        let end = start + "izmir".len();
        let (mapped_start, mapped_end) = normalized
            .original_range(start, end)
            .expect("folded range maps");
        assert_eq!(&CASED[mapped_start..mapped_end], "İzmir");
        assert_ne!(
            (mapped_start, mapped_end),
            (start, end),
            "the fold must actually move an offset, or the test proves nothing"
        );

        // And the other direction, past the one-byte-to-two-byte fold.
        let mri_start = normalized.text().find("MRı").expect("folded abbreviation");
        let (mri_from, mri_to) = normalized
            .original_range(mri_start, mri_start + "MRı".len())
            .expect("range maps");
        assert_eq!(&CASED[mri_from..mri_to], "MRI");
    }

    #[test]
    fn every_mapped_offset_lands_on_a_character_boundary_of_the_original() {
        const CASED: &str = "İIİ şğü İstanbul";
        let normalized = Normalized::new(CASED, Normalization::TurkishDottedI);
        for offset in 0..=normalized.text().len() {
            if !normalized.text().is_char_boundary(offset) {
                continue;
            }
            let (mapped, _) = normalized
                .original_range(offset, normalized.text().len())
                .expect("boundary offset maps");
            assert!(
                CASED.is_char_boundary(mapped),
                "normalised offset {offset} mapped to {mapped}, inside a character"
            );
        }
    }

    #[test]
    fn a_mid_character_offset_is_refused_rather_than_silently_truncated() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let mid = DOC.find('ş').expect("fixture has s-cedilla") + 1;
        assert!(!DOC.is_char_boundary(mid));
        assert_eq!(
            normalized.original_range(mid, mid + 3),
            Err(NerError::TokenSpanNotAligned {
                start: mid,
                end: mid + 3,
                len: DOC.len(),
            })
        );
        assert_eq!(
            normalized.original_range(0, DOC.len() + 1),
            Err(NerError::TokenSpanNotAligned {
                start: 0,
                end: DOC.len() + 1,
                len: DOC.len(),
            })
        );
    }

    #[test]
    fn a_name_span_covers_the_root_and_excludes_the_case_suffix() {
        // `Ayşe'nin`: the span must be `Ayşe`. Masking the suffix as well
        // breaks the sentence and protects nothing; keeping it makes the
        // surrogate ungrammatical and advertises the genitive.
        let (start, end) = at("Ayşe'nin");
        let (from, to) = trim_to_entity(DOC, start, end).expect("a root survives");
        assert_eq!(&DOC[from..to], "Ayşe");
        assert_eq!(&DOC[to..end], "'nin");
    }

    #[test]
    fn a_code_switched_medical_term_is_stripped_to_its_root() {
        // `carcinoma'lı` -> `carcinoma`. The allowlist holds the root, so a
        // span that kept the suffix would miss it and L4 would mask a
        // diagnosis, which the brief calls destroying the note.
        let (start, end) = at("carcinoma'lı");
        let (from, to) = trim_to_entity(DOC, start, end).expect("a root survives");
        assert_eq!(&DOC[from..to], "carcinoma");
    }

    #[test]
    fn a_multi_word_name_is_cut_only_at_its_final_suffix() {
        // The regression this rule was written for. Turkish attaches the case
        // suffix to the LAST word of a name, so cutting at the first mark found
        // would mask `Ayşe` and leave the surname in the note.
        let doc = "Ayşe Yılmaz'ın raporu";
        let (from, to) = trim_to_entity(doc, 0, "Ayşe Yılmaz'ın".len()).expect("a root survives");
        assert_eq!(&doc[from..to], "Ayşe Yılmaz");
    }

    #[test]
    fn a_mark_whose_tail_is_not_a_suffix_is_left_alone() {
        // `'` followed by punctuation or nothing is quotation, not morphology.
        let doc = "Ayşe Yılmaz'";
        assert_eq!(
            trim_to_entity(doc, 0, doc.len()).map(|(from, to)| &doc[from..to]),
            Some("Ayşe Yılmaz'")
        );
    }

    #[test]
    fn every_apostrophe_a_real_note_carries_is_recognised() {
        for mark in SUFFIX_MARKS {
            let doc = format!("Ayşe{mark}nin raporu");
            let (from, to) = trim_to_entity(&doc, 0, doc.find(" raporu").expect("fixture"))
                .expect("a root survives");
            assert_eq!(&doc[from..to], "Ayşe", "suffix mark {mark:?} was not cut");
        }
    }

    #[test]
    fn punctuation_and_whitespace_a_tokenizer_glued_on_are_trimmed() {
        let doc = " ( Ayşe Yılmaz ), ";
        let (from, to) = trim_to_entity(doc, 0, doc.len()).expect("a root survives");
        assert_eq!(&doc[from..to], "Ayşe Yılmaz");
    }

    #[test]
    fn a_range_that_opens_with_an_apostrophe_is_not_emptied() {
        // A quotation, not a suffix. Cutting at offset zero would return an
        // empty range and silently drop the span.
        let doc = "'Ayşe' yazıyor";
        let (from, to) = trim_to_entity(doc, 0, "'Ayşe'".len()).expect("a root survives");
        assert_eq!(&doc[from..to], "'Ayşe'");
    }

    #[test]
    fn a_range_of_pure_punctuation_yields_no_span() {
        let doc = " ,. ";
        assert_eq!(trim_to_entity(doc, 0, doc.len()), None);
        assert_eq!(trim_to_entity(doc, 2, 2), None);
    }

    #[test]
    fn anchoring_a_token_run_maps_and_trims_in_one_step() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let (start, end) = at("Ayşe'nin");
        // Subword fragmentation of a suffixed Turkish name, the failure mode
        // the brief names: `Ay` `##şe` `'` `nin`, four tokens for one entity.
        let tokens = [
            TokenSpan::special(),
            TokenSpan::new(start, start + 2),
            TokenSpan::new(start + 2, start + "Ayşe".len()),
            TokenSpan::new(start + "Ayşe".len(), start + "Ayşe'".len()),
            TokenSpan::new(start + "Ayşe'".len(), end),
        ];
        let (from, to) = normalized
            .anchor(&tokens)
            .expect("mapping succeeds")
            .expect("a root survives");
        assert_eq!(&DOC[from..to], "Ayşe");
    }

    #[test]
    fn a_run_of_only_special_tokens_anchors_to_nothing() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        assert_eq!(
            normalized.anchor(&[TokenSpan::special(), TokenSpan::special()]),
            Ok(None)
        );
        assert_eq!(normalized.anchor(&[]), Ok(None));
    }

    #[test]
    fn anchoring_survives_the_fold_end_to_end() {
        const CASED: &str = "Hasta İnci'nin raporu";
        let normalized = Normalized::new(CASED, Normalization::TurkishDottedI);
        let folded_start = normalized.text().find("inci").expect("folded name");
        let folded_end = folded_start + "inci'nin".len();
        let tokens = [
            TokenSpan::special(),
            TokenSpan::new(folded_start, folded_end),
        ];
        let (from, to) = normalized
            .anchor(&tokens)
            .expect("mapping succeeds")
            .expect("a root survives");
        assert_eq!(
            &CASED[from..to],
            "İnci",
            "the dotted capital must come back exactly as it was written"
        );
    }
}
