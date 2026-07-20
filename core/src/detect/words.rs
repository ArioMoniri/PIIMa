//! Word-level re-anchoring: the `is_split_into_words` path.
//!
//! # The trap this module closes
//!
//! [`super::align`] explains why a tokenizer's reported offsets are not offsets
//! into the caller's string. This module answers the harder half: even when the
//! offsets are right, a cased WordPiece vocabulary over Turkish fragments
//! `Ayşe'nin` into something like `Ay ##şe ' nin`, and the checkpoint was
//! FINE-TUNED with a label on the first piece of each word and `-100` on the
//! rest. The continuation pieces' logits are therefore not merely uncertain --
//! they are unsupervised, and decoding over them is decoding over noise that
//! happens to be shaped like evidence.
//!
//! The card for a checkpoint trained that way says to pass `is_split_into_words`
//! and keep the first WordPiece label per word. Two consequences, and both are
//! this module:
//!
//! 1. **The span of every piece is the span of its WORD**, computed HERE from
//!    the original text, never read back from the tokenizer. That is what makes
//!    a Turkish multi-byte word land on a character boundary regardless of what
//!    the vocabulary did to it -- there is no subword offset anywhere in the
//!    chain to be wrong. `Ayşe'nin` becomes one word span, and
//!    [`super::align::trim_to_entity`] cuts the case suffix off it exactly as it
//!    does for every other span in the pipeline.
//! 2. **A word's pieces all decode from the first piece's row**
//!    ([`first_piece_rows`]), so the continuation rows cannot contribute. The
//!    run then decodes as `B I ... E` over one word and yields one chunk with
//!    that word's span, which is the same answer as dropping the rows -- but
//!    without changing the row count the ensemble validates against.
//!
//! # Why the split is whitespace and nothing cleverer
//!
//! A punctuation-aware splitter would have to decide whether `'` in `Ayşe'nin`
//! opens a suffix or closes a quotation, whether `-` in `PET-CT'de` joins or
//! separates, and whether `.` in `Op. Dr.` ends a sentence. Every one of those
//! is a judgement the pipeline already makes ONCE, downstream, in
//! `trim_to_entity`, using the whole span. Making it twice in two places is how
//! the two places come to disagree, and a disagreement here is a span boundary
//! that moves. So the word is the whitespace-delimited word, the span is
//! generous, and the trimming stays where it was.

use super::align::TokenSpan;
use super::NerError;

/// The whitespace-delimited words of a text, as byte ranges into it.
///
/// Byte ranges into whatever string is passed, which for the L2 path is
/// [`super::align::Normalized::text`] -- the normalised text, because that is
/// what the tokenizer is given and what the word indices will refer to.
/// `Normalized` then maps them back to the original.
///
/// Every returned range starts and ends on a character boundary by
/// construction: the ranges are built from `char_indices`, so a multi-byte
/// Turkish letter can never be split by one.
#[must_use]
pub fn words(text: &str) -> Vec<TokenSpan> {
    let mut spans = Vec::new();
    let mut open: Option<usize> = None;
    for (offset, character) in text.char_indices() {
        match (character.is_whitespace(), open) {
            (true, Some(start)) => {
                spans.push(TokenSpan::new(start, offset));
                open = None;
            }
            (false, None) => open = Some(offset),
            _ => {}
        }
    }
    if let Some(start) = open {
        spans.push(TokenSpan::new(start, text.len()));
    }
    spans
}

/// Give every model token the span of the WORD it came from.
///
/// `word_ids` is one entry per model token in model order, exactly what the
/// tokenizer reports for a pre-split input: `None` for a special token
/// (`[CLS]`, `[SEP]`, padding), otherwise the index of the word the piece
/// belongs to. The tokenizer's own character offsets are not a parameter of this
/// function, deliberately -- there is no way for a caller to pass them and
/// therefore no way for them to be trusted.
///
/// A word index past the end of `words` is REFUSED rather than clamped. It means
/// the tokenizer was handed a different word list than the one built here, so
/// every span after it would anchor to the wrong bytes, and a clamp turns that
/// into a plausible-looking span over the last word of the note.
pub fn word_piece_spans(
    words: &[TokenSpan],
    word_ids: &[Option<u32>],
) -> Result<Vec<TokenSpan>, NerError> {
    let mut spans = Vec::with_capacity(word_ids.len());
    for &word in word_ids {
        let Some(index) = word else {
            spans.push(TokenSpan::special());
            continue;
        };
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        let span = words.get(index).ok_or(NerError::WordIndexOutOfRange {
            index,
            words: words.len(),
        })?;
        spans.push(*span);
    }
    Ok(spans)
}

/// Collapse a subword tokenization to ONE ROW AND ONE SPAN PER WORD.
///
/// A run is a maximal stretch of consecutive tokens carrying the same
/// non-special span, which is exactly one word under [`word_piece_spans`]. The
/// run contributes its FIRST row -- the only one the fine-tune supervised -- and
/// its single span. Special tokens contribute nothing at all: `[CLS]` and
/// `[SEP]` are not words and have no word label.
///
/// THE DECODE THEREFORE RUNS AT WORD GRANULARITY, which is the whole point and
/// is not the same as leaving the rows in place. Copying the first row across a
/// four-piece word looks equivalent and is not: four identical `B-X` rows widen
/// to four identical `{B-X, S-X}` rows, and the constrained Viterbi prefers
/// `S S S S` -- four one-piece entities over one word -- to `B I I E`, because
/// the `I`/`E` mass is the checkpoint's low `I-X` score rather than its high
/// `B-X` one. Four spans over one word is not a crash and not a leak, but it is
/// four audit entries for one identifier and four surrogate lookups for one
/// name. One row per word makes it one.
///
/// The returned vectors are parallel and shorter than the input, so the caller
/// must anchor chunks against the RETURNED spans and not against the
/// tokenization it started with.
#[must_use]
pub fn first_piece_rows(spans: &[TokenSpan], rows: &[Vec<f32>]) -> (Vec<TokenSpan>, Vec<Vec<f32>>) {
    let mut kept_spans = Vec::new();
    let mut kept_rows = Vec::new();
    let mut open: Option<TokenSpan> = None;
    for (index, row) in rows.iter().enumerate() {
        let span = spans.get(index).copied().unwrap_or_else(TokenSpan::special);
        if span.is_special() {
            open = None;
            continue;
        }
        if open == Some(span) {
            continue;
        }
        open = Some(span);
        kept_spans.push(span);
        kept_rows.push(row.clone());
    }
    (kept_spans, kept_rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic. Turkish name in the genitive, a code-switched Latin term with
    /// a Turkish suffix, and multi-byte letters throughout (I8: no real PHI).
    const DOC: &str = "Hasta Ayşe'nin carcinoma'lı MRI'da lezyonu";

    #[test]
    fn every_word_span_lands_on_character_boundaries_of_multi_byte_text() {
        let spans = words(DOC);
        assert_eq!(spans.len(), 5);
        for span in &spans {
            assert!(
                DOC.is_char_boundary(span.start) && DOC.is_char_boundary(span.end),
                "a word span split a multi-byte Turkish letter"
            );
            assert!(!span.is_special());
        }
        let covered: Vec<&str> = spans.iter().map(|s| &DOC[s.start..s.end]).collect();
        assert_eq!(
            covered,
            ["Hasta", "Ayşe'nin", "carcinoma'lı", "MRI'da", "lezyonu"]
        );
    }

    #[test]
    fn a_suffixed_name_is_one_word_and_trims_to_its_root() {
        // The end-to-end statement of the trap: the word is generous, the trim
        // is where the boundary is decided, and `Ayşe'nin` yields `Ayşe`.
        let spans = words(DOC);
        let name = spans[1];
        assert_eq!(&DOC[name.start..name.end], "Ayşe'nin");
        let (from, to) =
            super::super::align::trim_to_entity(DOC, name.start, name.end).expect("a root");
        assert_eq!(&DOC[from..to], "Ayşe");
    }

    #[test]
    fn leading_trailing_and_repeated_whitespace_produce_no_empty_words() {
        for text in ["  a  bb \n c  ", "\t\n ", "", "tek"] {
            for span in words(text) {
                assert!(span.start < span.end, "an empty word span was emitted");
                assert!(!text[span.start..span.end].chars().any(char::is_whitespace));
            }
        }
        assert!(words("   ").is_empty());
        assert_eq!(words("tek").len(), 1);
    }

    #[test]
    fn word_spans_are_reconstructed_from_the_text_not_from_the_tokenizer() {
        // Concatenating the covered slices must give the text back minus
        // whitespace, which is the coverage property `gate_tokenizer.py`
        // demands of a real tokenizer's offsets.
        let joined: String = words(DOC)
            .iter()
            .map(|span| &DOC[span.start..span.end])
            .collect();
        let expected: String = DOC.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(joined, expected);
    }

    #[test]
    fn every_piece_of_a_word_carries_that_words_span() {
        // `[CLS] Ay ##şe ' nin [SEP]` over a one-word input: four pieces, one
        // span, and the span is ours rather than the vocabulary's.
        let text = "Ayşe'nin";
        let spans = words(text);
        let mapped = word_piece_spans(&spans, &[None, Some(0), Some(0), Some(0), Some(0), None])
            .expect("word ids are in range");
        assert!(mapped[0].is_special());
        assert!(mapped[5].is_special());
        for piece in &mapped[1..5] {
            assert_eq!(&text[piece.start..piece.end], "Ayşe'nin");
        }
    }

    #[test]
    fn a_word_index_past_the_end_is_refused_rather_than_clamped() {
        let spans = words("bir iki");
        assert_eq!(
            word_piece_spans(&spans, &[Some(0), Some(7)]),
            Err(NerError::WordIndexOutOfRange { index: 7, words: 2 })
        );
    }

    #[test]
    fn a_word_contributes_its_first_pieces_row_and_nothing_else() {
        // The fine-tune labelled the first piece and masked the rest, so the
        // rows for `##şe`, `'` and `nin` are unsupervised. Letting them vote
        // would let noise decide a name boundary.
        let text = "Ayşe'nin raporu";
        let spans = words(text);
        let piece_spans =
            word_piece_spans(&spans, &[None, Some(0), Some(0), Some(0), Some(1), None])
                .expect("word ids");
        let rows = vec![
            vec![1.0, 0.0],
            vec![0.0, 9.0],
            vec![7.0, 0.0],
            vec![6.0, 0.0],
            vec![5.0, 0.0],
            vec![1.0, 0.0],
        ];
        let (kept_spans, kept_rows) = first_piece_rows(&piece_spans, &rows);
        assert_eq!(kept_rows, vec![vec![0.0, 9.0], vec![5.0, 0.0]]);
        assert_eq!(kept_spans.len(), 2, "one entry per word");
        assert_eq!(&text[kept_spans[0].start..kept_spans[0].end], "Ayşe'nin");
        assert_eq!(&text[kept_spans[1].start..kept_spans[1].end], "raporu");
    }

    #[test]
    fn special_tokens_contribute_no_word_and_break_a_run() {
        // `[SEP]` between two pieces of what would otherwise look like one run
        // must not be absorbed into it, and must not become a word of its own.
        let text = "Ayşe";
        let spans = words(text);
        let piece_spans =
            word_piece_spans(&spans, &[None, Some(0), None, Some(0)]).expect("word ids");
        let rows = vec![vec![1.0], vec![2.0], vec![3.0], vec![4.0]];
        let (kept_spans, kept_rows) = first_piece_rows(&piece_spans, &rows);
        assert_eq!(kept_rows, vec![vec![2.0], vec![4.0]]);
        assert_eq!(kept_spans.len(), 2);
    }

    #[test]
    fn two_adjacent_words_are_not_merged_into_one_run() {
        // Distinct spans must break the run even when the pieces are adjacent,
        // or two names in a row would decode from one row and become one span.
        let text = "Ayşe Yılmaz";
        let spans = words(text);
        let piece_spans = word_piece_spans(&spans, &[Some(0), Some(1)]).expect("word ids");
        let rows = vec![vec![9.0, 0.0], vec![0.0, 9.0]];
        let (kept_spans, kept_rows) = first_piece_rows(&piece_spans, &rows);
        assert_eq!(kept_rows, rows);
        assert_eq!(kept_spans.len(), 2);
    }

    #[test]
    fn fewer_spans_than_rows_drops_the_unmapped_rows_rather_than_panicking() {
        // `core/` is panic-free on every path. A binding that mis-sizes its own
        // vectors gets a loud row-count error from the ensemble; it must not
        // abort the process here.
        let (kept_spans, kept_rows) = first_piece_rows(&[], &[vec![1.0], vec![2.0]]);
        assert!(kept_spans.is_empty());
        assert!(kept_rows.is_empty());
    }
}
