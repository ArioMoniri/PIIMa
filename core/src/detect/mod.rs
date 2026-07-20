//! L2 -- the NER ensemble.
//!
//! Tokenize, run every fine-tuned encoder, decode each one's per-token logits
//! under a BIOES transition constraint, re-anchor the resulting subword spans
//! onto ORIGINAL-TEXT byte offsets, and UNION across models. Three modules, one
//! per hard problem:
//!
//! - [`bioes`] -- constrained Viterbi decode. Ill-formed tag sequences get zero
//!   probability instead of a post-hoc repair.
//! - [`align`] -- the offset map. Tokenizer offsets are never trusted; they are
//!   re-anchored through an index built at normalisation time.
//! - [`ensemble`] -- the union. A span one model proposed always survives.
//! - [`scheme`] -- BIO to BIOES. Published checkpoints are BIO and this crate
//!   decodes BIOES; the conversion is explicit, on logits, and tested.
//! - [`words`] -- the `is_split_into_words` path. A model token's span is its
//!   WORD's span, computed here from the text rather than read back from the
//!   tokenizer, and a word decodes from the first WordPiece the fine-tune
//!   actually put a label on.
//!
//! WHAT IS NOT HERE, AND WHY. No inference runtime, no tokenizer vocabulary, no
//! weights, no file access. `core/` is structurally incapable of I/O or network
//! (I1) and compiles to `wasm32`, so the forward pass sits behind
//! [`Detector`][crate::pipeline::Detector] and lives in `bindings/ort/` on
//! native targets and in a `onnxruntime-web` binding in the browser. Everything
//! in this module -- decode, alignment, merge -- is pure and single-sourced
//! across every target, which is what makes the browser build run the same L2
//! as the CLI. [`MockDetector`] closes the loop: the entire path is testable
//! with zero model weights on disk.

pub mod align;
pub mod bioes;
pub mod ensemble;
pub mod scheme;
pub mod words;

pub use align::{trim_to_entity, Normalization, Normalized, TokenSpan};
pub use bioes::{Chunk, Decoded, LabelSet, Tag};
pub use ensemble::{Member, NerEnsemble, PieceLabels, Tokenized};
pub use scheme::{BioScheme, BioTag};
pub use words::{first_piece_rows, word_piece_spans, words};

use crate::pipeline::Detector;

/// What can go wrong between a detector's logits and an L2 span.
///
/// A LAYER-LOCAL ERROR TYPE, deliberately. These are all failures of the
/// CONTRACT between this crate and a checkpoint -- wrong head width, wrong
/// sequence length, a tokenization that does not line up -- and none of them
/// can arise from any other layer. Keeping them out of [`crate::Error`] keeps
/// the crate-wide enum about the pipeline rather than about one layer's wire
/// format, and `Span(..)` below is the one-way door back into it.
///
/// I4 BINDS THIS ENUM exactly as it binds [`crate::Error`]: no variant may
/// carry document text, covered text, or a token's surface form. Counts,
/// offsets, lengths and a detector index only. An error message reaches a log
/// and a log reaches a bug report, and a token's surface form in one is a
/// patient's name that left the device.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum NerError {
    /// A detector returned a different number of logit rows than there were
    /// tokens, so every chunk after the divergence would anchor to the wrong
    /// bytes.
    #[error("detector {detector} returned {rows} logit rows for {tokens} tokens")]
    LogitRowCount {
        detector: u16,
        rows: usize,
        tokens: usize,
    },

    /// A logit row has a different number of columns than the label set has
    /// tags, which means the checkpoint's head was trained over a different tag
    /// inventory than the one it is being decoded against.
    #[error("logit row {row} has {actual} columns, the label set has {expected}")]
    LogitWidth {
        row: usize,
        actual: usize,
        expected: usize,
    },

    /// A logit was NaN or infinite. Rejected rather than propagated: a NaN
    /// makes every comparison in the decode false and turns the argmax into
    /// whichever column happened to come first.
    #[error("logit row {row} contains a non-finite value")]
    NonFiniteLogit { row: usize },

    /// The tokenizer's id and offset vectors have different lengths.
    #[error("tokenizer reported {ids} ids and {spans} token spans")]
    TokenSpanCount { ids: usize, spans: usize },

    /// A token offset is out of bounds or splits a character of the normalised
    /// text, so it cannot be mapped back without silently truncating a span.
    #[error("token range {start}..{end} is not aligned to the {len}-byte normalised text")]
    TokenSpanNotAligned {
        start: usize,
        end: usize,
        len: usize,
    },

    /// A model token claims a word index the word list does not have, so the
    /// tokenizer was handed a different word list than the one the spans were
    /// built from. Refused rather than clamped: a clamp anchors the span to the
    /// last word of the note, which looks like a detection.
    #[error("a model token claims word {index} of a {words}-word document")]
    WordIndexOutOfRange { index: usize, words: usize },

    /// A checkpoint's declared label inventory has no columns at all, so
    /// nothing can be decoded from it. Distinguished from "decoded and found
    /// nothing", which is a result rather than a failure.
    #[error("the checkpoint declares an empty label inventory")]
    EmptyScheme,

    /// More ensemble members than [`crate::DetectorId`] can distinguish.
    /// Refused rather than wrapped, because a wrapped index gives two models
    /// one identity and manufactures agreement between a model and itself.
    #[error("an ensemble may hold at most {max} detectors")]
    TooManyDetectors { max: usize },

    /// The span algebra rejected a proposal -- an offset off a character
    /// boundary, a confidence outside the unit interval.
    #[error(transparent)]
    Span(#[from] crate::Error),
}

/// A [`Detector`] that returns canned logits.
///
/// PUBLIC, not `#[cfg(test)]`, and that is the point. "Everything must be
/// testable and green with zero model weights on disk" is a property the
/// BINDINGS need too: `bindings/ort/` proves its plumbing against this type,
/// and an eval harness can exercise the whole L2 path deterministically without
/// a checkpoint. Gating it behind `cfg(test)` would make it unavailable to
/// exactly the callers that need it, and the alternative -- each binding
/// writing its own stub -- is several stubs that drift from the contract.
///
/// It ignores the input ids, which is what makes it a stub rather than a model:
/// the ROW COUNT is validated by the ensemble, so a mock whose canned rows do
/// not match the tokenization produces a loud [`NerError::LogitRowCount`]
/// rather than a quiet misalignment.
#[derive(Debug, Clone, Default)]
pub struct MockDetector {
    rows: Vec<Vec<f32>>,
}

impl MockDetector {
    /// A detector that always answers with these per-token logit rows.
    #[must_use]
    pub fn new(rows: Vec<Vec<f32>>) -> Self {
        Self { rows }
    }

    /// A detector that tags every one of `tokens` tokens as `Outside`.
    ///
    /// The honest null model: well-formed logits, no proposals, so a binding
    /// can prove its wiring end to end without asserting a detection that no
    /// weights justify.
    #[must_use]
    pub fn outside(labels: &LabelSet, tokens: usize) -> Self {
        let mut row = vec![0.0_f32; labels.width()];
        if let Some(outside) = row.first_mut() {
            // Column 0 is `Tag::Outside` by `LabelSet`'s construction order.
            *outside = 1.0;
        }
        Self::new(vec![row; tokens])
    }

    /// The canned rows, for a binding that wants to assert on its own stub.
    #[must_use]
    pub fn rows(&self) -> &[Vec<f32>] {
        &self.rows
    }
}

impl Detector for MockDetector {
    fn infer(&self, _ids: &[u32]) -> crate::Result<Vec<Vec<f32>>> {
        Ok(self.rows.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::EntityLabel;

    #[test]
    fn the_mock_detector_answers_without_any_weights() {
        let labels = LabelSet::new(&[EntityLabel::PatientName]);
        let detector = MockDetector::outside(&labels, 4);
        let logits = detector.infer(&[1, 2, 3, 4]).expect("the stub cannot fail");
        assert_eq!(logits.len(), 4);
        assert_eq!(logits[0].len(), labels.width());

        let decoded = labels.viterbi(&logits).expect("decode");
        assert!(
            decoded.chunks().is_empty(),
            "the null model must propose nothing"
        );
    }

    #[test]
    fn a_span_error_converts_into_a_layer_error_without_carrying_text() {
        let inner = crate::Error::ConfidenceOutOfRange { confidence: 1.5 };
        let error = NerError::from(inner.clone());
        assert_eq!(error, NerError::Span(inner));
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn no_error_variant_can_carry_document_text() {
        // I4, as a test rather than a review note. Every variant's payload is
        // numeric, so a rendered message is its static format string plus
        // integers -- and therefore pure ASCII. That is a NECESSARY condition,
        // not a sufficient one: it would not catch an ASCII name, and nothing
        // at this layer can. What makes it load-bearing is that it fails the
        // build the moment someone adds a `String` payload to this enum, which
        // is the change that would actually introduce the leak.
        for error in [
            NerError::LogitRowCount {
                detector: 0,
                rows: 2,
                tokens: 7,
            },
            NerError::LogitWidth {
                row: 1,
                actual: 3,
                expected: 9,
            },
            NerError::NonFiniteLogit { row: 0 },
            NerError::TokenSpanCount { ids: 3, spans: 1 },
            NerError::TokenSpanNotAligned {
                start: 6,
                end: 14,
                len: 51,
            },
            NerError::WordIndexOutOfRange { index: 7, words: 2 },
            NerError::EmptyScheme,
            NerError::TooManyDetectors { max: 65_536 },
            NerError::Span(crate::Error::SpanNotOrdered { start: 5, end: 5 }),
        ] {
            let rendered = error.to_string();
            assert!(
                rendered.is_ascii(),
                "an error message rendered non-ASCII content, so a payload is \
                 no longer purely numeric"
            );
            assert!(
                !rendered.contains('"'),
                "a quoted payload reached a message"
            );
        }
    }
}
