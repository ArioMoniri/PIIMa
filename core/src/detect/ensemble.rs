//! The L2 ensemble: run every detector, decode each, UNION across models.
//!
//! WHY UNION AND NEVER A VOTE. The temptation with N models is to keep what a
//! majority agreed on, because that is what raises precision on a benchmark.
//! In a de-identification pipeline it is a breach machine: the span exactly one
//! model saw is, by construction, the identifier the other models MISSED, and
//! out-voting the one detector that found it converts a near-miss into a leak.
//! I2 settles the trade in one direction -- a missed identifier is a breach, an
//! over-masked term is a papercut -- so this module's contract is that a
//! proposal from a single member always survives, and
//! [`a_span_proposed_by_exactly_one_model_survives`] states it as a test rather
//! than as a comment.
//!
//! WHY EACH MEMBER GETS ITS OWN [`DetectorId`]. Agreement has to be countable
//! to be usable, and `span::Merged` counts DISTINCT detector ids. If every
//! ensemble member emitted `DetectorId::Ner(0)`, five models agreeing on one
//! byte range would report support 1 and L4 would be free to demote it --
//! exactly on the strongest evidence the pipeline can produce. The detector
//! identity is therefore assigned from the member's slot in the ensemble and
//! is not something a member can choose.
//!
//! [`a_span_proposed_by_exactly_one_model_survives`]: tests::a_span_proposed_by_exactly_one_model_survives

use crate::pipeline::Detector;
use crate::span::{union_widest, DetectorId, Merged, Span};

use super::align::{Normalized, TokenSpan};
use super::bioes::LabelSet;
use super::scheme::BioScheme;
use super::words::first_piece_rows;
use super::NerError;

/// A tokenized document: the ids a model consumes and where each id came from.
///
/// The two vectors are parallel and index-aligned with the model's logit rows,
/// which is the only contract this crate can enforce without owning a
/// tokenizer. Tokenization itself lives in the bindings: `core/` performs no
/// I/O and loads no vocabulary file, so the caller runs the tokenizer over
/// [`Normalized::text`] and hands the result back here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tokenized {
    /// Input ids, in model order, including special tokens.
    pub ids: Vec<u32>,
    /// Where each id came from in the NORMALISED text. A special token carries
    /// [`TokenSpan::special`].
    pub spans: Vec<TokenSpan>,
}

impl Tokenized {
    /// Build a tokenization, checking that the two vectors line up.
    ///
    /// Checked at construction rather than at use because a length mismatch
    /// means every span after the divergence point is anchored to the wrong
    /// bytes, and that failure is silent: the spans are still well-formed, they
    /// just cover the wrong text.
    pub fn new(ids: Vec<u32>, spans: Vec<TokenSpan>) -> Result<Self, NerError> {
        if ids.len() != spans.len() {
            return Err(NerError::TokenSpanCount {
                ids: ids.len(),
                spans: spans.len(),
            });
        }
        Ok(Self { ids, spans })
    }

    /// How many tokens, and therefore how many logit rows a detector must emit.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// True when there is nothing to infer over.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// One fine-tuned checkpoint plus the tag inventory its head was trained with.
///
/// The label set travels WITH the detector rather than being ensemble-wide,
/// because ensemble members are different fine-tunes of different backbones and
/// nothing guarantees they were exported over the same entity vocabulary. A
/// single shared label set would decode one member's columns against another
/// member's inventory, which produces confident, well-formed, entirely wrong
/// labels.
pub struct Member {
    detector: Box<dyn Detector>,
    labels: LabelSet,
    /// `None` when the checkpoint already emits BIOES in `labels` column order.
    scheme: Option<BioScheme>,
    pieces: PieceLabels,
}

/// Which model tokens of a word carry a label the fine-tune supervised.
///
/// A PROPERTY OF THE CHECKPOINT, not of the tokenizer and not of the ensemble.
/// A fine-tune done with `is_split_into_words` labels the first WordPiece of
/// each word and masks the rest with `-100`, so the continuation rows are
/// unsupervised output that must not reach the decode; a fine-tune done over
/// raw subwords labels all of them. Getting this wrong in either direction is
/// silent: the decode still produces well-formed chunks, they are just derived
/// from rows the training never constrained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PieceLabels {
    /// Every model token's row is the model's answer for that token.
    #[default]
    EveryPiece,
    /// Only the first piece of each word was supervised; the rest inherit it.
    /// See [`super::words`].
    FirstPieceOnly,
}

impl Member {
    /// Pair a detector with the BIOES tag inventory its logit columns mean.
    #[must_use]
    pub fn new(detector: Box<dyn Detector>, labels: LabelSet) -> Self {
        Self {
            detector,
            labels,
            scheme: None,
            pieces: PieceLabels::EveryPiece,
        }
    }

    /// Pair a detector with a BIO head, converting its columns on the way in.
    ///
    /// The label set is DERIVED from the scheme rather than accepted alongside
    /// it, because the two must agree exactly and a caller who could pass both
    /// is a caller who can pass a pair that does not -- which decodes one
    /// checkpoint's columns against another's inventory and produces confident,
    /// well-formed, entirely wrong labels.
    #[must_use]
    pub fn bio(detector: Box<dyn Detector>, scheme: BioScheme, pieces: PieceLabels) -> Self {
        Self {
            detector,
            labels: scheme.labels().clone(),
            scheme: Some(scheme),
            pieces,
        }
    }

    /// The tag inventory this member's DECODED columns are indexed by.
    #[must_use]
    pub fn labels(&self) -> &LabelSet {
        &self.labels
    }

    /// The BIO conversion, when the checkpoint has a BIO head.
    #[must_use]
    pub fn scheme(&self) -> Option<&BioScheme> {
        self.scheme.as_ref()
    }

    /// Which of a word's pieces this checkpoint supervised.
    #[must_use]
    pub fn pieces(&self) -> PieceLabels {
        self.pieces
    }

    /// Raw checkpoint logits, in the column space and at the granularity the
    /// decode expects, with the spans each surviving row belongs to.
    ///
    /// RETURNS SPANS AS WELL AS ROWS because [`PieceLabels::FirstPieceOnly`]
    /// changes the granularity: the decode then runs over words, and a chunk's
    /// token indices index the returned spans rather than the tokenization the
    /// caller started with. Handing back only the rows is how those two vectors
    /// come to disagree, and a disagreement here anchors a span to the wrong
    /// word.
    ///
    /// ORDER IS LOAD-BEARING. The reduction runs FIRST, on the checkpoint's own
    /// columns, because that is the space in which "this row is the model's
    /// answer for this token" is true. Widening afterwards converts only rows
    /// the fine-tune actually supervised. Reversing the two would also make the
    /// row-shape error a caller sees name the BIOES width rather than the
    /// checkpoint's, which is the number they have to fix.
    fn adapt(
        &self,
        spans: &[TokenSpan],
        rows: Vec<Vec<f32>>,
    ) -> Result<(Vec<TokenSpan>, Vec<Vec<f32>>), NerError> {
        let (spans, rows) = match self.pieces {
            PieceLabels::EveryPiece => (spans.to_vec(), rows),
            PieceLabels::FirstPieceOnly => first_piece_rows(spans, &rows),
        };
        match &self.scheme {
            None => Ok((spans, rows)),
            Some(scheme) => {
                let widened = scheme.widen(&rows)?;
                Ok((spans, widened))
            }
        }
    }
}

/// L2. The ensemble of token classifiers.
#[derive(Default)]
pub struct NerEnsemble {
    members: Vec<Member>,
}

impl NerEnsemble {
    /// An ensemble with no members. Proposes nothing, which is the honest
    /// answer when no weights are configured.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one checkpoint. Its slot becomes its [`DetectorId::Ner`] index.
    ///
    /// Fallible only because the id interns as a `u16` to keep `Span` `Copy`
    /// and allocation-free in the browser build. An ensemble that overflows it
    /// is refused rather than wrapped: a wrapped index would give two members
    /// the same identity and manufacture agreement between a model and itself.
    pub fn with_member(
        self,
        detector: Box<dyn Detector>,
        labels: LabelSet,
    ) -> Result<Self, NerError> {
        self.push(Member::new(detector, labels))
    }

    /// Add one checkpoint whose head is BIO rather than BIOES.
    ///
    /// The conversion is [`BioScheme::widen`] and the reasoning for doing it on
    /// logits rather than on tags is in [`super::scheme`]. `pieces` says whether
    /// the fine-tune labelled every subword or only the first piece of each
    /// word, which is the other half of what a published checkpoint's card
    /// tells you and the other half of what silently mis-decodes if guessed.
    pub fn with_bio_member(
        self,
        detector: Box<dyn Detector>,
        scheme: BioScheme,
        pieces: PieceLabels,
    ) -> Result<Self, NerError> {
        self.push(Member::bio(detector, scheme, pieces))
    }

    /// Append a member, refusing to overflow the detector id.
    fn push(mut self, member: Member) -> Result<Self, NerError> {
        if u16::try_from(self.members.len()).is_err() {
            return Err(NerError::TooManyDetectors {
                max: usize::from(u16::MAX) + 1,
            });
        }
        self.members.push(member);
        Ok(self)
    }

    /// How many checkpoints are in the ensemble.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// True when no checkpoint is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The members, in slot order.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// RAW per-detector proposals, each carrying its own [`DetectorId`].
    ///
    /// THIS, not [`NerEnsemble::detect`], is what the orchestrator should feed
    /// into the pipeline-wide union. The reason is that a merge is lossy about
    /// identity by design: `Merged` keeps the contributor SET, but the `Span`
    /// it wraps carries the single dominant parent's detector id. Merging here
    /// and then handing the pipeline the merged spans would collapse five
    /// agreeing members into one id, `support` would count 1, and the L4
    /// demotion guardrail would be free to argue away the span the whole
    /// ensemble agreed on. Layers propose; the orchestrator merges once.
    pub fn propose(
        &self,
        normalized: &Normalized<'_>,
        tokenized: &Tokenized,
    ) -> Result<Vec<Span>, NerError> {
        let mut proposals = Vec::new();
        for (slot, member) in self.members.iter().enumerate() {
            // The bound was checked by `with_member`, so this cannot truncate.
            let index = u16::try_from(slot).map_err(|_| NerError::TooManyDetectors {
                max: usize::from(u16::MAX) + 1,
            })?;
            proposals.extend(self.propose_one(member, index, normalized, tokenized)?);
        }
        Ok(proposals)
    }

    /// The L2 UNION, for a caller that wants the ensemble's own view.
    ///
    /// Widest bounds win on overlap and confidence combines by noisy-OR, both
    /// inherited from [`union_widest`] rather than reimplemented -- one merge
    /// semantics for the whole pipeline is the point of the span algebra.
    /// Nothing is dropped, so a lone proposal comes out the other side with
    /// `support() == 1`.
    pub fn detect(
        &self,
        normalized: &Normalized<'_>,
        tokenized: &Tokenized,
    ) -> Result<Vec<Merged>, NerError> {
        let proposals = self.propose(normalized, tokenized)?;
        Ok(union_widest(normalized.original(), &proposals)?)
    }

    /// Run one member: infer, decode under the transition constraint, anchor.
    fn propose_one(
        &self,
        member: &Member,
        index: u16,
        normalized: &Normalized<'_>,
        tokenized: &Tokenized,
    ) -> Result<Vec<Span>, NerError> {
        if tokenized.is_empty() {
            return Ok(Vec::new());
        }
        let logits = member.detector.infer(&tokenized.ids)?;
        if logits.len() != tokenized.len() {
            return Err(NerError::LogitRowCount {
                detector: index,
                rows: logits.len(),
                tokens: tokenized.len(),
            });
        }

        // The row count is checked on the RAW logits, before any adaptation:
        // every adaptation preserves the row count, so a mismatch here is the
        // checkpoint disagreeing with the tokenization rather than anything
        // this crate did to the rows.
        let (spans_for_decode, logits) = member.adapt(&tokenized.spans, logits)?;
        let decoded = member.labels.viterbi(&logits)?;
        let detector_id = DetectorId::Ner(index);
        let mut spans = Vec::new();
        for chunk in decoded.chunks() {
            let Some(tokens) = spans_for_decode.get(chunk.first..=chunk.last) else {
                // Unreachable: chunk indices come from a decode over exactly
                // `tokenized.len()` rows. Handled rather than indexed so the
                // crate stays panic-free on every path (Definition of Done).
                continue;
            };
            let Some((start, end)) = normalized.anchor(tokens)? else {
                // The chunk covered only special tokens, or trimmed away to
                // nothing. Not an error: a model artefact is not a failure.
                continue;
            };
            spans.push(Span::new(
                normalized.original(),
                start,
                end,
                chunk.label,
                detector_id,
                chunk.confidence,
            )?);
        }
        Ok(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::super::MockDetector;
    use super::*;
    use crate::detect::align::Normalization;
    use crate::detect::bioes::Tag;
    use crate::label::EntityLabel;
    use crate::span::Layer;

    /// Synthetic. No real PHI, and no TCKN at all (I8).
    const DOC: &str = "Hasta Ayşe'nin carcinoma'lı akciğer grafisi okundu.";

    const NAME: EntityLabel = EntityLabel::PatientName;

    fn label_set() -> LabelSet {
        LabelSet::new(&[NAME, EntityLabel::ClinicianName])
    }

    /// Word-level tokenization of the fixture: enough to exercise anchoring
    /// without pulling a vocabulary file into a crate that performs no I/O.
    fn tokenize(text: &str) -> Tokenized {
        let mut ids = vec![0_u32];
        let mut spans = vec![TokenSpan::special()];
        for (offset, word) in text.match_indices(|c: char| !c.is_whitespace()).fold(
            Vec::<(usize, String)>::new(),
            |mut words, (offset, character)| {
                match words.last_mut() {
                    Some((start, word)) if *start + word.len() == offset => {
                        word.push_str(character)
                    }
                    _ => words.push((offset, character.to_owned())),
                }
                words
            },
        ) {
            // Ids are positional: `MockDetector` ignores them and returns canned
            // logits, so their only job is to have the right count.
            ids.push(u32::try_from(ids.len()).expect("small fixture"));
            spans.push(TokenSpan::new(offset, offset + word.len()));
        }
        Tokenized::new(ids, spans).expect("parallel by construction")
    }

    /// Canned logits that shout one tag per token.
    fn canned(set: &LabelSet, tags: &[Tag]) -> Vec<Vec<f32>> {
        tags.iter()
            .map(|&tag| {
                let column = set.index_of(tag).expect("tag is in the label set");
                let mut row = vec![0.0_f32; set.width()];
                row[column] = 8.0;
                row
            })
            .collect()
    }

    /// `[CLS] Hasta Ayşe'nin carcinoma'lı akciğer grafisi okundu.` -- seven
    /// rows. Index 2 is the suffixed name.
    fn tags_for(marked: &[(usize, Tag)]) -> Vec<Tag> {
        let mut tags = vec![Tag::Outside; 7];
        for &(index, tag) in marked {
            tags[index] = tag;
        }
        tags
    }

    fn ensemble(members: Vec<Vec<Tag>>) -> NerEnsemble {
        members
            .into_iter()
            .fold(NerEnsemble::new(), |ensemble, tags| {
                let set = label_set();
                let logits = canned(&set, &tags);
                ensemble
                    .with_member(Box::new(MockDetector::new(logits)), set)
                    .expect("the fixture ensemble is small")
            })
    }

    #[test]
    fn the_fixture_tokenizer_lines_up_with_the_document() {
        let tokenized = tokenize(DOC);
        assert_eq!(tokenized.len(), 7, "[CLS] plus six words");
        assert_eq!(
            &DOC[tokenized.spans[2].start..tokenized.spans[2].end],
            "Ayşe'nin"
        );
    }

    #[test]
    fn a_decoded_chunk_becomes_a_span_at_original_byte_offsets() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        let ensemble = ensemble(vec![tags_for(&[(2, Tag::Single(NAME))])]);

        let spans = ensemble
            .propose(&normalized, &tokenized)
            .expect("proposal succeeds");
        assert_eq!(spans.len(), 1);
        // The suffix is excluded: `Ayşe'nin` masks `Ayşe`.
        assert_eq!(&DOC[spans[0].start()..spans[0].end()], "Ayşe");
        assert_eq!(spans[0].label(), NAME);
        assert_eq!(spans[0].source(), Layer::Ner);
        assert_eq!(spans[0].detector_id(), DetectorId::Ner(0));
        assert!(!spans[0].is_checksum_validated());
    }

    #[test]
    fn each_member_carries_a_distinct_detector_id() {
        // Without this, five models agreeing on one range report support 1 and
        // L4 may demote the span the whole ensemble found.
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        let marked = tags_for(&[(2, Tag::Single(NAME))]);
        let ensemble = ensemble(vec![marked.clone(), marked.clone(), marked]);

        let spans = ensemble
            .propose(&normalized, &tokenized)
            .expect("proposal succeeds");
        assert_eq!(spans.len(), 3);
        let mut ids: Vec<_> = spans.iter().map(Span::detector_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids,
            vec![DetectorId::Ner(0), DetectorId::Ner(1), DetectorId::Ner(2)],
            "ensemble members must be distinguishable"
        );

        let merged = ensemble
            .detect(&normalized, &tokenized)
            .expect("union succeeds");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].support(), 3, "agreement must be countable");
        assert!(merged[0].is_protected());
    }

    #[test]
    fn a_span_proposed_by_exactly_one_model_survives() {
        // THE property that makes this an ensemble rather than a vote. Two
        // members agree on the name; exactly one also flags `akciğer`. The
        // lone proposal must come out the other side, at support 1, unaltered.
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        let ensemble = ensemble(vec![
            tags_for(&[(2, Tag::Single(NAME))]),
            tags_for(&[(2, Tag::Single(NAME))]),
            tags_for(&[(2, Tag::Single(NAME)), (4, Tag::Single(NAME))]),
        ]);

        let merged = ensemble
            .detect(&normalized, &tokenized)
            .expect("union succeeds");
        let lone = merged
            .iter()
            .find(|candidate| {
                let span = candidate.span();
                &DOC[span.start()..span.end()] == "akciğer"
            })
            .expect("a proposal from one model out of three was voted away");
        assert_eq!(lone.support(), 1);
        assert_eq!(lone.contributors(), [DetectorId::Ner(2)]);
    }

    #[test]
    fn overlapping_proposals_keep_the_widest_bounds_and_combine_by_noisy_or() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        // Member 0 sees the name alone; member 1 sees the name and the next
        // word as one entity. The union must cover both words.
        let ensemble = ensemble(vec![
            tags_for(&[(2, Tag::Single(NAME))]),
            tags_for(&[(2, Tag::Begin(NAME)), (3, Tag::End(NAME))]),
        ]);

        let merged = ensemble
            .detect(&normalized, &tokenized)
            .expect("union succeeds");
        assert_eq!(merged.len(), 1);
        let span = merged[0].span();
        assert_eq!(&DOC[span.start()..span.end()], "Ayşe'nin carcinoma");
        assert_eq!(merged[0].support(), 2);
        let narrow = ensemble
            .propose(&normalized, &tokenized)
            .expect("proposal succeeds");
        assert!(
            span.confidence() >= narrow[0].confidence(),
            "noisy-OR must never reduce a member's own confidence"
        );
    }

    #[test]
    fn an_ensemble_with_no_members_proposes_nothing() {
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        let ensemble = NerEnsemble::new();
        assert!(ensemble.is_empty());
        assert_eq!(
            ensemble.propose(&normalized, &tokenized),
            Ok(Vec::new()),
            "no weights configured must mean no guesses"
        );
    }

    #[test]
    fn an_empty_document_is_not_an_error() {
        let normalized = Normalized::new("", Normalization::Identity);
        let ensemble = ensemble(vec![tags_for(&[(2, Tag::Single(NAME))])]);
        assert_eq!(
            ensemble.propose(&normalized, &Tokenized::default()),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_detector_returning_the_wrong_number_of_rows_is_rejected() {
        // A checkpoint whose sequence length does not match the tokenization
        // would anchor every chunk to the wrong tokens. Silent misalignment is
        // the worst outcome available, so it fails loudly.
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        let set = label_set();
        let short = canned(&set, &[Tag::Outside, Tag::Outside]);
        let ensemble = NerEnsemble::new()
            .with_member(Box::new(MockDetector::new(short)), set)
            .expect("one member");
        assert_eq!(
            ensemble.propose(&normalized, &tokenized),
            Err(NerError::LogitRowCount {
                detector: 0,
                rows: 2,
                tokens: 7,
            })
        );
    }

    #[test]
    fn a_tokenization_whose_vectors_disagree_is_refused_at_construction() {
        assert_eq!(
            Tokenized::new(vec![1, 2, 3], vec![TokenSpan::special()]),
            Err(NerError::TokenSpanCount { ids: 3, spans: 1 })
        );
    }

    #[test]
    fn a_bio_checkpoint_over_word_pieces_masks_the_root_and_leaves_the_suffix() {
        // THE END-TO-END STATEMENT OF THE CHECKPOINT CONTRACT, with canned
        // logits and zero weights on disk. A cased WordPiece vocabulary
        // fragments `Ayşe'nin` into four pieces; the fine-tune labelled only
        // the first one; the head is BIO. All three facts are handled at once,
        // and the span that comes out is `Ayşe` at ORIGINAL byte offsets.
        use crate::detect::scheme::{BioScheme, BioTag};
        use crate::detect::words::{word_piece_spans, words};

        let scheme = BioScheme::new(vec![
            BioTag::Outside,
            BioTag::Begin(NAME),
            BioTag::Inside(NAME),
        ])
        .expect("a three-column head");

        let normalized = Normalized::new(DOC, Normalization::Identity);
        let word_spans = words(normalized.text());
        // `[CLS] Hasta Ay ##şe ' nin carcinoma ##'lı akciğer grafisi okundu . [SEP]`
        let word_ids = [
            None,
            Some(0),
            Some(1),
            Some(1),
            Some(1),
            Some(1),
            Some(2),
            Some(2),
            Some(3),
            Some(4),
            Some(5),
            None,
        ];
        let piece_spans = word_piece_spans(&word_spans, &word_ids).expect("word ids in range");
        let ids: Vec<u32> = (0..piece_spans.len() as u32).collect();
        let tokenized = Tokenized::new(ids, piece_spans).expect("parallel by construction");

        // Column 1 (`B-PATIENT_NAME`) is shouted on the FIRST piece of the name
        // only. Every continuation piece is given a loud `O`, which is exactly
        // the unsupervised noise `FirstPieceOnly` exists to discard -- if it
        // reached the decode, the name would not be tagged at all.
        let mut logits = vec![vec![6.0_f32, 0.0, 0.0]; word_ids.len()];
        logits[2] = vec![0.0, 6.0, 0.0];

        let ensemble = NerEnsemble::new()
            .with_bio_member(
                Box::new(MockDetector::new(logits)),
                scheme,
                PieceLabels::FirstPieceOnly,
            )
            .expect("one member");

        let spans = ensemble
            .propose(&normalized, &tokenized)
            .expect("proposal succeeds");
        assert_eq!(spans.len(), 1, "one name, one span");
        assert_eq!(
            &DOC[spans[0].start()..spans[0].end()],
            "Ayşe",
            "the case suffix must be excluded and the offsets must be original-text bytes"
        );
        assert!(DOC.is_char_boundary(spans[0].start()));
        assert!(DOC.is_char_boundary(spans[0].end()));
        assert_eq!(spans[0].label(), NAME);
    }

    #[test]
    fn piece_labels_is_not_a_cosmetic_setting() {
        // The negative control. Same checkpoint, same tokenization, same
        // logits, both settings -- and they differ, so the setting has to be
        // read off the checkpoint's card rather than defaulted.
        //
        // The logits are the realistic shape for a head fine-tuned with `-100`
        // on continuation pieces: every piece of the name scores `B-X`, because
        // nothing ever taught the model to score them differently. Kept, that
        // is FOUR spans over one word -- four audit entries and four surrogate
        // lookups for one name. Reduced, it is one.
        use crate::detect::scheme::{BioScheme, BioTag};
        use crate::detect::words::{word_piece_spans, words};

        let normalized = Normalized::new(DOC, Normalization::Identity);
        let word_spans = words(normalized.text());
        let word_ids = [None, Some(0), Some(1), Some(1), Some(1), Some(1)];
        let piece_spans = word_piece_spans(&word_spans, &word_ids).expect("word ids");
        let ids: Vec<u32> = (0..piece_spans.len() as u32).collect();
        let tokenized = Tokenized::new(ids, piece_spans).expect("parallel");

        let mut logits = vec![vec![6.0_f32, 0.0, 0.0]; word_ids.len()];
        for row in logits.iter_mut().take(6).skip(2) {
            *row = vec![0.0, 6.0, 0.0];
        }

        let count = |pieces: PieceLabels| {
            let scheme = BioScheme::new(vec![
                BioTag::Outside,
                BioTag::Begin(NAME),
                BioTag::Inside(NAME),
            ])
            .expect("scheme");
            NerEnsemble::new()
                .with_bio_member(Box::new(MockDetector::new(logits.clone())), scheme, pieces)
                .expect("one member")
                .propose(&normalized, &tokenized)
                .expect("proposal succeeds")
        };

        let reduced = count(PieceLabels::FirstPieceOnly);
        assert_eq!(reduced.len(), 1, "one word, one span");
        assert_eq!(&DOC[reduced[0].start()..reduced[0].end()], "Ayşe");

        let kept = count(PieceLabels::EveryPiece);
        assert_eq!(
            kept.len(),
            4,
            "every piece of the word proposed its own span"
        );
        // Not a leak -- the bytes are the same and `union_widest` collapses
        // them -- but a different answer, which is the point of the control.
        for span in &kept {
            assert_eq!(&DOC[span.start()..span.end()], "Ayşe");
        }
    }

    #[test]
    fn a_bio_checkpoint_whose_row_is_the_wrong_width_names_the_checkpoints_width() {
        use crate::detect::scheme::{BioScheme, BioTag};
        let scheme = BioScheme::new(vec![
            BioTag::Outside,
            BioTag::Begin(NAME),
            BioTag::Inside(NAME),
        ])
        .expect("scheme");
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = tokenize(DOC);
        // Nine columns is the BIOES width for two entities -- exactly what a
        // caller who forgot the conversion would send. It must be refused
        // against the checkpoint's three, not accepted against the decode's.
        let ensemble = NerEnsemble::new()
            .with_bio_member(
                Box::new(MockDetector::new(vec![vec![0.0; 9]; 7])),
                scheme,
                PieceLabels::FirstPieceOnly,
            )
            .expect("one member");
        assert_eq!(
            ensemble.propose(&normalized, &tokenized),
            Err(NerError::LogitWidth {
                row: 0,
                actual: 9,
                expected: 3,
            })
        );
    }

    #[test]
    fn the_whole_path_runs_with_no_model_weights_on_disk() {
        // The statement the milestone rests on: tokenization, inference,
        // constrained decode, alignment and union all execute against canned
        // logits, so L2 is testable before a single checkpoint exists.
        let normalized = Normalized::new(DOC, Normalization::TurkishDottedI);
        let tokenized = tokenize(normalized.text());
        let ensemble = ensemble(vec![tags_for(&[(2, Tag::Single(NAME))])]);
        let merged = ensemble
            .detect(&normalized, &tokenized)
            .expect("the whole path runs");
        assert_eq!(merged.len(), 1);
        let span = merged[0].span();
        assert_eq!(&DOC[span.start()..span.end()], "Ayşe");
        assert_eq!(span.source(), Layer::Ner);
    }
}
