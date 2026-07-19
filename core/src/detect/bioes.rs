//! BIOES decode under a VITERBI TRANSITION CONSTRAINT.
//!
//! WHY A CONSTRAINED DECODE RATHER THAN A PER-TOKEN ARGMAX. A token classifier
//! emits an independent distribution per token, so its argmax can produce tag
//! sequences that do not describe any set of chunks at all: `B-PATIENT_NAME`
//! followed by `B-PATIENT_NAME` leaves the first chunk unterminated,
//! `O I-TCKN` opens a chunk that was never begun, `B-TCKN E-PHONE` closes one
//! entity with another. Every ad-hoc repair for these -- drop the orphan, or
//! promote it to a singleton, or close the chunk at the previous token -- is a
//! guess made after the evidence was thrown away, and in a de-identification
//! pipeline a guess about a chunk boundary is a guess about how many bytes of a
//! patient name get masked.
//!
//! The fix is to never produce the ill-formed sequence. Illegal transitions get
//! ZERO probability -- `f32::NEG_INFINITY` in log space -- so Viterbi maximises
//! over well-formed sequences only, and the model's own scores decide which
//! well-formed sequence wins. Chunk extraction downstream is then total rather
//! than defensive.
//!
//! The constraint is derived from the label set rather than written out, because
//! a hand-maintained transition table drifts from the tag inventory the moment
//! a label is added to `eval/schema.yaml` and the drift is silent.

use crate::label::EntityLabel;

use super::NerError;

/// One BIOES tag: the tagging scheme's five roles over the label vocabulary.
///
/// BIOES rather than BIO because the explicit `End` and `Single` roles are what
/// make the transition constraint able to see an unterminated chunk at all. In
/// BIO, `B I B` is legal and the boundary between the two entities is inferred;
/// in BIOES the equivalent is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    /// Not part of any entity.
    Outside,
    /// First token of a multi-token entity.
    Begin(EntityLabel),
    /// Interior token of a multi-token entity.
    Inside(EntityLabel),
    /// Last token of a multi-token entity.
    End(EntityLabel),
    /// A whole entity in one token.
    Single(EntityLabel),
}

impl Tag {
    /// The entity this tag carries, if it carries one.
    #[must_use]
    pub const fn entity(self) -> Option<EntityLabel> {
        match self {
            Self::Outside => None,
            Self::Begin(label) | Self::Inside(label) | Self::End(label) | Self::Single(label) => {
                Some(label)
            }
        }
    }

    /// The scheme prefix, for diagnostics. Carries no document text (I4).
    #[must_use]
    pub const fn prefix(self) -> char {
        match self {
            Self::Outside => 'O',
            Self::Begin(_) => 'B',
            Self::Inside(_) => 'I',
            Self::End(_) => 'E',
            Self::Single(_) => 'S',
        }
    }

    /// True while this tag leaves a chunk OPEN, so only `I` or `E` of the same
    /// entity may follow.
    const fn opens_chunk(self) -> bool {
        matches!(self, Self::Begin(_) | Self::Inside(_))
    }

    /// True when this tag can only appear inside an already-open chunk.
    const fn needs_open_chunk(self) -> bool {
        matches!(self, Self::Inside(_) | Self::End(_))
    }
}

/// May `to` directly follow `from`?
///
/// The whole constraint, in one place, stated as the two questions the scheme
/// actually asks: is a chunk open, and does the tag agree with the chunk that
/// is open. Everything the brief enumerates falls out of these -- `B` must be
/// followed by `I` or `E`; `S` and `E` terminate; `O` cannot precede `I` or
/// `E`; a chunk cannot change entity halfway through.
const fn transition_allowed(from: Tag, to: Tag) -> bool {
    if from.opens_chunk() {
        // A chunk is open. Only a continuation or a closure of the SAME entity
        // may follow -- entity equality is what stops `B-TCKN E-PHONE` from
        // masking a phone number's bytes with a TCKN's surrogate format.
        return match (from.entity(), to.entity()) {
            (Some(open), Some(next)) if to.needs_open_chunk() => matches_label(open, next),
            _ => false,
        };
    }
    // No chunk is open, so a tag that requires one has no opener and is
    // unreachable. Everything else -- O, B, S -- may start fresh.
    !to.needs_open_chunk()
}

/// `EntityLabel` equality in a `const fn` context.
///
/// `PartialEq::eq` is not const, and the alternative -- comparing `as_str()`
/// pointers -- would silently compare two `&'static str` addresses rather than
/// their contents.
const fn matches_label(a: EntityLabel, b: EntityLabel) -> bool {
    // `as_str` is const and total over the enum, and the schema ids are
    // distinct by construction (the drift test in `label.rs` proves it), so
    // comparing their lengths and first bytes would be a weaker check than
    // comparing the strings. Byte-wise comparison keeps this const and exact.
    let (a, b) = (a.as_str().as_bytes(), b.as_str().as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The tag inventory a detector's logits are columns of, plus the transition
/// constraint derived from it.
///
/// COLUMN ORDER IS THE CONTRACT between this crate and a fine-tuned checkpoint:
/// column `i` of every logit row is `tags()[i]`. It is built here rather than
/// accepted from the caller so that the order is one deterministic function of
/// the entity list, and a checkpoint whose head was trained in a different
/// order is a checkpoint that must be re-exported, not silently mis-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSet {
    tags: Vec<Tag>,
    /// Row-major `allowed[from * width + to]`, materialised once so the decode
    /// inner loop is a lookup rather than a match.
    allowed: Vec<bool>,
    /// A sequence may not OPEN on a tag that needs an already-open chunk.
    start_allowed: Vec<bool>,
    /// A sequence may not END with a chunk still open.
    end_allowed: Vec<bool>,
}

impl LabelSet {
    /// Build the tag inventory for an entity vocabulary.
    ///
    /// Index 0 is always `Outside`; each entity then contributes `B`, `I`, `E`,
    /// `S` in that order.
    #[must_use]
    pub fn new(entities: &[EntityLabel]) -> Self {
        let mut tags = Vec::with_capacity(1 + entities.len() * 4);
        tags.push(Tag::Outside);
        for &entity in entities {
            tags.push(Tag::Begin(entity));
            tags.push(Tag::Inside(entity));
            tags.push(Tag::End(entity));
            tags.push(Tag::Single(entity));
        }

        let width = tags.len();
        let mut allowed = vec![false; width * width];
        for (from_index, &from) in tags.iter().enumerate() {
            for (to_index, &to) in tags.iter().enumerate() {
                allowed[from_index * width + to_index] = transition_allowed(from, to);
            }
        }
        let start_allowed = tags.iter().map(|tag| !tag.needs_open_chunk()).collect();
        let end_allowed = tags.iter().map(|tag| !tag.opens_chunk()).collect();

        Self {
            tags,
            allowed,
            start_allowed,
            end_allowed,
        }
    }

    /// The tag inventory, in logit-column order.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    /// How many logit columns a detector for this label set must emit.
    #[must_use]
    pub fn width(&self) -> usize {
        self.tags.len()
    }

    /// The logit column for a tag, if the tag is in this inventory.
    #[must_use]
    pub fn index_of(&self, tag: Tag) -> Option<usize> {
        self.tags.iter().position(|&candidate| candidate == tag)
    }

    /// True when `to` may directly follow `from`, by column index.
    #[must_use]
    pub fn allows(&self, from: usize, to: usize) -> bool {
        self.allowed
            .get(from * self.width() + to)
            .copied()
            .unwrap_or(false)
    }

    /// True when a sequence may begin with this column.
    #[must_use]
    pub fn allows_start(&self, tag: usize) -> bool {
        self.start_allowed.get(tag).copied().unwrap_or(false)
    }

    /// True when a sequence may end with this column.
    #[must_use]
    pub fn allows_end(&self, tag: usize) -> bool {
        self.end_allowed.get(tag).copied().unwrap_or(false)
    }

    /// The highest-scoring WELL-FORMED tag sequence for a document's logits.
    ///
    /// Standard Viterbi with the transition constraint folded in as an additive
    /// `NEG_INFINITY`: an illegal edge contributes negative infinity, which
    /// propagates through the running score and can never be the maximum, so
    /// the illegal sequence is not merely disfavoured but unreachable.
    ///
    /// A path always exists: `Outside` is start-legal, end-legal, and may
    /// follow itself, so the all-`O` sequence is always in the search space.
    pub fn viterbi(&self, logits: &[Vec<f32>]) -> Result<Decoded, NerError> {
        let width = self.width();
        if logits.is_empty() {
            return Ok(Decoded::default());
        }

        let mut normalised = Vec::with_capacity(logits.len());
        for (index, row) in logits.iter().enumerate() {
            if row.len() != width {
                return Err(NerError::LogitWidth {
                    row: index,
                    actual: row.len(),
                    expected: width,
                });
            }
            // Rejected up front rather than propagated: a NaN would make every
            // comparison below false and silently hand the decode to whichever
            // column happened to be first, which looks like a decode and is a
            // coin toss.
            if row.iter().any(|value| !value.is_finite()) {
                return Err(NerError::NonFiniteLogit { row: index });
            }
            normalised.push(log_softmax(row));
        }
        // Non-empty was established above, so this row exists.
        let first_row = normalised.first().cloned().unwrap_or_default();
        let mut score: Vec<f32> = first_row
            .iter()
            .enumerate()
            .map(|(tag, &emission)| {
                if self.allows_start(tag) {
                    emission
                } else {
                    f32::NEG_INFINITY
                }
            })
            .collect();

        let mut backpointers: Vec<Vec<usize>> = Vec::with_capacity(normalised.len() - 1);
        for row in normalised.iter().skip(1) {
            let mut next = vec![f32::NEG_INFINITY; width];
            let mut pointer = vec![0usize; width];
            for (to, (slot, back)) in next.iter_mut().zip(pointer.iter_mut()).enumerate() {
                let mut best = f32::NEG_INFINITY;
                let mut best_from = 0usize;
                for (from, &previous) in score.iter().enumerate() {
                    if !self.allows(from, to) {
                        continue;
                    }
                    if previous > best {
                        best = previous;
                        best_from = from;
                    }
                }
                // NEG_INFINITY plus a finite emission stays NEG_INFINITY, which
                // IS the zero probability the constraint assigns.
                *slot = best + row[to];
                *back = best_from;
            }
            backpointers.push(pointer);
            score = next;
        }

        // Terminate only on a tag that leaves no chunk open. Index 0 is
        // `Outside`, which is always end-legal, so the fallback is well-formed
        // even in the degenerate case where every score is negative infinity.
        let mut last = 0usize;
        let mut best = f32::NEG_INFINITY;
        for (tag, &value) in score.iter().enumerate() {
            if self.allows_end(tag) && value > best {
                best = value;
                last = tag;
            }
        }

        let mut columns = vec![0usize; normalised.len()];
        columns[normalised.len() - 1] = last;
        let mut cursor = last;
        for (step, pointer) in backpointers.iter().enumerate().rev() {
            cursor = pointer[cursor];
            columns[step] = cursor;
        }

        let tags = columns.iter().map(|&column| self.tags[column]).collect();
        let probabilities = columns
            .iter()
            .enumerate()
            .map(|(index, &column)| normalised[index][column].exp().clamp(0.0, 1.0))
            .collect();
        Ok(Decoded {
            tags,
            probabilities,
        })
    }
}

/// Numerically stable log-softmax over one token's logits.
fn log_softmax(row: &[f32]) -> Vec<f32> {
    let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    // Subtracting the max before exponentiating is what keeps a confident
    // checkpoint's large logits from overflowing to infinity and turning the
    // whole row into NaN.
    let total: f32 = row.iter().map(|value| (value - max).exp()).sum();
    let log_total = total.ln();
    row.iter()
        .map(|value| value - max - log_total)
        .collect::<Vec<_>>()
}

/// A decoded tag sequence and the model's own probability for each choice.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Decoded {
    tags: Vec<Tag>,
    /// Softmax probability of the tag Viterbi actually chose, per token. This
    /// is what becomes a span's confidence, so it is kept rather than
    /// recomputed: the path score is a sum of log probabilities and cannot be
    /// turned back into a per-span probability afterwards.
    probabilities: Vec<f32>,
}

impl Decoded {
    /// The chosen tag per token.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    /// The probability of the chosen tag per token.
    #[must_use]
    pub fn probabilities(&self) -> &[f32] {
        &self.probabilities
    }

    /// The entity chunks the tag sequence describes.
    ///
    /// Total rather than defensive, because [`LabelSet::viterbi`] cannot emit
    /// an ill-formed sequence. The one unreachable case -- a `Begin` with no
    /// `End` -- is still closed rather than dropped, because I2 decides ties in
    /// favour of emitting a candidate: a dropped chunk is a missed identifier,
    /// and a mis-sized one is an over-mask that L4 can argue down.
    #[must_use]
    pub fn chunks(&self) -> Vec<Chunk> {
        let mut chunks = Vec::new();
        let mut open: Option<(usize, EntityLabel)> = None;
        for (index, &tag) in self.tags.iter().enumerate() {
            match tag {
                Tag::Single(label) => {
                    open = None;
                    chunks.push(self.chunk(index, index, label));
                }
                Tag::Begin(label) => open = Some((index, label)),
                Tag::End(label) => {
                    let first = open.take().map_or(index, |(first, _)| first);
                    chunks.push(self.chunk(first, index, label));
                }
                Tag::Inside(_) | Tag::Outside => {}
            }
        }
        if let Some((first, label)) = open {
            let last = self.tags.len().saturating_sub(1);
            chunks.push(self.chunk(first, last, label));
        }
        chunks
    }

    /// Build one chunk, scoring it by the MEAN of its tokens' probabilities.
    ///
    /// Mean rather than product: a product punishes long entities for being
    /// long, and a four-token Turkish name with a case suffix would score below
    /// the escalation threshold purely for its length. Mean rather than min for
    /// the same reason in the other direction -- one uncertain interior subword
    /// should not decide the whole span.
    fn chunk(&self, first: usize, last: usize, label: EntityLabel) -> Chunk {
        let slice = self
            .probabilities
            .get(first..=last)
            .unwrap_or(&self.probabilities);
        let confidence = if slice.is_empty() {
            0.0
        } else {
            // `slice.len()` is a small positive count, so the cast is exact for
            // any document a tokenizer can produce.
            slice.iter().sum::<f32>() / slice.len() as f32
        };
        Chunk {
            first,
            last,
            label,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// One entity, as a closed range of TOKEN indices.
///
/// Token indices, not byte offsets: turning these into original-text byte
/// offsets is [`super::align`]'s job and it needs the offset map to do it
/// correctly, so this type deliberately cannot express a byte offset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Chunk {
    /// First token index, inclusive.
    pub first: usize,
    /// Last token index, INCLUSIVE.
    pub last: usize,
    /// The entity the chunk's tags agreed on.
    pub label: EntityLabel,
    /// Mean probability of the chosen tags over the chunk.
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: EntityLabel = EntityLabel::PatientName;
    const TCKN: EntityLabel = EntityLabel::Tckn;

    fn label_set() -> LabelSet {
        LabelSet::new(&[NAME, TCKN])
    }

    /// Logits that make the requested tag sequence overwhelmingly attractive.
    ///
    /// The point of every test below is that the CONSTRAINT beats the evidence,
    /// so the evidence has to be loud enough that nothing but the constraint
    /// could be responsible for the decode differing from it.
    fn shouting(set: &LabelSet, wanted: &[Tag]) -> Vec<Vec<f32>> {
        wanted
            .iter()
            .map(|&tag| {
                let column = set.index_of(tag).expect("tag is in the label set");
                let mut row = vec![0.0_f32; set.width()];
                row[column] = 50.0;
                row
            })
            .collect()
    }

    #[test]
    fn the_label_set_lays_out_columns_deterministically() {
        let set = label_set();
        assert_eq!(set.width(), 1 + 2 * 4);
        assert_eq!(set.tags()[0], Tag::Outside);
        assert_eq!(set.index_of(Tag::Begin(NAME)), Some(1));
        assert_eq!(set.index_of(Tag::Inside(NAME)), Some(2));
        assert_eq!(set.index_of(Tag::End(NAME)), Some(3));
        assert_eq!(set.index_of(Tag::Single(NAME)), Some(4));
        assert_eq!(set.index_of(Tag::Begin(TCKN)), Some(5));
        assert_eq!(
            LabelSet::new(&[]).width(),
            1,
            "an empty vocabulary still has Outside"
        );
    }

    #[test]
    fn the_transition_table_encodes_every_rule_the_scheme_states() {
        for (from, to, legal) in [
            // B must be followed by I or E of the SAME entity.
            (Tag::Begin(NAME), Tag::Inside(NAME), true),
            (Tag::Begin(NAME), Tag::End(NAME), true),
            (Tag::Begin(NAME), Tag::Outside, false),
            (Tag::Begin(NAME), Tag::Begin(NAME), false),
            (Tag::Begin(NAME), Tag::Single(NAME), false),
            (Tag::Begin(NAME), Tag::Inside(TCKN), false),
            (Tag::Begin(NAME), Tag::End(TCKN), false),
            // I continues or closes, same entity only.
            (Tag::Inside(NAME), Tag::Inside(NAME), true),
            (Tag::Inside(NAME), Tag::End(NAME), true),
            (Tag::Inside(NAME), Tag::Outside, false),
            (Tag::Inside(NAME), Tag::End(TCKN), false),
            // E and S terminate a chunk; only a fresh start may follow.
            (Tag::End(NAME), Tag::Outside, true),
            (Tag::End(NAME), Tag::Begin(TCKN), true),
            (Tag::End(NAME), Tag::Single(TCKN), true),
            (Tag::End(NAME), Tag::Inside(NAME), false),
            (Tag::End(NAME), Tag::End(NAME), false),
            (Tag::Single(NAME), Tag::Begin(NAME), true),
            (Tag::Single(NAME), Tag::Inside(NAME), false),
            (Tag::Single(NAME), Tag::End(NAME), false),
            // O cannot precede I or E: there is no chunk to continue.
            (Tag::Outside, Tag::Outside, true),
            (Tag::Outside, Tag::Begin(NAME), true),
            (Tag::Outside, Tag::Single(NAME), true),
            (Tag::Outside, Tag::Inside(NAME), false),
            (Tag::Outside, Tag::End(NAME), false),
        ] {
            let set = label_set();
            let (from_index, to_index) = (
                set.index_of(from).expect("tag present"),
                set.index_of(to).expect("tag present"),
            );
            assert_eq!(
                set.allows(from_index, to_index),
                legal,
                "{}->{} should be {}",
                from.prefix(),
                to.prefix(),
                if legal { "legal" } else { "illegal" }
            );
        }
    }

    #[test]
    fn every_illegal_transition_is_unreachable_however_loud_the_logits() {
        // THE test this module exists for. For each illegal ordered pair, hand
        // the decoder logits that demand exactly that pair and assert it does
        // not come out. A per-token argmax fails every one of these.
        let set = label_set();
        let mut checked = 0usize;
        for &from in set.tags() {
            for &to in set.tags() {
                let (from_index, to_index) = (
                    set.index_of(from).expect("tag present"),
                    set.index_of(to).expect("tag present"),
                );
                if set.allows(from_index, to_index) {
                    continue;
                }
                checked += 1;
                let decoded = set
                    .viterbi(&shouting(&set, &[from, to]))
                    .expect("well-formed logits decode");
                assert_ne!(
                    decoded.tags(),
                    [from, to],
                    "illegal transition {}->{} was decoded",
                    from.prefix(),
                    to.prefix()
                );
                // Stronger than "not the demanded pair": whatever came out must
                // itself be legal.
                let pair = decoded.tags();
                let (left, right) = (
                    set.index_of(pair[0]).expect("decoded tag is in the set"),
                    set.index_of(pair[1]).expect("decoded tag is in the set"),
                );
                assert!(set.allows_start(left));
                assert!(set.allows(left, right));
                assert!(set.allows_end(right));
            }
        }
        assert!(
            checked > 0,
            "the sweep found no illegal transitions to test"
        );
    }

    #[test]
    fn a_sequence_may_not_open_on_a_tag_that_needs_an_open_chunk() {
        let set = label_set();
        for tag in [Tag::Inside(NAME), Tag::End(NAME)] {
            let decoded = set.viterbi(&shouting(&set, &[tag])).expect("decode");
            assert_ne!(decoded.tags(), [tag], "{} started a sequence", tag.prefix());
        }
    }

    #[test]
    fn a_sequence_may_not_end_with_a_chunk_still_open() {
        let set = label_set();
        for tag in [Tag::Begin(NAME), Tag::Inside(NAME)] {
            let decoded = set.viterbi(&shouting(&set, &[tag])).expect("decode");
            assert_ne!(
                decoded.tags(),
                [tag],
                "{} terminated a sequence with a chunk open",
                tag.prefix()
            );
        }
    }

    #[test]
    fn a_legal_sequence_decodes_to_the_expected_chunks() {
        let set = label_set();
        let wanted = [
            Tag::Outside,
            Tag::Begin(NAME),
            Tag::Inside(NAME),
            Tag::End(NAME),
            Tag::Outside,
            Tag::Single(TCKN),
            Tag::Outside,
        ];
        let decoded = set.viterbi(&shouting(&set, &wanted)).expect("decode");
        assert_eq!(decoded.tags(), wanted);

        let chunks = decoded.chunks();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].first, 1);
        assert_eq!(chunks[0].last, 3);
        assert_eq!(chunks[0].label, NAME);
        assert_eq!(chunks[1].first, 5);
        assert_eq!(chunks[1].last, 5);
        assert_eq!(chunks[1].label, TCKN);
        for chunk in &chunks {
            assert!(
                chunk.confidence > 0.9,
                "a shouted chunk should be confident, got {}",
                chunk.confidence
            );
            assert!((0.0..=1.0).contains(&chunk.confidence));
        }
    }

    #[test]
    fn the_constraint_repairs_an_ill_formed_argmax_into_a_whole_chunk() {
        // The concrete failure mode: the model wants `B I O`, which leaves the
        // name unterminated. A per-token argmax would emit it and a downstream
        // repair would have to guess where the name ended. The constrained
        // decode instead closes the chunk, so the whole name is masked.
        let set = label_set();
        let mut logits = shouting(&set, &[Tag::Begin(NAME), Tag::Inside(NAME), Tag::Outside]);
        // Make the illegal `I -> O` step genuinely the model's preference.
        let outside = set.index_of(Tag::Outside).expect("tag present");
        logits[2][outside] = 90.0;

        let decoded = set.viterbi(&logits).expect("decode");
        assert_ne!(
            decoded.tags(),
            [Tag::Begin(NAME), Tag::Inside(NAME), Tag::Outside],
            "the argmax sequence leaves a chunk open and must be unreachable"
        );

        // WHERE the decoder closes the chunk is the model's business -- given a
        // loud `O` at the last token it prefers `B E O` over `B I E`, which is
        // the evidence talking, and both are well-formed. WHAT the constraint
        // guarantees is that the chunk is closed at all, so a whole entity
        // reaches L4 rather than a fragment plus an orphan tag.
        let chunks = decoded.chunks();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].first, 0);
        assert_eq!(chunks[0].label, NAME);
        assert!(matches!(
            decoded.tags()[chunks[0].last],
            Tag::End(_) | Tag::Single(_)
        ));
        let last = decoded.tags().last().copied().expect("three tokens");
        assert!(
            !matches!(last, Tag::Begin(_) | Tag::Inside(_)),
            "the sequence ended with a chunk still open"
        );
    }

    #[test]
    fn confidence_is_the_probability_of_the_chosen_tag_not_the_logit() {
        // A flat row is maximum uncertainty: every tag has probability 1/width.
        let set = label_set();
        let flat = vec![vec![0.0_f32; set.width()]];
        let decoded = set.viterbi(&flat).expect("decode");
        let expected = 1.0 / set.width() as f32;
        assert!((decoded.probabilities()[0] - expected).abs() < 1e-5);
    }

    #[test]
    fn a_row_of_the_wrong_width_is_an_error_and_names_no_text() {
        let set = label_set();
        let err = set
            .viterbi(&[vec![0.0; set.width()], vec![0.0; 3]])
            .expect_err("a mis-shaped head must be rejected");
        assert_eq!(
            err,
            NerError::LogitWidth {
                row: 1,
                actual: 3,
                expected: set.width(),
            }
        );
    }

    #[test]
    fn a_non_finite_logit_is_rejected_rather_than_silently_decoded() {
        let set = label_set();
        let mut row = vec![0.0_f32; set.width()];
        row[2] = f32::NAN;
        assert_eq!(
            set.viterbi(&[row]).expect_err("NaN must be rejected"),
            NerError::NonFiniteLogit { row: 0 }
        );
    }

    #[test]
    fn an_empty_document_decodes_to_nothing() {
        let decoded = label_set().viterbi(&[]).expect("decode");
        assert!(decoded.tags().is_empty());
        assert!(decoded.chunks().is_empty());
    }
}
