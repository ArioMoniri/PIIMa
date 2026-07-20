//! BIO -> BIOES, as an explicit conversion over LOGITS.
//!
//! THE TWO SCHEMES ARE NOT INTERCHANGEABLE AND THIS MODULE EXISTS TO SAY SO.
//! Published Turkish token-classification checkpoints are almost all BIO: their
//! head has `O`, `B-X` and `I-X` columns and nothing else. This project decodes
//! BIOES, because [`super::bioes`]'s transition constraint needs the explicit
//! `E` and `S` roles to be able to see an unterminated chunk at all. Feeding BIO
//! logit columns straight into a BIOES [`LabelSet`] is a silent
//! mis-interpretation: column 2 means `I-X` to the checkpoint and `I-X` to us
//! only by coincidence of ordering, column 3 means `I-Y` to the checkpoint and
//! `E-X` to us, and the decode comes out confident, well-formed and wrong.
//!
//! # Why the conversion is on logits and not on the argmax tag sequence
//!
//! The obvious implementation is: argmax each token, convert the BIO tag string
//! to BIOES, extract chunks. That throws the evidence away before the constraint
//! ever sees it, which is the exact mistake [`super::bioes`]'s header rejects --
//! `B-X B-X` and `B-X I-X O` then need a post-hoc repair, and a repair is a
//! guess about how many bytes of a patient's name get masked.
//!
//! Instead the BIO evidence is RE-EXPRESSED in the BIOES column space and the
//! constrained Viterbi decides. The re-expression is the only honest one
//! available:
//!
//! - `B-X` says "an entity of type X STARTS at this token". In BIOES that is
//!   `B-X` (more tokens follow) or `S-X` (it is the whole entity). The
//!   checkpoint did not distinguish them, so neither do we: the mass goes to
//!   both and the transition constraint picks, using the NEXT token's evidence,
//!   which is precisely the information BIO encodes positionally.
//! - `I-X` says "an entity of type X CONTINUES here". In BIOES that is `I-X`
//!   (more follow) or `E-X` (it ends here). Same split, same reasoning.
//! - `O` maps to `O`.
//!
//! `B-X B-X` -- two adjacent entities of the same type, the one configuration
//! BIO can express and a naive converter mangles -- falls out correctly without
//! a special case: `B B` is illegal under the constraint, `B S` and `S B` leave
//! a chunk open or start one that cannot close, so `S-X S-X` wins and two
//! entities come out. [`two_adjacent_entities_stay_two_entities`] states that as
//! a test rather than as this paragraph.
//!
//! # Why the split subtracts ln(k)
//!
//! Duplicating a logit into two columns would add `exp(v)` to the softmax
//! denominator, inflating that tag's total probability at the expense of every
//! other tag in the row -- so a checkpoint's calibrated confidence would change
//! merely by being decoded. Subtracting `ln(k)` before duplicating makes the
//! k copies sum, under softmax, to exactly what the single source column had.
//! Confidence is what L4's router escalates on and what
//! `eval/thresholds.yaml` gates, so a conversion that quietly rescales it would
//! move a release gate.
//!
//! [`two_adjacent_entities_stay_two_entities`]: tests::two_adjacent_entities_stay_two_entities

use crate::label::EntityLabel;

use super::bioes::{LabelSet, Tag};
use super::NerError;

/// One column of a BIO head, in the checkpoint's own column order.
///
/// `Outside` is also how a caller declares a column it is DELIBERATELY not
/// consuming -- a checkpoint tagging an entity type this project's schema has no
/// label for. Several columns may map to `Outside` and their probability mass is
/// then summed rather than overwritten, which is why [`BioScheme::widen`]
/// combines by log-sum-exp instead of assignment. Silently dropping such a
/// column would leave its mass unaccounted for and make the row's probabilities
/// no longer sum to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioTag {
    /// Not part of any entity this project models.
    Outside,
    /// First token of an entity.
    Begin(EntityLabel),
    /// A token continuing an entity begun earlier.
    Inside(EntityLabel),
}

impl BioTag {
    /// The entity this column carries, if it carries one.
    #[must_use]
    pub const fn entity(self) -> Option<EntityLabel> {
        match self {
            Self::Outside => None,
            Self::Begin(label) | Self::Inside(label) => Some(label),
        }
    }

    /// The scheme prefix, for diagnostics. Carries no document text (I4).
    #[must_use]
    pub const fn prefix(self) -> char {
        match self {
            Self::Outside => 'O',
            Self::Begin(_) => 'B',
            Self::Inside(_) => 'I',
        }
    }
}

/// A BIO head's column inventory, plus the BIOES [`LabelSet`] it widens into.
///
/// Built from the checkpoint's own column order -- which the binding reads out
/// of `config.json`'s `id2label` -- so that nothing anywhere assumes the
/// checkpoint and this crate happen to enumerate entities the same way. The
/// entity vocabulary of the derived label set is the entities in FIRST
/// APPEARANCE order, which makes the derivation a deterministic function of the
/// checkpoint and therefore reproducible across runs (I5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BioScheme {
    columns: Vec<BioTag>,
    labels: LabelSet,
    /// `targets[source]` are the BIOES columns `source` contributes to.
    targets: Vec<Vec<usize>>,
}

impl BioScheme {
    /// Build the conversion for a checkpoint's column inventory.
    ///
    /// Rejects an empty inventory: a head with no columns cannot be decoded, and
    /// accepting it would produce an all-`Outside` decode that is
    /// indistinguishable from a model that ran and found nothing. I2 makes that
    /// distinction load-bearing -- "found nothing" is a result, "could not run"
    /// is a breach risk the operator has to be told about.
    pub fn new(columns: Vec<BioTag>) -> Result<Self, NerError> {
        if columns.is_empty() {
            return Err(NerError::EmptyScheme);
        }

        // First-appearance order, de-duplicated. `Vec::contains` over a handful
        // of entities is cheaper than a set and keeps the order explicit.
        let mut entities: Vec<EntityLabel> = Vec::new();
        for entity in columns.iter().filter_map(|column| column.entity()) {
            if !entities.contains(&entity) {
                entities.push(entity);
            }
        }
        let labels = LabelSet::new(&entities);

        let mut targets = Vec::with_capacity(columns.len());
        for &column in &columns {
            // `LabelSet` was built from exactly these entities, so every lookup
            // resolves. Handled rather than indexed so the crate stays
            // panic-free on every path.
            let wanted = match column {
                BioTag::Outside => vec![Tag::Outside],
                BioTag::Begin(label) => vec![Tag::Begin(label), Tag::Single(label)],
                BioTag::Inside(label) => vec![Tag::Inside(label), Tag::End(label)],
            };
            let mut resolved = Vec::with_capacity(wanted.len());
            for tag in wanted {
                resolved.push(labels.index_of(tag).ok_or(NerError::EmptyScheme)?);
            }
            targets.push(resolved);
        }

        Ok(Self {
            columns,
            labels,
            targets,
        })
    }

    /// The checkpoint's columns, in its own order.
    #[must_use]
    pub fn columns(&self) -> &[BioTag] {
        &self.columns
    }

    /// How many columns a row of this checkpoint's logits must have.
    #[must_use]
    pub fn width(&self) -> usize {
        self.columns.len()
    }

    /// The BIOES inventory the widened logits are columns of.
    #[must_use]
    pub fn labels(&self) -> &LabelSet {
        &self.labels
    }

    /// Re-express BIO logit rows in BIOES column space.
    ///
    /// Mass-preserving by construction: each source column contributes
    /// `value - ln(k)` to each of its `k` targets, and targets that receive from
    /// several sources combine by log-sum-exp. Softmax over the output row
    /// therefore assigns each BIO tag exactly the probability the input row did,
    /// split across the BIOES tags that mean the same thing.
    pub fn widen(&self, rows: &[Vec<f32>]) -> Result<Vec<Vec<f32>>, NerError> {
        let width = self.labels.width();
        let mut widened = Vec::with_capacity(rows.len());
        for (index, row) in rows.iter().enumerate() {
            if row.len() != self.width() {
                return Err(NerError::LogitWidth {
                    row: index,
                    actual: row.len(),
                    expected: self.width(),
                });
            }
            // Rejected here as well as in the decode: a NaN that survives the
            // widening becomes a NaN in several columns, and the decode would
            // then name a row index that is still meaningful but a column
            // inventory that is no longer the checkpoint's.
            if row.iter().any(|value| !value.is_finite()) {
                return Err(NerError::NonFiniteLogit { row: index });
            }

            // `NEG_INFINITY` is the identity for log-sum-exp: a target no source
            // reaches stays at zero probability rather than at zero logit, which
            // would be a substantial probability.
            let mut out = vec![f32::NEG_INFINITY; width];
            for (source, &value) in row.iter().enumerate() {
                let Some(targets) = self.targets.get(source) else {
                    continue;
                };
                // `targets` is never empty by construction, and its length is a
                // small count, so the cast is exact.
                let share = value - (targets.len() as f32).ln();
                for &target in targets {
                    if let Some(slot) = out.get_mut(target) {
                        *slot = log_add(*slot, share);
                    }
                }
            }
            widened.push(out);
        }
        Ok(widened)
    }
}

/// `ln(exp(a) + exp(b))`, stable, and total over `NEG_INFINITY`.
fn log_add(a: f32, b: f32) -> f32 {
    if a == f32::NEG_INFINITY {
        return b;
    }
    if b == f32::NEG_INFINITY {
        return a;
    }
    let (high, low) = if a > b { (a, b) } else { (b, a) };
    high + (low - high).exp().ln_1p()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: EntityLabel = EntityLabel::PatientName;
    const CITY: EntityLabel = EntityLabel::AddressCity;

    /// A checkpoint's column order: `O, B-NAME, I-NAME, B-CITY, I-CITY`.
    fn scheme() -> BioScheme {
        BioScheme::new(vec![
            BioTag::Outside,
            BioTag::Begin(NAME),
            BioTag::Inside(NAME),
            BioTag::Begin(CITY),
            BioTag::Inside(CITY),
        ])
        .expect("a five-column head")
    }

    /// A row asserting one BIO column loudly.
    fn shouting(scheme: &BioScheme, column: usize) -> Vec<f32> {
        let mut row = vec![0.0_f32; scheme.width()];
        row[column] = 8.0;
        row
    }

    fn softmax(row: &[f32]) -> Vec<f32> {
        let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let exponentiated: Vec<f32> = row.iter().map(|value| (value - max).exp()).collect();
        let total: f32 = exponentiated.iter().sum();
        exponentiated.iter().map(|value| value / total).collect()
    }

    #[test]
    fn the_derived_label_set_follows_the_checkpoints_own_entity_order() {
        // Reproducibility: the BIOES column layout must be a deterministic
        // function of the checkpoint, not of this crate's enum order.
        let scheme = scheme();
        let labels = scheme.labels();
        assert_eq!(labels.width(), 1 + 2 * 4);
        assert_eq!(labels.index_of(Tag::Begin(NAME)), Some(1));
        assert_eq!(labels.index_of(Tag::Single(NAME)), Some(4));
        assert_eq!(labels.index_of(Tag::Begin(CITY)), Some(5));

        // The other order gives the other layout, which is the point.
        let flipped = BioScheme::new(vec![
            BioTag::Outside,
            BioTag::Begin(CITY),
            BioTag::Inside(CITY),
            BioTag::Begin(NAME),
            BioTag::Inside(NAME),
        ])
        .expect("scheme");
        assert_eq!(flipped.labels().index_of(Tag::Begin(CITY)), Some(1));
    }

    #[test]
    fn a_head_with_no_columns_is_refused_rather_than_decoded_as_all_outside() {
        assert_eq!(BioScheme::new(Vec::new()), Err(NerError::EmptyScheme));
    }

    #[test]
    fn a_begin_column_reaches_both_begin_and_single_and_nothing_else() {
        let scheme = scheme();
        let widened = scheme
            .widen(&[shouting(&scheme, 1)])
            .expect("well-formed row");
        let labels = scheme.labels();
        let probabilities = softmax(&widened[0]);
        let begin = probabilities[labels.index_of(Tag::Begin(NAME)).expect("tag")];
        let single = probabilities[labels.index_of(Tag::Single(NAME)).expect("tag")];
        let inside = probabilities[labels.index_of(Tag::Inside(NAME)).expect("tag")];
        let end = probabilities[labels.index_of(Tag::End(NAME)).expect("tag")];
        assert!((begin - single).abs() < 1e-6, "the split must be even");
        assert!(begin > 0.4, "the shouted column must dominate, got {begin}");
        assert!(inside < 1e-3, "a B column must not leak into I");
        assert!(end < 1e-3, "a B column must not leak into E");
    }

    #[test]
    fn widening_preserves_the_checkpoints_probability_for_every_tag() {
        // The calibration property. If this drifts, every confidence the router
        // escalates on and every threshold in eval/thresholds.yaml moves,
        // without a single line of the decode changing.
        let scheme = scheme();
        let row = vec![1.5_f32, -0.25, 3.0, 0.75, -2.0];
        let before = softmax(&row);
        let widened = scheme.widen(&[row]).expect("well-formed row");
        let after = softmax(&widened[0]);
        let labels = scheme.labels();

        for (source, &column) in scheme.columns().iter().enumerate() {
            let recombined: f32 = match column {
                BioTag::Outside => after[labels.index_of(Tag::Outside).expect("tag")],
                BioTag::Begin(label) => {
                    after[labels.index_of(Tag::Begin(label)).expect("tag")]
                        + after[labels.index_of(Tag::Single(label)).expect("tag")]
                }
                BioTag::Inside(label) => {
                    after[labels.index_of(Tag::Inside(label)).expect("tag")]
                        + after[labels.index_of(Tag::End(label)).expect("tag")]
                }
            };
            assert!(
                (recombined - before[source]).abs() < 1e-5,
                "column {source} carried {} before and {recombined} after",
                before[source]
            );
        }
        assert!((after.iter().sum::<f32>() - 1.0).abs() < 1e-4);
    }

    #[test]
    fn several_columns_mapped_to_outside_have_their_mass_summed_not_overwritten() {
        // A checkpoint tagging entity types this project has no schema label
        // for. Assigning instead of accumulating would silently discard the
        // mass of every such column but the last, and the row would no longer
        // be a distribution.
        let scheme = BioScheme::new(vec![BioTag::Outside, BioTag::Outside, BioTag::Begin(NAME)])
            .expect("scheme");
        let row = vec![1.0_f32, 1.0, 0.0];
        let before = softmax(&row);
        let widened = scheme.widen(&[row]).expect("row");
        let after = softmax(&widened[0]);
        let outside = after[scheme.labels().index_of(Tag::Outside).expect("tag")];
        assert!(
            (outside - (before[0] + before[1])).abs() < 1e-5,
            "two Outside columns carried {} and {}, the widened row has {outside}",
            before[0],
            before[1]
        );
    }

    #[test]
    fn a_single_token_entity_decodes_as_s_not_as_an_unterminated_b() {
        let scheme = scheme();
        let rows = vec![
            shouting(&scheme, 0),
            shouting(&scheme, 1),
            shouting(&scheme, 0),
        ];
        let decoded = scheme
            .labels()
            .viterbi(&scheme.widen(&rows).expect("widen"))
            .expect("decode");
        assert_eq!(decoded.tags()[1], Tag::Single(NAME));
        let chunks = decoded.chunks();
        assert_eq!(chunks.len(), 1);
        assert_eq!((chunks[0].first, chunks[0].last), (1, 1));
    }

    #[test]
    fn a_multi_token_entity_decodes_as_b_then_e() {
        let scheme = scheme();
        let rows = vec![
            shouting(&scheme, 0),
            shouting(&scheme, 1),
            shouting(&scheme, 2),
            shouting(&scheme, 0),
        ];
        let decoded = scheme
            .labels()
            .viterbi(&scheme.widen(&rows).expect("widen"))
            .expect("decode");
        assert_eq!(
            decoded.tags(),
            [Tag::Outside, Tag::Begin(NAME), Tag::End(NAME), Tag::Outside]
        );
        let chunks = decoded.chunks();
        assert_eq!(chunks.len(), 1);
        assert_eq!((chunks[0].first, chunks[0].last), (1, 2));
    }

    #[test]
    fn a_three_token_entity_keeps_its_interior() {
        let scheme = scheme();
        let rows = vec![
            shouting(&scheme, 1),
            shouting(&scheme, 2),
            shouting(&scheme, 2),
            shouting(&scheme, 0),
        ];
        let decoded = scheme
            .labels()
            .viterbi(&scheme.widen(&rows).expect("widen"))
            .expect("decode");
        assert_eq!(
            decoded.tags(),
            [
                Tag::Begin(NAME),
                Tag::Inside(NAME),
                Tag::End(NAME),
                Tag::Outside
            ]
        );
    }

    #[test]
    fn two_adjacent_entities_stay_two_entities() {
        // `B-X B-X` is the ONE configuration BIO can express that a careless
        // converter merges. Two patients named in a row, or a patient and a
        // relative, become one span covering both -- and one surrogate for two
        // people is a re-identification handle rather than a mask.
        let scheme = scheme();
        let rows = vec![shouting(&scheme, 1), shouting(&scheme, 1)];
        let decoded = scheme
            .labels()
            .viterbi(&scheme.widen(&rows).expect("widen"))
            .expect("decode");
        assert_eq!(decoded.tags(), [Tag::Single(NAME), Tag::Single(NAME)]);
        let chunks = decoded.chunks();
        assert_eq!(
            chunks.len(),
            2,
            "two BIO begins must not merge into one span"
        );
        assert_eq!((chunks[0].first, chunks[0].last), (0, 0));
        assert_eq!((chunks[1].first, chunks[1].last), (1, 1));
    }

    #[test]
    fn adjacent_entities_of_different_types_stay_separate_too() {
        let scheme = scheme();
        let rows = vec![shouting(&scheme, 1), shouting(&scheme, 3)];
        let decoded = scheme
            .labels()
            .viterbi(&scheme.widen(&rows).expect("widen"))
            .expect("decode");
        assert_eq!(decoded.tags(), [Tag::Single(NAME), Tag::Single(CITY)]);
    }

    #[test]
    fn an_ill_formed_bio_sequence_still_decodes_to_something_well_formed() {
        // `O I-X` is illegal in IOB2 and real checkpoints emit it anyway,
        // because the head is a per-token classifier with no sequence model.
        // The constraint has to absorb it rather than the caller repairing it.
        let scheme = scheme();
        let rows = vec![shouting(&scheme, 0), shouting(&scheme, 2)];
        let decoded = scheme
            .labels()
            .viterbi(&scheme.widen(&rows).expect("widen"))
            .expect("decode");
        let labels = scheme.labels();
        let columns: Vec<usize> = decoded
            .tags()
            .iter()
            .map(|&tag| labels.index_of(tag).expect("decoded tag is in the set"))
            .collect();
        assert!(labels.allows_start(columns[0]));
        assert!(labels.allows(columns[0], columns[1]));
        assert!(labels.allows_end(columns[1]));
    }

    #[test]
    fn a_row_of_the_wrong_width_names_the_checkpoints_width_not_the_bioes_one() {
        // The message an operator sees when a checkpoint's head was exported
        // over a different label inventory than its config.json declares. It
        // must name the number the checkpoint should have produced.
        let scheme = scheme();
        let error = scheme
            .widen(&[vec![0.0; 3]])
            .expect_err("a mis-shaped head must be rejected");
        assert_eq!(
            error,
            NerError::LogitWidth {
                row: 0,
                actual: 3,
                expected: 5,
            }
        );
    }

    #[test]
    fn a_non_finite_logit_is_rejected_before_it_reaches_several_columns() {
        let scheme = scheme();
        let mut row = vec![0.0_f32; scheme.width()];
        row[2] = f32::INFINITY;
        assert_eq!(
            scheme.widen(&[row]).expect_err("infinity must be rejected"),
            NerError::NonFiniteLogit { row: 0 }
        );
    }

    #[test]
    fn log_add_is_stable_and_treats_negative_infinity_as_zero_probability() {
        assert_eq!(log_add(f32::NEG_INFINITY, 2.0), 2.0);
        assert_eq!(log_add(2.0, f32::NEG_INFINITY), 2.0);
        assert_eq!(
            log_add(f32::NEG_INFINITY, f32::NEG_INFINITY),
            f32::NEG_INFINITY
        );
        // ln(exp(0) + exp(0)) == ln 2.
        assert!((log_add(0.0, 0.0) - 2.0_f32.ln()).abs() < 1e-6);
        // Large equal values must not overflow to infinity.
        let big = log_add(80.0, 80.0);
        assert!(big.is_finite());
        assert!((big - (80.0 + 2.0_f32.ln())).abs() < 1e-3);
    }
}
