//! The span type every layer speaks, and the algebra that combines them.

use core::cmp::Ordering;
use core::fmt;

use crate::error::{Error, Result};
use crate::label::EntityLabel;

/// Which layer proposed a span.
///
/// The declaration order is load-bearing, not cosmetic: `Ord` makes `Rules`
/// the smallest, and [`Span::dominates`] orders on it first, so a rules parent
/// always wins a merge. A merged span therefore remembers that a
/// deterministic, checksum-validated detector produced it. Forgetting that is
/// how a checksum-valid TCKN becomes demotable by L4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Layer {
    /// L1, deterministic regex plus checksum.
    Rules,
    /// L2, the token-classifier ensemble.
    Ner,
    /// L3, the local contextual LLM sweep.
    Context,
}

/// WHICH DETECTOR INSTANCE proposed a span.
///
/// Deliberately NOT the same question as [`Layer`], and the distinction is the
/// whole L4 guardrail. `Layer` answers "which architectural stage produced
/// this" -- rules, ensemble, contextual sweep. `DetectorId` answers "which
/// concrete model instance produced this", and a five-model L2 ensemble has one
/// `Layer` and five `DetectorId`s.
///
/// Without this, two DIFFERENT ensemble members proposing the byte-identical
/// span are indistinguishable from ONE model emitting the same span twice.
/// Both collapse to `support: 1`, noisy-OR never runs, the span is not
/// protected, and L4 may demote it -- precisely on exact boundary agreement,
/// which is the strongest agreement signal the pipeline can produce.
///
/// The declaration order mirrors [`Layer`]'s. `Ord` is used to keep
/// [`Merged::contributors`] in a stable, sorted order and to look a detector up
/// in it; it is NOT how a merge picks a winner. Picking the smallest id was the
/// old provenance rule, and it named a detector that had produced neither the
/// surviving label nor the surviving bounds -- see [`Span::union_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DetectorId {
    /// L1, the deterministic rule set. There is exactly one.
    Rules,
    /// L2, one member of the token-classifier ensemble, indexed by its slot in
    /// the ensemble. Interned as a `u16` so a `Span` stays `Copy` and carries
    /// no allocation into the browser build.
    Ner(u16),
    /// L3, the local contextual sweep. There is exactly one.
    Context,
}

impl DetectorId {
    /// The architectural layer this detector belongs to.
    pub const fn layer(self) -> Layer {
        match self {
            Self::Rules => Layer::Rules,
            Self::Ner(_) => Layer::Ner,
            Self::Context => Layer::Context,
        }
    }
}

impl fmt::Display for DetectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rules => f.write_str("rules"),
            Self::Ner(index) => write!(f, "ner[{index}]"),
            Self::Context => f.write_str("context"),
        }
    }
}

/// What L4 decided to do with a span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Replace the covered bytes with a surrogate.
    Mask,
    /// Leave the covered bytes untouched.
    Keep,
}

/// The confidence a checksum-validated detection carries.
///
/// A span at this confidence from [`Layer::Rules`] passed an arithmetic check,
/// not a threshold, so it is never a false positive and never demotable.
pub const CHECKSUM_CONFIDENCE: f32 = 1.0;

/// A candidate identifier located in the original document.
///
/// Offsets are BYTE offsets into the ORIGINAL text and must land on UTF-8
/// character boundaries. Never char indices: `ş`, `ğ` and `İ` are two bytes
/// each, so in Turkish the two numbers diverge in almost every real note, and
/// a tokenizer or LLM that reports one where the other is expected produces
/// spans that mask the wrong bytes.
///
/// EVERY FIELD IS PRIVATE, and that is a safety property rather than a style
/// choice. [`Span::new`] enforces three invariants -- offsets on UTF-8
/// character boundaries, confidence in the unit interval, `source` derived
/// from `detector_id` -- and [`Span::checksum_validated`] is the sole setter
/// of the arithmetic flag. Public fields made all four claims false from any
/// other crate: `Span { checksum_validated: true, ..ner_span }` forged
/// protection onto a model guess, and a struct literal could place `start`
/// inside a `ş`, set `confidence: 42.0`, or pin `source: Rules` on an
/// `Ner(0)` detection. The BREACH direction was worse than the forgery: a
/// binding author writing a literal for a genuinely checksum-valid TCKN could
/// simply omit the flag and hand L4 a demotable identifier, which is the exact
/// failure the flag was introduced to prevent. `#[non_exhaustive]` was
/// considered and is not enough -- it blocks the external literal but leaves
/// every in-crate one, and it makes the invariants inconvenient rather than
/// unforgeable. Construction goes through a validating constructor or it does
/// not happen; reading goes through the accessors below.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Span {
    start: usize,
    end: usize,
    label: EntityLabel,
    /// Always `detector_id.layer()`. Stored rather than recomputed because it
    /// is the key the merge orders by and the value the audit log reports; see
    /// [`DetectorId`] for why the two are different questions.
    source: Layer,
    detector_id: DetectorId,
    confidence: f32,
    /// Set by the rules layer when an arithmetic check -- TCKN, VKN, IBAN
    /// mod-97 -- actually passed on the covered bytes.
    ///
    /// RECORDED, never inferred. Protection used to be reconstructed from
    /// `source == Rules && confidence >= 1.0`, but confidence is a derived
    /// quantity after noisy-OR and `source` follows a merge's dominant parent,
    /// so the single most safety-critical predicate in the crate was reading
    /// two values that no longer meant what it assumed. A rules hit with no
    /// checksum to run (an email regex) is not arithmetic and must not be
    /// protected as if it were.
    checksum_validated: bool,
    /// Hash of the covered text, so L5 can give the same entity the same
    /// surrogate throughout a document WITHOUT the pipeline ever storing the
    /// identifying text itself.
    ///
    /// KNOWN WEAKNESS, tracked as an open issue for M5: 64 bits of unkeyed
    /// hash over a short Turkish name is brute-forceable by anyone holding the
    /// span map, which partially defeats "never store the text". The fix is a
    /// keyed HMAC with a per-run secret salt; until then a span map is treated
    /// as sensitive as the document.
    text_hash: u64,
}

/// The result of merging one or more overlapping spans.
///
/// The contributor set is private for the same reason [`Span`]'s fields are:
/// `Merged { span, support: 2 }` handed the L4 guardrail its own answer, and
/// the crate's own tests wrote that literal, which is how the defect below
/// stayed invisible. The only ways to obtain one are [`Merged::single`], which
/// yields the weakest possible value, and [`union_widest`], which counts.
#[derive(Debug, Clone, PartialEq)]
pub struct Merged {
    span: Span,
    /// The distinct detectors that contributed to this merged region, sorted.
    ///
    /// A SET, not a count of merge events. `support` used to be incremented
    /// once per merge after a byte-identical dedup, so one `Ner(0)` proposing
    /// two overlapping-but-not-identical ranges, or the same bounds under two
    /// labels, reported `support: 2` and became undemotable -- a single model
    /// manufacturing the agreement the guardrail exists to require.
    contributors: Vec<DetectorId>,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rules => "rules",
            Self::Ner => "ner",
            Self::Context => "context",
        })
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mask => "mask",
            Self::Keep => "keep",
        })
    }
}

/// FNV-1a, 64-bit.
///
/// Chosen over `DefaultHasher` because the surrogate map must stay stable
/// across compiler and standard-library versions: a document de-identified
/// today and re-identified through its span map next year has to hash the same
/// bytes to the same value, and `DefaultHasher`'s output is explicitly not
/// guaranteed to be stable.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Combine two confidences by noisy-OR: `1 - (1-a)(1-b)`.
///
/// This is the arithmetic that makes the union a union. Agreement raises
/// confidence, but a single detector is already enough to flag: the result is
/// never below either input. Averaging instead would let a confident detector
/// be diluted by silent ones, which is a majority vote wearing a probability
/// costume, and invariant I2 forbids it.
pub fn noisy_or(a: f32, b: f32) -> f32 {
    (1.0 - (1.0 - a) * (1.0 - b)).clamp(0.0, 1.0)
}

impl Span {
    /// Build a span against the document it refers to.
    ///
    /// Validates that the range is non-empty, in bounds, and that BOTH offsets
    /// land on UTF-8 character boundaries.
    pub fn new(
        text: &str,
        start: usize,
        end: usize,
        label: EntityLabel,
        detector_id: DetectorId,
        confidence: f32,
    ) -> Result<Self> {
        if start >= end {
            return Err(Error::SpanNotOrdered { start, end });
        }
        let doc_len = text.len();
        if end > doc_len {
            return Err(Error::SpanOutOfBounds {
                offset: end,
                doc_len,
            });
        }
        for offset in [start, end] {
            if !text.is_char_boundary(offset) {
                return Err(Error::SpanNotCharBoundary { offset, doc_len });
            }
        }
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(Error::ConfidenceOutOfRange { confidence });
        }
        // Boundary and bounds are established above, so `get` cannot fail; it
        // is used anyway to keep every path in the crate panic-free.
        let covered = text.get(start..end).ok_or(Error::SpanOutOfBounds {
            offset: end,
            doc_len,
        })?;
        Ok(Self {
            start,
            end,
            label,
            source: detector_id.layer(),
            detector_id,
            confidence,
            checksum_validated: false,
            text_hash: fnv1a64(covered.as_bytes()),
        })
    }

    /// Build the one kind of span that is arithmetic rather than inference.
    ///
    /// The only way to set [`Span::checksum_validated`], and it is reachable
    /// only with [`DetectorId::Rules`]: a checksum is a property of digits, so
    /// no model gets to claim one. Confidence is fixed at
    /// [`CHECKSUM_CONFIDENCE`] because a check that passed is not a threshold
    /// that was cleared.
    pub fn checksum_validated(
        text: &str,
        start: usize,
        end: usize,
        label: EntityLabel,
    ) -> Result<Self> {
        Ok(Self {
            checksum_validated: true,
            ..Self::new(
                text,
                start,
                end,
                label,
                DetectorId::Rules,
                CHECKSUM_CONFIDENCE,
            )?
        })
    }

    /// Inclusive byte offset into the original text.
    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Exclusive byte offset into the original text.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// The schema label, from `eval/schema.yaml`.
    #[must_use]
    pub const fn label(&self) -> EntityLabel {
        self.label
    }

    /// The architectural layer that proposed this span.
    #[must_use]
    pub const fn source(&self) -> Layer {
        self.source
    }

    /// The concrete detector instance that proposed this span.
    ///
    /// This is what makes agreement countable: two spans over the same bytes
    /// corroborate each other only if their detector ids differ.
    #[must_use]
    pub const fn detector_id(&self) -> DetectorId {
        self.detector_id
    }

    /// 1.0 for checksum-valid, softmax for NER, model-reported for L3.
    #[must_use]
    pub const fn confidence(&self) -> f32 {
        self.confidence
    }

    /// True when an arithmetic check actually passed on the covered bytes.
    ///
    /// Named `is_*` because [`Span::checksum_validated`] is the constructor
    /// that sets it, and an inherent method may not share that name.
    #[must_use]
    pub const fn is_checksum_validated(&self) -> bool {
        self.checksum_validated
    }

    /// Hash of the covered text, for within-document surrogate consistency.
    #[must_use]
    pub const fn text_hash(&self) -> u64 {
        self.text_hash
    }

    /// Length of the covered range in bytes.
    ///
    /// Named for bytes rather than `len` because a caller reaching for a
    /// length in a de-identification pipeline is usually about to slice, and
    /// this is the number that is safe to slice with.
    pub const fn byte_len(&self) -> usize {
        self.end - self.start
    }

    /// True when the two spans share at least one byte.
    ///
    /// Strict: touching spans do not overlap. `Ayşe` immediately followed by
    /// `Yılmaz` are two proposals about two tokens, and merging them on
    /// contact would swallow the boundary between two different entities.
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// True when `other` lies entirely within `self`.
    pub const fn contains_span(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// True when the byte offset lies within the covered range.
    pub const fn contains_offset(&self, offset: usize) -> bool {
        self.start <= offset && offset < self.end
    }

    /// True when the two spans touch without overlapping, in either order.
    pub const fn is_adjacent_to(&self, other: &Self) -> bool {
        self.end == other.start || other.end == self.start
    }

    /// Merge an overlapping span into this one, keeping the widest bounds.
    ///
    /// Bounds take the outer hull and confidence combines by noisy-OR, but
    /// LABEL, SOURCE AND DETECTOR ID ALL COME FROM THE SAME PARENT -- the
    /// dominant one. The label follows dominance rather than width because the
    /// label chooses the surrogate format in L5, so a checksum-valid `TCKN`
    /// overlapped by a wider `PATIENT_NAME` guess must still produce a fake
    /// TCKN, not a fake name. The detector id follows it for a different
    /// reason: provenance that names a detector which produced neither the
    /// surviving label nor the surviving bounds is a false claim about who
    /// found what. It used to be `min()` of the parents, so merging
    /// `Ner(0)@"Ayşe"` with the wider `Ner(1)@"Ayşe Yılmaz"` reported
    /// `Ner(0)` over `Ner(1)`'s label and hull. Nothing egressed that today
    /// only because the audit log records `layer` and not `detector_id`, and
    /// recording the detector is the obvious next entry. The parents that lost
    /// are not forgotten: [`Merged::contributors`] keeps the full set.
    ///
    /// Dominance orders on [`Layer`] first, so a rules parent still wins and
    /// the merged span still reports `Layer::Rules`.
    ///
    /// The hash is recomputed over the merged bounds, because the merged span
    /// may cover text that neither parent covered and a stale hash silently
    /// breaks within-document surrogate consistency.
    pub fn union_with(&self, text: &str, other: &Self) -> Result<Self> {
        if !self.overlaps(other) {
            return Err(Error::DisjointUnion {
                left_start: self.start,
                left_end: self.end,
                right_start: other.start,
                right_end: other.end,
            });
        }
        let dominant = if other.dominates(self) { other } else { self };
        Ok(Self {
            // A checksum that passed on either parent's bytes still passed:
            // the merged hull covers them. Dropping the flag here would let a
            // wide, weak NER guess launder a checksum-valid TCKN into a
            // demotable span, which is the exact failure the flag exists for.
            checksum_validated: self.checksum_validated || other.checksum_validated,
            ..Self::new(
                text,
                self.start.min(other.start),
                self.end.max(other.end),
                dominant.label,
                dominant.detector_id,
                noisy_or(self.confidence, other.confidence),
            )?
        })
    }

    /// Whose label and identity survive a merge: strongest source first, then
    /// widest, then most confident.
    fn dominates(&self, other: &Self) -> bool {
        // f32 is not Ord, so confidence cannot ride in a derived tuple key and
        // is compared explicitly with `total_cmp`, descending. Comparing each
        // confidence against the top of the range instead -- as this used to --
        // maps every sub-1.0 value to the same `Ordering::Greater`, so 0.99
        // tied with 0.05 and the "most confident" tiebreak silently degraded
        // into "whichever argument came first".
        (self.source, core::cmp::Reverse(self.byte_len()))
            .cmp(&(other.source, core::cmp::Reverse(other.byte_len())))
            .then_with(|| other.confidence.total_cmp(&self.confidence))
            == Ordering::Less
    }
}

impl Merged {
    /// One proposal, standing alone.
    ///
    /// Public because a caller needs SOME way to present a single span to the
    /// L4 guardrail, and safe to expose because it yields the weakest value
    /// the type can hold: exactly one contributor, so it can never manufacture
    /// protection. Everything above support 1 is earned through
    /// [`union_widest`] from proposals that actually exist.
    #[must_use]
    pub fn single(span: Span) -> Self {
        Self {
            contributors: vec![span.detector_id],
            span,
        }
    }

    /// The widest covering span, with combined confidence.
    #[must_use]
    pub const fn span(&self) -> &Span {
        &self.span
    }

    /// Every distinct detector that contributed, in [`DetectorId`] order.
    #[must_use]
    pub fn contributors(&self) -> &[DetectorId] {
        &self.contributors
    }

    /// How many DISTINCT detectors contributed to this merged region.
    ///
    /// SEMANTICS, stated because the previous definition could not back the
    /// claim it made. `support` is the cardinality of [`Merged::contributors`]
    /// -- the set of detector instances whose proposals reached this region.
    /// It is NOT a count of merge events, and one detector cannot raise it by
    /// proposing more ranges.
    ///
    /// TRANSITIVE CHAINS ARE COUNTED, AND AGREEMENT DOES NOT REQUIRE A
    /// COMMONLY-AGREED BYTE RANGE. Three detectors chained A-B, B-C report
    /// support 3 even though A and C may share no byte. This over-approximates
    /// "independent agreement" and it is chosen deliberately: the only use of
    /// `support` is [`Merged::is_protected`], where a higher number forbids
    /// demotion. Requiring a common byte range would make chained spans
    /// demotable, and demotion of a real identifier is a breach while
    /// over-protection is a precision papercut -- I2 decides that trade in one
    /// direction only. A caller that needs the stricter property must intersect
    /// [`Merged::contributors`] against bounds itself; the merge will not
    /// silently apply the weaker protection on its behalf.
    #[must_use]
    pub fn support(&self) -> usize {
        self.contributors.len()
    }

    /// True when L4 is forbidden to demote this span.
    ///
    /// Two grounds, both from the brief: a checksum-validated rules hit is
    /// arithmetic rather than inference, and independent agreement between
    /// detectors is the strongest evidence the pipeline can produce. Demoting
    /// either is how a union quietly becomes a majority vote.
    ///
    /// Both grounds are read, never reconstructed: the checksum flag is set by
    /// the code that ran the arithmetic, and `support` counts DISTINCT detector
    /// ids.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.span.checksum_validated || self.support() > 1
    }

    /// Fold an overlapping proposal into this region.
    ///
    /// Private: growing the contributor set is the act the guardrail depends
    /// on, so it happens only where an actual overlapping proposal was
    /// observed.
    fn absorb(&mut self, text: &str, other: &Span) -> Result<()> {
        self.span = self.span.union_with(text, other)?;
        if let Err(index) = self.contributors.binary_search(&other.detector_id) {
            self.contributors.insert(index, other.detector_id);
        }
        Ok(())
    }
}

/// Merge overlapping spans into an ordered, non-overlapping covering set.
///
/// UNION SEMANTICS, and the reason this function is not a filter: every input
/// byte range is covered by exactly one output range. Nothing is ever dropped,
/// including a span that exactly one detector proposed. A merge that can drop
/// a lone proposal is a majority vote, and a majority vote over PHI candidates
/// is a breach machine -- the one detector that saw the identifier is
/// out-voted by the ones that did not.
///
/// `text` is required because the merged bounds need a fresh `text_hash`.
pub fn union_widest(text: &str, spans: &[Span]) -> Result<Vec<Merged>> {
    let mut ordered = spans.to_vec();
    ordered.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(a.detector_id.cmp(&b.detector_id))
            .then(a.label.cmp(&b.label))
            .then(b.confidence.total_cmp(&a.confidence))
    });
    // Collapse EXACT duplicates: same bounds, same label, same detector id.
    //
    // What this actually guarantees, stated narrowly because an overstated
    // comment is how the next reader trusts a property the code does not have:
    // it removes byte-identical SAME-LABEL repeats from one detector, and
    // nothing else. It does NOT prevent one detector from raising the merged
    // confidence of a region. Two measured cases that still inflate:
    //   - one detector emitting the same bounds under two different labels
    //     noisy-ORs 0.4 with itself to 0.6400, because the label is part of the
    //     dedup key;
    //   - four merely OVERLAPPING (not identical) ranges from one detector
    //     take 0.4 to 0.8704, because absorb() folds each one in turn.
    // `support` is unaffected in both cases -- it counts a SET of detector ids,
    // so a repeat cannot inflate it -- which is what keeps `is_protected` and
    // the L4 demotion guardrail honest regardless of the confidence arithmetic.
    //
    // WHY that residual inflation is left alone rather than clamped: the
    // direction is safe under I2. Higher confidence means a span skips
    // escalation and is auto-Masked, so the failure mode is over-masking a
    // region a detector saw several times -- a papercut. The dangerous
    // direction would be inflated confidence letting something be DEMOTED, and
    // demotion keys on `support` and `checksum_validated`, never on confidence.
    //
    // The key is the detector id and not the layer, because two ensemble
    // members share a layer and keying on it would collapse their genuine
    // agreement into one vote. Sorting by detector id above is what puts the
    // true duplicates next to each other for `dedup_by`, which only removes
    // consecutive elements.
    ordered.dedup_by(|a, b| {
        a.start == b.start && a.end == b.end && a.label == b.label && a.detector_id == b.detector_id
    });

    let mut merged: Vec<Merged> = Vec::with_capacity(ordered.len());
    for span in ordered {
        match merged.last_mut() {
            Some(current) if current.span.overlaps(&span) => current.absorb(text, &span)?,
            _ => merged.push(Merged::single(span)),
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic. The TCKN is deliberately checksum-INVALID (I8).
    const DOC: &str = "Hasta Ayşe Yılmaz, TCKN 12345678951, Dr. Şükrü Gökçe tarafından görüldü.";

    /// The two ensemble members the agreement tests need to tell apart.
    const MODEL_A: DetectorId = DetectorId::Ner(0);
    const MODEL_B: DetectorId = DetectorId::Ner(1);

    fn at(needle: &str) -> (usize, usize) {
        let start = DOC.find(needle).expect("fixture must contain the needle");
        (start, start + needle.len())
    }

    fn span_over(needle: &str, label: EntityLabel, detector: DetectorId, confidence: f32) -> Span {
        let (start, end) = at(needle);
        Span::new(DOC, start, end, label, detector, confidence).expect("fixture span must be valid")
    }

    /// A checksum-validated rules hit, the way L1 will build one.
    fn checksum_span(needle: &str, label: EntityLabel) -> Span {
        let (start, end) = at(needle);
        Span::checksum_validated(DOC, start, end, label).expect("fixture span must be valid")
    }

    #[test]
    fn new_accepts_a_valid_span() {
        let (start, end) = at("Ayşe Yılmaz");
        let span = Span::new(DOC, start, end, EntityLabel::PatientName, MODEL_A, 0.91)
            .expect("valid span");
        assert_eq!((span.start(), span.end()), (start, end));
        assert_eq!(span.byte_len(), end - start);
    }

    #[test]
    fn a_span_reports_the_layer_of_its_detector() {
        assert_eq!(DetectorId::Rules.layer(), Layer::Rules);
        assert_eq!(MODEL_B.layer(), Layer::Ner);
        assert_eq!(DetectorId::Context.layer(), Layer::Context);
        let span = span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.5);
        assert_eq!(span.detector_id(), MODEL_B);
        assert_eq!(span.source(), Layer::Ner);
    }

    #[test]
    fn new_rejects_empty_and_inverted_ranges() {
        assert_eq!(
            Span::new(DOC, 5, 5, EntityLabel::Tckn, DetectorId::Rules, 1.0),
            Err(Error::SpanNotOrdered { start: 5, end: 5 })
        );
        assert_eq!(
            Span::new(DOC, 9, 4, EntityLabel::Tckn, DetectorId::Rules, 1.0),
            Err(Error::SpanNotOrdered { start: 9, end: 4 })
        );
    }

    #[test]
    fn new_rejects_offsets_past_the_end_of_the_document() {
        let past = DOC.len() + 1;
        assert_eq!(
            Span::new(DOC, 0, past, EntityLabel::Tckn, DetectorId::Rules, 1.0),
            Err(Error::SpanOutOfBounds {
                offset: past,
                doc_len: DOC.len(),
            })
        );
    }

    #[test]
    fn new_rejects_offsets_inside_a_multibyte_character() {
        // `ş` occupies two bytes; its second byte is not a boundary. A span
        // starting there is a corruption bug, so it must be unconstructible.
        let mid_s = DOC.find('ş').expect("fixture contains s-cedilla") + 1;
        assert!(!DOC.is_char_boundary(mid_s));
        assert_eq!(
            Span::new(
                DOC,
                mid_s,
                mid_s + 4,
                EntityLabel::PatientName,
                MODEL_A,
                0.8
            ),
            Err(Error::SpanNotCharBoundary {
                offset: mid_s,
                doc_len: DOC.len(),
            })
        );
        let (start, _) = at("Ayşe");
        assert_eq!(
            Span::new(DOC, start, mid_s, EntityLabel::PatientName, MODEL_A, 0.8),
            Err(Error::SpanNotCharBoundary {
                offset: mid_s,
                doc_len: DOC.len(),
            })
        );
    }

    #[test]
    fn new_rejects_confidence_outside_the_unit_interval() {
        let (start, end) = at("Ayşe");
        assert_eq!(
            Span::new(DOC, start, end, EntityLabel::PatientName, MODEL_A, 1.5),
            Err(Error::ConfidenceOutOfRange { confidence: 1.5 })
        );
        assert!(matches!(
            Span::new(DOC, start, end, EntityLabel::PatientName, MODEL_A, f32::NAN),
            Err(Error::ConfidenceOutOfRange { .. })
        ));
    }

    #[test]
    fn turkish_byte_offsets_differ_from_char_indices() {
        let (start, end) = at("Şükrü Gökçe");
        let char_start = DOC
            .char_indices()
            .position(|(i, _)| i == start)
            .expect("char index");
        assert_ne!(
            start, char_start,
            "fixture must place the name after multi-byte characters"
        );
        let span = Span::new(DOC, start, end, EntityLabel::ClinicianName, MODEL_A, 0.9)
            .expect("valid span");
        // Three two-byte letters in `Şükrü Gökçe`: S-caron, u-diaeresis twice,
        // o-diaeresis, c-cedilla -- so the byte length exceeds the char count.
        let chars = DOC[start..end].chars().count();
        assert!(
            span.byte_len() > chars,
            "byte length {} must exceed char count {chars}",
            span.byte_len()
        );
        // The actual bug this type prevents: a caller who reached the end of
        // the name by counting CHARACTERS and then used that count as a BYTE
        // length stops short of the end AND lands inside a letter, so the
        // slice is both truncated and invalid.
        let as_if_chars_were_bytes = start + chars;
        assert!(
            as_if_chars_were_bytes < end,
            "a char count used as a byte length must truncate the span"
        );
        assert!(
            !DOC.is_char_boundary(as_if_chars_were_bytes),
            "and must land inside a multi-byte letter"
        );
    }

    #[test]
    fn overlap_containment_and_adjacency_predicates() {
        let name = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.9);
        let given = span_over("Ayşe", EntityLabel::PatientName, MODEL_A, 0.7);
        let tckn = checksum_span("12345678951", EntityLabel::Tckn);

        assert!(name.overlaps(&given));
        assert!(given.overlaps(&name));
        assert!(name.contains_span(&given));
        assert!(!given.contains_span(&name));
        assert!(!name.overlaps(&tckn));
        assert!(name.contains_offset(name.start));
        assert!(!name.contains_offset(name.end));
    }

    #[test]
    fn adjacent_spans_touch_but_do_not_overlap() {
        let (start, end) = at("Ayşe Yılmaz");
        let left = Span::new(
            DOC,
            start,
            start + 5,
            EntityLabel::PatientName,
            MODEL_A,
            0.8,
        )
        .expect("valid");
        let right =
            Span::new(DOC, start + 5, end, EntityLabel::PatientName, MODEL_A, 0.8).expect("valid");
        assert!(left.is_adjacent_to(&right));
        assert!(right.is_adjacent_to(&left));
        assert!(!left.overlaps(&right));
    }

    #[test]
    fn noisy_or_never_reduces_either_input() {
        assert!((noisy_or(0.6, 0.5) - 0.8).abs() < 1e-6);
        assert!((noisy_or(1.0, 0.0) - 1.0).abs() < 1e-6);
        for a in [0.0_f32, 0.3, 0.7, 1.0] {
            for b in [0.0_f32, 0.3, 0.7, 1.0] {
                let combined = noisy_or(a, b);
                assert!(combined >= a && combined >= b, "{combined} < max({a}, {b})");
            }
        }
    }

    #[test]
    fn union_keeps_the_widest_bounds_and_combines_by_noisy_or() {
        let wide = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.6);
        let narrow = span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.5);
        let merged = wide
            .union_with(DOC, &narrow)
            .expect("overlapping spans union");
        assert_eq!((merged.start(), merged.end()), (wide.start(), wide.end()));
        assert!((merged.confidence() - 0.8).abs() < 1e-6);
    }

    #[test]
    fn union_rehashes_over_the_merged_bounds() {
        let left = span_over("Ayşe Yıl", EntityLabel::PatientName, MODEL_A, 0.6);
        let right = span_over("şe Yılmaz", EntityLabel::PatientName, MODEL_B, 0.6);
        let merged = left
            .union_with(DOC, &right)
            .expect("overlapping spans union");
        let hull = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.6);
        assert_eq!(merged.text_hash(), hull.text_hash());
        assert_ne!(merged.text_hash(), left.text_hash());
    }

    #[test]
    fn union_of_disjoint_spans_is_an_error() {
        let name = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.9);
        let tckn = checksum_span("12345678951", EntityLabel::Tckn);
        assert!(matches!(
            name.union_with(DOC, &tckn),
            Err(Error::DisjointUnion { .. })
        ));
    }

    #[test]
    fn merge_keeps_the_strongest_source_and_its_label() {
        // A checksum-valid TCKN overlapped by a wider, weaker NER guess. The
        // hull is the wider range, but the identity stays the rules hit, or
        // L5 would mint a fake name where a fake TCKN belongs and L4 would
        // believe the span is demotable.
        let tckn = checksum_span("12345678951", EntityLabel::Tckn);
        let guess = span_over("TCKN 12345678951", EntityLabel::OtherUniqueId, MODEL_A, 0.4);
        let merged = union_widest(DOC, &[guess, tckn]).expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].span().label(), EntityLabel::Tckn);
        assert_eq!(merged[0].span().source(), Layer::Rules);
        assert_eq!(merged[0].span().detector_id(), DetectorId::Rules);
        assert_eq!(
            (merged[0].span().start(), merged[0].span().end()),
            (guess.start(), guess.end())
        );
        assert!(merged[0].is_protected());
    }

    #[test]
    fn a_span_proposed_by_exactly_one_detector_survives_the_merge() {
        // THE invariant that stops the union from becoming a majority vote.
        // Two detectors agree on the patient name; exactly one detector saw
        // the clinician name. The lone proposal must come out the other side.
        let agreed_a = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.8);
        let agreed_b = span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.6);
        let lone = span_over("Şükrü Gökçe", EntityLabel::ClinicianName, MODEL_A, 0.31);

        let merged = union_widest(DOC, &[agreed_a, agreed_b, lone]).expect("merge");
        let survivor = merged
            .iter()
            .find(|m| m.span.label == EntityLabel::ClinicianName)
            .expect("the lone proposal must survive the merge");
        assert_eq!(survivor.support(), 1);
        assert_eq!(
            (survivor.span().start(), survivor.span().end()),
            (lone.start(), lone.end())
        );
        assert!((survivor.span().confidence() - 0.31).abs() < 1e-6);
    }

    #[test]
    fn merge_never_drops_a_span_and_covers_every_input_byte_range() {
        let inputs = [
            span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.8),
            span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.6),
            span_over("Yılmaz", EntityLabel::PatientName, DetectorId::Context, 0.5),
            checksum_span("12345678951", EntityLabel::Tckn),
            span_over("Şükrü Gökçe", EntityLabel::ClinicianName, MODEL_A, 0.3),
            span_over("Dr. Şükrü", EntityLabel::ClinicianName, MODEL_B, 0.4),
        ];
        let merged = union_widest(DOC, &inputs).expect("merge");
        for input in &inputs {
            assert!(
                merged.iter().any(|m| m.span().contains_span(input)),
                "input range {}..{} was dropped by the merge",
                input.start(),
                input.end()
            );
        }
    }

    #[test]
    fn merge_output_is_ordered_and_non_overlapping() {
        let inputs = [
            span_over("Şükrü Gökçe", EntityLabel::ClinicianName, MODEL_A, 0.3),
            span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.6),
            checksum_span("12345678951", EntityLabel::Tckn),
            span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.8),
            span_over("Dr. Şükrü", EntityLabel::ClinicianName, MODEL_B, 0.4),
        ];
        let merged = union_widest(DOC, &inputs).expect("merge");
        assert_eq!(merged.len(), 3);
        for pair in merged.windows(2) {
            let (left, right) = (pair[0].span(), pair[1].span());
            assert!(left.start() < right.start(), "merge output is not sorted");
            assert!(!left.overlaps(right), "merge output still overlaps");
            assert!(left.end() <= right.start());
        }
    }

    #[test]
    fn merge_is_transitive_through_a_chain_of_overlaps() {
        let a = span_over("Ayşe Yıl", EntityLabel::PatientName, MODEL_A, 0.5);
        let b = span_over("şe Yılmaz", EntityLabel::PatientName, MODEL_B, 0.5);
        let c = span_over(
            "Yılmaz, TCKN",
            EntityLabel::PatientName,
            DetectorId::Context,
            0.5,
        );
        let merged = union_widest(DOC, &[a, b, c]).expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].span().start(), a.start());
        assert_eq!(merged[0].span().end(), c.end());
        assert_eq!(merged[0].support(), 3);
    }

    #[test]
    fn duplicate_proposals_do_not_manufacture_agreement() {
        let once = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.4);
        let merged = union_widest(DOC, &[once, once, once]).expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].support(),
            1,
            "one detector repeating itself is not independent agreement"
        );
        assert!(!merged[0].is_protected());
    }

    #[test]
    fn one_detector_repeating_identical_bounds_is_not_agreement() {
        // The same model emitting the same bounds twice at DIFFERENT
        // confidences is still one model. Keying the dedup on confidence, or
        // on anything the model can vary between passes, would turn a retry
        // into a protected span.
        let first = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.4);
        let again = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.55);
        let merged = union_widest(DOC, &[first, again]).expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].support(), 1);
        assert!(
            !merged[0].is_protected(),
            "a demotable span must stay demotable"
        );
    }

    #[test]
    fn two_distinct_ner_detectors_at_identical_bounds_agree() {
        // Byte-identical proposals from two different ensemble members are the
        // STRONGEST agreement signal there is. Collapsing them to support 1 --
        // which keying the dedup on `Layer` instead of `DetectorId` did --
        // defeated the L4 guardrail exactly there.
        let a = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.4);
        let b = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_B, 0.5);
        let merged = union_widest(DOC, &[a, b]).expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].support(), 2);
        assert!(merged[0].is_protected());
        // noisy-OR ran: 1 - 0.6*0.5 = 0.7, above either input.
        assert!((merged[0].span().confidence() - 0.7).abs() < 1e-6);
    }

    #[test]
    fn agreement_between_detectors_protects_a_span() {
        let a = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.4);
        let b = span_over("Ayşe", EntityLabel::PatientName, DetectorId::Context, 0.4);
        let merged = union_widest(DOC, &[a, b]).expect("merge");
        assert_eq!(merged[0].support(), 2);
        assert!(merged[0].is_protected());
    }

    #[test]
    fn a_checksum_span_is_protected_on_its_own() {
        let merged =
            union_widest(DOC, &[checksum_span("12345678951", EntityLabel::Tckn)]).expect("merge");
        assert_eq!(merged[0].support(), 1);
        assert!(merged[0].span().is_checksum_validated());
        assert!(merged[0].is_protected());
    }

    #[test]
    fn protection_is_recorded_not_inferred_from_confidence() {
        // A rules hit with no arithmetic behind it -- an email regex, say --
        // can legitimately reach confidence 1.0 without being a checksum. It
        // used to be protected by inference from (source, confidence); it must
        // not be, because nothing validated it.
        let unchecked = span_over("12345678951", EntityLabel::Email, DetectorId::Rules, 1.0);
        assert!(!unchecked.is_checksum_validated());
        let candidate = Merged::single(unchecked);
        assert!(!candidate.is_protected());
    }

    #[test]
    fn a_merge_never_loses_the_checksum_flag() {
        // The flag is OR-ed across a merge: a wide, weak NER guess swallowing
        // a checksum-valid TCKN must not launder it into a demotable span.
        let tckn = checksum_span("12345678951", EntityLabel::Tckn);
        let guess = span_over("TCKN 12345678951", EntityLabel::OtherUniqueId, MODEL_A, 0.2);
        for pair in [[guess, tckn], [tckn, guess]] {
            let merged = union_widest(DOC, &pair).expect("merge");
            assert_eq!(merged.len(), 1);
            assert!(
                merged[0].span().is_checksum_validated(),
                "the checksum flag did not survive the merge"
            );
            assert!(merged[0].is_protected());
        }
    }

    #[test]
    fn a_merge_of_two_unvalidated_spans_stays_unvalidated() {
        let a = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_A, 0.4);
        let b = span_over("Ayşe", EntityLabel::PatientName, MODEL_A, 0.4);
        let merged = a.union_with(DOC, &b).expect("union");
        assert!(!merged.is_checksum_validated());
    }

    #[test]
    fn the_more_confident_span_dominates_a_merge() {
        // Confidence used to be compared only against 1.0, so every sub-1.0
        // value mapped to the same ordering and 0.9 tied with 0.5: the label
        // of the merged span was then decided by argument order, not evidence.
        let low = span_over("Ayşe Yılmaz", EntityLabel::OtherUniqueId, MODEL_A, 0.5);
        let high = span_over("Ayşe Yılmaz", EntityLabel::PatientName, MODEL_B, 0.9);
        assert_eq!(
            low.union_with(DOC, &high).expect("union").label(),
            EntityLabel::PatientName
        );
        assert_eq!(
            high.union_with(DOC, &low).expect("union").label(),
            EntityLabel::PatientName,
            "dominance must not depend on argument order"
        );
    }

    #[test]
    fn source_outranks_width_and_width_outranks_confidence() {
        // The tiebreak order itself: a strong source beats a wider span, and a
        // wider span beats a more confident one. Only equal source and equal
        // width let confidence decide.
        let wide_weak = span_over("Ayşe Yılmaz", EntityLabel::OtherUniqueId, MODEL_A, 0.1);
        let narrow_sure = span_over("Ayşe", EntityLabel::PatientName, MODEL_B, 0.99);
        assert_eq!(
            wide_weak
                .union_with(DOC, &narrow_sure)
                .expect("union")
                .label(),
            EntityLabel::OtherUniqueId,
            "the wider span keeps its label against a narrower, surer one"
        );
    }

    #[test]
    fn merging_an_empty_proposal_set_yields_nothing() {
        assert!(union_widest(DOC, &[]).expect("merge").is_empty());
    }
}
