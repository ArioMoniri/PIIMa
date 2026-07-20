//! Redaction methods, and the per-entity-type policy that selects them.
//!
//! L5 mints format-preserving surrogates, and for a long time that was the only
//! thing this pipeline could do to a masked span. It is the right default and
//! it is not the right answer for every deployment, because the downstream uses
//! genuinely differ:
//!
//! | Method | Output | Destroys length? | Recoverable from output text? |
//! |---|---|---|---|
//! | [`Mask`] | `[PATIENT_NAME]` | yes | no |
//! | [`Redact`] | `********` (fixed width) | **yes, entirely** | no |
//! | [`Hash`] | `[PATIENT_NAME:a8cf...]` | yes | no (keyed) |
//! | [`DateShift`] | `19.03.2019` | no (format kept) | no |
//! | [`Surrogate`] | `Umut Deva` | yes | no |
//! | [`Remove`] | nothing | yes | no |
//!
//! [`Mask`]: RedactionMethod::Mask
//! [`Redact`]: RedactionMethod::Redact
//! [`Hash`]: RedactionMethod::Hash
//! [`DateShift`]: RedactionMethod::DateShift
//! [`Surrogate`]: RedactionMethod::Surrogate
//! [`Remove`]: RedactionMethod::Remove
//!
//! # "Recoverable from the output text" is not the same as "irreversible"
//!
//! No method here is reversible from the de-identified document alone. Every
//! method is reversible from the [`Redacted`] map, because that map holds the
//! originals -- re-identification is impossible otherwise, and M2's gateway
//! exists to re-identify. A map is therefore as sensitive as the document it
//! came from: local, never logged, never transmitted. What the methods differ
//! in is what an attacker learns from the OUTPUT, and that is the axis the
//! table above measures.
//!
//! # Why the policy is per entity type
//!
//! A real deployment does not want one method. It wants names masked so a
//! clinician can see that a name stood there, dates shifted so intervals
//! survive for research, and IBANs removed entirely because a bank account has
//! no clinical value and every character of it is a liability. One global
//! setting cannot express that, so [`RedactionPolicy`] maps [`EntityLabel`] to
//! method with a default for everything unmapped.
//!
//! # HONEST SCOPE
//!
//! Everything in this module operates on spans some other layer already found.
//! It changes what happens to a detected identifier; it detects nothing. As of
//! this writing L2 has no trained model, so the spans reaching a [`Redactor`]
//! in a stock build are the ones L1's deterministic rules prove -- TCKN, VKN,
//! SGK, IBAN, phone, MRN, email, dates. **Names are not among them: deid-tr
//! masks zero names today.** A policy entry for `PATIENT_NAME` configures what
//! would happen to a patient name if one were found, and nothing more.

mod hash;

use core::fmt;
use std::collections::BTreeMap;

use crate::label::EntityLabel;
use crate::span::Span;
use crate::surrogate::{Assigner, SurrogateEngine, SurrogateError};

pub use hash::{HashKey, HASH_HEX_LEN, HASH_KEY_LEN, MIN_HASH_KEY_MATERIAL};

/// The blackout character used when none is chosen.
///
/// ASCII, because the output of this method is frequently re-ingested by a
/// hospital system whose encoding assumptions nobody documented, and a
/// multi-byte block glyph that arrives as mojibake is a support ticket rather
/// than a redaction.
pub const DEFAULT_BLACKOUT_FILL: char = '*';

/// The blackout width used when none is chosen, in characters.
pub const DEFAULT_BLACKOUT_WIDTH: usize = 8;

/// The widest blackout that will be built.
///
/// A bound rather than an open number: the width is fixed and therefore
/// multiplied by every masked span in the document, and a caller who passes a
/// width from a config file typo should get an error rather than a gigabyte.
pub const MAX_BLACKOUT_WIDTH: usize = 64;

/// Everything redaction can refuse to do.
///
/// I4 applies here exactly as it does to [`crate::Error`]: no variant carries
/// document text, covered text, or a replacement. Offsets, counts, lengths and
/// method names only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedactError {
    /// Key material shorter than [`MIN_HASH_KEY_MATERIAL`].
    #[error("hash key material of {len} bytes is below the minimum accepted width")]
    HashKeyTooShort { len: usize },

    /// The policy selected [`RedactionMethod::Hash`] with no key installed.
    ///
    /// An error rather than a fallback to an unkeyed digest, because that
    /// fallback silently converts a privacy control into a lookup table over
    /// Turkish names and produces output that looks identical.
    #[error("the hash method requires a key and none was installed")]
    HashKeyRequired,

    /// The policy selected a method that needs L5 and no engine was installed.
    #[error("the {method} method requires a surrogate engine and none was installed")]
    SurrogateEngineRequired { method: RedactionMethod },

    /// Two spans handed to [`Redactor::redact`] cover the same bytes.
    ///
    /// Not resolved silently. Overlap resolution belongs to the span algebra
    /// (`union_widest`); a second, invisible merge rule here with possibly
    /// different semantics is how a pipeline ends up with two answers.
    #[error("spans {left_start}..{left_end} and {right_start}..{right_end} overlap")]
    OverlappingSpans {
        left_start: usize,
        left_end: usize,
        right_start: usize,
        right_end: usize,
    },

    /// A span points outside the document it was applied to.
    #[error("span offset {offset} lies outside a document of {doc_len} bytes")]
    SpanOutOfBounds { offset: usize, doc_len: usize },

    /// A blackout width of zero, or above [`MAX_BLACKOUT_WIDTH`].
    ///
    /// Zero is refused rather than clamped: a zero-width blackout is
    /// [`RedactionMethod::Remove`] wearing another method's name, and a caller
    /// who meant to remove should say so.
    #[error("blackout width {width} is outside 1..={max}")]
    BlackoutWidthOutOfRange { width: usize, max: usize },

    /// A blackout fill character that would not be visible in the output.
    ///
    /// Whitespace and control characters are refused because a redaction
    /// nobody can see reads as a transcription gap, and the reader concludes
    /// nothing stood there rather than that something was removed.
    #[error("the blackout fill character is whitespace or a control character")]
    BlackoutFillNotVisible,

    /// L5 refused.
    #[error("the surrogate engine refused: {0}")]
    Surrogate(#[from] SurrogateError),
}

/// A fixed-width blackout.
///
/// THE ONLY METHOD IN THIS MODULE THAT REMOVES THE LENGTH SIGNAL ENTIRELY, and
/// that is its whole reason to exist. `structural leakage` is one of L6's seven
/// attack classes: if a four-letter name becomes a four-letter replacement, or
/// an eleven-digit identifier becomes an eleven-character token, then the
/// SHAPE of the output narrows the candidate set even though the value is gone.
/// Every other method here leaks something about width -- [`Mask`] and
/// [`Hash`] leak the entity type's own constant width (harmless, it is the
/// same for every span of that type), [`Surrogate`] draws a length from the
/// keyed stream (uncorrelated but variable), and [`DateShift`] deliberately
/// re-emits the written date format, which is a width. A blackout emits the
/// same `width` characters for every span it touches, so the output carries
/// exactly one bit -- something was here -- and nothing else.
///
/// [`Mask`]: RedactionMethod::Mask
/// [`Hash`]: RedactionMethod::Hash
/// [`Surrogate`]: RedactionMethod::Surrogate
/// [`DateShift`]: RedactionMethod::DateShift
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blackout {
    fill: char,
    width: usize,
}

impl Default for Blackout {
    fn default() -> Self {
        Self {
            fill: DEFAULT_BLACKOUT_FILL,
            width: DEFAULT_BLACKOUT_WIDTH,
        }
    }
}

impl Blackout {
    /// A blackout of `width` copies of `fill`.
    ///
    /// # Errors
    ///
    /// [`RedactError::BlackoutWidthOutOfRange`] outside `1..=MAX_BLACKOUT_WIDTH`,
    /// and [`RedactError::BlackoutFillNotVisible`] for whitespace or a control
    /// character.
    pub fn new(fill: char, width: usize) -> Result<Self, RedactError> {
        if width == 0 || width > MAX_BLACKOUT_WIDTH {
            return Err(RedactError::BlackoutWidthOutOfRange {
                width,
                max: MAX_BLACKOUT_WIDTH,
            });
        }
        if fill.is_whitespace() || fill.is_control() {
            return Err(RedactError::BlackoutFillNotVisible);
        }
        Ok(Self { fill, width })
    }

    /// The fill character.
    #[must_use]
    pub const fn fill(self) -> char {
        self.fill
    }

    /// The width in characters. Constant across every span, by construction.
    #[must_use]
    pub const fn width(self) -> usize {
        self.width
    }

    fn render(self) -> String {
        core::iter::repeat_n(self.fill, self.width).collect()
    }
}

/// What to do with a masked span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactionMethod {
    /// Replace with the entity-type label: `[PATIENT_NAME]`.
    ///
    /// Readable, obviously redacted, and destroys the format. What a reader
    /// expects by default and what a downstream parser expecting a TCKN
    /// cannot ingest -- which is the trade against [`Self::Surrogate`].
    Mask,

    /// Replace with a fixed-width blackout. See [`Blackout`].
    Redact(Blackout),

    /// Replace with a KEYED, truncated digest: `[PATIENT_NAME:a8cfcd7412b39e05]`.
    ///
    /// Consistent within the document, so cross-references survive, and not
    /// invertible without the key. The key is mandatory; see [`HashKey`] for
    /// why an unkeyed digest of a short Turkish name is a lookup table rather
    /// than a one-way function.
    Hash,

    /// Shift the date by the engine's single per-salt offset.
    ///
    /// INTERVALS SURVIVE EXACTLY and absolute dates are fake, which is the
    /// property that makes a de-identified record still support the research it
    /// was de-identified for: a cycle three weeks after admission is still
    /// three weeks after admission. The offset comes from
    /// [`SurrogateEngine::date_shift_days`], so a document is internally
    /// consistent by construction.
    ///
    /// APPLIES TO DATE LABELS ONLY. On any other label the redactor falls back
    /// to [`Self::Mask`] and records the fallback in
    /// [`RedactedSpan::applied`] -- it never leaves the span in place, because
    /// a misconfigured policy must not become a leak.
    DateShift,

    /// Replace with a format-preserving fake: a checksum-valid fake TCKN, a
    /// mod-97-valid fake IBAN, a plausible Turkish name. The default.
    Surrogate,

    /// Delete the span, closing the text up around it.
    ///
    /// Leaves no marker at all, so a reader cannot tell that anything was
    /// removed and the sentence may not parse. Chosen when the identifier has
    /// no downstream value and its presence is pure liability.
    Remove,
}

impl Default for RedactionMethod {
    /// [`RedactionMethod::Surrogate`], which is what L5 has always done.
    fn default() -> Self {
        Self::Surrogate
    }
}

impl fmt::Display for RedactionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RedactionMethod {
    /// A stable identifier, for audit output and machine-readable formats.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mask => "mask",
            Self::Redact(_) => "redact",
            Self::Hash => "hash",
            Self::DateShift => "date_shift",
            Self::Surrogate => "surrogate",
            Self::Remove => "remove",
        }
    }
}

/// Which method applies to which entity type.
///
/// A default plus per-label overrides, rather than a full table, because the
/// safe behaviour for a label nobody configured has to be the default rather
/// than "do nothing". A missing entry can never mean "leave it in the text".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    default: RedactionMethod,
    by_label: BTreeMap<EntityLabel, RedactionMethod>,
}

impl Default for RedactionPolicy {
    /// Surrogates for everything, which is the behaviour this module replaced
    /// and therefore the one an existing caller must keep getting.
    fn default() -> Self {
        Self::new(RedactionMethod::Surrogate)
    }
}

impl RedactionPolicy {
    /// A policy with one default and no overrides.
    #[must_use]
    pub fn new(default: RedactionMethod) -> Self {
        Self {
            default,
            by_label: BTreeMap::new(),
        }
    }

    /// Override one entity type. Builder form.
    #[must_use]
    pub fn with(mut self, label: EntityLabel, method: RedactionMethod) -> Self {
        self.set(label, method);
        self
    }

    /// Override one entity type.
    pub fn set(&mut self, label: EntityLabel, method: RedactionMethod) {
        self.by_label.insert(label, method);
    }

    /// The default for every unconfigured entity type.
    #[must_use]
    pub const fn default_method(&self) -> RedactionMethod {
        self.default
    }

    /// The method configured for this entity type, or the default.
    #[must_use]
    pub fn method_for(&self, label: EntityLabel) -> RedactionMethod {
        self.by_label.get(&label).copied().unwrap_or(self.default)
    }

    /// Every explicit override, in label order.
    pub fn overrides(&self) -> impl Iterator<Item = (EntityLabel, RedactionMethod)> + '_ {
        self.by_label
            .iter()
            .map(|(label, method)| (*label, *method))
    }
}

/// One span as it appears before and after redaction.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedSpan {
    /// The schema label.
    pub label: EntityLabel,
    /// Inclusive byte offset in the ORIGINAL document.
    pub start: usize,
    /// Exclusive byte offset in the ORIGINAL document.
    pub end: usize,
    /// Inclusive byte offset in the OUTPUT document.
    pub output_start: usize,
    /// Exclusive byte offset in the OUTPUT document. Equal to `output_start`
    /// for [`RedactionMethod::Remove`], which produces a zero-width result.
    pub output_end: usize,
    /// What the policy asked for.
    pub requested: RedactionMethod,
    /// What was actually applied.
    ///
    /// DIFFERENT FROM `requested` ONLY ON A DOCUMENTED FALLBACK, currently
    /// [`RedactionMethod::DateShift`] on a non-date label. Recorded rather than
    /// silently substituted, because a policy that quietly does something other
    /// than what it says is a policy nobody can audit.
    pub applied: RedactionMethod,
    /// The text substituted. NOT PHI -- it is the mask, digest or surrogate.
    pub replacement: String,
    /// THE PHI. Private, readable only through [`RedactedSpan::original`], so
    /// every read is a line a reviewer can point at.
    original: String,
}

/// Hand-written so `{:?}` can never egress an original (I4).
///
/// Same construction and same argument as `MappedSpan`'s and `SurrogateEntry`'s.
/// The original renders as a fixed literal rather than as its length, because
/// `original: 11 bytes` re-emits exactly the length tell that
/// [`RedactionMethod::Redact`] exists to destroy.
impl fmt::Debug for RedactedSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactedSpan")
            .field("label", &self.label)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("output_start", &self.output_start)
            .field("output_end", &self.output_end)
            .field("requested", &self.requested)
            .field("applied", &self.applied)
            .field("replacement", &self.replacement)
            .field("original", &format_args!("<redacted>"))
            .finish()
    }
}

impl RedactedSpan {
    /// The original text this span covered.
    ///
    /// PHI. Every caller of this is holding an identifier and is responsible
    /// for it.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }
}

/// The output of one redaction pass.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted {
    text: String,
    spans: Vec<RedactedSpan>,
}

/// Hand-written for the same reason `DeidResult`'s is: this is the value a
/// binding hands back, so it is the value most likely to reach a `{:?}`, a
/// failing assertion or a panic message. The delegation to [`RedactedSpan`]'s
/// Debug is what redacts the originals.
impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redacted")
            .field("text", &self.text)
            .field("spans", &self.spans)
            .finish()
    }
}

impl Redacted {
    /// The redacted document.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The round-trip table, in document order.
    #[must_use]
    pub fn spans(&self) -> &[RedactedSpan] {
        &self.spans
    }

    /// Put the originals back, reversing this pass exactly.
    ///
    /// Works for EVERY method, including the one-way ones, because the table
    /// holds the originals -- which is precisely why the table is
    /// document-equivalent PHI. Walking `output_start` rather than recomputing
    /// offsets is what makes it exact: no method preserves byte length, so
    /// every replacement shifts everything after it.
    #[must_use]
    pub fn reidentify(&self) -> String {
        let mut out = String::with_capacity(self.text.len());
        let mut cursor = 0usize;
        for span in &self.spans {
            // `get` rather than indexing: this method is infallible by
            // contract, and a table edited by hand must degrade to a wrong
            // string rather than to a panic in a clinical tool.
            let Some(prefix) = self.text.get(cursor..span.output_start) else {
                continue;
            };
            out.push_str(prefix);
            out.push_str(&span.original);
            cursor = span.output_end;
        }
        if let Some(tail) = self.text.get(cursor..) {
            out.push_str(tail);
        }
        out
    }
}

/// One span's replacement, and both methods behind it.
///
/// The unit [`Redactor::replacement_for`] returns and the unit
/// [`Redactor::redact`] is built out of, so the orchestrator and the standalone
/// redaction pass cannot drift into resolving a method two different ways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// What the policy asked for.
    pub requested: RedactionMethod,
    /// What was actually applied, after [`resolve`]'s one documented fallback.
    pub applied: RedactionMethod,
    /// The text to substitute. NOT PHI.
    pub replacement: String,
}

/// Applies a [`RedactionPolicy`] to a document.
///
/// Holds no owned state: the surrogate engine and the hash key are borrowed, so
/// a caller cannot accidentally keep key material alive inside a long-lived
/// redactor.
pub struct Redactor<'a> {
    policy: &'a RedactionPolicy,
    surrogates: Option<&'a SurrogateEngine>,
    hash_key: Option<&'a HashKey>,
}

impl<'a> Redactor<'a> {
    /// A redactor for one policy, with no engine and no key.
    ///
    /// In this state [`RedactionMethod::Mask`], [`RedactionMethod::Redact`] and
    /// [`RedactionMethod::Remove`] work and the other three return an error
    /// naming what is missing. Erroring rather than degrading is deliberate:
    /// silently masking where the policy said surrogate changes the output
    /// format that a downstream system was configured against.
    #[must_use]
    pub const fn new(policy: &'a RedactionPolicy) -> Self {
        Self {
            policy,
            surrogates: None,
            hash_key: None,
        }
    }

    /// Install L5, which [`RedactionMethod::Surrogate`] and
    /// [`RedactionMethod::DateShift`] need.
    #[must_use]
    pub const fn with_surrogates(mut self, engine: &'a SurrogateEngine) -> Self {
        self.surrogates = Some(engine);
        self
    }

    /// Install the key [`RedactionMethod::Hash`] needs.
    #[must_use]
    pub const fn with_hash_key(mut self, key: &'a HashKey) -> Self {
        self.hash_key = Some(key);
        self
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &RedactionPolicy {
        self.policy
    }

    /// Render the replacement for ONE span, without rewriting a document.
    ///
    /// THE SEAM THE ORCHESTRATOR USES. `Pipeline` already walks the document
    /// once to build the round-trip map and the audit log, and a second walk
    /// inside [`Redactor::redact`] would have to agree with the first about
    /// every byte offset. Sharing the rendering rather than the walk is what
    /// keeps one method-resolution rule in the crate while leaving each caller
    /// its own rewrite.
    ///
    /// `assigner` must be the SAME assigner across a document, or L5's
    /// within-document consistency is lost.
    ///
    /// # Errors
    ///
    /// [`RedactError::HashKeyRequired`] or
    /// [`RedactError::SurrogateEngineRequired`] when the policy names a method
    /// this redactor is not equipped for, and whatever L5 returns.
    pub fn replacement_for(
        &self,
        label: EntityLabel,
        original: &str,
        assigner: Option<&mut Assigner<'_>>,
    ) -> Result<Rendered, RedactError> {
        let requested = self.policy.method_for(label);
        let applied = resolve(requested, label);
        let replacement = self.render(applied, label, original, assigner)?;
        Ok(Rendered {
            requested,
            applied,
            replacement,
        })
    }

    /// Redact every span, in document order.
    ///
    /// Spans may arrive in any order but must not overlap; resolving overlaps
    /// is `union_widest`'s job in the span algebra.
    ///
    /// # Errors
    ///
    /// [`RedactError::OverlappingSpans`], [`RedactError::SpanOutOfBounds`],
    /// [`RedactError::HashKeyRequired`] or
    /// [`RedactError::SurrogateEngineRequired`] when the policy names a method
    /// this redactor is not equipped for, and whatever L5 returns.
    pub fn redact(&self, text: &str, spans: &[Span]) -> Result<Redacted, RedactError> {
        let mut ordered: Vec<&Span> = spans.iter().collect();
        ordered.sort_by_key(|span| (span.start(), span.end()));
        for pair in ordered.windows(2) {
            let (left, right) = (pair[0], pair[1]);
            if left.end() > right.start() {
                return Err(RedactError::OverlappingSpans {
                    left_start: left.start(),
                    left_end: left.end(),
                    right_start: right.start(),
                    right_end: right.end(),
                });
            }
        }

        // ONE assigner for the whole document, which is what makes the same
        // entity receive the same surrogate everywhere in it.
        let mut assigner = self.surrogates.map(SurrogateEngine::assigner);
        let mut out = String::with_capacity(text.len());
        let mut redacted = Vec::with_capacity(ordered.len());
        let mut cursor = 0usize;

        for span in ordered {
            let original = slice(text, span.start(), span.end())?;
            out.push_str(slice(text, cursor, span.start())?);

            let Rendered {
                requested,
                applied,
                replacement,
            } = self.replacement_for(span.label(), original, assigner.as_mut())?;

            let output_start = out.len();
            out.push_str(&replacement);
            let output_end = out.len();
            cursor = span.end();

            redacted.push(RedactedSpan {
                label: span.label(),
                start: span.start(),
                end: span.end(),
                output_start,
                output_end,
                requested,
                applied,
                replacement,
                original: original.to_owned(),
            });
        }
        out.push_str(slice(text, cursor, text.len())?);

        Ok(Redacted {
            text: out,
            spans: redacted,
        })
    }

    fn render(
        &self,
        method: RedactionMethod,
        label: EntityLabel,
        original: &str,
        assigner: Option<&mut Assigner<'_>>,
    ) -> Result<String, RedactError> {
        match method {
            RedactionMethod::Mask => Ok(format!("[{}]", label.as_str())),
            RedactionMethod::Redact(blackout) => Ok(blackout.render()),
            RedactionMethod::Remove => Ok(String::new()),
            RedactionMethod::Hash => self
                .hash_key
                .ok_or(RedactError::HashKeyRequired)
                .map(|key| key.token(label, original)),
            // Both of these are L5. `DateShift` reaches the shift by asking the
            // assigner for a date-family surrogate, which is where the single
            // per-salt offset already lives -- rather than by reimplementing
            // civil-date arithmetic here, which would be a second date parser
            // with its own leap-year bugs.
            RedactionMethod::Surrogate | RedactionMethod::DateShift => {
                let assigner = assigner.ok_or(RedactError::SurrogateEngineRequired { method })?;
                Ok(assigner.assign(label, original)?)
            }
        }
    }
}

/// The one documented fallback: a date shift asked for on a non-date label.
///
/// Falls back to [`RedactionMethod::Mask`] rather than to `Surrogate`, because
/// the fallback should be the method that is always available and always safe
/// rather than one that might itself be unconfigured. It never falls back to
/// leaving the text in place -- a misconfigured policy must cost readability,
/// never recall (I2).
const fn resolve(requested: RedactionMethod, label: EntityLabel) -> RedactionMethod {
    match requested {
        RedactionMethod::DateShift if !is_date_like(label) => RedactionMethod::Mask,
        other => other,
    }
}

/// True for the five labels whose surrogate family is a date.
const fn is_date_like(label: EntityLabel) -> bool {
    matches!(
        label,
        EntityLabel::Date
            | EntityLabel::DateBirth
            | EntityLabel::DateAdmission
            | EntityLabel::DateDischarge
            | EntityLabel::DateDeath
    )
}

/// Slice without panicking on a bad range.
fn slice(text: &str, start: usize, end: usize) -> Result<&str, RedactError> {
    text.get(start..end).ok_or(RedactError::SpanOutOfBounds {
        offset: end,
        doc_len: text.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::{DetectorId, Span};
    use crate::surrogate::{Salt, SALT_LEN};

    /// Synthetic. Every identifier here is fake and the numbers are deliberately
    /// checksum-INVALID (I8); the checksum-valid vectors are built at runtime.
    const DOC: &str = "Hasta Ayşe Yılmaz, dogum 01.02.1970, yatis 10.03.2019, \
taburcu 24.03.2019, IBAN TR000000000000000000000000, Ayşe Yılmaz tekrar goruldu.";

    fn engine(byte: u8) -> SurrogateEngine {
        SurrogateEngine::new(Salt::from_bytes([byte; SALT_LEN]))
    }

    fn key(byte: u8) -> HashKey {
        HashKey::from_bytes([byte; HASH_KEY_LEN])
    }

    fn span(needle: &str, label: EntityLabel) -> Span {
        let start = DOC.find(needle).expect("fixture must contain the needle");
        Span::new(
            DOC,
            start,
            start + needle.len(),
            label,
            DetectorId::Ner(0),
            0.9,
        )
        .expect("fixture span must be valid")
    }

    /// The second occurrence of a repeated surface, so consistency is testable.
    fn second(needle: &str, label: EntityLabel) -> Span {
        let first = DOC.find(needle).expect("fixture");
        let start = DOC[first + needle.len()..]
            .find(needle)
            .expect("fixture must repeat the needle")
            + first
            + needle.len();
        Span::new(
            DOC,
            start,
            start + needle.len(),
            label,
            DetectorId::Ner(0),
            0.9,
        )
        .expect("fixture span must be valid")
    }

    fn policy(method: RedactionMethod) -> RedactionPolicy {
        RedactionPolicy::new(method)
    }

    // --- the policy itself ------------------------------------------------

    #[test]
    fn the_default_method_is_the_surrogate() {
        // The behaviour that existed before this module did. An existing caller
        // who adopts a default policy must see no change.
        assert_eq!(RedactionMethod::default(), RedactionMethod::Surrogate);
        assert_eq!(
            RedactionPolicy::default().method_for(EntityLabel::PatientName),
            RedactionMethod::Surrogate
        );
    }

    #[test]
    fn an_unconfigured_label_falls_back_to_the_default_never_to_nothing() {
        let policy = policy(RedactionMethod::Mask).with(EntityLabel::Tckn, RedactionMethod::Remove);
        assert_eq!(
            policy.method_for(EntityLabel::PassportNo),
            RedactionMethod::Mask
        );
        assert_eq!(
            policy.method_for(EntityLabel::Tckn),
            RedactionMethod::Remove
        );
        assert_eq!(policy.overrides().count(), 1);
    }

    #[test]
    fn a_real_deployment_policy_is_honoured_per_entity_type() {
        // The motivating configuration from the module header: names masked,
        // dates shifted so intervals survive, IBANs removed outright.
        let engine = engine(1);
        let policy = policy(RedactionMethod::Surrogate)
            .with(EntityLabel::PatientName, RedactionMethod::Mask)
            .with(EntityLabel::DateAdmission, RedactionMethod::DateShift)
            .with(EntityLabel::Iban, RedactionMethod::Remove);
        let out = Redactor::new(&policy)
            .with_surrogates(&engine)
            .redact(
                DOC,
                &[
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                    span("10.03.2019", EntityLabel::DateAdmission),
                    span("TR000000000000000000000000", EntityLabel::Iban),
                    // The fixture names the patient twice, so every "the
                    // original is gone" assertion has to cover both mentions;
                    // covering one is how a test passes over a leak.
                    second("Ayşe Yılmaz", EntityLabel::PatientName),
                ],
            )
            .expect("redact");

        assert!(out.text().contains("[PATIENT_NAME]"));
        assert!(!out.text().contains("Ayşe Yılmaz"));
        assert!(!out.text().contains("TR000000000000000000000000"));
        assert!(!out.text().contains("10.03.2019"));
        assert!(out.text().contains("IBAN ,"), "the IBAN was not closed up");

        let applied: Vec<_> = out.spans().iter().map(|s| s.applied).collect();
        assert_eq!(
            applied,
            vec![
                RedactionMethod::Mask,
                RedactionMethod::DateShift,
                RedactionMethod::Remove,
                RedactionMethod::Mask
            ]
        );
    }

    // --- per-method behaviour ---------------------------------------------

    #[test]
    fn mask_replaces_with_the_entity_label() {
        let policy = policy(RedactionMethod::Mask);
        let out = Redactor::new(&policy)
            .redact(DOC, &[span("Ayşe Yılmaz", EntityLabel::PatientName)])
            .expect("redact");
        assert_eq!(out.spans()[0].replacement, "[PATIENT_NAME]");
        assert_eq!(out.reidentify(), DOC);
    }

    #[test]
    fn redact_emits_a_constant_width_regardless_of_the_original() {
        // THE STRUCTURAL-LEAKAGE PROPERTY, as an assertion. A three-letter
        // original and a twenty-six-character IBAN must produce byte-identical
        // output, or the shape of the document still narrows the candidate set.
        let blackout = Blackout::new('#', 6).expect("valid blackout");
        let policy = policy(RedactionMethod::Redact(blackout));
        let out = Redactor::new(&policy)
            .redact(
                DOC,
                &[
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                    span("TR000000000000000000000000", EntityLabel::Iban),
                ],
            )
            .expect("redact");
        assert_eq!(out.spans()[0].replacement, "######");
        assert_eq!(out.spans()[1].replacement, "######");
        assert_eq!(out.spans()[0].replacement, out.spans()[1].replacement);
    }

    #[test]
    fn a_blackout_refuses_an_invisible_or_absurd_shape() {
        assert_eq!(
            Blackout::new('*', 0),
            Err(RedactError::BlackoutWidthOutOfRange {
                width: 0,
                max: MAX_BLACKOUT_WIDTH
            })
        );
        assert_eq!(
            Blackout::new('*', MAX_BLACKOUT_WIDTH + 1),
            Err(RedactError::BlackoutWidthOutOfRange {
                width: MAX_BLACKOUT_WIDTH + 1,
                max: MAX_BLACKOUT_WIDTH
            })
        );
        assert_eq!(
            Blackout::new(' ', 8),
            Err(RedactError::BlackoutFillNotVisible)
        );
        assert_eq!(
            Blackout::new('\n', 8),
            Err(RedactError::BlackoutFillNotVisible)
        );
        assert_eq!(Blackout::default().width(), DEFAULT_BLACKOUT_WIDTH);
        assert_eq!(Blackout::default().fill(), DEFAULT_BLACKOUT_FILL);
    }

    #[test]
    fn remove_deletes_the_span_and_closes_the_text_up() {
        let policy = policy(RedactionMethod::Remove);
        let out = Redactor::new(&policy)
            .redact(DOC, &[span("Ayşe Yılmaz", EntityLabel::PatientName)])
            .expect("redact");
        assert_eq!(out.spans()[0].replacement, "");
        assert_eq!(out.spans()[0].output_start, out.spans()[0].output_end);
        assert_eq!(out.text(), DOC.replacen("Ayşe Yılmaz", "", 1));
        assert_eq!(out.text().len(), DOC.len() - "Ayşe Yılmaz".len());
    }

    #[test]
    fn hash_is_stable_within_a_document() {
        // Cross-references have to survive: the two mentions of one patient
        // must still be one patient to a reader of the redacted note.
        let key = key(1);
        let policy = policy(RedactionMethod::Hash);
        let out = Redactor::new(&policy)
            .with_hash_key(&key)
            .redact(
                DOC,
                &[
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                    second("Ayşe Yılmaz", EntityLabel::PatientName),
                ],
            )
            .expect("redact");
        assert_eq!(out.spans()[0].replacement, out.spans()[1].replacement);
        assert!(out.spans()[0].replacement.starts_with("[PATIENT_NAME:"));
    }

    #[test]
    fn hash_differs_across_documents_under_different_keys() {
        // The linkage property: with a per-document key, the same patient in
        // two notes gets two tokens, so an attacker holding a corpus cannot
        // chain notes into a longitudinal profile.
        let policy = policy(RedactionMethod::Hash);
        let token = |k: &HashKey| {
            Redactor::new(&policy)
                .with_hash_key(k)
                .redact(DOC, &[span("Ayşe Yılmaz", EntityLabel::PatientName)])
                .expect("redact")
                .spans()[0]
                .replacement
                .clone()
        };
        assert_ne!(token(&key(1)), token(&key(2)));
        assert_eq!(token(&key(1)), token(&key(1)));
    }

    #[test]
    fn hash_without_a_key_is_an_error_not_an_unkeyed_digest() {
        // Silently emitting an unkeyed digest would produce output that looks
        // identical and is brute-forceable by enumerating Turkish names.
        let policy = policy(RedactionMethod::Hash);
        assert_eq!(
            Redactor::new(&policy)
                .redact(DOC, &[span("Ayşe Yılmaz", EntityLabel::PatientName)])
                .map(|_| ()),
            Err(RedactError::HashKeyRequired)
        );
    }

    #[test]
    fn date_shift_preserves_the_interval_between_two_dates() {
        // The clinical property. Admission and discharge are fourteen days
        // apart in the original and must stay fourteen days apart after the
        // shift, or the de-identified record cannot support the research it was
        // de-identified for.
        let engine = engine(9);
        let policy = policy(RedactionMethod::DateShift);
        let out = Redactor::new(&policy)
            .with_surrogates(&engine)
            .redact(
                DOC,
                &[
                    span("10.03.2019", EntityLabel::DateAdmission),
                    span("24.03.2019", EntityLabel::DateDischarge),
                ],
            )
            .expect("redact");

        let day = |value: &str| -> i64 {
            let mut parts = value.split('.');
            let d: i64 = parts.next().expect("day").parse().expect("day");
            let m: i64 = parts.next().expect("month").parse().expect("month");
            let y: i64 = parts.next().expect("year").parse().expect("year");
            // Howard Hinnant's days_from_civil, the same algorithm L5 uses.
            let y = if m <= 2 { y - 1 } else { y };
            let era = if y >= 0 { y } else { y - 399 } / 400;
            let yoe = y - era * 400;
            let mp = (m + 9) % 12;
            let doy = (153 * mp + 2) / 5 + d - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            era * 146_097 + doe - 719_468
        };

        let admission = &out.spans()[0].replacement;
        let discharge = &out.spans()[1].replacement;
        assert_ne!(admission, "10.03.2019", "the absolute date did not move");
        assert_eq!(
            day(discharge) - day(admission),
            14,
            "the interval did not survive the shift"
        );
        assert_eq!(engine.date_shift_days(), day(admission) - day("10.03.2019"));
    }

    #[test]
    fn date_shift_on_a_non_date_label_falls_back_to_mask_and_says_so() {
        // A misconfigured policy costs readability, never recall. The span is
        // still redacted and the substitution is recorded as a fallback.
        let engine = engine(2);
        let policy = policy(RedactionMethod::DateShift);
        let out = Redactor::new(&policy)
            .with_surrogates(&engine)
            .redact(
                DOC,
                &[
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                    second("Ayşe Yılmaz", EntityLabel::PatientName),
                ],
            )
            .expect("redact");
        assert_eq!(out.spans()[0].requested, RedactionMethod::DateShift);
        assert_eq!(out.spans()[0].applied, RedactionMethod::Mask);
        assert_eq!(out.spans()[0].replacement, "[PATIENT_NAME]");
        assert!(!out.text().contains("Ayşe Yılmaz"));
    }

    #[test]
    fn surrogate_preserves_the_format_and_stays_consistent() {
        let engine = engine(3);
        let policy = RedactionPolicy::default();
        let out = Redactor::new(&policy)
            .with_surrogates(&engine)
            .redact(
                DOC,
                &[
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                    span("TR000000000000000000000000", EntityLabel::Iban),
                    second("Ayşe Yılmaz", EntityLabel::PatientName),
                ],
            )
            .expect("redact");
        let iban = &out.spans()[1].replacement;
        assert!(iban.starts_with("TR"), "the IBAN format was not preserved");
        assert_eq!(
            out.spans()[0].replacement,
            out.spans()[2].replacement,
            "one entity received two surrogates"
        );
        assert!(!out.text().contains("Ayşe Yılmaz"));
    }

    #[test]
    fn a_method_that_needs_an_engine_errors_without_one() {
        for method in [RedactionMethod::Surrogate, RedactionMethod::DateShift] {
            let policy = policy(method);
            // DateShift resolves to Mask on a name, so the date label is used
            // here to reach the branch that actually needs the engine.
            let subject = span("10.03.2019", EntityLabel::DateAdmission);
            assert_eq!(
                Redactor::new(&policy).redact(DOC, &[subject]).map(|_| ()),
                Err(RedactError::SurrogateEngineRequired { method })
            );
        }
    }

    // --- round-trip, and the explicit statement of one-wayness ------------

    #[test]
    fn every_method_round_trips_through_the_map() {
        // The map holds the originals, so it reverses every method including
        // the one-way ones. This is what M2's gateway depends on, and it is
        // also why the map is document-equivalent PHI.
        let engine = engine(4);
        let key = key(5);
        let spans = [
            span("Ayşe Yılmaz", EntityLabel::PatientName),
            span("10.03.2019", EntityLabel::DateAdmission),
            span("TR000000000000000000000000", EntityLabel::Iban),
        ];
        for method in [
            RedactionMethod::Mask,
            RedactionMethod::Redact(Blackout::default()),
            RedactionMethod::Hash,
            RedactionMethod::DateShift,
            RedactionMethod::Surrogate,
            RedactionMethod::Remove,
        ] {
            let policy = policy(method);
            let out = Redactor::new(&policy)
                .with_surrogates(&engine)
                .with_hash_key(&key)
                .redact(DOC, &spans)
                .expect("redact");
            assert_eq!(
                out.reidentify(),
                DOC,
                "{method} did not round-trip through its map"
            );
        }
    }

    #[test]
    fn the_one_way_methods_leave_nothing_recoverable_in_the_output_text() {
        // The other half of the round-trip claim, stated explicitly: Redact,
        // Remove and Hash put nothing in the OUTPUT from which the original can
        // be read back. Only the map reverses them.
        let key = key(6);
        let subjects = [
            span("Ayşe Yılmaz", EntityLabel::PatientName),
            second("Ayşe Yılmaz", EntityLabel::PatientName),
        ];
        for method in [
            RedactionMethod::Redact(Blackout::default()),
            RedactionMethod::Remove,
            RedactionMethod::Hash,
        ] {
            let policy = policy(method);
            let out = Redactor::new(&policy)
                .with_hash_key(&key)
                .redact(DOC, &subjects)
                .expect("redact");
            let text = out.text();
            assert!(!text.contains("Ayşe Yılmaz"), "{method} left the original");
            assert!(!text.contains("Ayşe"), "{method} left part of the original");
            assert!(
                !text.contains("Yılmaz"),
                "{method} left part of the original"
            );
        }
    }

    #[test]
    fn hash_output_carries_no_length_signal() {
        // A digest of a short name and a digest of a long one are the same
        // width, so the token cannot be sorted back onto name lengths.
        let key = key(7);
        let policy = policy(RedactionMethod::Hash);
        let out = Redactor::new(&policy)
            .with_hash_key(&key)
            .redact(
                DOC,
                &[
                    span("Ayşe", EntityLabel::PatientName),
                    span("TR000000000000000000000000", EntityLabel::PatientName),
                ],
            )
            .expect("redact");
        assert_eq!(
            out.spans()[0].replacement.len(),
            out.spans()[1].replacement.len()
        );
    }

    // --- offsets, ordering and refusals -----------------------------------

    #[test]
    fn output_offsets_address_the_replacement_in_the_output_text() {
        let policy = policy(RedactionMethod::Mask);
        let out = Redactor::new(&policy)
            .redact(
                DOC,
                &[
                    span("10.03.2019", EntityLabel::DateAdmission),
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                ],
            )
            .expect("redact");
        for mapped in out.spans() {
            assert_eq!(
                out.text().get(mapped.output_start..mapped.output_end),
                Some(mapped.replacement.as_str())
            );
        }
        // Sorted into document order regardless of input order.
        assert!(out.spans()[0].start < out.spans()[1].start);
    }

    #[test]
    fn a_multibyte_neighbourhood_survives_the_rewrite() {
        // The suffix on the far side of a two-byte `ı` only survives if the
        // rewrite used byte offsets throughout.
        let doc = "Hasta Ayşe'nin dosyası";
        let start = doc.find("Ayşe").expect("fixture");
        let subject = Span::new(
            doc,
            start,
            start + "Ayşe".len(),
            EntityLabel::PatientName,
            DetectorId::Ner(0),
            0.9,
        )
        .expect("valid span");
        let policy = policy(RedactionMethod::Mask);
        let out = Redactor::new(&policy)
            .redact(doc, &[subject])
            .expect("redact");
        assert_eq!(out.text(), "Hasta [PATIENT_NAME]'nin dosyası");
        assert_eq!(out.reidentify(), doc);
    }

    #[test]
    fn overlapping_spans_are_refused_rather_than_silently_resolved() {
        let start = DOC.find("Ayşe Yılmaz").expect("fixture");
        let wide = span("Ayşe Yılmaz", EntityLabel::PatientName);
        let inner = Span::new(
            DOC,
            start,
            start + "Ayşe".len(),
            EntityLabel::PatientName,
            DetectorId::Ner(1),
            0.5,
        )
        .expect("valid span");
        let policy = policy(RedactionMethod::Mask);
        assert!(matches!(
            Redactor::new(&policy).redact(DOC, &[wide, inner]),
            Err(RedactError::OverlappingSpans { .. })
        ));
    }

    #[test]
    fn redacting_nothing_returns_the_document_unchanged() {
        let policy = RedactionPolicy::default();
        let out = Redactor::new(&policy).redact(DOC, &[]).expect("redact");
        assert_eq!(out.text(), DOC);
        assert!(out.spans().is_empty());
        assert_eq!(out.reidentify(), DOC);
    }

    #[test]
    fn debug_never_prints_an_original() {
        // I4. `Redacted` is what a binding hands back, so it is the value most
        // likely to reach a `{:?}`, a failing assertion or a panic message.
        let policy = policy(RedactionMethod::Mask);
        let out = Redactor::new(&policy)
            .redact(
                DOC,
                &[
                    span("Ayşe Yılmaz", EntityLabel::PatientName),
                    second("Ayşe Yılmaz", EntityLabel::PatientName),
                ],
            )
            .expect("redact");
        let rendered = format!("{out:?}");
        assert!(!rendered.contains("Ayşe Yılmaz"));
        assert!(rendered.contains("<redacted>"));
        // The de-identified text and the mask stay visible, or the value is
        // not debuggable at all.
        assert!(rendered.contains("PATIENT_NAME"));
        assert_eq!(out.spans()[0].original(), "Ayşe Yılmaz");
    }

    #[test]
    fn an_error_never_carries_document_text() {
        let rendered = format!(
            "{} {} {}",
            RedactError::HashKeyRequired,
            RedactError::SurrogateEngineRequired {
                method: RedactionMethod::Surrogate
            },
            RedactError::SpanOutOfBounds {
                offset: 400,
                doc_len: 12
            }
        );
        assert!(!rendered.contains("Ayşe"));
        assert!(rendered.contains("surrogate"));
    }
}
