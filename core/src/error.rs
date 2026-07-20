//! Crate error type.

use crate::label::EntityLabel;
use crate::span::Layer;

/// Result alias for every fallible operation in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong inside the pure core.
///
/// THE ONE RULE THIS ENUM EXISTS TO ENFORCE (invariant I4): no variant may
/// carry document text, a span's covered text, an LLM rationale, or any other
/// input-derived string. Variants carry offsets, lengths, labels, layers and
/// confidences -- never content.
///
/// The reason is the lifecycle of an error message, not aesthetics. An error
/// reaches stderr, stderr reaches a log file, the log file reaches a log
/// aggregator, and someone eventually pastes the whole thing into a bug
/// report. Every one of those hops is outside the device boundary that I1
/// promises PHI will never cross. `MaskFailed { text: "Ayşe Yılmaz" }` is a
/// breach with a `#[derive(Debug)]` on it.
///
/// A span's offsets are useless to an attacker who does not already hold the
/// document; the covered text is the identifier itself. That asymmetry is why
/// offsets are allowed here and text never is. When a new variant needs to
/// explain *what* was wrong with a string, it carries the string's length.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A span must cover at least one byte and must not be inverted.
    #[error("span start {start} is not strictly before end {end}")]
    SpanNotOrdered { start: usize, end: usize },

    /// A span offset points past the end of the document it was built against.
    #[error("span offset {offset} lies outside a document of {doc_len} bytes")]
    SpanOutOfBounds { offset: usize, doc_len: usize },

    /// A span offset splits a multi-byte character.
    ///
    /// This is the failure the type exists to make impossible. Turkish is
    /// multi-byte UTF-8 (`ş`, `ğ`, `İ` are two bytes each), and a tokenizer or
    /// an LLM that reports char indices as byte offsets produces spans that
    /// start halfway through a letter. Such a span masks the wrong bytes and
    /// corrupts the surrounding text on re-assembly.
    #[error("span offset {offset} does not land on a UTF-8 character boundary of a {doc_len}-byte document")]
    SpanNotCharBoundary { offset: usize, doc_len: usize },

    /// Confidence must be a finite probability.
    #[error("confidence {confidence} is not a finite value in 0.0..=1.0")]
    ConfidenceOutOfRange { confidence: f32 },

    /// Two spans that do not overlap cannot be unioned into one.
    #[error("cannot union disjoint spans {left_start}..{left_end} and {right_start}..{right_end}")]
    DisjointUnion {
        left_start: usize,
        left_end: usize,
        right_start: usize,
        right_end: usize,
    },

    /// L4 attempted to demote a span it is forbidden to touch.
    ///
    /// Loud failure rather than a silent no-op is deliberate: a silently
    /// ignored demotion means the adjudicator believes it kept a span it did
    /// not keep, and that disagreement is exactly how a guardrail rots.
    #[error("refused to demote protected span {start}..{end} labelled {label} from layer {layer}")]
    ProtectedSpanDemotion {
        start: usize,
        end: usize,
        label: EntityLabel,
        layer: Layer,
    },

    /// A rationale was attached to an audit entry from a layer that may not
    /// produce one. Only L3 explains itself.
    #[error("layer {layer} may not attach a rationale to an audit entry")]
    RationaleNotPermitted { layer: Layer },

    /// The Expert Determination tier was selected without an L3 implementation.
    ///
    /// Degrading silently to Safe Harbor would be the worst possible outcome:
    /// the caller believes quasi-identifiers were swept and they were not.
    #[error("the Expert Determination tier requires a contextual (L3) layer, none configured")]
    ContextualLayerMissing,

    /// The L3 model returned something that is not the requested JSON.
    ///
    /// Carries a classification, a byte position and a length -- never the
    /// response itself. A model asked to quote quasi-identifiers verbatim
    /// answers with the patient's employer in the very first field, so its
    /// output is treated as document-derived content and is never quoted back
    /// into an error, a log or a panic (I4). The position is enough to find the
    /// defect while holding the response in memory, and useless without it.
    #[error("the contextual model response was malformed ({defect}) at byte {byte_offset} of {response_len} bytes")]
    MalformedContextualResponse {
        defect: ResponseDefect,
        byte_offset: usize,
        response_len: usize,
    },

    /// The local L3 runtime could not produce a response at all.
    ///
    /// Distinct from a malformed response because the remedies are different:
    /// this is a host problem (no runtime, no weights, a failed launch), while
    /// a malformed response is a model problem. The variant carries a
    /// classification only -- a runtime's stderr routinely echoes the prompt it
    /// was given, and the prompt contains the whole document.
    #[error("the local contextual model could not run ({kind})")]
    LocalModelFailed { kind: ModelFailure },

    /// A label id did not match any variant of [`EntityLabel`].
    ///
    /// Only the length of the offending id is reported. The id can arrive from
    /// an L3 model's JSON, and a model that hallucinates a label field can
    /// hallucinate the patient's name into it -- so the unknown id is treated
    /// as untrusted document-derived content, not as a config key.
    #[error("unknown entity label id of {id_len} bytes")]
    UnknownEntityLabel { id_len: usize },

    /// The L2 ensemble is configured but no tokenizer was installed.
    ///
    /// The same argument as [`Error::ContextualLayerMissing`], one layer down.
    /// `core/` cannot tokenize -- a vocabulary is a file and this crate performs
    /// no I/O (I1) -- so the tokenizer arrives from a binding. An ensemble that
    /// silently proposed nothing because nothing could turn the document into
    /// ids would hand back a document that looks de-identified by L2 and was
    /// never seen by it, which is the failure mode I2 cares about most.
    #[error("the detector ensemble requires a tokenizer, none configured")]
    TokenizerMissing,

    /// L2 refused the tokenization or the logits it was given.
    ///
    /// Carries a CLASSIFICATION and nothing else, for the reason the rest of
    /// this enum carries offsets: [`crate::detect::NerError`] is layer-local and
    /// keeps its numeric detail for the caller that can act on it, while the
    /// crate-wide error that escapes into a binding's log says only what kind of
    /// contract was violated.
    #[error("the detector ensemble failed ({kind})")]
    DetectionFailed { kind: DetectionFailure },

    /// L5 could not produce a surrogate for a masked span.
    #[error("surrogate assignment failed ({kind})")]
    SurrogateFailed { kind: SurrogateFailure },

    /// The configured redaction policy named a method the pipeline is not
    /// equipped for.
    ///
    /// An error rather than a fallback, for the reason
    /// [`crate::redact::RedactError::HashKeyRequired`] gives: quietly applying
    /// a different method than the policy names produces plausible output that
    /// no audit can catch.
    #[error("redaction failed ({kind})")]
    RedactionFailed { kind: RedactionFailure },
}

/// Why a redaction method could not be applied.
///
/// A closed vocabulary, so no document-derived string reaches a log through
/// this path (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedactionFailure {
    /// The policy selected `Hash` and no key was installed.
    HashKeyRequired,
    /// The policy selected `Surrogate` or `DateShift` and no L5 engine was
    /// installed.
    SurrogateEngineRequired,
    /// The caller's hash key material was below the accepted width.
    HashKeyTooShort,
    /// A blackout shape the redactor refuses to build.
    BlackoutRejected,
}

impl core::fmt::Display for RedactionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::HashKeyRequired => "hash key required",
            Self::SurrogateEngineRequired => "surrogate engine required",
            Self::HashKeyTooShort => "hash key material too short",
            Self::BlackoutRejected => "blackout shape rejected",
        })
    }
}

/// Why L2 could not turn a detector's output into spans.
///
/// A closed vocabulary, so no document-derived string can reach a log through
/// this path (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DetectionFailure {
    /// A detector returned a different number of logit rows than there were
    /// tokens.
    LogitRowCount,
    /// A logit row was a different width than the label set.
    LogitWidth,
    /// A logit was NaN or infinite.
    NonFiniteLogit,
    /// The tokenizer's ids and offsets had different lengths.
    TokenSpanCount,
    /// A token offset did not align to the normalised text.
    TokenSpanNotAligned,
    /// More ensemble members than a `DetectorId` can distinguish.
    TooManyDetectors,
}

impl core::fmt::Display for DetectionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::LogitRowCount => "logit row count",
            Self::LogitWidth => "logit width",
            Self::NonFiniteLogit => "non-finite logit",
            Self::TokenSpanCount => "token span count",
            Self::TokenSpanNotAligned => "token span not aligned",
            Self::TooManyDetectors => "too many detectors",
        })
    }
}

/// Why L5 could not mint a surrogate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SurrogateFailure {
    /// The caller's key material was below the accepted width.
    KeyMaterialTooShort,
    /// Two spans handed to L5 covered the same bytes. Unreachable through the
    /// pipeline, whose spans come out of `union_widest` non-overlapping.
    OverlappingSpans,
    /// A closed-vocabulary pool ran out of distinct replacements.
    PoolExhausted,
}

impl core::fmt::Display for SurrogateFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::KeyMaterialTooShort => "key material too short",
            Self::OverlappingSpans => "overlapping spans",
            Self::PoolExhausted => "surrogate pool exhausted",
        })
    }
}

/// What was wrong with an L3 model response.
///
/// A closed vocabulary rather than a message, for the same reason the rest of
/// this enum carries offsets: a free-text explanation of a malformed response
/// is written by quoting the response, and the response quotes the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResponseDefect {
    /// No JSON array could be located anywhere in the response.
    NoArrayFound,
    /// A value started but the response ended before it closed.
    Truncated,
    /// A byte appeared where no JSON value may begin.
    UnexpectedByte,
    /// Nesting exceeded the parser's fixed depth budget.
    TooDeeplyNested,
    /// The array held more items than the sweep will consider.
    TooManyItems,
    /// An element of the findings array was not an object.
    ItemNotAnObject,
    /// The required `quote` field was absent or was not a string.
    MissingQuote,
    /// The `quote` field was present but empty, so it can anchor nothing.
    EmptyQuote,
    /// The required `category` field was absent or was not a string.
    MissingCategory,
    /// The `category` field named something outside [`crate::QuasiCategory`].
    UnknownCategory,
    /// The required `reason` field was absent or was not a string.
    MissingReason,
    /// A string contained an escape sequence that is not valid JSON.
    BadEscape,
}

impl core::fmt::Display for ResponseDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NoArrayFound => "no JSON array found",
            Self::Truncated => "truncated",
            Self::UnexpectedByte => "unexpected byte",
            Self::TooDeeplyNested => "too deeply nested",
            Self::TooManyItems => "too many items",
            Self::ItemNotAnObject => "item is not an object",
            Self::MissingQuote => "missing quote field",
            Self::EmptyQuote => "empty quote field",
            Self::MissingCategory => "missing category field",
            Self::UnknownCategory => "unknown category",
            Self::MissingReason => "missing reason field",
            Self::BadEscape => "bad string escape",
        })
    }
}

/// Why the local L3 runtime produced nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ModelFailure {
    /// The runtime executable was not found or is not a file.
    RuntimeMissing,
    /// The weights file was not found or is not a file.
    WeightsMissing,
    /// The runtime could not be started.
    LaunchFailed,
    /// The runtime started and exited with a failure status.
    ExitedWithError,
    /// The prompt could not be handed to the runtime.
    PromptNotDelivered,
    /// The runtime produced no output on the channel we read.
    EmptyOutput,
    /// The runtime's output was not valid UTF-8.
    OutputNotUtf8,
}

impl core::fmt::Display for ModelFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::RuntimeMissing => "local runtime missing",
            Self::WeightsMissing => "weights missing",
            Self::LaunchFailed => "launch failed",
            Self::ExitedWithError => "exited with error",
            Self::PromptNotDelivered => "prompt not delivered",
            Self::EmptyOutput => "empty output",
            Self::OutputNotUtf8 => "output not utf-8",
        })
    }
}
