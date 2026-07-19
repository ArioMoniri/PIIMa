//! The span map: the round-trip table, and the reason it is dangerous.
//!
//! WHAT IT IS FOR. The MCP gateway sends de-identified text to a model and gets
//! de-identified text back. To hand the clinician an answer about THEIR
//! patient, it has to put the originals back, so something has to remember that
//! `Kerem Yavuz` stood where `Ayşe Yılmaz` stands. That table is this type.
//!
//! WHAT IT IS. The only structure in the pipeline that holds original PHI text
//! in memory ALONGSIDE its offsets and its replacement. The audit log
//! deliberately does not, errors deliberately do not, and `Span` deliberately
//! stores a hash instead. This one has to, because re-identification is
//! impossible otherwise, and pretending otherwise would mean an L5 that cannot
//! do its job.
//!
//! THE RULES THAT FOLLOW FROM THAT. It is local, it never leaves the device, it
//! is never logged, never persisted by this crate, and never serialised by
//! anything in `core/`. Its `Debug` is hand-written so that the originals
//! cannot escape through a `{:?}`, a failing `assert_eq!` or a panic message --
//! the same construction, for the same reason, as `AuditEntry`'s (D-013, I4).
//! A binding that needs to persist a map is holding a document-equivalent
//! secret and must protect it as one.

use core::fmt;

use crate::label::EntityLabel;

/// What a `Debug` rendering prints where an original would be.
const REDACTED: &str = "<redacted>";

/// One original entity and the surrogate that replaced it.
#[derive(Clone, PartialEq, Eq)]
pub struct SurrogateEntry {
    /// The schema label, which chose the format.
    pub label: EntityLabel,
    /// Inclusive byte offset in the ORIGINAL document.
    pub start: usize,
    /// Exclusive byte offset in the ORIGINAL document.
    pub end: usize,
    /// Inclusive byte offset in the DE-IDENTIFIED document.
    ///
    /// Not derivable from `start`: a surrogate deliberately does not preserve
    /// the original's length, so every replacement shifts everything after it.
    pub output_start: usize,
    /// Exclusive byte offset in the DE-IDENTIFIED document.
    pub output_end: usize,
    /// THE PHI. Private, and readable only through [`SurrogateEntry::original`],
    /// so that every read is a place a reviewer can point at.
    original: String,
    /// The fake text that replaced it. Not PHI, and left visible in `Debug`,
    /// because a redacted surrogate would make the map unreadable while
    /// protecting nothing.
    surrogate: String,
}

/// Hand-written so `{:?}` can never egress an original.
///
/// The offsets, the label and the surrogate stay visible: they are what makes
/// the map debuggable, and none of them is the identifier. The original renders
/// as the literal `<redacted>` unconditionally, so the rendering does not vary
/// with its content or its length either -- a `Debug` that printed
/// `original: 11 bytes` would leak the length tell that the rest of L5 exists
/// to destroy.
impl fmt::Debug for SurrogateEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SurrogateEntry")
            .field("label", &self.label)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("output_start", &self.output_start)
            .field("output_end", &self.output_end)
            .field("original", &format_args!("{REDACTED}"))
            .field("surrogate", &self.surrogate)
            .finish()
    }
}

impl SurrogateEntry {
    pub(super) fn new(
        label: EntityLabel,
        start: usize,
        end: usize,
        output_start: usize,
        output_end: usize,
        original: String,
        surrogate: String,
    ) -> Self {
        Self {
            label,
            start,
            end,
            output_start,
            output_end,
            original,
            surrogate,
        }
    }

    /// The original text. PHI: never log the return value.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// The surrogate that replaced it.
    #[must_use]
    pub fn surrogate(&self) -> &str {
        &self.surrogate
    }
}

/// The round-trip table for one document.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SpanMap {
    entries: Vec<SurrogateEntry>,
}

/// Hand-written for the same reason as [`SurrogateEntry`]'s, and not left to
/// the derive even though the derive would delegate correctly today: the
/// guarantee has to survive someone adding a field to this struct later. That
/// is exactly how `AuditLog` justifies its own hand-written impl.
impl fmt::Debug for SpanMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanMap")
            .field("entries", &self.entries)
            .finish()
    }
}

impl SpanMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn push(&mut self, entry: SurrogateEntry) {
        self.entries.push(entry);
    }

    /// Every substitution, in document order.
    #[must_use]
    pub fn entries(&self) -> &[SurrogateEntry] {
        &self.entries
    }

    /// How many spans were replaced.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing was replaced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Put the originals back into text that came out of a model.
    ///
    /// THE RETURN VALUE IS PHI. This is the gateway's inbound path: the model
    /// saw only surrogates, and its answer quotes them, so restoring the
    /// originals is what makes the answer about the actual patient.
    ///
    /// LONGEST SURROGATE FIRST, and the ordering is load-bearing. Two
    /// surrogates can be prefixes of one another -- `Kerem` and
    /// `Kerem Yavuz` -- and replacing the shorter one first would rewrite the
    /// first half of the longer and leave an orphaned tail. Sorting by
    /// descending length makes the longest match win, which is the same
    /// discipline `union_widest` applies to overlapping spans.
    #[must_use]
    pub fn reidentify(&self, model_output: &str) -> String {
        let mut ordered: Vec<&SurrogateEntry> = self.entries.iter().collect();
        ordered.sort_by(|a, b| {
            b.surrogate
                .len()
                .cmp(&a.surrogate.len())
                .then_with(|| a.surrogate.cmp(&b.surrogate))
        });
        let mut text = model_output.to_owned();
        for entry in ordered {
            if entry.surrogate.is_empty() {
                continue;
            }
            text = text.replace(&entry.surrogate, &entry.original);
        }
        text
    }
}
