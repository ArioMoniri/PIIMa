//! The one place this crate calls the pipeline, and the one place it holds an
//! identifier.
//!
//! Every format module funnels through [`Masker::mask`] so that there is a
//! single answer to "what did we take out of this document?". That answer is
//! needed twice: once to rewrite the container, and once by
//! [`crate::pdf::verify`], which has to know what string to hunt for in the
//! output bytes.
//!
//! # The originals are PHI
//!
//! [`Masked::originals`] holds patient identifiers verbatim. It exists only
//! inside one call, is never written to disk, never logged, never placed in an
//! error, and has a hand-written [`fmt::Debug`] for the same reason
//! `DeidResult`'s does (I4). A `{:?}` on a verification failure is exactly the
//! kind of accident that puts a TCKN in a bug report.
//!
//! # HONEST SCOPE
//!
//! `Pipeline::new` installs an EMPTY L2 ensemble, so this crate masks the
//! identifiers `core/src/rules/` can prove -- TCKN, VKN, IBAN, phone, email,
//! MRN, date -- and NOTHING ELSE. Person names, institution names and every
//! contextual quasi-identifier survive. That is stated in the CLI help, in the
//! module docs of every format, and in [`Report::rule_detectable_only`],
//! because a user who believes a redacted file is name-free is worse off than
//! a user who has no tool.

use core::cell::RefCell;
use core::fmt;

use deid_tr_core::{Decision, Pipeline};

/// One span the pipeline masked, described WITHOUT the text it covered.
///
/// This is the span map a surface can show. Every field is a count, a label, a
/// classification or a synthetic replacement, so the whole struct is safe to
/// print, serialise and hand across a language boundary (I4). The identifier
/// itself stays in [`Masked::originals`], which never leaves the call it was
/// produced in.
///
/// `byte_len` is the length of what was removed, not what was removed. It is
/// carried because a reviewer reading a span map needs to know whether an
/// 11-byte or a 40-byte thing left the document, and a length is not an
/// identifier.
#[derive(Debug, Clone, PartialEq)]
pub struct SpanRecord {
    /// The schema label, e.g. `TCKN`, `PHONE`, `EMAIL`.
    pub label: String,
    /// Which layer proposed the span: `rules`, `ner` or `context`.
    pub layer: String,
    /// Length in bytes of the text that was removed.
    pub byte_len: usize,
    /// Confidence at the point of decision.
    pub confidence: f32,
    /// True when an arithmetic check actually passed on the covered bytes.
    pub checksum_validated: bool,
    /// What was put in its place. Synthetic by construction, so not PHI.
    pub replacement: String,
}

// NO `Eq`, HERE OR ANYWHERE THAT CARRIES ONE OF THESE. `confidence` is an
// `f32`, and `Eq` promises a reflexive equality that floating point does not
// have. `Report` and `Output` therefore lost their `Eq` derive when they gained
// span records; nothing in the workspace used it, and a struct that quietly
// claims total equality over a float is the kind of thing that later becomes a
// `HashMap` key.

/// One de-identified string, plus what was removed from it.
#[derive(Clone, PartialEq, Eq)]
pub struct Masked {
    /// The rewritten text.
    pub text: String,
    /// The original text of every span that was masked. PHI.
    pub originals: Vec<String>,
}

/// Hand-written: the whole struct is an identifier list (I4).
impl fmt::Debug for Masked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Masked")
            .field("text", &self.text)
            .field(
                "originals",
                &format_args!("<{} redacted>", self.originals.len()),
            )
            .finish()
    }
}

impl Masked {
    /// A string nothing was found in.
    #[must_use]
    pub fn unchanged(text: String) -> Self {
        Self {
            text,
            originals: Vec::new(),
        }
    }

    /// True when the pipeline removed something.
    #[must_use]
    pub fn is_changed(&self) -> bool {
        !self.originals.is_empty()
    }
}

/// The pipeline, wrapped so a format module cannot reach anything else on it.
///
/// # The span recorder
///
/// A container format destroys offsets. A TCKN in a `.docx` lives at some byte
/// range of a joined scan buffer that exists for the duration of one function
/// call; a TCKN in a PDF lives at a range of a decoded content stream. Neither
/// number means anything to a caller holding the original file, so the span map
/// a surface can honestly show is a list of WHAT was removed, not WHERE.
///
/// That list is accumulated here rather than threaded through six format
/// modules, so it cannot drift from what the pipeline actually decided: the
/// records come from the same `span_map` iteration that produces
/// [`Masked::originals`].
///
/// [`Masker::mask`] records automatically, because every one of its callers
/// commits every span it returns. [`Masker::replacements`] does NOT, because
/// [`crate::pdf::redact`] reads each page TWICE (see its two-view loop) and
/// discards the duplicate hits -- auto-recording there would report an
/// identifier found twice as two identifiers. Those callers call
/// [`Masker::record`] at the point they commit, which is the only point at
/// which the truth is known.
pub struct Masker<'a> {
    pipeline: &'a Pipeline,
    /// `RefCell` rather than `&mut self`: every format module holds `&Masker`,
    /// and threading mutability through them would be a refactor of the whole
    /// crate to gain nothing. It costs `Sync`, which `Pipeline` does not have
    /// either -- it holds boxed trait objects -- so nothing is lost.
    records: RefCell<Vec<SpanRecord>>,
}

impl<'a> Masker<'a> {
    /// Wrap a configured pipeline.
    #[must_use]
    pub const fn new(pipeline: &'a Pipeline) -> Self {
        Self {
            pipeline,
            records: RefCell::new(Vec::new()),
        }
    }

    /// Every span recorded so far, in the order the formats presented text.
    #[must_use]
    pub fn records(&self) -> Vec<SpanRecord> {
        self.records.borrow().clone()
    }

    /// Take the records and reset the recorder.
    ///
    /// DRAINING RATHER THAN COPYING is what makes a reused `Masker` correct.
    /// The CLI masks a whole directory with one of these, so a span map built
    /// from [`Masker::records`] would grow monotonically and report file three
    /// as carrying everything files one and two contained.
    #[must_use]
    pub fn take_records(&self) -> Vec<SpanRecord> {
        core::mem::take(&mut *self.records.borrow_mut())
    }

    /// Record a replacement a caller has decided to commit.
    ///
    /// See the type docs for why [`Masker::replacements`] does not do this
    /// itself.
    pub fn record(&self, edit: &Replacement) {
        self.records.borrow_mut().push(SpanRecord {
            label: edit.label.clone(),
            layer: edit.layer.clone(),
            byte_len: edit.end.saturating_sub(edit.start),
            confidence: edit.confidence,
            checksum_validated: edit.checksum_validated,
            replacement: edit.replacement.clone(),
        });
    }

    /// De-identify one string.
    ///
    /// # Errors
    ///
    /// Whatever the pipeline returns.
    pub fn mask(&self, text: &str) -> Result<Masked, deid_tr_core::Error> {
        if text.is_empty() {
            return Ok(Masked::unchanged(String::new()));
        }
        let result = self.pipeline.deidentify(text)?;
        let mut originals = Vec::new();
        let mut records = self.records.borrow_mut();
        for mapped in result
            .span_map
            .iter()
            .filter(|mapped| mapped.decision == Decision::Mask)
        {
            originals.push(mapped.original().to_owned());
            records.push(SpanRecord {
                label: mapped.span.label().to_string(),
                layer: mapped.span.source().to_string(),
                byte_len: mapped.span.byte_len(),
                confidence: mapped.span.confidence(),
                checksum_validated: mapped.span.is_checksum_validated(),
                replacement: mapped.replacement.clone().unwrap_or_default(),
            });
        }
        Ok(Masked {
            text: result.text,
            originals,
        })
    }

    /// De-identify one string, returned as EDITS against it rather than as a
    /// rewritten string.
    ///
    /// Ordered by `start`, non-overlapping, because that is what the pipeline's
    /// own merge guarantees and what an applier needs to walk backwards safely.
    ///
    /// # Errors
    ///
    /// Whatever the pipeline returns.
    pub fn replacements(&self, text: &str) -> Result<Vec<Replacement>, deid_tr_core::Error> {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let result = self.pipeline.deidentify(text)?;
        Ok(result
            .span_map
            .iter()
            .filter(|mapped| mapped.decision == Decision::Mask)
            .map(|mapped| Replacement {
                start: mapped.span.start(),
                end: mapped.span.end(),
                replacement: mapped.replacement.clone().unwrap_or_default(),
                original: mapped.original().to_owned(),
                label: mapped.span.label().to_string(),
                layer: mapped.span.source().to_string(),
                confidence: mapped.span.confidence(),
                checksum_validated: mapped.span.is_checksum_validated(),
            })
            .collect())
    }
}

/// One span the pipeline decided to remove, as an edit against the input.
///
/// Returned by [`Masker::replacements`] for callers that cannot use the
/// rewritten string directly -- a `.docx` paragraph split across runs, or a PDF
/// content stream where the "text" is a decoded view of glyph codes. Both have
/// to apply the edit to a DIFFERENT buffer than the one the pipeline saw, so
/// they need the offsets rather than the result.
#[derive(Clone, PartialEq)]
pub struct Replacement {
    /// Inclusive byte offset into the string that was masked.
    pub start: usize,
    /// Exclusive byte offset into the string that was masked.
    pub end: usize,
    /// What to put there.
    pub replacement: String,
    /// What was there. PHI.
    pub original: String,
    /// The schema label, carried so a committing caller can [`Masker::record`]
    /// the span without re-deriving anything.
    pub label: String,
    /// Which layer proposed it.
    pub layer: String,
    /// Confidence at the point of decision.
    pub confidence: f32,
    /// True when an arithmetic check passed on the covered bytes.
    pub checksum_validated: bool,
}

/// Hand-written: `original` is an identifier (I4).
impl fmt::Debug for Replacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replacement")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("replacement", &self.replacement)
            .field("original", &format_args!("<redacted>"))
            .field("label", &self.label)
            .field("layer", &self.layer)
            .finish()
    }
}

/// What a run of [`crate::mask_file`] did, in counts only.
///
/// SAFE TO PRINT, which is the point: the CLI needs to tell an operator that
/// something happened, and `Masked` is not printable. Every field here is a
/// number or a fixed string.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    /// The format that was detected.
    pub format: &'static str,
    /// How many spans were removed across the whole document.
    pub masked: usize,
    /// How many discrete locations were rewritten -- pages, records, parts.
    pub locations: usize,
    /// Structures removed wholesale rather than rewritten, by name.
    ///
    /// Structural names only (`/Info`, `word/footer1.xml`), never content.
    pub stripped: Vec<String>,
    /// One entry per page or per package part, with what was removed from it.
    ///
    /// STRUCTURAL NAMES ONLY: `page 3`, `word/document.xml`, `document`. A
    /// surface shows this so a reviewer can see that page 4 of a 6-page scan
    /// yielded nothing, which is the difference between "clean" and "not read".
    pub parts: Vec<PartSummary>,
    /// The span map: what was removed, never where or what it said.
    pub spans: Vec<SpanRecord>,
    /// Pages carrying images whose pixels were NOT read.
    ///
    /// EMPTY IS THE ONLY REASSURING VALUE HERE, and it is the only one a
    /// surface may present quietly. A non-empty list means part of the document
    /// went through untouched and unexamined, which no count of masked spans
    /// discloses. See [`Report::images_not_read`] for the sentence that goes
    /// with it, and `crate::pdf::ImagePolicy` for why reaching this state at
    /// all takes an explicit override.
    pub images: Vec<crate::pdf::PageImages>,
}

/// What one page or one package part contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartSummary {
    /// A structural name: `page 1`, `word/footer1.xml`, `document`.
    pub name: String,
    /// How many spans were removed from it.
    pub masked: usize,
}

impl Report {
    /// The sentence every surface must show next to a result.
    ///
    /// A constant rather than prose each caller writes, so it cannot drift into
    /// something more reassuring than the tool has earned.
    pub const fn rule_detectable_only() -> &'static str {
        "deid-tr masks rule-detectable identifiers only (TCKN, VKN, IBAN, phone, \
         email, MRN, date). It does NOT mask person names, institution names or \
         contextual quasi-identifiers: no trained model is installed. Do not treat \
         the output as name-free."
    }

    /// The sentence every surface must show when [`Report::images`] is not
    /// empty.
    ///
    /// A constant for the same reason as the one above: three surfaces
    /// describing the same gap in three tones is how one of them ends up
    /// sounding like a footnote. The per-page detail -- page number, count,
    /// dimensions -- comes from `Display` on each `crate::pdf::PageImages`, and
    /// this is the sentence that says what the list means.
    pub const fn images_not_read() -> &'static str {
        "This document contains images and deid-tr did not read them. It redacts text and \
         never touches pixels, so anything drawn into an image -- a QR or barcode carrying a \
         protokol or patient number, a signature, a stamped name -- survives byte-identical \
         into the output. This file is NOT fully de-identified. Have a human look at the \
         pages listed below before it leaves the building."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::Tier;

    #[test]
    fn masking_removes_a_checksum_valid_tckn_and_reports_the_original() {
        let tckn = crate::testing::tckn();
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let masker = Masker::new(&pipeline);
        let masked = masker.mask(&format!("TCKN {tckn} kayıtlı.")).expect("mask");
        assert!(!masked.text.contains(&tckn));
        assert_eq!(masked.originals, vec![tckn]);
        assert!(masked.is_changed());
    }

    #[test]
    fn a_name_is_not_masked_and_the_report_says_so() {
        // THE HONESTY TEST. L2 has no trained model, so `Ayşe Yılmaz` survives.
        // If this test ever starts failing because a name IS masked, the
        // disclosure text below has to change with it -- that is why the two
        // assertions live in one test.
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let masked = Masker::new(&pipeline)
            .mask("Hasta Ayşe Yılmaz muayene edildi.")
            .expect("mask");
        assert!(masked.text.contains("Ayşe Yılmaz"));
        assert!(!masked.is_changed());
        assert!(Report::rule_detectable_only().contains("does NOT mask person names"));
    }

    #[test]
    fn debug_on_a_masked_string_never_prints_an_original() {
        // I8: built at runtime rather than written as a literal. The same number
        // spelled out here would be checksum-VALID, which the pre-commit PHI
        // scan refuses -- correctly, because a committed checksum-valid TCKN is
        // indistinguishable from a real one to every tool that reads this repo.
        let tckn = crate::testing::tckn();
        let masked = Masked {
            text: "[TCKN]".to_owned(),
            originals: vec![tckn.clone()],
        };
        let rendered = format!("{masked:?}");
        assert!(!rendered.contains(&tckn));
        assert!(rendered.contains("<1 redacted>"));
    }
}
