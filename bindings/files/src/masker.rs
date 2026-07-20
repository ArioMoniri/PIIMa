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

use core::fmt;

use deid_tr_core::{Decision, Pipeline};

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
pub struct Masker<'a> {
    pipeline: &'a Pipeline,
}

impl<'a> Masker<'a> {
    /// Wrap a configured pipeline.
    #[must_use]
    pub const fn new(pipeline: &'a Pipeline) -> Self {
        Self { pipeline }
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
        let originals = result
            .span_map
            .iter()
            .filter(|mapped| mapped.decision == Decision::Mask)
            .map(|mapped| mapped.original().to_owned())
            .collect();
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
#[derive(Clone, PartialEq, Eq)]
pub struct Replacement {
    /// Inclusive byte offset into the string that was masked.
    pub start: usize,
    /// Exclusive byte offset into the string that was masked.
    pub end: usize,
    /// What to put there.
    pub replacement: String,
    /// What was there. PHI.
    pub original: String,
}

/// Hand-written: `original` is an identifier (I4).
impl fmt::Debug for Replacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replacement")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("replacement", &self.replacement)
            .field("original", &format_args!("<redacted>"))
            .finish()
    }
}

/// What a run of [`crate::mask_file`] did, in counts only.
///
/// SAFE TO PRINT, which is the point: the CLI needs to tell an operator that
/// something happened, and `Masked` is not printable. Every field here is a
/// number or a fixed string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
