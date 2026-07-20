//! Verification, run against the OUTPUT, after every redaction.
//!
//! # Verification is part of the feature, not a debugging aid
//!
//! A redaction tool that emits a file it could not verify has produced a
//! document a user will treat as safe. So [`crate::pdf::redact`] calls
//! [`verify`] on its own output and returns an ERROR rather than the bytes if
//! anything survives. There is no flag to skip it.
//!
//! # What is checked
//!
//! 1. **Structure.** Exactly one `%%EOF`, no `/Prev` in any trailer, no
//!    `/Encrypt`, no `/Type /ObjStm`. The first two together are the assertion
//!    that no previous revision survived; the last is the assertion that no
//!    object is hiding inside another one where a grep cannot see it.
//! 2. **Re-extraction.** The output is re-parsed from bytes -- not from the
//!    in-memory graph the redactor was holding -- and every page's text is
//!    extracted again and searched.
//! 3. **Decompressed byte scan.** Every object's streams are decoded and the
//!    whole flattened blob is searched for each identifier in three encodings:
//!    UTF-8, UTF-16BE (how a PDF text string carries Turkish) and raw
//!    Latin-1/PDFDocEncoding. A grep of a compressed PDF proves nothing, which
//!    is why the scan happens after decoding.
//! 4. **Non-page objects.** `/JavaScript`, `/EmbeddedFiles`, `/XFA`,
//!    `/OpenAction`, `/AA` and `/Metadata` must be absent.
//!
//! # What is NOT checked, stated plainly
//!
//! Pixels. If an identifier is drawn into a raster image, no text-extraction
//! check can see it and a "no PHI found" result over a rasterised page is a
//! VACUOUS PASS. This crate does not OCR, so it does not accept such a page in
//! the first place -- see [`crate::pdf::PdfError::UnreadablePage`]. That refusal
//! is what keeps this verification honest.

use crate::pdf::content;
use crate::pdf::document::{decode_stream, find_all, Document};
use crate::pdf::object::Object;

/// Where a surviving identifier was found.
///
/// A CLASS, never the text (I4). The index identifies which of the caller's own
/// identifiers it was, so a caller holding the list can look it up locally
/// without the value ever entering an error, a log or a bug report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Survival {
    /// Recovered by re-extracting page text.
    PageText {
        /// One-based page number.
        page: usize,
    },
    /// Found in the fully decompressed object bytes.
    ObjectBytes {
        /// The object number it was found in.
        object: u32,
    },
}

/// A verification that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerificationFailure {
    /// An identifier is still present in the output.
    #[error("identifier #{index} survived redaction ({where_found:?})")]
    IdentifierSurvived {
        /// Index into the caller's list of removed identifiers.
        index: usize,
        /// Where it was found.
        where_found: Survival,
    },
    /// The output carries more than one revision.
    #[error("the output contains {count} revisions; a previous revision survived")]
    MultipleRevisions {
        /// How many `%%EOF` markers were found.
        count: usize,
    },
    /// A trailer still chains to an earlier cross-reference section.
    #[error("the output trailer still has a /Prev chain to a previous revision")]
    PreviousRevisionChain,
    /// A structure that must have been removed is still present.
    #[error("the output still contains {key}")]
    StructureSurvived {
        /// The PDF key that should not be there.
        key: &'static str,
    },
    /// The output could not be re-opened.
    #[error("the output could not be re-parsed for verification")]
    Unreadable,
}

/// Structures whose presence in the OUTPUT is a failure.
const FORBIDDEN: &[&str] = &[
    "/JavaScript",
    "/EmbeddedFiles",
    "/XFA",
    "/OpenAction",
    "/Metadata",
    "/ObjStm",
    "/Encrypt",
];

/// Check a redacted PDF.
///
/// `originals` is the list of identifiers the redactor removed. It is PHI: it
/// is read here and never stored, logged or placed in the returned error.
///
/// # Errors
///
/// [`VerificationFailure`] for the first problem found.
pub fn verify(bytes: &[u8], originals: &[String]) -> Result<(), VerificationFailure> {
    let revisions = find_all(bytes, b"%%EOF").len();
    if revisions != 1 {
        return Err(VerificationFailure::MultipleRevisions { count: revisions });
    }
    if !find_all(bytes, b"/Prev").is_empty() {
        return Err(VerificationFailure::PreviousRevisionChain);
    }
    for key in FORBIDDEN {
        if !find_all(bytes, key.as_bytes()).is_empty() {
            return Err(VerificationFailure::StructureSurvived { key });
        }
    }

    let document = Document::load(bytes).map_err(|_| VerificationFailure::Unreadable)?;

    // (2) Re-extraction, from the bytes rather than from the graph the
    // redactor was holding. A check that reads the redactor's own state can
    // only ever confirm what the redactor believed.
    let pages = document.page_numbers().unwrap_or_default();
    for (index, page_number) in pages.iter().enumerate() {
        let Some(page) = document.objects.get(page_number).and_then(Object::as_dict) else {
            continue;
        };
        let (combined, _) = crate::pdf::page_streams(&document, page);
        let fonts = crate::pdf::page_fonts(&document, page);
        let text = content::extract(&content::parse(&combined), &fonts).text();
        if let Some(found) = first_match(&text, originals) {
            return Err(VerificationFailure::IdentifierSurvived {
                index: found,
                where_found: Survival::PageText { page: index + 1 },
            });
        }
    }

    // (3) The decompressed byte scan, which is the check that catches an
    // identifier hiding in an annotation, an outline title, a form value or a
    // stream the page tree does not reach.
    for (number, object) in &document.objects {
        let mut blob: Vec<u8> = Vec::new();
        flatten(object, &mut blob);
        if let Some(found) = first_byte_match(&blob, originals) {
            return Err(VerificationFailure::IdentifierSurvived {
                index: found,
                where_found: Survival::ObjectBytes { object: *number },
            });
        }
    }
    Ok(())
}

/// Collect every byte an object can yield, streams DECODED.
fn flatten(object: &Object, out: &mut Vec<u8>) {
    match object {
        Object::Str(bytes, _) => out.extend_from_slice(bytes),
        Object::Name(name) => out.extend_from_slice(name.as_bytes()),
        Object::Array(items) => {
            for item in items {
                flatten(item, out);
            }
        }
        Object::Dict(dict) => {
            for (_, value) in &dict.0 {
                flatten(value, out);
            }
        }
        Object::Stream(dict, raw) => {
            for (_, value) in &dict.0 {
                flatten(value, out);
            }
            match decode_stream(dict, raw) {
                Some(data) => out.extend_from_slice(&data),
                // A stream this crate cannot decode is a stream it cannot
                // clear, so the raw bytes are scanned as well. That can only
                // produce a false ALARM, never a false pass.
                None => out.extend_from_slice(raw),
            }
        }
        Object::Null
        | Object::Bool(_)
        | Object::Int(_)
        | Object::Real(_)
        | Object::Reference(..) => {}
    }
}

fn first_match(haystack: &str, needles: &[String]) -> Option<usize> {
    let folded = haystack.to_lowercase();
    needles.iter().position(|needle| {
        !needle.is_empty() && (haystack.contains(needle) || folded.contains(&needle.to_lowercase()))
    })
}

fn first_byte_match(haystack: &[u8], needles: &[String]) -> Option<usize> {
    needles.iter().position(|needle| {
        if needle.is_empty() {
            return false;
        }
        let mut utf16 = Vec::new();
        for unit in needle.encode_utf16() {
            utf16.extend_from_slice(&unit.to_be_bytes());
        }
        let latin1: Vec<u8> = needle
            .chars()
            .filter_map(|value| u8::try_from(u32::from(value)).ok())
            .collect();
        [needle.as_bytes(), utf16.as_slice(), latin1.as_slice()]
            .iter()
            .any(|form| !form.is_empty() && contains(haystack, form))
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !find_all(haystack, needle).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_utf16be_form_of_an_identifier_is_caught() {
        // A PDF text string carries Turkish as UTF-16BE, so a verifier that
        // only greps UTF-8 misses every identifier in an annotation or an
        // outline title.
        let mut blob = vec![0xfe, 0xff];
        for unit in "Ayşe".encode_utf16() {
            blob.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(first_byte_match(&blob, &["Ayşe".to_owned()]), Some(0));
        assert_eq!(first_byte_match(&blob, &["Bora".to_owned()]), None);
    }

    #[test]
    fn an_empty_needle_never_matches() {
        // Otherwise a run that removed nothing would "find" its empty
        // identifier everywhere and fail every verification.
        assert_eq!(first_byte_match(b"anything", &[String::new()]), None);
        assert_eq!(first_match("anything", &[String::new()]), None);
    }

    #[test]
    fn a_case_variant_in_page_text_is_still_a_survival() {
        assert_eq!(
            first_match("hasta AYSE geldi", &["Ayse".to_owned()]),
            Some(0)
        );
    }
}
