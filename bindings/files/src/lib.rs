#![forbid(unsafe_code)]

//! `deid-tr-files` -- file and document de-identification for deid-tr.
//!
//! This crate is the container layer. It opens a file format, finds the text
//! inside it, hands that text to `deid-tr-core`, and puts the answer back
//! without disturbing anything else. It performs NO filesystem and NO network
//! access of its own: it takes `&[u8]` and returns `Vec<u8>`. Reading and
//! writing paths is the CLI's job, which keeps this crate testable in memory
//! and keeps the I/O surface in one place.
//!
//! # Invariant I1
//!
//! `core/` has no I/O and no network dependency and compiles to `wasm32`.
//! Decompression, zip parsing and PDF object graphs are none of those things,
//! so they live here. Nothing in this crate may be moved, re-exported or
//! feature-flagged into `core/`.
//!
//! # HONEST SCOPE -- read this before trusting an output
//!
//! `Pipeline::new` installs an EMPTY L2 ensemble because no trained model
//! exists yet. Every format in this crate therefore removes the identifiers
//! `core/src/rules/` can PROVE -- TCKN, VKN, IBAN, phone, email, MRN, date --
//! and nothing else. **Person names, clinician names, institution names and
//! every contextual quasi-identifier survive.** The one exception is `.docx`
//! metadata, where a name is removed because the SCHEMA said the field held one
//! (`dc:creator`, `w:author`), not because anything recognised it.
//!
//! A "redacted" file from this tool is not name-free.
//! [`Report::rule_detectable_only`] is the sentence every surface must show.
//!
//! # True redaction
//!
//! For PDF this crate does true redaction and nothing weaker: the glyph codes
//! are removed from the content stream, the file is fully rewritten so no
//! previous revision survives, and the OUTPUT IS RE-OPENED AND VERIFIED before
//! it is returned. If verification fails, or if a page is a scan whose text is
//! pixels, the operation FAILS. See [`pdf`].

pub mod csv;
pub mod docx;
pub mod inflate;
pub mod json;
pub mod jsonl;
pub mod masker;
pub mod pdf;
pub mod txt;
pub mod zip;

#[cfg(test)]
mod testing;

pub use masker::{Masked, Masker, Replacement, Report};

/// Anything that can go wrong opening, reading or rewriting a document.
///
/// NO VARIANT CARRIES DOCUMENT TEXT (I4). Offsets, line numbers, page numbers,
/// part names and PDF keys only. An error message ends up in a terminal, then a
/// screenshot, then a ticket.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum FileError {
    /// The pipeline refused the text.
    #[error("de-identification failed: {0}")]
    Pipeline(#[from] deid_tr_core::Error),
    /// A text file could not be decoded.
    #[error("text decoding failed: {0}")]
    Text(#[from] txt::TextError),
    /// A CSV could not be parsed.
    #[error("CSV parsing failed: {0}")]
    Csv(#[from] csv::CsvError),
    /// A JSON document could not be parsed.
    #[error("JSON parsing failed: {0}")]
    Json(#[from] json::JsonError),
    /// A JSON Lines record could not be parsed.
    #[error("JSON Lines parsing failed: {0}")]
    Jsonl(#[from] jsonl::JsonlError),
    /// A `.docx` could not be processed.
    #[error("DOCX processing failed: {0}")]
    Docx(#[from] docx::DocxError),
    /// A PDF could not be redacted, or the redaction could not be verified.
    #[error("PDF redaction failed: {0}")]
    Pdf(#[from] pdf::PdfError),
    /// The bytes are not a format this crate handles.
    #[error("the file format could not be determined")]
    UnknownFormat,
}

/// The formats this crate handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Plain text.
    Text,
    /// Comma- or semicolon-separated records.
    Csv,
    /// One JSON value per line.
    Jsonl,
    /// A single JSON document.
    Json,
    /// Office Open XML word processing.
    Docx,
    /// Portable Document Format.
    Pdf,
}

impl Format {
    /// The name used in a report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
            Self::Json => "json",
            Self::Docx => "docx",
            Self::Pdf => "pdf",
        }
    }

    /// The format a file extension names, if any.
    #[must_use]
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "txt" | "text" | "md" | "log" => Some(Self::Text),
            "csv" | "tsv" => Some(Self::Csv),
            "jsonl" | "ndjson" => Some(Self::Jsonl),
            "json" => Some(Self::Json),
            "docx" => Some(Self::Docx),
            "pdf" => Some(Self::Pdf),
            _ => None,
        }
    }
}

/// Detect a format from the bytes, with the file name as a tie-breaker.
///
/// CONTENT FIRST, name second. A `.txt` that is actually a PDF must be redacted
/// as a PDF: treating it as text would rewrite the compressed bytes and produce
/// a corrupt file that still contains every identifier. The name only decides
/// between the text-shaped formats, which are not distinguishable by a magic
/// number.
#[must_use]
pub fn detect_format(bytes: &[u8], name: Option<&str>) -> Option<Format> {
    if pdf::is_pdf(bytes) {
        return Some(Format::Pdf);
    }
    if docx::is_docx(bytes) {
        return Some(Format::Docx);
    }
    if bytes.starts_with(b"PK\x03\x04") {
        // A zip that is not a .docx is a container this crate cannot sweep, and
        // guessing "text" for it would produce a corrupt archive.
        return None;
    }

    let named = name
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension)
        .and_then(Format::from_extension);

    let shape = txt::detect(bytes);
    let Ok(text) = txt::decode(bytes, shape) else {
        return None;
    };
    let trimmed = text.trim_start();

    // A named format wins over the shape heuristics below, EXCEPT where the
    // bytes have already contradicted it above.
    if let Some(format) = named {
        return Some(format);
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // One value or many? A second `{` at the start of a later line is the
        // JSON Lines signature.
        let records = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(3)
            .count();
        if records > 1 && json::parse(&text).is_err() {
            return Some(Format::Jsonl);
        }
        return Some(Format::Json);
    }
    Some(Format::Text)
}

/// What one [`mask_file`] call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The rewritten file.
    pub bytes: Vec<u8>,
    /// Counts and structural names. Safe to print.
    pub report: Report,
}

/// De-identify a whole file.
///
/// # Errors
///
/// [`FileError`] when the format cannot be determined or the document cannot be
/// processed. A PDF whose redaction cannot be VERIFIED returns an error and no
/// bytes.
pub fn mask_file(masker: &Masker<'_>, bytes: &[u8], format: Format) -> Result<Output, FileError> {
    let mut report = Report {
        format: format.name(),
        ..Report::default()
    };
    let bytes = match format {
        Format::Text => {
            let (out, masked) = txt::mask(masker, bytes)?;
            report.masked = masked.originals.len();
            report.locations = 1;
            out
        }
        Format::Csv => {
            let shape = txt::detect(bytes);
            let text = txt::decode(bytes, shape)?;
            let masked = csv::mask(masker, &text, true, &csv::Fields::All)?;
            report.masked = masked.originals.len();
            report.locations = masked.text.lines().count();
            txt::encode(&masked.text, shape)
        }
        Format::Json | Format::Jsonl => {
            let shape = txt::detect(bytes);
            let text = txt::decode(bytes, shape)?;
            let masked = if format == Format::Json {
                json::mask(masker, &text)?
            } else {
                jsonl::mask(masker, &text)?
            };
            report.masked = masked.originals.len();
            report.locations = masked.text.lines().count();
            txt::encode(&masked.text, shape)
        }
        Format::Docx => {
            let (outcome, originals) = docx::mask(masker, bytes)?;
            report.masked = originals.len();
            report.locations = outcome.parts_rewritten.len();
            report.stripped = outcome.fields_cleared;
            outcome.bytes
        }
        Format::Pdf => {
            let redaction = pdf::redact(masker, bytes)?;
            report.masked = redaction.removed_from_pages + redaction.removed_from_objects;
            report.locations = redaction.pages;
            report.stripped = redaction.stripped;
            redaction.bytes
        }
    };
    Ok(Output { bytes, report })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::{Pipeline, Tier};

    fn masker() -> Masker<'static> {
        // `Box::leak` rather than a `static`: `Pipeline` holds boxed trait
        // objects and is deliberately not `Sync`, so it cannot live in a
        // static. The leak is bounded by the test process.
        Masker::new(Box::leak(Box::new(Pipeline::new(Tier::SafeHarbor))))
    }

    #[test]
    fn content_beats_the_file_name() {
        // A PDF named `.txt` must be redacted as a PDF. Masking it as text
        // would rewrite compressed bytes into nonsense and leave every
        // identifier in place while looking like it worked.
        assert_eq!(
            detect_format(b"%PDF-1.7\n", Some("note.txt")),
            Some(Format::Pdf)
        );
        assert_eq!(detect_format(b"hello", Some("a.csv")), Some(Format::Csv));
        assert_eq!(detect_format(b"hello", None), Some(Format::Text));
    }

    #[test]
    fn json_and_jsonl_are_distinguished_without_a_name() {
        assert_eq!(
            detect_format(b"{\"a\":1}\n{\"b\":2}\n", None),
            Some(Format::Jsonl)
        );
        assert_eq!(
            detect_format(b"{\n  \"a\": 1\n}\n", None),
            Some(Format::Json)
        );
    }

    #[test]
    fn an_unknown_zip_is_refused_rather_than_treated_as_text() {
        assert_eq!(detect_format(b"PK\x03\x04rubbish", None), None);
    }

    #[test]
    fn mask_file_reports_counts_and_never_text() {
        let tckn = testing::tckn();
        let source = format!("TCKN {tckn}\n");
        let output = mask_file(&masker(), source.as_bytes(), Format::Text).expect("mask");
        assert!(!output.bytes.windows(11).any(|w| w == tckn.as_bytes()));
        assert_eq!(output.report.masked, 1);
        assert_eq!(output.report.format, "txt");
        let rendered = format!("{:?}", output.report);
        assert!(!rendered.contains(&tckn));
    }
}
