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

pub use masker::{Masked, Masker, PartSummary, Replacement, Report, SpanRecord};

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
    /// An identifier the masker removed is still present in the output bytes.
    ///
    /// THE INDEX, NEVER THE IDENTIFIER (I4). A caller holding the removal list
    /// can resolve it locally; an error message that travels to a terminal, a
    /// screenshot and a ticket must not.
    #[error("identifier #{index} survived redaction and is still in the output")]
    NotVerified {
        /// Index into the list of identifiers the masker removed.
        index: usize,
    },
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

/// Binary containers this crate cannot sweep, recognised by magic number.
///
/// WHY A DENYLIST OF MAGICS RATHER THAN AN ALLOWLIST OF TEXT: the text formats
/// have no magic number, so "is it text" cannot be answered positively from a
/// prefix. The residual NUL check below is the general net; these prefixes are
/// the shapes worth naming, because each one is a file a clinical user
/// plausibly drops and each would otherwise be swept as text.
fn is_unsupported_binary(bytes: &[u8]) -> bool {
    // OLE2 / CFBF: legacy .doc, .xls, .ppt. First in the list because it is the
    // one that actually reached a user, and the one a hospital share is full of.
    const OLE2: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    const MAGICS: &[&[u8]] = &[
        OLE2,
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff", // JPEG
        b"GIF8",
        b"BM",      // BMP
        b"II*\x00", // TIFF little-endian
        b"MM\x00*", // TIFF big-endian
        b"RIFF",    // WebP and friends
        b"{\\rtf",  // RTF: text-shaped, but a control-word format that
        // a byte-level sweep corrupts while leaving text in \u escapes intact
        b"\x1f\x8b",     // gzip
        b"BZh",          // bzip2
        b"\xfd7zXZ\x00", // xz
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"\x7fELF",
        b"MZ",               // PE
        b"\xca\xfe\xba\xbe", // Mach-O fat
        b"\xcf\xfa\xed\xfe", // Mach-O 64
        b"SQLite format 3\x00",
        b"%!PS", // PostScript
        b"OggS",
        b"\x00\x00\x01\xba", // MPEG program stream
    ];
    if MAGICS.iter().any(|magic| bytes.starts_with(magic)) {
        return true;
    }

    // The general net, for a binary whose magic is not listed above. Text does
    // not contain NUL. A single embedded NUL in the leading window is enough to
    // say "this is not a document I can sweep as text", and refusing is the
    // safe direction: the cost of a false refusal is that a user converts the
    // file, and the cost of a false accept is an output that looks redacted.
    //
    // UTF-16 text is deliberately caught here. It is genuinely text, and it is
    // genuinely NOT something the text path handles today: the rules layer
    // would see NUL-separated bytes and match nothing, which is the exact
    // silent-zero-spans failure this guard exists to stop.
    const WINDOW: usize = 8192;
    bytes.iter().take(WINDOW).any(|byte| *byte == 0)
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
    if is_unsupported_binary(bytes) {
        // THE SAME REASONING AS THE ZIP GUARD ABOVE, WHICH USED TO BE APPLIED TO
        // ZIP ALONE. Everything it did not name fell through to `Format::Text`,
        // and that fallback is unconditional, so a legacy `.doc` was swept as
        // plain text. Measured before this guard existed:
        //
        //     deid mask-file real.doc  ->  "txt format, masked 0 span(s)", exit 0
        //
        // Word stores text as UTF-16LE, so an ASCII-oriented rule layer sees
        // nothing: zero spans matched, an output file was written, success was
        // reported, and the TCKN, phone number and e-mail all survived intact.
        // A `.doc` is precisely what sits on a hospital share, and "0 spans"
        // reads to a user as "this document was clean".
        //
        // A single-byte code page cannot reject this for us. CP1254 maps every
        // one of the 256 byte values to some character, so `txt::decode` below
        // succeeds on arbitrary binary and can never be the thing that catches
        // it. The magic number has to be checked explicitly.
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
///
/// NOT `Eq`: [`Report`] carries an `f32` confidence, and `f32` is `PartialEq`
/// only. Deriving `Eq` here again would fail to compile rather than silently
/// mislead, but the reason is worth recording so it is not re-added.
#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    /// The rewritten file.
    pub bytes: Vec<u8>,
    /// Counts and structural names. Safe to print.
    pub report: Report,
    /// What was checked on the bytes above before they were returned.
    pub verification: Verification,
}

/// One readable region of a document, named the way a reader navigates it.
///
/// `text` IS DOCUMENT TEXT AND THEREFORE PHI: [`fmt::Debug`] is hand-written to
/// print a length, for the same reason [`Masked`]'s is.
///
/// [`fmt::Debug`]: core::fmt::Debug
#[derive(Clone, PartialEq, Eq)]
pub struct DocPart {
    /// What a reader would call this region: `page 3`, `word/document.xml`, or
    /// the format name for a document that has exactly one region. Structural,
    /// safe to print.
    pub name: String,
    /// The text of the region, exactly as the masker sees it. PHI.
    pub text: String,
}

impl core::fmt::Debug for DocPart {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DocPart")
            .field("name", &self.name)
            .field(
                "text",
                &format_args!("<{} bytes redacted>", self.text.len()),
            )
            .finish()
    }
}

/// Read a document's text WITHOUT masking anything.
///
/// # Why this exists next to [`mask_file`] rather than inside it
///
/// A binary format cannot be edited in place by a person, so a surface offering
/// PDF or `.docx` redaction has to show what it read before it hands back bytes
/// the reader cannot inspect. That display must come from the SAME decoder the
/// masker uses or it is decoration: [`pdf::extract_pages`] and
/// [`docx::extract_parts`] both share their per-page and per-part reading code
/// with the redaction path, so what is shown is what was scanned.
///
/// It is deliberately NOT folded into [`mask_file`]'s return value. `Output` is
/// counts-and-keys and derives `Debug` safely; a text field on it would put a
/// clinical document into the first `{:?}` anyone writes (I4).
///
/// # Errors
///
/// [`FileError`], including the by-page refusals a scanned PDF earns -- so a
/// caller that displays before redacting learns about a refusal at display time
/// rather than after the reader has waited.
pub fn extract(bytes: &[u8], format: Format) -> Result<Vec<DocPart>, FileError> {
    extract_with(bytes, format, Options::default())
}

/// Read a document's text under an explicit [`Options`].
///
/// # Errors
///
/// As [`extract`].
pub fn extract_with(
    bytes: &[u8],
    format: Format,
    options: Options,
) -> Result<Vec<DocPart>, FileError> {
    match format {
        Format::Text | Format::Csv | Format::Json | Format::Jsonl => {
            let shape = txt::detect(bytes);
            Ok(vec![DocPart {
                name: format.name().to_owned(),
                text: txt::decode(bytes, shape)?,
            }])
        }
        Format::Docx => Ok(docx::extract_parts(bytes)?
            .into_iter()
            .map(|part| DocPart {
                name: part.name,
                text: part.text,
            })
            .collect()),
        Format::Pdf => Ok(pdf::extract_pages_with(bytes, options.images)?
            .into_iter()
            .map(|page| DocPart {
                name: format!("page {}", page.page),
                text: page.text,
            })
            .collect()),
    }
}

/// How a document is to be handled where this crate has a choice.
///
/// Exactly one knob today, and it is deliberately a struct rather than a bare
/// enum parameter: the next honest limitation will want reporting too, and a
/// second positional boolean at every call site is how a caller ends up passing
/// them in the wrong order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    /// What to do about images whose pixels this crate cannot read.
    ///
    /// Defaults to [`pdf::ImagePolicy::Refuse`]; see that type for the
    /// argument.
    pub images: pdf::ImagePolicy,
}

/// How the output was checked before it was handed back.
///
/// A REDACTION WHOSE VERIFICATION DID NOT RUN IS AN UNVERIFIED REDACTION, and
/// the further a surface is from a terminal the less able its user is to check
/// by hand. So every format checks, every check is named here, and the result
/// travels with the bytes instead of being a fact about the code that a user
/// has to take on trust.
///
/// This type only ever describes a PASS: a failed check returns an error and no
/// bytes, in both the PDF path ([`pdf::verify`]) and the generic one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Which verifier ran: `pdf-reopen` or `output-scan`.
    pub method: &'static str,
    /// What it checked, in the order it checked it. Safe to print.
    pub checks: Vec<&'static str>,
    /// How many removed identifiers were hunted for in the output.
    ///
    /// ZERO IS NOT A PASS TO BOAST ABOUT. It means nothing was removed, so the
    /// scan had nothing to look for -- a surface should say "nothing detected"
    /// rather than "verified clean".
    pub identifiers_checked: usize,
}

/// The checks [`verify_output`] performs, named for a report.
const OUTPUT_SCAN_CHECKS: &[&str] = &[
    "every removed identifier absent from the output bytes (UTF-8)",
    "every removed identifier absent from the output bytes (UTF-16LE)",
    "every removed identifier absent from the output bytes (UTF-16BE)",
];

/// Hunt for every removed identifier in the bytes that are about to be returned.
///
/// THE OUTPUT, not the in-memory string the masker produced. A container has
/// regions the sweep does not rewrite -- an unswept `.docx` part, an embedded
/// object -- and an identifier that survives in one of those is a leak no
/// amount of checking the masker's own return value can see.
///
/// Three encodings because a container decides how it stores text and the
/// caller does not: `txt::encode` emits UTF-16 for a document that arrived as
/// UTF-16, and a scan in UTF-8 alone would walk straight past it.
fn verify_output(bytes: &[u8], originals: &[String]) -> Result<(), FileError> {
    for (index, original) in originals.iter().enumerate() {
        if original.is_empty() {
            continue;
        }
        let utf16: Vec<u16> = original.encode_utf16().collect();
        let le: Vec<u8> = utf16.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let be: Vec<u8> = utf16.iter().flat_map(|unit| unit.to_be_bytes()).collect();
        for needle in [original.as_bytes(), &le, &be] {
            if !needle.is_empty() && contains(bytes, needle) {
                // The INDEX, never the identifier (I4). A caller holding the
                // list can look it up locally; an error message cannot.
                return Err(FileError::NotVerified { index });
            }
        }
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// De-identify a whole file.
///
/// # Errors
///
/// [`FileError`] when the format cannot be determined or the document cannot be
/// processed. A document whose redaction cannot be VERIFIED returns an error and
/// no bytes.
pub fn mask_file(masker: &Masker<'_>, bytes: &[u8], format: Format) -> Result<Output, FileError> {
    mask_file_with(masker, bytes, format, Options::default())
}

/// De-identify a whole file under an explicit [`Options`].
///
/// # Errors
///
/// As [`mask_file`].
pub fn mask_file_with(
    masker: &Masker<'_>,
    bytes: &[u8],
    format: Format,
    options: Options,
) -> Result<Output, FileError> {
    let mut report = Report {
        format: format.name(),
        ..Report::default()
    };
    // Held only for the length of this call, then dropped. PHI (I4).
    let mut originals: Vec<String> = Vec::new();
    let mut verification = Verification {
        method: "output-scan",
        checks: OUTPUT_SCAN_CHECKS.to_vec(),
        identifiers_checked: 0,
    };
    let bytes = match format {
        Format::Text => {
            let (out, masked) = txt::mask(masker, bytes)?;
            report.masked = masked.originals.len();
            report.locations = 1;
            report.parts = vec![PartSummary {
                name: "document".to_owned(),
                masked: report.masked,
            }];
            originals = masked.originals;
            out
        }
        Format::Csv => {
            let shape = txt::detect(bytes);
            let text = txt::decode(bytes, shape)?;
            let masked = csv::mask(masker, &text, true, &csv::Fields::All)?;
            report.masked = masked.originals.len();
            report.locations = masked.text.lines().count();
            report.parts = vec![PartSummary {
                name: "document".to_owned(),
                masked: report.masked,
            }];
            originals = masked.originals;
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
            report.parts = vec![PartSummary {
                name: "document".to_owned(),
                masked: report.masked,
            }];
            originals = masked.originals;
            txt::encode(&masked.text, shape)
        }
        Format::Docx => {
            let (outcome, swept) = docx::mask(masker, bytes)?;
            report.masked = swept.len();
            report.locations = outcome.parts_rewritten.len();
            report.stripped = outcome.fields_cleared;
            report.parts = outcome
                .part_spans
                .into_iter()
                .map(|(name, masked)| PartSummary { name, masked })
                .collect();
            originals = swept;
            outcome.bytes
        }
        Format::Pdf => {
            let redaction = pdf::redact_with(masker, bytes, options.images)?;
            report.images = redaction.images;
            report.masked = redaction.removed_from_pages + redaction.removed_from_objects;
            report.locations = redaction.pages;
            report.stripped = redaction.stripped;
            report.parts = redaction
                .page_spans
                .iter()
                .enumerate()
                .map(|(index, masked)| PartSummary {
                    name: format!("page {}", index + 1),
                    masked: *masked,
                })
                .collect();
            // `pdf::redact` ALREADY verified, against a re-parse of these
            // bytes, and returned an error rather than a file if anything
            // survived. Re-running the generic scan here would be weaker than
            // what already ran, so the stronger result is reported instead.
            verification = Verification {
                method: "pdf-reopen",
                checks: pdf::VERIFY_CHECKS.to_vec(),
                identifiers_checked: report.masked,
            };
            redaction.bytes
        }
    };
    if verification.method == "output-scan" {
        verify_output(&bytes, &originals)?;
        verification.identifiers_checked = originals.len();
    }
    report.spans = masker.take_records();
    Ok(Output {
        bytes,
        report,
        verification,
    })
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

    /// A legacy `.doc` is refused, not swept as text.
    ///
    /// THE REGRESSION THIS PINS, measured on the shipped binary before the fix:
    ///
    ///     deid mask-file real.doc  ->  "txt format, masked 0 span(s)", exit 0
    ///
    /// Word writes text as UTF-16LE, so an ASCII-oriented rule layer matched
    /// nothing across the whole document, an output file was written, success
    /// was reported, and every identifier survived. "0 spans" reads to a user
    /// as "this document was clean", which is the most dangerous sentence this
    /// tool can imply. `.doc` is also the single likeliest file on a hospital
    /// share, so this was the common path, not a corner.
    ///
    /// The name is passed as `Some("report.doc")` deliberately: an extension
    /// this crate does not support must not talk the detector into a format,
    /// and the bytes have to be what refuses.
    #[test]
    fn a_legacy_doc_is_refused_rather_than_swept_as_text() {
        const OLE2: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        let mut doc = OLE2.to_vec();
        doc.extend(std::iter::repeat_n(0u8, 480));
        // As Word stores it, and as the ASCII rule layer cannot see it.
        for unit in "TCKN 12345678901".encode_utf16() {
            doc.extend(unit.to_le_bytes());
        }
        assert_eq!(detect_format(&doc, Some("report.doc")), None);
        assert_eq!(detect_format(&doc, None), None);
    }

    #[test]
    fn common_binary_containers_are_refused() {
        for (label, magic) in [
            ("png", b"\x89PNG\r\n\x1a\n".as_slice()),
            ("jpeg", b"\xff\xd8\xff".as_slice()),
            ("gzip", b"\x1f\x8b".as_slice()),
            ("elf", b"\x7fELF".as_slice()),
            ("sqlite", b"SQLite format 3\x00".as_slice()),
            ("rtf", b"{\\rtf1\\ansi".as_slice()),
        ] {
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(b"TCKN 12345678901 padding padding padding");
            assert_eq!(detect_format(&bytes, None), None, "{label} was not refused");
        }
    }

    /// UTF-16 text is refused rather than silently matching nothing.
    ///
    /// It IS text, which makes this the least obvious case. But the rules layer
    /// reads bytes, and NUL-separated UTF-16 matches no pattern it has, so
    /// accepting it produces the same silent zero-span success as the `.doc`
    /// above. Refusing is honest until the text path decodes UTF-16 properly.
    #[test]
    fn utf16_text_is_refused_rather_than_matching_nothing() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "TCKN 12345678901".encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        assert_eq!(detect_format(&bytes, Some("note.txt")), None);
    }

    /// The guard must not swallow the formats it exists to protect.
    #[test]
    fn supported_formats_still_detect_after_the_binary_guard() {
        assert_eq!(
            detect_format(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n", None),
            Some(Format::Pdf)
        );
        assert_eq!(
            detect_format(b"Hasta Ayse Yilmaz\n", None),
            Some(Format::Text)
        );
        assert_eq!(detect_format(b"{\"a\":1}", None), Some(Format::Json));
        // Turkish in CP1254 is high-byte and NUL-free, so it must still pass.
        assert_eq!(
            detect_format(b"Hasta Ay\xfee Y\xfdlmaz\n", None),
            Some(Format::Text)
        );
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
