//! Whole-FILE de-identification in the browser, using the audited crate.
//!
//! # Why this module is a binding and not an implementation
//!
//! `deid-tr-files` already compiles to `wasm32-unknown-unknown` unmodified. Its
//! whole dependency list is `deid-tr-core` and `thiserror`; it carries its own
//! DEFLATE decoder, its own PKZIP reader and its own PDF object model, calls no
//! subprocess and touches no filesystem. So the browser can run the CLI's exact
//! redaction code, and everything below is plumbing.
//!
//! That matters more than it sounds. The alternative -- a JavaScript PDF
//! redactor for the panel -- would be a SECOND implementation of the one part
//! of this product where a subtle difference is invisible and catastrophic. Two
//! redactors drift; the one that drifts is the one nobody runs the PDF test
//! corpus against; and the surface where the user is least able to check the
//! result by hand is exactly the browser.
//!
//! # The three properties, and where each one is enforced
//!
//! 1. **True removal.** Not preserved by this module -- performed by
//!    [`deid_tr_files::pdf::redact`], which deletes the operand bytes from the
//!    decoded content stream, draws nothing in their place, and rewrites the
//!    file from the objects reachable from the current catalogue so no
//!    incremental-update revision survives. Metadata, XMP, annotations,
//!    AcroForm values, `/XFA`, bookmarks, named destinations, thumbnails,
//!    embedded files and JavaScript are stripped there too. This module calls
//!    that function and adds nothing to it.
//! 2. **Verification runs here too.** `redact` calls
//!    [`deid_tr_files::pdf::verify`] on its own output bytes and returns an
//!    error instead of a file when anything survives. There is no flag to skip
//!    it and this binding does not add one. What the binding DOES add is
//!    [`RedactedFile::verification`], because a green tick with no statement
//!    behind it is a badge: the panel can now name the five checks that ran.
//!    Non-PDF formats get the generic output scan, also reported by name.
//! 3. **Refusal.** A page with no text layer is refused BY NUMBER, by the same
//!    `PdfError::ScannedPage` the CLI raises, and the refusal reaches JS as a
//!    thrown error carrying that page number. No bytes are returned. A user who
//!    uploads a scan of a discharge summary gets told the tool cannot read it,
//!    which is the only honest answer available to a program with no OCR.
//! 4. **Images on a page that DOES have text.** Same policy as the CLI, same
//!    code: refused by default, and continued only when the caller passes
//!    `allowImages`, in which case [`RedactedFile::image_warning`] carries the
//!    page number, the count and the pixel dimensions and the panel is required
//!    to show them. A browser user has no `pdfimages` to check with, so this is
//!    the surface where an unmentioned image is least recoverable.
//!
//! # HONEST SCOPE, restated because this surface is new
//!
//! deid-tr masks ZERO names. No trained L2 model exists, so what comes out is
//! the identifiers `core/src/rules/` can prove -- TCKN, VKN, IBAN, phone,
//! email, MRN, date. Person names, clinician names and institution names
//! SURVIVE in every format here, with the one exception of `.docx` fields whose
//! schema declares them to hold a name. [`RedactedFile::disclosure`] returns the
//! sentence a surface must show, and it is a getter rather than prose in the
//! panel so it cannot be softened by whoever writes the panel next.
//!
//! # Size
//!
//! Linking this crate grows the wasm module. The panel states the number rather
//! than claiming it ships no extra runtime -- it ships a PDF parser, and the
//! honest framing is that the parser is Rust that was already reviewed, not
//! that it is free.
//!
//! # I4
//!
//! Nothing here puts document text into an error. `FileError`,
//! `PdfError` and `VerificationFailure` are all structurally incapable of it:
//! they carry page numbers, part names, PDF keys, byte counts and an INDEX into
//! a removal list the caller holds. [`RedactedFile::preview`] is the one place
//! document text crosses to JS, it is post-redaction text the caller already
//! has in [`RedactedFile::bytes`], and it is reachable only through a named
//! getter so no `console.log` of the result object can emit it by accident.

use deid_tr_files::pdf::ImagePolicy;
use deid_tr_files::{detect_format, mask_file_with, Format, Masker, Options, Output, Report};
use wasm_bindgen::prelude::*;

use crate::{configured, Tier, WasmError};

/// The largest input this binding will accept, in bytes.
///
/// # Why there is a number at all
///
/// A browser hands a file over as one `ArrayBuffer`, and PDF redaction is not a
/// streaming operation: the object graph, every decompressed stream, the
/// rewritten output and the re-parse that verifies it all coexist. Peak
/// residency is several times the input. wasm32 has a 4 GiB address space and
/// browsers cap a module's memory well below that, so a large enough file does
/// not fail -- it aborts the whole module on a failed allocation, taking the
/// panel with it and telling the user nothing.
///
/// # Why 64 MiB
///
/// It is roughly an order of magnitude above a clinical PDF (a scanned-free
/// discharge summary or lab report is tens to hundreds of kilobytes; a
/// several-hundred-page imaging report is single-digit megabytes) and, at a
/// conservative 8x peak-to-input ratio, leaves the module around half a
/// gigabyte -- inside what a browser tab reliably grants. The number is stated
/// here and reported by [`max_file_bytes`] so a surface can check before it
/// reads a file rather than after.
///
/// Above it the answer is a specific, catchable error naming both sizes, which
/// is the difference between "this file is too large for the browser build, use
/// the CLI" and a tab that dies.
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// How much of a document's text [`RedactedFile::preview`] returns.
///
/// A preview is for reading, and a megabyte of extracted text is not read -- it
/// is pasted somewhere. Truncation is reported by
/// [`RedactedFile::preview_truncated`] so a surface never silently shows part of
/// a document as though it were all of it.
const PREVIEW_BYTES: usize = 32 * 1024;

/// Everything the file surface can fail with.
///
/// Every variant's `Display` is offsets, names, numbers and lengths (I4).
enum FilesError {
    /// The pipeline, the salt, or a tier that cannot run here.
    Wasm(WasmError),
    /// The container layer.
    File(deid_tr_files::FileError),
    /// The bytes are larger than [`MAX_FILE_BYTES`].
    TooLarge { bytes: usize },
    /// The format string is not one this build knows.
    UnknownFormat,
    /// The bytes match no format this crate can sweep.
    Undetectable,
    /// Expert Determination was asked for, which this entry point cannot run.
    NoContextualSweep,
}

impl std::fmt::Display for FilesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wasm(error) => error.fmt(f),
            Self::File(error) => error.fmt(f),
            Self::TooLarge { bytes } => write!(
                f,
                "the file is {bytes} bytes; this browser build accepts at most {MAX_FILE_BYTES}. \
                 Use the command-line tool for a file this size rather than a browser tab"
            ),
            Self::UnknownFormat => f.write_str(
                "unknown format name; pass one of txt, csv, json, jsonl, docx, pdf -- or the \
                 string detectFormat returned",
            ),
            Self::Undetectable => f.write_str(
                "the bytes match no format deid-tr can sweep; it will not guess, because guessing \
                 'text' at a container rewrites its compressed bytes and returns a corrupt file \
                 with every identifier still in it",
            ),
            Self::NoContextualSweep => f.write_str(
                "Expert Determination needs a host-run local model completion, which the file \
                 entry point has no way to obtain. Use Safe Harbor here, or run the two-phase \
                 contextual seam over extracted text",
            ),
        }
    }
}

// Delegates to `Display` for the same reason `WasmError`'s does: a derive would
// start printing whatever a future variant carries.
impl std::fmt::Debug for FilesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<WasmError> for FilesError {
    fn from(error: WasmError) -> Self {
        Self::Wasm(error)
    }
}

impl From<deid_tr_files::FileError> for FilesError {
    fn from(error: deid_tr_files::FileError) -> Self {
        Self::File(error)
    }
}

/// The name this build uses for a format, both in and out.
fn format_named(name: &str) -> Option<Format> {
    // Matched against `Format::name` rather than against an extension, so
    // `redactFile(bytes, detectFormat(bytes), ..)` round-trips by construction.
    [
        Format::Text,
        Format::Csv,
        Format::Jsonl,
        Format::Json,
        Format::Docx,
        Format::Pdf,
    ]
    .into_iter()
    .find(|format| format.name() == name)
}

/// The size ceiling, so a surface can refuse a file before it reads it.
#[wasm_bindgen(js_name = maxFileBytes)]
#[must_use]
pub fn max_file_bytes() -> usize {
    MAX_FILE_BYTES
}

/// Identify a file from its CONTENT.
///
/// THE NAME IS NOT CONSULTED, and that is the whole point of the function. A
/// `.pdf` extension on a zip is a lie a user can tell by accident -- an export
/// button that picked the wrong suffix, a rename, a download that guessed. The
/// content is the truth, and treating a PDF as text would rewrite its
/// compressed bytes into nonsense while leaving every identifier in place and
/// looking like it worked.
///
/// Returns one of `txt`, `csv`, `json`, `jsonl`, `docx`, `pdf` -- the exact
/// strings [`redact_file`] accepts.
///
/// # Errors
///
/// When the bytes exceed [`MAX_FILE_BYTES`], or match no format this crate can
/// sweep. A zip that is not a `.docx` lands in the second case deliberately.
#[wasm_bindgen(js_name = detectFormat)]
pub fn detect_file_format(bytes: &[u8]) -> std::result::Result<String, JsError> {
    to_js(detect_inner(bytes).map(|format| format.name().to_owned()))
}

fn detect_inner(bytes: &[u8]) -> std::result::Result<Format, FilesError> {
    check_size(bytes)?;
    // `None` for the name: this binding is never given one, which removes the
    // whole class of bug where a caller's extension overrides the bytes.
    detect_format(bytes, None).ok_or(FilesError::Undetectable)
}

fn check_size(bytes: &[u8]) -> std::result::Result<(), FilesError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(FilesError::TooLarge { bytes: bytes.len() });
    }
    Ok(())
}

/// De-identify a whole file and hand back the rewritten bytes.
///
/// `format` is a name from [`detect_file_format`]. It is a parameter rather
/// than re-sniffed internally so a surface can show the user what it detected
/// and let them refuse before anything is rewritten.
///
/// `tier` must be [`Tier::SafeHarbor`]. Expert Determination is REFUSED rather
/// than silently degraded: L3 needs a host-run local model completion, and a
/// caller who asked for the tier that sweeps quasi-identifiers must not receive
/// an un-swept file that looks swept.
///
/// # Errors
///
/// Everything is an error and nothing is a partial success. A scanned page, an
/// encrypted PDF, a page whose fonts cannot be decoded, a failed verification,
/// an oversized input and a short salt all return here with no bytes. The
/// message carries page numbers, part names, PDF keys, lengths and indices --
/// never document text (I4).
#[wasm_bindgen(js_name = redactFile)]
pub fn redact_file(
    bytes: &[u8],
    format: &str,
    tier: Tier,
    salt_key_material: &[u8],
    allow_images: bool,
) -> std::result::Result<RedactedFile, JsError> {
    to_js(redact_inner(
        bytes,
        format,
        tier,
        salt_key_material,
        allow_images,
    ))
}

/// [`redact_file`] without the JS error wrapping.
///
/// Split for the reason the text entry points are split: `JsError::new` panics
/// on a non-wasm target, so every failure path of an exported function is
/// unreachable from a host-target test. The refusals are the most
/// safety-relevant behaviour in this module, so they are the last thing that
/// may go untested.
fn redact_inner(
    bytes: &[u8],
    format: &str,
    tier: Tier,
    key_material: &[u8],
    allow_images: bool,
) -> std::result::Result<RedactedFile, FilesError> {
    check_size(bytes)?;
    if tier == Tier::ExpertDetermination {
        return Err(FilesError::NoContextualSweep);
    }
    let format = format_named(format).ok_or(FilesError::UnknownFormat)?;
    let pipeline = configured(tier.into(), Some(key_material))?;
    let masker = Masker::new(&pipeline);
    // `allowImages` is the browser spelling of the CLI's `--allow-images`, and
    // it buys the same thing: continuation, not silence. The images are
    // reported on the result either way.
    let options = Options {
        images: if allow_images {
            ImagePolicy::Warn
        } else {
            ImagePolicy::Refuse
        },
    };
    let output = mask_file_with(&masker, bytes, format, options)?;
    Ok(RedactedFile::new(format, output, options))
}

/// One de-identified file.
///
/// NO `Debug`, deliberately: the struct holds a text preview of the document,
/// and a derived `Debug` would put it in the first `{:?}` anyone writes. The
/// text is reachable only through [`RedactedFile::preview`], which is a place a
/// reviewer can point at.
#[wasm_bindgen]
pub struct RedactedFile {
    format: &'static str,
    bytes: Vec<u8>,
    report: Report,
    verification: FileVerification,
    preview: String,
    preview_truncated: bool,
    preview_available: bool,
}

impl RedactedFile {
    fn new(format: Format, output: Output, options: Options) -> Self {
        let verification = FileVerification {
            method: output.verification.method,
            checks: output.verification.checks,
            identifiers_checked: output.verification.identifiers_checked,
        };
        // THE PREVIEW IS TAKEN FROM THE OUTPUT, never from the input. It is
        // what a text extractor recovers from the file the user is about to
        // download, which is the only preview worth showing: a preview of the
        // input would show the reader the identifiers instead of proving they
        // are gone.
        let (preview, preview_truncated, preview_available) =
            // UNDER THE SAME OPTIONS the redaction ran with. Re-reading the
            // output under the default policy would refuse the very file this
            // call just produced, and the reader would lose the preview as a
            // side effect of having been warned about images.
            match deid_tr_files::extract_with(&output.bytes, format, options) {
                Ok(parts) => {
                    let joined = parts
                        .into_iter()
                        .map(|part| format!("--- {} ---\n{}", part.name, part.text))
                        .collect::<Vec<_>>()
                        .join("\n\n");
                    truncate_on_char_boundary(joined)
                }
                // Reported rather than raised. The bytes were already verified;
                // an extractor that cannot re-read them is a fact worth
                // surfacing, but it is not a reason to withhold a file whose
                // redaction was proved by a stronger check than this one.
                Err(_) => (String::new(), false, false),
            };
        Self {
            format: format.name(),
            bytes: output.bytes,
            report: output.report,
            verification,
            preview,
            preview_truncated,
            preview_available,
        }
    }
}

/// Cut a preview to [`PREVIEW_BYTES`] without splitting a character.
///
/// Turkish is multi-byte UTF-8, so a naive byte truncation lands inside `ş` or
/// `ğ` and produces a string that cannot cross to JS.
fn truncate_on_char_boundary(text: String) -> (String, bool, bool) {
    if text.len() <= PREVIEW_BYTES {
        return (text, false, true);
    }
    let mut cut = PREVIEW_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_owned(), true, true)
}

#[wasm_bindgen]
impl RedactedFile {
    /// The rewritten file. Hand this straight to a `Blob`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// The format that was processed.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn format(&self) -> String {
        self.format.to_owned()
    }

    /// How many spans were removed across the whole document.
    #[wasm_bindgen(getter, js_name = maskedCount)]
    #[must_use]
    pub fn masked_count(&self) -> usize {
        self.report.masked
    }

    /// The span map: how many entries it has.
    #[wasm_bindgen(getter, js_name = spanCount)]
    #[must_use]
    pub fn span_count(&self) -> usize {
        self.report.spans.len()
    }

    /// One entry of the span map.
    ///
    /// CARRIES NO OFFSET INTO THE FILE, and that is a statement about the
    /// formats rather than an omission. An identifier in a `.docx` was found in
    /// a joined scan buffer that existed for one function call; one in a PDF was
    /// found in a decoded content stream. Neither position means anything to a
    /// caller holding the original bytes, so a number would be decoration a
    /// reviewer might trust. What was removed, how long it was, which layer
    /// found it and whether arithmetic proved it are all real.
    #[must_use]
    pub fn span(&self, index: usize) -> Option<FileSpan> {
        self.report.spans.get(index).map(|record| FileSpan {
            label: record.label.clone(),
            layer: record.layer.clone(),
            byte_len: record.byte_len,
            confidence: record.confidence,
            checksum_validated: record.checksum_validated,
            replacement: record.replacement.clone(),
        })
    }

    /// How many pages or parts the summary has.
    #[wasm_bindgen(getter, js_name = partCount)]
    #[must_use]
    pub fn part_count(&self) -> usize {
        self.report.parts.len()
    }

    /// One page or one package part, and what came out of it.
    ///
    /// A part with a count of zero was READ AND FOUND CLEAN, which is a
    /// different fact from a part that was never reached -- and for a PDF it is
    /// the fact a reviewer most needs, because it is how a page of a six-page
    /// document that yielded nothing becomes visible instead of implied.
    #[must_use]
    pub fn part(&self, index: usize) -> Option<FilePart> {
        self.report.parts.get(index).map(|part| FilePart {
            name: part.name.clone(),
            masked: part.masked,
        })
    }

    /// How many structures were removed wholesale.
    #[wasm_bindgen(getter, js_name = strippedCount)]
    #[must_use]
    pub fn stripped_count(&self) -> usize {
        self.report.stripped.len()
    }

    /// One removed structure, by PDF key or part name.
    ///
    /// Structural names only -- `/Info`, `/JavaScript`, `dc:creator` -- never
    /// what they held.
    #[must_use]
    pub fn stripped(&self, index: usize) -> Option<String> {
        self.report.stripped.get(index).cloned()
    }

    /// What was checked on the returned bytes before they were returned.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn verification(&self) -> FileVerification {
        self.verification.clone()
    }

    /// The text a reader recovers from the REDACTED file.
    ///
    /// DOCUMENT TEXT, and the only such text this module returns. It is
    /// post-redaction, so it holds nothing the caller does not already have in
    /// [`RedactedFile::bytes`] -- but it is still a clinical note, it still
    /// contains every person name (deid-tr masks none), and it must not be
    /// logged, posted or persisted anywhere the file itself would not be.
    ///
    /// It is produced by the same decoder the redactor scanned with, so what is
    /// shown is what was read. A preview that came from a second reader could
    /// display a page as clean that the redactor never saw.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn preview(&self) -> String {
        self.preview.clone()
    }

    /// True when [`RedactedFile::preview`] is only the start of the document.
    #[wasm_bindgen(getter, js_name = previewTruncated)]
    #[must_use]
    pub fn preview_truncated(&self) -> bool {
        self.preview_truncated
    }

    /// False when the output could not be re-read for a preview.
    ///
    /// Distinguished from an empty preview on purpose: "the redacted file
    /// contains no text" and "we could not read the redacted file back" must
    /// not look the same to a user deciding whether to trust it.
    #[wasm_bindgen(getter, js_name = previewAvailable)]
    #[must_use]
    pub fn preview_available(&self) -> bool {
        self.preview_available
    }

    /// The sentence a surface must show beside this result.
    ///
    /// A getter rather than prose in the panel, so it cannot drift into
    /// something more reassuring than the tool has earned.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn disclosure(&self) -> String {
        Report::rule_detectable_only().to_owned()
    }

    /// How many pages carry images whose pixels were not read.
    ///
    /// NON-ZERO ONLY WHEN THE CALLER PASSED `allowImages`, because the default
    /// returns no file at all in that situation. Zero therefore means what a
    /// reader would hope it means: nothing on any page was skipped for being a
    /// picture.
    #[wasm_bindgen(getter, js_name = imageWarningCount)]
    #[must_use]
    pub fn image_warning_count(&self) -> usize {
        self.report.images.len()
    }

    /// One page's images: the page number, the count and every pixel size.
    ///
    /// Rendered by the same `Display` the CLI prints and the refusal message
    /// carries, so the panel cannot describe this more gently than the terminal
    /// does.
    #[must_use]
    pub fn image_warning(&self, index: usize) -> Option<String> {
        self.report
            .images
            .get(index)
            .map(std::string::ToString::to_string)
    }

    /// The sentence that goes with a non-empty [`RedactedFile::image_warning`]
    /// list.
    #[wasm_bindgen(getter, js_name = imagesDisclosure)]
    #[must_use]
    pub fn images_disclosure(&self) -> String {
        Report::images_not_read().to_owned()
    }
}

/// One entry of the span map. No offsets, no covered text -- see
/// [`RedactedFile::span`].
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct FileSpan {
    label: String,
    layer: String,
    byte_len: usize,
    confidence: f32,
    checksum_validated: bool,
    replacement: String,
}

#[wasm_bindgen]
impl FileSpan {
    /// The schema label, e.g. `TCKN`, `PHONE`, `EMAIL`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn label(&self) -> String {
        self.label.clone()
    }

    /// Which layer proposed it: `rules`, `ner` or `context`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn layer(&self) -> String {
        self.layer.clone()
    }

    /// How many bytes were removed. A length is not an identifier.
    #[wasm_bindgen(getter, js_name = byteLen)]
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// Confidence at the point of decision.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    /// True when arithmetic actually proved this one.
    #[wasm_bindgen(getter, js_name = checksumValidated)]
    #[must_use]
    pub fn checksum_validated(&self) -> bool {
        self.checksum_validated
    }

    /// What was put in its place. Synthetic, so not an egress.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn replacement(&self) -> String {
        self.replacement.clone()
    }
}

/// One page or package part of the summary.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct FilePart {
    name: String,
    masked: usize,
}

#[wasm_bindgen]
impl FilePart {
    /// A structural name: `page 3`, `word/footer1.xml`, `document`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// How many spans were removed from it. Zero means read and clean.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn masked(&self) -> usize {
        self.masked
    }
}

/// What ran against the output bytes, and what it looked for.
///
/// EXISTS SO THE PANEL CAN NAME THE CHECKS. A redaction whose verification did
/// not run is an unverified redaction, and a browser user cannot open
/// `pdftotext` to find out which it was. Since a failed check returns an error
/// and no bytes, the presence of this object is itself the pass -- but a pass
/// with its checks listed is a result, and a pass with nothing behind it is a
/// badge.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct FileVerification {
    method: &'static str,
    checks: Vec<&'static str>,
    identifiers_checked: usize,
}

#[wasm_bindgen]
impl FileVerification {
    /// Which verifier ran: `pdf-reopen` or `output-scan`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn method(&self) -> String {
        self.method.to_owned()
    }

    /// How many checks it performed.
    #[wasm_bindgen(getter, js_name = checkCount)]
    #[must_use]
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// One check, in the order it ran.
    #[must_use]
    pub fn check(&self, index: usize) -> Option<String> {
        self.checks.get(index).map(|check| (*check).to_owned())
    }

    /// How many removed identifiers were hunted for in the output.
    ///
    /// ZERO IS NOT A CLEAN BILL OF HEALTH. It means nothing was removed, so the
    /// scan had nothing to look for. A surface should say "nothing detected",
    /// not "verified clean" -- especially given deid-tr detects no names.
    #[wasm_bindgen(getter, js_name = identifiersChecked)]
    #[must_use]
    pub fn identifiers_checked(&self) -> usize {
        self.identifiers_checked
    }
}

/// The one place a file error becomes a JS exception.
fn to_js<T>(outcome: std::result::Result<T, FilesError>) -> std::result::Result<T, JsError> {
    outcome.map_err(|error| JsError::new(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a PDF from object bodies.
    ///
    /// The cross-reference table is a stub on purpose: the loader SCANS for
    /// objects rather than trusting the xref, so a fixture that hand-computed
    /// offsets would be testing the fixture builder. Duplicated from
    /// `bindings/files/tests/pdf_true_redaction.rs` rather than shared, because
    /// a fixture helper exported from the library would be shipped code that
    /// exists only for tests.
    fn build_pdf(objects: &[(u32, String)], trailer: &str) -> Vec<u8> {
        let mut out = String::from("%PDF-1.7\n");
        for (number, body) in objects {
            out.push_str(&format!("{number} 0 obj\n{body}\nendobj\n"));
        }
        out.push_str("xref\n0 1\n0000000000 65535 f \n");
        out.push_str(&format!("trailer\n{trailer}\nstartxref\n0\n%%EOF\n"));
        out.into_bytes()
    }

    fn stream(body: &str) -> String {
        format!("<< /Length {} >>\nstream\n{body}\nendstream", body.len())
    }

    /// A one-page PDF whose page carries real, extractable text.
    fn text_page_pdf(text: &str) -> Vec<u8> {
        build_pdf(
            &[
                (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
                (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
                (
                    3,
                    "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
                     /Contents 4 0 R >>"
                        .to_owned(),
                ),
                (4, stream(&format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET"))),
                (
                    5,
                    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
                ),
            ],
            "<< /Size 6 /Root 1 0 R >>",
        )
    }

    /// A one-page PDF whose only content is an image: a scan.
    fn scanned_page_pdf() -> Vec<u8> {
        build_pdf(
            &[
                (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
                (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
                (
                    3,
                    "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> \
                     /Contents 5 0 R >>"
                        .to_owned(),
                ),
                (
                    4,
                    "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /Length 4 >>\n\
                     stream\n\x00\x01\x02\x03\nendstream"
                        .to_owned(),
                ),
                (5, stream("q 612 0 0 792 0 0 cm /Im0 Do Q")),
            ],
            "<< /Size 6 /Root 1 0 R >>",
        )
    }

    /// A checksum-valid TCKN, COMPUTED rather than written down (I8).
    fn valid_tckn() -> String {
        const STEM: [u32; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let odd: u32 = STEM.iter().step_by(2).sum();
        let even: u32 = STEM.iter().skip(1).step_by(2).sum();
        let tenth = (odd * 7 + 100 - even) % 10;
        let eleventh = (STEM.iter().sum::<u32>() + tenth) % 10;
        let mut digits = STEM.to_vec();
        digits.push(tenth);
        digits.push(eleventh);
        digits.iter().map(|digit| digit.to_string()).collect()
    }

    const SALT: &[u8] = &[0x5au8; 32];

    #[test]
    fn the_format_comes_from_the_bytes_and_not_from_a_name() {
        // THE POINT OF `detectFormat`. This binding is never given a file name,
        // so a `.pdf` extension on a zip cannot mislead it -- there is no
        // parameter through which the lie could arrive.
        assert_eq!(detect_inner(b"%PDF-1.7\n").expect("pdf").name(), "pdf");
        assert_eq!(detect_inner(b"Hasta notu.\n").expect("txt").name(), "txt");
        assert_eq!(
            detect_inner(b"{\"a\":1}\n{\"b\":2}\n")
                .expect("jsonl")
                .name(),
            "jsonl"
        );
        // A zip that is not a .docx is refused rather than guessed at.
        assert!(detect_inner(b"PK\x03\x04rubbish").is_err());
    }

    #[test]
    fn a_text_file_is_redacted_through_the_same_crate_the_cli_runs() {
        let tckn = valid_tckn();
        let source = format!("Hasta Ayşe Yılmaz, TCKN {tckn}.\n");
        let result = redact_inner(source.as_bytes(), "txt", Tier::SafeHarbor, SALT, false)
            .expect("redaction");
        assert!(
            !result
                .bytes
                .windows(tckn.len())
                .any(|window| window == tckn.as_bytes()),
            "the TCKN survived"
        );
        assert_eq!(result.masked_count(), 1);
        assert_eq!(result.span_count(), 1);
        let span = result.span(0).expect("one span");
        assert_eq!(span.label(), "TCKN");
        assert_eq!(span.layer(), "rules");
        assert!(span.checksum_validated());
        assert_eq!(span.byte_len(), 11);
    }

    #[test]
    fn the_name_survives_and_the_disclosure_says_so() {
        // THE HONESTY TEST, repeated at this boundary because a new surface is
        // a new chance for a user to believe the output is name-free. deid-tr
        // masks ZERO names: no L2 model exists.
        let result = redact_inner(
            "Hasta Ayşe Yılmaz muayene edildi.\n".as_bytes(),
            "txt",
            Tier::SafeHarbor,
            SALT,
            false,
        )
        .expect("redaction");
        let text = String::from_utf8(result.bytes.clone()).expect("utf-8");
        assert!(text.contains("Ayşe Yılmaz"), "{text}");
        assert_eq!(result.masked_count(), 0);
        assert!(result.disclosure().contains("does NOT mask person names"));
        // And the preview shows the reader exactly that, rather than implying
        // the name is gone.
        assert!(result.preview().contains("Ayşe Yılmaz"));
    }

    #[test]
    fn verification_is_reported_by_name_rather_than_as_a_tick() {
        let tckn = valid_tckn();
        let result = redact_inner(
            format!("TCKN {tckn}\n").as_bytes(),
            "txt",
            Tier::SafeHarbor,
            SALT,
            false,
        )
        .expect("redaction");
        let verification = result.verification();
        assert_eq!(verification.method(), "output-scan");
        assert!(verification.check_count() >= 3);
        assert!(verification.check(0).expect("a check").contains("absent"));
        assert_eq!(verification.identifiers_checked(), 1);
    }

    #[test]
    fn expert_determination_is_refused_rather_than_degraded_to_safe_harbor() {
        // The single most dangerous silent failure this surface could have: a
        // caller asks for the tier that sweeps quasi-identifiers and gets back
        // a file that was never swept but looks processed.
        let outcome = redact_inner(b"nothing\n", "txt", Tier::ExpertDetermination, SALT, false);
        let Err(error) = outcome else {
            panic!("Expert Determination must not silently run Safe Harbor");
        };
        assert!(format!("{error}").contains("Expert Determination"));
    }

    #[test]
    fn a_file_over_the_ceiling_fails_with_both_numbers_and_no_allocation_storm() {
        // Failing cleanly and specifically, rather than dying inside an
        // allocator with the panel taking the tab down.
        let oversized = vec![b'a'; MAX_FILE_BYTES + 1];
        let Err(error) = redact_inner(&oversized, "txt", Tier::SafeHarbor, SALT, false) else {
            panic!("the ceiling was not enforced");
        };
        let rendered = format!("{error}");
        assert!(rendered.contains(&MAX_FILE_BYTES.to_string()));
        assert!(rendered.contains(&(MAX_FILE_BYTES + 1).to_string()));
        // The same ceiling gates detection, so a surface can refuse before it
        // ever reaches the redactor.
        assert!(detect_inner(&oversized).is_err());
    }

    #[test]
    fn an_unknown_format_name_is_refused_rather_than_defaulted_to_text() {
        // Defaulting to text for an unrecognised name is how a PDF gets its
        // compressed bytes rewritten while every identifier stays put.
        assert!(redact_inner(b"hello", "docm", Tier::SafeHarbor, SALT, false).is_err());
    }

    #[test]
    fn a_scanned_page_is_refused_by_number_and_returns_no_bytes() {
        // PROPERTY 3, at this boundary. A page whose text is pixels cannot be
        // redacted without OCR, which this does not have. Returning a
        // cheerful-looking file for a scan somebody believes is redacted is the
        // worst outcome this feature could produce.
        let pdf = scanned_page_pdf();
        let outcome = redact_inner(&pdf, "pdf", Tier::SafeHarbor, SALT, false);
        let Err(error) = outcome else {
            panic!("a scanned page must be refused, not passed through");
        };
        let rendered = format!("{error}");
        assert!(rendered.contains("page 1"), "{rendered}");
        assert!(rendered.contains("OCR"), "{rendered}");
    }

    /// A one-page PDF with a real text layer AND two images in it.
    ///
    /// The hybrid case, at the browser boundary. Sizes taken from a measured
    /// clinical sample: a 102x102 image in a Turkish report is very often a QR
    /// code carrying the protokol number.
    fn text_page_with_images_pdf(text: &str) -> Vec<u8> {
        build_pdf(
            &[
                (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
                (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
                (
                    3,
                    "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> \
                     /XObject << /Im0 6 0 R /Im1 7 0 R >> >> /Contents 4 0 R >>"
                        .to_owned(),
                ),
                (
                    4,
                    stream(&format!(
                        "BT /F1 12 Tf 72 720 Td ({text}) Tj ET q 102 0 0 102 60 60 cm /Im0 Do Q \
                         q 320 0 0 38 60 200 cm /Im1 Do Q"
                    )),
                ),
                (
                    5,
                    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
                ),
                (
                    6,
                    "<< /Type /XObject /Subtype /Image /Width 102 /Height 102 /Length 4 >>\n\
                     stream\n\x00\x01\x02\x03\nendstream"
                        .to_owned(),
                ),
                (
                    7,
                    "<< /Type /XObject /Subtype /Image /Width 320 /Height 38 /Length 4 >>\n\
                     stream\n\x00\x01\x02\x03\nendstream"
                        .to_owned(),
                ),
            ],
            "<< /Size 8 /Root 1 0 R >>",
        )
    }

    #[test]
    fn a_page_with_text_and_images_is_refused_here_too_unless_allowed() {
        // The panel is the surface where a user is least able to check by hand:
        // no `pdfimages`, no terminal, just a download button. So it gets the
        // same default the CLI has, from the same code.
        let tckn = valid_tckn();
        let pdf = text_page_with_images_pdf(&format!("TCKN {tckn}"));
        let Err(error) = redact_inner(&pdf, "pdf", Tier::SafeHarbor, SALT, false) else {
            panic!("a page carrying images must be refused by default");
        };
        let rendered = format!("{error}");
        assert!(rendered.contains("page 1"), "{rendered}");
        assert!(rendered.contains("102x102"), "{rendered}");
        assert!(rendered.contains("320x38"), "{rendered}");
        // I4: the refusal describes pixels, never the page.
        assert!(!rendered.contains(&tckn), "{rendered}");
    }

    #[test]
    fn allowing_images_returns_a_file_that_states_what_was_not_read() {
        // And the statement is reachable from JS by a named getter, so a panel
        // cannot render the result without it being available -- the same list,
        // rendered by the same `Display` the terminal prints.
        let tckn = valid_tckn();
        let pdf = text_page_with_images_pdf(&format!("TCKN {tckn}"));
        let result =
            redact_inner(&pdf, "pdf", Tier::SafeHarbor, SALT, true).expect("allowed redaction");
        assert!(
            !result
                .bytes
                .windows(tckn.len())
                .any(|window| window == tckn.as_bytes()),
            "the TCKN survived"
        );
        assert_eq!(result.image_warning_count(), 1);
        let warning = result.image_warning(0).expect("one warning");
        assert!(warning.contains("page 1"), "{warning}");
        assert!(warning.contains("102x102"), "{warning}");
        assert!(warning.contains("320x38"), "{warning}");
        assert!(warning.contains("HEURISTIC"), "{warning}");
        assert!(!warning.contains(&tckn), "{warning}");
        assert!(result
            .images_disclosure()
            .contains("NOT fully de-identified"));
        // The preview still works: re-reading the output must not refuse the
        // file this very call produced.
        assert!(result.preview_available());
    }

    #[test]
    fn a_pdf_with_no_images_reports_no_image_warning() {
        let tckn = valid_tckn();
        let result = redact_inner(
            &text_page_pdf(&format!("TCKN {tckn}")),
            "pdf",
            Tier::SafeHarbor,
            SALT,
            true,
        )
        .expect("redaction");
        assert_eq!(result.image_warning_count(), 0);
        assert!(result.image_warning(0).is_none());
    }

    #[test]
    fn a_pdf_is_truly_redacted_and_its_verification_names_the_checks_that_ran() {
        // PROPERTIES 1 AND 2, at this boundary. `pdf::redact` deletes the glyph
        // codes and re-opens its own output; reaching this assertion at all
        // means verification passed, because a failure returns an error and no
        // bytes.
        let tckn = valid_tckn();
        let pdf = text_page_pdf(&format!("TCKN {tckn}"));
        let result = redact_inner(&pdf, "pdf", Tier::SafeHarbor, SALT, false).expect("redaction");

        assert!(
            !result
                .bytes
                .windows(tckn.len())
                .any(|window| window == tckn.as_bytes()),
            "the TCKN is still in the output bytes"
        );
        let verification = result.verification();
        assert_eq!(verification.method(), "pdf-reopen");
        assert!(verification.check_count() >= 5);
        let checks: Vec<String> = (0..verification.check_count())
            .filter_map(|index| verification.check(index))
            .collect();
        assert!(checks.iter().any(|check| check.contains("%%EOF")));
        assert!(checks.iter().any(|check| check.contains("re-parsed")));
        // Per-page summary, including pages that were read and found clean.
        assert_eq!(result.part_count(), 1);
        assert_eq!(result.part(0).expect("page 1").name(), "page 1");
    }

    #[test]
    fn an_error_never_carries_document_text() {
        // I4 at the JS boundary. A malformed-PDF error that echoes the
        // malformed bytes is a PHI leak from a file too broken to redact.
        const MARKER: &str = "Ayşe Yılmaz";
        let broken = format!("%PDF-1.7\n{MARKER} and then rubbish with no catalogue\n");
        let Err(error) = redact_inner(broken.as_bytes(), "pdf", Tier::SafeHarbor, SALT, false)
        else {
            panic!("a PDF with no catalogue must fail");
        };
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(MARKER), "{rendered}");
    }

    #[test]
    fn a_salt_the_host_did_not_take_seriously_is_refused() {
        let outcome = redact_inner(b"nothing\n", "txt", Tier::SafeHarbor, b"tooshort", false);
        let Err(error) = outcome else {
            panic!("a short salt must be an error, not a quiet stretch");
        };
        assert!(!format!("{error}").contains("nothing"));
    }

    #[test]
    fn the_preview_is_taken_from_the_output_and_not_from_the_input() {
        // A preview of the INPUT would show the reader the identifier and imply
        // it was removed. This one is the text a extractor recovers from the
        // file they are about to download.
        let tckn = valid_tckn();
        let result = redact_inner(
            format!("TCKN {tckn}\n").as_bytes(),
            "txt",
            Tier::SafeHarbor,
            SALT,
            false,
        )
        .expect("redaction");
        assert!(result.preview_available());
        assert!(!result.preview().contains(&tckn));
        assert!(!result.preview_truncated());
    }

    #[test]
    fn a_long_document_is_truncated_on_a_character_boundary() {
        // Turkish is multi-byte UTF-8, so a naive byte cut lands inside `ş`.
        let doc = "şğüöçİ".repeat(PREVIEW_BYTES);
        let result =
            redact_inner(doc.as_bytes(), "txt", Tier::SafeHarbor, SALT, false).expect("redaction");
        assert!(result.preview_truncated());
        assert!(result.preview().len() <= PREVIEW_BYTES);
    }
}
