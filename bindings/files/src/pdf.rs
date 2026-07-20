//! TRUE PDF redaction: the text is REMOVED, and the output is verified.
//!
//! # The threat this module is built against
//!
//! Drawing a black rectangle over text is not redaction. The glyph codes stay
//! in the content stream and every extractor, every copy-paste and every
//! `pdftotext` recovers them. That is the mechanism behind the Manafort court
//! filing and the EU/AstraZeneca contract leaks. So this module edits the
//! decoded content stream and deletes the operand bytes, and it draws nothing
//! in their place.
//!
//! A tool that silently produces fake redaction is worse than no tool, because
//! someone will trust it. Every path here therefore either removes the text and
//! proves it, or FAILS. There is no third outcome and no flag that creates one.
//!
//! # What is swept, beyond the page
//!
//! Redacting only the page content stream is insufficient. Handled here:
//!
//! * **Incremental update history** -- the output is fully rewritten from the
//!   objects reachable from the current catalogue, so no previous revision can
//!   survive. See `document.rs` and `writer.rs`.
//! * **Object streams** -- expanded on load, so nothing hides inside another
//!   object where a grep cannot see it.
//! * **The Info dictionary** -- not emitted at all.
//! * **XMP metadata** (`/Metadata`, on the catalogue, pages and images).
//! * **Annotations** -- `/Contents`, `/TU`, `/RC`, `/A /URI` are swept;
//!   `/Redact` annotations (an unapplied redaction is a MARKER, not a
//!   redaction) and `/FileAttachment` annotations are removed entirely.
//! * **AcroForm** -- field values and `/XFA`, which duplicates every value in
//!   an XML payload that page-level redaction never touches.
//! * **Embedded file attachments** and **JavaScript**, both removed.
//! * **Bookmarks / outlines** -- the AstraZeneca leak was exactly this.
//! * **Named destinations**, **page thumbnails** (`/Thumb`, a rasterisation of
//!   the PRE-redaction page), **`/PieceInfo`** and the **structure tree**,
//!   whose `/Alt` strings duplicate page text for accessibility.
//!
//! # Scanned pages are REFUSED
//!
//! If a page yields no extractable text, the identifiers on it are pixels. This
//! crate has no OCR and no image editor, so it cannot redact them -- and a
//! text-extraction check over a raster page returns "no PHI found" VACUOUSLY.
//! Such a page is refused by number ([`PdfError::ScannedPage`]) rather than
//! passed through looking processed.
//!
//! # HONEST SCOPE
//!
//! Only rule-detectable identifiers are removed from page text: TCKN, VKN,
//! IBAN, phone, email, MRN, date. **Person names and institution names are NOT
//! removed** -- no trained model is installed. A redacted PDF from this tool is
//! not name-free. See [`crate::Report::rule_detectable_only`].

pub mod content;
pub mod document;
pub mod font;
pub mod object;
pub mod verify;
pub mod writer;

use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet};

use crate::masker::Masker;
use document::{decode_stream, Document};
use font::Font;
use object::{Dict, Object};
pub use verify::{verify, Survival, VerificationFailure};

/// A PDF this crate will not process, or could not.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PdfError {
    /// The bytes do not start with `%PDF-`.
    #[error("the file is not a PDF")]
    NotAPdf,
    /// No `/Root` was found in any trailer.
    #[error("the PDF has no document catalogue")]
    NoCatalogue,
    /// The catalogue has no page tree.
    #[error("the PDF has no pages")]
    NoPages,
    /// The PDF is encrypted.
    ///
    /// REFUSED, not passed through. This crate cannot decrypt, so it cannot
    /// read the text, so it cannot prove it removed anything.
    #[error("the PDF is encrypted; deid-tr cannot read it and will not pretend to redact it")]
    Encrypted,
    /// A page has no extractable text but does have images.
    #[error(
        "page {page} is a scanned image with no extractable text. deid-tr has no OCR and cannot \
         redact pixels; it will not return a file that looks processed and is not"
    )]
    ScannedPage {
        /// One-based page number.
        page: usize,
    },
    /// A page carries an invisible OCR text layer over a raster image.
    ///
    /// `3 Tr` is the rendering mode that draws nothing, and it is how every OCR
    /// tool attaches searchable text to a scan. Redacting that layer removes
    /// the SEARCHABLE copy and leaves the identifier visible in the pixels --
    /// the most convincing fake redaction this crate could produce, because the
    /// output passes a text-extraction check while the page still shows the
    /// name.
    #[error(
        "page {page} is a scan with an invisible OCR text layer. Redacting the text layer would \
         leave the identifier visible in the image; deid-tr has no OCR or image editor and refuses"
    )]
    ScannedWithTextLayer {
        /// One-based page number.
        page: usize,
    },
    /// A page uses fonts this crate cannot decode.
    #[error(
        "page {page} uses {codes} glyph codes with no /ToUnicode mapping, so its text cannot be \
         read and therefore cannot be redacted"
    )]
    UnreadablePage {
        /// One-based page number.
        page: usize,
        /// How many codes could not be decoded.
        codes: usize,
    },
    /// A content stream uses a filter this crate does not implement.
    #[error("a content stream on page {page} uses a filter deid-tr cannot decode")]
    UndecodableStream {
        /// One-based page number.
        page: usize,
    },
    /// A stream never terminated.
    #[error("a stream in the PDF was never terminated")]
    UnterminatedStream,
    /// The object parser refused the bytes.
    #[error("the PDF could not be parsed")]
    Parse(#[from] object::ParseError),
    /// The output failed its own verification.
    ///
    /// THE POINT OF THE MODULE. A file that reaches this arm is not returned.
    #[error("redaction could not be verified: {0}")]
    NotVerified(#[from] VerificationFailure),
}

/// What a redaction did.
///
/// Counts and structural names only, so this is safe to print (I4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Redaction {
    /// The rewritten, verified PDF.
    pub bytes: Vec<u8>,
    /// How many spans were removed from page content.
    pub removed_from_pages: usize,
    /// How many spans were removed from non-page strings.
    pub removed_from_objects: usize,
    /// How many pages were processed.
    pub pages: usize,
    /// How many revisions the INPUT carried. Above 1 means it was saved
    /// incrementally and was carrying its own history.
    pub input_revisions: usize,
    /// Structures removed wholesale, by PDF key.
    pub stripped: Vec<String>,
}

/// True when the bytes look like a PDF.
#[must_use]
pub fn is_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-")
}

/// Redact a PDF, then verify the result.
///
/// # Errors
///
/// [`PdfError`] for a document this crate refuses (encrypted, scanned,
/// undecodable) and for a verification failure, or whatever the pipeline
/// returns. On any error NO BYTES ARE RETURNED.
pub fn redact(masker: &Masker<'_>, bytes: &[u8]) -> Result<Redaction, crate::FileError> {
    let mut document = Document::load(bytes)?;
    let page_numbers = document.page_numbers()?;
    let mut report = Redaction {
        pages: page_numbers.len(),
        input_revisions: document.input_revisions,
        ..Redaction::default()
    };
    let mut originals: Vec<String> = Vec::new();

    for (index, page_number) in page_numbers.iter().enumerate() {
        let page = index + 1;
        let Some(dict) = document
            .objects
            .get(page_number)
            .and_then(Object::as_dict)
            .cloned()
        else {
            continue;
        };
        let (combined, parts) = page_streams(&document, &dict);
        if parts.is_empty() && !combined.is_empty() {
            return Err(PdfError::UndecodableStream { page }.into());
        }
        let fonts = page_fonts(&document, &dict);
        let operations = content::parse(&combined);
        let raster = has_raster_content(&document, &dict, &combined);
        if raster && has_invisible_text(&operations) {
            return Err(PdfError::ScannedWithTextLayer { page }.into());
        }
        let extraction = content::extract(&operations, &fonts);

        if extraction.undecodable > 0 {
            return Err(PdfError::UnreadablePage {
                page,
                codes: extraction.undecodable,
            }
            .into());
        }
        let text = extraction.text();
        if text.trim().is_empty() && raster {
            return Err(PdfError::ScannedPage { page }.into());
        }

        // TWO READINGS OF THE SAME PAGE, unioned. `text` carries the synthetic
        // separators that give a one-run page its word boundaries; `glued` drops
        // them, so an identifier the producer split across a kern adjustment or
        // across two show operators is contiguous in exactly one of the two. See
        // `Extraction::glued_text` for why neither reading alone is sufficient
        // and why the union is the safe direction (I2).
        let glued = extraction.glued_text();
        let mut ranges: Vec<Range<usize>> = Vec::new();
        for (view, is_glued) in [(&text, false), (&glued, true)] {
            if is_glued && glued == text {
                continue;
            }
            for edit in masker.replacements(view)? {
                let hit = if is_glued {
                    extraction.ranges_for_glued(edit.start..edit.end)
                } else {
                    extraction.ranges_for(edit.start..edit.end)
                };
                // An identifier that is contiguous in BOTH readings is one
                // occurrence found twice, not two occurrences. It resolves to
                // the same source bytes, which is what makes that decidable
                // here without re-deriving it from the offsets.
                if !hit.is_empty() && hit.iter().all(|range| ranges.contains(range)) {
                    continue;
                }
                report.removed_from_pages += 1;
                originals.push(edit.original);
                for range in hit {
                    if !ranges.contains(&range) {
                        ranges.push(range);
                    }
                }
            }
        }
        if ranges.is_empty() {
            continue;
        }
        for part in parts {
            let local: Vec<Range<usize>> = ranges
                .iter()
                .filter(|range| range.start >= part.at && range.end <= part.at + part.data.len())
                .map(|range| (range.start - part.at)..(range.end - part.at))
                .collect();
            if local.is_empty() {
                continue;
            }
            let edited = content::delete(&part.data, &local);
            if let Some(Object::Stream(stream_dict, body)) = document.objects.get_mut(&part.object)
            {
                *body = edited;
                stream_dict.remove("Filter");
                stream_dict.remove("DecodeParms");
            }
        }
    }

    strip_structures(&mut document, &page_numbers, &mut report.stripped);
    report.removed_from_objects = mask_object_strings(masker, &mut document, &mut originals)?;

    let root = match document.trailer.get("Root") {
        Some(Object::Reference(number, _)) => *number,
        _ => return Err(PdfError::NoCatalogue.into()),
    };
    let reachable = reachable_from(&document, root);
    let objects: BTreeMap<u32, Object> = document
        .objects
        .into_iter()
        .filter(|(number, _)| reachable.contains(number))
        .collect();

    let out = writer::write(&objects, root);
    // NOT OPTIONAL, and not a warning. A file that fails here is not returned.
    verify(&out, &originals).map_err(PdfError::NotVerified)?;
    report.bytes = out;
    Ok(report)
}

/// One decoded content stream and where it sits in the concatenation.
pub(crate) struct StreamPart {
    /// The object number, so the edited bytes can be written back.
    pub object: u32,
    /// Offset of this part in the combined buffer.
    pub at: usize,
    /// The decoded bytes.
    pub data: Vec<u8>,
}

/// Decode and concatenate a page's content streams.
///
/// CONCATENATED, because §7.8.2 says the streams of a `/Contents` array form a
/// single stream -- a producer may split one `Tj` across two of them. Scanning
/// each separately would miss an identifier that straddles the join.
pub(crate) fn page_streams(document: &Document, page: &Dict) -> (Vec<u8>, Vec<StreamPart>) {
    let mut references: Vec<u32> = Vec::new();
    match page.get("Contents") {
        Some(Object::Reference(number, _)) => match document.objects.get(number) {
            Some(Object::Array(items)) => references.extend(items.iter().filter_map(number_of)),
            _ => references.push(*number),
        },
        Some(Object::Array(items)) => references.extend(items.iter().filter_map(number_of)),
        _ => {}
    }

    let mut combined = Vec::new();
    let mut parts = Vec::new();
    for number in references {
        let Some(Object::Stream(dict, raw)) = document.objects.get(&number) else {
            continue;
        };
        let Some(data) = decode_stream(dict, raw) else {
            // Signalled to the caller by an empty part list against non-empty
            // content: an undecodable stream must not read as an empty page.
            combined.push(b' ');
            continue;
        };
        parts.push(StreamPart {
            object: number,
            at: combined.len(),
            data: data.clone(),
        });
        combined.extend_from_slice(&data);
        // §7.8.2: the streams are joined with at least one white-space byte, so
        // a token cannot be formed across the boundary by accident.
        combined.push(b'\n');
    }
    (combined, parts)
}

fn number_of(object: &Object) -> Option<u32> {
    match object {
        Object::Reference(number, _) => Some(*number),
        _ => None,
    }
}

/// Build the font table a page's `Tf` operators select from.
///
/// `/Resources` is INHERITABLE: a page may not have one and rely on an ancestor
/// in the page tree. A lookup that stops at the page finds no fonts, decodes
/// nothing, and reports a clean page.
pub(crate) fn page_fonts(document: &Document, page: &Dict) -> BTreeMap<String, Font> {
    let mut fonts = BTreeMap::new();
    let mut node = page.clone();
    for _ in 0..32 {
        if let Some(resources) = document.get(&node, "Resources").and_then(Object::as_dict) {
            if let Some(table) = document.get(resources, "Font").and_then(Object::as_dict) {
                for (name, value) in &table.0 {
                    if fonts.contains_key(name) {
                        continue;
                    }
                    if let Some(dict) = document.resolve(value).as_dict() {
                        fonts.insert(name.clone(), Font::load(document, dict));
                    }
                }
            }
        }
        let Some(parent) = document.get(&node, "Parent").and_then(Object::as_dict) else {
            break;
        };
        node = parent.clone();
    }
    fonts
}

/// True when a page carries raster content, which this crate cannot redact.
fn has_raster_content(document: &Document, page: &Dict, combined: &[u8]) -> bool {
    if !document::find_all(combined, b"BI ").is_empty() {
        return true;
    }
    let Some(resources) = document.get(page, "Resources").and_then(Object::as_dict) else {
        return false;
    };
    let Some(xobjects) = document.get(resources, "XObject").and_then(Object::as_dict) else {
        return false;
    };
    xobjects.0.iter().any(|(_, value)| {
        document
            .resolve(value)
            .as_dict()
            .and_then(|dict| dict.get("Subtype"))
            .and_then(Object::as_name)
            == Some("Image")
    })
}

/// True when the page draws text in the invisible rendering mode.
fn has_invisible_text(operations: &[content::Operation]) -> bool {
    operations.iter().any(|operation| {
        operation.operator == "Tr"
            && matches!(operation.operands.first(), Some(content::Value::Number(mode)) if (*mode - 3.0).abs() < f64::EPSILON)
    })
}

/// Keys removed from the catalogue outright.
const CATALOGUE_STRIP: &[&str] = &[
    "Metadata",
    "Names",
    "OpenAction",
    "AA",
    "AcroForm",
    "StructTreeRoot",
    "PieceInfo",
    "Outlines",
    "Dests",
    "SpiderInfo",
    "Legal",
];

/// Keys removed from every page.
const PAGE_STRIP: &[&str] = &["Metadata", "Thumb", "PieceInfo", "AA", "B"];

/// Annotation subtypes removed rather than swept.
const ANNOTATION_STRIP: &[&str] = &["Redact", "FileAttachment", "Movie", "Screen", "RichMedia"];

fn strip_structures(document: &mut Document, pages: &[u32], stripped: &mut Vec<String>) {
    // `/Outlines` and `/AcroForm` are removed rather than swept, and that is a
    // deliberate trade: bookmark titles and form field values are author text
    // whose content this crate cannot reliably scrub field by field, and losing
    // navigation is a smaller harm than shipping the AstraZeneca failure.
    if let Some(Object::Reference(root, _)) = document.trailer.get("Root").cloned() {
        if let Some(catalogue) = document
            .objects
            .get_mut(&root)
            .and_then(Object::as_dict_mut)
        {
            for key in CATALOGUE_STRIP {
                if catalogue.remove(key) {
                    stripped.push(format!("/{key}"));
                }
            }
        }
    }

    for page_number in pages {
        let annotations = document
            .objects
            .get(page_number)
            .and_then(Object::as_dict)
            .and_then(|dict| dict.get("Annots"))
            .cloned();
        if let Some(annotations) = annotations {
            let kept = filter_annotations(document, &annotations, stripped);
            if let Some(dict) = document
                .objects
                .get_mut(page_number)
                .and_then(Object::as_dict_mut)
            {
                dict.set("Annots", kept);
            }
        }
        if let Some(dict) = document
            .objects
            .get_mut(page_number)
            .and_then(Object::as_dict_mut)
        {
            for key in PAGE_STRIP {
                if dict.remove(key) {
                    stripped.push(format!("/{key}"));
                }
            }
        }
    }

    // `/Metadata` also hangs off image XObjects and off individual streams.
    let numbers: Vec<u32> = document.objects.keys().copied().collect();
    for number in numbers {
        if let Some(dict) = document
            .objects
            .get_mut(&number)
            .and_then(Object::as_dict_mut)
        {
            for key in ["Metadata", "PieceInfo", "JS", "JavaScript", "XFA"] {
                if dict.remove(key) {
                    stripped.push(format!("/{key}"));
                }
            }
        }
    }
    stripped.sort_unstable();
    stripped.dedup();
}

fn filter_annotations(
    document: &Document,
    annotations: &Object,
    stripped: &mut Vec<String>,
) -> Object {
    let items: Vec<Object> = match document.resolve(annotations) {
        Object::Array(items) => items.clone(),
        _ => return Object::Array(Vec::new()),
    };
    let kept: Vec<Object> = items
        .into_iter()
        .filter(|item| {
            let subtype = document
                .resolve(item)
                .as_dict()
                .and_then(|dict| dict.get("Subtype"))
                .and_then(Object::as_name)
                .unwrap_or_default()
                .to_owned();
            if ANNOTATION_STRIP.contains(&subtype.as_str()) {
                stripped.push(format!("/{subtype}"));
                return false;
            }
            true
        })
        .collect();
    Object::Array(kept)
}

/// Run the pipeline over every string in every object.
///
/// This is what reaches annotation contents, form field values, named
/// destinations and any string a producer invented -- everything that is text
/// but is not a content stream. Stream BODIES are excluded: their text is glyph
/// codes and was handled by the page pass.
fn mask_object_strings(
    masker: &Masker<'_>,
    document: &mut Document,
    originals: &mut Vec<String>,
) -> Result<usize, crate::FileError> {
    let numbers: Vec<u32> = document.objects.keys().copied().collect();
    let mut count = 0usize;
    for number in numbers {
        let Some(object) = document.objects.get(&number).cloned() else {
            continue;
        };
        let mut edited = object;
        count += mask_in(masker, &mut edited, originals)?;
        document.objects.insert(number, edited);
    }
    Ok(count)
}

fn mask_in(
    masker: &Masker<'_>,
    object: &mut Object,
    originals: &mut Vec<String>,
) -> Result<usize, crate::FileError> {
    let mut count = 0usize;
    match object {
        Object::Str(..) => {
            let Some(text) = object.as_text() else {
                return Ok(0);
            };
            let masked = masker.mask(&text)?;
            if masked.is_changed() {
                count += masked.originals.len();
                originals.extend(masked.originals);
                *object = Object::text(&masked.text);
            }
        }
        Object::Array(items) => {
            for item in items {
                count += mask_in(masker, item, originals)?;
            }
        }
        Object::Dict(dict) | Object::Stream(dict, _) => {
            for (_, value) in &mut dict.0 {
                count += mask_in(masker, value, originals)?;
            }
        }
        _ => {}
    }
    Ok(count)
}

/// Every object number reachable from the catalogue.
///
/// The output is built from THIS SET and nothing else, which is what makes a
/// previous revision structurally unable to survive: an object nobody points at
/// is never written.
fn reachable_from(document: &Document, root: u32) -> BTreeSet<u32> {
    let mut seen = BTreeSet::new();
    let mut queue = vec![root];
    while let Some(number) = queue.pop() {
        if !seen.insert(number) {
            continue;
        }
        if let Some(object) = document.objects.get(&number) {
            collect_references(object, &mut queue);
        }
    }
    seen
}

fn collect_references(object: &Object, out: &mut Vec<u32>) {
    match object {
        Object::Reference(number, _) => out.push(*number),
        Object::Array(items) => {
            for item in items {
                collect_references(item, out);
            }
        }
        Object::Dict(dict) | Object::Stream(dict, _) => {
            for (_, value) in &dict.0 {
                collect_references(value, out);
            }
        }
        _ => {}
    }
}
