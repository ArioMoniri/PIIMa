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
//! # A page with BOTH text and images is refused too, by default
//!
//! The refusal above only fires when a page has NO text at all. The common
//! shape of real hospital output is not that: it is a text layer WITH images
//! sitting in it -- a QR or barcode encoding the protokol or patient number, a
//! scanned signature, a letterhead. Redacting the text of such a page and
//! returning it reports success while every pixel survives byte-identical, and
//! that is the least safe path this crate could offer, because it is the one
//! that produces a file somebody believes is finished.
//!
//! So an image on an otherwise-processed page is reported by page number,
//! count and pixel size ([`PageImages`]), and by default it REFUSES
//! ([`PdfError::PageCarriesImages`]). [`ImagePolicy::Warn`] continues instead
//! and puts the same report in [`Redaction::images`], where every surface is
//! required to show it. There is no third setting, and no setting under which
//! images go unmentioned.
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

/// The largest edge, in pixels, at which an image is called plausible
/// decoration rather than plausible content.
///
/// SIXTEEN IS A GUESS WITH A REASON, not a measurement. Below it an image is
/// icon-sized: a bullet, a rule, a checkbox glyph. It is chosen to be small
/// enough that almost nothing legible fits, and it is deliberately NOT used to
/// decide policy -- see [`ImagePolicy`]. It only labels a line in a message, so
/// a reader looking at a list of sizes has some idea which ones to open first.
const DECORATION_MAX_EDGE: u32 = 16;

/// One image drawn on a page, by pixel size and nothing else.
///
/// `0 x 0` means the size was not stated where this crate could read it -- an
/// inline image, or an XObject with no `/Width`. THAT IS REPORTED AS UNKNOWN
/// rather than as small: an unknown size must never read as a reassuring one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageImage {
    /// Width in pixels, or zero when it could not be read.
    pub width: u32,
    /// Height in pixels, or zero when it could not be read.
    pub height: u32,
}

impl PageImage {
    /// True when the size is known.
    #[must_use]
    pub const fn has_size(self) -> bool {
        self.width > 0 && self.height > 0
    }

    /// True when this is small enough to be plausibly decorative.
    ///
    /// A HEURISTIC OVER PIXEL COUNTS, and the only claim it makes is about
    /// size. Nothing here decodes an image, so nothing here knows what one
    /// contains: a 102x102 image in a Turkish clinical report is very often a
    /// QR code carrying the protokol number, and this function cannot tell that
    /// from a 102x102 logo. An unknown size is never decorative.
    #[must_use]
    pub const fn plausible_decoration(self) -> bool {
        self.has_size() && self.width <= DECORATION_MAX_EDGE && self.height <= DECORATION_MAX_EDGE
    }
}

impl core::fmt::Display for PageImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.has_size() {
            write!(f, "{}x{}", self.width, self.height)
        } else {
            f.write_str("size not stated")
        }
    }
}

/// Every image found on one page.
///
/// Counts, page numbers and pixel dimensions. NO DOCUMENT TEXT and no image
/// bytes (I4), which is what makes this safe to print in a terminal, a log, a
/// browser panel and an error message alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageImages {
    /// One-based page number.
    pub page: usize,
    /// Every image on it, in the order the resources named them.
    pub images: Vec<PageImage>,
}

impl PageImages {
    /// How many of these are too big to dismiss as decoration.
    #[must_use]
    pub fn plausible_content(&self) -> usize {
        self.images
            .iter()
            .filter(|image| !image.plausible_decoration())
            .count()
    }
}

/// The sentence a surface shows for a page carrying images.
///
/// Written once, here, so the CLI, the browser panel and the error message
/// cannot drift into three different degrees of reassurance about the same
/// fact. It states what was found and refuses to state what it means.
impl core::fmt::Display for PageImages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sizes: Vec<String> = self.images.iter().map(ToString::to_string).collect();
        write!(
            f,
            "page {} carries {} image(s) deid-tr did not read: {}. {} of them are larger than \
             {DECORATION_MAX_EDGE}x{DECORATION_MAX_EDGE} and so could hold legible text, a \
             signature, or a QR or barcode encoding a protokol or patient number. That split is a \
             HEURISTIC ON SIZE ALONE -- deid-tr has no OCR and no barcode reader, does not decode \
             an image, and cannot tell you what any of these contain",
            self.page,
            self.images.len(),
            sizes.join(", "),
            self.plausible_content(),
        )
    }
}

/// What to do about images on a page that is otherwise processed.
///
/// # Why the default is to REFUSE
///
/// The alternative -- warn loudly and hand back the file -- was the starting
/// position, and it loses on three counts.
///
/// 1. **I2.** A missed identifier is a breach; an over-mask is a papercut. A
///    102x102 image on a Turkish clinical report is very often a QR code
///    carrying the protokol number, which is a direct identifier under the
///    schema this crate is built around. Passing it through is a miss, and the
///    document says "redacted" on the way out.
/// 2. **The policy hole this closes was exactly a default's worth wide.** This
///    module already refuses a page whose text is entirely pixels
///    ([`PdfError::ScannedPage`]). Refusing the whole-page case and quietly
///    passing an embedded barcode that encodes the same number is not a
///    considered position, it is the seam between two rules. Same reasoning,
///    same answer.
/// 3. **The size heuristic is not strong enough to decide.** It is honest
///    enough to inform a human ([`PageImage::plausible_decoration`]), and it is
///    not remotely good enough to auto-approve on someone's behalf: a QR code
///    is legible to a scanner at sizes where nothing is legible to a person. A
///    rule that silently passes anything under a threshold is a decision the
///    user never sees, which is the property this whole module exists to
///    refuse.
///
/// The counter-argument is real and is answered rather than dismissed:
/// refusing every document with a letterhead logo would make the tool useless.
/// So the override is one flag (`--allow-images`), it is named in the refusal
/// itself, and taking it does not buy silence -- the same page-and-dimension
/// report is then printed beside the result on every surface. A user who
/// overrides knows what they overrode. A user who does not override gets no
/// file at all. Neither one can end up believing pixels were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImagePolicy {
    /// Refuse the document, naming the page and the dimensions.
    #[default]
    Refuse,
    /// Continue, and report the images alongside the result.
    Warn,
}

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
    /// A page has extractable text AND images, under [`ImagePolicy::Refuse`].
    ///
    /// THE HYBRID CASE, which is the common shape of real hospital output and
    /// which fell between [`PdfError::ScannedPage`] (no text at all) and a
    /// clean pass. See [`ImagePolicy`] for why refusing is the default.
    #[error(
        "{0}. deid-tr redacts text and never touches pixels, so those images survive \
         byte-identical into the output; it will not report success over content it did not \
         read. Pass --allow-images to continue anyway -- the same list is then printed beside \
         the result"
    )]
    PageCarriesImages(PageImages),
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
    /// How many spans came off each page, indexed by page number minus one.
    ///
    /// A page that yielded nothing appears as `0`. That is a different fact
    /// from a page that was never reached, and a redaction summary that cannot
    /// distinguish them is telling a reader less than it knows.
    pub page_spans: Vec<usize>,
    /// Pages carrying images whose pixels were NOT read, one entry per page.
    ///
    /// Non-empty only under [`ImagePolicy::Warn`], because [`ImagePolicy::Refuse`]
    /// returns an error instead of a file. A surface that shows a redaction
    /// result and not this list is telling the user the document was handled
    /// when part of it was skipped.
    pub images: Vec<PageImages>,
}

/// What [`verify`] checks, in the order it checks it.
///
/// Named here so a SURFACE can show them. `verify` returning `Ok(())` proves
/// the checks passed but says nothing about what they were, and "verified" with
/// no list attached is a badge rather than a result -- especially in a browser,
/// where the user has no `pdftotext` to hand and cannot audit the claim
/// themselves. This list is what turns a green tick back into a statement.
///
/// It is a constant beside the function rather than a doc comment because a
/// doc comment cannot be rendered into a UI.
pub const VERIFY_CHECKS: &[&str] = &[
    "exactly one %%EOF: no previous revision survived",
    "no /Prev trailer chain to an earlier cross-reference section",
    "no /Encrypt, /ObjStm, /JavaScript, /EmbeddedFiles, /XFA, /OpenAction or /Metadata",
    "output re-parsed from bytes and every page's text re-extracted and searched",
    "every object's streams decompressed and scanned in UTF-8, UTF-16BE and Latin-1",
];

/// True when the bytes look like a PDF.
#[must_use]
pub fn is_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-")
}

/// Redact a PDF under the default image policy, then verify the result.
///
/// # Errors
///
/// [`PdfError`] for a document this crate refuses (encrypted, scanned, carrying
/// images, undecodable) and for a verification failure, or whatever the
/// pipeline returns. On any error NO BYTES ARE RETURNED.
pub fn redact(masker: &Masker<'_>, bytes: &[u8]) -> Result<Redaction, crate::FileError> {
    redact_with(masker, bytes, ImagePolicy::default())
}

/// Redact a PDF, then verify the result.
///
/// # Errors
///
/// As [`redact`]. `images` decides only whether a page carrying images is
/// refused or reported; there is no value of it under which the images go
/// unmentioned.
pub fn redact_with(
    masker: &Masker<'_>,
    bytes: &[u8],
    images: ImagePolicy,
) -> Result<Redaction, crate::FileError> {
    let mut document = Document::load(bytes)?;
    let page_numbers = document.page_numbers()?;
    let mut report = Redaction {
        pages: page_numbers.len(),
        input_revisions: document.input_revisions,
        // Sized up front and indexed by position rather than pushed, so a page
        // the loop skips still occupies its slot and page N of the summary is
        // page N of the document.
        page_spans: vec![0; page_numbers.len()],
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
        let PageRead {
            parts,
            extraction,
            images: found,
        } = read_page(&document, &dict, page)?;
        // BEFORE ANY MASKING. A page whose pixels this crate cannot read is
        // decided on before its text is touched, so a refusal never leaves a
        // half-edited object graph behind and never spends the pipeline on a
        // document that is not going to be returned.
        if !found.images.is_empty() {
            match images {
                ImagePolicy::Refuse => return Err(PdfError::PageCarriesImages(found).into()),
                ImagePolicy::Warn => report.images.push(found),
            }
        }
        let text = extraction.text();

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
                if let Some(count) = report.page_spans.get_mut(index) {
                    *count += 1;
                }
                // RECORDED HERE, not inside `Masker::replacements`, because
                // this is the line that decides the hit is real: the two
                // readings above find the same identifier twice and the guard
                // just above discards the duplicate. A recorder upstream of
                // that guard would report one TCKN as two.
                masker.record(&edit);
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

/// One page, decoded far enough to be read -- or a refusal.
struct PageRead {
    /// The individual content streams, so an edit can be written back to the
    /// object it came from. Empty for a caller that only wants the text.
    parts: Vec<StreamPart>,
    /// The decoded text plus the offset table that maps it back to stream bytes.
    extraction: content::Extraction,
    /// Every image drawn on the page. Reported, never read.
    images: PageImages,
}

/// Decode one page's text, applying every refusal this crate makes.
///
/// FACTORED OUT SO THE TWO CALLERS CANNOT DIVERGE. [`redact`] and
/// [`extract_pages`] must agree exactly on what a page says and on which pages
/// are refused: a surface that DISPLAYS extracted text from one code path and
/// redacts using another would eventually show a reader a page that the redactor
/// read differently, and the difference would be invisible in exactly the
/// direction that matters -- text shown as clean that the redactor never saw, or
/// a page displayed as readable that redaction then refuses.
fn read_page(document: &Document, dict: &Dict, page: usize) -> Result<PageRead, PdfError> {
    let PageContent {
        combined,
        parts,
        groups,
    } = page_content(document, dict);
    if parts.is_empty() && !combined.is_empty() {
        return Err(PdfError::UndecodableStream { page });
    }
    let operations = content::parse(&combined);
    let images = PageImages {
        page,
        images: page_images(document, dict, &combined),
    };
    let raster = !images.images.is_empty();
    if raster && has_invisible_text(&operations) {
        return Err(PdfError::ScannedWithTextLayer { page });
    }
    let extraction = extract_groups(&groups);
    if extraction.undecodable > 0 {
        return Err(PdfError::UnreadablePage {
            page,
            codes: extraction.undecodable,
        });
    }
    // ORDER MATTERS. A page with images and NO text is a scan, and it keeps the
    // unconditional refusal it has always had -- no policy and no flag reaches
    // that one. The image policy governs only a page that ALSO has text, which
    // is the case that used to pass through silently.
    if extraction.text().trim().is_empty() && raster {
        return Err(PdfError::ScannedPage { page });
    }
    Ok(PageRead {
        parts,
        extraction,
        images,
    })
}

/// The text of every page, in page order, WITHOUT redacting anything.
///
/// For a surface that has to show a reader what it is about to redact. It runs
/// the same [`read_page`] as [`redact`], so a document this refuses is exactly
/// the set of documents redaction refuses, and a page whose text is shown is
/// exactly the text the masker will be given.
///
/// The returned strings are DOCUMENT TEXT, so they are PHI. See [`PageText`].
///
/// # Errors
///
/// [`PdfError`] for a document this crate refuses, by page number.
pub fn extract_pages(bytes: &[u8]) -> Result<Vec<PageText>, crate::FileError> {
    extract_pages_with(bytes, ImagePolicy::default())
}

/// The text of every page under an explicit image policy.
///
/// TAKES THE SAME POLICY AS [`redact_with`] and applies it identically, for the
/// reason [`read_page`] is shared: a surface that displays under one policy and
/// redacts under another would show a reader a page it is then going to refuse,
/// or refuse a page it has already displayed as readable.
///
/// # Errors
///
/// [`PdfError`] for a document this crate refuses, by page number.
pub fn extract_pages_with(
    bytes: &[u8],
    images: ImagePolicy,
) -> Result<Vec<PageText>, crate::FileError> {
    let document = Document::load(bytes)?;
    let mut pages = Vec::new();
    for (index, page_number) in document.page_numbers()?.iter().enumerate() {
        let Some(dict) = document
            .objects
            .get(page_number)
            .and_then(Object::as_dict)
            .cloned()
        else {
            continue;
        };
        let read = read_page(&document, &dict, index + 1)?;
        if !read.images.images.is_empty() && images == ImagePolicy::Refuse {
            return Err(PdfError::PageCarriesImages(read.images).into());
        }
        pages.push(PageText {
            page: index + 1,
            text: read.extraction.text(),
            images: read.images.images,
        });
    }
    Ok(pages)
}

/// One page's extracted text.
///
/// `text` IS DOCUMENT TEXT AND THEREFORE PHI, which is why [`fmt::Debug`] is
/// hand-written to print a length rather than the string (I4). Every other type
/// this module returns is counts-and-keys and derives `Debug` safely; this one
/// cannot, and a derive added here later would silently put a clinical page into
/// the first `{:?}` that touches it.
///
/// [`fmt::Debug`]: core::fmt::Debug
#[derive(Clone, PartialEq, Eq)]
pub struct PageText {
    /// One-based page number.
    pub page: usize,
    /// The decoded text of the page. PHI.
    pub text: String,
    /// Images on the page, whose pixels are NOT part of `text`.
    ///
    /// Carried so a surface showing "here is what page 2 says" can also say
    /// "and here is what was on page 2 that this is not showing you". Sizes
    /// only -- no pixels cross this boundary.
    pub images: Vec<PageImage>,
}

impl core::fmt::Debug for PageText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageText")
            .field("page", &self.page)
            .field(
                "text",
                &format_args!("<{} bytes redacted>", self.text.len()),
            )
            .field("images", &self.images)
            .finish()
    }
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

/// One self-contained content buffer and the font scope it is read under.
///
/// The unit is a FONT SCOPE, not a stream: a page's `/Contents` array is one
/// group however many streams it holds, and each Form XObject is another,
/// because §8.10.1 gives a form its own `/Resources`.
pub(crate) struct ContentGroup {
    /// Where this group's bytes start in the combined buffer.
    pub base: usize,
    /// The decoded bytes of this group.
    pub data: Vec<u8>,
    /// The fonts a `Tf` inside this group selects from.
    pub fonts: BTreeMap<String, Font>,
}

/// Everything a page's text can be read from.
pub(crate) struct PageContent {
    /// Every group's bytes, back to back. Offsets in `parts` and
    /// [`ContentGroup::base`] index into THIS buffer.
    pub combined: Vec<u8>,
    /// The individual streams, so an edit can be written back to its object.
    pub parts: Vec<StreamPart>,
    /// The font-scoped groups, in reading order.
    pub groups: Vec<ContentGroup>,
}

/// Run [`content::extract`] over each group and concatenate the results.
pub(crate) fn extract_groups(groups: &[ContentGroup]) -> content::Extraction {
    let mut out = content::Extraction::default();
    for group in groups {
        out.absorb(
            content::extract(&content::parse(&group.data), &group.fonts),
            group.base,
        );
    }
    out
}

/// How deep a chain of Form XObjects invoking Form XObjects is followed.
///
/// A form may invoke another form, and a malformed file may make that a cycle.
/// The visited set below stops a cycle; this stops a legal-but-absurd nesting
/// from turning one page into unbounded work.
const MAX_FORM_DEPTH: usize = 8;

/// Decode a page's content streams AND the Form XObjects it invokes.
///
/// # Why the forms are not optional
///
/// A `Do` operator paints a Form XObject, whose own content stream holds text
/// and whose own `/Resources` hold the fonts to read it with. Several
/// widely-deployed producers (HiQPdf and the Crystal/Telerik lineage among
/// them) emit an entire report body as one form and leave the page stream
/// holding little more than a `Do`. A reader that stops at `/Contents`
/// therefore sees a nearly empty page, reports no identifiers, and is WRONG in
/// the direction that ships a file. Worse, the forms are where the Type0 fonts
/// live, so `/ToUnicode` never reached the strings that needed it most.
pub(crate) fn page_content(document: &Document, page: &Dict) -> PageContent {
    let mut out = PageContent {
        combined: Vec::new(),
        parts: Vec::new(),
        groups: Vec::new(),
    };

    let (data, parts) = page_streams(document, page);
    out.combined.clone_from(&data);
    out.parts = parts;
    out.groups.push(ContentGroup {
        base: 0,
        data,
        fonts: page_fonts(document, page),
    });

    let mut seen = BTreeSet::new();
    collect_forms(document, page, 0, &mut seen, &mut out);
    out
}

/// Append every Form XObject reachable from `node`'s `/Resources`.
fn collect_forms(
    document: &Document,
    node: &Dict,
    depth: usize,
    seen: &mut BTreeSet<u32>,
    out: &mut PageContent,
) {
    if depth >= MAX_FORM_DEPTH {
        return;
    }
    let Some(resources) = document.get(node, "Resources").and_then(Object::as_dict) else {
        return;
    };
    let Some(table) = document.get(resources, "XObject").and_then(Object::as_dict) else {
        return;
    };
    for (_, value) in &table.0 {
        let Object::Reference(number, _) = value else {
            continue;
        };
        // Also the cycle guard: a form that invokes itself is read once.
        if !seen.insert(*number) {
            continue;
        }
        let Some(Object::Stream(dict, raw)) = document.objects.get(number) else {
            continue;
        };
        if dict.get("Subtype").and_then(Object::as_name) != Some("Form") {
            continue;
        }
        let Some(data) = decode_stream(dict, raw) else {
            // Consistent with `page_streams`: a stream that cannot be decoded
            // must not read as absent text. A space in the combined buffer with
            // no matching part is what signals it upstream.
            out.combined.push(b' ');
            continue;
        };
        let dict = dict.clone();
        // A form with NO `/Resources` of its own inherits the page's (§8.10.1).
        // A form that HAS one is authoritative: a name it does not define is
        // left undefined rather than resolved against the page, because
        // borrowing a same-named page font is a silent wrong decode and this
        // module's answer to "cannot read" is to refuse.
        let fonts = if dict.get("Resources").is_some() {
            page_fonts(document, &dict)
        } else {
            page_fonts(document, node)
        };
        let base = out.combined.len();
        out.parts.push(StreamPart {
            object: *number,
            at: base,
            data: data.clone(),
        });
        out.combined.extend_from_slice(&data);
        out.combined.push(b'\n');
        out.groups.push(ContentGroup { base, data, fonts });
        collect_forms(document, &dict, depth + 1, seen, out);
    }
}

/// Decode and concatenate a page's own `/Contents` streams.
///
/// CONCATENATED, because §7.8.2 says the streams of a `/Contents` array form a
/// single stream -- a producer may split one `Tj` across two of them. Scanning
/// each separately would miss an identifier that straddles the join. A Form
/// XObject gets no such treatment: it is a complete stream on its own, and
/// giving it its own group is what lets it keep its own fonts.
fn page_streams(document: &Document, page: &Dict) -> (Vec<u8>, Vec<StreamPart>) {
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

/// Every image a page draws, by pixel size.
///
/// This is the successor to a `has_raster_content` predicate that answered only
/// yes or no. A boolean was enough while the only question was "is this page a
/// scan?"; it is not enough to TELL somebody what is on a page they are about
/// to hand to a colleague, and "there is something here I cannot read" is a
/// materially different message from "there are two 102x102 images and a
/// 320x38 one on page 1".
///
/// `/Resources` is INHERITABLE, so the page tree is walked upward exactly as
/// [`page_fonts`] walks it. A letterhead declared on the `/Pages` node and used
/// by every page would otherwise be invisible here -- and invisible in the safe
/// direction is the one direction this crate does not accept.
fn page_images(document: &Document, page: &Dict, combined: &[u8]) -> Vec<PageImage> {
    let mut found = Vec::new();
    // Inline images carry their size as `/W` and `/H` inside the content stream
    // rather than in a dictionary this crate models, so they are counted and
    // reported WITH AN UNKNOWN SIZE. Counting them is what matters: an
    // uncounted image is one nobody is told about, and an unknown size already
    // reads as the non-reassuring answer (`PageImage::has_size`).
    found.extend(
        document::find_all(combined, b"BI ")
            .iter()
            .map(|_| PageImage::default()),
    );

    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut node = page.clone();
    for _ in 0..32 {
        if let Some(resources) = document.get(&node, "Resources").and_then(Object::as_dict) {
            collect_images(document, resources, &mut seen, 0, &mut found);
        }
        let Some(parent) = document.get(&node, "Parent").and_then(Object::as_dict) else {
            break;
        };
        node = parent.clone();
    }
    found
}

/// Walk one `/XObject` table, descending into form XObjects.
///
/// A logo is routinely wrapped in a `/Form` XObject rather than drawn directly,
/// so a scan of the top level only would miss exactly the images a letterhead
/// contributes. `seen` makes a cyclic or shared reference terminate, and the
/// depth cap bounds a pathological nesting rather than trusting the file.
fn collect_images(
    document: &Document,
    resources: &Dict,
    seen: &mut BTreeSet<u32>,
    depth: usize,
    out: &mut Vec<PageImage>,
) {
    if depth >= 8 {
        return;
    }
    let Some(xobjects) = document.get(resources, "XObject").and_then(Object::as_dict) else {
        return;
    };
    for (_, value) in &xobjects.0 {
        if let Object::Reference(number, _) = value {
            if !seen.insert(*number) {
                continue;
            }
        }
        let Some(dict) = document.resolve(value).as_dict() else {
            continue;
        };
        match dict.get("Subtype").and_then(Object::as_name) {
            Some("Image") => out.push(PageImage {
                width: pixel_count(document, dict, "Width"),
                height: pixel_count(document, dict, "Height"),
            }),
            Some("Form") => {
                if let Some(inner) = document.get(dict, "Resources").and_then(Object::as_dict) {
                    collect_images(document, inner, seen, depth + 1, out);
                }
            }
            _ => {}
        }
    }
}

/// One `/Width` or `/Height`, or zero when it cannot be read.
///
/// Saturating rather than wrapping: a negative or absurd value is a broken file,
/// and the answer to a broken file is not a small number.
fn pixel_count(document: &Document, dict: &Dict, key: &str) -> u32 {
    document
        .get(dict, key)
        .and_then(Object::as_int)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0)
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
