//! Office Open XML (`.docx`): a zip of XML parts, all of which carry text.
//!
//! # A name in a header is still a name
//!
//! The single most common mistake in document redaction tooling is treating
//! `word/document.xml` as "the document". It is the BODY. A `.docx` also
//! carries text in:
//!
//! | Part | What is in it |
//! |---|---|
//! | `word/header*.xml`, `word/footer*.xml` | letterhead, patient banner, MRN in a running head |
//! | `word/footnotes.xml`, `word/endnotes.xml` | notes |
//! | `word/comments*.xml`, `word/people.xml` | reviewer comments and their AUTHOR names |
//! | `docProps/core.xml` | `dc:creator`, `cp:lastModifiedBy`, `dc:title` |
//! | `docProps/app.xml` | `Company`, `Manager` |
//! | `docProps/custom.xml` | whatever the exporting system decided to add |
//! | `word/glossary/document.xml` | building blocks / autotext |
//!
//! Every one of them is swept. [`STRUCTURAL_PARTS`] is the deny list of parts
//! that are pure formatting, and it is a deny list rather than an allow list on
//! purpose: a producer that invents a new part gets swept by default, and the
//! failure mode of the wrong default is over-scanning rather than a missed
//! identifier (I2).
//!
//! # Runs, and why text is joined before it is scanned
//!
//! Word splits a single word across `<w:t>` elements freely -- a spell-check
//! marker, a revision id or a language change is enough. A TCKN typed in one
//! go can be stored as `<w:t>123</w:t><w:t>45678901</w:t>`, and a redactor that
//! scans each element separately finds NEITHER half. So the text of every
//! element in a part is joined in document order, scanned once, and the
//! resulting edits are applied back across whichever elements they land in.
//!
//! # Author-identifying attributes are cleared, not scanned
//!
//! `w:author` on a comment or a tracked change, and `dc:creator` in the
//! properties, are known by their POSITION to hold a person's name. Clearing
//! them is deterministic and needs no model, which is exactly why it is done
//! here rather than left to a detector that does not exist yet. This is the one
//! place a person name is reliably removed, and it works because the schema
//! said what the field was -- not because anything recognised the name.
//!
//! HONEST SCOPE: in the body text, only rule-detectable identifiers are
//! removed. See [`crate::Report::rule_detectable_only`].

use crate::masker::{Masker, Replacement};
use crate::zip::{self, Entry};

/// A `.docx` that could not be processed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocxError {
    /// The container is not a readable zip.
    #[error("the .docx container could not be read")]
    Container(#[from] zip::ZipError),
    /// No `word/document.xml`, so this is not a Word document.
    #[error("the package has no word/document.xml and is not a .docx")]
    NotADocx,
    /// A part was not valid UTF-8.
    ///
    /// OOXML parts are XML and XML in a `.docx` is UTF-8 by specification, so
    /// this is a corrupt package rather than an encoding this crate should
    /// guess at.
    #[error("package part '{name}' is not valid UTF-8")]
    NotUtf8 {
        /// The part name.
        name: String,
    },
}

/// Parts that hold formatting and never hold narrative text.
///
/// Scanning them is not unsafe, it is just noise -- and `theme1.xml` in
/// particular is full of colour names that a future gazetteer would have
/// opinions about.
pub const STRUCTURAL_PARTS: &[&str] = &[
    "word/styles.xml",
    "word/stylesWithEffects.xml",
    "word/settings.xml",
    "word/webSettings.xml",
    "word/fontTable.xml",
    "word/numbering.xml",
];

/// Attributes whose VALUE is a person's name by schema, wherever they appear.
const AUTHOR_ATTRIBUTES: &[&str] = &["w:author", "w:initials", "w15:userId", "w16cid:userId"];

/// Elements in `docProps/` whose text content is metadata about people.
const METADATA_ELEMENTS: &[&str] = &[
    "dc:creator",
    "cp:lastModifiedBy",
    "dc:title",
    "dc:subject",
    "dc:description",
    "cp:keywords",
    "cp:category",
    "Company",
    "Manager",
];

/// What a `.docx` sweep did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DocxOutcome {
    /// The rewritten package.
    pub bytes: Vec<u8>,
    /// Every part that was rewritten, by name. Structural, never content.
    pub parts_rewritten: Vec<String>,
    /// Every metadata field that was cleared outright, by name.
    pub fields_cleared: Vec<String>,
    /// How many spans the pipeline removed across all parts.
    pub masked: usize,
    /// Every part that was SWEPT, with what came out of it.
    ///
    /// A superset of [`DocxOutcome::parts_rewritten`]: a part that was read and
    /// yielded nothing appears here with a count of zero, because "we looked
    /// and it was clean" and "we never looked" are different facts and a
    /// surface that cannot tell them apart is not showing a summary.
    pub part_spans: Vec<(String, usize)>,
}

/// True when the bytes look like an Office Open XML word processing package.
#[must_use]
pub fn is_docx(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        && zip::read(bytes).is_ok_and(|entries| {
            entries
                .iter()
                .any(|entry| entry.name == "word/document.xml")
        })
}

fn should_sweep(name: &str) -> bool {
    if !name.ends_with(".xml") || name.contains("_rels/") || name.starts_with("word/theme/") {
        return false;
    }
    if STRUCTURAL_PARTS.contains(&name) {
        return false;
    }
    name.starts_with("word/") || name.starts_with("docProps/")
}

/// De-identify every text-bearing part of a `.docx`.
///
/// # Errors
///
/// [`DocxError`] for a container this crate cannot read, or whatever the
/// pipeline returns.
pub fn mask(
    masker: &Masker<'_>,
    bytes: &[u8],
) -> Result<(DocxOutcome, Vec<String>), crate::FileError> {
    let entries = zip::read(bytes).map_err(DocxError::Container)?;
    if !entries
        .iter()
        .any(|entry| entry.name == "word/document.xml")
    {
        return Err(DocxError::NotADocx.into());
    }

    let mut outcome = DocxOutcome::default();
    let mut originals = Vec::new();
    let mut rewritten = Vec::with_capacity(entries.len());

    for entry in entries {
        if !should_sweep(&entry.name) {
            rewritten.push(entry);
            continue;
        }
        let xml = core::str::from_utf8(&entry.data).map_err(|_| DocxError::NotUtf8 {
            name: entry.name.clone(),
        })?;
        // WordprocessingML splits a word across `<w:t>` runs, so text is joined
        // across them. Every OTHER schema in the package -- `docProps/core.xml`
        // and friends -- has one value per element, so joining across elements
        // there would manufacture matches that are not in the document.
        let joins_runs = entry.name.starts_with("word/");
        let swept = sweep_part(masker, xml, joins_runs, &mut outcome.fields_cleared)?;
        if swept.changed {
            outcome.parts_rewritten.push(entry.name.clone());
        }
        outcome.masked += swept.masked;
        outcome.part_spans.push((entry.name.clone(), swept.masked));
        originals.extend(swept.originals);
        rewritten.push(Entry {
            name: entry.name,
            data: swept.xml.into_bytes(),
        });
    }

    outcome.fields_cleared.sort_unstable();
    outcome.fields_cleared.dedup();
    outcome.bytes = zip::write(&rewritten);
    Ok((outcome, originals))
}

/// One package part's readable text.
///
/// `text` IS DOCUMENT TEXT AND THEREFORE PHI, so [`fmt::Debug`] is hand-written
/// to print a length. `name` is a structural path (`word/document.xml`) and is
/// safe to print, which is the distinction the derive on [`DocxOutcome`] relies
/// on and this type cannot.
///
/// [`fmt::Debug`]: core::fmt::Debug
#[derive(Clone, PartialEq, Eq)]
pub struct PartText {
    /// The package part path. Structural, safe to print.
    pub name: String,
    /// The part's joined character data, exactly as the masker will see it. PHI.
    pub text: String,
}

impl core::fmt::Debug for PartText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartText")
            .field("name", &self.name)
            .field(
                "text",
                &format_args!("<{} bytes redacted>", self.text.len()),
            )
            .finish()
    }
}

/// The readable text of every part [`mask`] would sweep, WITHOUT masking.
///
/// For a surface that has to show a reader what it is about to redact. It reuses
/// `should_sweep`, `clear_known_fields` and `collect_text`, so the parts listed
/// here and the buffer shown for each are the same parts and the same buffers
/// [`mask`] hands the pipeline -- not a second, similar-looking reading.
///
/// Parts whose joined buffer is blank are omitted: a `.docx` carries a dozen
/// relationship and settings parts that sweep to nothing, and listing them as
/// empty rows buries the one part a reader is looking for.
///
/// # Errors
///
/// [`DocxError`] for a container this crate cannot read.
pub fn extract_parts(bytes: &[u8]) -> Result<Vec<PartText>, DocxError> {
    let entries = zip::read(bytes).map_err(DocxError::Container)?;
    if !entries
        .iter()
        .any(|entry| entry.name == "word/document.xml")
    {
        return Err(DocxError::NotADocx);
    }
    let mut parts = Vec::new();
    for entry in entries {
        if !should_sweep(&entry.name) {
            continue;
        }
        let xml = core::str::from_utf8(&entry.data).map_err(|_| DocxError::NotUtf8 {
            name: entry.name.clone(),
        })?;
        let (cleared, _) = clear_known_fields(xml);
        let (_, joined) = collect_text(&cleared, entry.name.starts_with("word/"));
        if joined.trim().is_empty() {
            continue;
        }
        parts.push(PartText {
            name: entry.name,
            text: joined,
        });
    }
    Ok(parts)
}

struct Swept {
    xml: String,
    changed: bool,
    masked: usize,
    originals: Vec<String>,
}

/// One region of a part: either character data (scannable) or markup (not).
struct TextRegion {
    /// Byte range in the ORIGINAL part.
    start: usize,
    end: usize,
    /// The XML-decoded text.
    text: String,
    /// Offset of this region's text within the joined scan buffer.
    joined_at: usize,
}

fn sweep_part(
    masker: &Masker<'_>,
    xml: &str,
    joins_runs: bool,
    fields_cleared: &mut Vec<String>,
) -> Result<Swept, crate::FileError> {
    let (mut out, cleared) = clear_known_fields(xml);
    let cleared_here = !cleared.is_empty();
    fields_cleared.extend(cleared);

    let (regions, joined) = collect_text(&out, joins_runs);
    let replacements = masker.replacements(&joined)?;
    // Every replacement returned here is applied below, so recording them all
    // is exact. `Masker::replacements` does not record on its own because the
    // PDF page path reads each page twice and commits a subset.
    for edit in &replacements {
        masker.record(edit);
    }
    let masked = replacements.len();
    let originals: Vec<String> = replacements
        .iter()
        .map(|edit| edit.original.clone())
        .collect();

    if !replacements.is_empty() {
        out = apply(&out, &regions, &replacements);
    }
    let changed = masked > 0 || cleared_here;
    Ok(Swept {
        xml: out,
        changed,
        masked,
        originals,
    })
}

/// Split a part into markup and character data, and build the joined scan
/// buffer.
///
/// Paragraph and line breaks contribute a `\n` to the buffer that belongs to no
/// region, so a rule can never match across two paragraphs while a rule CAN
/// match across two runs of the same paragraph -- which is the whole point.
fn collect_text(xml: &str, joins_runs: bool) -> (Vec<TextRegion>, String) {
    let bytes = xml.as_bytes();
    let mut regions = Vec::new();
    let mut joined = String::with_capacity(xml.len() / 4);
    let mut at = 0usize;

    while at < bytes.len() {
        let Some(open) = xml[at..].find('<').map(|offset| at + offset) else {
            break;
        };
        if open > at {
            let raw = &xml[at..open];
            let text = decode_entities(raw);
            if !text.is_empty() {
                regions.push(TextRegion {
                    start: at,
                    end: open,
                    text: text.clone(),
                    joined_at: joined.len(),
                });
                joined.push_str(&text);
            }
        }
        let Some(close) = xml[open..].find('>').map(|offset| open + offset) else {
            break;
        };
        let tag = &xml[open..=close];
        if !joins_runs || is_break_tag(tag) {
            joined.push('\n');
        }
        at = close + 1;
    }
    (regions, joined)
}

fn is_break_tag(tag: &str) -> bool {
    let name = tag
        .trim_start_matches('<')
        .trim_start_matches('/')
        .split([' ', '/', '>'])
        .next()
        .unwrap_or_default();
    matches!(name, "w:p" | "w:br" | "w:tab" | "w:tr" | "w:cr")
}

/// Apply pipeline edits, expressed against the joined buffer, back onto the
/// part.
///
/// A span that crosses two regions -- an identifier split across runs -- puts
/// the whole replacement in the FIRST region it touches and deletes the covered
/// bytes from the rest. That is the only arrangement that both removes every
/// covered byte and leaves the replacement readable; distributing it
/// proportionally would slice a surrogate across formatting boundaries.
fn apply(xml: &str, regions: &[TextRegion], replacements: &[Replacement]) -> String {
    // Per region, the new decoded text.
    let mut edited: Vec<Option<String>> = vec![None; regions.len()];
    for edit in replacements {
        let mut placed = false;
        for (index, region) in regions.iter().enumerate() {
            let region_start = region.joined_at;
            let region_end = region_start + region.text.len();
            if edit.end <= region_start || edit.start >= region_end {
                continue;
            }
            let local_start = edit
                .start
                .saturating_sub(region_start)
                .min(region.text.len());
            let local_end = (edit.end - region_start).min(region.text.len());
            let current = edited[index].clone().unwrap_or_else(|| region.text.clone());
            // Offsets index the ORIGINAL region text, so edits within one
            // region are applied against a fresh copy each time and would
            // conflict if two overlapped. `union_widest` guarantees they do
            // not: the pipeline's spans are non-overlapping by construction.
            let mut next = String::with_capacity(current.len());
            next.push_str(current.get(..local_start).unwrap_or_default());
            if !placed {
                next.push_str(&edit.replacement);
                placed = true;
            }
            next.push_str(current.get(local_end..).unwrap_or_default());
            edited[index] = Some(next);
        }
    }

    let mut out = String::with_capacity(xml.len());
    let mut cursor = 0usize;
    for (index, region) in regions.iter().enumerate() {
        let Some(text) = edited[index].as_ref() else {
            continue;
        };
        out.push_str(xml.get(cursor..region.start).unwrap_or_default());
        out.push_str(&encode_entities(text));
        cursor = region.end;
    }
    out.push_str(xml.get(cursor..).unwrap_or_default());
    out
}

/// Clear attributes and elements whose position makes them person-identifying.
fn clear_known_fields(xml: &str) -> (String, Vec<String>) {
    let mut out = xml.to_owned();
    let mut cleared = Vec::new();

    for name in AUTHOR_ATTRIBUTES {
        let needle = format!("{name}=\"");
        while let Some(at) = out.find(&needle) {
            let value_start = at + needle.len();
            let Some(value_end) = out[value_start..].find('"').map(|off| value_start + off) else {
                break;
            };
            if value_end == value_start {
                // Already empty; replacing it would loop forever.
                break;
            }
            out.replace_range(value_start..value_end, "");
            cleared.push((*name).to_owned());
        }
    }

    for name in METADATA_ELEMENTS {
        let open = format!("<{name}");
        let close = format!("</{name}>");
        let mut from = 0usize;
        while let Some(at) = out[from..].find(&open).map(|off| from + off) {
            let Some(tag_end) = out[at..].find('>').map(|off| at + off + 1) else {
                break;
            };
            let Some(close_at) = out[tag_end..].find(&close).map(|off| tag_end + off) else {
                from = tag_end;
                continue;
            };
            if close_at > tag_end {
                out.replace_range(tag_end..close_at, "");
                cleared.push((*name).to_owned());
            }
            from = tag_end;
        }
    }
    (out, cleared)
}

fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(end) = tail.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix('#')
                .and_then(
                    |number| match number.strip_prefix('x').or(number.strip_prefix('X')) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => number.parse().ok(),
                    },
                )
                .and_then(char::from_u32),
        };
        match decoded {
            Some(value) => {
                out.push(value);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn encode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for value in text.chars() {
        match value {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tckn;
    use deid_tr_core::{Pipeline, Tier};

    fn masker() -> Masker<'static> {
        // `Box::leak` rather than a `static`: `Pipeline` holds boxed trait
        // objects and is deliberately not `Sync`, so it cannot live in a
        // static. The leak is bounded by the test process.
        Masker::new(Box::leak(Box::new(Pipeline::new(Tier::SafeHarbor))))
    }

    fn part(name: &str, xml: &str) -> Entry {
        Entry {
            name: name.to_owned(),
            data: xml.as_bytes().to_vec(),
        }
    }

    fn package(parts: Vec<Entry>) -> Vec<u8> {
        zip::write(&parts)
    }

    fn text_of(bytes: &[u8], name: &str) -> String {
        let entries = zip::read(bytes).expect("read");
        let entry = entries
            .iter()
            .find(|entry| entry.name == name)
            .expect("part exists");
        String::from_utf8(entry.data.clone()).expect("utf-8")
    }

    #[test]
    fn a_name_in_a_header_footer_footnote_and_comment_is_all_swept() {
        // THE test this module exists for. The identifier is placed in every
        // non-body part; a redactor that only sweeps word/document.xml leaves
        // four copies of it in the file.
        let tckn = tckn();
        let body = format!("<w:document><w:p><w:t>TCKN {tckn}</w:t></w:p></w:document>");
        let other = format!("<w:hdr><w:p><w:t>{tckn}</w:t></w:p></w:hdr>");
        let bytes = package(vec![
            part("[Content_Types].xml", "<Types/>"),
            part("word/document.xml", &body),
            part("word/header1.xml", &other),
            part("word/footer1.xml", &other),
            part("word/footnotes.xml", &other),
            part("word/endnotes.xml", &other),
            part("word/comments.xml", &other),
        ]);
        let (outcome, originals) = mask(&masker(), &bytes).expect("mask");
        let out = outcome.bytes;
        assert!(
            !String::from_utf8_lossy(&out).contains(&tckn),
            "the identifier survived somewhere in the package"
        );
        assert_eq!(originals.len(), 6);
        assert_eq!(outcome.parts_rewritten.len(), 6);
    }

    #[test]
    fn an_identifier_split_across_two_runs_is_still_found() {
        // Word does this on its own. Scanning each <w:t> separately finds
        // neither half of the number.
        let tckn = tckn();
        let (head, tail) = tckn.split_at(4);
        let body =
            format!("<w:document><w:p><w:t>{head}</w:t><w:t>{tail}</w:t></w:p></w:document>");
        let bytes = package(vec![
            part("[Content_Types].xml", "<Types/>"),
            part("word/document.xml", &body),
        ]);
        let (outcome, originals) = mask(&masker(), &bytes).expect("mask");
        let document = text_of(&outcome.bytes, "word/document.xml");
        assert!(!document.contains(head), "the first run survived");
        assert!(!document.contains(tail), "the second run survived");
        assert_eq!(originals, vec![tckn]);
    }

    #[test]
    fn a_rule_does_not_match_across_a_paragraph_boundary() {
        // The other side of the join: two paragraphs are two contexts, and
        // gluing them would manufacture identifiers that are not in the text.
        let tckn = tckn();
        let (head, tail) = tckn.split_at(4);
        let body = format!(
            "<w:document><w:p><w:t>{head}</w:t></w:p><w:p><w:t>{tail}</w:t></w:p></w:document>"
        );
        let bytes = package(vec![
            part("[Content_Types].xml", "<Types/>"),
            part("word/document.xml", &body),
        ]);
        let (_, originals) = mask(&masker(), &bytes).expect("mask");
        assert!(originals.is_empty());
    }

    #[test]
    fn author_attributes_and_metadata_elements_are_cleared_outright() {
        // The ONLY reliable person-name removal this crate performs, and it
        // works because the schema named the field -- not because anything
        // recognised the name.
        let comments = "<w:comments><w:comment w:author=\"Dr. Şükrü Gökçe\" w:initials=\"ŞG\">\
                        <w:p><w:t>ok</w:t></w:p></w:comment></w:comments>";
        let core = "<cp:coreProperties><dc:creator>Ayşe Yılmaz</dc:creator>\
                    <cp:lastModifiedBy>Bora Demir</cp:lastModifiedBy>\
                    <dc:title>Hasta raporu</dc:title></cp:coreProperties>";
        let bytes = package(vec![
            part("[Content_Types].xml", "<Types/>"),
            part(
                "word/document.xml",
                "<w:document><w:p><w:t>x</w:t></w:p></w:document>",
            ),
            part("word/comments.xml", comments),
            part("docProps/core.xml", core),
        ]);
        let (outcome, _) = mask(&masker(), &bytes).expect("mask");
        let rendered = String::from_utf8_lossy(&outcome.bytes).into_owned();
        for name in ["Şükrü Gökçe", "Ayşe Yılmaz", "Bora Demir", "Hasta raporu"] {
            assert!(!rendered.contains(name), "{name} survived");
        }
        assert!(outcome.fields_cleared.contains(&"w:author".to_owned()));
        assert!(outcome.fields_cleared.contains(&"dc:creator".to_owned()));
    }

    #[test]
    fn xml_entities_survive_the_round_trip() {
        let body = "<w:document><w:p><w:t>A &amp; B &lt;x&gt;</w:t></w:p></w:document>";
        let bytes = package(vec![
            part("[Content_Types].xml", "<Types/>"),
            part("word/document.xml", body),
        ]);
        let (outcome, _) = mask(&masker(), &bytes).expect("mask");
        assert_eq!(text_of(&outcome.bytes, "word/document.xml"), body);
    }

    #[test]
    fn a_package_without_a_document_part_is_refused() {
        let bytes = package(vec![part("[Content_Types].xml", "<Types/>")]);
        assert!(matches!(
            mask(&masker(), &bytes),
            Err(crate::FileError::Docx(DocxError::NotADocx))
        ));
        assert!(!is_docx(&bytes));
    }

    #[test]
    fn structural_parts_are_left_alone() {
        assert!(!should_sweep("word/styles.xml"));
        assert!(!should_sweep("word/theme/theme1.xml"));
        assert!(!should_sweep("word/_rels/document.xml.rels"));
        assert!(should_sweep("word/header3.xml"));
        assert!(should_sweep("docProps/custom.xml"));
        assert!(should_sweep("word/glossary/document.xml"));
    }
}
