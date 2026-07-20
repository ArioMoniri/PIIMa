//! Loading a PDF into an object graph, WITHOUT trusting its cross-reference
//! table.
//!
//! # Why the xref table is not followed
//!
//! The xref is an index. Following it tells you where the file says its objects
//! are; it does NOT tell you what else is in the file. A PDF that has been
//! saved incrementally carries its entire previous revision as unreferenced
//! objects after the first `%%EOF`, and a loader that only walks the current
//! xref never sees them -- which is precisely how a "redacted" file ships with
//! the original text still inside it.
//!
//! This loader SCANS the whole byte range for `N G obj`. That has two effects,
//! both wanted:
//!
//! 1. Every revision is visible, so the redactor knows what is in the file.
//! 2. The output is rebuilt from the objects reachable from the CURRENT
//!    catalogue and nothing else, so no previous revision can survive by
//!    accident. Survival would require this module to deliberately emit it.
//!
//! When two revisions define the same object number, the one at the higher file
//! offset wins -- which is exactly the incremental-update rule.
//!
//! # Encryption
//!
//! An encrypted PDF is REFUSED. Not warned about, not passed through: this
//! crate has no decryption, so it cannot see the text, so it cannot prove it
//! removed anything. Emitting a file it could not read would be the fake
//! redaction this whole module exists to prevent.

use std::collections::BTreeMap;

use crate::inflate::zlib_decompress;
use crate::pdf::object::{is_whitespace, Dict, Lexer, Object};
use crate::pdf::PdfError;

/// A loaded PDF.
pub struct Document {
    /// Object number to object. Sorted, so the writer emits a stable file.
    pub objects: BTreeMap<u32, Object>,
    /// The trailer dictionary of the LAST revision that has a `/Root`.
    pub trailer: Dict,
    /// How many `%%EOF` markers the INPUT had.
    ///
    /// Recorded rather than checked here: more than one means the input was
    /// saved incrementally, which is a fact about the input the report should
    /// carry, not a reason to refuse it. The OUTPUT having more than one is a
    /// verification failure.
    pub input_revisions: usize,
}

impl Document {
    /// Parse a PDF from bytes.
    ///
    /// # Errors
    ///
    /// [`PdfError`] when the file is not a PDF, is encrypted, or has no
    /// catalogue.
    pub fn load(data: &[u8]) -> Result<Self, PdfError> {
        if !data.starts_with(b"%PDF-") {
            return Err(PdfError::NotAPdf);
        }
        let mut objects: BTreeMap<u32, Object> = BTreeMap::new();
        let mut offsets: BTreeMap<u32, usize> = BTreeMap::new();
        let mut trailers: Vec<(usize, Dict)> = Vec::new();

        for (offset, number) in scan_object_headers(data) {
            let mut lexer = Lexer::new(data, offset);
            let Ok(object) = parse_body(&mut lexer, data) else {
                // A single unparseable object must not lose the rest of the
                // file: the scan is a recovery mechanism by design.
                continue;
            };
            if offsets
                .get(&number)
                .is_none_or(|previous| offset > *previous)
            {
                offsets.insert(number, offset);
                objects.insert(number, object);
            }
        }

        for at in find_all(data, b"trailer") {
            let mut lexer = Lexer::new(data, at + b"trailer".len());
            lexer.skip_whitespace();
            if let Ok(dict) = lexer.dictionary() {
                trailers.push((at, dict));
            }
        }
        // Cross-reference STREAMS carry the trailer in PDF 1.5 and later, so a
        // modern file has no `trailer` keyword at all.
        for (number, object) in &objects {
            if let Object::Stream(dict, _) = object {
                if dict.get("Type").and_then(Object::as_name) == Some("XRef") {
                    let at = offsets.get(number).copied().unwrap_or(0);
                    trailers.push((at, dict.clone()));
                }
            }
        }

        let trailer = trailers
            .into_iter()
            .filter(|(_, dict)| dict.has("Root"))
            .max_by_key(|(at, _)| *at)
            .map(|(_, dict)| dict)
            .ok_or(PdfError::NoCatalogue)?;

        if trailer.has("Encrypt") {
            return Err(PdfError::Encrypted);
        }

        let mut document = Self {
            objects,
            trailer,
            input_revisions: find_all(data, b"%%EOF").len(),
        };
        document.expand_object_streams(&offsets);
        Ok(document)
    }

    /// Unpack `/Type /ObjStm` containers so their contents are ordinary
    /// objects.
    ///
    /// Without this, a grep of the file for an identifier finds nothing while
    /// the identifier is present -- the objects are Flate-compressed INSIDE
    /// another object. Every verification claim in this crate depends on the
    /// object graph being flat.
    fn expand_object_streams(&mut self, offsets: &BTreeMap<u32, usize>) {
        let containers: Vec<(u32, Dict, Vec<u8>)> = self
            .objects
            .iter()
            .filter_map(|(number, object)| match object {
                Object::Stream(dict, raw)
                    if dict.get("Type").and_then(Object::as_name) == Some("ObjStm") =>
                {
                    Some((*number, dict.clone(), raw.clone()))
                }
                _ => None,
            })
            .collect();

        for (container, dict, raw) in containers {
            let Some(data) = decode_stream(&dict, &raw) else {
                continue;
            };
            let count = dict.get("N").and_then(Object::as_int).unwrap_or(0);
            let first = dict.get("First").and_then(Object::as_int).unwrap_or(0);
            let (Ok(count), Ok(first)) = (usize::try_from(count), usize::try_from(first)) else {
                continue;
            };
            let container_offset = offsets.get(&container).copied().unwrap_or(0);

            let mut header = Lexer::new(&data, 0);
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let (Ok(Object::Int(number)), Ok(Object::Int(relative))) =
                    (header.object(), header.object())
                else {
                    break;
                };
                pairs.push((number, relative));
            }
            for (number, relative) in pairs {
                let (Ok(number), Ok(relative)) = (u32::try_from(number), usize::try_from(relative))
                else {
                    continue;
                };
                // A direct object from a LATER revision outranks a packed one;
                // a packed object from a later revision outranks an earlier
                // direct one. Comparing the container's offset is what makes
                // the incremental-update rule apply to both forms.
                if offsets
                    .get(&number)
                    .is_some_and(|direct| *direct > container_offset)
                {
                    continue;
                }
                let mut lexer = Lexer::new(&data, first + relative);
                if let Ok(object) = lexer.object() {
                    self.objects.insert(number, object);
                }
            }
        }
    }

    /// Follow a reference to the object it names.
    #[must_use]
    pub fn resolve<'a>(&'a self, object: &'a Object) -> &'a Object {
        match object {
            Object::Reference(number, _) => self.objects.get(number).unwrap_or(&Object::Null),
            other => other,
        }
    }

    /// Look a key up in a dictionary and follow it if it is a reference.
    #[must_use]
    pub fn get<'a>(&'a self, dict: &'a Dict, key: &str) -> Option<&'a Object> {
        dict.get(key).map(|value| self.resolve(value))
    }

    /// The document catalogue.
    ///
    /// # Errors
    ///
    /// [`PdfError::NoCatalogue`] when `/Root` does not resolve to a dictionary.
    pub fn catalogue(&self) -> Result<&Dict, PdfError> {
        self.trailer
            .get("Root")
            .map(|root| self.resolve(root))
            .and_then(Object::as_dict)
            .ok_or(PdfError::NoCatalogue)
    }

    /// Every page object number, in document order.
    ///
    /// # Errors
    ///
    /// [`PdfError::NoCatalogue`] when there is no page tree.
    pub fn page_numbers(&self) -> Result<Vec<u32>, PdfError> {
        let catalogue = self.catalogue()?;
        let root = catalogue.get("Pages").ok_or(PdfError::NoPages)?;
        let mut pages = Vec::new();
        let mut seen = Vec::new();
        self.walk_pages(root, &mut pages, &mut seen, 0);
        if pages.is_empty() {
            return Err(PdfError::NoPages);
        }
        Ok(pages)
    }

    fn walk_pages(&self, node: &Object, pages: &mut Vec<u32>, seen: &mut Vec<u32>, depth: usize) {
        // A page tree with a cycle is malformed and also a hang; the depth
        // bound and the visited set are both cheap and both necessary.
        if depth > 64 {
            return;
        }
        let number = match node {
            Object::Reference(number, _) => Some(*number),
            _ => None,
        };
        if let Some(number) = number {
            if seen.contains(&number) {
                return;
            }
            seen.push(number);
        }
        let Some(dict) = self.resolve(node).as_dict() else {
            return;
        };
        match dict.get("Type").and_then(Object::as_name) {
            Some("Page") => {
                if let Some(number) = number {
                    pages.push(number);
                }
            }
            _ => {
                let Some(kids) = self.get(dict, "Kids").and_then(Object::as_array) else {
                    return;
                };
                for kid in kids {
                    self.walk_pages(kid, pages, seen, depth + 1);
                }
            }
        }
    }
}

/// Decode a stream's bytes through its `/Filter` chain.
///
/// Returns `None` for a filter this crate does not implement, which callers
/// treat as "cannot read, therefore cannot claim to have redacted".
#[must_use]
pub fn decode_stream(dict: &Dict, raw: &[u8]) -> Option<Vec<u8>> {
    let filters: Vec<&str> = match dict.get("Filter") {
        None => Vec::new(),
        Some(Object::Name(name)) => vec![name.as_str()],
        Some(Object::Array(items)) => items.iter().filter_map(Object::as_name).collect(),
        Some(_) => return None,
    };
    let mut data = raw.to_vec();
    for filter in filters {
        data = match filter {
            "FlateDecode" | "Fl" => zlib_decompress(&data).ok()?,
            // A stream whose filter this crate cannot undo is not readable, and
            // an unreadable stream must never be reported as "no PHI found".
            _ => return None,
        };
    }
    Some(data)
}

/// Find every `N G obj` header, returning (offset AFTER `obj`, object number).
fn scan_object_headers(data: &[u8]) -> Vec<(usize, u32)> {
    let mut found = Vec::new();
    for at in find_all(data, b"obj") {
        // `obj` must be a whole token: `endobj` ends with it, and so does a
        // name like `/Subj`.
        let after = data.get(at + 3).copied();
        if after.is_some_and(|byte| !is_whitespace(byte) && !crate::pdf::object::is_delimiter(byte))
        {
            continue;
        }
        // Walk backwards over `<digits> <ws> <digits> <ws>` to the object
        // number. A signed cursor rather than `checked_sub`, because a header
        // at byte 0 of the file is legal and an unsigned walk underflows on it.
        let mut cursor = at as i64 - 1;
        let mut back = |want_digits: bool| -> Option<usize> {
            let mut count = 0usize;
            while cursor >= 0 {
                let byte = data[cursor as usize];
                let matched = if want_digits {
                    byte.is_ascii_digit()
                } else {
                    is_whitespace(byte)
                };
                if !matched {
                    break;
                }
                count += 1;
                cursor -= 1;
            }
            (count > 0).then_some(count)
        };
        if back(false).is_none() || back(true).is_none() || back(false).is_none() {
            continue;
        }
        let Some(digits) = back(true) else {
            continue;
        };
        let start = (cursor + 1) as usize;
        let number = core::str::from_utf8(&data[start..start + digits])
            .ok()
            .and_then(|text| text.parse::<u32>().ok());
        if let Some(number) = number {
            found.push((at + 3, number));
        }
    }
    found
}

/// Parse the body of an indirect object, including its stream if it has one.
fn parse_body(lexer: &mut Lexer<'_>, data: &[u8]) -> Result<Object, PdfError> {
    let object = lexer.object().map_err(PdfError::Parse)?;
    let Object::Dict(dict) = object else {
        return Ok(object);
    };
    let save = lexer.at;
    if !lexer.eat_keyword("stream") {
        lexer.at = save;
        return Ok(Object::Dict(dict));
    }
    // §7.3.8.1: `stream` is followed by CRLF or LF, never by CR alone.
    let mut start = lexer.at;
    if data.get(start) == Some(&b'\r') {
        start += 1;
    }
    if data.get(start) == Some(&b'\n') {
        start += 1;
    }

    let declared = dict
        .get("Length")
        .and_then(Object::as_int)
        .and_then(|value| usize::try_from(value).ok());
    let end = declared
        .filter(|length| {
            // Trust /Length only when `endstream` is actually where it says.
            // Producers get this wrong, and a wrong length silently truncates
            // a page -- which would look like a successful redaction.
            let after = start + length;
            data.get(after..)
                .is_some_and(|tail| tail.trim_ascii_start().starts_with(b"endstream"))
        })
        .map(|length| start + length)
        .or_else(|| {
            find_all(&data[start..], b"endstream")
                .first()
                .map(|at| start + at)
        })
        .ok_or(PdfError::UnterminatedStream)?;

    let mut body = data.get(start..end).unwrap_or_default().to_vec();
    if declared.is_none() {
        // The `endstream` search includes the EOL that precedes the keyword.
        while matches!(body.last(), Some(b'\n' | b'\r')) {
            body.pop();
        }
    }
    Ok(Object::Stream(dict, body))
}

/// Every offset at which `needle` occurs.
#[must_use]
pub fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    (0..=data.len() - needle.len())
        .filter(|&at| &data[at..at + needle.len()] == needle)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_all_reports_every_occurrence_and_handles_the_empty_needle() {
        assert_eq!(find_all(b"aXbXc", b"X"), vec![1, 3]);
        assert!(find_all(b"abc", b"").is_empty());
        assert!(find_all(b"a", b"abc").is_empty());
    }

    #[test]
    fn a_non_pdf_is_refused_before_anything_is_parsed() {
        assert!(matches!(
            Document::load(b"PK\x03\x04"),
            Err(PdfError::NotAPdf)
        ));
    }

    #[test]
    fn an_object_header_is_recognised_only_as_a_whole_token() {
        // `endobj` ends in `obj`. A scanner that matches the substring finds a
        // phantom object at every object END, and every one of them shadows a
        // real object at a higher offset.
        let data = b"1 0 obj\n<< /A 1 >>\nendobj\n";
        let headers = scan_object_headers(data);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].1, 1);
    }
}
