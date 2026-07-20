//! Content streams: extract the text and edit the operands IN THE SAME PASS.
//!
//! # Why one pass
//!
//! The pipeline reports byte offsets into an extracted `&str`. Turning those
//! back into "which bytes of which operand" is only sound if the extractor
//! remembered, per output character, the operand bytes it came from. Nothing
//! reconstructs that afterwards: the encoding indirection in `font.rs` means a
//! search of the content stream for the identifier's UTF-8 finds nothing even
//! when the identifier is on the page. So extraction records provenance as it
//! goes, and redaction consumes it.
//!
//! # Removal, not covering
//!
//! The identifier's glyph codes are DELETED from the decoded content stream and
//! the stream is re-serialised uncompressed. Nothing is painted over anything.
//! A filled rectangle drawn on top of text changes no byte of the text: every
//! extractor, every copy-paste and every `pdftotext` recovers it, which is the
//! mechanism behind the Manafort filing and the EU/AstraZeneca contract leaks.
//!
//! # Why nothing is drawn in its place
//!
//! A black bar sized to the removed word leaks the word's rendered width, which
//! narrows a name guess -- the same length tell L5 exists to destroy in text.
//! Drawing a fixed-width bar instead would require font metrics and a text
//! matrix this module deliberately does not model. Deleting the codes leaves a
//! gap, which is honest: nothing on the page claims to be a redaction, and the
//! [`crate::pdf::Redaction`] report is where the count lives.

use core::ops::Range;
use std::collections::BTreeMap;

use crate::pdf::font::Font;
use crate::pdf::object::{is_delimiter, is_whitespace};

/// A string operand, with the source range of every decoded byte.
#[derive(Debug, Clone, Default)]
pub struct StringOperand {
    /// The decoded bytes -- glyph codes, not text.
    pub bytes: Vec<u8>,
    /// `ranges[i]` is where `bytes[i]` came from in the content stream.
    pub ranges: Vec<Range<usize>>,
}

/// One operand of a content-stream operator.
#[derive(Debug, Clone)]
pub enum Value {
    /// A number.
    Number(f64),
    /// `/Name`.
    Name(String),
    /// `(...)` or `<...>`.
    Str(StringOperand),
    /// `[ ... ]`, as used by `TJ`.
    Array(Vec<Value>),
    /// Anything else: dictionaries, booleans, nulls.
    Other,
}

/// One operator with the operands that preceded it.
#[derive(Debug, Clone)]
pub struct Operation {
    /// The operands, in order.
    pub operands: Vec<Value>,
    /// The operator token, e.g. `Tj`, `TJ`, `Tf`, `Td`.
    pub operator: String,
}

/// A chunk of extracted text and where it came from.
#[derive(Debug, Clone)]
pub struct Atom {
    /// The text this glyph code stands for.
    pub text: String,
    /// The bytes to delete to remove it, or `None` for text this module
    /// SYNTHESISED (the line breaks and spaces that make the page readable).
    /// Synthetic atoms are never deleted, because there is nothing there.
    pub source: Option<Range<usize>>,
}

/// The extracted text of one content stream.
#[derive(Debug, Clone, Default)]
pub struct Extraction {
    /// The atoms, in page order.
    pub atoms: Vec<Atom>,
    /// Codes that no font in scope could decode.
    ///
    /// A NON-ZERO VALUE MEANS THE PAGE WAS NOT FULLY READ, and the caller must
    /// treat it the way it treats a scan: refuse, rather than report a clean
    /// result over text it could not see.
    pub undecodable: usize,
}

impl Extraction {
    /// The page text the detection pipeline is run over.
    #[must_use]
    pub fn text(&self) -> String {
        self.atoms.iter().map(|atom| atom.text.as_str()).collect()
    }

    /// The source ranges of every atom overlapping a byte range of [`Self::text`].
    ///
    /// WHOLE ATOMS, always. A glyph code is atomic -- half of a two-byte CID is
    /// not a character -- so an atom the span touches at all is removed
    /// entirely. Over-removal is the safe direction (I2).
    #[must_use]
    pub fn ranges_for(&self, span: Range<usize>) -> Vec<Range<usize>> {
        self.ranges_in(span, false)
    }

    /// The page text with every SYNTHESISED separator dropped.
    ///
    /// # Why a second view exists
    ///
    /// [`Self::text`] inserts a `\n` after each show operator and a space for a
    /// large negative `TJ` kern, so that a page written as one long run reads
    /// with word boundaries and a rule anchored on one can fire. Those inserted
    /// characters land INSIDE an identifier whenever the producer split it —
    /// and justified or kerned text splits runs as a matter of course, so
    /// `TCKN 12345678901` written as `[(12345) -150 (678901)] TJ`, or as two
    /// consecutive `Tj` operators, read as two fragments and survived masking
    /// intact. Neither shape is exotic; both are ordinary producer output.
    ///
    /// Modelling the text matrix well enough to know which gaps are real is not
    /// something this module does, and guessing would trade a silent miss for a
    /// silent miss in the other direction. So both readings are produced and the
    /// caller runs detection over each, taking the UNION of what to delete —
    /// which is I2's rule: a missed identifier is a breach, an over-removed
    /// character is a gap on a page.
    #[must_use]
    pub fn glued_text(&self) -> String {
        self.atoms
            .iter()
            .filter(|atom| atom.source.is_some())
            .map(|atom| atom.text.as_str())
            .collect()
    }

    /// [`Self::ranges_for`], against offsets into [`Self::glued_text`].
    #[must_use]
    pub fn ranges_for_glued(&self, span: Range<usize>) -> Vec<Range<usize>> {
        self.ranges_in(span, true)
    }

    fn ranges_in(&self, span: Range<usize>, glued: bool) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        let mut at = 0usize;
        for atom in &self.atoms {
            if glued && atom.source.is_none() {
                continue;
            }
            let end = at + atom.text.len();
            if at < span.end && span.start < end {
                if let Some(source) = atom.source.clone() {
                    out.push(source);
                }
            }
            at = end;
        }
        out
    }
}

/// Tokenise a decoded content stream.
#[must_use]
pub fn parse(data: &[u8]) -> Vec<Operation> {
    let mut operations = Vec::new();
    let mut operands: Vec<Value> = Vec::new();
    let mut at = 0usize;

    while at < data.len() {
        let byte = data[at];
        if is_whitespace(byte) {
            at += 1;
            continue;
        }
        if byte == b'%' {
            while at < data.len() && data[at] != b'\n' && data[at] != b'\r' {
                at += 1;
            }
            continue;
        }
        match byte {
            b'(' | b'<' | b'[' | b'/' | b'+' | b'-' | b'.' | b'0'..=b'9' => {
                let (value, next) = value(data, at);
                operands.push(value);
                at = next;
            }
            b']' | b')' | b'>' | b'{' | b'}' => {
                // Unbalanced punctuation in a malformed stream. Skipped rather
                // than treated as an operator, which would clear the operands.
                at += 1;
            }
            _ => {
                let start = at;
                while at < data.len() && !is_whitespace(data[at]) && !is_delimiter(data[at]) {
                    at += 1;
                }
                let operator = String::from_utf8_lossy(&data[start..at]).into_owned();
                if operator == "BI" {
                    // An inline image's binary payload is not PDF syntax and
                    // must be skipped wholesale, or its bytes tokenise into
                    // nonsense operators that clear real operands.
                    at = skip_inline_image(data, at);
                    operands.clear();
                    continue;
                }
                operations.push(Operation {
                    operands: core::mem::take(&mut operands),
                    operator,
                });
            }
        }
    }
    operations
}

fn value(data: &[u8], at: usize) -> (Value, usize) {
    match data[at] {
        b'(' => {
            let (operand, next) = literal_string(data, at);
            (Value::Str(operand), next)
        }
        b'<' if data.get(at + 1) == Some(&b'<') => (Value::Other, skip_dictionary(data, at)),
        b'<' => {
            let (operand, next) = hex_string(data, at);
            (Value::Str(operand), next)
        }
        b'[' => {
            let mut items = Vec::new();
            let mut cursor = at + 1;
            while cursor < data.len() {
                if is_whitespace(data[cursor]) {
                    cursor += 1;
                    continue;
                }
                if data[cursor] == b']' {
                    cursor += 1;
                    break;
                }
                let (item, next) = value(data, cursor);
                if next == cursor {
                    cursor += 1;
                    continue;
                }
                items.push(item);
                cursor = next;
            }
            (Value::Array(items), cursor)
        }
        b'/' => {
            let mut cursor = at + 1;
            while cursor < data.len() && !is_whitespace(data[cursor]) && !is_delimiter(data[cursor])
            {
                cursor += 1;
            }
            (
                Value::Name(String::from_utf8_lossy(&data[at + 1..cursor]).into_owned()),
                cursor,
            )
        }
        _ => {
            let mut cursor = at;
            while cursor < data.len()
                && matches!(data[cursor], b'+' | b'-' | b'.' | b'0'..=b'9' | b'e' | b'E')
            {
                cursor += 1;
            }
            let text = String::from_utf8_lossy(&data[at..cursor]);
            let number = text.trim_end_matches('.').parse::<f64>().unwrap_or(0.0);
            (Value::Number(number), cursor)
        }
    }
}

fn skip_dictionary(data: &[u8], at: usize) -> usize {
    let mut cursor = at + 2;
    let mut depth = 1usize;
    while cursor < data.len() {
        if data[cursor] == b'<' && data.get(cursor + 1) == Some(&b'<') {
            depth += 1;
            cursor += 2;
            continue;
        }
        if data[cursor] == b'>' && data.get(cursor + 1) == Some(&b'>') {
            depth -= 1;
            cursor += 2;
            if depth == 0 {
                return cursor;
            }
            continue;
        }
        cursor += 1;
    }
    cursor
}

fn skip_inline_image(data: &[u8], at: usize) -> usize {
    // `BI <dict> ID <binary> EI`. `EI` must be preceded by white space and
    // followed by white space or end-of-stream, or a byte pair inside the pixel
    // data ends the image early.
    let mut cursor = at;
    while cursor + 1 < data.len() {
        if data[cursor] == b'I' && data[cursor + 1] == b'D' {
            cursor += 2;
            break;
        }
        cursor += 1;
    }
    while cursor + 1 < data.len() {
        if data[cursor] == b'E'
            && data[cursor + 1] == b'I'
            && cursor > 0
            && is_whitespace(data[cursor - 1])
            && data
                .get(cursor + 2)
                .is_none_or(|byte| is_whitespace(*byte) || is_delimiter(*byte))
        {
            return cursor + 2;
        }
        cursor += 1;
    }
    data.len()
}

fn literal_string(data: &[u8], at: usize) -> (StringOperand, usize) {
    let mut operand = StringOperand::default();
    let mut cursor = at + 1;
    let mut nesting = 1usize;
    while cursor < data.len() {
        let start = cursor;
        let byte = data[cursor];
        cursor += 1;
        let decoded = match byte {
            b'\\' => {
                let Some(escape) = data.get(cursor).copied() else {
                    break;
                };
                cursor += 1;
                match escape {
                    b'n' => Some(b'\n'),
                    b'r' => Some(b'\r'),
                    b't' => Some(b'\t'),
                    b'b' => Some(0x08),
                    b'f' => Some(0x0c),
                    b'\n' => None,
                    b'\r' => {
                        if data.get(cursor) == Some(&b'\n') {
                            cursor += 1;
                        }
                        None
                    }
                    b'0'..=b'7' => {
                        let mut octal = u32::from(escape - b'0');
                        for _ in 0..2 {
                            match data.get(cursor) {
                                Some(digit @ b'0'..=b'7') => {
                                    octal = octal * 8 + u32::from(digit - b'0');
                                    cursor += 1;
                                }
                                _ => break,
                            }
                        }
                        Some(u8::try_from(octal & 0xff).unwrap_or(0))
                    }
                    other => Some(other),
                }
            }
            b'(' => {
                nesting += 1;
                Some(byte)
            }
            b')' => {
                nesting -= 1;
                if nesting == 0 {
                    return (operand, cursor);
                }
                Some(byte)
            }
            other => Some(other),
        };
        if let Some(value) = decoded {
            operand.bytes.push(value);
            operand.ranges.push(start..cursor);
        }
    }
    (operand, cursor)
}

fn hex_string(data: &[u8], at: usize) -> (StringOperand, usize) {
    let mut operand = StringOperand::default();
    let mut cursor = at + 1;
    let mut high: Option<(u8, usize)> = None;
    while cursor < data.len() {
        let byte = data[cursor];
        cursor += 1;
        if byte == b'>' {
            break;
        }
        let Some(nibble) = char::from(byte).to_digit(16) else {
            continue;
        };
        let nibble = u8::try_from(nibble).unwrap_or(0);
        match high.take() {
            None => high = Some((nibble, cursor - 1)),
            Some((first, start)) => {
                operand.bytes.push((first << 4) | nibble);
                operand.ranges.push(start..cursor);
            }
        }
    }
    if let Some((first, start)) = high {
        // §7.3.4.3: an odd final digit is padded with a trailing zero.
        operand.bytes.push(first << 4);
        operand.ranges.push(start..cursor.min(data.len()));
    }
    (operand, cursor)
}

/// Extract the text of a content stream, with provenance.
///
/// `fonts` maps the resource names a `Tf` operator can select.
#[must_use]
pub fn extract(operations: &[Operation], fonts: &BTreeMap<String, Font>) -> Extraction {
    let mut out = Extraction::default();
    let mut current = Font::default();
    let mut have_font = false;

    for operation in operations {
        match operation.operator.as_str() {
            "Tf" => {
                if let Some(Value::Name(name)) = operation.operands.first() {
                    match fonts.get(name) {
                        Some(font) => {
                            current = font.clone();
                            have_font = true;
                        }
                        None => {
                            // A `Tf` naming a font that is not in the page's
                            // resources means this module does not know how to
                            // read what follows. The fallback decode is Latin-1
                            // and would produce plausible-looking wrong text.
                            current = Font::default();
                            have_font = false;
                        }
                    }
                }
            }
            "Tj" | "'" | "\"" => {
                if let Some(Value::Str(operand)) = operation.operands.last() {
                    push_string(&mut out, &current, have_font, operand);
                }
                out.atoms.push(synthetic("\n"));
            }
            "TJ" => {
                if let Some(Value::Array(items)) = operation.operands.last() {
                    for item in items {
                        match item {
                            Value::Str(operand) => {
                                push_string(&mut out, &current, have_font, operand);
                            }
                            // A large negative kerning adjustment is how a
                            // producer writes a space without emitting one.
                            // Without this the page reads as one long word and
                            // a rule anchored on a boundary never fires.
                            Value::Number(adjustment) if *adjustment <= -120.0 => {
                                out.atoms.push(synthetic(" "));
                            }
                            _ => {}
                        }
                    }
                }
                out.atoms.push(synthetic("\n"));
            }
            "Td" | "TD" | "T*" | "ET" => out.atoms.push(synthetic("\n")),
            _ => {}
        }
    }
    out
}

fn synthetic(text: &str) -> Atom {
    Atom {
        text: text.to_owned(),
        source: None,
    }
}

fn push_string(out: &mut Extraction, font: &Font, have_font: bool, operand: &StringOperand) {
    let mut index = 0usize;
    for (code, width) in font.codes(&operand.bytes) {
        let start = operand.ranges.get(index).map(|range| range.start);
        let end = operand.ranges.get(index + width - 1).map(|range| range.end);
        index += width;
        let source = match (start, end) {
            (Some(start), Some(end)) => Some(start..end),
            _ => None,
        };
        // No font in scope means no decoding table, and the Latin-1 fallback
        // would produce plausible-looking WRONG text -- which reads as a page
        // that was searched and found clean.
        let decoded = if have_font { font.text(code) } else { None };
        match decoded {
            Some(text) => out.atoms.push(Atom { text, source }),
            None => {
                out.undecodable += 1;
                // Recorded with EMPTY text but a real source range, so that a
                // caller which decides to redact the whole stream can still
                // reach these bytes.
                out.atoms.push(Atom {
                    text: String::new(),
                    source,
                });
            }
        }
    }
}

/// Delete byte ranges from a content stream.
///
/// Ranges may arrive in any order and may overlap; they are normalised first,
/// because deleting a stale range after an earlier deletion shifted the buffer
/// is how a redactor corrupts a page it meant to edit.
#[must_use]
pub fn delete(data: &[u8], ranges: &[Range<usize>]) -> Vec<u8> {
    let mut sorted: Vec<Range<usize>> = ranges
        .iter()
        .filter(|range| range.start < range.end && range.end <= data.len())
        .cloned()
        .collect();
    sorted.sort_by_key(|range| (range.start, range.end));

    let mut out = Vec::with_capacity(data.len());
    let mut cursor = 0usize;
    for range in sorted {
        if range.start >= cursor {
            out.extend_from_slice(&data[cursor..range.start]);
            cursor = range.end;
        } else if range.end > cursor {
            cursor = range.end;
        }
    }
    out.extend_from_slice(&data[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fonts() -> BTreeMap<String, Font> {
        let mut map = BTreeMap::new();
        map.insert("F1".to_owned(), Font::default());
        map
    }

    #[test]
    fn a_simple_text_object_extracts_and_maps_back() {
        let stream = b"BT /F1 12 Tf 72 720 Td (Hasta 123) Tj ET";
        let extraction = extract(&parse(stream), &fonts());
        assert!(extraction.text().contains("Hasta 123"));
        assert_eq!(extraction.undecodable, 0);

        let text = extraction.text();
        let at = text.find("123").expect("digits");
        let ranges = extraction.ranges_for(at..at + 3);
        assert_eq!(ranges.len(), 3);
        let edited = delete(stream, &ranges);
        assert!(!edited.windows(3).any(|w| w == b"123"));
        assert!(edited.windows(5).any(|w| w == b"Hasta"));
    }

    #[test]
    fn a_tj_array_is_read_and_kerning_becomes_a_space() {
        let stream = b"BT /F1 12 Tf [(Ay) -300 (se)] TJ ET";
        let extraction = extract(&parse(stream), &fonts());
        assert!(extraction.text().contains("Ay se"));
    }

    #[test]
    fn a_run_split_by_a_large_kern_is_contiguous_in_the_glued_reading() {
        // The producer's shape for justified text. In `text()` the -150 becomes
        // a space that lands mid-identifier, so a rule matching 11 consecutive
        // digits sees two fragments and the number survives redaction whole.
        let stream = b"BT /F1 12 Tf [(12345) -150 (678901)] TJ ET";
        let extraction = extract(&parse(stream), &fonts());
        assert!(
            !extraction.text().contains("12345678901"),
            "the separated reading is expected to split it; the glued one is the answer"
        );

        let glued = extraction.glued_text();
        let at = glued.find("12345678901").expect("contiguous when glued");
        let ranges = extraction.ranges_for_glued(at..at + 11);
        assert_eq!(ranges.len(), 11);
        let edited = delete(stream, &ranges);
        assert!(!String::from_utf8_lossy(&edited).contains("12345"));
        assert!(!String::from_utf8_lossy(&edited).contains("678901"));
    }

    #[test]
    fn a_run_split_across_two_show_operators_is_contiguous_in_the_glued_reading() {
        // Two `Tj` operators inside one text object: the synthetic newline after
        // the first one is what separated the halves.
        let stream = b"BT /F1 12 Tf (12345) Tj (678901) Tj ET";
        let extraction = extract(&parse(stream), &fonts());
        assert!(!extraction.text().contains("12345678901"));

        let glued = extraction.glued_text();
        let at = glued.find("12345678901").expect("contiguous when glued");
        let edited = delete(stream, &extraction.ranges_for_glued(at..at + 11));
        let rendered = String::from_utf8_lossy(&edited);
        assert!(!rendered.contains("12345"));
        assert!(!rendered.contains("678901"));
    }

    #[test]
    fn the_glued_reading_keeps_offsets_and_provenance_aligned() {
        // The failure this guards is off-by-one drift: `ranges_for_glued` walks
        // a different atom sequence to `ranges_for`, so an index computed on one
        // reading must never be resolved against the other.
        let stream = b"BT /F1 12 Tf (AB) Tj (CD) Tj ET";
        let extraction = extract(&parse(stream), &fonts());
        assert_eq!(extraction.glued_text(), "ABCD");
        let edited = delete(stream, &extraction.ranges_for_glued(1..3));
        let rendered = String::from_utf8_lossy(&edited);
        assert!(rendered.contains("(A) Tj"));
        assert!(rendered.contains("(D) Tj"));
    }

    #[test]
    fn escapes_in_a_literal_string_map_to_their_whole_source_range() {
        // `\101` is four source bytes for one glyph. Deleting only one of them
        // would leave `\10` behind, which renders as a different character --
        // a partial deletion is a corrupted page, not a redaction.
        let stream = br"BT /F1 12 Tf (\101B) Tj ET";
        let extraction = extract(&parse(stream), &fonts());
        assert_eq!(extraction.text().trim_end(), "AB");
        let ranges = extraction.ranges_for(0..1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].end - ranges[0].start, 4);
        let edited = delete(stream, &ranges);
        assert!(String::from_utf8_lossy(&edited).contains("(B) Tj"));
    }

    #[test]
    fn hex_strings_map_per_byte() {
        let stream = b"BT /F1 12 Tf <48 49> Tj ET";
        let extraction = extract(&parse(stream), &fonts());
        assert_eq!(extraction.text().trim_end(), "HI");
        let edited = delete(stream, &extraction.ranges_for(0..1));
        assert!(String::from_utf8_lossy(&edited).contains("< 49>"));
    }

    #[test]
    fn an_inline_image_payload_does_not_tokenise_into_operators() {
        // The binary between `ID` and `EI` contains bytes that look like
        // operators. Without the skip they clear the operand stack and the
        // text after the image is lost -- silently unredacted.
        let stream = b"BT /F1 12 Tf (before) Tj ET\nBI /W 1 /H 1 ID \x00Tj(x)\xff EI\nBT /F1 12 Tf (after) Tj ET";
        let extraction = extract(&parse(stream), &fonts());
        let text = extraction.text();
        assert!(text.contains("before"));
        assert!(text.contains("after"));
    }

    #[test]
    fn overlapping_and_unsorted_deletions_are_normalised() {
        // {1,2} and {2,3} overlap into {1,2,3}; {6,7} is separate.
        assert_eq!(
            delete(b"0123456789", &[6..8, 1..3, 2..4]),
            b"04589".to_vec()
        );
        // A range past the end of the buffer is dropped, not clamped: a
        // clamped range would delete bytes nobody asked about.
        assert_eq!(delete(b"abc", &[5..9, 7..8]), b"abc".to_vec());
    }

    #[test]
    fn an_undecodable_code_is_counted_rather_than_guessed_at() {
        // A Type0 font with no /ToUnicode. Reporting this page as clean would
        // be the vacuous pass the whole module exists to avoid.
        let mut map = BTreeMap::new();
        map.insert(
            "F1".to_owned(),
            Font {
                two_byte: true,
                ..Font::default()
            },
        );
        let extraction = extract(&parse(b"BT /F1 12 Tf <00030004> Tj ET"), &map);
        assert_eq!(extraction.undecodable, 2);
        assert!(extraction.text().trim().is_empty());
    }
}
