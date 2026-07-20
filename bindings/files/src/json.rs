//! JSON: walk the tree, de-identify string VALUES, preserve keys and shape.
//!
//! # Why a parser lives here instead of `serde_json`
//!
//! `serde_json`'s default `Value` stores objects in a `BTreeMap`, so
//! round-tripping a document REORDERS ITS KEYS. Preserving order needs the
//! `preserve_order` feature, which needs `indexmap`, which is not in this
//! workspace's Cargo.lock -- and acquiring it is a network resolve (see
//! `Cargo.toml`). Since "preserve the shape" is the requirement, and the
//! requirement is the part serde_json's default does not meet, the tree is
//! modelled here as an ordered `Vec<(String, Json)>`.
//!
//! # Keys are not values
//!
//! Object keys are left ALONE. A key is a schema name (`hastaAdi`, `tckn`),
//! chosen by the system that wrote the file, not by the patient. Masking keys
//! would destroy the document's shape for zero privacy gain. A key that
//! genuinely contains an identifier is a data-modelling failure upstream and is
//! not something this layer can fix without making every consumer of the file
//! break.
//!
//! Numbers are also left alone, deliberately and visibly: a TCKN stored as a
//! JSON *number* is not a string and this module does not reach it. That is
//! recorded in [`Masked`] semantics and tested, rather than silently accepted.
//!
//! HONEST SCOPE: only rule-detectable identifiers are removed. See
//! [`crate::Report::rule_detectable_only`].

use crate::masker::{Masked, Masker};

/// A JSON value, with object key order preserved.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, kept as its ORIGINAL TEXT.
    ///
    /// Never parsed to `f64` and re-formatted: `1.10`, `1e3` and a 20-digit
    /// integer all survive a round trip unchanged this way, and an identifier
    /// stored as a long number does not silently become `1.2345678901e10`.
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object. Ordered, so serialising reproduces the input's key order.
    Object(Vec<(String, Json)>),
}

/// A malformed JSON document.
///
/// Carries a BYTE OFFSET, never the offending text (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// A token that is not valid JSON at this position.
    #[error("invalid JSON at byte {offset}")]
    Invalid {
        /// Byte offset into the document.
        offset: usize,
    },
    /// The document ended mid-value.
    #[error("the JSON document ended unexpectedly")]
    Truncated,
    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("the JSON document nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
    /// Content after the top-level value.
    #[error("trailing content after the JSON value at byte {offset}")]
    Trailing {
        /// Byte offset of the first trailing byte.
        offset: usize,
    },
}

/// Nesting ceiling.
///
/// A bound, not a preference: the parser recurses, so an input of 100k open
/// brackets would blow the stack of a tool running on a clinical workstation.
pub const MAX_DEPTH: usize = 128;

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

/// Parse a JSON document.
///
/// # Errors
///
/// [`JsonError`] when the document is not valid JSON.
pub fn parse(text: &str) -> Result<Json, JsonError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
        depth: 0,
    };
    parser.skip_whitespace();
    let value = parser.value()?;
    parser.skip_whitespace();
    if parser.at < parser.bytes.len() {
        return Err(JsonError::Trailing { offset: parser.at });
    }
    Ok(value)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        match self.peek() {
            Some(found) if found == byte => {
                self.at += 1;
                Ok(())
            }
            // "ran out" and "wrong character" are different defects and a
            // caller acting on them differs: a truncated export can be retried,
            // a malformed one cannot.
            None => Err(JsonError::Truncated),
            Some(_) => Err(JsonError::Invalid { offset: self.at }),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), JsonError> {
        if self.bytes.get(self.at..self.at + word.len()) == Some(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(JsonError::Invalid { offset: self.at })
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        let value = match self.peek().ok_or(JsonError::Truncated)? {
            b'n' => {
                self.literal(b"null")?;
                Json::Null
            }
            b't' => {
                self.literal(b"true")?;
                Json::Bool(true)
            }
            b'f' => {
                self.literal(b"false")?;
                Json::Bool(false)
            }
            b'"' => Json::String(self.string()?),
            b'[' => self.array()?,
            b'{' => self.object()?,
            b'-' | b'0'..=b'9' => self.number()?,
            _ => return Err(JsonError::Invalid { offset: self.at }),
        };
        self.depth -= 1;
        Ok(value)
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value()?);
            self.skip_whitespace();
            match self.peek().ok_or(JsonError::Truncated)? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(JsonError::Invalid { offset: self.at }),
            }
        }
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.expect(b'{')?;
        let mut fields = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value()?;
            fields.push((key, value));
            self.skip_whitespace();
            match self.peek().ok_or(JsonError::Truncated)? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    return Ok(Json::Object(fields));
                }
                _ => return Err(JsonError::Invalid { offset: self.at }),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        // A lone `-` would otherwise parse as the number "-" and serialise back
        // out as invalid JSON, which is worse than refusing the input.
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(JsonError::Invalid { offset: start });
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.at += 1;
        }
        self.bytes
            .get(start..self.at)
            .filter(|slice| !slice.is_empty())
            .and_then(|slice| core::str::from_utf8(slice).ok())
            .map(|text| Json::Number(text.to_owned()))
            .ok_or(JsonError::Invalid { offset: start })
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or(JsonError::Truncated)?;
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek().ok_or(JsonError::Truncated)?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => {
                            return Err(JsonError::Invalid {
                                offset: self.at - 1,
                            })
                        }
                    }
                }
                _ => {
                    // Copy whole UTF-8 characters: `ş` is two bytes and pushing
                    // them one at a time is not expressible as `char`.
                    let rest = self.bytes.get(self.at..).ok_or(JsonError::Truncated)?;
                    let text = core::str::from_utf8(rest)
                        .map_err(|_| JsonError::Invalid { offset: self.at })?;
                    let value = text.chars().next().ok_or(JsonError::Truncated)?;
                    out.push(value);
                    self.at += value.len_utf8();
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let read_unit = |parser: &mut Self| -> Result<u16, JsonError> {
            let slice = parser
                .bytes
                .get(parser.at..parser.at + 4)
                .ok_or(JsonError::Truncated)?;
            let text = core::str::from_utf8(slice)
                .map_err(|_| JsonError::Invalid { offset: parser.at })?;
            let unit = u16::from_str_radix(text, 16)
                .map_err(|_| JsonError::Invalid { offset: parser.at })?;
            parser.at += 4;
            Ok(unit)
        };
        let high = read_unit(self)?;
        if (0xd800..0xdc00).contains(&high) {
            // A surrogate pair. Rejecting it rather than substituting U+FFFD:
            // this document round-trips, and a lossy substitution is an edit
            // the caller did not ask for.
            self.expect(b'\\')?;
            self.expect(b'u')?;
            let low = read_unit(self)?;
            let combined =
                0x1_0000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
            return char::from_u32(combined).ok_or(JsonError::Invalid { offset: self.at });
        }
        char::from_u32(u32::from(high)).ok_or(JsonError::Invalid { offset: self.at })
    }
}

/// Serialise a JSON value, compactly.
#[must_use]
pub fn to_string(value: &Json) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(text) => out.push_str(text),
        Json::String(text) => write_string(text, out),
        Json::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Json::Object(fields) => {
            out.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(item, out);
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for value in text.chars() {
        match value {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            // Non-ASCII is emitted RAW rather than as `\uXXXX`. Turkish text is
            // mostly non-ASCII and escaping it would triple the size of every
            // clinical field and make the output unreadable to a reviewer.
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// De-identify every string VALUE in a JSON document.
///
/// # Errors
///
/// [`JsonError`] when the input is not valid JSON, or whatever the pipeline
/// returns.
pub fn mask(masker: &Masker<'_>, text: &str) -> Result<Masked, crate::FileError> {
    let mut tree = parse(text)?;
    let mut originals = Vec::new();
    walk(masker, &mut tree, &mut originals)?;
    Ok(Masked {
        text: to_string(&tree),
        originals,
    })
}

fn walk(
    masker: &Masker<'_>,
    value: &mut Json,
    originals: &mut Vec<String>,
) -> Result<(), crate::FileError> {
    match value {
        Json::String(text) => {
            let masked = masker.mask(text)?;
            originals.extend(masked.originals);
            *text = masked.text;
        }
        Json::Array(items) => {
            for item in items {
                walk(masker, item, originals)?;
            }
        }
        Json::Object(fields) => {
            for (_key, item) in fields {
                walk(masker, item, originals)?;
            }
        }
        Json::Null | Json::Bool(_) | Json::Number(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tckn;
    use deid_tr_core::{Pipeline, Tier};

    #[test]
    fn key_order_and_number_formatting_survive_a_round_trip() {
        // The property `serde_json`'s default `Value` does not have, and the
        // reason this parser exists.
        let source = r#"{"zeta":1.10,"alpha":[1e3,null,true],"beta":{"gamma":"x"}}"#;
        assert_eq!(to_string(&parse(source).expect("parse")), source);
    }

    #[test]
    fn masking_rewrites_string_values_and_leaves_keys_alone() {
        let tckn = tckn();
        let source = format!(r#"{{"tckn":"{tckn}","ad":"Ayşe","yas":42}}"#);
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let masked = mask(&Masker::new(&pipeline), &source).expect("mask");
        assert!(!masked.text.contains(&tckn));
        assert!(masked.text.contains(r#""tckn":"#), "the key was rewritten");
        assert!(
            masked.text.contains(r#""yas":42"#),
            "a number was rewritten"
        );
        // The name survives: no model is installed.
        assert!(masked.text.contains("Ayşe"));
        assert_eq!(masked.originals, vec![tckn]);
    }

    #[test]
    fn an_identifier_stored_as_a_json_number_is_not_reached() {
        // NOT A BUG REPORT, A DOCUMENTED LIMIT. This module de-identifies
        // strings. A TCKN written as a bare JSON number survives, and a caller
        // whose schema does that needs to know rather than to assume.
        let tckn = tckn();
        let source = format!(r#"{{"tckn":{tckn}}}"#);
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let masked = mask(&Masker::new(&pipeline), &source).expect("mask");
        assert!(masked.text.contains(&tckn));
        assert!(masked.originals.is_empty());
    }

    #[test]
    fn escapes_and_non_ascii_round_trip() {
        let source = r#"{"a":"line\nbreak \"quoted\" ş","b":"ç"}"#;
        let parsed = parse(source).expect("parse");
        let Json::Object(fields) = &parsed else {
            panic!("object");
        };
        assert_eq!(
            fields[0].1,
            Json::String("line\nbreak \"quoted\" ş".to_owned())
        );
        assert_eq!(fields[1].1, Json::String("ç".to_owned()));
        assert_eq!(
            to_string(&parsed),
            r#"{"a":"line\nbreak \"quoted\" ş","b":"ç"}"#
        );
    }

    #[test]
    fn a_surrogate_pair_escape_decodes_to_one_character() {
        assert_eq!(
            parse("\"\\ud83d\\ude00\"").expect("parse"),
            Json::String("\u{1f600}".to_owned())
        );
    }

    #[test]
    fn malformed_input_reports_an_offset_and_never_the_text() {
        let error = parse(r#"{"hastaAdi":}"#).expect_err("invalid");
        assert_eq!(error, JsonError::Invalid { offset: 12 });
        assert!(
            !format!("{error}").contains("hastaAdi"),
            "the error rendered the document"
        );
        assert_eq!(parse("{"), Err(JsonError::Truncated));
        assert_eq!(parse("1 2"), Err(JsonError::Trailing { offset: 2 }));
    }

    #[test]
    fn nesting_past_the_ceiling_is_refused_rather_than_overflowing_the_stack() {
        let deep = "[".repeat(MAX_DEPTH + 2);
        assert_eq!(parse(&deep), Err(JsonError::TooDeep));
    }
}
