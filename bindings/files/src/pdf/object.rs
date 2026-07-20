//! The ISO 32000-1 object model, and a parser for it.
//!
//! Deliberately small: eight object types, an order-preserving dictionary, and
//! a lexer. There is no xref-table interpreter here, and that is a design
//! decision rather than an omission -- see `document.rs`.

use core::fmt;

/// How a string was written in the file.
///
/// Preserved because a hex string and a literal string with the same bytes are
/// the same VALUE but not the same TEXT, and a redaction diff that rewrote
/// every string into one form would bury the real edit in churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringForm {
    /// `(text)`.
    Literal,
    /// `<48657861>`.
    Hex,
}

/// A PDF object.
#[derive(Clone, PartialEq)]
pub enum Object {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A real number.
    Real(f64),
    /// A string, as BYTES.
    ///
    /// Never a `String`: PDF strings are PDFDocEncoded or UTF-16BE, and
    /// deciding which is the caller's job (see [`Object::as_text`]).
    Str(Vec<u8>, StringForm),
    /// `/Name`.
    Name(String),
    /// `[ ... ]`.
    Array(Vec<Object>),
    /// `<< ... >>`.
    Dict(Dict),
    /// A stream: its dictionary and its RAW (still encoded) bytes.
    Stream(Dict, Vec<u8>),
    /// `N G R`, an indirect reference.
    Reference(u32, u16),
}

/// Hand-written so `{:?}` on a PDF object can never print document text (I4).
///
/// A PDF string IS clinical text -- it is what a page shows. Deriving Debug
/// here would put a patient name into any `assert_eq!` failure or panic
/// message in this module.
impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(value) => write!(f, "Bool({value})"),
            Self::Int(value) => write!(f, "Int({value})"),
            Self::Real(value) => write!(f, "Real({value})"),
            Self::Str(_, form) => write!(f, "Str(<redacted>, {form:?})"),
            Self::Name(name) => write!(f, "Name(/{name})"),
            Self::Array(items) => f.debug_tuple("Array").field(items).finish(),
            Self::Dict(dict) => f.debug_tuple("Dict").field(dict).finish(),
            Self::Stream(dict, bytes) => write!(f, "Stream({dict:?}, {} bytes)", bytes.len()),
            Self::Reference(number, generation) => write!(f, "Ref({number} {generation})"),
        }
    }
}

/// A PDF dictionary, with key order preserved.
#[derive(Clone, Default, PartialEq)]
pub struct Dict(pub Vec<(String, Object)>);

/// Keys are structural (`/Type`, `/Author`); VALUES are document text.
impl fmt::Debug for Dict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (key, value) in &self.0 {
            map.entry(&format_args!("/{key}"), value);
        }
        map.finish()
    }
}

impl Dict {
    /// Look a key up.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Object> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Look a key up for mutation.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Object> {
        self.0
            .iter_mut()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// True when the key is present.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Remove a key, returning whether it was there.
    ///
    /// The workhorse of the metadata sweep: most of what a PDF hides is
    /// removed by deleting a key, not by editing a value.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.0.len();
        self.0.retain(|(name, _)| name != key);
        before != self.0.len()
    }

    /// Insert or overwrite, keeping the original position when overwriting.
    pub fn set(&mut self, key: &str, value: Object) {
        match self.get_mut(key) {
            Some(slot) => *slot = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }
}

impl Object {
    /// The dictionary of a dict or a stream.
    #[must_use]
    pub const fn as_dict(&self) -> Option<&Dict> {
        match self {
            Self::Dict(dict) | Self::Stream(dict, _) => Some(dict),
            _ => None,
        }
    }

    /// The dictionary of a dict or a stream, for mutation.
    pub fn as_dict_mut(&mut self) -> Option<&mut Dict> {
        match self {
            Self::Dict(dict) | Self::Stream(dict, _) => Some(dict),
            _ => None,
        }
    }

    /// An integer, accepting a real that happens to be whole.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            Self::Real(value) => Some(*value as i64),
            _ => None,
        }
    }

    /// The name, without its slash.
    #[must_use]
    pub fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            _ => None,
        }
    }

    /// The array items.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Object]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Decode a PDF text string to Rust text.
    ///
    /// UTF-16BE when the BOM is present -- which is how every producer writes
    /// Turkish -- and PDFDocEncoding otherwise, which agrees with Latin-1 over
    /// the range that matters here.
    #[must_use]
    pub fn as_text(&self) -> Option<String> {
        let Self::Str(bytes, _) = self else {
            return None;
        };
        if let [0xfe, 0xff, rest @ ..] = bytes.as_slice() {
            let units: Vec<u16> = rest
                .chunks_exact(2)
                .map(|pair| (u16::from(pair[0]) << 8) | u16::from(pair[1]))
                .collect();
            return Some(String::from_utf16_lossy(&units));
        }
        Some(bytes.iter().map(|&byte| char::from(byte)).collect())
    }

    /// Build a PDF text string from Rust text.
    ///
    /// Always UTF-16BE, because a surrogate or a label may contain characters
    /// PDFDocEncoding cannot represent and a silently-substituted `?` in a
    /// replacement is a defect that looks like a rendering quirk.
    #[must_use]
    pub fn text(value: &str) -> Self {
        let mut bytes = vec![0xfe, 0xff];
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Self::Str(bytes, StringForm::Hex)
    }
}

/// The object parser could not make sense of the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The bytes ended mid-object.
    #[error("the PDF object ended unexpectedly")]
    Truncated,
    /// A byte that starts no object.
    #[error("unexpected byte at offset {offset} in a PDF object")]
    Unexpected {
        /// Byte offset into the buffer being parsed.
        offset: usize,
    },
    /// Nesting past [`MAX_DEPTH`].
    #[error("the PDF object nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
}

/// Nesting ceiling, for the same stack-safety reason as the JSON parser's.
pub const MAX_DEPTH: usize = 96;

/// A cursor over PDF syntax.
pub struct Lexer<'a> {
    data: &'a [u8],
    /// Current byte offset. Public because the document scanner drives it.
    pub at: usize,
    depth: usize,
}

/// True for the PDF white-space characters (§7.2.2).
#[must_use]
pub const fn is_whitespace(byte: u8) -> bool {
    matches!(byte, 0x00 | 0x09 | 0x0a | 0x0c | 0x0d | 0x20)
}

/// True for the PDF delimiter characters (§7.2.2).
#[must_use]
pub const fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

impl<'a> Lexer<'a> {
    /// Start at a byte offset.
    #[must_use]
    pub const fn new(data: &'a [u8], at: usize) -> Self {
        Self { data, at, depth: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.at).copied()
    }

    /// Skip white space and `%` comments.
    pub fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if is_whitespace(byte) {
                self.at += 1;
            } else if byte == b'%' {
                while let Some(inner) = self.peek() {
                    self.at += 1;
                    if inner == b'\n' || inner == b'\r' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Read a bare keyword such as `obj`, `stream` or `R`.
    pub fn keyword(&mut self) -> String {
        self.skip_whitespace();
        let start = self.at;
        while let Some(byte) = self.peek() {
            if is_whitespace(byte) || is_delimiter(byte) {
                break;
            }
            self.at += 1;
        }
        String::from_utf8_lossy(&self.data[start..self.at]).into_owned()
    }

    /// True when the next token is exactly this keyword; consumes it if so.
    pub fn eat_keyword(&mut self, word: &str) -> bool {
        let save = self.at;
        if self.keyword() == word {
            return true;
        }
        self.at = save;
        false
    }

    /// Parse one object.
    ///
    /// # Errors
    ///
    /// [`ParseError`] when the bytes are not a PDF object.
    pub fn object(&mut self) -> Result<Object, ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return Err(ParseError::TooDeep);
        }
        // The decrement happens on the ERROR path too, deliberately. This
        // lexer is driven speculatively -- `/ToUnicode` parsing tries
        // `object()` at every token and falls back to `keyword()` -- so a
        // depth counter that leaks on failure would climb past MAX_DEPTH and
        // turn a readable font into an unreadable one after a few hundred
        // tokens.
        let value = self.object_inner();
        self.depth -= 1;
        value
    }

    fn object_inner(&mut self) -> Result<Object, ParseError> {
        self.skip_whitespace();
        let byte = self.peek().ok_or(ParseError::Truncated)?;
        match byte {
            b'/' => Ok(Object::Name(self.name())),
            b'(' => Ok(Object::Str(self.literal_string()?, StringForm::Literal)),
            b'<' => {
                if self.data.get(self.at + 1) == Some(&b'<') {
                    Ok(Object::Dict(self.dictionary()?))
                } else {
                    Ok(Object::Str(self.hex_string()?, StringForm::Hex))
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_whitespace();
                    match self.peek().ok_or(ParseError::Truncated)? {
                        b']' => {
                            self.at += 1;
                            return Ok(Object::Array(items));
                        }
                        _ => items.push(self.object()?),
                    }
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.number_or_reference(),
            b't' | b'f' | b'n' => match self.keyword().as_str() {
                "true" => Ok(Object::Bool(true)),
                "false" => Ok(Object::Bool(false)),
                "null" => Ok(Object::Null),
                _ => Err(ParseError::Unexpected { offset: self.at }),
            },
            _ => Err(ParseError::Unexpected { offset: self.at }),
        }
    }

    /// `<< ... >>`, stopping before any `stream` keyword.
    ///
    /// # Errors
    ///
    /// [`ParseError`] when the dictionary is malformed.
    pub fn dictionary(&mut self) -> Result<Dict, ParseError> {
        self.at += 2;
        let mut dict = Dict::default();
        loop {
            self.skip_whitespace();
            match self.peek().ok_or(ParseError::Truncated)? {
                b'>' => {
                    self.at += 2;
                    return Ok(dict);
                }
                b'/' => {
                    let key = self.name();
                    let value = self.object()?;
                    dict.0.push((key, value));
                }
                _ => return Err(ParseError::Unexpected { offset: self.at }),
            }
        }
    }

    fn name(&mut self) -> String {
        self.at += 1;
        let mut out = String::new();
        while let Some(byte) = self.peek() {
            if is_whitespace(byte) || is_delimiter(byte) {
                break;
            }
            self.at += 1;
            if byte == b'#' {
                let hex = self
                    .data
                    .get(self.at..self.at + 2)
                    .and_then(|pair| core::str::from_utf8(pair).ok())
                    .and_then(|text| u8::from_str_radix(text, 16).ok());
                if let Some(value) = hex {
                    self.at += 2;
                    out.push(char::from(value));
                    continue;
                }
            }
            out.push(char::from(byte));
        }
        out
    }

    fn number_or_reference(&mut self) -> Result<Object, ParseError> {
        let save = self.at;
        let first = self.number()?;
        if let Object::Int(number) = first {
            let after_number = self.at;
            let mut probe = Self::new(self.data, self.at);
            if let Ok(Object::Int(generation)) = probe.number() {
                if probe.eat_keyword("R") {
                    self.at = probe.at;
                    let number = u32::try_from(number)
                        .map_err(|_| ParseError::Unexpected { offset: save })?;
                    let generation = u16::try_from(generation).unwrap_or(0);
                    return Ok(Object::Reference(number, generation));
                }
            }
            self.at = after_number;
        }
        Ok(first)
    }

    fn number(&mut self) -> Result<Object, ParseError> {
        self.skip_whitespace();
        let start = self.at;
        let mut real = false;
        while let Some(byte) = self.peek() {
            match byte {
                b'+' | b'-' | b'0'..=b'9' => self.at += 1,
                b'.' => {
                    real = true;
                    self.at += 1;
                }
                _ => break,
            }
        }
        let text = core::str::from_utf8(&self.data[start..self.at])
            .map_err(|_| ParseError::Unexpected { offset: start })?;
        if text.is_empty() {
            return Err(ParseError::Unexpected { offset: start });
        }
        if real {
            // A trailing `.` is legal PDF (`5.`) and not legal Rust.
            let cleaned = text.trim_end_matches('.');
            return cleaned
                .parse::<f64>()
                .map(Object::Real)
                .map_err(|_| ParseError::Unexpected { offset: start });
        }
        text.parse::<i64>()
            .map(Object::Int)
            .map_err(|_| ParseError::Unexpected { offset: start })
    }

    fn literal_string(&mut self) -> Result<Vec<u8>, ParseError> {
        self.at += 1;
        let mut out = Vec::new();
        let mut nesting = 1usize;
        loop {
            let byte = self.peek().ok_or(ParseError::Truncated)?;
            self.at += 1;
            match byte {
                b'\\' => {
                    let escape = self.peek().ok_or(ParseError::Truncated)?;
                    self.at += 1;
                    match escape {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'\n' => {}
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.at += 1;
                            }
                        }
                        b'0'..=b'7' => {
                            let mut value = u32::from(escape - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(digit @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(digit - b'0');
                                        self.at += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(u8::try_from(value & 0xff).unwrap_or(0));
                        }
                        other => out.push(other),
                    }
                }
                b'(' => {
                    nesting += 1;
                    out.push(byte);
                }
                b')' => {
                    nesting -= 1;
                    if nesting == 0 {
                        return Ok(out);
                    }
                    out.push(byte);
                }
                other => out.push(other),
            }
        }
    }

    fn hex_string(&mut self) -> Result<Vec<u8>, ParseError> {
        self.at += 1;
        let mut nibbles = Vec::new();
        loop {
            let byte = self.peek().ok_or(ParseError::Truncated)?;
            self.at += 1;
            match byte {
                b'>' => break,
                _ if is_whitespace(byte) => {}
                _ => {
                    let value = char::from(byte)
                        .to_digit(16)
                        .ok_or(ParseError::Unexpected {
                            offset: self.at - 1,
                        })?;
                    nibbles.push(u8::try_from(value).unwrap_or(0));
                }
            }
        }
        // An odd nibble count means the last digit is a high nibble; §7.3.4.3.
        if nibbles.len() % 2 == 1 {
            nibbles.push(0);
        }
        Ok(nibbles
            .chunks_exact(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Object {
        Lexer::new(source.as_bytes(), 0).object().expect("object")
    }

    #[test]
    fn primitives_parse() {
        assert_eq!(parse("true"), Object::Bool(true));
        assert_eq!(parse("null"), Object::Null);
        assert_eq!(parse("-42"), Object::Int(-42));
        assert_eq!(parse("3.5"), Object::Real(3.5));
        assert_eq!(parse("5."), Object::Real(5.0));
        assert_eq!(parse("/Type"), Object::Name("Type".to_owned()));
        assert_eq!(parse("/A#20B"), Object::Name("A B".to_owned()));
    }

    #[test]
    fn a_reference_is_not_two_numbers() {
        assert_eq!(parse("12 0 R"), Object::Reference(12, 0));
        // And two numbers that are NOT a reference must stay two numbers, or
        // an array of coordinates silently becomes one object.
        assert_eq!(
            parse("[1 2 3]"),
            Object::Array(vec![Object::Int(1), Object::Int(2), Object::Int(3)])
        );
    }

    #[test]
    fn literal_string_escapes_and_nesting() {
        assert_eq!(
            parse(r"(a\(b\)c)"),
            Object::Str(b"a(b)c".to_vec(), StringForm::Literal)
        );
        assert_eq!(
            parse("(a(b)c)"),
            Object::Str(b"a(b)c".to_vec(), StringForm::Literal)
        );
        assert_eq!(
            parse(r"(\101\n)"),
            Object::Str(b"A\n".to_vec(), StringForm::Literal)
        );
    }

    #[test]
    fn hex_strings_pad_an_odd_final_nibble() {
        assert_eq!(
            parse("<48656C6C6F>"),
            Object::Str(b"Hello".to_vec(), StringForm::Hex)
        );
        assert_eq!(parse("<4>"), Object::Str(vec![0x40], StringForm::Hex));
    }

    #[test]
    fn dictionaries_keep_key_order() {
        let Object::Dict(dict) = parse("<< /Type /Page /Parent 3 0 R >>") else {
            panic!("dict");
        };
        assert_eq!(dict.0[0].0, "Type");
        assert_eq!(dict.0[1].0, "Parent");
        assert_eq!(dict.get("Parent"), Some(&Object::Reference(3, 0)));
    }

    #[test]
    fn utf16_text_strings_round_trip() {
        let object = Object::text("Şükrü");
        assert_eq!(object.as_text().as_deref(), Some("Şükrü"));
        // And a plain byte string decodes as PDFDocEncoding.
        assert_eq!(
            Object::Str(b"Hasta".to_vec(), StringForm::Literal)
                .as_text()
                .as_deref(),
            Some("Hasta")
        );
    }

    #[test]
    fn debug_on_a_string_object_never_prints_the_string() {
        let rendered = format!("{:?}", Object::text("Ayşe Yılmaz"));
        assert!(!rendered.contains("Ayşe"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn nesting_past_the_ceiling_is_refused() {
        let deep = "[".repeat(MAX_DEPTH + 2);
        assert_eq!(
            Lexer::new(deep.as_bytes(), 0).object(),
            Err(ParseError::TooDeep)
        );
    }
}
