//! Defensive parsing of whatever the local model actually returned.
//!
//! WHY A HAND-WRITTEN PARSER AND NOT A JSON CRATE. Two reasons, and only the
//! second is about dependencies. The first is that a general JSON library is
//! built to accept documents, while this module is built to REFUSE them: it
//! rejects at a fixed depth, a fixed item count and a closed key vocabulary,
//! and every rejection is classified into [`ResponseDefect`] so the failure can
//! be counted in an eval run rather than merely logged. The second is I1 and
//! the wasm target -- `core/` carries `thiserror` and `regex` and argues for
//! each addition in the manifest, and roughly three hundred lines of parser is
//! a smaller thing to own than a general deserialiser plus its derive macros.
//!
//! WHAT "DEFENSIVE" MEANS HERE, CONCRETELY:
//!
//! - A malformed response is an `Err`, never a panic. There is no indexing, no
//!   slicing by range and no `unwrap` anywhere below; every read goes through
//!   `get`.
//! - NO ERROR CARRIES THE RESPONSE (I4). A model asked to quote the patient's
//!   employer verbatim puts that employer in the first field of its answer, so
//!   its output is document-derived content. The errors carry a defect class, a
//!   byte position and a length -- enough to find the problem while holding the
//!   response in memory, useless to anyone who is not.
//! - Prose and code fences around the JSON are expected rather than treated as
//!   a failure. Small local models routinely answer "İşte bulgular:" and then a
//!   fenced block, and refusing that costs recall for no privacy gain. The
//!   recovery is uniform: scan for a `[`, try to parse an array there, and move
//!   to the next `[` if it does not parse. Fences need no special case because
//!   backticks are not brackets.
//!
//! One subtlety in that recovery is worth stating. A model that writes
//! "bulgu yoksa [] döndürülür" before its real array offers TWO parseable
//! candidates, and the first is empty. Taking the first would silently discard
//! every finding, so a candidate that parses to an EMPTY array is remembered
//! but does not stop the scan: an empty result is only returned when no
//! candidate anywhere in the response yielded a finding. I2 decides that trade
//! -- a missed quasi-identifier is the failure that matters.

use core::fmt;

use crate::error::{Error, ResponseDefect, Result};
use crate::label::QuasiCategory;

/// Maximum nesting the parser will follow before giving up.
///
/// The requested shape nests two deep (array, object). Anything past this is
/// either a confused model or an attempt to exhaust the stack, and both are
/// answered the same way.
const MAX_DEPTH: usize = 8;

/// Maximum findings accepted from one response.
///
/// A full-document sweep of a clinical note that legitimately contains more
/// than this many distinct quasi-identifiers is not a sweep result, it is a
/// model that has started enumerating sentences.
const MAX_ITEMS: usize = 256;

/// How many `[` positions the recovery scan will try.
///
/// Bounded so that a pathological response full of brackets cannot turn a
/// linear parse into a quadratic one.
const MAX_ARRAY_CANDIDATES: usize = 32;

/// One quasi-identifier exactly as the model reported it.
///
/// NOT YET A SPAN, and the distinction is the whole hallucination filter. A
/// finding is an unverified claim: the quote may be a phrase the model invented,
/// a paraphrase, or a real phrase with one character changed. It becomes a span
/// only in [`super::anchor`], and only if it is found verbatim in the original
/// document.
#[derive(Clone, PartialEq, Eq)]
pub struct Finding {
    quote: String,
    category: QuasiCategory,
    reason: String,
}

/// Hand-written for the reason [`crate::audit::AuditEntry`]'s is: a derived
/// `Debug` would print the quote, and the quote IS the quasi-identifier. This
/// type is the one most likely to appear in a failing assertion while someone
/// is debugging the sweep, which is exactly when a derive would egress it (I4).
impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("category", &self.category)
            .field("quote_len", &self.quote.len())
            .field("quote", &format_args!("<redacted>"))
            .field("reason", &format_args!("<redacted>"))
            .finish()
    }
}

impl Finding {
    /// The verbatim quote the model claims to have taken from the document.
    #[must_use]
    pub fn quote(&self) -> &str {
        &self.quote
    }

    /// The quasi-identifier category.
    #[must_use]
    pub const fn category(&self) -> QuasiCategory {
        self.category
    }

    /// The model's one-line justification, destined for the audit log.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Parse a model response into findings.
///
/// Accepts a bare JSON array, an array wrapped in prose, an array inside a code
/// fence, and an array nested inside an object the model wrapped it in.
pub fn findings(response: &str) -> Result<Vec<Finding>> {
    let bytes = response.as_bytes();
    let total = response.len();
    let mut first_error: Option<Error> = None;
    let mut saw_empty_array = false;
    let mut tried = 0usize;

    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'[' {
            continue;
        }
        if tried >= MAX_ARRAY_CANDIDATES {
            break;
        }
        tried += 1;
        let mut parser = Parser {
            bytes,
            pos: index,
            total,
        };
        match parser
            .value(0)
            .and_then(|value| into_findings(&value, total))
        {
            // See the module header: an empty parse is remembered, never
            // returned early, because prose frequently contains a literal `[]`.
            Ok(parsed) if parsed.is_empty() => saw_empty_array = true,
            Ok(parsed) => return Ok(parsed),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    if saw_empty_array {
        return Ok(Vec::new());
    }
    Err(first_error.unwrap_or(Error::MalformedContextualResponse {
        defect: ResponseDefect::NoArrayFound,
        byte_offset: 0,
        response_len: total,
    }))
}

/// A parsed JSON value. Numbers are recognised but not evaluated: the requested
/// schema has no numeric field, and a value nothing reads is a value nothing
/// can be wrong about.
enum Json {
    /// The three scalar kinds the schema never asks for are recognised so that
    /// an unknown field carrying one can be skipped, but they carry no payload:
    /// a value nothing reads is a value nothing can be wrong about, and a field
    /// nothing reads is a `dead_code` warning waiting to be silenced.
    Null,
    Bool,
    Number,
    Str(String),
    Array(Vec<Json>),
    /// The byte offset where the object started, so a semantic complaint about
    /// a missing field can point at the object rather than at the whole array.
    Object(usize, Vec<(String, Json)>),
}

impl Json {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }
}

/// Turn a parsed array into findings, validating the closed key vocabulary.
fn into_findings(value: &Json, total: usize) -> Result<Vec<Finding>> {
    let items = match value {
        Json::Array(items) => items,
        _ => {
            return Err(defect_at(ResponseDefect::ItemNotAnObject, 0, total));
        }
    };
    if items.len() > MAX_ITEMS {
        return Err(defect_at(ResponseDefect::TooManyItems, 0, total));
    }

    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        let (start, fields) = match item {
            Json::Object(start, fields) => (*start, fields),
            _ => return Err(defect_at(ResponseDefect::ItemNotAnObject, 0, total)),
        };
        let field = |key: &str| {
            fields
                .iter()
                .find(|(name, _)| name == key)
                .and_then(|(_, value)| value.as_str())
        };

        let quote = field("quote").ok_or(defect_at(ResponseDefect::MissingQuote, start, total))?;
        if quote.is_empty() {
            return Err(defect_at(ResponseDefect::EmptyQuote, start, total));
        }
        let category_id =
            field("category").ok_or(defect_at(ResponseDefect::MissingCategory, start, total))?;
        let category = QuasiCategory::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == category_id)
            .ok_or(defect_at(ResponseDefect::UnknownCategory, start, total))?;
        let reason =
            field("reason").ok_or(defect_at(ResponseDefect::MissingReason, start, total))?;

        parsed.push(Finding {
            quote: quote.to_owned(),
            category,
            reason: reason.to_owned(),
        });
    }
    Ok(parsed)
}

/// Build the one error this module produces. Offsets and lengths only (I4).
const fn defect_at(defect: ResponseDefect, byte_offset: usize, response_len: usize) -> Error {
    Error::MalformedContextualResponse {
        defect,
        byte_offset,
        response_len,
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    /// Length of the WHOLE response, not of the slice being parsed, so the
    /// error reports a position a reader can locate.
    total: usize,
}

impl Parser<'_> {
    fn defect(&self, defect: ResponseDefect) -> Error {
        defect_at(defect, self.pos, self.total)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Consume an exact ASCII literal (`true`, `false`, `null`).
    fn literal(&mut self, word: &str) -> Result<()> {
        let end = self.pos + word.len();
        match self.bytes.get(self.pos..end) {
            Some(found) if found == word.as_bytes() => {
                self.pos = end;
                Ok(())
            }
            Some(_) => Err(self.defect(ResponseDefect::UnexpectedByte)),
            None => Err(self.defect(ResponseDefect::Truncated)),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        if depth >= MAX_DEPTH {
            return Err(self.defect(ResponseDefect::TooDeeplyNested));
        }
        self.skip_whitespace();
        match self.peek() {
            None => Err(self.defect(ResponseDefect::Truncated)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal("true").map(|()| Json::Bool),
            Some(b'f') => self.literal("false").map(|()| Json::Bool),
            Some(b'n') => self.literal("null").map(|()| Json::Null),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.number(),
            Some(_) => Err(self.defect(ResponseDefect::UnexpectedByte)),
        }
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            let is_number_byte =
                byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E');
            if is_number_byte {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.defect(ResponseDefect::UnexpectedByte));
        }
        Ok(Json::Number)
    }

    fn array(&mut self, depth: usize) -> Result<Json> {
        // The opening bracket; presence checked by the caller.
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => return Err(self.defect(ResponseDefect::Truncated)),
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                Some(b',') if !items.is_empty() => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        // A trailing comma. Accepted rather than rejected: it
                        // is the single most common shape a small model gets
                        // wrong, and refusing it discards every finding in the
                        // array over a punctuation slip (I2).
                        self.pos += 1;
                        return Ok(Json::Array(items));
                    }
                }
                Some(_) if !items.is_empty() => {
                    return Err(self.defect(ResponseDefect::UnexpectedByte))
                }
                Some(_) => {}
            }
            if items.len() >= MAX_ITEMS {
                return Err(self.defect(ResponseDefect::TooManyItems));
            }
            items.push(self.value(depth + 1)?);
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json> {
        let start = self.pos;
        self.pos += 1;
        let mut fields = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => return Err(self.defect(ResponseDefect::Truncated)),
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(start, fields));
                }
                Some(b',') if !fields.is_empty() => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        return Ok(Json::Object(start, fields));
                    }
                }
                Some(_) if !fields.is_empty() => {
                    return Err(self.defect(ResponseDefect::UnexpectedByte))
                }
                Some(_) => {}
            }
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.defect(ResponseDefect::UnexpectedByte));
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.bump() != Some(b':') {
                return Err(self.defect(ResponseDefect::UnexpectedByte));
            }
            if fields.len() >= MAX_ITEMS {
                return Err(self.defect(ResponseDefect::TooManyItems));
            }
            let value = self.value(depth + 1)?;
            fields.push((key, value));
        }
    }

    /// Parse a JSON string, resolving escapes.
    ///
    /// The escapes matter more here than they would in a general parser,
    /// because the result is compared BYTE FOR BYTE against the original
    /// document. A `İ` left unresolved, or an `İ` decoded into the wrong
    /// code point, produces a quote that cannot anchor, and a quote that cannot
    /// anchor is silently dropped -- a decoding bug would surface as a recall
    /// loss nobody can see rather than as an error.
    fn string(&mut self) -> Result<String> {
        // The opening quote; presence checked by the caller.
        self.pos += 1;
        let mut out = String::new();
        loop {
            let byte = self.bump().ok_or(self.defect(ResponseDefect::Truncated))?;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = self.bump().ok_or(self.defect(ResponseDefect::Truncated))?;
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
                        _ => return Err(self.defect(ResponseDefect::BadEscape)),
                    }
                }
                _ => {
                    // Multi-byte UTF-8 arrives one byte at a time here, so the
                    // bytes are collected and validated as a unit rather than
                    // pushed as chars. This is the Turkish path: `ş` and `İ`
                    // are two bytes each, and splitting them would corrupt
                    // exactly the letters the project exists to handle.
                    let start = self.pos - 1;
                    while let Some(next) = self.peek() {
                        if next == b'"' || next == b'\\' {
                            break;
                        }
                        self.pos += 1;
                    }
                    let chunk = self
                        .bytes
                        .get(start..self.pos)
                        .ok_or(self.defect(ResponseDefect::Truncated))?;
                    let decoded = core::str::from_utf8(chunk)
                        .map_err(|_| self.defect(ResponseDefect::BadEscape))?;
                    out.push_str(decoded);
                }
            }
        }
    }

    /// Resolve a `\uXXXX` escape, including a surrogate pair.
    fn unicode_escape(&mut self) -> Result<char> {
        let high = self.hex4()?;
        if !(0xD800..0xDC00).contains(&high) {
            return char::from_u32(high).ok_or(self.defect(ResponseDefect::BadEscape));
        }
        // A high surrogate must be followed by `\uDC00..\uDFFF`; anything else
        // is an unpaired surrogate, which is not a character.
        if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
            return Err(self.defect(ResponseDefect::BadEscape));
        }
        let low = self.hex4()?;
        if !(0xDC00..0xE000).contains(&low) {
            return Err(self.defect(ResponseDefect::BadEscape));
        }
        let combined = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
        char::from_u32(combined).ok_or(self.defect(ResponseDefect::BadEscape))
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or(self.defect(ResponseDefect::Truncated))?;
        let mut value = 0u32;
        for digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a') + 10,
                b'A'..=b'F' => u32::from(digit - b'A') + 10,
                _ => return Err(self.defect(ResponseDefect::BadEscape)),
            };
            value = (value << 4) | nibble;
        }
        self.pos += 4;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed response. Synthetic Turkish narrative, no real PHI (I8).
    const CLEAN: &str = r#"[
        {"quote": "Merkez Bankası'nda müfettiş olarak çalışıyor",
         "category": "EMPLOYER_ROLE",
         "reason": "küçük bir popülasyonda mesleği tekilleştirici"},
        {"quote": "eşi ilçedeki tek kadın hâkim",
         "category": "RELATIONSHIP_REF",
         "reason": "yakın referansı artı ayırt edici unvan"}
    ]"#;

    fn defect_of(error: &Error) -> Option<ResponseDefect> {
        match error {
            Error::MalformedContextualResponse { defect, .. } => Some(*defect),
            _ => None,
        }
    }

    #[test]
    fn a_clean_response_parses_into_findings() {
        let parsed = findings(CLEAN).expect("well-formed response");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].category(), QuasiCategory::EmployerRole);
        assert_eq!(
            parsed[0].quote(),
            "Merkez Bankası'nda müfettiş olarak çalışıyor"
        );
        assert_eq!(parsed[1].category(), QuasiCategory::RelationshipRef);
        assert!(!parsed[1].reason().is_empty());
    }

    #[test]
    fn prose_around_the_json_is_tolerated() {
        let wrapped = format!("İşte bulgular:\n{CLEAN}\nUmarım yardımcı olur.");
        assert_eq!(findings(&wrapped).expect("prose-wrapped").len(), 2);
    }

    #[test]
    fn a_code_fence_around_the_json_is_tolerated() {
        let fenced = format!("```json\n{CLEAN}\n```");
        assert_eq!(findings(&fenced).expect("fenced").len(), 2);
    }

    #[test]
    fn an_object_wrapper_around_the_array_is_tolerated() {
        let wrapped = format!("{{\"findings\": {CLEAN}}}");
        assert_eq!(findings(&wrapped).expect("object-wrapped").len(), 2);
    }

    #[test]
    fn a_literal_empty_array_in_the_prose_does_not_discard_the_real_one() {
        // THE recovery bug this scan was written to avoid: the model repeats
        // the instruction ("bulgu yoksa [] döndür") before answering, and a
        // first-match scan returns zero findings from a response that had two.
        let chatty = format!("Bulgu yoksa [] döndürülür. Bu metinde ise:\n{CLEAN}");
        assert_eq!(findings(&chatty).expect("chatty").len(), 2);
    }

    #[test]
    fn a_bracket_in_the_prose_does_not_abort_the_parse() {
        let noisy = format!("[not JSON at all] sonra:\n{CLEAN}");
        assert_eq!(findings(&noisy).expect("noisy").len(), 2);
    }

    #[test]
    fn an_honestly_empty_response_is_not_an_error() {
        assert!(findings("[]").expect("empty array").is_empty());
        assert!(findings("Bulgu yok: []").expect("empty array").is_empty());
    }

    #[test]
    fn a_response_with_no_array_is_an_error() {
        let error = findings("Üzgünüm, bu isteği yerine getiremem.")
            .expect_err("prose without an array must fail");
        assert_eq!(defect_of(&error), Some(ResponseDefect::NoArrayFound));
    }

    #[test]
    fn a_truncated_response_is_an_error_and_not_a_panic() {
        // A local runtime hitting its token budget mid-object is the single
        // most common real failure, and it must not take the process with it.
        for cut in 1..CLEAN.len() {
            if !CLEAN.is_char_boundary(cut) {
                continue;
            }
            let partial = CLEAN.get(..cut).expect("boundary checked");
            // Either it parses (a prefix can be a valid shorter array) or it
            // errors. What it must never do is panic.
            let _ = findings(partial);
        }
        let error = findings(r#"[{"quote": "eşi"#).expect_err("truncated");
        assert_eq!(defect_of(&error), Some(ResponseDefect::Truncated));
    }

    #[test]
    fn every_required_field_is_required() {
        let cases = [
            (
                r#"[{"category": "EMPLOYER_ROLE", "reason": "r"}]"#,
                ResponseDefect::MissingQuote,
            ),
            (
                r#"[{"quote": "", "category": "EMPLOYER_ROLE", "reason": "r"}]"#,
                ResponseDefect::EmptyQuote,
            ),
            (
                r#"[{"quote": "q", "reason": "r"}]"#,
                ResponseDefect::MissingCategory,
            ),
            (
                r#"[{"quote": "q", "category": "EMPLOYER_ROLE"}]"#,
                ResponseDefect::MissingReason,
            ),
            (
                r#"[{"quote": "q", "category": "İŞ_YERİ", "reason": "r"}]"#,
                ResponseDefect::UnknownCategory,
            ),
            (r#"["just a string"]"#, ResponseDefect::ItemNotAnObject),
        ];
        for (response, expected) in cases {
            let error = findings(response).expect_err("must be rejected");
            assert_eq!(defect_of(&error), Some(expected));
        }
    }

    #[test]
    fn an_error_never_carries_the_response() {
        // I4 at the point it is easiest to violate: the natural way to explain
        // a parse failure is to quote the thing that failed to parse, and the
        // thing that failed to parse is the employer of a real person.
        const SYNTHETIC_QUOTE: &str = "Merkez Bankası'nda müfettiş";
        let response = format!(r#"[{{"quote": "{SYNTHETIC_QUOTE}", "category": "NOPE"}}]"#);
        let error = findings(&response).expect_err("unknown category");
        let rendered = error.to_string();
        assert!(!rendered.contains(SYNTHETIC_QUOTE));
        assert!(!rendered.contains("Merkez"));
        assert!(rendered.contains("unknown category"));
    }

    #[test]
    fn debug_on_a_finding_never_prints_the_quote() {
        const SYNTHETIC_QUOTE: &str = "eşi ilçedeki tek kadın hâkim";
        let parsed = findings(CLEAN).expect("clean");
        let rendered = format!("{:?}", parsed[1]);
        assert!(!rendered.contains(SYNTHETIC_QUOTE));
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("RelationshipRef"),
            "the category must stay visible"
        );
    }

    #[test]
    fn escapes_are_resolved_so_a_quote_can_anchor() {
        // `İ` written as a surrogate-free escape, plus the escapes a model
        // emits around punctuation. If any of these survives unresolved the
        // quote silently fails to anchor and the finding disappears.
        let escaped = r#"[{"quote": "İlkçe \"tek\" hâkim",
                          "category": "RELATIONSHIP_REF", "reason": "r"}]"#;
        let parsed = findings(escaped).expect("escaped");
        assert_eq!(parsed[0].quote(), "İlkçe \"tek\" hâkim");
    }

    #[test]
    fn a_surrogate_pair_escape_is_decoded_and_a_lone_surrogate_is_rejected() {
        // U+1F300 written as the surrogate pair a JSON encoder emits for any
        // astral code point. Escaped rather than written literally so the
        // repository stays free of non-text glyphs.
        let paired = r#"[{"quote": "\ud83c\udf00", "category": "EMPLOYER_ROLE", "reason": "r"}]"#;
        let parsed = findings(paired).expect("pair");
        assert_eq!(parsed[0].quote().chars().count(), 1);
        assert_eq!(parsed[0].quote().len(), 4, "one astral char is four bytes");
        let lone = r#"[{"quote": "\ud800x", "category": "EMPLOYER_ROLE", "reason": "r"}]"#;
        assert_eq!(
            defect_of(&findings(lone).expect_err("lone surrogate")),
            Some(ResponseDefect::BadEscape)
        );
    }

    #[test]
    fn a_trailing_comma_does_not_discard_the_findings() {
        let sloppy = r#"[{"quote": "q", "category": "ASSET_LOCATION", "reason": "r"},]"#;
        assert_eq!(findings(sloppy).expect("trailing comma").len(), 1);
    }

    #[test]
    fn unknown_fields_are_ignored_rather_than_rejected() {
        // Forward compatibility in the safe direction: an extra field a future
        // prompt asks for must not make today's parser discard the finding.
        let extra = r#"[{"quote": "q", "category": "DISTINCTIVE_EVENT",
                        "reason": "r", "confidence": 0.8, "offsets": [1, 2]}]"#;
        assert_eq!(findings(extra).expect("extra fields").len(), 1);
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_recursed() {
        let deep = "[".repeat(MAX_DEPTH + 4);
        let error = findings(&deep).expect_err("must refuse");
        assert_eq!(defect_of(&error), Some(ResponseDefect::TooDeeplyNested));
    }

    #[test]
    fn an_over_long_findings_list_is_refused() {
        let one = r#"{"quote": "q", "category": "EMPLOYER_ROLE", "reason": "r"}"#;
        let many = format!("[{}]", vec![one; MAX_ITEMS + 1].join(","));
        let error = findings(&many).expect_err("must refuse");
        assert_eq!(defect_of(&error), Some(ResponseDefect::TooManyItems));
    }

    #[test]
    fn the_candidate_scan_is_bounded() {
        // A response that is nothing but opening brackets must not become a
        // quadratic parse. Only the bound is asserted; the point is that the
        // call returns at all.
        let brackets = "[".repeat(MAX_ARRAY_CANDIDATES * 4);
        assert!(findings(&brackets).is_err());
    }
}
