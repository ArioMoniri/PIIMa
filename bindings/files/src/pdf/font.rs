//! Turning glyph codes back into characters.
//!
//! # The bytes inside `(...)` are not text
//!
//! A PDF string operand holds CODES in the current font's encoding. For a
//! simple font that is one byte per glyph, mapped through `/Encoding` and its
//! `/Differences`; for a composite (Type0/CID) font it is one or two bytes
//! selected by a CMap, and the route back to Unicode is a separate
//! `/ToUnicode` stream. `Ayşe` in a subsetted font can be the bytes
//! `\003\027\061\014`.
//!
//! The consequence is the single most important rule in this module, and it is
//! why the redactor extracts and edits in one pass: **you cannot find an
//! identifier by searching a content stream for the UTF-8 of a name.** Any code
//! that does is not redacting, it is guessing.
//!
//! # The single-byte fallback is Windows-1254, unconditionally
//!
//! A simple font with `/WinAnsiEncoding` or no `/Encoding` at all decodes one
//! byte per glyph through a Latin code page. Which one is not recorded anywhere
//! in the file, and the two candidates -- Windows-1252/Latin-1 and
//! Windows-1254, the Turkish ANSI page -- are IDENTICAL except at six byte
//! positions: `0xD0 0xDD 0xDE 0xF0 0xFD 0xFE`. Those six are exactly
//! `Ğ İ Ş ğ ı ş` under 1254 and `Ð Ý Þ ð ý þ` under Latin-1.
//!
//! So the choice is not "which code page is this document" in general; it is
//! only "what do those six bytes mean", and this crate answers Turkish every
//! time. The alternative -- sniffing the document -- is circular here, because
//! the evidence a sniffer would weigh is the decoded text it is trying to
//! produce, and it would have to reach a verdict per font, per page, from a few
//! bytes. A wrong verdict is silent: `Şükrü` decoded as `Þükrü` is a string the
//! rules layer and any future model see as a different name, so it is a RECALL
//! bug (I2), and I2 says recall wins the tie.
//!
//! `txt.rs` already made this exact trade for `.txt` input and owns the table;
//! this module calls into it rather than carrying a second copy, because two
//! copies of a code page drift until only one of them decodes `ş`.
//!
//! RESIDUAL RISK, stated plainly: a genuinely Icelandic or Faroese document
//! (`Ð ð Þ þ Ý ý`) or any other producer relying on those six Latin-1
//! positions is decoded wrongly at exactly those characters. That is accepted.
//! Those letters carry no Turkish identifier information, the tool is scoped to
//! Turkish clinical text, and the failure is symmetric with the one being fixed
//! -- but only one direction of it loses Turkish names.
//!
//! # What is NOT claimed
//!
//! A font with no `/ToUnicode` and a non-standard `/Encoding` cannot be decoded
//! correctly by this module -- there is no general inverse for a subsetted
//! symbolic font without parsing the embedded font program's `cmap` table,
//! which this crate does not do. Such a page yields no readable text, which
//! [`crate::pdf`] treats exactly like a scanned page: it REFUSES, rather than
//! reporting that it found no identifiers.

use std::collections::BTreeMap;

use crate::pdf::document::{decode_stream, Document};
use crate::pdf::object::{Dict, Lexer, Object};

/// One font as far as this crate needs to understand it.
#[derive(Debug, Clone, Default)]
pub struct Font {
    /// True for composite fonts, whose codes are two bytes wide.
    ///
    /// A simplification of the CMap's real `codespacerange` machinery, and the
    /// only one this crate makes: `/Identity-H` (two bytes, fixed) covers
    /// effectively every Type0 font a document producer emits.
    pub two_byte: bool,
    /// `/ToUnicode`, code to the string it stands for.
    pub to_unicode: BTreeMap<u32, String>,
    /// `/Encoding /Differences`, code to character.
    pub differences: BTreeMap<u32, char>,
}

impl Font {
    /// Build from a font dictionary.
    #[must_use]
    pub fn load(document: &Document, dict: &Dict) -> Self {
        let two_byte = document
            .get(dict, "Subtype")
            .and_then(Object::as_name)
            .is_some_and(|subtype| subtype == "Type0");

        let mut font = Self {
            two_byte,
            ..Self::default()
        };

        if let Some(Object::Stream(stream_dict, raw)) =
            dict.get("ToUnicode").map(|value| document.resolve(value))
        {
            if let Some(data) = decode_stream(stream_dict, raw) {
                font.to_unicode = parse_to_unicode(&data);
            }
        }
        if let Some(encoding) = document.get(dict, "Encoding").and_then(Object::as_dict) {
            if let Some(items) = document
                .get(encoding, "Differences")
                .and_then(Object::as_array)
            {
                font.differences = parse_differences(items);
            }
        }
        font
    }

    /// Split raw operand bytes into (code, byte width) pairs.
    #[must_use]
    pub fn codes(&self, bytes: &[u8]) -> Vec<(u32, usize)> {
        if self.two_byte {
            let mut out = Vec::with_capacity(bytes.len() / 2);
            let mut index = 0;
            while index + 1 < bytes.len() {
                out.push((
                    (u32::from(bytes[index]) << 8) | u32::from(bytes[index + 1]),
                    2,
                ));
                index += 2;
            }
            if index < bytes.len() {
                // An odd trailing byte in a two-byte font is malformed. Kept as
                // a one-byte code so it is still DELETABLE -- dropping it here
                // would leave a byte in the stream that no span can reach.
                out.push((u32::from(bytes[index]), 1));
            }
            out
        } else {
            bytes.iter().map(|&byte| (u32::from(byte), 1)).collect()
        }
    }

    /// The text a code stands for, if this font can say.
    ///
    /// `None` rather than a guess: an undecodable code becomes an
    /// UNREADABLE-page signal upstream, and a guess would become a page that
    /// silently was not searched.
    #[must_use]
    pub fn text(&self, code: u32) -> Option<String> {
        if let Some(text) = self.to_unicode.get(&code) {
            return Some(text.clone());
        }
        if let Some(value) = self.differences.get(&code) {
            return Some(value.to_string());
        }
        if self.two_byte {
            return None;
        }
        // A simple font with no `/ToUnicode` and no `/Differences` is using a
        // standard single-byte Latin code page, and this crate decodes that page
        // as WINDOWS-1254, not Latin-1 -- see the module header for why that is
        // a decision rather than a detail.
        if !(0x20..=0xff).contains(&code) {
            return None;
        }
        let byte = u8::try_from(code).ok()?;
        match crate::txt::cp1254_to_char(byte) {
            // The handful of positions Windows-1254 leaves undefined. `\u{fffd}`
            // is the table's way of saying "no character here"; emitting it
            // would be a guess, and this module's rule is that an undecodable
            // code becomes an UNREADABLE-page signal instead.
            '\u{fffd}' => None,
            value => Some(value.to_string()),
        }
    }
}

/// Parse the `bfchar` / `bfrange` sections of a `/ToUnicode` CMap.
fn parse_to_unicode(data: &[u8]) -> BTreeMap<u32, String> {
    let mut map = BTreeMap::new();
    let mut lexer = Lexer::new(data, 0);
    while lexer.at < data.len() {
        lexer.skip_whitespace();
        let save = lexer.at;
        // Objects are skipped, keywords are dispatched on. The CMap preamble
        // is full of both and none of it matters except the two section
        // markers.
        if lexer.object().is_ok() {
            continue;
        }
        lexer.at = save;
        let keyword = lexer.keyword();
        if keyword.is_empty() {
            lexer.at += 1;
            continue;
        }
        match keyword.as_str() {
            "beginbfchar" => read_bfchar(&mut lexer, data, &mut map),
            "beginbfrange" => read_bfrange(&mut lexer, data, &mut map),
            _ => {}
        }
    }
    map
}

fn read_bfchar(lexer: &mut Lexer<'_>, data: &[u8], map: &mut BTreeMap<u32, String>) {
    loop {
        lexer.skip_whitespace();
        if lexer.at >= data.len() || lexer.eat_keyword("endbfchar") {
            return;
        }
        let (Ok(source), Ok(target)) = (lexer.object(), lexer.object()) else {
            return;
        };
        if let (Some(code), Some(text)) = (code_of(&source), utf16be_of(&target)) {
            map.insert(code, text);
        }
    }
}

fn read_bfrange(lexer: &mut Lexer<'_>, data: &[u8], map: &mut BTreeMap<u32, String>) {
    loop {
        lexer.skip_whitespace();
        if lexer.at >= data.len() || lexer.eat_keyword("endbfrange") {
            return;
        }
        let (Ok(low), Ok(high), Ok(target)) = (lexer.object(), lexer.object(), lexer.object())
        else {
            return;
        };
        let (Some(low), Some(high)) = (code_of(&low), code_of(&high)) else {
            return;
        };
        // Ranges can be enormous if the file is malformed; 65536 is the whole
        // two-byte code space and anything past it is not a real mapping.
        if high < low || high - low > 0xffff {
            continue;
        }
        match &target {
            Object::Array(items) => {
                for (offset, item) in items.iter().enumerate() {
                    if let Some(text) = utf16be_of(item) {
                        map.insert(low + offset as u32, text);
                    }
                }
            }
            _ => {
                let Some(base) = utf16be_of(&target) else {
                    continue;
                };
                let Some(first) = base.chars().next() else {
                    continue;
                };
                let suffix: String = base.chars().skip(1).collect();
                for code in low..=high {
                    let Some(value) = char::from_u32(u32::from(first) + (code - low)) else {
                        continue;
                    };
                    map.insert(code, format!("{value}{suffix}"));
                }
            }
        }
    }
}

fn code_of(object: &Object) -> Option<u32> {
    match object {
        Object::Str(bytes, _) => bytes
            .iter()
            .take(4)
            .try_fold(0u32, |acc, &byte| Some((acc << 8) | u32::from(byte))),
        Object::Int(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}

fn utf16be_of(object: &Object) -> Option<String> {
    let Object::Str(bytes, _) = object else {
        return None;
    };
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| (u16::from(pair[0]) << 8) | u16::from(pair[1]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn parse_differences(items: &[Object]) -> BTreeMap<u32, char> {
    let mut map = BTreeMap::new();
    let mut code = 0u32;
    for item in items {
        match item {
            Object::Int(value) => code = u32::try_from(*value).unwrap_or(0),
            Object::Name(name) => {
                if let Some(value) = glyph_name_to_char(name) {
                    map.insert(code, value);
                }
                code += 1;
            }
            _ => {}
        }
    }
    map
}

/// Map an Adobe glyph name to a character, for the names that matter here.
///
/// Deliberately partial. A full Adobe Glyph List is ~4300 entries of data this
/// crate would then have to keep current; what the detection layer needs is
/// digits, ASCII letters, the punctuation that appears inside identifiers, and
/// the Turkish letters. Everything else returns `None`, which routes the page to
/// the REFUSE path rather than to a wrong decode.
///
/// The Turkish block is not decoration. A name missing from this list does not
/// fail loudly: `parse_differences` simply never records the code, `text` then
/// reaches the single-byte fallback, and the glyph the font EXPLICITLY named
/// comes out as whatever that code page says. A producer that writes
/// `253 /dotlessi` has told this crate the character is `ı`, and dropping that
/// statement on the floor to guess from the byte is the worst of both paths.
fn glyph_name_to_char(name: &str) -> Option<char> {
    if let Some(hex) = name.strip_prefix("uni") {
        return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
    }
    if name.len() == 1 {
        return name.chars().next();
    }
    const NAMED: &[(&str, char)] = &[
        ("space", ' '),
        ("period", '.'),
        ("comma", ','),
        ("hyphen", '-'),
        ("slash", '/'),
        ("colon", ':'),
        ("at", '@'),
        ("plus", '+'),
        ("parenleft", '('),
        ("parenright", ')'),
        ("underscore", '_'),
        ("zero", '0'),
        ("one", '1'),
        ("two", '2'),
        ("three", '3'),
        ("four", '4'),
        ("five", '5'),
        ("six", '6'),
        ("seven", '7'),
        ("eight", '8'),
        ("nine", '9'),
        // The six that carry Turkish, under their Adobe Glyph List names.
        ("dotlessi", 'ı'),
        ("Idotaccent", 'İ'),
        ("scedilla", 'ş'),
        ("Scedilla", 'Ş'),
        ("gbreve", 'ğ'),
        ("Gbreve", 'Ğ'),
        // The other three Turkish letters, which Latin-1 does agree on but
        // which still need a name here to survive a `/Differences` array.
        ("ccedilla", 'ç'),
        ("Ccedilla", 'Ç'),
        ("odieresis", 'ö'),
        ("Odieresis", 'Ö'),
        ("udieresis", 'ü'),
        ("Udieresis", 'Ü'),
        // Turkish attaches case suffixes with an apostrophe (`Ayşe'nin`), so
        // both apostrophe glyphs are punctuation INSIDE an identifier here, not
        // between two.
        ("quotesingle", '\''),
        ("quoteright", '\u{2019}'),
    ];
    NAMED
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, value)| *value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_simple_font_falls_back_to_windows_1254_not_latin1() {
        // Renamed from `a_simple_font_falls_back_to_latin1`, which asserted the
        // bug. Latin-1 turns every `ş` in a Turkish report into `þ` before any
        // detector runs, which makes an encoding choice a recall failure.
        let font = Font::default();
        assert_eq!(font.text(u32::from(b'A')).as_deref(), Some("A"));
        assert_eq!(font.text(u32::from(b'7')).as_deref(), Some("7"));
        assert_eq!(font.text(0x01), None, "a control code is not text");

        // THE SIX, at the byte positions where the two code pages disagree.
        for (code, expected) in [
            (0xd0u32, "Ğ"),
            (0xdd, "İ"),
            (0xde, "Ş"),
            (0xf0, "ğ"),
            (0xfd, "ı"),
            (0xfe, "ş"),
        ] {
            assert_eq!(font.text(code).as_deref(), Some(expected));
        }
        // Everywhere else the two pages agree, so nothing else moved.
        assert_eq!(font.text(0xfc).as_deref(), Some("ü"));
        assert_eq!(font.text(0xe7).as_deref(), Some("ç"));
        // 0x81 has no character in Windows-1254; a guess here would be a page
        // reported as read that was not.
        assert_eq!(font.text(0x81), None);
    }

    #[test]
    fn a_declared_turkish_glyph_name_beats_the_code_page() {
        // The shape this document actually had: `/Differences [253 /dotlessi]`.
        // Before, `dotlessi` was not in the table, the entry was dropped, and
        // the fallback decoded byte 253 -- so a font that SAID `ı` yielded `ý`.
        let items = vec![
            Object::Int(253),
            Object::Name("dotlessi".to_owned()),
            Object::Int(222),
            Object::Name("Scedilla".to_owned()),
        ];
        let font = Font {
            differences: parse_differences(&items),
            ..Font::default()
        };
        assert_eq!(font.text(253).as_deref(), Some("ı"));
        assert_eq!(font.text(222).as_deref(), Some("Ş"));
    }

    #[test]
    fn a_composite_font_without_tounicode_decodes_nothing() {
        // THE case that must not silently succeed: a subsetted CID font whose
        // codes have no published inverse. Reporting "no identifiers found"
        // here would be a vacuous pass.
        let font = Font {
            two_byte: true,
            ..Font::default()
        };
        assert_eq!(font.text(0x0003), None);
        assert_eq!(font.codes(&[0x00, 0x03, 0x00, 0x1b]), vec![(3, 2), (27, 2)]);
    }

    #[test]
    fn bfchar_and_bfrange_are_both_read() {
        let cmap = b"/CIDInit /ProcSet findresource begin\n\
                     1 beginbfchar\n<0003> <0041>\nendbfchar\n\
                     1 beginbfrange\n<0010> <0012> <0061>\nendbfrange\n\
                     1 beginbfrange\n<0020> <0021> [<00FC> <015F>]\nendbfrange\n";
        let map = parse_to_unicode(cmap);
        assert_eq!(map.get(&0x0003).map(String::as_str), Some("A"));
        assert_eq!(map.get(&0x0010).map(String::as_str), Some("a"));
        assert_eq!(map.get(&0x0012).map(String::as_str), Some("c"));
        assert_eq!(map.get(&0x0020).map(String::as_str), Some("ü"));
        assert_eq!(map.get(&0x0021).map(String::as_str), Some("ş"));
    }

    #[test]
    fn differences_are_applied_from_the_running_code() {
        let items = vec![
            Object::Int(65),
            Object::Name("A".to_owned()),
            Object::Name("space".to_owned()),
            Object::Int(200),
            Object::Name("uni015F".to_owned()),
        ];
        let map = parse_differences(&items);
        assert_eq!(map.get(&65), Some(&'A'));
        assert_eq!(map.get(&66), Some(&' '));
        assert_eq!(map.get(&200), Some(&'ş'));
    }
}
