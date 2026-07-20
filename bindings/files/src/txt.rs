//! Plain text, with the original encoding and line endings preserved.
//!
//! # Why this is not `String::from_utf8`
//!
//! Turkish hospital exports are frequently NOT UTF-8. Windows-1254 is the
//! Turkish ANSI code page and is what a decade of Delphi and older .NET HIS
//! software writes; UTF-16LE with a BOM is what Notepad and several report
//! generators write. Decoding those as UTF-8 fails outright, and decoding them
//! as Latin-1 silently corrupts exactly the six letters that carry Turkish
//! name information -- `Ğ ğ İ ı Ş ş`. A corrupted `Şükrü` is a `Şükrü` the
//! rules layer and any future model see as a different string, so an encoding
//! bug here is a RECALL bug, not a cosmetic one.
//!
//! # Round-trip discipline
//!
//! Whatever came in comes back out: same encoding, same BOM presence, same
//! line-ending convention. The de-identified file has to open in the same tool
//! the original opened in, and a redactor that silently converts a clinician's
//! file to UTF-8/LF has made a change nobody asked it to make and given the
//! reviewer a diff full of noise to hide a real edit in.
//!
//! HONEST SCOPE: see [`crate::Report::rule_detectable_only`]. Only
//! rule-detectable identifiers are removed.

use crate::masker::{Masked, Masker};

/// The byte encoding a text file was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-8, with or without a BOM (recorded separately).
    Utf8,
    /// UTF-16, little-endian. Always BOM-marked in practice.
    Utf16Le,
    /// UTF-16, big-endian.
    Utf16Be,
    /// Windows-1254, the Turkish ANSI code page.
    ///
    /// The FALLBACK, chosen over Latin-1/Windows-1252 deliberately: this is a
    /// Turkish clinical tool, the two code pages differ in exactly the six
    /// Turkish letters, and guessing 1252 turns `Şahin` into `Sahin`-adjacent
    /// mojibake at the six positions that matter most.
    Cp1254,
}

/// The line terminator convention a file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnding {
    /// `\n`.
    Lf,
    /// `\r\n`.
    CrLf,
    /// `\r`, classic Mac.
    Cr,
    /// No terminator was found; a single-line file.
    None,
}

/// What was detected about a text file's byte layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextShape {
    /// The detected encoding.
    pub encoding: Encoding,
    /// Whether a byte-order mark was present and must be re-emitted.
    pub bom: bool,
    /// The dominant line terminator.
    pub line_ending: LineEnding,
}

/// A text file that could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TextError {
    /// A UTF-16 file with an odd byte length.
    #[error("the UTF-16 input has a trailing half code unit")]
    Utf16Truncated,
    /// A UTF-16 file containing an unpaired surrogate.
    #[error("the UTF-16 input contains an unpaired surrogate")]
    Utf16Unpaired,
}

/// Decide how a byte string is encoded, without changing it.
#[must_use]
pub fn detect(bytes: &[u8]) -> TextShape {
    let (encoding, bom, body) = match bytes {
        [0xef, 0xbb, 0xbf, rest @ ..] => (Encoding::Utf8, true, rest),
        [0xff, 0xfe, rest @ ..] => (Encoding::Utf16Le, true, rest),
        [0xfe, 0xff, rest @ ..] => (Encoding::Utf16Be, true, rest),
        // No BOM: UTF-8 validity is a strong enough signal on its own. A byte
        // string that is valid UTF-8 and also meaningful Windows-1254 is
        // vanishingly rare above ASCII, because 1254's high bytes are almost
        // never a valid UTF-8 continuation sequence.
        rest if core::str::from_utf8(rest).is_ok() => (Encoding::Utf8, false, rest),
        rest => (Encoding::Cp1254, false, rest),
    };
    TextShape {
        encoding,
        bom,
        line_ending: line_ending_of(body, encoding),
    }
}

fn line_ending_of(body: &[u8], encoding: Encoding) -> LineEnding {
    // Counted on the DECODED characters would be cleaner, but the counts only
    // need to be right about `\r` and `\n`, which are single bytes in UTF-8 and
    // 1254 and are `XX 00` / `00 XX` in UTF-16 -- so a byte scan for the ASCII
    // values is correct in every case this supports.
    let step = match encoding {
        Encoding::Utf16Le | Encoding::Utf16Be => 2,
        _ => 1,
    };
    let at = |index: usize| -> Option<u8> {
        match encoding {
            Encoding::Utf16Le => body.get(index).copied(),
            Encoding::Utf16Be => body.get(index + 1).copied(),
            _ => body.get(index).copied(),
        }
    };
    let (mut crlf, mut lf, mut cr) = (0usize, 0usize, 0usize);
    let mut index = 0usize;
    while index < body.len() {
        match at(index) {
            Some(b'\r') => {
                if at(index + step) == Some(b'\n') {
                    crlf += 1;
                    index += step;
                } else {
                    cr += 1;
                }
            }
            Some(b'\n') => lf += 1,
            _ => {}
        }
        index += step;
    }
    if crlf == 0 && lf == 0 && cr == 0 {
        return LineEnding::None;
    }
    if crlf >= lf && crlf >= cr {
        LineEnding::CrLf
    } else if lf >= cr {
        LineEnding::Lf
    } else {
        LineEnding::Cr
    }
}

/// Decode a text file to a `String`, given its detected shape.
///
/// # Errors
///
/// [`TextError`] for malformed UTF-16. UTF-8 and Windows-1254 cannot fail:
/// invalid UTF-8 is what routes a file to 1254 in the first place, and every
/// 1254 byte has a defined character.
pub fn decode(bytes: &[u8], shape: TextShape) -> Result<String, TextError> {
    let body = strip_bom(bytes, shape);
    match shape.encoding {
        Encoding::Utf8 => Ok(String::from_utf8_lossy(body).into_owned()),
        Encoding::Cp1254 => Ok(body.iter().map(|&byte| cp1254_to_char(byte)).collect()),
        Encoding::Utf16Le | Encoding::Utf16Be => {
            if !body.len().is_multiple_of(2) {
                return Err(TextError::Utf16Truncated);
            }
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|pair| {
                    if shape.encoding == Encoding::Utf16Le {
                        u16::from(pair[0]) | (u16::from(pair[1]) << 8)
                    } else {
                        u16::from(pair[1]) | (u16::from(pair[0]) << 8)
                    }
                })
                .collect();
            String::from_utf16(&units).map_err(|_| TextError::Utf16Unpaired)
        }
    }
}

/// Re-encode a `String` in the shape the input had.
///
/// A character with no Windows-1254 representation is written as `?`, which is
/// what every encoder does and is only reachable for text the INPUT could not
/// have contained -- a surrogate replacement never introduces one.
#[must_use]
pub fn encode(text: &str, shape: TextShape) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 3);
    if shape.bom {
        match shape.encoding {
            Encoding::Utf8 => out.extend_from_slice(&[0xef, 0xbb, 0xbf]),
            Encoding::Utf16Le => out.extend_from_slice(&[0xff, 0xfe]),
            Encoding::Utf16Be => out.extend_from_slice(&[0xfe, 0xff]),
            Encoding::Cp1254 => {}
        }
    }
    match shape.encoding {
        Encoding::Utf8 => out.extend_from_slice(text.as_bytes()),
        Encoding::Cp1254 => out.extend(text.chars().map(char_to_cp1254)),
        Encoding::Utf16Le => {
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
        }
        Encoding::Utf16Be => {
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_be_bytes());
            }
        }
    }
    out
}

fn strip_bom(bytes: &[u8], shape: TextShape) -> &[u8] {
    if !shape.bom {
        return bytes;
    }
    let width = if shape.encoding == Encoding::Utf8 {
        3
    } else {
        2
    };
    bytes.get(width..).unwrap_or_default()
}

/// De-identify a text file, byte layer preserved.
///
/// # Errors
///
/// [`TextError`] when the input cannot be decoded, or whatever the pipeline
/// returns.
pub fn mask(masker: &Masker<'_>, bytes: &[u8]) -> Result<(Vec<u8>, Masked), crate::FileError> {
    let shape = detect(bytes);
    let text = decode(bytes, shape)?;
    let masked = masker.mask(&text)?;
    Ok((encode(&masked.text, shape), masked))
}

/// The 0x80..=0x9F block of Windows-1254, which is where it diverges from
/// ISO-8859-9. Above 0xA0 the two agree, and 0xA0..=0xFF maps to U+00A0.. with
/// the six Turkish substitutions applied in [`cp1254_to_char`].
const CP1254_HIGH_CONTROL: [char; 32] = [
    '\u{20ac}', '\u{fffd}', '\u{201a}', '\u{0192}', '\u{201e}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02c6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{fffd}', '\u{fffd}', '\u{fffd}',
    '\u{fffd}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02dc}', '\u{2122}', '\u{0161}', '\u{203a}', '\u{0153}', '\u{fffd}', '\u{fffd}', '\u{0178}',
];

/// One Windows-1254 byte as a character.
///
/// `pub(crate)` because [`crate::pdf::font`] needs the SAME table: a PDF simple
/// font with `/WinAnsiEncoding` carries the same single-byte code page, and two
/// copies of a code page is how the two paths drift until only one of them
/// decodes `ş`.
pub(crate) fn cp1254_to_char(byte: u8) -> char {
    match byte {
        0x00..=0x7f => char::from(byte),
        0x80..=0x9f => CP1254_HIGH_CONTROL[usize::from(byte) - 0x80],
        // THE SIX. These are the positions where Windows-1254 differs from
        // Windows-1252/Latin-1, and they are the whole reason this table
        // exists: they are the Turkish letters that carry name information.
        0xd0 => 'Ğ',
        0xdd => 'İ',
        0xde => 'Ş',
        0xf0 => 'ğ',
        0xfd => 'ı',
        0xfe => 'ş',
        _ => char::from_u32(u32::from(byte)).unwrap_or('\u{fffd}'),
    }
}

fn char_to_cp1254(value: char) -> u8 {
    match value {
        'Ğ' => 0xd0,
        'İ' => 0xdd,
        'Ş' => 0xde,
        'ğ' => 0xf0,
        'ı' => 0xfd,
        'ş' => 0xfe,
        _ => {
            if let Some(index) = CP1254_HIGH_CONTROL
                .iter()
                .position(|&mapped| mapped == value && value != '\u{fffd}')
            {
                return 0x80 + u8::try_from(index).unwrap_or(0);
            }
            let code = u32::from(value);
            if code <= 0x7f || (0xa0..=0xff).contains(&code) {
                u8::try_from(code).unwrap_or(b'?')
            } else {
                b'?'
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tckn;
    use deid_tr_core::{Pipeline, Tier};

    fn masker_for(pipeline: &Pipeline) -> Masker<'_> {
        Masker::new(pipeline)
    }

    #[test]
    fn utf8_without_a_bom_is_detected() {
        let shape = detect("Şükrü\nGökçe\n".as_bytes());
        assert_eq!(shape.encoding, Encoding::Utf8);
        assert!(!shape.bom);
        assert_eq!(shape.line_ending, LineEnding::Lf);
    }

    #[test]
    fn windows_1254_round_trips_the_six_turkish_letters() {
        // THE test this module exists for. Decoding these bytes as Latin-1 or
        // Windows-1252 yields `Ð İ Þ ð ý þ` -- six wrong letters in six Turkish
        // names.
        let bytes = [0xd0, 0xdd, 0xde, 0xf0, 0xfd, 0xfe];
        let shape = detect(&bytes);
        assert_eq!(shape.encoding, Encoding::Cp1254);
        let text = decode(&bytes, shape).expect("decode");
        assert_eq!(text, "ĞİŞğış");
        assert_eq!(encode(&text, shape), bytes);
    }

    #[test]
    fn a_utf8_bom_survives_the_round_trip() {
        let mut bytes = vec![0xef, 0xbb, 0xbf];
        bytes.extend_from_slice("merhaba".as_bytes());
        let shape = detect(&bytes);
        assert!(shape.bom);
        assert_eq!(decode(&bytes, shape).expect("decode"), "merhaba");
        assert_eq!(encode("merhaba", shape), bytes);
    }

    #[test]
    fn utf16_le_is_detected_and_re_encoded() {
        let mut bytes = vec![0xff, 0xfe];
        for unit in "Ayşe\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let shape = detect(&bytes);
        assert_eq!(shape.encoding, Encoding::Utf16Le);
        assert_eq!(shape.line_ending, LineEnding::CrLf);
        assert_eq!(decode(&bytes, shape).expect("decode"), "Ayşe\r\n");
        assert_eq!(encode("Ayşe\r\n", shape), bytes);
    }

    #[test]
    fn utf16_be_line_endings_are_counted_on_the_right_byte() {
        let mut bytes = vec![0xfe, 0xff];
        for unit in "a\nb\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        let shape = detect(&bytes);
        assert_eq!(shape.encoding, Encoding::Utf16Be);
        assert_eq!(shape.line_ending, LineEnding::Lf);
    }

    #[test]
    fn crlf_wins_when_it_dominates_and_is_not_double_counted_as_lf() {
        assert_eq!(detect(b"a\r\nb\r\nc").line_ending, LineEnding::CrLf);
        assert_eq!(detect(b"a\rb\rc").line_ending, LineEnding::Cr);
        assert_eq!(detect(b"single line").line_ending, LineEnding::None);
    }

    #[test]
    fn masking_preserves_encoding_and_line_endings() {
        let tckn = tckn();
        let source = format!("Hasta kaydı\r\nTCKN: {tckn}\r\n");
        let mut bytes = vec![0xff, 0xfe];
        for unit in source.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let (out, masked) = mask(&masker_for(&pipeline), &bytes).expect("mask");

        assert_eq!(&out[..2], &[0xff, 0xfe], "the BOM was dropped");
        let shape = detect(&out);
        assert_eq!(shape.encoding, Encoding::Utf16Le);
        assert_eq!(shape.line_ending, LineEnding::CrLf);
        let text = decode(&out, shape).expect("decode");
        assert!(!text.contains(&tckn));
        assert!(text.contains("\r\n"));
        assert_eq!(masked.originals, vec![tckn]);
    }

    #[test]
    fn a_name_survives_masking_because_no_model_is_installed() {
        let pipeline = Pipeline::new(Tier::SafeHarbor);
        let (out, masked) =
            mask(&masker_for(&pipeline), "Hasta Ayşe Yılmaz.".as_bytes()).expect("mask");
        assert_eq!(out, "Hasta Ayşe Yılmaz.".as_bytes());
        assert!(!masked.is_changed());
    }

    #[test]
    fn a_truncated_utf16_body_is_an_error_rather_than_a_dropped_byte() {
        let bytes = [0xff, 0xfe, 0x41];
        let shape = detect(&bytes);
        assert_eq!(decode(&bytes, shape), Err(TextError::Utf16Truncated));
    }
}
