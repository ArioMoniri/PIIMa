//! Serialising the object graph back to a file.
//!
//! # Full rewrite, always
//!
//! There is no incremental-save path in this module and there must never be
//! one. A PDF may append a new body, xref and trailer after the existing
//! `%%EOF`, which leaves the ENTIRE previous revision in the file for anyone
//! who walks the old cross-reference table. That is the most common
//! catastrophic redaction failure there is. Output from here has:
//!
//! * exactly one `%%EOF`,
//! * one cross-reference section,
//! * no `/Prev` in the trailer,
//! * and only the objects the caller asked for.
//!
//! `verify.rs` asserts all four against the produced bytes rather than trusting
//! this comment.
//!
//! # Everything is emitted uncompressed
//!
//! No `/FlateDecode`, no `/Type /ObjStm`. Two reasons, in order: this crate has
//! no compressor (see `inflate.rs`), and a reviewer holding the output can run
//! `strings` on it and see what is actually in the file. A redaction whose
//! result can only be audited by the tool that produced it is a redaction
//! nobody can check.

use std::collections::BTreeMap;

use crate::pdf::object::{Dict, Object, StringForm};

/// Serialise a set of objects into a complete PDF file.
///
/// `objects` is emitted verbatim; the caller decides reachability. `root` and
/// the optional `info` are what the trailer will point at.
#[must_use]
pub fn write(objects: &BTreeMap<u32, Object>, root: u32) -> Vec<u8> {
    let mut out = Vec::new();
    // The binary comment on line 2 is what marks the file as binary for
    // transfer tools; omitting it makes some readers mangle streams.
    out.extend_from_slice(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n");

    let max = objects.keys().copied().max().unwrap_or(0);
    let mut offsets: BTreeMap<u32, usize> = BTreeMap::new();
    for (number, object) in objects {
        offsets.insert(*number, out.len());
        out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        serialise(object, &mut out);
        out.extend_from_slice(b"\nendobj\n");
    }

    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", max + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for number in 1..=max {
        match offsets.get(&number) {
            Some(offset) => {
                out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
            }
            // A gap in the numbering is a free entry, not an omitted row: the
            // subsection header declared `max + 1` rows and a reader counts
            // them by position.
            None => out.extend_from_slice(b"0000000000 65535 f \n"),
        }
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root {root} 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            max + 1
        )
        .as_bytes(),
    );
    out
}

fn serialise(object: &Object, out: &mut Vec<u8>) {
    match object {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Bool(true) => out.extend_from_slice(b"true"),
        Object::Bool(false) => out.extend_from_slice(b"false"),
        Object::Int(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Object::Real(value) => {
            // PDF has no exponent syntax for reals, so `1e-7` must be written
            // out. A reader that meets `1e-7` treats it as the number 1
            // followed by a name, which silently moves whatever it positions.
            let mut text = format!("{value:.6}");
            if text.contains('.') {
                // Trimmed in two steps, not with one chained `trim_end_matches`:
                // that is greedy ACROSS the decimal point, so `100.000000`
                // becomes `1` and every coordinate in the file moves.
                while text.ends_with('0') {
                    text.pop();
                }
                if text.ends_with('.') {
                    text.pop();
                }
            }
            if text == "-0" {
                text = "0".to_owned();
            }
            out.extend_from_slice(text.as_bytes());
        }
        Object::Str(bytes, form) => serialise_string(bytes, *form, out),
        Object::Name(name) => {
            out.push(b'/');
            for byte in name.bytes() {
                if byte <= 0x20 || crate::pdf::object::is_delimiter(byte) || byte == b'#' {
                    out.extend_from_slice(format!("#{byte:02X}").as_bytes());
                } else {
                    out.push(byte);
                }
            }
        }
        Object::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b' ');
                }
                serialise(item, out);
            }
            out.push(b']');
        }
        Object::Dict(dict) => serialise_dict(dict, out),
        Object::Stream(dict, body) => {
            let mut dict = dict.clone();
            // The stream is written out raw, so any filter the input declared
            // no longer applies. Leaving `/Filter` behind would make every
            // reader try to inflate plain bytes and fail.
            dict.remove("Filter");
            dict.remove("DecodeParms");
            dict.remove("DL");
            dict.set(
                "Length",
                Object::Int(i64::try_from(body.len()).unwrap_or(0)),
            );
            serialise_dict(&dict, out);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendstream");
        }
        Object::Reference(number, generation) => {
            out.extend_from_slice(format!("{number} {generation} R").as_bytes());
        }
    }
}

fn serialise_dict(dict: &Dict, out: &mut Vec<u8>) {
    out.extend_from_slice(b"<<");
    for (key, value) in &dict.0 {
        out.push(b' ');
        serialise(&Object::Name(key.clone()), out);
        out.push(b' ');
        serialise(value, out);
    }
    out.extend_from_slice(b" >>");
}

fn serialise_string(bytes: &[u8], form: StringForm, out: &mut Vec<u8>) {
    if form == StringForm::Hex {
        out.push(b'<');
        for byte in bytes {
            out.extend_from_slice(format!("{byte:02X}").as_bytes());
        }
        out.push(b'>');
        return;
    }
    out.push(b'(');
    for &byte in bytes {
        match byte {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(byte);
            }
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            // Non-printables are octal-escaped so the file stays greppable and
            // so a stray `\r` cannot be normalised by a transfer tool.
            0x00..=0x1f | 0x7f..=0xff => out.extend_from_slice(format!("\\{byte:03o}").as_bytes()),
            other => out.push(other),
        }
    }
    out.push(b')');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::document::Document;

    fn minimal() -> BTreeMap<u32, Object> {
        let mut objects = BTreeMap::new();
        let mut catalogue = Dict::default();
        catalogue.set("Type", Object::Name("Catalog".to_owned()));
        catalogue.set("Pages", Object::Reference(2, 0));
        objects.insert(1, Object::Dict(catalogue));

        let mut pages = Dict::default();
        pages.set("Type", Object::Name("Pages".to_owned()));
        pages.set("Kids", Object::Array(vec![Object::Reference(3, 0)]));
        pages.set("Count", Object::Int(1));
        objects.insert(2, Object::Dict(pages));

        let mut page = Dict::default();
        page.set("Type", Object::Name("Page".to_owned()));
        page.set("Parent", Object::Reference(2, 0));
        page.set("Contents", Object::Reference(4, 0));
        objects.insert(3, Object::Dict(page));

        objects.insert(
            4,
            Object::Stream(Dict::default(), b"BT (hi) Tj ET".to_vec()),
        );
        objects
    }

    #[test]
    fn written_output_reloads_with_the_same_page_count() {
        let bytes = write(&minimal(), 1);
        let document = Document::load(&bytes).expect("reload");
        assert_eq!(document.page_numbers().expect("pages"), vec![3]);
        assert_eq!(document.input_revisions, 1);
    }

    #[test]
    fn output_has_exactly_one_eof_and_no_prev() {
        let bytes = write(&minimal(), 1);
        assert_eq!(crate::pdf::document::find_all(&bytes, b"%%EOF").len(), 1);
        assert!(crate::pdf::document::find_all(&bytes, b"/Prev").is_empty());
    }

    #[test]
    fn a_stream_loses_its_filter_when_it_is_written_raw() {
        let mut dict = Dict::default();
        dict.set("Filter", Object::Name("FlateDecode".to_owned()));
        dict.set("Length", Object::Int(9999));
        let mut objects = minimal();
        objects.insert(4, Object::Stream(dict, b"BT (hi) Tj ET".to_vec()));
        let bytes = write(&objects, 1);
        assert!(crate::pdf::document::find_all(&bytes, b"/Filter").is_empty());
        assert!(crate::pdf::document::find_all(&bytes, b"/Length 13").len() == 1);
    }

    #[test]
    fn reals_are_written_without_an_exponent() {
        let mut out = Vec::new();
        serialise(&Object::Real(0.000_000_1), &mut out);
        assert_eq!(String::from_utf8_lossy(&out), "0");
        out.clear();
        serialise(&Object::Real(-12.5), &mut out);
        assert_eq!(String::from_utf8_lossy(&out), "-12.5");
    }
}
