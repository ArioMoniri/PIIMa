//! JSON serialisation, written by hand.
//!
//! WHY BY HAND rather than with `serde_json`: `core/` carries invariant I1, and
//! the dependency list is short enough that a pre-commit hook audits it by eye.
//! The output here is one object with one array of flat records -- no
//! polymorphism, no borrowed lifetimes, no schema evolution -- so the whole
//! serialiser is the escaper below plus a loop. A derive macro would be more
//! code in the dependency graph than in this file.
//!
//! The escaper is the part that matters and the part that is tested: an
//! unescaped `"` or a raw control byte in a replacement turns valid JSON into a
//! parse error at the consumer, and a consumer that recovers by regex is a
//! consumer that will eventually read a field boundary wrong.

use core::fmt::Write as _;

use super::{EntityRow, Report};
use crate::span::Decision;

/// Render the report as a JSON object.
pub(super) fn render(report: &Report) -> String {
    let mut out = String::with_capacity(report.text().len() + report.rows().len() * 200);
    out.push_str("{\"text\":");
    string(&mut out, report.text());
    out.push_str(",\"entities\":[");
    for (index, row) in report.rows().iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        entity(&mut out, row);
    }
    out.push_str("]}");
    out
}

fn entity(out: &mut String, row: &EntityRow) {
    out.push_str("{\"label\":");
    string(out, row.label.as_str());
    // `write!` into a String cannot fail; the result is discarded rather than
    // unwrapped to keep every path in this crate panic-free.
    let _ = write!(
        out,
        ",\"start\":{},\"end\":{},\"output_start\":{},\"output_end\":{}",
        row.start, row.end, row.output_start, row.output_end
    );
    out.push_str(",\"decision\":");
    string(
        out,
        match row.decision {
            Decision::Mask => "mask",
            Decision::Keep => "keep",
        },
    );
    out.push_str(",\"method\":");
    match row.method {
        Some(method) => string(out, method.as_str()),
        None => out.push_str("null"),
    }
    out.push_str(",\"layer\":");
    match row.layer {
        Some(layer) => {
            let rendered = layer.to_string();
            string(out, &rendered);
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"confidence\":");
    number(out, row.confidence);
    let _ = write!(out, ",\"checksum_validated\":{}", row.checksum_validated);
    out.push_str(",\"replacement\":");
    match row.replacement.as_deref() {
        Some(replacement) => string(out, replacement),
        None => out.push_str("null"),
    }
    out.push('}');
}

/// A finite float, or `null`.
///
/// JSON HAS NO NaN AND NO INFINITY. Emitting the Rust rendering of either
/// produces a bare `NaN` token that every strict parser rejects, so a
/// non-finite confidence becomes `null` -- absent, which is true, rather than
/// syntactically invalid.
fn number(out: &mut String, value: Option<f32>) {
    match value.filter(|v| v.is_finite()) {
        Some(value) => {
            let _ = write!(out, "{}", f64::from(value));
        }
        None => out.push_str("null"),
    }
}

/// A JSON string literal, escaped per RFC 8259 section 7.
fn string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // Every other C0 control has to be escaped as \u00XX; a raw one is
            // invalid JSON even though it is valid UTF-8.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::super::tests::{report, DOC};
    use super::*;

    #[test]
    fn the_document_and_every_entity_are_present() {
        let rendered = report().to_json();
        assert!(rendered.starts_with("{\"text\":\""));
        assert!(rendered.contains("\"label\":\"PATIENT_NAME\""));
        assert!(rendered.contains("\"label\":\"DATE_ADMISSION\""));
        assert!(rendered.contains("\"decision\":\"mask\""));
        assert!(rendered.contains("\"method\":\"mask\""));
        assert!(rendered.contains("\"layer\":null"));
        assert!(rendered.contains("\"confidence\":null"));
    }

    #[test]
    fn quotes_backslashes_and_controls_are_escaped() {
        // The fixture already carries `"`; the control and backslash cases are
        // added here because a replacement or a kept span can contain either.
        let mut rendered = String::new();
        string(&mut rendered, "a\"b\\c\nd\te\u{1}f");
        // The trailing \u{1} is the case a naive escaper misses: valid UTF-8,
        // invalid JSON, so it must come out as a \\u escape.
        assert_eq!(rendered, "\"a\\\"b\\\\c\\nd\\te\\u0001f\"");
    }

    #[test]
    fn turkish_characters_survive_verbatim() {
        // No \u escaping of non-ASCII: JSON is UTF-8 and escaping `ş` would
        // make the output unreadable for no gain.
        let mut rendered = String::new();
        string(&mut rendered, "Şükrü İşil ığ");
        assert_eq!(rendered, "\"Şükrü İşil ığ\"");
    }

    #[test]
    fn a_non_finite_confidence_becomes_null_not_a_parse_error() {
        let mut rendered = String::new();
        number(&mut rendered, Some(f32::NAN));
        assert_eq!(rendered, "null");
        rendered.clear();
        number(&mut rendered, Some(f32::INFINITY));
        assert_eq!(rendered, "null");
        rendered.clear();
        number(&mut rendered, Some(0.5));
        assert_eq!(rendered, "0.5");
    }

    #[test]
    fn the_output_is_balanced_and_quote_consistent() {
        // A cheap structural check that catches the class of bug this file can
        // actually have: an unescaped quote or a dropped brace. Counting quotes
        // outside escapes must come out even, and braces must balance.
        let rendered = report().to_json();
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escaped = false;
        let mut quotes = 0usize;
        for ch in rendered.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                    quotes += 1;
                }
                continue;
            }
            match ch {
                '"' => {
                    in_string = true;
                    quotes += 1;
                }
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "json output closed a bracket it never opened");
        }
        assert_eq!(depth, 0, "json output is unbalanced");
        assert_eq!(quotes % 2, 0, "json output has an odd number of quotes");
        assert!(!in_string, "json output ended inside a string");
    }

    #[test]
    fn no_original_reaches_the_json() {
        let rendered = report().to_json();
        assert!(!rendered.contains("Ayşe"));
        assert!(
            DOC.contains("Ayşe"),
            "the fixture must contain the original"
        );
    }
}
