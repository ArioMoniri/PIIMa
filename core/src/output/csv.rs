//! CSV rows, quoted per RFC 4180.
//!
//! ONE ROW PER ENTITY, NOT ONE ROW PER DOCUMENT, and no column holds the
//! document text. A CSV is the format most likely to be opened in a
//! spreadsheet, mailed, or loaded into a warehouse, so it carries the metadata
//! that supports an audit -- offsets, labels, decisions -- and nothing that
//! supports a re-identification.

use super::{EntityRow, Report};
use crate::span::Decision;

/// The header row. Stable: a consumer may key on column position.
pub const CSV_HEADER: &str = "label,start,end,output_start,output_end,decision,method,layer,confidence,checksum_validated,replacement";

/// Render the report as [`CSV_HEADER`] followed by one row per entity.
pub(super) fn render(report: &Report) -> Vec<String> {
    let mut rows = Vec::with_capacity(report.rows().len() + 1);
    rows.push(CSV_HEADER.to_owned());
    rows.extend(report.rows().iter().map(row));
    rows
}

fn row(entity: &EntityRow) -> String {
    let decision = match entity.decision {
        Decision::Mask => "mask",
        Decision::Keep => "keep",
    };
    let method = entity.method.map_or("", |method| method.as_str());
    let layer = entity.layer.map(|layer| layer.to_string());
    let confidence = entity
        .confidence
        .filter(|value| value.is_finite())
        .map(|value| format!("{value}"));
    [
        field(entity.label.as_str()),
        entity.start.to_string(),
        entity.end.to_string(),
        entity.output_start.to_string(),
        entity.output_end.to_string(),
        field(decision),
        field(method),
        field(layer.as_deref().unwrap_or("")),
        confidence.unwrap_or_default(),
        entity.checksum_validated.to_string(),
        field(entity.replacement.as_deref().unwrap_or("")),
    ]
    .join(",")
}

/// Quote a field when RFC 4180 requires it, doubling any embedded quote.
///
/// A replacement can legitimately contain a comma (`Kartal Cad. No: 12`), a
/// quote, or a newline if a detector ever spans one. An unquoted comma silently
/// shifts every later column by one, which produces a file that parses cleanly
/// and means something different -- the worst failure mode a data format has.
fn field(value: &str) -> String {
    let needs_quoting = value.contains([',', '"', '\n', '\r']);
    if !needs_quoting {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::super::tests::{report, DOC};
    use super::*;

    #[test]
    fn the_header_comes_first_and_one_row_follows_per_entity() {
        let rows = report().to_csv();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], CSV_HEADER);
        assert!(rows[1].starts_with("PATIENT_NAME,"));
        assert!(rows[2].starts_with("DATE_ADMISSION,"));
    }

    #[test]
    fn every_row_has_the_same_column_count_as_the_header() {
        // Column count under RFC 4180 quoting, so a quoted comma does not
        // inflate the count. This is the check that catches the shifted-column
        // failure the quoting exists to prevent.
        fn columns(line: &str) -> usize {
            let mut count = 1;
            let mut quoted = false;
            let mut chars = line.chars().peekable();
            while let Some(ch) = chars.next() {
                match ch {
                    '"' if quoted && chars.peek() == Some(&'"') => {
                        chars.next();
                    }
                    '"' => quoted = !quoted,
                    ',' if !quoted => count += 1,
                    _ => {}
                }
            }
            count
        }
        let rows = report().to_csv();
        let expected = columns(&rows[0]);
        for line in &rows[1..] {
            assert_eq!(columns(line), expected, "row has the wrong column count");
        }
    }

    #[test]
    fn a_field_with_a_comma_quote_or_newline_is_quoted() {
        assert_eq!(field("plain"), "plain");
        assert_eq!(field("Kartal Cad., No: 12"), "\"Kartal Cad., No: 12\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn turkish_characters_are_not_mangled() {
        assert_eq!(field("Şükrü İşil"), "Şükrü İşil");
    }

    #[test]
    fn no_original_reaches_the_csv() {
        let rendered = report().to_csv().join("\n");
        assert!(!rendered.contains("Ayşe"));
        assert!(
            DOC.contains("Ayşe"),
            "the fixture must contain the original"
        );
    }
}
