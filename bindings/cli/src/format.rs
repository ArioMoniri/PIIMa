//! `--format text|json|csv|html`, and `--confidence-threshold`.
//!
//! # What each format is for
//!
//! * `text` -- the de-identified document, and nothing else. The default,
//!   because it is the one a pipe can carry.
//! * `json` -- the document plus the span report, for a caller that is going to
//!   parse it.
//! * `csv` -- the span report alone, one row per span, for a spreadsheet or a
//!   `cut` pipeline. The document is NOT in it: a CSV cell containing a clinical
//!   note is a cell that will be opened in a spreadsheet on somebody's laptop.
//! * `html` -- the de-identified document with each replacement marked, for a
//!   human reviewing what was masked.
//!
//! # What none of them contains
//!
//! The ORIGINAL identifiers. Every format renders the MASKED document and the
//! surrogates that replaced the originals. The span map -- the table from
//! surrogate back to real identifier -- is not written by any of them and is not
//! written to disk by this binary at all. If it were, `deid mask > out.json`
//! would produce a file that is a de-identified note next to the key that undoes
//! it, which is worse than not masking at all.
//!
//! # `--confidence-threshold`, and the divergence from the incumbent
//!
//! The incumbent's `confidence_threshold` decides what gets REDACTED: raising it
//! leaves low-confidence detections in the document. Ours cannot, and the
//! difference is invariant I2 -- recall is the product, precision is a feature.
//! A missed identifier is a breach; an over-masked term is a papercut. So a
//! threshold here filters the REPORT and never the masking, and
//! [`RECALL_WARNING`] is printed to stderr on every run that uses it. Two things
//! follow that are worth stating because they are surprising:
//!
//! * `--format text --confidence-threshold 0.9` changes NOTHING. The text format
//!   is the document, the document is fully masked, and the flag has no report to
//!   filter. It is still accepted, and it still warns.
//! * A span hidden from the report is still masked in the output. A caller who
//!   reconciles "entities I was shown" against "spans in the document" will find
//!   the second is larger, and that is the correct direction.

use deid_tr_core::{Decision, DeidResult, MappedSpan};

/// The warning printed on every run that passes `--confidence-threshold`.
pub const RECALL_WARNING: &str = concat!(
    "WARNING: --confidence-threshold filters what is REPORTED and never what is masked. ",
    "Raising it hides low-confidence detections from the entity report; the document is masked ",
    "identically either way, and this flag must never be used as a masking control. Recall is ",
    "the product: a missed identifier is a breach, an over-masked term is a papercut (I2)."
);

/// The note printed when a threshold is given with a format that has no report.
pub const NO_REPORT_NOTE: &str =
    "note: --confidence-threshold has no effect with --format text, which emits the \
     de-identified document and no entity report. The document is masked identically.";

/// The output shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// The de-identified document, bytes only.
    #[default]
    Text,
    /// The document plus the span report.
    Json,
    /// The span report, one row per span.
    Csv,
    /// The document with each replacement marked, for review.
    Html,
}

impl Format {
    /// Parse the `--format` value, or `None` for an unknown one.
    ///
    /// An unknown value is a parse failure and not a fallback to `text`: a
    /// caller who typed `--format jsonl` and received the raw document has been
    /// handed something they will pipe into a JSON parser.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "html" => Some(Self::Html),
            _ => None,
        }
    }

    /// The name, for diagnostics and for the batch manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
        }
    }

    /// The file extension a batch run gives an output of this format.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
        }
    }

    /// True when this format carries an entity report a threshold can filter.
    #[must_use]
    pub const fn has_report(self) -> bool {
        !matches!(self, Self::Text)
    }
}

/// Whether a span survives the reporting threshold.
fn reported(mapped: &MappedSpan, threshold: Option<f32>) -> bool {
    threshold.is_none_or(|floor| mapped.span.confidence() >= floor)
}

/// Render a result in the requested format.
///
/// `threshold` filters the REPORT only. The masked document in the `text` and
/// `html` outputs is unaffected by it, which is the whole point.
#[must_use]
pub fn render(format: Format, result: &DeidResult, threshold: Option<f32>) -> String {
    match format {
        Format::Text => result.text.clone(),
        Format::Json => json(result, threshold),
        Format::Csv => csv(result, threshold),
        Format::Html => html(result, threshold),
    }
}

/// How many spans were masked, and how many the report withheld.
#[must_use]
pub fn counts(result: &DeidResult, threshold: Option<f32>) -> (usize, usize, usize) {
    let masked = result
        .span_map
        .iter()
        .filter(|mapped| mapped.decision == Decision::Mask)
        .count();
    let withheld = result
        .span_map
        .iter()
        .filter(|mapped| !reported(mapped, threshold))
        .count();
    (result.span_map.len(), masked, withheld)
}

/// Serialise a string as a JSON string literal.
///
/// Written out rather than pulled in, because `serde_json` is not a dependency
/// of this crate and adding one to emit four escapes would put a parser in the
/// binary that reads clinical documents. The escapes are the full set JSON
/// requires: the two structural characters, the five named control escapes, and
/// `\u00XX` for everything else below 0x20.
pub(crate) fn quote(value: &str, out: &mut String) {
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
            ch if (ch as u32) < 0x20 => {
                out.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    let nibble = ((ch as u32) >> shift) & 0xf;
                    out.push(char::from_digit(nibble, 16).unwrap_or('0'));
                }
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

/// One span, as JSON object fields, without the enclosing braces.
fn span_fields(mapped: &MappedSpan, out: &mut String) {
    out.push_str("\"label\":");
    quote(mapped.span.label().as_str(), out);
    out.push_str(",\"start\":");
    out.push_str(&mapped.span.start().to_string());
    out.push_str(",\"end\":");
    out.push_str(&mapped.span.end().to_string());
    out.push_str(",\"output_start\":");
    out.push_str(&mapped.output_start.to_string());
    out.push_str(",\"output_end\":");
    out.push_str(&mapped.output_end.to_string());
    out.push_str(",\"confidence\":");
    out.push_str(&mapped.span.confidence().to_string());
    out.push_str(",\"layer\":");
    quote(&mapped.span.source().to_string(), out);
    out.push_str(",\"checksum_validated\":");
    out.push_str(if mapped.span.is_checksum_validated() {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"decision\":");
    quote(&mapped.decision.to_string(), out);
    out.push_str(",\"replacement\":");
    match &mapped.replacement {
        Some(surrogate) => quote(surrogate, out),
        None => out.push_str("null"),
    }
}

fn json(result: &DeidResult, threshold: Option<f32>) -> String {
    let (total, masked, withheld) = counts(result, threshold);
    let mut out = String::with_capacity(result.text.len() + 256);
    out.push_str("{\"text\":");
    quote(&result.text, &mut out);
    out.push_str(",\"spans\":[");
    let mut first = true;
    for mapped in result.span_map.iter().filter(|m| reported(m, threshold)) {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('{');
        span_fields(mapped, &mut out);
        out.push('}');
    }
    out.push_str("],\"counts\":{\"total\":");
    out.push_str(&total.to_string());
    out.push_str(",\"masked\":");
    out.push_str(&masked.to_string());
    out.push_str(",\"reported\":");
    out.push_str(&(total - withheld).to_string());
    out.push_str(",\"withheld_by_threshold\":");
    out.push_str(&withheld.to_string());
    out.push_str("},\"offsets\":");
    quote(
        "start/end are BYTE offsets into the ORIGINAL document; output_start/output_end are \
         BYTE offsets into the masked text above. Not character indices.",
        &mut out,
    );
    if let Some(floor) = threshold {
        out.push_str(",\"confidence_threshold\":");
        out.push_str(&floor.to_string());
        out.push_str(",\"threshold_warning\":");
        quote(RECALL_WARNING, &mut out);
    }
    out.push('}');
    out
}

/// Escape one CSV field per RFC 4180.
fn csv_field(value: &str, out: &mut String) {
    let needs_quotes = value.contains([',', '"', '\n', '\r']);
    if !needs_quotes {
        out.push_str(value);
        return;
    }
    out.push('"');
    for ch in value.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
}

fn csv(result: &DeidResult, threshold: Option<f32>) -> String {
    // NO DOCUMENT COLUMN, deliberately: see the module header.
    let mut out = String::from(
        "label,start,end,output_start,output_end,confidence,layer,checksum_validated,decision,replacement\n",
    );
    for mapped in result.span_map.iter().filter(|m| reported(m, threshold)) {
        csv_field(mapped.span.label().as_str(), &mut out);
        out.push(',');
        out.push_str(&mapped.span.start().to_string());
        out.push(',');
        out.push_str(&mapped.span.end().to_string());
        out.push(',');
        out.push_str(&mapped.output_start.to_string());
        out.push(',');
        out.push_str(&mapped.output_end.to_string());
        out.push(',');
        out.push_str(&mapped.span.confidence().to_string());
        out.push(',');
        csv_field(&mapped.span.source().to_string(), &mut out);
        out.push(',');
        out.push_str(if mapped.span.is_checksum_validated() {
            "true"
        } else {
            "false"
        });
        out.push(',');
        csv_field(&mapped.decision.to_string(), &mut out);
        out.push(',');
        csv_field(mapped.replacement.as_deref().unwrap_or(""), &mut out);
        out.push('\n');
    }
    out
}

/// Escape text for HTML element content and attribute values.
///
/// All five, including the two quote forms, because the label is interpolated
/// into a `data-entity` attribute. A label comes from a closed schema so it
/// cannot currently carry a quote, and escaping it anyway costs nothing and
/// removes the need for the next reader to verify that claim.
fn escape_html(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            ch => out.push(ch),
        }
    }
}

fn html(result: &DeidResult, threshold: Option<f32>) -> String {
    let (total, masked, withheld) = counts(result, threshold);
    let mut out = String::with_capacity(result.text.len() * 2 + 1024);
    out.push_str(
        "<!doctype html>\n<html lang=\"tr\"><head><meta charset=\"utf-8\">\
         <title>deid-tr</title><style>\
         body{font:16px/1.6 system-ui,sans-serif;margin:2rem;max-width:60rem}\
         pre{white-space:pre-wrap;word-wrap:break-word;background:#f6f6f6;padding:1rem;border-radius:6px}\
         mark{background:#ffe08a;padding:0 .15em;border-radius:3px}\
         .meta{color:#444;font-size:.9em}\
         .warn{border-left:4px solid #c00;padding-left:.75rem}\
         </style></head><body>\n",
    );
    out.push_str("<h1>De-identified document</h1>\n<p class=\"meta\">");
    out.push_str(&masked.to_string());
    out.push_str(" of ");
    out.push_str(&total.to_string());
    out.push_str(" candidate span(s) masked");
    if withheld > 0 {
        out.push_str("; ");
        out.push_str(&withheld.to_string());
        out.push_str(" withheld from the report by --confidence-threshold (still masked)");
    }
    out.push_str(".</p>\n");
    // Stated in the artifact itself, because an HTML report is the output most
    // likely to be shown to somebody who did not run the command.
    out.push_str(
        "<p class=\"meta warn\">Coverage: rule-detectable identifiers only. L2 has no trained \
         model in this build, so <strong>no names are masked</strong> &mdash; any personal name \
         below is still the real one.</p>\n<pre>",
    );

    // The MASKED text is walked, and each replacement is wrapped where it
    // actually landed in the output. Walking output offsets rather than
    // searching for the surrogate is what keeps the marks correct when a
    // surrogate happens to occur elsewhere in the document as ordinary prose.
    let mut cursor = 0usize;
    for mapped in &result.span_map {
        if mapped.decision != Decision::Mask {
            continue;
        }
        let Some(between) = result.text.get(cursor..mapped.output_start) else {
            continue;
        };
        escape_html(between, &mut out);
        out.push_str("<mark data-entity=\"");
        escape_html(mapped.span.label().as_str(), &mut out);
        out.push_str("\" title=\"");
        escape_html(mapped.span.label().as_str(), &mut out);
        out.push_str("\">");
        if let Some(surrogate) = result.text.get(mapped.output_start..mapped.output_end) {
            escape_html(surrogate, &mut out);
        }
        out.push_str("</mark>");
        cursor = mapped.output_end;
    }
    if let Some(tail) = result.text.get(cursor..) {
        escape_html(tail, &mut out);
    }
    out.push_str("</pre>\n");
    if threshold.is_some() {
        out.push_str("<p class=\"meta warn\">");
        escape_html(RECALL_WARNING, &mut out);
        out.push_str("</p>\n");
    }
    out.push_str("</body></html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::surrogate::SALT_LEN;
    use deid_tr_core::{Pipeline, Salt, SurrogateEngine, Tier};

    /// A fixed salt, so the surrogates are stable across runs of this test.
    /// Test-only: the shipped binary draws one from the OS per run.
    const TEST_SALT: [u8; SALT_LEN] = [0x27; SALT_LEN];

    fn masked(source: &str) -> DeidResult {
        Pipeline::new(Tier::SafeHarbor)
            .with_surrogates(SurrogateEngine::new(Salt::from_bytes(TEST_SALT)))
            .deidentify(source)
            .expect("pipeline run")
    }

    /// Synthetic, and the TCKN is built at run time (I8).
    fn note() -> String {
        format!(
            "Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00. carcinoma'lı.",
            crate::fixtures::tckn()
        )
    }

    #[test]
    fn an_unknown_format_is_a_parse_failure_and_not_a_fallback() {
        assert_eq!(Format::parse("json"), Some(Format::Json));
        assert_eq!(Format::parse("jsonl"), None);
        assert_eq!(Format::parse("JSON"), None);
        assert_eq!(Format::default(), Format::Text);
    }

    #[test]
    fn text_is_the_document_and_nothing_else() {
        let result = masked(&note());
        assert_eq!(render(Format::Text, &result, None), result.text);
    }

    #[test]
    fn a_threshold_never_changes_the_masked_document() {
        // I2 at the format layer. Every format that carries the document must
        // carry the SAME document whatever the threshold is.
        let result = masked(&note());
        assert_eq!(
            render(Format::Text, &result, None),
            render(Format::Text, &result, Some(0.99))
        );
        let wide = render(Format::Html, &result, None);
        let narrow = render(Format::Html, &result, Some(0.99));
        // The marked-up body is identical; only the trailing warning differs.
        let body_of = |page: &str| {
            page.split_once("<pre>")
                .and_then(|(_, rest)| rest.split_once("</pre>"))
                .map(|(body, _)| body.to_owned())
                .expect("a pre block")
        };
        assert_eq!(body_of(&wide), body_of(&narrow));
        assert!(
            narrow.contains("never what is masked")
                || narrow.contains("never used as a masking control")
        );
    }

    #[test]
    fn json_is_parseable_and_carries_the_document_and_the_spans() {
        let source = note();
        let result = masked(&source);
        let rendered = render(Format::Json, &result, None);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("the json format must be valid JSON");
        assert_eq!(parsed["text"], serde_json::json!(result.text));
        let spans = parsed["spans"].as_array().expect("spans");
        assert_eq!(spans.len(), result.span_map.len());
        let tckn_span = spans
            .iter()
            .find(|span| span["label"] == serde_json::json!("TCKN"))
            .expect("the TCKN reached the report");
        assert_eq!(tckn_span["checksum_validated"], serde_json::json!(true));
        assert_eq!(tckn_span["layer"], serde_json::json!("rules"));
    }

    #[test]
    fn no_format_ever_emits_an_original_identifier() {
        // The property that makes these formats safe to redirect to a file. The
        // span map holds the originals; nothing here may print one.
        let source = note();
        let result = masked(&source);
        let secret = crate::fixtures::tckn();
        for format in [Format::Text, Format::Json, Format::Csv, Format::Html] {
            let rendered = render(format, &result, None);
            assert!(
                !rendered.contains(&secret),
                "{} leaked an original identifier",
                format.as_str()
            );
        }
    }

    #[test]
    fn json_escapes_a_document_that_contains_json_punctuation() {
        // A clinical note can legitimately contain a quote or a backslash. If
        // the escaper misses one, `deid mask --format json | jq` fails on real
        // input and passes on every fixture anyone thought to write.
        let source = "Hasta \"Ayşe\" dedi.\nSatır\tsonu\\ters.";
        let result = masked(source);
        let rendered = render(Format::Json, &result, None);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(parsed["text"], serde_json::json!(source));
    }

    #[test]
    fn csv_has_a_header_one_row_per_span_and_no_document_column() {
        let result = masked(&note());
        let rendered = render(Format::Csv, &result, None);
        let mut lines = rendered.lines();
        let header = lines.next().expect("header");
        assert!(header.starts_with("label,start,end,"));
        assert!(!header.contains("text"), "the CSV must not carry the note");
        assert_eq!(lines.count(), result.span_map.len());
    }

    #[test]
    fn csv_quotes_a_field_that_contains_a_separator() {
        let mut out = String::new();
        csv_field("a,b", &mut out);
        assert_eq!(out, "\"a,b\"");
        out.clear();
        csv_field("say \"hi\"", &mut out);
        assert_eq!(out, "\"say \"\"hi\"\"\"");
        out.clear();
        csv_field("plain", &mut out);
        assert_eq!(out, "plain");
    }

    #[test]
    fn html_escapes_the_document_and_marks_every_replacement() {
        let result = masked("Hasta <b>Ayşe</b> & TCKN 12345678951 gecersiz. tel 0(532) 000 00 00.");
        let rendered = render(Format::Html, &result, None);
        assert!(
            !rendered.contains("<b>Ayşe</b>"),
            "the document was not escaped"
        );
        assert!(rendered.contains("&lt;b&gt;"));
        assert!(rendered.contains("data-entity=\"PHONE\""));
        // And the honesty banner is in the artifact, because an HTML report is
        // the output most likely to be read by someone who did not run it.
        assert!(rendered.contains("no names are masked"));
    }

    #[test]
    fn a_threshold_withholds_spans_from_the_report_and_counts_them() {
        let result = masked(&note());
        let (total, masked_count, withheld) = counts(&result, Some(1.01));
        assert_eq!(total, result.span_map.len());
        assert_eq!(
            withheld, total,
            "a threshold above 1.0 withholds everything"
        );
        assert!(masked_count > 0, "and the pipeline still masked them");

        let rendered = render(Format::Json, &result, Some(1.01));
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert!(parsed["spans"].as_array().expect("spans").is_empty());
        assert_eq!(parsed["counts"]["masked"], serde_json::json!(masked_count));
        assert!(parsed["threshold_warning"].is_string());
    }

    #[test]
    fn the_recall_warning_says_which_direction_is_safe() {
        assert!(RECALL_WARNING.contains("never what is masked"));
        assert!(RECALL_WARNING.contains("breach"));
        assert!(NO_REPORT_NOTE.contains("--format text"));
    }

    #[test]
    fn only_the_text_format_lacks_a_report() {
        assert!(!Format::Text.has_report());
        for format in [Format::Json, Format::Csv, Format::Html] {
            assert!(format.has_report(), "{}", format.as_str());
        }
    }
}
