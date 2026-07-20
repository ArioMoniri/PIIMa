//! Output formats: the structured result, JSON, CSV rows, and an HTML
//! highlight view.
//!
//! # What is in an output, and what is deliberately not
//!
//! Every format in this module renders the DE-IDENTIFIED document and SPAN
//! METADATA. None of them renders an original. That is not an oversight and it
//! is not configurable: an exported file is the artifact most likely to be
//! attached to a ticket, dropped in a shared folder or pasted into a chat, and
//! I4 says the original never travels that path. Re-identification data lives
//! in the in-memory map (`MappedSpan::original`, [`RedactedSpan::original`]) and
//! goes back to the caller who is already holding the document.
//!
//! A caveat that has to be said out loud rather than assumed: the de-identified
//! text is only as clean as the run that produced it. L4 may KEEP a span, and a
//! kept span's bytes are the original bytes. An export is therefore safe to the
//! degree the pipeline was, no further.
//!
//! # Structure
//!
//! [`Report`] is the one intermediate the three serialisers share. It is built
//! from either pipeline output ([`Report::from_deid`]) or a redaction pass
//! ([`Report::from_redacted`]), so a format is written once rather than twice
//! and the two paths cannot drift into emitting different column sets.
//!
//! [`RedactedSpan::original`]: crate::redact::RedactedSpan::original

mod csv;
mod html;
mod json;

use crate::label::EntityLabel;
use crate::pipeline::DeidResult;
use crate::redact::{Redacted, RedactionMethod};
use crate::span::{Decision, Layer};

pub use csv::CSV_HEADER;
pub use html::{palette, HtmlOptions};

/// One detected entity, as every output format sees it.
///
/// NO `original` FIELD, and none is reachable from here. See the module header.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityRow {
    /// The schema label.
    pub label: EntityLabel,
    /// Inclusive byte offset in the ORIGINAL document.
    pub start: usize,
    /// Exclusive byte offset in the ORIGINAL document.
    pub end: usize,
    /// Inclusive byte offset in the OUTPUT document.
    pub output_start: usize,
    /// Exclusive byte offset in the OUTPUT document.
    pub output_end: usize,
    /// Mask or Keep.
    pub decision: Decision,
    /// The redaction method APPLIED -- not the one the policy requested.
    ///
    /// `None` only for a kept span, which had no method applied to it.
    /// Reported rather than guessed, because a format that invents
    /// `"surrogate"` for a run that did not use one is a false audit record,
    /// and reporting the requested method would misreport every documented
    /// fallback (`DateShift` on a non-date label).
    pub method: Option<RedactionMethod>,
    /// The layer that proposed the span, when known.
    pub layer: Option<Layer>,
    /// Combined confidence at the point of decision, when known.
    pub confidence: Option<f32>,
    /// True when an arithmetic check actually passed on the covered bytes.
    pub checksum_validated: bool,
    /// The text substituted. NOT PHI. `None` for a kept span.
    pub replacement: Option<String>,
}

/// A de-identified document plus its entity metadata, ready to serialise.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    text: String,
    rows: Vec<EntityRow>,
}

impl Report {
    /// A report over pipeline output.
    #[must_use]
    pub fn from_deid(result: &DeidResult) -> Self {
        let rows = result
            .span_map
            .iter()
            .map(|mapped| EntityRow {
                label: mapped.span.label(),
                start: mapped.span.start(),
                end: mapped.span.end(),
                output_start: mapped.output_start,
                output_end: mapped.output_end,
                decision: mapped.decision,
                method: mapped.applied_method,
                layer: Some(mapped.span.source()),
                confidence: Some(mapped.span.confidence()),
                checksum_validated: mapped.span.is_checksum_validated(),
                replacement: mapped.replacement.clone(),
            })
            .collect();
        Self {
            text: result.text.clone(),
            rows,
        }
    }

    /// A report over a redaction pass.
    ///
    /// Every row is a [`Decision::Mask`]: a span that reached [`Redacted`] was
    /// redacted by definition, and the decision to keep it was taken upstream
    /// in L4 and is therefore not represented here.
    #[must_use]
    pub fn from_redacted(redacted: &Redacted) -> Self {
        let rows = redacted
            .spans()
            .iter()
            .map(|span| EntityRow {
                label: span.label,
                start: span.start,
                end: span.end,
                output_start: span.output_start,
                output_end: span.output_end,
                decision: Decision::Mask,
                method: Some(span.applied),
                layer: None,
                confidence: None,
                checksum_validated: false,
                replacement: Some(span.replacement.clone()),
            })
            .collect();
        Self {
            text: redacted.text().to_owned(),
            rows,
        }
    }

    /// The de-identified document.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The entity rows, in the producer's order.
    #[must_use]
    pub fn rows(&self) -> &[EntityRow] {
        &self.rows
    }

    /// The report as a JSON object.
    #[must_use]
    pub fn to_json(&self) -> String {
        json::render(self)
    }

    /// The report as CSV rows: [`CSV_HEADER`] followed by one row per entity.
    ///
    /// Rows rather than one blob, so a caller streaming a large corpus writes
    /// the header once and appends without re-parsing.
    #[must_use]
    pub fn to_csv(&self) -> Vec<String> {
        csv::render(self)
    }

    /// The report as an HTML highlight view.
    #[must_use]
    pub fn to_html(&self, options: &HtmlOptions) -> String {
        html::render(self, options)
    }

    /// A report assembled from parts, so a test can hand a formatter rows that
    /// no producer would ever emit -- overlapping, or addressing bytes past the
    /// end of the text. Test-only, because a public constructor with no
    /// consistency check is a way to build a report that lies.
    #[cfg(test)]
    pub(super) fn from_parts_for_tests(text: String, rows: Vec<EntityRow>) -> Self {
        Self { text, rows }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::{RedactionPolicy, Redactor};
    use crate::span::{DetectorId, Span};

    /// Synthetic, and chosen to be hostile to a markup serialiser: it carries
    /// `<`, `>`, `&`, `"` and Turkish multi-byte letters.
    pub(super) const DOC: &str =
        "Hasta \"Ayşe & Şükrü\" <ilk> muayene: 10.03.2019, not: a<b & c>d.";

    pub(super) fn span(label: EntityLabel, needle: &str) -> Span {
        let start = DOC.find(needle).expect("fixture must contain the needle");
        Span::new(
            DOC,
            start,
            start + needle.len(),
            label,
            DetectorId::Ner(0),
            0.87,
        )
        .expect("fixture span must be valid")
    }

    /// A redaction over the hostile fixture, which every format test shares.
    pub(super) fn report() -> Report {
        let policy = RedactionPolicy::new(crate::redact::RedactionMethod::Mask);
        let redacted = Redactor::new(&policy)
            .redact(
                DOC,
                &[
                    span(EntityLabel::PatientName, "Ayşe & Şükrü"),
                    span(EntityLabel::DateAdmission, "10.03.2019"),
                ],
            )
            .expect("redact");
        Report::from_redacted(&redacted)
    }

    #[test]
    fn a_report_from_a_redaction_carries_the_applied_method() {
        let report = report();
        assert_eq!(report.rows().len(), 2);
        assert_eq!(
            report.rows()[0].method,
            Some(crate::redact::RedactionMethod::Mask)
        );
        assert_eq!(report.rows()[0].decision, Decision::Mask);
        assert_eq!(report.rows()[0].label, EntityLabel::PatientName);
    }

    #[test]
    fn a_report_never_exposes_an_original() {
        // I4, structurally rather than by convention: there is no field on
        // EntityRow that could hold one, so no format can serialise one.
        let report = report();
        for row in report.rows() {
            assert!(!format!("{row:?}").contains("Ayşe"));
        }
        assert!(!report.text().contains("Ayşe"));
    }

    #[test]
    fn a_report_from_the_pipeline_records_the_layer_and_the_applied_method() {
        // The pipeline renders through the same RedactionPolicy the standalone
        // redactor does, so the method it applied is a fact to report rather
        // than a null. With no L5 engine installed the effective default is
        // `Mask`, which is exactly the label placeholder the pipeline always
        // emitted in that configuration.
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let doc = format!("TCKN {tckn}.");
        let result = crate::pipeline::Pipeline::new(crate::pipeline::Tier::SafeHarbor)
            .deidentify(&doc)
            .expect("run");
        let report = Report::from_deid(&result);
        let row = report
            .rows()
            .iter()
            .find(|row| row.label == EntityLabel::Tckn)
            .expect("the TCKN reached the report");
        assert_eq!(row.method, Some(RedactionMethod::Mask));
        assert_eq!(row.layer, Some(Layer::Rules));
        assert!(row.checksum_validated);
        assert_eq!(row.replacement.as_deref(), Some("[TCKN]"));
        assert!(!report.text().contains(&tckn));
    }
}
