//! Dates -- numeric and Turkish month-name forms.
//!
//! LABEL CHOICE. FINDING a date and knowing WHAT IT IS TO THE PATIENT are two
//! different problems, and this module only solves the first. `12.03.2024` is
//! the same eight characters whether it is a birth date, an admission, a
//! discharge or a death; the answer lives in the words around it, and precise
//! role assignment over prose is L2/L4's job, not a regex's.
//!
//! WHY L1 MUST NOT GUESS A ROLE IT CANNOT SEE A CUE FOR. This module used to
//! label every date it found [`EntityLabel::DateBirth`], reasoning that
//! over-assigning the label with the strictest recall floor was the recall-safe
//! direction. It is the opposite. The eval matches a prediction to a gold span
//! only when the LABELS AGREE as well as the offsets, so a correctly-located
//! date carrying the wrong role scores twice: a MISS on the role it really has
//! and a FALSE POSITIVE on the role it was given. On the 178-document corpus
//! that turned 179 correctly-located dates into 358 errors -- `DATE_BIRTH` read
//! recall 1.0000 at precision 0.3285 while `DATE_ADMISSION` (155 gold) and
//! `DATE_DISCHARGE` (24 gold) read 0.0000, and nothing about the detector's
//! actual behaviour justified either number. Guessing is strictly worse than
//! declining, and it also hides the miss behind a label that looks healthy.
//!
//! So: where a cue is in reach the date gets the role the cue names, and where
//! none is the date gets [`EntityLabel::Date`], the role-less entry added to
//! `eval/schema.yaml` for exactly this. Nothing is masked less -- `DATE` is a
//! direct identifier like the other four -- and L2/L4 refine it later.
//!
//! CUE MATCHING IS NEAREST-WINS AND LINE-BOUNDED. A header block reads
//! `Yatış Tarihi: 28.01.2026` on one line and `Exitus Tarihi: 06.02.2026` on
//! the next, so a backward search that crossed the newline would lend the
//! admission cue to the death date. Both windows are bounded, both are clipped
//! to the current line, and the cue physically closest to the digits wins.
//! Looking FORWARD as well as back is not optional: Turkish puts the cue after
//! the date as often as before it (`30.11.1932 doğumlu`, `exitus 11.02.2026`).
//!
//! NO CHECKSUM EXISTS, but a date has something close to one: it can be
//! CALENDAR-INVALID. `31.02.2024` is rejected outright, which is the same
//! over-match-then-reject shape the checksummed modules use.

use std::sync::OnceLock;

use regex::Regex;

use crate::label::EntityLabel;
use crate::span::Span;

use super::{Doc, CHECKSUM_ABSENT};

/// Turkish month names in all three casings that occur in real notes.
///
/// WRITTEN OUT rather than matched with `(?i)`: Unicode simple case folding
/// does not relate dotless `ı` (U+0131) to ASCII `I`, so `(?i)Mayıs` does not
/// match `MAYIS` and `(?i)Kasım` does not match `KASIM`. Turkish casing is four
/// letters, not two, and a case-insensitive flag silently loses two of them.
const MONTHS: [(&str, &str, &str, u32); 12] = [
    ("Ocak", "OCAK", "ocak", 1),
    ("Şubat", "ŞUBAT", "şubat", 2),
    ("Mart", "MART", "mart", 3),
    ("Nisan", "NİSAN", "nisan", 4),
    ("Mayıs", "MAYIS", "mayıs", 5),
    ("Haziran", "HAZİRAN", "haziran", 6),
    ("Temmuz", "TEMMUZ", "temmuz", 7),
    ("Ağustos", "AĞUSTOS", "ağustos", 8),
    ("Eylül", "EYLÜL", "eylül", 9),
    ("Ekim", "EKİM", "ekim", 10),
    ("Kasım", "KASIM", "kasım", 11),
    ("Aralık", "ARALIK", "aralık", 12),
];

fn numeric() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    super::compiled(&CELL, r"\b([0-9]{1,2})[./-]([0-9]{1,2})[./-]([0-9]{4})\b")
}

fn iso() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    super::compiled(&CELL, r"\b([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})\b")
}

/// Built from [`MONTHS`] rather than written out a second time, so the name
/// table stays the single source of truth for both matching and month number.
fn named() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        let alternation = MONTHS
            .iter()
            .flat_map(|(title, upper, lower, _)| [*title, *upper, *lower])
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!(
            r"\b([0-9]{{1,2}})\s+({alternation})\s+([0-9]{{4}})\b"
        ))
        .ok()
    })
    .as_ref()
}

/// Test-only: proves the module's pattern actually compiled.
///
/// `#[cfg(test)]` rather than a lint allowance, because outside the test
/// build there is genuinely no caller -- `detect` reads the same `OnceLock`
/// directly and returns early rather than asking a question it cannot act on.
#[cfg(test)]
pub(super) fn pattern_ok() -> bool {
    numeric().is_some() && iso().is_some() && named().is_some()
}

pub(super) fn is_real_date(day: u32, month: u32, year: u32) -> bool {
    if !(1000..=9999).contains(&year) || day == 0 {
        return false;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return false,
    };
    day <= days_in_month
}

pub(super) fn detect(doc: &Doc<'_>, out: &mut Vec<Span>) {
    let text = doc.text();
    for (pattern, day_group, month_group, year_group) in [
        (numeric(), 1, 2, 3),
        // ISO puts the year first; the group indices are what stops the day and
        // the year being read into each other's validation.
        (iso(), 3, 2, 1),
    ] {
        let Some(pattern) = pattern else {
            continue;
        };
        for found in pattern.captures_iter(text) {
            let parts = [
                found.get(day_group),
                found.get(month_group),
                found.get(year_group),
            ];
            let Some([day, month, year]) = numbers(&parts) else {
                continue;
            };
            if !is_real_date(day, month, year) {
                continue;
            }
            push(doc, &found, out);
        }
    }

    let Some(named) = named() else {
        return;
    };
    for found in named.captures_iter(text) {
        let (Some(day), Some(name), Some(year)) = (found.get(1), found.get(2), found.get(3)) else {
            continue;
        };
        let (Ok(day), Ok(year)) = (day.as_str().parse::<u32>(), year.as_str().parse::<u32>())
        else {
            continue;
        };
        let Some(month) = MONTHS
            .iter()
            .find(|(title, upper, lower, _)| [*title, *upper, *lower].contains(&name.as_str()))
            .map(|(_, _, _, number)| *number)
        else {
            continue;
        };
        if !is_real_date(day, month, year) {
            continue;
        }
        push(doc, &found, out);
    }
}

/// Role cues, each written out in the casings that occur in real notes.
///
/// SAME REASON AS [`MONTHS`]: `(?i)` cannot be trusted here. Turkish uppercases
/// `ı` to ASCII `I` and `i` to dotted `İ`, and Unicode simple case folding
/// relates neither pair, so `(?i)yatış` misses `YATIŞ` and `(?i)çıkış` misses
/// `ÇIKIŞ`. The ASCII-drift spellings (`dogum`, `yatis`, `cikis`) are listed
/// beside the diacritic ones because a hospital export that stripped diacritics
/// is a note we still have to read.
///
/// STEMS, NOT WORDS. `doğum` covers `Doğum Tarihi`, `doğumu` and `doğumlu`;
/// `taburcu` covers `Taburculuk` and `Taburcu`. Turkish is agglutinative, so
/// matching a whole inflected form is a guarantee of missing the other seven.
const ROLE_CUES: [(EntityLabel, &[&str]); 4] = [
    (
        EntityLabel::DateBirth,
        &["Doğum", "DOĞUM", "doğum", "Dogum", "DOGUM", "dogum"],
    ),
    (
        EntityLabel::DateDeath,
        &[
            "Exitus", "EXITUS", "exitus", "Ölüm", "ÖLÜM", "ölüm", "Olum", "OLUM", "olum", "Vefat",
            "VEFAT", "vefat",
        ],
    ),
    (
        EntityLabel::DateDischarge,
        &[
            "Taburcu",
            "TABURCU",
            "taburcu",
            "Çıkış",
            "ÇIKIŞ",
            "çıkış",
            "Cikis",
            "CIKIS",
            "cikis",
        ],
    ),
    (
        EntityLabel::DateAdmission,
        // Every cue naming an ENCOUNTER: the day the patient was in front of
        // the service. Admission proper (`Yatış`, `Kabul`), the presentation
        // (`Başvuru`, `Geliş`), and the scheduled contacts a Turkish note dates
        // the same way (`Tetkik`, `Muayene`, `Kontrol`, `Konsey`, `Randevu`).
        &[
            "Yatış", "YATIŞ", "yatış", "Yatis", "YATIS", "yatis", "Kabul", "KABUL", "kabul",
            "Başvuru", "BAŞVURU", "başvuru", "Basvuru", "basvuru", "Geliş", "GELİŞ", "geliş",
            "Gelis", "gelis", "Tetkik", "TETKİK", "tetkik", "Muayene", "MUAYENE", "muayene",
            "Kontrol", "KONTROL", "kontrol", "Konsey", "KONSEY", "konsey", "Randevu", "RANDEVU",
            "randevu",
        ],
    ),
];

/// How far a cue may sit from the digits and still name their role.
///
/// Asymmetric on purpose. A field label precedes its value at arm's length
/// (`Planlanan Taburculuk Tarihi: `), while a trailing cue is a suffix on the
/// date itself (`1932 doğumlu`) and sits right against it. Widening the
/// forward window would start pulling in the cue belonging to the NEXT field.
const REACH_BEFORE: usize = 44;
const REACH_AFTER: usize = 18;

/// Clip a byte range to the current line and to a character boundary.
fn window(text: &str, from: usize, to: usize, stop_at_newline_before: bool) -> &str {
    let mut from = from;
    while from < to && !text.is_char_boundary(from) {
        from += 1;
    }
    let mut to = to.min(text.len());
    while to > from && !text.is_char_boundary(to) {
        to -= 1;
    }
    let slice = text.get(from..to).unwrap_or("");
    if stop_at_newline_before {
        slice.rfind('\n').map_or(slice, |at| &slice[at + 1..])
    } else {
        slice.split('\n').next().unwrap_or(slice)
    }
}

/// True when `at` begins a word rather than landing inside one.
///
/// ONLY THE LEADING EDGE IS CHECKED, and the asymmetry is Turkish: the cues are
/// stems and the language agglutinates, so `doğum` legitimately continues into
/// `doğumlu` and `taburcu` into `taburculuk`. Requiring a trailing boundary
/// would reject every inflected form, which is most of them. Requiring the
/// LEADING one costs nothing and is what stops `ölüm` from matching inside
/// `bölümümüzce` ("by our department") and labelling a routine imaging date a
/// death.
fn starts_a_word(text: &str, at: usize) -> bool {
    text.get(..at)
        .and_then(|head| head.chars().next_back())
        .is_none_or(|ch| !ch.is_alphanumeric())
}

/// Bytes from the end of the nearest preceding cue to the date, if any.
fn distance_before(window: &str, cue: &str) -> Option<usize> {
    window
        .match_indices(cue)
        .filter(|(at, _)| starts_a_word(window, *at))
        .map(|(at, _)| window.len() - (at + cue.len()))
        .min()
}

/// Bytes from the date to the start of the nearest following cue, if any.
///
/// Offset by one so a cue touching the date scores 1 rather than 0; a preceding
/// cue that ends flush against the date scores 0 and therefore wins the tie,
/// which is right, because a Turkish field label is the strongest cue there is.
fn distance_after(window: &str, cue: &str) -> Option<usize> {
    window
        .match_indices(cue)
        .filter(|(at, _)| starts_a_word(window, *at))
        .map(|(at, _)| at + 1)
        .min()
}

/// The role named by the cue physically closest to the date, if any.
///
/// Distance is measured between NEAREST EDGES -- the end of a preceding cue,
/// the start of a following one -- not between the cue's start and the date.
/// Measuring from the start makes a long cue look far away, and in
/// `Yatış 15.09.2026, taburculuk 22.09.2026` that handed the admission date to
/// the discharge cue five characters behind it.
fn role(text: &str, start: usize, end: usize) -> EntityLabel {
    let before = window(text, start.saturating_sub(REACH_BEFORE), start, true);
    let after = window(text, end, end + REACH_AFTER, false);
    let mut best: Option<(usize, EntityLabel)> = None;
    for (label, cues) in ROLE_CUES {
        for cue in cues {
            let Some(distance) = distance_before(before, cue)
                .into_iter()
                .chain(distance_after(after, cue))
                .min()
            else {
                continue;
            };
            if best.is_none_or(|(closest, _)| distance < closest) {
                best = Some((distance, label));
            }
        }
    }
    best.map_or(EntityLabel::Date, |(_, label)| label)
}

fn numbers(parts: &[Option<regex::Match<'_>>; 3]) -> Option<[u32; 3]> {
    let mut values = [0u32; 3];
    for (slot, part) in values.iter_mut().zip(parts) {
        *slot = part.as_ref()?.as_str().parse().ok()?;
    }
    Some(values)
}

fn push(doc: &Doc<'_>, found: &regex::Captures<'_>, out: &mut Vec<Span>) {
    let Some(whole) = found.get(0) else {
        return;
    };
    let label = role(doc.text(), whole.start(), whole.end());
    out.extend(doc.emit(whole.start(), whole.end(), label, CHECKSUM_ABSENT));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    /// Every span this module could have produced, under ANY role.
    ///
    /// Filtering on one role would make a location test silently double as a
    /// role test, which is how "the date was found" and "the date was labelled
    /// DATE_BIRTH" became the same assertion in the first place.
    fn date_spans(doc: &str) -> Vec<Span> {
        RuleSet
            .detect(doc)
            .into_iter()
            .filter(|s| {
                matches!(
                    s.label(),
                    EntityLabel::Date
                        | EntityLabel::DateBirth
                        | EntityLabel::DateAdmission
                        | EntityLabel::DateDischarge
                        | EntityLabel::DateDeath
                )
            })
            .collect()
    }

    #[test]
    fn the_calendar_accepts_real_dates_and_rejects_impossible_ones() {
        for (day, month, year) in [(1, 1, 1900), (31, 12, 2024), (29, 2, 2024), (28, 2, 2023)] {
            assert!(is_real_date(day, month, year), "{day}.{month}.{year}");
        }
        for (day, month, year) in [
            (31, 2, 2024),  // February never has 31 days
            (29, 2, 2023),  // 2023 is not a leap year
            (29, 2, 1900),  // divisible by 100, not by 400
            (31, 4, 2024),  // April has 30
            (0, 5, 2024),   // day zero
            (12, 13, 2024), // month thirteen
            (12, 0, 2024),  // month zero
        ] {
            assert!(!is_real_date(day, month, year), "{day}.{month}.{year}");
        }
        assert!(is_real_date(29, 2, 2000), "2000 is divisible by 400");
    }

    #[test]
    fn every_numeric_separator_form_is_matched() {
        for surface in ["12.03.2024", "12/03/2024", "12-03-2024", "2024-03-12"] {
            let doc = format!("Tarih {surface} olarak kayitli.");
            let spans = date_spans(&doc);
            assert_eq!(spans.len(), 1, "{surface} was not matched");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], surface);
            assert!(!spans[0].is_checksum_validated());
            assert!((spans[0].confidence() - CHECKSUM_ABSENT).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn turkish_month_names_are_matched_in_all_three_casings() {
        for (title, upper, lower, _) in MONTHS {
            for name in [title, upper, lower] {
                let doc = format!("12 {name} 2024 tarihinde.");
                let spans = date_spans(&doc);
                assert_eq!(spans.len(), 1, "{name} was not matched");
                assert_eq!(
                    &doc[spans[0].start()..spans[0].end()],
                    format!("12 {name} 2024")
                );
            }
        }
    }

    #[test]
    fn the_dotless_i_month_names_survive_uppercasing() {
        // The specific İ/ı trap: `MAYIS` and `KASIM` uppercase to ASCII `I`,
        // while `NİSAN` and `EKİM` uppercase to dotted `İ`. A `(?i)` flag over
        // the title-case forms catches neither pair.
        for doc in [
            "12 MAYIS 2024",
            "12 KASIM 2024",
            "12 NİSAN 2024",
            "12 EKİM 2024",
            "12 ARALIK 2024",
        ] {
            assert_eq!(date_spans(doc).len(), 1, "{doc}");
        }
    }

    #[test]
    fn a_trailing_weekday_does_not_break_the_match() {
        let doc = "12 Mart 2024 Salı günü başvurdu.";
        let spans = date_spans(doc);
        assert_eq!(spans.len(), 1);
        assert_eq!(&doc[spans[0].start()..spans[0].end()], "12 Mart 2024");
    }

    #[test]
    fn a_suffixed_date_keeps_its_bounds() {
        for (doc, expected) in [
            ("14 Kasım 2025'te başvurdu", "14 Kasım 2025"),
            ("04.11.2025'te yatırıldı", "04.11.2025"),
        ] {
            let spans = date_spans(doc);
            assert_eq!(spans.len(), 1, "{doc}");
            assert_eq!(&doc[spans[0].start()..spans[0].end()], expected);
        }
    }

    #[test]
    fn calendar_impossible_surface_forms_are_not_emitted() {
        for doc in [
            "31.02.2024 tarihli",
            "29.02.2023 tarihli",
            "32.01.2024 tarihli",
            "12.13.2024 tarihli",
            "2024-02-31 tarihli",
            "31 Şubat 2024 tarihli",
        ] {
            assert!(date_spans(doc).is_empty(), "{doc} is not a real date");
        }
    }

    #[test]
    fn a_protocol_number_is_not_a_date() {
        // `2026-0004312` has the right punctuation and the wrong field widths.
        assert!(date_spans("Protokol No: 2026-0004312").is_empty());
    }

    #[test]
    fn a_cue_in_reach_names_the_role_and_its_absence_declines_to() {
        for (doc, expected) in [
            ("Doğum Tarihi: 12.03.1968", EntityLabel::DateBirth),
            ("12.03.1968 doğumlu hasta", EntityLabel::DateBirth),
            ("DOGUM TARIHI: 12.03.1968", EntityLabel::DateBirth),
            ("Yatış Tarihi: 03.02.2026", EntityLabel::DateAdmission),
            ("Başvuru Tarihi: 03.02.2026", EntityLabel::DateAdmission),
            ("Kabul Tarihi: 03.02.2026", EntityLabel::DateAdmission),
            ("Çıkış Tarihi: 09.02.2026", EntityLabel::DateDischarge),
            ("Taburculuk Tarihi: 09.02.2026", EntityLabel::DateDischarge),
            ("Exitus Tarihi: 06.02.2026", EntityLabel::DateDeath),
            (
                "exitus 11.02.2026 olarak kaydedildi",
                EntityLabel::DateDeath,
            ),
            // NO CUE. The date is still found and still masked; only the role
            // is withheld, because guessing one converts a found date into two
            // errors.
            (
                "Onceki grafi 04.05.2026 ile karsilastirildi",
                EntityLabel::Date,
            ),
            ("Rapor 12 Mart 2024 tarihlidir", EntityLabel::Date),
        ] {
            let spans = date_spans(doc);
            assert_eq!(spans.len(), 1, "{doc}");
            assert_eq!(spans[0].label(), expected, "{doc}");
        }
    }

    #[test]
    fn the_nearest_cue_wins_and_a_cue_does_not_cross_a_line() {
        // The exact failure a backward-only, unbounded search produces: in a
        // header block the admission cue one line up would claim the death
        // date, and the discharge date would inherit the admission label.
        let doc = "Yatış Tarihi: 28.01.2026\nExitus Tarihi: 06.02.2026\nÇıkış Tarihi: 09.02.2026";
        let spans = date_spans(doc);
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].label(), EntityLabel::DateAdmission);
        assert_eq!(spans[1].label(), EntityLabel::DateDeath);
        assert_eq!(spans[2].label(), EntityLabel::DateDischarge);
    }

    #[test]
    fn a_date_offset_lands_on_a_char_boundary_after_turkish_text() {
        let doc = "Şükrü Gökçe'nin doğum tarihi 12 Ağustos 1968 olarak kayıtlı.";
        let spans = date_spans(doc);
        assert_eq!(spans.len(), 1);
        assert_eq!(&doc[spans[0].start()..spans[0].end()], "12 Ağustos 1968");
    }
}
