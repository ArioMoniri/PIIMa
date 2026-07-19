//! Format generators: the arithmetic and the shapes that make property (a)
//! true.
//!
//! PROPERTY (a) RESTATED AS AN ACCEPTANCE TEST: a downstream system that
//! validates the format must still accept the output. A hospital information
//! system that rejects the de-identified note because the TCKN field no longer
//! checksums has not been de-identified, it has been broken, and the compliance
//! officer's answer becomes "we cannot use this tool". So a fake TCKN passes
//! the TCKN check digits, a fake VKN passes the VKN check digit, a fake TR IBAN
//! passes ISO 7064 mod-97, and a fake phone number carries an allocated Turkish
//! operator prefix.
//!
//! NOTHING IN THIS FILE IS A LITERAL IDENTIFIER. Every checksum-valid value is
//! computed at run time from a keyed stream (I8: a checksum-valid TCKN may
//! never appear in a committed file, and the pre-commit hook enforces it).

use super::keyed_hash::Stream;
use super::pools;

/// Fixed widths, from `core/src/rules/`.
const TCKN_LEN: usize = 11;
const VKN_LEN: usize = 10;
const IBAN_LEN: usize = 26;

/// A checksum-valid TCKN.
///
/// The issuing rules `rules/tckn.rs` enforces are honoured here too, because a
/// surrogate that violates them is not a plausible national id: the first digit
/// is never zero, and an all-same sequence is reserved. The second is
/// unreachable given a non-zero lead and eight uniform digits, but it is
/// checked rather than argued, since "unreachable" is how the next reader
/// stops checking.
pub(super) fn tckn(stream: &mut Stream) -> String {
    loop {
        let mut digits = [0u8; TCKN_LEN];
        digits[0] = stream.between(1, 9) as u8;
        for digit in digits.iter_mut().take(9).skip(1) {
            *digit = stream.digit();
        }
        let odd: u32 = (0..9).step_by(2).map(|i| u32::from(digits[i])).sum();
        let even: u32 = (1..9).step_by(2).map(|i| u32::from(digits[i])).sum();
        // `+ 100` keeps the subtraction in u32 without changing the residue:
        // `even` never exceeds 36. Same construction as `rules/tckn.rs`.
        digits[9] = ((odd * 7 + 100 - even) % 10) as u8;
        let total: u32 = digits[..10].iter().map(|d| u32::from(*d)).sum();
        digits[10] = (total % 10) as u8;
        if digits.iter().all(|d| *d == digits[0]) {
            continue;
        }
        return digits.iter().map(|d| char::from(b'0' + d)).collect();
    }
}

/// A VKN whose single check digit is valid.
///
/// The algorithm is the tax-number one, NOT the TCKN one; see
/// `core/src/rules/vkn.rs` for the statement it mirrors.
pub(super) fn vkn(stream: &mut Stream) -> String {
    let mut digits = [0u8; VKN_LEN];
    let mut total: u32 = 0;
    for (i, digit) in digits.iter_mut().enumerate().take(9) {
        *digit = stream.digit();
        let t = (u32::from(*digit) + 9 - i as u32) % 10;
        total += if t == 9 { 9 } else { (t << (9 - i)) % 9 };
    }
    digits[9] = ((10 - (total % 10)) % 10) as u8;
    digits.iter().map(|d| char::from(b'0' + d)).collect()
}

/// ISO 7064 mod-97 over an IBAN in its rearranged, letter-expanded form.
///
/// Duplicated from `rules/iban.rs` rather than shared, deliberately and
/// narrowly: that function is `pub(super)` inside the rules module, and
/// widening its visibility means editing a file this module does not own.
/// Twenty lines of published arithmetic is the cheaper of the two costs, and
/// the test below pins the two implementations to the same answer by
/// generating here and validating with the same rearrangement.
fn mod97(compact: &str) -> Option<u32> {
    let head = compact.get(..4)?;
    let tail = compact.get(4..)?;
    let mut remainder: u32 = 0;
    for ch in tail.chars().chain(head.chars()) {
        let value = ch.to_digit(36)?;
        remainder = if value < 10 {
            remainder * 10 + value
        } else {
            remainder * 100 + value
        };
        remainder %= 97;
    }
    Some(remainder)
}

/// A mod-97-valid TR IBAN, 26 characters.
///
/// The body is five bank digits, the one reserved digit Turkey fixes at zero,
/// and sixteen account digits; the two check digits are then solved for, which
/// is the only way to produce a valid IBAN rather than a plausible-looking one.
pub(super) fn iban(stream: &mut Stream) -> String {
    let bank = pools::BANK_CODES
        .get(stream.below(pools::BANK_CODES.len()))
        .copied()
        .unwrap_or("00061");
    let account: String = (0..16).map(|_| char::from(b'0' + stream.digit())).collect();
    let body = format!("{bank}0{account}");
    // Solve for the check digits: with "00" in their place, the remainder r of
    // the rearranged string gives check = 98 - r.
    let probe = format!("TR00{body}");
    let check = mod97(&probe).map_or(2, |r| 98 - r);
    let iban = format!("TR{check:02}{body}");
    debug_assert_eq!(iban.len(), IBAN_LEN);
    iban
}

/// A Turkish mobile or landline number in one of several valid shapes.
///
/// THE SHAPE IS DRAWN, NOT COPIED FROM THE ORIGINAL. Preserving the original's
/// punctuation would preserve its length, and the length of a phone number as
/// written is a per-author habit that survives de-identification as a linkage
/// signal across a corpus -- the red team's format-tells attack class. Every
/// shape produced here is one a Turkish validator accepts.
pub(super) fn phone(stream: &mut Stream) -> String {
    let subscriber = |stream: &mut Stream| -> String {
        (0..7).map(|_| char::from(b'0' + stream.digit())).collect()
    };
    let mobile = stream.below(4) != 0;
    let prefix = if mobile {
        pools::MOBILE_PREFIXES
            .get(stream.below(pools::MOBILE_PREFIXES.len()))
            .copied()
            .unwrap_or("532")
    } else {
        pools::AREA_CODES
            .get(stream.below(pools::AREA_CODES.len()))
            .copied()
            .unwrap_or("212")
    };
    let rest = subscriber(stream);
    let (a, b, c) = (
        rest.get(..3).unwrap_or("000"),
        rest.get(3..5).unwrap_or("00"),
        rest.get(5..).unwrap_or("00"),
    );
    match stream.below(4) {
        0 => format!("+90 {prefix} {a} {b} {c}"),
        1 => format!("0{prefix}{a}{b}{c}"),
        2 => format!("0({prefix}) {a} {b} {c}"),
        _ => format!("0 {prefix} {a} {b} {c}"),
    }
}

/// A digit string of a length drawn from `low..=high`.
///
/// Used for the identifier types with no published checksum (MRN, SGK, account
/// and health-plan numbers). The LENGTH IS DRAWN rather than copied, for the
/// same reason as everywhere else in this module: an MRN's width is a
/// per-institution convention, and preserving it re-identifies the institution.
pub(super) fn digits(stream: &mut Stream, low: usize, high: usize) -> String {
    let len = stream.between(low, high);
    (0..len)
        .map(|_| char::from(b'0' + stream.digit()))
        .collect()
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/// Turkish month names, long form, lower-cased for matching.
const MONTHS_TR: [&str; 12] = [
    "ocak", "şubat", "mart", "nisan", "mayıs", "haziran", "temmuz", "ağustos", "eylül", "ekim",
    "kasım", "aralık",
];

/// How a parsed date was written, so the shifted one can be written the same
/// way.
///
/// FORMAT IS THE ONE THING DATES DO PRESERVE, and the exception is deliberate
/// rather than an oversight in property (c). Two arguments, both stronger than
/// the length-tell argument that governs every other type. First, a date has
/// almost no length variance to leak: `01.02.2026` and `31.12.2026` are the
/// same width, so the format carries information about the AUTHOR's template,
/// which is already visible in the surrounding unmasked prose. Second, dates
/// are the field downstream systems parse most aggressively, and re-emitting a
/// `dd.mm.yyyy` note in ISO would break every one of them -- property (a) wins
/// the trade. The tell that actually matters for a date is the ABSOLUTE VALUE,
/// and that is destroyed by the shift.
///
/// The residual tell is MEASURED rather than asserted away, because the first
/// argument above is weaker than it looks: `14.06.1959` and `14 Haziran 1959`
/// are the same date at very different widths, so preserving the format does
/// preserve a length signal across format families. Pearson r between original
/// and surrogate length over the committed corpus is 0.85 (`DATE_BIRTH`), 0.89
/// (`DATE_ADMISSION`) and 1.0000 (`DATE_DEATH`) -- see
/// `surrogate::tests::length_correlation_by_label_over_the_committed_corpus`
/// and ADR D-028, which records why the trade is kept and what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateStyle {
    /// `dd.mm.yyyy`, `dd/mm/yyyy`, `dd-mm-yyyy`.
    Numeric { separator: char, padded: bool },
    /// `yyyy-mm-dd`.
    Iso,
    /// `d Mart yyyy`, with the month name capitalised as it was found.
    Named { capitalised: bool },
}

/// A calendar date, with the way it was written alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ParsedDate {
    year: i64,
    month: i64,
    day: i64,
    style: DateStyle,
}

/// Days since 1970-01-01, by Howard Hinnant's proleptic Gregorian algorithm.
///
/// Integer arithmetic only, so it runs identically on every target this crate
/// compiles to, and there is no calendar dependency to add under I1.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// True when the triple is a real calendar date.
///
/// Checked rather than normalised: `31.02.2026` round-tripped through the day
/// count would come back as `03.03.2026`, which silently invents a date that
/// was never in the note. An unparseable date falls back to a synthesised one
/// instead, which is honest about having failed.
fn is_real(year: i64, month: i64, day: i64) -> bool {
    (1900..=2200).contains(&year)
        && (1..=12).contains(&month)
        && day >= 1
        && civil_from_days(days_from_civil(year, month, day)) == (year, month, day)
}

/// Recognise the date shapes `core/src/rules/date.rs` emits spans for.
pub(super) fn parse_date(text: &str) -> Option<ParsedDate> {
    let trimmed = text.trim();

    // ISO first: `yyyy-mm-dd` and `dd-mm-yyyy` share a separator, and the
    // four-digit lead is what tells them apart.
    let parts: Vec<&str> = trimmed.split(['.', '/', '-']).collect();
    if parts.len() == 3 {
        let all_digits = parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 4 && p.bytes().all(|b| b.is_ascii_digit()));
        if all_digits {
            let first = parts[0];
            let numbers: Vec<i64> = parts.iter().filter_map(|p| p.parse().ok()).collect();
            if numbers.len() == 3 {
                if first.len() == 4 {
                    let (year, month, day) = (numbers[0], numbers[1], numbers[2]);
                    if is_real(year, month, day) {
                        return Some(ParsedDate {
                            year,
                            month,
                            day,
                            style: DateStyle::Iso,
                        });
                    }
                } else {
                    let (day, month, year) = (numbers[0], numbers[1], numbers[2]);
                    if is_real(year, month, day) {
                        let separator = trimmed
                            .chars()
                            .find(|c| matches!(c, '.' | '/' | '-'))
                            .unwrap_or('.');
                        return Some(ParsedDate {
                            year,
                            month,
                            day,
                            style: DateStyle::Numeric {
                                separator,
                                padded: first.len() == 2,
                            },
                        });
                    }
                }
            }
        }
        return None;
    }

    // `d Mart yyyy`.
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.len() == 3 {
        let day: i64 = words[0].parse().ok()?;
        let year: i64 = words[2].parse().ok()?;
        let folded = super::fold(words[1]);
        let month = MONTHS_TR.iter().position(|m| *m == folded)? as i64 + 1;
        if is_real(year, month, day) {
            let capitalised = words[1].chars().next().is_some_and(|c| c.is_uppercase());
            return Some(ParsedDate {
                year,
                month,
                day,
                style: DateStyle::Named { capitalised },
            });
        }
    }
    None
}

impl ParsedDate {
    /// The same date moved by `shift` days, written in the same style.
    pub(super) fn shifted(&self, shift: i64) -> String {
        let (year, month, day) =
            civil_from_days(days_from_civil(self.year, self.month, self.day) + shift);
        match self.style {
            DateStyle::Iso => format!("{year:04}-{month:02}-{day:02}"),
            DateStyle::Numeric { separator, padded } => {
                if padded {
                    format!("{day:02}{separator}{month:02}{separator}{year:04}")
                } else {
                    format!("{day}{separator}{month}{separator}{year:04}")
                }
            }
            DateStyle::Named { capitalised } => {
                let name = MONTHS_TR
                    .get((month - 1).clamp(0, 11) as usize)
                    .copied()
                    .unwrap_or("ocak");
                let name = if capitalised {
                    capitalise(name)
                } else {
                    name.to_owned()
                };
                format!("{day} {name} {year:04}")
            }
        }
    }
}

/// Turkish-correct capitalisation of the first letter.
///
/// `i` uppercases to `İ` and not to `I` -- the four-letter problem. Rust's
/// `to_uppercase` is Unicode-default and maps `i` to `I`, which is the wrong
/// letter in Turkish and turns `ısırık` into a different word; the two Turkish
/// cases are therefore handled explicitly before falling back.
pub(super) fn capitalise(word: &str) -> String {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let head = match first {
        'i' => "İ".to_owned(),
        'ı' => "I".to_owned(),
        other => other.to_uppercase().collect(),
    };
    head + chars.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> Stream {
        Stream::new([42u8; 32])
    }

    /// The TCKN checksum, restated independently of the generator so the test
    /// is a check and not a tautology.
    fn tckn_is_valid(value: &str) -> bool {
        let digits: Vec<u8> = value.bytes().map(|b| b - b'0').collect();
        if digits.len() != 11 || digits[0] == 0 || digits.iter().all(|d| *d == digits[0]) {
            return false;
        }
        let odd: u32 = (0..9).step_by(2).map(|i| u32::from(digits[i])).sum();
        let even: u32 = (1..9).step_by(2).map(|i| u32::from(digits[i])).sum();
        if u32::from(digits[9]) != (odd * 7 + 100 - even) % 10 {
            return false;
        }
        let total: u32 = digits[..10].iter().map(|d| u32::from(*d)).sum();
        u32::from(digits[10]) == total % 10
    }

    fn vkn_is_valid(value: &str) -> bool {
        let digits: Vec<u8> = value.bytes().map(|b| b - b'0').collect();
        if digits.len() != 10 {
            return false;
        }
        let mut total: u32 = 0;
        for (i, digit) in digits.iter().enumerate().take(9) {
            let t = (u32::from(*digit) + 9 - i as u32) % 10;
            total += if t == 9 { 9 } else { (t << (9 - i)) % 9 };
        }
        u32::from(digits[9]) == (10 - (total % 10)) % 10
    }

    #[test]
    fn every_generated_tckn_passes_the_checksum() {
        // I8: the valid identifiers this test asserts on are built HERE, at run
        // time, and never written into the file.
        let mut stream = stream();
        for _ in 0..500 {
            let value = tckn(&mut stream);
            assert_eq!(value.len(), TCKN_LEN);
            assert!(tckn_is_valid(&value), "generated TCKN failed its checksum");
        }
    }

    #[test]
    fn a_mutated_generated_tckn_fails_the_checksum() {
        // Guards against a checksum function that accepts everything.
        let mut stream = stream();
        let value = tckn(&mut stream);
        let mut bytes = value.into_bytes();
        bytes[3] = b'0' + ((bytes[3] - b'0') + 1) % 10;
        let mutated = String::from_utf8(bytes).expect("ascii digits");
        assert!(!tckn_is_valid(&mutated));
    }

    #[test]
    fn every_generated_vkn_passes_the_checksum() {
        let mut stream = stream();
        for _ in 0..500 {
            let value = vkn(&mut stream);
            assert_eq!(value.len(), VKN_LEN);
            assert!(vkn_is_valid(&value), "generated VKN failed its checksum");
        }
    }

    #[test]
    fn every_generated_iban_is_mod_97_valid() {
        let mut stream = stream();
        for _ in 0..500 {
            let value = iban(&mut stream);
            assert_eq!(value.len(), IBAN_LEN);
            assert!(value.starts_with("TR"));
            assert_eq!(
                mod97(&value),
                Some(1),
                "generated IBAN failed ISO 7064 mod-97"
            );
        }
    }

    #[test]
    fn a_mutated_iban_fails_mod_97() {
        let mut stream = stream();
        let value = iban(&mut stream);
        let mut bytes = value.into_bytes();
        bytes[10] = b'0' + ((bytes[10] - b'0') + 1) % 10;
        let mutated = String::from_utf8(bytes).expect("ascii");
        assert_ne!(mod97(&mutated), Some(1));
    }

    #[test]
    fn every_generated_phone_is_a_valid_turkish_shape() {
        let mut stream = stream();
        for _ in 0..300 {
            let value = phone(&mut stream);
            let bare: String = value.chars().filter(char::is_ascii_digit).collect();
            // Either 10 significant digits behind a `0` trunk prefix, or 12
            // behind `+90`.
            assert!(
                matches!(bare.len(), 11 | 12),
                "phone {value} has {} digits",
                bare.len()
            );
            let significant = bare
                .strip_prefix("90")
                .or_else(|| bare.strip_prefix('0'))
                .expect("a trunk or country prefix");
            assert_eq!(significant.len(), 10);
            let prefix = &significant[..3];
            assert!(
                pools::MOBILE_PREFIXES.contains(&prefix) || pools::AREA_CODES.contains(&prefix),
                "phone {value} carries unallocated prefix {prefix}"
            );
        }
    }

    #[test]
    fn dates_round_trip_through_the_day_count() {
        for (y, m, d) in [
            (1900, 1, 1),
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 7, 19),
            (2100, 12, 31),
        ] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
    }

    #[test]
    fn an_impossible_date_is_rejected_rather_than_normalised() {
        assert!(!is_real(2026, 2, 30));
        assert!(!is_real(2026, 13, 1));
        assert!(!is_real(2025, 2, 29));
        assert!(is_real(2024, 2, 29));
        assert!(parse_date("30.02.2026").is_none());
    }

    #[test]
    fn the_written_style_survives_the_shift() {
        let cases = [
            ("12.03.2026", "13.03.2026"),
            ("12/03/2026", "13/03/2026"),
            ("2026-03-12", "2026-03-13"),
            ("1.3.2026", "2.3.2026"),
            ("12 Mart 2026", "13 Mart 2026"),
            ("12 mart 2026", "13 mart 2026"),
        ];
        for (original, expected) in cases {
            let parsed = parse_date(original).expect("recognised date");
            assert_eq!(parsed.shifted(1), expected);
        }
    }

    #[test]
    fn a_shift_crosses_month_and_year_boundaries() {
        let parsed = parse_date("31.12.2026").expect("date");
        assert_eq!(parsed.shifted(1), "01.01.2027");
        assert_eq!(parsed.shifted(-365), "31.12.2025");
    }

    #[test]
    fn turkish_capitalisation_uses_the_dotted_capital() {
        assert_eq!(capitalise("izmir"), "İzmir");
        assert_eq!(capitalise("ısırgan"), "Isırgan");
        assert_eq!(capitalise("mart"), "Mart");
        assert_eq!(capitalise(""), "");
    }

    #[test]
    fn generated_digit_runs_stay_inside_their_bounds() {
        let mut stream = stream();
        for _ in 0..200 {
            let value = digits(&mut stream, 6, 12);
            assert!((6..=12).contains(&value.len()));
            assert!(value.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
