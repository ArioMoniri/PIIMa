//! CSV: de-identify selected fields, preserve the record structure.
//!
//! RFC 4180 with the two concessions every real exporter needs: the delimiter
//! may be `;` (which is what a Turkish-locale Excel writes, because `,` is the
//! decimal separator) and the line terminator is preserved per record rather
//! than normalised.
//!
//! # Structure preservation is a correctness requirement, not a nicety
//!
//! A de-identified CSV is usually going somewhere that will parse it again. If
//! masking changes the field count of one row -- by emitting an unquoted
//! surrogate that contains the delimiter, say -- that row silently shifts every
//! column after it, and a column shift in a clinical export is a wrong value
//! attached to a patient. So: field count is asserted to be preserved, and any
//! field whose masked value contains the delimiter, a quote or a newline is
//! quoted on the way out whether or not it was quoted on the way in.
//!
//! # Field selection
//!
//! The default is EVERY field. Selecting a subset is an opt-in, and it is a
//! recall decision the caller is making: an unselected field is not scanned, so
//! an identifier in it survives (I2 -- this module will not make that choice on
//! a caller's behalf).
//!
//! HONEST SCOPE: only rule-detectable identifiers are removed. See
//! [`crate::Report::rule_detectable_only`].

use crate::masker::{Masked, Masker};

/// Which fields to scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Fields {
    /// Every field of every record. The default, because it is the only
    /// setting that cannot miss an identifier through a configuration mistake.
    #[default]
    All,
    /// Only the named columns, matched against the header row.
    Named(Vec<String>),
}

/// A CSV that could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CsvError {
    /// A quoted field was never closed.
    #[error("a quoted field starting at byte {offset} was never closed")]
    UnclosedQuote {
        /// Byte offset of the opening quote.
        offset: usize,
    },
    /// A named column was requested that the header does not have.
    ///
    /// LOUD RATHER THAN IGNORED: a typo in a column name would otherwise mean
    /// the column is silently never scanned, which is a missed identifier
    /// dressed up as a successful run.
    #[error("the requested column is not in the header row")]
    UnknownColumn,
    /// [`Fields::Named`] was used on a file with no header row.
    #[error("selecting columns by name needs a header row")]
    NoHeader,
}

/// One parsed field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    value: String,
    quoted: bool,
}

/// One parsed record: its fields and the exact terminator that followed it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    fields: Vec<Field>,
    /// `"\r\n"`, `"\n"`, `"\r"`, or `""` for the last record of a file with no
    /// trailing newline. Stored verbatim so the output is byte-identical
    /// wherever nothing was masked.
    terminator: String,
}

/// Guess the delimiter from the first line.
///
/// Counts occurrences OUTSIDE quotes of `,` and `;` and takes the winner, with
/// `,` breaking a tie. A one-column file has neither and gets `,`, which is
/// correct because there is nothing to separate.
#[must_use]
pub fn detect_delimiter(text: &str) -> char {
    let first_line = text.split('\n').next().unwrap_or_default();
    let (mut commas, mut semicolons, mut in_quotes) = (0usize, 0usize, false);
    for value in first_line.chars() {
        match value {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => commas += 1,
            ';' if !in_quotes => semicolons += 1,
            _ => {}
        }
    }
    if semicolons > commas {
        ';'
    } else {
        ','
    }
}

fn parse(text: &str, delimiter: char) -> Result<Vec<Record>, CsvError> {
    let mut records = Vec::new();
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = text.char_indices().peekable();

    while let Some((offset, value)) = chars.next() {
        if value == '"' && current.is_empty() && !quoted {
            quoted = true;
            loop {
                let Some((_, inner)) = chars.next() else {
                    return Err(CsvError::UnclosedQuote { offset });
                };
                if inner != '"' {
                    current.push(inner);
                    continue;
                }
                // `""` inside a quoted field is one literal quote.
                if chars.peek().map(|(_, next)| *next) == Some('"') {
                    chars.next();
                    current.push('"');
                    continue;
                }
                break;
            }
            continue;
        }
        if value == delimiter {
            fields.push(Field {
                value: core::mem::take(&mut current),
                quoted: core::mem::take(&mut quoted),
            });
            continue;
        }
        if value == '\r' || value == '\n' {
            let mut terminator = String::from(value);
            if value == '\r' && chars.peek().map(|(_, next)| *next) == Some('\n') {
                chars.next();
                terminator.push('\n');
            }
            fields.push(Field {
                value: core::mem::take(&mut current),
                quoted: core::mem::take(&mut quoted),
            });
            records.push(Record {
                fields: core::mem::take(&mut fields),
                terminator,
            });
            continue;
        }
        current.push(value);
    }
    if !current.is_empty() || quoted || !fields.is_empty() {
        fields.push(Field {
            value: current,
            quoted,
        });
        records.push(Record {
            fields,
            terminator: String::new(),
        });
    }
    Ok(records)
}

fn serialise(records: &[Record], delimiter: char) -> String {
    let mut out = String::new();
    for record in records {
        for (index, field) in record.fields.iter().enumerate() {
            if index > 0 {
                out.push(delimiter);
            }
            // Re-quote when the ORIGINAL was quoted, or when the CURRENT value
            // would otherwise change the record's shape. The second condition
            // is the one that matters: a surrogate is not the original, and an
            // unquoted delimiter inside it shifts every later column.
            let needs_quotes = field.quoted
                || field.value.contains(delimiter)
                || field.value.contains('"')
                || field.value.contains('\n')
                || field.value.contains('\r');
            if needs_quotes {
                out.push('"');
                for value in field.value.chars() {
                    if value == '"' {
                        out.push('"');
                    }
                    out.push(value);
                }
                out.push('"');
            } else {
                out.push_str(&field.value);
            }
        }
        out.push_str(&record.terminator);
    }
    out
}

/// De-identify a CSV document.
///
/// `has_header` decides whether the first record is treated as column names.
/// A header row is NOT scanned when it is a header: column names are schema,
/// like JSON keys.
///
/// # Errors
///
/// [`CsvError`] for a malformed document or an unknown column, or whatever the
/// pipeline returns.
pub fn mask(
    masker: &Masker<'_>,
    text: &str,
    has_header: bool,
    fields: &Fields,
) -> Result<Masked, crate::FileError> {
    let delimiter = detect_delimiter(text);
    let mut records = parse(text, delimiter)?;

    let selected: Option<Vec<usize>> = match fields {
        Fields::All => None,
        Fields::Named(names) => {
            if !has_header {
                return Err(CsvError::NoHeader.into());
            }
            let header = records.first().ok_or(CsvError::NoHeader)?;
            let mut indices = Vec::with_capacity(names.len());
            for name in names {
                let index = header
                    .fields
                    .iter()
                    .position(|field| field.value.trim() == name)
                    .ok_or(CsvError::UnknownColumn)?;
                indices.push(index);
            }
            Some(indices)
        }
    };

    let mut originals = Vec::new();
    for (row, record) in records.iter_mut().enumerate() {
        if has_header && row == 0 {
            continue;
        }
        let before = record.fields.len();
        for (column, field) in record.fields.iter_mut().enumerate() {
            if selected
                .as_ref()
                .is_some_and(|only| !only.contains(&column))
            {
                continue;
            }
            let masked = masker.mask(&field.value)?;
            originals.extend(masked.originals);
            field.value = masked.text;
        }
        debug_assert_eq!(before, record.fields.len(), "masking changed a field count");
    }

    Ok(Masked {
        text: serialise(&records, delimiter),
        originals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tckn;
    use deid_tr_core::{Pipeline, Tier};

    /// One pipeline for the whole module, so the test signatures stay readable
    /// without every test threading a borrow through.
    fn pipeline_masker() -> Masker<'static> {
        // `Box::leak` rather than a `static`: `Pipeline` holds boxed trait
        // objects and is deliberately not `Sync`, so it cannot live in a
        // static. The leak is bounded by the test process.
        Masker::new(Box::leak(Box::new(Pipeline::new(Tier::SafeHarbor))))
    }

    #[test]
    fn an_untouched_document_round_trips_byte_for_byte() {
        // Including CRLF, a quoted field with an embedded delimiter, an escaped
        // quote, and no trailing newline.
        let source = "ad;not\r\n\"Ayşe\";\"a;b \"\"c\"\"\"\r\nBora;x";
        let masked = mask(&pipeline_masker(), source, true, &Fields::All).expect("mask");
        assert_eq!(masked.text, source);
        assert!(masked.originals.is_empty());
    }

    #[test]
    fn the_semicolon_delimiter_of_a_turkish_locale_export_is_detected() {
        assert_eq!(detect_delimiter("ad;soyad;tckn\n"), ';');
        assert_eq!(detect_delimiter("ad,soyad,tckn\n"), ',');
        assert_eq!(detect_delimiter("\"a;b\",c\n"), ',');
    }

    #[test]
    fn masking_removes_an_identifier_and_keeps_the_field_count() {
        let tckn = tckn();
        let source = format!("ad,tckn,not\nAyşe,{tckn},iyi\n");
        let masked = mask(&pipeline_masker(), &source, true, &Fields::All).expect("mask");
        assert!(!masked.text.contains(&tckn));
        assert_eq!(masked.originals, vec![tckn]);
        for line in masked.text.lines() {
            assert_eq!(line.matches(',').count(), 2, "a record changed shape");
        }
        // The header row is schema and is not scanned.
        assert!(masked.text.starts_with("ad,tckn,not\n"));
        // The name survives: no model is installed.
        assert!(masked.text.contains("Ayşe"));
    }

    #[test]
    fn selecting_columns_leaves_the_others_unscanned() {
        // The RECALL COST of a selection, made visible. `not` is not scanned,
        // so the identifier in it survives -- which is why `Fields::All` is the
        // default and this has to be asked for.
        let tckn = tckn();
        let source = format!("ad,not\nAyşe,{tckn}\n");
        let masked = mask(
            &pipeline_masker(),
            &source,
            true,
            &Fields::Named(vec!["ad".to_owned()]),
        )
        .expect("mask");
        assert!(masked.text.contains(&tckn));
        assert!(masked.originals.is_empty());
    }

    #[test]
    fn an_unknown_column_is_an_error_rather_than_a_silently_unscanned_file() {
        let result = mask(
            &pipeline_masker(),
            "ad,not\nAyşe,x\n",
            true,
            &Fields::Named(vec!["tckn".to_owned()]),
        );
        assert!(matches!(
            result,
            Err(crate::FileError::Csv(CsvError::UnknownColumn))
        ));
    }

    #[test]
    fn an_unclosed_quote_is_refused() {
        let result = mask(&pipeline_masker(), "a,\"unterminated\n", true, &Fields::All);
        assert!(matches!(
            result,
            Err(crate::FileError::Csv(CsvError::UnclosedQuote { .. }))
        ));
    }

    #[test]
    fn line_endings_are_preserved_per_record() {
        let source = "a\r\nb\nc";
        let masked = mask(&pipeline_masker(), source, false, &Fields::All).expect("mask");
        assert_eq!(masked.text, source);
    }
}
