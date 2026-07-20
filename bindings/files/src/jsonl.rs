//! JSON Lines: one JSON value per line, structure preserved line by line.
//!
//! # Why this is not "parse the file as JSON"
//!
//! A JSONL file is a stream of independent records. Treating it as one document
//! would fail on the second line; treating each line independently is also what
//! makes a partial failure survivable -- a malformed record is reported with its
//! LINE NUMBER, and the caller can decide, rather than losing the whole export
//! to one bad row.
//!
//! # Structure preservation
//!
//! Line terminators are preserved exactly, including a missing final newline
//! and any blank lines, because a JSONL file is frequently appended to and a
//! rewritten terminator changes what the next append produces. Object key
//! order inside each record is preserved by [`crate::json`].
//!
//! HONEST SCOPE: only rule-detectable identifiers are removed. See
//! [`crate::Report::rule_detectable_only`].

use crate::json;
use crate::masker::{Masked, Masker};

/// A malformed JSON Lines document.
///
/// Carries a LINE NUMBER, never the line (I4). A JSONL line in this pipeline is
/// a clinical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("line {line} is not a valid JSON value")]
pub struct JsonlError {
    /// One-based line number.
    pub line: usize,
    /// What the JSON parser said about it.
    #[source]
    pub cause: json::JsonError,
}

/// De-identify every string value of every record.
///
/// # Errors
///
/// [`JsonlError`] naming the first line that does not parse, or whatever the
/// pipeline returns.
pub fn mask(masker: &Masker<'_>, text: &str) -> Result<Masked, crate::FileError> {
    let mut out = String::with_capacity(text.len());
    let mut originals = Vec::new();
    let mut line_number = 0usize;
    let mut rest = text;

    while !rest.is_empty() {
        line_number += 1;
        // Split on `\n` and keep whatever came before it verbatim, so a `\r\n`
        // file keeps its `\r` without this module ever naming the convention.
        let (line, terminator, remainder) = match rest.find('\n') {
            Some(at) => (&rest[..at], "\n", &rest[at + 1..]),
            None => (rest, "", ""),
        };
        let (body, carriage) = match line.strip_suffix('\r') {
            Some(stripped) => (stripped, "\r"),
            None => (line, ""),
        };

        if body.trim().is_empty() {
            // A blank line is not a record. Preserved rather than dropped: a
            // rewritten file that loses blank lines is a file whose diff
            // against the original is unreadable.
            out.push_str(body);
        } else {
            let masked = json::mask(masker, body).map_err(|error| match error {
                crate::FileError::Json(cause) => crate::FileError::Jsonl(JsonlError {
                    line: line_number,
                    cause,
                }),
                other => other,
            })?;
            originals.extend(masked.originals);
            out.push_str(&masked.text);
        }
        out.push_str(carriage);
        out.push_str(terminator);
        rest = remainder;
    }

    Ok(Masked {
        text: out,
        originals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tckn;
    use deid_tr_core::{Pipeline, Tier};

    fn masker() -> Masker<'static> {
        // `Box::leak` rather than a `static`: `Pipeline` holds boxed trait
        // objects and is deliberately not `Sync`, so it cannot live in a
        // static. The leak is bounded by the test process.
        Masker::new(Box::leak(Box::new(Pipeline::new(Tier::SafeHarbor))))
    }

    #[test]
    fn each_record_is_masked_and_the_line_structure_survives() {
        let tckn = tckn();
        let source = format!("{{\"a\":\"{tckn}\"}}\r\n{{\"b\":1}}\r\n");
        let masked = mask(&masker(), &source).expect("mask");
        assert!(!masked.text.contains(&tckn));
        assert_eq!(masked.text.matches("\r\n").count(), 2);
        assert!(masked.text.ends_with("\r\n"));
        assert_eq!(masked.originals, vec![tckn]);
    }

    #[test]
    fn a_missing_final_newline_stays_missing() {
        let masked = mask(&masker(), "{\"a\":1}\n{\"b\":2}").expect("mask");
        assert_eq!(masked.text, "{\"a\":1}\n{\"b\":2}");
    }

    #[test]
    fn blank_lines_are_preserved_rather_than_parsed() {
        let masked = mask(&masker(), "{\"a\":1}\n\n{\"b\":2}\n").expect("mask");
        assert_eq!(masked.text, "{\"a\":1}\n\n{\"b\":2}\n");
    }

    #[test]
    fn a_malformed_record_names_its_line_and_not_its_content() {
        let error = mask(&masker(), "{\"a\":1}\n{\"patient\":\n").expect_err("invalid");
        let crate::FileError::Jsonl(inner) = error else {
            panic!("expected a JSONL error");
        };
        assert_eq!(inner.line, 2);
        assert!(!format!("{inner}").contains("patient"));
    }
}
