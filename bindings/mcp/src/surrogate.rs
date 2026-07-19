//! Reversible placeholders, and the substitution that undoes them.
//!
//! # Why the gateway mints its own placeholders
//!
//! There are two things it could have used instead, and both are wrong for a ROUND TRIP
//! specifically. Neither is wrong for masking, which is why the pipeline offers them.
//!
//! **The pipeline's fallback placeholder.** With no L5 engine installed, `Pipeline::deidentify`
//! replaces each masked span with its label: every TCKN becomes `[TCKN]`, every name becomes
//! `[PATIENT_NAME]`. Safe, and not reversible -- two different patients in one note collapse
//! onto one token and nothing downstream can tell them apart again. Restoring from that map
//! would put one patient's identifier onto another patient's finding, which is worse than not
//! restoring at all.
//!
//! **`core`'s real L5 surrogates** (`Pipeline::with_surrogates`). These are format-preserving
//! and document-consistent: a Turkish name becomes a plausible Turkish name, a TCKN becomes a
//! checksum-valid TCKN. That is exactly right for producing a de-identified corpus and exactly
//! wrong here, because re-identification on the way back is a SEARCH for the surrogate in a
//! model's free-text answer. A surrogate that looks like ordinary clinical prose cannot be
//! searched for safely: a fake surname that happens to be a common word, or that the model
//! echoes inside an unrelated sentence, gets rewritten into a real patient's name. The property
//! this module needs is not plausibility, it is being UNMISTAKABLE in arbitrary text.
//!
//! So the gateway re-renders the pipeline's output with bracketed, nonce-carrying tokens. It
//! does not re-implement masking: it consumes `DeidResult::span_map`, whose
//! `output_start`/`output_end` already address the pipeline's own replacements in the
//! pipeline's own output text.
//!
//! # The shape of a token, and why each part is there
//!
//! ```text
//! [PATIENT_NAME_4f1a2b7c_2]
//!  |            |        |
//!  |            |        +-- ordinal: distinct entities of this label, in first-seen order
//!  |            +----------- session nonce: 32 bits of CSPRNG, fresh for every document
//!  +------------------------ schema label: what a model needs to reason about the redaction
//! ```
//!
//! The label is present because the whole point of the gateway is that the cloud model can
//! still do useful work: `[PATIENT_NAME_4f1a2b7c_2]` tells it a person is referenced without
//! telling it which person, and it is stable within the document so the model can track that
//! the same person recurs.
//!
//! The NONCE is the part that is easy to leave out and expensive to omit. It does two jobs:
//!
//! 1. **It stops cross-session bleed.** Session A's tokens cannot be restored by session B,
//!    because B's span map contains no token with A's nonce. Without it, `[TCKN_1]` means one
//!    thing in one session and something else in another, and a client that mixes up two
//!    handles silently restores one patient's identifier into another patient's document. That
//!    is a breach produced by a client-side bookkeeping mistake, and the gateway should not be
//!    the kind of thing that can be misused that way.
//! 2. **It stops collision with document content.** A note that literally contains the string
//!    `[PATIENT_NAME_1]` would otherwise have that text rewritten into a real patient name on
//!    the way back. With a fresh nonce the collision requires guessing 32 random bits.
//!
//! Collision is nonetheless CHECKED rather than assumed -- see [`mint`].

use std::collections::HashMap;

use deid_tr_core::{Decision, DeidResult};

use crate::error::{GatewayError, Result};
use crate::session::{hex, Restoration, Secret};

/// Bytes of nonce in a token. 32 bits: enough that accidental collision with document content
/// is not a practical concern, short enough that a token stays readable to a model.
const NONCE_BYTES: usize = 4;

/// How many nonces to try before giving up on a document.
///
/// A collision means the document already contains a string shaped like one of our tokens. One
/// retry is almost certainly enough; the ceiling exists so that a pathological document -- an
/// adversarial one, or our own output fed back in -- fails loudly instead of looping.
const MINT_ATTEMPTS: usize = 8;

/// The gateway's own view of a de-identified document.
pub struct Masked {
    /// The text to hand to the cloud model. Contains no PHI.
    pub body: String,
    /// The span map: every token and the identifier it replaced.
    pub entries: Vec<Restoration>,
}

/// Re-render a pipeline result with unique, reversible tokens.
///
/// `source` is the original document, needed because `DeidResult` deliberately does not retain
/// it: the pipeline hands back offsets into it rather than copies of it.
pub fn mint(source: &str, result: &DeidResult) -> Result<Masked> {
    for attempt in 0..MINT_ATTEMPTS {
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| GatewayError::EntropyUnavailable)?;
        let candidate = render(source, result, &hex(&nonce))?;
        // The collision test is run against the ORIGINAL document, not the rendered one: the
        // rendered one contains our tokens by construction, so asking whether it contains them
        // answers nothing. What matters is whether the author of the note happened to write a
        // string we are about to claim as ours.
        if candidate
            .entries
            .iter()
            .all(|entry| !source.contains(&entry.placeholder))
        {
            return Ok(candidate);
        }
        let _ = attempt;
    }
    Err(GatewayError::SurrogateCollision {
        attempts: MINT_ATTEMPTS,
    })
}

/// Build the token text and the span map for one nonce.
///
/// The rewrite walks `result.text` -- the pipeline's output -- and splices our token over each
/// region the pipeline already replaced. `output_start`/`output_end` are byte offsets into that
/// text and the span map is ordered and non-overlapping, so a single forward pass with a cursor
/// is correct and needs no offset arithmetic of its own.
fn render(source: &str, result: &DeidResult, nonce: &str) -> Result<Masked> {
    let mut body = String::with_capacity(result.text.len());
    let mut entries: Vec<Restoration> = Vec::new();
    // Distinct entities are keyed by `text_hash`, which is how the core identifies "the same
    // identifier appearing again" WITHOUT retaining the identifier. Reusing the ordinal for a
    // repeated hash is what makes a token stable within a document.
    let mut ordinals: HashMap<(u64, &'static str), usize> = HashMap::new();
    let mut next_ordinal: HashMap<&'static str, usize> = HashMap::new();
    let mut cursor = 0usize;

    for mapped in &result.span_map {
        if mapped.decision != Decision::Mask {
            continue;
        }
        let label = mapped.span.label().as_str();
        let key = (mapped.span.text_hash(), label);
        let ordinal = match ordinals.get(&key) {
            Some(existing) => *existing,
            None => {
                let counter = next_ordinal.entry(label).or_insert(0);
                *counter += 1;
                ordinals.insert(key, *counter);
                *counter
            }
        };
        let placeholder = format!("[{label}_{nonce}_{ordinal}]");

        body.push_str(slice(&result.text, cursor, mapped.output_start)?);
        body.push_str(&placeholder);
        cursor = mapped.output_end;

        // The identifier is read out of the ORIGINAL document at the span's original offsets,
        // which is the only place it exists -- the pipeline's output has already overwritten it.
        let original = slice(source, mapped.span.start(), mapped.span.end())?;
        entries.push(Restoration {
            placeholder,
            original: Secret::new(original),
            label: mapped.span.label(),
            start: mapped.span.start(),
            end: mapped.span.end(),
        });
    }
    body.push_str(slice(&result.text, cursor, result.text.len())?);

    Ok(Masked { body, entries })
}

/// The result of putting identifiers back.
pub struct Restored {
    /// The model's response with tokens replaced by the identifiers they stood for.
    pub body: String,
    /// How many token occurrences were substituted. A count, safe to log.
    pub substitutions: usize,
    /// How many DISTINCT entities from the span map appeared at least once.
    pub entities_seen: usize,
}

/// Replace every token from `entries` with the identifier it stands for.
///
/// # Why this is a single left-to-right pass and not a loop of `str::replace`
///
/// Repeated `replace` calls re-scan text that has already been substituted, so a restored
/// identifier that happens to contain a token-shaped substring would be substituted AGAIN by a
/// later iteration. With patient-controlled content -- a note quoting a form the patient filled
/// in -- that is reachable, and the result is one patient's identifier spliced into another's
/// record. One pass, never revisiting output, makes the class of bug unreachable rather than
/// unlikely.
///
/// At each `[` the longest matching token wins, so `[TCKN_ab12cd34_1]` is never mistaken for a
/// prefix of `[TCKN_ab12cd34_11]`.
pub fn restore(body: &str, entries: &[Restoration]) -> Restored {
    // Longest first is what makes "longest match wins" fall out of a linear scan.
    let mut ordered: Vec<&Restoration> = entries.iter().collect();
    ordered.sort_by(|a, b| {
        b.placeholder
            .len()
            .cmp(&a.placeholder.len())
            .then_with(|| a.placeholder.cmp(&b.placeholder))
    });

    let mut out = String::with_capacity(body.len());
    let mut substitutions = 0usize;
    let mut seen = vec![false; ordered.len()];
    let bytes = body.as_bytes();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        // Every token starts with `[`, so anything else cannot begin a match and is copied
        // through without consulting the table at all.
        if bytes[cursor] == b'[' {
            let rest = &body[cursor..];
            if let Some((index, entry)) = ordered
                .iter()
                .enumerate()
                .find(|(_, entry)| rest.starts_with(&entry.placeholder))
            {
                out.push_str(entry.original.expose());
                substitutions += 1;
                seen[index] = true;
                cursor += entry.placeholder.len();
                continue;
            }
        }
        // Advance by a whole character. Turkish is multi-byte, and stepping one byte at a time
        // would split `ş` across two pushes and corrupt the output.
        let step = char_len(bytes[cursor]);
        out.push_str(&body[cursor..(cursor + step).min(bytes.len())]);
        cursor += step;
    }

    Restored {
        body: out,
        substitutions,
        entities_seen: seen.iter().filter(|hit| **hit).count(),
    }
}

/// Length in bytes of the UTF-8 character starting with this byte.
const fn char_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// Slice without panicking on a bad range.
fn slice(body: &str, start: usize, end: usize) -> Result<&str> {
    body.get(start..end)
        .ok_or(GatewayError::Core(deid_tr_core::Error::SpanOutOfBounds {
            offset: end,
            doc_len: body.len(),
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::{EntityLabel, Pipeline, Tier};

    /// The tail of a token, so a test can assert the ordinal without knowing the nonce.
    fn ordinal_suffix(entry: &Restoration) -> &str {
        let cut = entry.placeholder.rfind('_').unwrap_or(0);
        &entry.placeholder[cut..]
    }

    fn masked_for(source: &str) -> Masked {
        let result = Pipeline::new(Tier::SafeHarbor)
            .deidentify(source)
            .expect("safe harbor run");
        mint(source, &result).expect("mint")
    }

    #[test]
    fn a_token_carries_its_label_and_the_identifier_is_gone() {
        let tckn = crate::fixtures::tckn();
        let source = format!("Hasta TCKN {tckn} ile kayıtlı.");
        let masked = masked_for(&source);
        assert!(
            !masked.body.contains(&tckn),
            "the identifier survived masking"
        );
        assert!(masked.body.contains("[TCKN_"));
        assert_eq!(masked.entries.len(), 1);
        assert_eq!(masked.entries[0].label, EntityLabel::Tckn);
        assert_eq!(masked.entries[0].original.expose(), tckn);
    }

    #[test]
    fn the_same_identifier_twice_gets_the_same_token() {
        let tckn = crate::fixtures::tckn();
        let source = format!("TCKN {tckn}. Tekrar: TCKN {tckn}.");
        let masked = masked_for(&source);
        assert_eq!(masked.entries.len(), 2);
        assert_eq!(
            masked.entries[0].placeholder, masked.entries[1].placeholder,
            "one entity must read as one entity to the model"
        );
        assert_eq!(ordinal_suffix(&masked.entries[0]), "_1]");
    }

    #[test]
    fn two_different_identifiers_get_different_tokens() {
        let source = "Tel 0(532) 000 00 00 ve tel 0(533) 111 11 11.";
        let masked = masked_for(source);
        assert_eq!(masked.entries.len(), 2);
        assert_ne!(
            masked.entries[0].placeholder, masked.entries[1].placeholder,
            "two entities collapsed into one token and can never be told apart again"
        );
    }

    #[test]
    fn restore_is_the_exact_inverse_of_mint() {
        let tckn = crate::fixtures::tckn();
        let source = format!("Hasta Ayşe Yılmaz, TCKN {tckn}, tel 0(532) 000 00 00.");
        let masked = masked_for(&source);
        let restored = restore(&masked.body, &masked.entries);
        assert_eq!(restored.body, source, "the round trip was not exact");
    }

    #[test]
    fn restore_never_revisits_its_own_output() {
        // A restored identifier that itself looks like a token must not be substituted again.
        // Constructed directly rather than through the pipeline, because getting L1 to emit
        // this shape is incidental to the property being asserted.
        let entries = vec![
            Restoration {
                placeholder: "[A_ab12cd34_1]".to_owned(),
                original: Secret::new("[A_ab12cd34_2]"),
                label: EntityLabel::PatientName,
                start: 0,
                end: 14,
            },
            Restoration {
                placeholder: "[A_ab12cd34_2]".to_owned(),
                original: Secret::new("SECOND"),
                label: EntityLabel::PatientName,
                start: 20,
                end: 26,
            },
        ];
        let restored = restore("x [A_ab12cd34_1] y", &entries);
        assert_eq!(
            restored.body, "x [A_ab12cd34_2] y",
            "the substitution re-entered its own output"
        );
        assert_eq!(restored.substitutions, 1);
    }

    #[test]
    fn the_longest_matching_token_wins() {
        let entries = vec![
            Restoration {
                placeholder: "[A_ab12cd34_1]".to_owned(),
                original: Secret::new("ONE"),
                label: EntityLabel::PatientName,
                start: 0,
                end: 3,
            },
            Restoration {
                placeholder: "[A_ab12cd34_11]".to_owned(),
                original: Secret::new("ELEVEN"),
                label: EntityLabel::PatientName,
                start: 4,
                end: 10,
            },
        ];
        let restored = restore("[A_ab12cd34_11] and [A_ab12cd34_1]", &entries);
        assert_eq!(restored.body, "ELEVEN and ONE");
        assert_eq!(restored.entities_seen, 2);
    }

    #[test]
    fn text_with_no_tokens_passes_through_byte_for_byte() {
        let entries = vec![Restoration {
            placeholder: "[A_ab12cd34_1]".to_owned(),
            original: Secret::new("ONE"),
            label: EntityLabel::PatientName,
            start: 0,
            end: 3,
        }];
        // Multi-byte Turkish and a bracket that begins nothing: both must survive the scan.
        let body = "Hastanın şikâyeti [devam] ediyor. İğne yapıldı.";
        let restored = restore(body, &entries);
        assert_eq!(restored.body, body);
        assert_eq!(restored.substitutions, 0);
        assert_eq!(restored.entities_seen, 0);
    }

    #[test]
    fn a_token_is_restored_everywhere_it_appears() {
        let entries = vec![Restoration {
            placeholder: "[A_ab12cd34_1]".to_owned(),
            original: Secret::new("Ayşe"),
            label: EntityLabel::PatientName,
            start: 0,
            end: 5,
        }];
        let restored = restore("[A_ab12cd34_1] ve [A_ab12cd34_1]", &entries);
        assert_eq!(restored.body, "Ayşe ve Ayşe");
        assert_eq!(restored.substitutions, 2);
        assert_eq!(restored.entities_seen, 1, "one entity, seen twice");
    }

    #[test]
    fn a_nonce_is_fresh_for_every_document() {
        let source = "Tel 0(532) 000 00 00.";
        let first = masked_for(source);
        let second = masked_for(source);
        assert_ne!(
            first.entries[0].placeholder, second.entries[0].placeholder,
            "a reused nonce lets one session's tokens be restored by another's span map"
        );
        // And the cross-restoration is therefore a no-op rather than a wrong answer.
        let crossed = restore(&first.body, &second.entries);
        assert_eq!(crossed.substitutions, 0);
        assert_eq!(crossed.body, first.body);
    }

    #[test]
    fn a_document_that_already_contains_a_token_shape_is_not_corrupted() {
        // The nonce makes this astronomically unlikely in practice; the test proves the output
        // is still self-consistent when the author writes bracketed, label-shaped text.
        let source = "Not: [TCKN_1] alanı boş. Tel 0(532) 000 00 00.";
        let masked = masked_for(source);
        assert!(
            masked.body.contains("[TCKN_1]"),
            "the author's text was eaten"
        );
        let restored = restore(&masked.body, &masked.entries);
        assert_eq!(restored.body, source);
    }

    #[test]
    fn a_document_with_nothing_to_mask_round_trips_unchanged() {
        let source = "Hastada carcinoma şüphesi yok, MRI'da bulgu saptanmadı.";
        let masked = masked_for(source);
        assert_eq!(masked.body, source);
        assert!(masked.entries.is_empty());
        assert_eq!(restore(&masked.body, &masked.entries).body, source);
    }
}
