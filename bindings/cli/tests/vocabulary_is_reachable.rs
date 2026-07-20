//! Does the SHIPPED `deid` binary carry the audited medical vocabulary and L5?
//!
//! # Why this file exists rather than another test in `core/`
//!
//! `core/` already proved the D-010 collision resolution -- `Costa` the surname
//! against `costa` the rib -- and every one of those tests passed while the
//! product did not have the behaviour, because each binding built
//! `Pipeline::new(tier)` with an empty allowlist and no surrogate engine. A
//! test that constructs its own pipeline cannot detect that; only a test that
//! runs the artifact a hospital installs can. So this file execs
//! `CARGO_BIN_EXE_deid` and reads its stdout, and nothing in it is allowed to
//! import a builder.
//!
//! # What this file can and cannot assert, stated rather than implied
//!
//! The brief's canonical fixture is `Prof. Dr. Marco Costa` masked while
//! `sol 5. costa'da` is kept. Half of that is not reachable from ANY shipped
//! binary today, and not because of the allowlist: no layer in a released
//! `deid` proposes a name span at all. L1 has no name rule (`rules/mod.rs`
//! runs tckn, vkn, iban, sgk, phone, date, email and mrn), L2 ships with an
//! empty ensemble because there are no weights yet, and L3 -- now reachable via
//! `--model`/`--runtime`, see `tests/expert_tier_is_reachable.rs` -- proposes
//! quasi-identifiers rather than names. A surname is therefore never a
//! CANDIDATE, so no allowlist wiring could mask it. That is a separate,
//! larger gap and it is reported as one; inventing a name detector here to make
//! an assertion pass would be worse than naming the hole.
//!
//! What IS reachable end to end is the same discrimination on a span L1 really
//! does produce: `B12` is a lab analyte in `eval/allowlist/lab_analyte.txt` AND
//! a record-number-shaped token that `rules::mrn` flags when it follows a cue
//! word. One surface form, two contexts, two decisions -- which is exactly the
//! `costa`/`Costa` property, tested through the binary instead of through a
//! builder. The A/B against `--no-medical-allowlist` makes the vocabulary the
//! cause: with it, kept; without it, masked.
//!
//! Every fixture is synthetic (I8). The checksum-valid TCKN is COMPUTED here
//! and never written down, because the pre-commit hook refuses a committed one.

use std::io::Write;
use std::process::{Command, Output};

/// The brief's canonical medical-register document, synthetic.
const COSTA_NOTE: &str = "\
GÖĞÜS CERRAHİSİ KONSÜLTASYON NOTU
Konsültan: Prof. Dr. Marco Costa

Tetkikler: Toraks BT'de sol 5. costa'da deplase olmayan fraktür izlendi.
Hasta carcinoma'lı değil; MRI'da ek patoloji yok.
";

/// Run the shipped binary over a document handed to it on stdin.
///
/// stdin rather than a path so no fixture file is left on disk, and `--offline`
/// because a test must not depend on this machine's network posture.
fn deid_mask(document: &str, extra: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .arg("mask")
        .args(extra)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the deid binary must be runnable");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(document.as_bytes())
        .expect("write the document");
    child.wait_with_output().expect("deid must terminate")
}

fn stdout_of(document: &str, extra: &[&str]) -> String {
    let output = deid_mask(document, extra);
    assert!(
        output.status.success(),
        "deid mask exited {:?}",
        output.status.code()
    );
    String::from_utf8(output.stdout).expect("the output must be UTF-8")
}

/// A checksum-valid TCKN, derived at run time.
///
/// I8: a checksum-valid national id may never be a literal in a committed file.
/// `d10 = ((d1+d3+d5+d7+d9) * 7 - (d2+d4+d6+d8)) mod 10`, `d11 = sum(d1..d10) mod 10`.
fn valid_tckn(stem: [u32; 9]) -> String {
    let odd: u32 = stem.iter().step_by(2).sum();
    let even: u32 = stem.iter().skip(1).step_by(2).sum();
    let tenth = (odd * 7 + 100 - even) % 10;
    let eleventh = (stem.iter().sum::<u32>() + tenth) % 10;
    stem.iter()
        .chain([tenth, eleventh].iter())
        .map(|d| char::from_digit(*d, 10).expect("a decimal digit"))
        .collect()
}

#[test]
fn the_binary_keeps_the_medical_register_of_a_clinical_note() {
    let out = stdout_of(COSTA_NOTE, &[]);
    // The anatomical term, the diagnosis and the code-switched abbreviation all
    // survive byte for byte. Turkish is multi-byte, so this also catches an
    // offset bug that would corrupt the note rather than mask it.
    assert!(out.contains("costa'da deplase"), "{out}");
    assert!(out.contains("carcinoma'lı"), "{out}");
    assert!(out.contains("MRI'da"), "{out}");
}

#[test]
fn the_shipped_vocabulary_is_what_keeps_an_allowlisted_term_masked_or_kept() {
    // Cue plus an analyte code: `rules::mrn` proposes it at CONTEXT_CUED
    // confidence, which is below the escalation ceiling, so L4 decides it.
    let note = "Dosya No: B12\n";

    // WITH the vocabulary -- the default, and the whole point of this file.
    let kept = stdout_of(note, &[]);
    assert!(
        kept.contains("Dosya No: B12"),
        "the shipped binary masked a lab analyte, so L4 consulted no vocabulary: {kept}"
    );

    // WITHOUT it, by explicit opt-out. Same binary, same document, masked --
    // which is what every release before this change did unconditionally.
    let masked = stdout_of(note, &["--no-medical-allowlist"]);
    assert!(
        !masked.contains("B12"),
        "the opt-out did not disable the vocabulary: {masked}"
    );
}

#[test]
fn the_same_surface_form_is_masked_when_its_context_marks_a_person() {
    // The `costa` versus `Costa` property, on a span the CLI can actually
    // produce: person-shaped context next to the same allowlisted token sends
    // it back to `Mask`. L4 may only ever demote, so this direction is the one
    // that protects recall (I2).
    let note = "Hasta No: B12 Yılmaz\n";
    let out = stdout_of(note, &[]);
    assert!(
        !out.contains("B12 Yılmaz"),
        "an allowlisted token in person context was kept: {out}"
    );
}

#[test]
fn the_masked_output_carries_a_real_surrogate_and_not_a_label_placeholder() {
    let tckn = valid_tckn([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let note = format!("Hasta TCKN {tckn} ile kayıtlıdır.\n");

    let out = stdout_of(&note, &[]);
    assert!(
        !out.contains("[TCKN]"),
        "L5 is not installed in the shipped binary: {out}"
    );
    assert!(!out.contains(&tckn), "the original identifier survived");

    // Format-preserving: what replaced it is itself an 11-digit
    // checksum-valid TCKN, which is what makes the de-identified note still
    // parse in a hospital system.
    let surrogate: String = out
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    assert_eq!(surrogate.len(), 11, "not a TCKN-shaped surrogate: {out}");
    assert!(is_checksum_valid(&surrogate), "{surrogate}");

    // And the opt-out really is the only way to get the old behaviour.
    let placeholders = stdout_of(&note, &["--placeholder-labels"]);
    assert!(placeholders.contains("[TCKN]"), "{placeholders}");
}

#[test]
fn a_repeated_identifier_gets_one_consistent_surrogate_within_the_document() {
    // Property (b) of L5, observed through the binary: the same patient
    // referenced twice must not become two people.
    let tckn = valid_tckn([2, 3, 4, 5, 6, 7, 8, 9, 1]);
    let note = format!("TCKN {tckn} kayıt açıldı.\nKontrolde TCKN {tckn} doğrulandı.\n");
    let out = stdout_of(&note, &[]);

    let surrogates: Vec<String> = out
        .split(|c: char| !c.is_ascii_digit())
        .filter(|run| run.len() == 11)
        .map(str::to_owned)
        .collect();
    assert_eq!(surrogates.len(), 2, "{out}");
    assert_eq!(surrogates[0], surrogates[1], "{out}");
}

fn is_checksum_valid(tckn: &str) -> bool {
    let digits: Vec<u32> = tckn.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 || digits[0] == 0 {
        return false;
    }
    let odd: u32 = digits[..9].iter().step_by(2).sum();
    let even: u32 = digits[1..8].iter().step_by(2).sum();
    let tenth = (odd * 7 + 100 - even) % 10;
    let eleventh = (digits[..10].iter().sum::<u32>()) % 10;
    digits[9] == tenth && digits[10] == eleventh
}
