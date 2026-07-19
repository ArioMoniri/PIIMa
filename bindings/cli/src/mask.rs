//! `deid mask` — the only command that touches a clinical document.
//!
//! # This module is deliberately offline
//!
//! It does not import `crate::transport`, `crate::update`, or `reqwest`, and it
//! must never do so. `tests/mask_path_is_offline.rs` reads this file and fails if
//! the module name appears here at all, so the guarantee survives a refactor by
//! someone who has not read this comment.
//!
//! WHY structural and not procedural: "we call the check before we read the
//! document" is a property of statement order that any future edit can silently
//! reverse. "This translation unit cannot name the networking code" is a property
//! a compiler and a test can both hold. While a clinical note is resident in
//! memory, there must be no reachable code path that opens a socket.
//!
//! # Output discipline
//!
//! The de-identified document goes to stdout as bytes, never through a format
//! macro. Everything else — diagnostics, counts, warnings — goes to stderr, so a
//! pipe carries the document and nothing but the document.

use std::io::{self, Read, Write};
use std::path::Path;

use deid_tr_core::surrogate::SALT_LEN;
use deid_tr_core::{Pipeline, Salt, SurrogateEngine, Tier};

/// What went wrong, without ever carrying a fragment of the document (I4).
#[derive(Debug, thiserror::Error)]
pub enum MaskError {
    /// The input could not be read.
    #[error("could not read the input")]
    Read(#[source] io::Error),
    /// The output could not be written.
    #[error("could not write the output")]
    Write(#[source] io::Error),
    /// The pipeline refused the document.
    #[error("de-identification failed: {0}")]
    Pipeline(#[from] deid_tr_core::Error),
    /// The operating system would not produce key material for the L5 salt.
    ///
    /// FATAL RATHER THAN A DEGRADATION TO LABEL PLACEHOLDERS. A run that
    /// silently drops L5 produces a document that looks de-identified and is
    /// less useful than the operator expects, and the operator finds out by
    /// reading the output rather than by being told. There is also no honest
    /// fallback: a salt derived from a clock is a salt an attacker can
    /// reconstruct, which makes the surrogate mapping recoverable.
    #[error("the operating system entropy source is unavailable")]
    Entropy,
}

/// What the caller asked NOT to have.
///
/// Both fields default to `false`, which is the point: the safe configuration
/// -- the audited medical vocabulary in L4 and format-preserving surrogates
/// from L5 -- is what a caller who passes no flags gets. Every field here is an
/// explicit opt-OUT, named on the command line for what it costs.
#[derive(Debug, Clone, Copy, Default)]
pub struct Opts {
    /// `--placeholder-labels`: skip L5 and write `[PATIENT_NAME]` in place of a
    /// surrogate. Every patient in the note collapses onto one token, so the
    /// document stops being readable as a clinical narrative and stops being
    /// re-identifiable through the span map.
    pub placeholder_labels: bool,
    /// `--no-medical-allowlist`: run L4 with an empty class C vocabulary.
    /// `carcinoma`, `costa` and `Adalat` are then masked whenever a detector
    /// proposes them, which destroys the meaning of the note.
    pub no_medical_allowlist: bool,
}

/// Build the pipeline the CLI actually ships.
///
/// THE DEFAULT PATH IS THE SAFE ONE. `Pipeline::new` now carries the audited
/// class C vocabulary, and L5 is installed here from a per-run salt drawn from
/// the operating system. Before this, every `deid mask` ran with an empty
/// allowlist and no surrogate engine: the entire D-010 collision resolution was
/// unreachable from the binary, and the output was `[LABEL]` placeholders.
fn build(tier: Tier, opts: Opts) -> Result<Pipeline, MaskError> {
    let mut pipeline = Pipeline::new(tier);
    if opts.no_medical_allowlist {
        pipeline = pipeline.without_medical_allowlist();
    }
    if !opts.placeholder_labels {
        let mut key = [0u8; SALT_LEN];
        getrandom::fill(&mut key).map_err(|_| MaskError::Entropy)?;
        // A FRESH SALT PER RUN, which is `SaltScope::Document`, the
        // privacy-preserving default: two documents masked by two invocations
        // are not linkable through their surrogates. An operator who needs
        // longitudinal linkage across a patient's notes needs a salt that
        // outlives the process, and that is a key-management decision this
        // binary must not make silently on their behalf.
        pipeline = pipeline.with_surrogates(SurrogateEngine::new(Salt::from_bytes(key)));
    }
    Ok(pipeline)
}

/// Read from a path, or from stdin when the path is absent or `-`.
fn read_input(path: Option<&str>) -> Result<String, MaskError> {
    match path {
        None | Some("-") => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(MaskError::Read)?;
            Ok(buffer)
        }
        Some(path) => std::fs::read_to_string(Path::new(path)).map_err(MaskError::Read),
    }
}

/// Run the Safe Harbor pipeline over one document.
///
/// The tier is a parameter because Expert Determination needs a host that can
/// run a local LLM, and the CLI cannot silently promote a caller into a tier
/// whose contextual layer is not installed.
pub fn run(
    path: Option<&str>,
    tier: Tier,
    opts: Opts,
    out: &mut dyn Write,
    diagnostics: &mut dyn Write,
) -> Result<(), MaskError> {
    let source = read_input(path)?;
    let pipeline = build(tier, opts)?;
    let result = pipeline.deidentify(&source)?;

    // write_all, not a format macro: the guard in scripts/hooks is right that
    // document bytes must never enter a format string, and stdout is the one
    // legitimate destination for them.
    out.write_all(result.text.as_bytes())
        .map_err(MaskError::Write)?;
    out.flush().map_err(MaskError::Write)?;

    // Counts and labels only. The span map is the round-trip table and stays in
    // memory; printing it would print the offsets of every identifier in a
    // document alongside the document.
    let masked = result
        .span_map
        .iter()
        .filter(|mapped| mapped.decision == deid_tr_core::Decision::Mask)
        .count();
    let _ = writeln!(diagnostics, "deid: masked {masked} span(s)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_survives_the_pipeline_byte_for_byte_when_nothing_matches() {
        // Turkish multi-byte characters and a code-switched medical term: if the
        // rewrite ever used char indices, this is where it would corrupt.
        let source = "Hasta carcinoma'lı, MRI'da lezyon yok. Şükrü Bey taburcu edildi.";
        let path =
            std::env::temp_dir().join(format!("deid-mask-{:?}.txt", std::thread::current().id()));
        std::fs::write(&path, source).expect("fixture");

        let mut out = Vec::new();
        let mut diagnostics = Vec::new();
        run(
            Some(path.to_str().expect("path")),
            Tier::SafeHarbor,
            Opts::default(),
            &mut out,
            &mut diagnostics,
        )
        .expect("mask run");

        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains("carcinoma'lı"));
        assert!(String::from_utf8(diagnostics)
            .expect("utf8")
            .contains("masked"));
    }

    #[test]
    fn a_missing_input_file_is_an_error_that_names_no_content() {
        let err = run(
            Some("/nonexistent/clinical-note.txt"),
            Tier::SafeHarbor,
            Opts::default(),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("missing file");
        assert!(!format!("{err}").contains("clinical-note"));
    }

    #[test]
    fn the_default_pipeline_carries_the_vocabulary_and_the_surrogate_engine() {
        // The unit-level statement of the defect this module used to have. The
        // end-to-end statement, through the shipped binary, is in
        // tests/vocabulary_is_reachable.rs -- both exist because a builder that
        // is correct and never called is exactly what was wrong here.
        let pipeline = build(Tier::SafeHarbor, Opts::default()).expect("build");
        assert!(pipeline.allowlist().contains("costa"));
        assert!(pipeline.surrogate().is_some());

        let opted_out = build(
            Tier::SafeHarbor,
            Opts {
                placeholder_labels: true,
                no_medical_allowlist: true,
            },
        )
        .expect("build");
        assert!(!opted_out.allowlist().contains("costa"));
        assert!(opted_out.surrogate().is_none());
    }
}
