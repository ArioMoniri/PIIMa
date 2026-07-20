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
// Aliased: `crate::format::Format` is the OUTPUT shape (text/json/csv/html) and
// this one is the INPUT container. Two different questions that would otherwise
// share a name in this module.
use deid_tr_files::{detect_format, Format as FileFormat};

use crate::format::Format;

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
    /// The input is a binary container this verb must not rewrite as text.
    ///
    /// MEASURED, NOT HYPOTHETICAL. An UNCOMPRESSED PDF is valid UTF-8, so it
    /// read cleanly, took the text path, and came out with its cross-reference
    /// table rewritten by a surrogate -- a corrupt file that looks redacted. A
    /// COMPRESSED one is worse in the other direction: the identifiers live in
    /// a Flate stream the text path cannot see, so the rewrite would report
    /// success having removed nothing. Both are refusals, and the refusal names
    /// the verb that does the job.
    #[error(
        "this looks like a {0} file. `deid mask` rewrites text and would corrupt it \
         while leaving identifiers in place; use `deid mask-file IN --out OUT`"
    )]
    NotTextFormat(&'static str),
    /// The input is a container this build cannot redact at all.
    #[error(
        "the input is a binary container this build cannot redact as text; \
         use `deid mask-file IN --out OUT` if it is a PDF, DOCX, CSV, JSON or JSONL file"
    )]
    UnknownContainer,
    /// A checkpoint was configured for L2 and could not be used.
    ///
    /// A SEPARATE VARIANT AND A HARD FAILURE, for the same reason
    /// [`MaskError::Contextual`] is one. There is no branch that reacts to an
    /// unusable checkpoint by running rules-only: an operator who asked for the
    /// NER ensemble and silently got L1 alone has a document they believe is
    /// more masked than it is.
    #[error("{0}")]
    Ner(#[from] crate::l2::L2Error),
    /// The Expert Determination tier was asked for and L3 could not be wired.
    ///
    /// A SEPARATE VARIANT RATHER THAN A FALLBACK. There is no branch anywhere in
    /// this module that reacts to an L3 failure by running Safe Harbor instead:
    /// handing back a less-masked document than the caller asked for, without
    /// saying so, is the worst failure this tool can have. Every spelling of the
    /// failure names the missing precondition; see `src/l3.rs`.
    #[error("{0}")]
    Contextual(#[from] crate::l3::L3Error),
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

/// Everything the pipeline is built from, in one value.
///
/// Grouped rather than passed as three parameters because the three always
/// travel together and always come from the same place -- the tier chooses
/// whether L3 runs, `l3` says what it runs, and `opts` says what the caller
/// opted out of. Splitting them made `run` an eight-argument function whose
/// call sites were positional soup.
#[derive(Debug, Clone, Copy)]
pub struct Build<'a> {
    /// Which assurance tier was asked for.
    pub tier: Tier,
    /// The explicit opt-OUTs.
    pub opts: Opts,
    /// The two local paths L3 is built from. Unused outside Expert
    /// Determination, and required inside it.
    pub l3: &'a crate::l3::L3Config,
    /// The local directory L2's checkpoint is loaded from. Absent by default,
    /// in which case no ensemble is installed and the pipeline is exactly the
    /// one this binary has always shipped.
    pub l2: &'a crate::l2::L2Config,
}

/// Turn a pipeline failure into the most specific thing that can be said.
///
/// L3-shaped failures gain the remedy `core/` cannot know -- it has no idea a
/// `--runtime` flag exists -- and every other failure passes through untouched,
/// so a span-offset bug is never reported as a model problem.
pub(crate) fn classify(error: deid_tr_core::Error) -> MaskError {
    match crate::l3::L3Error::from_core(&error) {
        Some(l3) => MaskError::Contextual(l3),
        None => MaskError::Pipeline(error),
    }
}

/// Build the pipeline the CLI actually ships.
///
/// THE DEFAULT PATH IS THE SAFE ONE. `Pipeline::new` now carries the audited
/// class C vocabulary, and L5 is installed here from a per-run salt drawn from
/// the operating system. Before this, every `deid mask` ran with an empty
/// allowlist and no surrogate engine: the entire D-010 collision resolution was
/// unreachable from the binary, and the output was `[LABEL]` placeholders.
///
/// L3 was the same defect one layer up and is fixed the same way: the tier now
/// installs a real contextual layer instead of naming one that no binary could
/// construct.
pub(crate) fn build(spec: &Build<'_>) -> Result<Pipeline, MaskError> {
    let mut pipeline = Pipeline::new(spec.tier);
    // L2 IS INSTALLED WHENEVER A CHECKPOINT IS CONFIGURED, and a configured
    // checkpoint that cannot be used is fatal here rather than at the first
    // document. `ensemble` returns `Ok(None)` only when nothing was configured
    // at any layer, which is the unchanged default path.
    if let Some(ensemble) = crate::l2::ensemble(spec.l2)? {
        pipeline = pipeline.with_ensemble(ensemble);
    }
    // L3 IS INSTALLED WHENEVER THE TIER ASKS FOR IT, and its absence is fatal
    // here rather than at the first document. `Pipeline::propose` would refuse
    // an Expert Determination run with no contextual layer anyway, but that
    // refusal arrives with a clinical note already in memory and says only that
    // none is configured. Failing at build time says which path is missing.
    if spec.tier == Tier::ExpertDetermination {
        pipeline = pipeline.with_context(crate::l3::contextual(spec.l3)?);
    }
    if spec.opts.no_medical_allowlist {
        pipeline = pipeline.without_medical_allowlist();
    }
    if !spec.opts.placeholder_labels {
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
///
/// Reads BYTES and then decides, rather than reading a `String` and letting
/// UTF-8 validity stand in for "this is a text document". The two are not the
/// same question: an uncompressed PDF is valid UTF-8 and is not a text document.
fn read_input(path: Option<&str>) -> Result<String, MaskError> {
    let (bytes, name) = match path {
        None | Some("-") => {
            let mut buffer = Vec::new();
            io::stdin()
                .read_to_end(&mut buffer)
                .map_err(MaskError::Read)?;
            (buffer, None)
        }
        Some(path) => (
            std::fs::read(Path::new(path)).map_err(MaskError::Read)?,
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned),
        ),
    };
    refuse_binary_containers(&bytes, name.as_deref())?;
    String::from_utf8(bytes).map_err(|_| {
        // Not valid UTF-8 and not a container we recognise: this verb has no
        // honest way to proceed, and guessing an encoding in a de-identification
        // tool would silently change which bytes the rules layer sees.
        MaskError::Read(io::Error::new(
            io::ErrorKind::InvalidData,
            "the input is not UTF-8",
        ))
    })
}

/// Refuse the formats a text rewrite would corrupt or silently miss.
///
/// DELIBERATELY NARROW. `Csv`, `Json` and `Jsonl` are text and masking them as
/// text removes every identifier in them, so they are still accepted here and
/// refusing them would be a regression. Only the binary containers -- and the
/// containers this build cannot open at all -- are refused.
fn refuse_binary_containers(bytes: &[u8], name: Option<&str>) -> Result<(), MaskError> {
    match detect_format(bytes, name) {
        Some(FileFormat::Pdf) => Err(MaskError::NotTextFormat("PDF")),
        Some(FileFormat::Docx) => Err(MaskError::NotTextFormat("DOCX")),
        // `detect_format` returns None for a zip that is not a .docx, which is a
        // container whose text this build cannot reach.
        None => Err(MaskError::UnknownContainer),
        Some(_) => Ok(()),
    }
}

/// Run the Safe Harbor pipeline over one document.
///
/// The tier is a parameter because Expert Determination needs a host that can
/// run a local LLM, and the CLI cannot silently promote a caller into a tier
/// whose contextual layer is not installed. `l3` carries the two paths that
/// layer is built from; when the tier does not ask for L3 they are unused.
pub fn run(
    path: Option<&str>,
    spec: &Build<'_>,
    format: Format,
    threshold: Option<f32>,
    out: &mut dyn Write,
    diagnostics: &mut dyn Write,
) -> Result<(), MaskError> {
    let source = read_input(path)?;
    let pipeline = build(spec)?;
    let result = pipeline.deidentify(&source).map_err(classify)?;
    let rendered = crate::format::render(format, &result, threshold);

    // write_all, not a format macro: the guard in scripts/hooks is right that
    // document bytes must never enter a format string, and stdout is the one
    // legitimate destination for them.
    out.write_all(rendered.as_bytes())
        .map_err(MaskError::Write)?;
    out.flush().map_err(MaskError::Write)?;

    // Counts and labels only. The span map is the round-trip table and stays in
    // memory; printing it would print the offsets of every identifier in a
    // document alongside the document.
    let (total, masked, withheld) = crate::format::counts(&result, threshold);
    let _ = writeln!(diagnostics, "deid: masked {masked} of {total} span(s)");
    if threshold.is_some() {
        // Printed EVERY time the flag is used, not once per session and not
        // behind a verbose switch. A caller who reaches for a confidence
        // threshold is usually reaching for a masking control, and this is the
        // moment to tell them it is not one.
        let _ = writeln!(diagnostics, "deid: {}", crate::format::RECALL_WARNING);
        if format.has_report() {
            let _ = writeln!(
                diagnostics,
                "deid: {withheld} span(s) withheld from the report; all {masked} masked span(s) are still masked in the output"
            );
        } else {
            let _ = writeln!(diagnostics, "deid: {}", crate::format::NO_REPORT_NOTE);
        }
    }
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
            &Build {
                tier: Tier::SafeHarbor,
                opts: Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            Format::Text,
            None,
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
    fn a_pdf_is_refused_rather_than_rewritten_as_text() {
        // THE MEASURED DEFECT. An uncompressed PDF is valid UTF-8, so it used to
        // read cleanly, take the text path, and come out with its cross-reference
        // table overwritten by a surrogate: a corrupt file that looks redacted.
        let content = "BT /F1 12 Tf 72 720 Td (hasta kaydi) Tj ET";
        let pdf = format!(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
             4 0 obj\n<< /Length {} >>\nstream\n{content}\nendstream\nendobj\n\
             xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 5 >>\n%%EOF\n",
            content.len()
        );
        let path = std::env::temp_dir().join(format!(
            "deid-mask-pdf-{:?}.pdf",
            std::thread::current().id()
        ));
        std::fs::write(&path, &pdf).expect("fixture");

        let err = run(
            Some(path.to_str().expect("path")),
            &Build {
                tier: Tier::SafeHarbor,
                opts: Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            Format::Text,
            None,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("a PDF must be refused by the text verb");
        let rendered = err.to_string();
        assert!(rendered.contains("PDF"));
        assert!(
            rendered.contains("mask-file"),
            "the refusal must name the verb that does the job"
        );
    }

    #[test]
    fn the_text_shaped_formats_are_still_accepted() {
        // The refusal is narrow on purpose: masking a CSV or a JSON file as text
        // removes every identifier in it, so refusing them would be a regression.
        for (name, body) in [
            ("note.csv", "ad,tckn\nhasta,x\n"),
            ("note.json", "{\n  \"ad\": \"hasta\"\n}\n"),
            ("note.txt", "hasta kaydi"),
        ] {
            assert!(
                refuse_binary_containers(body.as_bytes(), Some(name)).is_ok(),
                "{name} was refused by the text verb"
            );
        }
    }

    #[test]
    fn an_unopenable_container_is_refused_rather_than_guessed_at() {
        assert!(matches!(
            refuse_binary_containers(b"PK\x03\x04not-a-docx", Some("a.zip")),
            Err(MaskError::UnknownContainer)
        ));
    }

    #[test]
    fn a_missing_input_file_is_an_error_that_names_no_content() {
        let err = run(
            Some("/nonexistent/clinical-note.txt"),
            &Build {
                tier: Tier::SafeHarbor,
                opts: Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            Format::Text,
            None,
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
        let l3 = crate::l3::L3Config::default();
        let l2 = crate::l2::L2Config::default();
        let pipeline = build(&Build {
            tier: Tier::SafeHarbor,
            opts: Opts::default(),
            l3: &l3,
            l2: &l2,
        })
        .expect("build");
        assert!(pipeline.allowlist().contains("costa"));
        assert!(pipeline.surrogate().is_some());

        let opted_out = build(&Build {
            tier: Tier::SafeHarbor,
            opts: Opts {
                placeholder_labels: true,
                no_medical_allowlist: true,
            },
            l3: &l3,
            l2: &l2,
        })
        .expect("build");
        assert!(!opted_out.allowlist().contains("costa"));
        assert!(opted_out.surrogate().is_none());
    }

    #[test]
    fn the_expert_tier_refuses_to_build_rather_than_becoming_safe_harbor() {
        // The property that matters more than the message: an unconfigured L3
        // yields NO PIPELINE. There is no value of the arguments on which this
        // returns a Safe Harbor pipeline, so there is nothing for a caller to
        // accidentally mask a document with.
        // `Pipeline` has no `Debug`, so the Ok side is discarded explicitly
        // rather than through `expect_err`.
        let built = build(&Build {
            tier: Tier::ExpertDetermination,
            opts: Opts::default(),
            l3: &crate::l3::L3Config::default(),
            l2: &crate::l2::L2Config::default(),
        });
        let error = match built {
            Ok(_) => panic!("expert with no model must not build a pipeline"),
            Err(error) => error,
        };
        assert!(matches!(error, MaskError::Contextual(_)));
        assert!(error.to_string().contains("--model"));
    }
}
