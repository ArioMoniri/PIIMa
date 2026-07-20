//! `deid mask-file` -- de-identify a document that is not plain text.
//!
//! # Why this is a separate verb from `mask`
//!
//! `deid mask` speaks TEXT. It reads a UTF-8 string, writes a UTF-8 string to
//! stdout, and its `--format` chooses the shape of that stdout (the document, or
//! a JSON/CSV/HTML entity report). None of that is meaningful for a PDF: the
//! input is bytes, the output is bytes, and the only sane destination is a file.
//! Overloading one verb with two byte-level contracts is how a caller ends up
//! piping a redacted PDF through a terminal and truncating it at the first
//! `0x00`.
//!
//! Until this module existed, `bindings/files` -- the crate that performs true
//! PDF redaction, DOCX part rewriting and CSV/JSON field masking -- had NO
//! CONSUMER. It compiled, its tests passed, and no shipped binary could reach a
//! line of it. `deid mask t.pdf` failed at `read_to_string` with "could not read
//! the input", which is the correct refusal and is not a feature.
//!
//! # This module is deliberately offline
//!
//! Same rule and same enforcement as `src/mask.rs`: it does not import
//! `crate::transport` or `crate::update`, and `tests/mask_path_is_offline.rs`
//! reads this file and fails if it ever does. A clinical document is in memory
//! here.
//!
//! # Output discipline
//!
//! The redacted bytes go to a file, or to stdout when `--out -` is given.
//! Everything else -- the format that was detected, the counts, the coverage
//! notice -- goes to stderr. Neither destination ever carries a fragment of the
//! document: `deid_tr_files::Report` holds numbers and structural names only,
//! which is why it is the type printed here.
//!
//! # In-place rewriting is refused
//!
//! Writing the output over the input destroys the only copy of the record, and
//! a failure part-way through leaves neither the original nor a redaction. The
//! operator names a different destination or nothing happens.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use deid_tr_files::pdf::ImagePolicy;
use deid_tr_files::{detect_format, mask_file_with, Format, Masker, Options, Report};

use crate::mask::{self, MaskError};

/// What went wrong, without ever carrying a fragment of the document (I4).
///
/// Paths are absent from every variant for the reason `batch.rs` records: a
/// clinical export is routinely named `ayse_yilmaz_2026-03-14.pdf`, and stderr
/// goes to a log which goes to an aggregator.
#[derive(Debug, thiserror::Error)]
pub enum FileMaskError {
    /// The input could not be read.
    #[error("could not read the input")]
    Read(#[source] io::Error),
    /// The output could not be written.
    #[error("could not write the output")]
    Write(#[source] io::Error),
    /// Neither the bytes nor the file name named a format this build handles.
    ///
    /// A REFUSAL RATHER THAN A GUESS. Falling back to "treat it as text" for an
    /// unrecognised container rewrites compressed bytes into nonsense: the
    /// output looks processed, is corrupt, and still contains every identifier.
    #[error("the input is not a format this build can redact (txt, csv, json, jsonl, docx, pdf)")]
    UnknownFormat,
    /// `--input-format` named something that is not one of the six.
    #[error("--input-format must be one of: auto, txt, csv, json, jsonl, docx, pdf")]
    BadFormat,
    /// The output path is the input path.
    #[error("--out must name a different file than the input; nothing was written")]
    InPlace,
    /// The file layer refused the document.
    #[error("de-identification failed: {0}")]
    Files(#[from] deid_tr_files::FileError),
    /// The pipeline could not be built.
    #[error("{0}")]
    Pipeline(#[from] MaskError),
}

/// Where the redacted bytes go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// A file on disk.
    Path(PathBuf),
    /// Standard output, requested explicitly with `--out -`.
    ///
    /// Explicit rather than the default, because the default destination for a
    /// PDF must not be a terminal.
    Stdout,
}

/// Parse `--input-format`, where the absent value means "detect".
///
/// # Errors
///
/// [`FileMaskError::BadFormat`] for anything else.
pub fn parse_input_format(value: Option<&str>) -> Result<Option<Format>, FileMaskError> {
    match value {
        None | Some("auto") => Ok(None),
        Some(name) => Format::from_extension(name).map(Some).ok_or({
            // `from_extension` is the single source of the name -> format map,
            // so the CLI cannot drift from what the file layer accepts.
            FileMaskError::BadFormat
        }),
    }
}

/// Decide the format, honouring an explicit override.
///
/// CONTENT FIRST when detecting, which is `detect_format`'s contract: a PDF
/// named `.txt` is redacted as a PDF. An explicit `--input-format` wins over
/// both, because an operator who names a format is asserting something about a
/// file this build's heuristics got wrong, and second-guessing them leaves them
/// with no way to proceed.
fn resolve_format(
    override_format: Option<Format>,
    bytes: &[u8],
    input: &Path,
) -> Result<Format, FileMaskError> {
    if let Some(format) = override_format {
        return Ok(format);
    }
    let name = input.file_name().and_then(|name| name.to_str());
    detect_format(bytes, name).ok_or(FileMaskError::UnknownFormat)
}

/// De-identify one non-text document.
///
/// The tier is a parameter for the same reason it is on `mask`: Expert
/// Determination needs a host that can run a local LLM, and the CLI must not
/// promote a caller into a tier whose contextual layer is not installed.
///
/// # Errors
///
/// [`FileMaskError`] for a read, write, format or pipeline failure. A PDF whose
/// redaction cannot be VERIFIED produces an error and NO OUTPUT FILE -- the file
/// layer returns no bytes in that case, and this function writes nothing rather
/// than writing a partially-redacted document.
pub fn run(
    input: &Path,
    destination: &Destination,
    spec: &mask::Build<'_>,
    input_format: Option<Format>,
    allow_images: bool,
    stdout: &mut dyn Write,
    diagnostics: &mut dyn Write,
) -> Result<Report, FileMaskError> {
    if let Destination::Path(out) = destination {
        // Compared after canonicalisation where possible, so `./note.pdf` and
        // `note.pdf` are recognised as the same file. An input that cannot be
        // canonicalised has bigger problems and is caught by the read below.
        let same = match (input.canonicalize(), out.canonicalize()) {
            (Ok(from), Ok(to)) => from == to,
            _ => input == out,
        };
        if same {
            return Err(FileMaskError::InPlace);
        }
    }

    let bytes = std::fs::read(input).map_err(FileMaskError::Read)?;
    let format = resolve_format(input_format, &bytes, input)?;

    let pipeline = mask::build(spec)?;
    let masker = Masker::new(&pipeline);
    let output = mask_file_with(
        &masker,
        &bytes,
        format,
        Options {
            // The flag turns a refusal into a report. It does NOT turn it into
            // silence: the same page-and-dimension list is printed below.
            images: if allow_images {
                ImagePolicy::Warn
            } else {
                ImagePolicy::Refuse
            },
        },
    )?;

    match destination {
        Destination::Stdout => {
            stdout
                .write_all(&output.bytes)
                .map_err(FileMaskError::Write)?;
            stdout.flush().map_err(FileMaskError::Write)?;
        }
        Destination::Path(path) => {
            std::fs::write(path, &output.bytes).map_err(FileMaskError::Write)?;
        }
    }

    // Counts and structural names only. `Report` has no field that can hold
    // document text, which is why it is the type that crosses to stderr.
    let report = output.report;
    let _ = writeln!(
        diagnostics,
        "deid: {} format, masked {} span(s) across {} location(s)",
        report.format, report.masked, report.locations
    );
    if !report.stripped.is_empty() {
        let _ = writeln!(
            diagnostics,
            "deid: removed {} structure(s) wholesale: {}",
            report.stripped.len(),
            report.stripped.join(", ")
        );
    }
    // PRINTED LAST, so it is the final thing on the operator's terminal rather
    // than a line above a reassuring count. Reaching this at all means
    // `--allow-images` was passed, and the flag buys continuation, not quiet.
    if !report.images.is_empty() {
        let _ = writeln!(diagnostics, "deid: WARNING: {}", Report::images_not_read());
        for page in &report.images {
            let _ = writeln!(diagnostics, "deid: WARNING: {page}");
        }
    }
    // Printed on EVERY file run, not once per session and not behind a verbose
    // flag. An operator redacting a PDF is the operator most likely to hand the
    // result to somebody else.
    let _ = writeln!(diagnostics, "deid: {}", Report::rule_detectable_only());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::Tier;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("deid-maskfile-{:?}", std::thread::current().id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    /// A checksum-valid TCKN, computed at runtime. Never committed as a
    /// literal (I8), and computed rather than imported because the file crate's
    /// own fixture builder is `#[cfg(test)]` and unreachable from here.
    fn tckn() -> String {
        let prefix = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let digit = |i: usize| u32::from(prefix[i]);
        let odd = digit(0) + digit(2) + digit(4) + digit(6) + digit(8);
        let even = digit(1) + digit(3) + digit(5) + digit(7);
        // `+ 1000` keeps the subtraction positive without changing the residue.
        let tenth = ((odd * 7 + 1000) - even) % 10;
        let eleventh = (odd + even + tenth) % 10;
        let mut out: String = prefix.iter().map(|d| char::from(b'0' + d)).collect();
        out.push(char::from(b'0' + u8::try_from(tenth).unwrap_or(0)));
        out.push(char::from(b'0' + u8::try_from(eleventh).unwrap_or(0)));
        out
    }

    /// A minimal one-page PDF carrying `body` in its content stream.
    ///
    /// The xref is a stub on purpose: the loader scans for objects rather than
    /// trusting it, so a fixture that hand-computed offsets would be testing
    /// the fixture builder.
    fn pdf(body: &str) -> Vec<u8> {
        let content = format!("BT /F1 12 Tf 72 720 Td ({body}) Tj ET");
        let objects = [
            (1u32, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
                 /Contents 4 0 R >>"
                    .to_owned(),
            ),
            (
                4,
                format!(
                    "<< /Length {} >>\nstream\n{content}\nendstream",
                    content.len()
                ),
            ),
            (
                5,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
            ),
        ];
        let mut out = String::from("%PDF-1.7\n");
        for (number, object) in &objects {
            out.push_str(&format!("{number} 0 obj\n{object}\nendobj\n"));
        }
        out.push_str("xref\n0 1\n0000000000 65535 f \n");
        out.push_str("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
        out.into_bytes()
    }

    fn mask_to_string(input: &Path, out: &Path) -> String {
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        run(
            input,
            &Destination::Path(out.to_path_buf()),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect("mask-file run");
        String::from_utf8(std::fs::read(out).expect("output")).expect("utf8")
    }

    #[test]
    fn a_text_file_is_masked_through_the_file_layer() {
        let tckn = tckn();
        let input = temp("note.txt");
        let out = temp("note.masked.txt");
        std::fs::write(&input, format!("TCKN {tckn} kayitli.")).expect("fixture");
        let masked = mask_to_string(&input, &out);
        assert!(!masked.contains(&tckn), "the TCKN survived the file path");
    }

    #[test]
    fn a_pdf_reaches_the_pdf_redactor_rather_than_the_text_path() {
        // THE DEFECT THIS MODULE FIXES, as an assertion. Before it, no shipped
        // binary could reach `deid_tr_files::pdf` at all.
        let tckn = tckn();
        let input = temp("note.pdf");
        let out = temp("note.masked.pdf");
        std::fs::write(&input, pdf(&format!("TCKN {tckn} kayitli"))).expect("fixture");

        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        let report = run(
            &input,
            &Destination::Path(out.clone()),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect("mask-file run");

        assert_eq!(report.format, "pdf", "the PDF took the text path");
        let bytes = std::fs::read(&out).expect("output");
        assert!(bytes.starts_with(b"%PDF"), "the output is not a PDF");
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&tckn),
            "the TCKN survived PDF redaction"
        );
    }

    #[test]
    fn content_beats_the_extension() {
        // A PDF named `.txt` must be redacted as a PDF, or the rewrite mangles
        // compressed bytes and leaves every identifier in place.
        let input = temp("liar.txt");
        let out = temp("liar.masked.txt");
        std::fs::write(&input, pdf("hasta kaydi")).expect("fixture");
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        let report = run(
            &input,
            &Destination::Path(out),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect("mask-file run");
        assert_eq!(report.format, "pdf");
    }

    #[test]
    fn writing_over_the_input_is_refused() {
        let input = temp("inplace.txt");
        std::fs::write(&input, "hasta kaydi").expect("fixture");
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        let err = run(
            &input,
            &Destination::Path(input.clone()),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect_err("in-place must be refused");
        assert!(matches!(err, FileMaskError::InPlace));
        // The original is untouched, which is the whole point of the refusal.
        assert_eq!(
            std::fs::read_to_string(&input).expect("input"),
            "hasta kaydi"
        );
    }

    #[test]
    fn an_unrecognised_container_is_refused_rather_than_treated_as_text() {
        let input = temp("archive.zip");
        let out = temp("archive.masked.zip");
        std::fs::write(&input, b"PK\x03\x04not-a-docx").expect("fixture");
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        let err = run(
            &input,
            &Destination::Path(out.clone()),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect_err("an unknown zip must be refused");
        assert!(matches!(err, FileMaskError::UnknownFormat));
        assert!(!out.exists(), "a refused run must write no output file");
    }

    #[test]
    fn an_explicit_input_format_overrides_detection() {
        assert_eq!(parse_input_format(None).expect("auto"), None);
        assert_eq!(parse_input_format(Some("auto")).expect("auto"), None);
        assert_eq!(
            parse_input_format(Some("pdf")).expect("pdf"),
            Some(Format::Pdf)
        );
        assert_eq!(
            parse_input_format(Some("csv")).expect("csv"),
            Some(Format::Csv)
        );
        assert!(matches!(
            parse_input_format(Some("docbook")),
            Err(FileMaskError::BadFormat)
        ));
    }

    #[test]
    fn a_missing_input_is_an_error_that_names_no_path() {
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        let err = run(
            Path::new("/nonexistent/ayse-yilmaz-2026.pdf"),
            &Destination::Path(temp("unused.pdf")),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect_err("a missing input must fail");
        let rendered = err.to_string();
        assert!(!rendered.contains("ayse"), "the error named the file");
        assert!(!rendered.contains("nonexistent"));
    }

    /// A one-page PDF with a real text layer AND two images in it.
    ///
    /// The hybrid case: neither a scan nor a clean text page, and the shape of
    /// most real hospital output. The 102x102 and 320x38 sizes are from a
    /// measured sample -- in a Turkish clinical report the first is very often
    /// a QR code carrying the protokol number.
    fn pdf_with_images(body: &str) -> Vec<u8> {
        let content = format!(
            "BT /F1 12 Tf 72 720 Td ({body}) Tj ET q 102 0 0 102 60 60 cm /Im0 Do Q \
             q 320 0 0 38 60 200 cm /Im1 Do Q"
        );
        let objects = [
            (1u32, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> \
                 /XObject << /Im0 6 0 R /Im1 7 0 R >> >> /Contents 4 0 R >>"
                    .to_owned(),
            ),
            (
                4,
                format!(
                    "<< /Length {} >>\nstream\n{content}\nendstream",
                    content.len()
                ),
            ),
            (
                5,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
            ),
            (
                6,
                "<< /Type /XObject /Subtype /Image /Width 102 /Height 102 /Length 4 >>\n\
                 stream\n\x00\x01\x02\x03\nendstream"
                    .to_owned(),
            ),
            (
                7,
                "<< /Type /XObject /Subtype /Image /Width 320 /Height 38 /Length 4 >>\n\
                 stream\n\x00\x01\x02\x03\nendstream"
                    .to_owned(),
            ),
        ];
        let mut out = String::from("%PDF-1.7\n");
        for (number, object) in &objects {
            out.push_str(&format!("{number} 0 obj\n{object}\nendobj\n"));
        }
        out.push_str("xref\n0 1\n0000000000 65535 f \n");
        out.push_str("trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
        out.into_bytes()
    }

    fn run_with_images(
        input: &Path,
        out: &Path,
        allow: bool,
    ) -> (Result<Report, FileMaskError>, String) {
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        let outcome = run(
            input,
            &Destination::Path(out.to_path_buf()),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            allow,
            &mut stdout,
            &mut diagnostics,
        );
        (outcome, String::from_utf8(diagnostics).expect("utf8"))
    }

    #[test]
    fn a_pdf_page_carrying_images_is_refused_and_writes_no_file() {
        // The CLI's half of the gap. The page has text, so the scan refusal
        // never fired; it also has pixels this build cannot read, so a written
        // file would have been one somebody trusted.
        let input = temp("images.pdf");
        let out = temp("images.masked.pdf");
        let _ = std::fs::remove_file(&out);
        // The body is built from the runtime-computed TCKN like every other
        // fixture here: a checksum-valid number written as a literal is
        // indistinguishable from a real one to every tool that reads this repo
        // (I8).
        std::fs::write(&input, pdf_with_images(&format!("TCKN {} kayitli", tckn())))
            .expect("fixture");
        let (outcome, _) = run_with_images(&input, &out, false);
        let error = outcome
            .expect_err("a page with images must be refused")
            .to_string();
        assert!(error.contains("page 1"), "{error}");
        assert!(error.contains("102x102"), "{error}");
        assert!(error.contains("320x38"), "{error}");
        assert!(!out.exists(), "a refused run must write no output file");
    }

    #[test]
    fn allow_images_writes_the_file_and_prints_an_unmissable_warning() {
        // The override does not buy silence. Page number, count and every pixel
        // size are printed, and the warning carries no document text (I4).
        let tckn = tckn();
        let input = temp("images-ok.pdf");
        let out = temp("images-ok.masked.pdf");
        std::fs::write(&input, pdf_with_images(&format!("TCKN {tckn} kayitli"))).expect("fixture");
        let (outcome, printed) = run_with_images(&input, &out, true);
        let report = outcome.expect("--allow-images must produce a file");
        assert_eq!(report.images.len(), 1);
        assert!(printed.contains("WARNING"), "{printed}");
        assert!(printed.contains("page 1"), "{printed}");
        assert!(printed.contains("102x102"), "{printed}");
        assert!(printed.contains("320x38"), "{printed}");
        assert!(printed.contains("NOT fully de-identified"), "{printed}");
        assert!(!printed.contains(&tckn), "the warning echoed the document");
        assert!(
            !printed.contains("kayitli"),
            "the warning echoed the document"
        );
        // And the text really was redacted, which is what makes the warning a
        // statement about the images rather than about the whole run.
        let bytes = std::fs::read(&out).expect("output");
        assert!(!String::from_utf8_lossy(&bytes).contains(&tckn));
    }

    #[test]
    fn a_pdf_with_no_images_prints_no_image_warning() {
        // A notice printed on every document is a notice nobody reads.
        let input = temp("plain.pdf");
        let out = temp("plain.masked.pdf");
        std::fs::write(&input, pdf("hasta kaydi")).expect("fixture");
        let (outcome, printed) = run_with_images(&input, &out, true);
        assert!(outcome.expect("run").images.is_empty());
        assert!(!printed.contains("WARNING"), "{printed}");
    }

    #[test]
    fn the_coverage_notice_is_printed_on_every_run() {
        // deid-tr masks ZERO names. An operator redacting a document to hand to
        // somebody else is told so, every time.
        let input = temp("notice.txt");
        let out = temp("notice.masked.txt");
        std::fs::write(&input, "Hasta Ayse Yilmaz").expect("fixture");
        let mut stdout = Vec::new();
        let mut diagnostics = Vec::new();
        run(
            &input,
            &Destination::Path(out),
            &mask::Build {
                tier: Tier::SafeHarbor,
                opts: mask::Opts::default(),
                l3: &crate::l3::L3Config::default(),
                l2: &crate::l2::L2Config::default(),
            },
            None,
            false,
            &mut stdout,
            &mut diagnostics,
        )
        .expect("run");
        let printed = String::from_utf8(diagnostics).expect("utf8");
        assert!(printed.contains("does NOT mask person names"));
        // And the name really did survive, which is what the notice is about.
        assert!(printed.contains("masked 0 span(s)"));
    }
}
