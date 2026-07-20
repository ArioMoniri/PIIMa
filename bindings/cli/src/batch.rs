//! `deid mask --batch <dir>` -- de-identify a directory.
//!
//! # The rule this module exists to enforce
//!
//! **A file is never silently skipped.** A skipped file in a de-identification
//! batch is an unredacted document that somebody believes is redacted, and they
//! find out when it is somewhere it should not be. So:
//!
//! * every entry in the input tree produces exactly one manifest record, in a
//!   stable order, whether it was masked, failed, or was not a file at all;
//! * a read failure, a non-UTF-8 file, a pipeline refusal and a write failure
//!   are four DISTINCT recorded outcomes, not one "error" bucket, because they
//!   need four different responses from the operator;
//! * a subdirectory encountered without `--recursive` is recorded as
//!   `skipped_directory` rather than passed over, so "I pointed it at the parent
//!   folder" shows up in the manifest instead of as a quiet absence;
//! * the run continues after a failure and exits non-zero at the end. Stopping
//!   at the first bad file would leave the rest of the corpus unprocessed and
//!   the operator with a partial output directory they have to reason about.
//!
//! # Where the paths go, and where they do not
//!
//! The MANIFEST carries the relative path of every item. It is a local artifact
//! written next to the masked outputs, and a batch report without paths is
//! useless.
//!
//! STDERR carries counts, indices and outcome classes, and never a path. A file
//! name in a clinical export is routinely `ayse_yilmaz_2026-03-14.txt`, stderr
//! goes to a log, and a log goes to an aggregator. This is the same line the
//! rest of the CLI already draws: `mask` reports "could not read the input"
//! rather than naming the file. The final summary therefore points the operator
//! at the manifest by name -- that is where the failing paths are.
//!
//! # One salt for the whole batch
//!
//! The pipeline is built ONCE and reused for every document, so the same
//! identifier receives the same surrogate across the whole run. That is what
//! makes a batch of one patient's notes internally consistent. It also means the
//! batch is linkable within itself and not across runs, which is the right
//! default: cross-run linkage needs a salt that outlives the process, and that is
//! a key management decision this binary must not make on an operator's behalf.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use deid_tr_core::{DeidResult, EntityLabel, Pipeline, Tier};

use crate::format::{self, Format};
use crate::mask::{self, MaskError};

/// The manifest file name, inside the output directory.
pub const MANIFEST_NAME: &str = "manifest.jsonl";

/// What the operator asked for.
#[derive(Debug, Clone, Copy)]
pub struct BatchOpts {
    /// Descend into subdirectories.
    pub recursive: bool,
    /// The output format for each masked document.
    pub format: Format,
    /// The REPORTING threshold. Never a masking control; see `crate::format`.
    pub threshold: Option<f32>,
    /// The pipeline opt-outs, shared with single-document masking.
    pub mask: mask::Opts,
}

/// Why one item was not masked.
///
/// Four variants rather than one, because they need four different responses:
/// fix a permission, convert an encoding, report a bug, free some disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The file could not be opened or read.
    Unreadable,
    /// The bytes were not valid UTF-8.
    ///
    /// NOT lossily decoded. Replacing an invalid byte shifts every byte offset
    /// after it, so a lossy read would produce a document whose spans address
    /// the wrong bytes -- masking the wrong text while reporting success.
    NotUtf8,
    /// The pipeline refused the document.
    PipelineFailed,
    /// The masked output could not be written.
    ///
    /// A FAILURE and never a warning: the operator's copy of this document is
    /// the unmasked original, and a run that reported success would leave them
    /// believing otherwise.
    WriteFailed,
}

impl Failure {
    /// A stable machine-readable code, for the manifest.
    const fn code(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NotUtf8 => "not_utf8",
            Self::PipelineFailed => "pipeline_failed",
            Self::WriteFailed => "write_failed",
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "could not be read",
            Self::NotUtf8 => "is not valid UTF-8",
            Self::PipelineFailed => "was refused by the pipeline",
            Self::WriteFailed => "was masked but could not be written",
        })
    }
}

/// What happened to one entry in the input tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Masked and written.
    Masked {
        /// Spans L4 decided to mask.
        masked: usize,
        /// Spans L4 decided to keep.
        kept: usize,
        /// Masked spans by label. Metadata, never text.
        labels: BTreeMap<&'static str, usize>,
    },
    /// Not masked, and why.
    Failed(Failure),
    /// A directory encountered without `--recursive`.
    SkippedDirectory,
}

impl Outcome {
    const fn status(&self) -> &'static str {
        match self {
            Self::Masked { .. } => "masked",
            Self::Failed(_) => "failed",
            Self::SkippedDirectory => "skipped_directory",
        }
    }
}

/// One manifest record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Path relative to the input directory.
    pub path: PathBuf,
    /// Path relative to the output directory, when something was written.
    pub output: Option<PathBuf>,
    /// What happened.
    pub outcome: Outcome,
}

/// The whole run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Every entry, in enumeration order. Never filtered.
    pub items: Vec<Item>,
    /// Entries masked and written.
    pub masked: usize,
    /// Entries that failed.
    pub failed: usize,
    /// Directories not descended into.
    pub skipped_directories: usize,
    /// Total masked spans across the run.
    pub total_spans: usize,
}

impl Summary {
    /// True when every item that could be masked was.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.failed == 0
    }

    /// The failures, for the final report.
    #[must_use]
    pub fn failures(&self) -> Vec<(&Path, Failure)> {
        self.items
            .iter()
            .filter_map(|item| match item.outcome {
                Outcome::Failed(failure) => Some((item.path.as_path(), failure)),
                _ => None,
            })
            .collect()
    }
}

/// Why a batch could not start.
///
/// Distinct from a per-item [`Failure`]: these are conditions under which the
/// run must not begin at all, because starting would either do nothing useful or
/// destroy the operator's originals.
#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    /// The input path is not a directory.
    #[error("--batch needs a directory")]
    NotADirectory,
    /// The input directory could not be listed.
    #[error("the input directory could not be read")]
    InputUnreadable,
    /// `--out` was not given.
    #[error(
        "--batch requires --out DIR. Masked documents are written as files, and writing many \
         documents to stdout would interleave them into one unusable stream."
    )]
    NoOutputDirectory,
    /// The output directory is the input directory, or inside it.
    ///
    /// REFUSED, not worked around. Writing masked output into the input tree
    /// either overwrites the originals -- destroying the only copy of the
    /// clinical record -- or, with `--recursive`, feeds this run's output back
    /// into its own enumeration.
    #[error(
        "the output directory must not be the input directory or inside it: masked output would \
         overwrite the originals, and a recursive run would re-process its own output"
    )]
    OutputInsideInput,
    /// The output directory could not be created or written to.
    #[error("the output directory could not be created")]
    OutputUnwritable,
    /// The manifest could not be written.
    ///
    /// FATAL. The manifest is the record of what was processed; a run that
    /// masked a thousand documents and cannot say which ones is a run whose
    /// result nobody can rely on.
    #[error("the manifest could not be written, so this run has no record of what it processed")]
    ManifestUnwritable,
    /// The pipeline could not be built.
    #[error("{0}")]
    Setup(#[from] MaskError),
}

/// Every entry under `root`, relative to it, in a stable order.
///
/// Directories are RETURNED rather than skipped when `recursive` is false, so
/// the caller records them. `read_dir` order is filesystem-dependent, so the
/// results are sorted: a manifest whose line order changes between two runs over
/// the same corpus cannot be diffed, and diffing two manifests is how an
/// operator checks that a re-run processed the same set.
fn enumerate(root: &Path, recursive: bool) -> Result<Vec<(PathBuf, bool)>, BatchError> {
    let mut found = Vec::new();
    walk(root, Path::new(""), recursive, &mut found)?;
    found.sort();
    Ok(found)
}

fn walk(
    root: &Path,
    relative: &Path,
    recursive: bool,
    found: &mut Vec<(PathBuf, bool)>,
) -> Result<(), BatchError> {
    let entries =
        std::fs::read_dir(root.join(relative)).map_err(|_| BatchError::InputUnreadable)?;
    let mut here: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        here.push(relative.join(entry.file_name()));
    }
    here.sort();
    for child in here {
        let is_dir = root.join(&child).is_dir();
        if is_dir && recursive {
            walk(root, &child, recursive, found)?;
        } else {
            found.push((child, is_dir));
        }
    }
    Ok(())
}

/// Where a masked document lands.
///
/// `text` keeps the input's file name so a masked corpus mirrors the original
/// tree exactly. Every other format APPENDS its extension rather than replacing
/// one, because `note.txt` and `note.json` in the same run would otherwise
/// collide with a genuine `note.json` in the input.
fn output_path(relative: &Path, format: Format) -> PathBuf {
    if format == Format::Text {
        return relative.to_path_buf();
    }
    let mut name = relative.as_os_str().to_os_string();
    name.push(".");
    name.push(format.extension());
    PathBuf::from(name)
}

/// Mask one document that has already been read.
fn mask_one(pipeline: &Pipeline, source: &str) -> Result<DeidResult, Failure> {
    pipeline
        .deidentify(source)
        .map_err(|_| Failure::PipelineFailed)
}

/// The masked-label histogram for one result.
fn histogram(result: &DeidResult) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for mapped in &result.span_map {
        if mapped.decision == deid_tr_core::Decision::Mask {
            *counts.entry(label_name(mapped.span.label())).or_insert(0) += 1;
        }
    }
    counts
}

/// The schema id for a label, as a `'static` string.
const fn label_name(label: EntityLabel) -> &'static str {
    label.as_str()
}

/// Render one manifest record.
fn manifest_line(item: &Item) -> String {
    let mut line = String::from("{\"record\":\"item\",\"path\":");
    format::quote(&item.path.to_string_lossy(), &mut line);
    line.push_str(",\"output\":");
    match &item.output {
        Some(path) => format::quote(&path.to_string_lossy(), &mut line),
        None => line.push_str("null"),
    }
    line.push_str(",\"status\":");
    format::quote(item.outcome.status(), &mut line);
    match &item.outcome {
        Outcome::Masked {
            masked,
            kept,
            labels,
        } => {
            line.push_str(",\"masked_spans\":");
            line.push_str(&masked.to_string());
            line.push_str(",\"kept_spans\":");
            line.push_str(&kept.to_string());
            line.push_str(",\"labels\":{");
            for (index, (label, count)) in labels.iter().enumerate() {
                if index > 0 {
                    line.push(',');
                }
                format::quote(label, &mut line);
                line.push(':');
                line.push_str(&count.to_string());
            }
            line.push('}');
        }
        Outcome::Failed(failure) => {
            line.push_str(",\"error\":");
            format::quote(failure.code(), &mut line);
            line.push_str(",\"detail\":");
            format::quote(&failure.to_string(), &mut line);
        }
        Outcome::SkippedDirectory => {
            line.push_str(",\"detail\":");
            format::quote(
                "a directory, and --recursive was not given, so nothing under it was processed",
                &mut line,
            );
        }
    }
    line.push('}');
    line
}

/// The manifest header, written before any item.
fn manifest_header(opts: BatchOpts, tier: Tier, total: usize) -> String {
    let mut line = String::from("{\"record\":\"run\",\"tool\":\"deid mask --batch\",\"version\":");
    format::quote(crate::VERSION, &mut line);
    line.push_str(",\"tier\":");
    format::quote(
        match tier {
            Tier::SafeHarbor => "safe_harbor",
            Tier::ExpertDetermination => "expert_determination",
        },
        &mut line,
    );
    line.push_str(",\"format\":");
    format::quote(opts.format.as_str(), &mut line);
    line.push_str(",\"medical_allowlist\":");
    line.push_str(if opts.mask.no_medical_allowlist {
        "false"
    } else {
        "true"
    });
    line.push_str(",\"surrogates\":");
    line.push_str(if opts.mask.placeholder_labels {
        "false"
    } else {
        "true"
    });
    line.push_str(",\"entries\":");
    line.push_str(&total.to_string());
    line.push_str(",\"coverage\":");
    format::quote(
        "rule-detectable identifiers only: L2 has no trained model in this build, so no names \
         are masked in any of these outputs",
        &mut line,
    );
    line.push('}');
    line
}

/// The manifest trailer.
fn manifest_summary(summary: &Summary) -> String {
    let mut line = String::from("{\"record\":\"summary\",\"entries\":");
    line.push_str(&summary.items.len().to_string());
    line.push_str(",\"masked\":");
    line.push_str(&summary.masked.to_string());
    line.push_str(",\"failed\":");
    line.push_str(&summary.failed.to_string());
    line.push_str(",\"skipped_directories\":");
    line.push_str(&summary.skipped_directories.to_string());
    line.push_str(",\"total_masked_spans\":");
    line.push_str(&summary.total_spans.to_string());
    line.push('}');
    line
}

/// True when `candidate` is `root` or lies underneath it.
///
/// Compared after canonicalisation where possible, so `out` and `in/../in/out`
/// are recognised as the same place. When the output directory does not exist
/// yet it cannot be canonicalised, so its EXISTING ancestor is canonicalised
/// instead -- refusing to check is not an option, and assuming they differ is
/// how the originals get overwritten.
fn is_inside(root: &Path, candidate: &Path) -> bool {
    let resolve = |path: &Path| -> PathBuf {
        // LEXICAL NORMALISATION FIRST. `Path::file_name` returns None for a
        // path ending in `..`, so the ancestor walk below terminates early on
        // `in/a/../b` and hands back an un-canonicalised path that then fails
        // to match a canonicalised root -- and `--out in/a/../b` was accepted
        // as an output directory outside the input tree while being inside it.
        // Resolving `.` and `..` textually first removes that shape entirely.
        // It is not symlink-exact, and it does not need to be: it can only
        // ever make this check refuse MORE, and over-refusing an output
        // directory costs a re-run while under-refusing one overwrites the
        // originals.
        let mut current = lexically_normal(path);
        let mut suffix = PathBuf::new();
        loop {
            if let Ok(real) = current.canonicalize() {
                return real.join(&suffix);
            }
            let Some(parent) = current.parent().map(Path::to_path_buf) else {
                return path.to_path_buf();
            };
            let Some(name) = current.file_name().map(std::ffi::OsString::from) else {
                return path.to_path_buf();
            };
            suffix = PathBuf::from(name).join(&suffix);
            current = parent;
        }
    };
    let root = resolve(root);
    let candidate = resolve(candidate);
    candidate == root || candidate.starts_with(&root)
}

/// Resolve `.` and `..` textually, without touching the filesystem.
///
/// A leading `..` that cannot be popped is kept, so a relative path outside its
/// own root still normalises to something comparable.
fn lexically_normal(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// De-identify every document under `input`, writing to `output`.
///
/// # Errors
///
/// A [`BatchError`] when the run must not start. Per-document failures are not
/// errors here: they are recorded in the returned [`Summary`] and in the
/// manifest, and the run continues.
pub fn run(
    input: &Path,
    output: &Path,
    tier: Tier,
    opts: BatchOpts,
    l3: &crate::l3::L3Config,
    l2: &crate::l2::L2Config,
    progress: &mut dyn Write,
) -> Result<Summary, BatchError> {
    if !input.is_dir() {
        return Err(BatchError::NotADirectory);
    }
    if is_inside(input, output) {
        return Err(BatchError::OutputInsideInput);
    }
    std::fs::create_dir_all(output).map_err(|_| BatchError::OutputUnwritable)?;

    let entries = enumerate(input, opts.recursive)?;
    let pipeline = mask::build(&mask::Build {
        tier,
        opts: opts.mask,
        l3,
        l2,
    })?;

    let mut manifest = std::fs::File::create(output.join(MANIFEST_NAME))
        .map_err(|_| BatchError::ManifestUnwritable)?;
    writeln!(manifest, "{}", manifest_header(opts, tier, entries.len()))
        .map_err(|_| BatchError::ManifestUnwritable)?;

    let mut summary = Summary::default();
    let total = entries.len();
    for (index, (relative, is_dir)) in entries.into_iter().enumerate() {
        let item = if is_dir {
            summary.skipped_directories += 1;
            Item {
                path: relative,
                output: None,
                outcome: Outcome::SkippedDirectory,
            }
        } else {
            process(input, output, &pipeline, opts, &relative, &mut summary)
        };
        // Counts and outcome classes only. The path is in the manifest.
        let _ = writeln!(
            progress,
            "deid: [{}/{total}] {}",
            index + 1,
            item.outcome.status()
        );
        writeln!(manifest, "{}", manifest_line(&item))
            .map_err(|_| BatchError::ManifestUnwritable)?;
        summary.items.push(item);
    }

    writeln!(manifest, "{}", manifest_summary(&summary))
        .map_err(|_| BatchError::ManifestUnwritable)?;
    manifest
        .flush()
        .map_err(|_| BatchError::ManifestUnwritable)?;
    Ok(summary)
}

/// Mask one file and write it, recording whatever happened.
fn process(
    input: &Path,
    output: &Path,
    pipeline: &Pipeline,
    opts: BatchOpts,
    relative: &Path,
    summary: &mut Summary,
) -> Item {
    let destination = output_path(relative, opts.format);
    let outcome = read_utf8(&input.join(relative)).and_then(|source| {
        let result = mask_one(pipeline, &source)?;
        let rendered = format::render(opts.format, &result, opts.threshold);
        write_output(&output.join(&destination), &rendered)?;
        let (_, masked, _) = format::counts(&result, None);
        summary.total_spans += masked;
        Ok(Outcome::Masked {
            masked,
            kept: result.span_map.len() - masked,
            labels: histogram(&result),
        })
    });
    match outcome {
        Ok(outcome) => {
            summary.masked += 1;
            Item {
                path: relative.to_path_buf(),
                output: Some(destination),
                outcome,
            }
        }
        Err(failure) => {
            summary.failed += 1;
            Item {
                path: relative.to_path_buf(),
                // No output path on a failure, and that is load-bearing: a
                // manifest naming an output file that does not exist would send
                // an operator looking for a masked document that was never
                // written.
                output: None,
                outcome: Outcome::Failed(failure),
            }
        }
    }
}

/// Read a file as UTF-8, distinguishing "cannot read" from "not text".
fn read_utf8(path: &Path) -> Result<String, Failure> {
    let bytes = std::fs::read(path).map_err(|_| Failure::Unreadable)?;
    String::from_utf8(bytes).map_err(|_| Failure::NotUtf8)
}

/// Write one masked document, creating its parent directories.
fn write_output(path: &Path, rendered: &str) -> Result<(), Failure> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| Failure::WriteFailed)?;
    }
    // write, not a format macro: document bytes must never enter a format
    // string, and this file is the one legitimate destination for them.
    std::fs::write(path, rendered.as_bytes()).map_err(|_| Failure::WriteFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{note, tckn};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh scratch directory per test, without a temp-file dependency.
    fn scratch(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("deid-batch-{tag}-{unique}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch dir");
        path
    }

    fn write(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, body).expect("fixture file");
    }

    fn opts() -> BatchOpts {
        BatchOpts {
            recursive: false,
            format: Format::Text,
            threshold: None,
            mask: mask::Opts::default(),
        }
    }

    fn run_batch(input: &Path, output: &Path, opts: BatchOpts) -> Summary {
        run(
            input,
            output,
            Tier::SafeHarbor,
            opts,
            &crate::l3::L3Config::default(),
            &crate::l2::L2Config::default(),
            &mut Vec::new(),
        )
        .expect("batch run")
    }

    fn manifest_of(output: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(output.join(MANIFEST_NAME))
            .expect("manifest")
            .lines()
            .map(|line| serde_json::from_str(line).expect("manifest line is JSON"))
            .collect()
    }

    #[test]
    fn every_document_is_masked_and_written() {
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "a.txt", &note());
        write(&input, "b.txt", "TCKN yok, sadece metin.");

        let summary = run_batch(&input, &output, opts());
        assert_eq!(summary.masked, 2);
        assert_eq!(summary.failed, 0);
        assert!(summary.is_clean());

        let masked = std::fs::read_to_string(output.join("a.txt")).expect("output a");
        assert!(!masked.contains(&tckn()), "the TCKN survived masking");
        assert!(masked.contains("carcinoma'lı"));
        // The honest boundary: no names are masked, and the batch does not
        // pretend otherwise.
        assert!(masked.contains("Ayşe Yılmaz"));
        assert!(std::fs::read_to_string(output.join("b.txt")).is_ok());
    }

    #[test]
    fn a_failure_does_not_stop_the_run_and_every_failure_is_reported() {
        // THE batch invariant. The second file is not UTF-8; the third must
        // still be processed, and both the failure and the success must appear.
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "1-ok.txt", &note());
        std::fs::write(input.join("2-bad.txt"), [0xff, 0xfe, 0x00]).expect("binary fixture");
        write(&input, "3-ok.txt", "ikinci belge.");

        let summary = run_batch(&input, &output, opts());
        assert_eq!(summary.items.len(), 3, "a batch dropped an entry");
        assert_eq!(summary.masked, 2, "the run stopped at the first failure");
        assert_eq!(summary.failed, 1);
        assert!(!summary.is_clean());

        let failures = summary.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, Path::new("2-bad.txt"));
        assert_eq!(failures[0].1, Failure::NotUtf8);

        // The failing file produced no output, and the manifest says so rather
        // than naming a file that does not exist.
        assert!(!output.join("2-bad.txt").exists());
        let failed_record = summary
            .items
            .iter()
            .find(|item| item.path == Path::new("2-bad.txt"))
            .expect("record");
        assert_eq!(failed_record.output, None);
    }

    #[test]
    fn the_manifest_records_every_entry_in_order_with_a_header_and_a_summary() {
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "a.txt", &note());
        std::fs::write(input.join("b.bin"), [0x80]).expect("binary fixture");
        std::fs::create_dir_all(input.join("nested")).expect("subdir");

        let summary = run_batch(&input, &output, opts());
        let records = manifest_of(&output);
        assert_eq!(records.len(), 5, "header + three items + summary");
        assert_eq!(records[0]["record"], serde_json::json!("run"));
        assert_eq!(records[0]["format"], serde_json::json!("text"));
        assert!(records[0]["coverage"]
            .as_str()
            .expect("coverage")
            .contains("no names are masked"));

        assert_eq!(records[1]["path"], serde_json::json!("a.txt"));
        assert_eq!(records[1]["status"], serde_json::json!("masked"));
        assert!(records[1]["labels"]["TCKN"].as_u64().expect("tckn count") >= 1);

        assert_eq!(records[2]["path"], serde_json::json!("b.bin"));
        assert_eq!(records[2]["status"], serde_json::json!("failed"));
        assert_eq!(records[2]["error"], serde_json::json!("not_utf8"));

        assert_eq!(records[3]["path"], serde_json::json!("nested"));
        assert_eq!(records[3]["status"], serde_json::json!("skipped_directory"));

        let trailer = &records[4];
        assert_eq!(trailer["record"], serde_json::json!("summary"));
        assert_eq!(trailer["entries"], serde_json::json!(3));
        assert_eq!(trailer["masked"], serde_json::json!(1));
        assert_eq!(trailer["failed"], serde_json::json!(1));
        assert_eq!(trailer["skipped_directories"], serde_json::json!(1));
        assert_eq!(
            trailer["total_masked_spans"],
            serde_json::json!(summary.total_spans)
        );
    }

    #[test]
    fn no_manifest_record_carries_document_text() {
        // The manifest sits next to the masked outputs and is the artifact most
        // likely to be copied into a ticket. It carries paths, counts and
        // labels; it must never carry a fragment of a note.
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "a.txt", &note());
        run_batch(&input, &output, opts());
        let rendered = std::fs::read_to_string(output.join(MANIFEST_NAME)).expect("manifest");
        assert!(!rendered.contains(&tckn()));
        assert!(!rendered.contains("Ayşe"));
        assert!(!rendered.contains("carcinoma"));
    }

    #[test]
    fn a_subdirectory_is_recorded_rather_than_passed_over() {
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "top.txt", "bir");
        write(&input, "sub/inner.txt", "iki");

        let summary = run_batch(&input, &output, opts());
        assert_eq!(summary.masked, 1);
        assert_eq!(summary.skipped_directories, 1);
        assert!(summary
            .items
            .iter()
            .any(|item| item.outcome == Outcome::SkippedDirectory));
        assert!(
            !output.join("sub/inner.txt").exists(),
            "a non-recursive run descended anyway"
        );
    }

    #[test]
    fn recursive_masks_the_whole_tree_and_mirrors_it() {
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "top.txt", &note());
        write(&input, "sub/inner.txt", &note());
        write(&input, "sub/deeper/leaf.txt", &note());

        let summary = run_batch(
            &input,
            &output,
            BatchOpts {
                recursive: true,
                ..opts()
            },
        );
        assert_eq!(summary.masked, 3);
        assert_eq!(summary.skipped_directories, 0);
        for path in ["top.txt", "sub/inner.txt", "sub/deeper/leaf.txt"] {
            let masked = std::fs::read_to_string(output.join(path)).expect(path);
            assert!(!masked.contains(&tckn()), "{path} kept its TCKN");
        }
    }

    #[test]
    fn the_enumeration_order_is_stable_so_two_manifests_can_be_diffed() {
        let input = scratch("in");
        write(&input, "c.txt", "uc");
        write(&input, "a.txt", "bir");
        write(&input, "b.txt", "iki");
        let first = run_batch(&input, &scratch("out"), opts());
        let second = run_batch(&input, &scratch("out"), opts());
        let paths = |summary: &Summary| -> Vec<PathBuf> {
            summary.items.iter().map(|item| item.path.clone()).collect()
        };
        assert_eq!(paths(&first), paths(&second));
        assert_eq!(
            paths(&first),
            vec![
                PathBuf::from("a.txt"),
                PathBuf::from("b.txt"),
                PathBuf::from("c.txt")
            ]
        );
    }

    #[test]
    fn the_formats_choose_the_output_name() {
        assert_eq!(
            output_path(Path::new("a/b.txt"), Format::Text),
            PathBuf::from("a/b.txt")
        );
        // Appended, not replaced: `note.txt` -> `note.txt.json` cannot collide
        // with a genuine `note.json` in the same input tree.
        assert_eq!(
            output_path(Path::new("a/b.txt"), Format::Json),
            PathBuf::from("a/b.txt.json")
        );
        assert_eq!(
            output_path(Path::new("b.txt"), Format::Csv),
            PathBuf::from("b.txt.csv")
        );
    }

    #[test]
    fn a_json_batch_writes_parseable_documents() {
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "a.txt", &note());
        run_batch(
            &input,
            &output,
            BatchOpts {
                format: Format::Json,
                ..opts()
            },
        );
        let rendered = std::fs::read_to_string(output.join("a.txt.json")).expect("output");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert!(parsed["text"].is_string());
        assert!(!rendered.contains(&tckn()));
    }

    #[test]
    fn a_reporting_threshold_does_not_change_what_is_masked() {
        // I2 through the batch path. The two runs cannot be compared BYTE for
        // byte -- each draws a fresh L5 salt, so the surrogates legitimately
        // differ -- so the comparison is over what was masked: the same spans,
        // the same labels, and the original absent from both outputs. The
        // byte-identity statement lives in `format.rs`, where a fixed salt makes
        // it meaningful.
        let input = scratch("in");
        let plain = scratch("out");
        let filtered = scratch("out");
        write(&input, "a.txt", &note());
        run_batch(&input, &plain, opts());
        run_batch(
            &input,
            &filtered,
            BatchOpts {
                threshold: Some(0.99),
                ..opts()
            },
        );
        let spans_of = |output: &Path| -> serde_json::Value {
            let record = &manifest_of(output)[1];
            serde_json::json!({
                "masked": record["masked_spans"],
                "kept": record["kept_spans"],
                "labels": record["labels"],
            })
        };
        assert_eq!(
            spans_of(&plain),
            spans_of(&filtered),
            "the reporting threshold changed what was masked"
        );
        assert!(spans_of(&plain)["masked"].as_u64().expect("count") > 0);
        for output in [&plain, &filtered] {
            let masked = std::fs::read_to_string(output.join("a.txt")).expect("output");
            assert!(!masked.contains(&tckn()), "the TCKN survived masking");
        }
    }

    #[test]
    fn writing_into_the_input_tree_is_refused() {
        // Masked output written over the originals destroys the only copy of
        // the clinical record, and a recursive run would re-process its own
        // output. Both are refusals, not warnings.
        let input = scratch("in");
        write(&input, "a.txt", "bir");
        for candidate in [input.clone(), input.join("masked"), input.join("a/../b")] {
            let refused = run(
                &input,
                &candidate,
                Tier::SafeHarbor,
                opts(),
                &crate::l3::L3Config::default(),
                &crate::l2::L2Config::default(),
                &mut Vec::new(),
            );
            assert!(
                matches!(refused, Err(BatchError::OutputInsideInput)),
                "{} was accepted as an output directory",
                candidate.display()
            );
        }
    }

    #[test]
    fn a_missing_input_directory_is_refused_before_anything_is_created() {
        let output = scratch("out");
        let refused = run(
            Path::new("/nonexistent/clinical-corpus"),
            &output,
            Tier::SafeHarbor,
            opts(),
            &crate::l3::L3Config::default(),
            &crate::l2::L2Config::default(),
            &mut Vec::new(),
        );
        assert!(matches!(refused, Err(BatchError::NotADirectory)));
        assert!(!output.join(MANIFEST_NAME).exists());
    }

    #[test]
    fn an_empty_directory_produces_an_empty_but_present_manifest() {
        // A run over nothing must still leave a record saying it ran over
        // nothing. The alternative is an operator who cannot tell an empty
        // corpus from a batch that never started.
        let input = scratch("in");
        let output = scratch("out");
        let summary = run_batch(&input, &output, opts());
        assert!(summary.items.is_empty());
        assert!(summary.is_clean());
        let records = manifest_of(&output);
        assert_eq!(records.len(), 2, "header and summary");
        assert_eq!(records[1]["entries"], serde_json::json!(0));
    }

    #[test]
    fn progress_reports_counts_and_never_a_path() {
        // A clinical export routinely names files after patients. Progress goes
        // to stderr, stderr goes to a log; the paths live in the manifest.
        let input = scratch("in");
        let output = scratch("out");
        write(&input, "ayse-yilmaz-2026.txt", &note());
        let mut progress = Vec::new();
        run(
            &input,
            &output,
            Tier::SafeHarbor,
            opts(),
            &crate::l3::L3Config::default(),
            &crate::l2::L2Config::default(),
            &mut progress,
        )
        .expect("run");
        let printed = String::from_utf8(progress).expect("utf8");
        assert!(printed.contains("[1/1]"));
        assert!(printed.contains("masked"));
        assert!(
            !printed.contains("ayse"),
            "the progress line named a file: {printed}"
        );
    }

    #[test]
    fn one_salt_serves_the_whole_batch_so_a_patient_is_consistent_across_notes() {
        // Two notes carrying the SAME identifier must receive the SAME
        // surrogate, or a longitudinal record becomes two unrelated patients.
        let input = scratch("in");
        let output = scratch("out");
        let shared = format!("Hasta, TCKN {}. Ilk not.", tckn());
        let again = format!("Ayni hasta, TCKN {}. Ikinci not.", tckn());
        write(&input, "1.txt", &shared);
        write(&input, "2.txt", &again);
        run_batch(&input, &output, opts());

        let extract = |name: &str| -> String {
            let body = std::fs::read_to_string(output.join(name)).expect(name);
            body.split_whitespace()
                .find(|token| {
                    token
                        .trim_end_matches('.')
                        .chars()
                        .all(|c| c.is_ascii_digit())
                })
                .map(|token| token.trim_end_matches('.').to_owned())
                .expect("a surrogate TCKN in the masked output")
        };
        let first = extract("1.txt");
        assert_eq!(first, extract("2.txt"));
        assert_ne!(first, tckn(), "the original survived");
    }
}
