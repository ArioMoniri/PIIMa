//! `deid` — the native CLI.
//!
//! # Command surface
//!
//! ```text
//! deid mask [FILE] [--tier safe-harbor|expert]   de-identify a TEXT document
//! deid mask --batch DIR --out DIR [--recursive]  de-identify a directory
//! deid mask --format text|json|csv|html          output shape (default text)
//! deid mask --confidence-threshold F             filter the REPORT, never the masking
//! deid mask --placeholder-labels                 opt OUT of L5 surrogates
//! deid mask --model FILE.gguf --runtime BIN      the LOCAL model L3 needs
//! deid mask --no-medical-allowlist               opt OUT of the class C vocabulary
//! deid mask-file IN --out OUT                   de-identify a PDF/DOCX/CSV/JSON file
//! deid mask-file --input-format auto|pdf|...     override format detection (default auto)
//! deid mask-file --allow-images                  process a page carrying unreadable images anyway
//! deid doctor                                    what this machine can and cannot do
//! deid update [--check]                          check for a new release
//! deid pull [--from DIR]                         fetch model weights (M3)
//! deid version                                   print the version
//! deid --offline <command>                       disable all network activity
//! ```
//!
//! # Batch semantics
//!
//! `--batch` never silently skips a file. Every entry in the input tree produces
//! one manifest record, failures are recorded and the run continues, and the
//! process exits non-zero if any item failed. See `src/batch.rs` for why each of
//! those is not negotiable: a skipped file in a de-identification batch is an
//! unredacted document that somebody believes is redacted.
//!
//! # `--confidence-threshold` is not a masking control
//!
//! It filters the entity REPORT and never what gets masked, and it prints a
//! warning saying so on every run. Invariant I2: recall is the product. See
//! `src/format.rs`.
//!
//! # Where the update check is allowed to happen
//!
//! At process start, before dispatch, for commands that never open a document —
//! and nowhere else. The `Command::Mask` arm below contains no reference to the
//! updater and neither does `src/mask.rs`; `tests/mask_path_is_offline.rs`
//! enforces both. `mask` is excluded even though the check would begin before the
//! document is read, because the check is asynchronous and would otherwise still
//! be in flight while the note is in memory.
//!
//! # Honesty about stubs
//!
//! `deid pull` is not implemented. It says so and exits non-zero rather than
//! printing a reassuring message and doing nothing, because a command that
//! appears to have fetched weights and did not is how a pipeline silently runs
//! with no detector.

mod batch;
mod config;
mod doctor;
#[cfg(test)]
mod fixtures;
mod format;
mod l2;
mod l3;
mod mask;
mod maskfile;
mod notice;
mod transport;
mod update;
mod verify;

use std::io::Write;
use std::process::ExitCode;
use std::time::SystemTime;

use config::{CliFlags, Config, EnvView};
use deid_tr_core::Tier;
use l2::{L2Config, L2Flags};
use l3::{L3Config, L3Flags};

/// The running version, from the workspace manifest.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for a command that exists but is not implemented yet.
const EXIT_UNIMPLEMENTED: u8 = 2;

enum Command {
    Mask {
        path: Option<String>,
        tier: Tier,
        opts: mask::Opts,
        format: format::Format,
        threshold: Option<f32>,
        /// `Some` when `--batch` was given: the input directory and `--out`.
        batch: Option<BatchTargets>,
    },
    /// `mask-file`: a document whose format is not plain text.
    ///
    /// Separate from `Mask` because the contract is bytes-in/bytes-out and the
    /// destination is a file. See `src/maskfile.rs`.
    MaskFile {
        input: String,
        out: Option<String>,
        tier: Tier,
        opts: mask::Opts,
        input_format: Option<deid_tr_files::Format>,
        /// Continue when a page carries images deid-tr cannot read, instead of
        /// refusing. The images are reported either way.
        allow_images: bool,
    },
    /// A flag carried a value this binary cannot parse. Named separately from
    /// `Usage` because falling back to a default here would silently change what
    /// the operator asked for -- `--confidence-threshold hign` reverting to
    /// "no threshold" is a reporting change nobody chose.
    BadValue {
        flag: &'static str,
    },
    /// `doctor`: report which layers can actually run here, and how to fix the
    /// ones that cannot. Deliberately not a `mask` flag -- an operator asking
    /// why the deep tier is unavailable has no document in play.
    Doctor,
    Update,
    Pull {
        from: Option<String>,
    },
    Version,
    Usage {
        unknown: bool,
    },
}

/// The per-layer configuration one run resolves to.
///
/// Grouped rather than passed as two parameters, for the reason `mask::Build`
/// gives for grouping its own three: they always travel together and always
/// come from the same resolution, and threading them separately turns every
/// call site into positional soup one layer at a time.
struct Layers<'a> {
    l3: &'a L3Config,
    l2: &'a L2Config,
}

/// The two directories a batch run needs.
struct BatchTargets {
    input: String,
    output: Option<String>,
    recursive: bool,
}

/// The per-layer paths, so `parse_args` keeps one return value for "everything
/// the layers were told" instead of growing a tuple element per layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LayerFlags {
    l3: L3Flags,
    l2: L2Flags,
}

fn parse_args(args: &[String]) -> (CliFlags, LayerFlags, Command) {
    let mut flags = CliFlags::default();
    let mut rest = Vec::new();
    for arg in args {
        if arg == "--offline" {
            flags.offline = true;
        } else {
            rest.push(arg.clone());
        }
    }

    let Some(verb) = rest.first().map(String::as_str) else {
        return (
            flags,
            LayerFlags::default(),
            Command::Usage { unknown: false },
        );
    };
    let tail = &rest[1..];
    let value_of = |name: &str| {
        tail.iter()
            .position(|a| a == name)
            .and_then(|i| tail.get(i + 1))
            .cloned()
    };

    // Read for EVERY verb, not just `mask`. `doctor` needs them to report what
    // this invocation would actually use, and reporting a different resolution
    // than the one `mask` would perform is how a diagnostic command starts
    // lying.
    let l3_flags = LayerFlags {
        l3: L3Flags {
            model: value_of("--model"),
            runtime: value_of("--runtime"),
        },
        l2: L2Flags {
            model: value_of(l2::FLAG),
        },
    };

    let command = match verb {
        "mask" => {
            let tier = match value_of("--tier").as_deref() {
                Some("expert") | Some("expert-determination") => Tier::ExpertDetermination,
                _ => Tier::SafeHarbor,
            };
            // Every flag that takes a value, so a value is never mistaken for
            // the positional input file. Listed once and consulted once,
            // because the previous shape special-cased --tier alone and would
            // have read `--out masked/` as the document to mask.
            let valued = [
                "--tier",
                "--format",
                "--confidence-threshold",
                "--batch",
                "--out",
                "--model",
                "--runtime",
                l2::FLAG,
            ];
            let taken: Vec<String> = valued.iter().filter_map(|name| value_of(name)).collect();
            let path = tail
                .iter()
                .find(|a| !a.starts_with('-') && !taken.contains(a))
                .cloned();
            // Opt-OUTS, both of them. A caller who passes neither gets the
            // audited medical vocabulary and real surrogates; the degraded
            // configurations have to be asked for by name.
            let opts = mask::Opts {
                placeholder_labels: tail.iter().any(|a| a == "--placeholder-labels"),
                no_medical_allowlist: tail.iter().any(|a| a == "--no-medical-allowlist"),
            };
            let format = match value_of("--format") {
                Some(value) => match format::Format::parse(&value) {
                    Some(format) => format,
                    None => return (flags, l3_flags, Command::BadValue { flag: "--format" }),
                },
                None => format::Format::default(),
            };
            let threshold = match value_of("--confidence-threshold") {
                Some(value) => match value.parse::<f32>() {
                    Ok(floor) if (0.0..=1.0).contains(&floor) => Some(floor),
                    _ => {
                        return (
                            flags,
                            l3_flags,
                            Command::BadValue {
                                flag: "--confidence-threshold",
                            },
                        )
                    }
                },
                None => None,
            };
            let batch = value_of("--batch").map(|input| BatchTargets {
                input,
                output: value_of("--out"),
                recursive: tail.iter().any(|a| a == "--recursive"),
            });
            Command::Mask {
                path,
                tier,
                opts,
                format,
                threshold,
                batch,
            }
        }
        "mask-file" => {
            let tier = match value_of("--tier").as_deref() {
                Some("expert") | Some("expert-determination") => Tier::ExpertDetermination,
                _ => Tier::SafeHarbor,
            };
            // Same rule as `mask`: every flag that takes a value is listed
            // once, so a value can never be mistaken for the positional input.
            let valued = [
                "--tier",
                "--out",
                "--input-format",
                "--model",
                "--runtime",
                l2::FLAG,
            ];
            let taken: Vec<String> = valued.iter().filter_map(|name| value_of(name)).collect();
            let input = tail
                .iter()
                .find(|a| !a.starts_with('-') && !taken.contains(a))
                .cloned();
            let input_format =
                match maskfile::parse_input_format(value_of("--input-format").as_deref()) {
                    Ok(format) => format,
                    Err(_) => {
                        return (
                            flags,
                            l3_flags,
                            Command::BadValue {
                                flag: "--input-format",
                            },
                        )
                    }
                };
            match input {
                Some(input) => Command::MaskFile {
                    input,
                    out: value_of("--out"),
                    tier,
                    opts: mask::Opts {
                        placeholder_labels: tail.iter().any(|a| a == "--placeholder-labels"),
                        no_medical_allowlist: tail.iter().any(|a| a == "--no-medical-allowlist"),
                    },
                    input_format,
                    allow_images: tail.iter().any(|a| a == "--allow-images"),
                },
                // No positional input: `mask-file` cannot read stdin, because
                // format detection uses the file name as a tie-breaker between
                // the text-shaped formats and a stream has none.
                None => Command::BadValue { flag: "IN" },
            }
        }
        "doctor" => Command::Doctor,
        "update" => Command::Update,
        "pull" => Command::Pull {
            from: value_of("--from"),
        },
        "version" | "--version" | "-V" => Command::Version,
        "help" | "--help" | "-h" => Command::Usage { unknown: false },
        _ => Command::Usage { unknown: true },
    };
    (flags, l3_flags, command)
}

/// Resolve both configurations from one read of the environment and the file.
///
/// One read, because two would let the updater and L3 disagree about what the
/// machine says -- and `deid doctor` exists to report exactly what `deid mask`
/// would use.
fn load_config(flags: &CliFlags, layers: &LayerFlags) -> (Config, L3Config, L2Config) {
    let env = EnvView::from_process();
    let file = config::load_file(&env).unwrap_or_default();
    (
        config::resolve(flags, &env, &file),
        l3::resolve(&layers.l3, &env, &file),
        l2::resolve(&layers.l2, &env, &file),
    )
}

/// Start a check on a detached thread and return immediately.
///
/// Deliberately never joined. If the process finishes its real work first the
/// check dies with it, which is the correct priority: the tool's job is masking,
/// and an update check has no claim on the operator's time. This is what makes
/// the check non-blocking in the strong sense — there is no code path on which
/// its duration is added to the command's duration.
fn spawn_startup_check(config: &Config) {
    if !config.checks_allowed() {
        return;
    }
    let config = config.clone();
    let install_target = std::env::current_exe().ok();
    std::thread::spawn(move || {
        // The result is intentionally discarded. Failure is silent and
        // non-fatal; a user who wants to know runs `deid update`.
        let _ = update::run_check(
            &config,
            VERSION,
            &transport::TcpProbe::new(),
            &transport::HttpsSource,
            SystemTime::now(),
            install_target.as_deref(),
        );
    });
}

fn report(outcome: &update::Outcome, out: &mut dyn Write) {
    let _ = match outcome {
        update::Outcome::Blocked(update::Blocked::Disabled(by)) => writeln!(
            out,
            "deid: update checks are disabled by {}",
            by.as_str()
        ),
        update::Outcome::Blocked(update::Blocked::NoEndpoint) => writeln!(
            out,
            "deid: no release host is configured (set update_host in your config file), so nothing was sent"
        ),
        update::Outcome::Blocked(update::Blocked::AirGapSuppressed) => writeln!(
            out,
            "deid: a previous check found no route out, so checks are paused for 24h"
        ),
        update::Outcome::AirGapped => writeln!(
            out,
            "deid: the release host is unreachable; treating this install as air-gapped"
        ),
        update::Outcome::Unreachable => {
            writeln!(out, "deid: the update check did not complete")
        }
        update::Outcome::UpToDate => writeln!(out, "deid: {VERSION} is current"),
        update::Outcome::Installed { version } => {
            writeln!(out, "deid: verified and installed {version}")
        }
        update::Outcome::Staged { version, path } => writeln!(
            out,
            "deid: verified {version} but could not replace the running binary; it is staged at {}",
            path.display()
        ),
        update::Outcome::NotifyOnly { version, .. } => writeln!(
            out,
            "deid: {version} is available but was NOT installed, because no release signing key is pinned in this configuration. Set update_public_key, or upgrade manually."
        ),
        update::Outcome::Refused(err) => writeln!(out, "deid: {err}"),
    };
}

/// Run `deid mask --batch`, reporting every outcome.
///
/// The exit code is non-zero when ANY item failed. A batch that masked
/// ninety-nine of a hundred documents and exited zero is a batch whose one
/// unmasked document reaches whatever comes next in the pipeline.
fn run_batch(
    targets: &BatchTargets,
    tier: Tier,
    opts: mask::Opts,
    layers: &Layers<'_>,
    format: format::Format,
    threshold: Option<f32>,
    stderr: &mut dyn Write,
) -> ExitCode {
    let Some(output) = targets.output.as_deref() else {
        let _ = writeln!(stderr, "deid: {}", batch::BatchError::NoOutputDirectory);
        return ExitCode::FAILURE;
    };
    if threshold.is_some() {
        let _ = writeln!(stderr, "deid: {}", format::RECALL_WARNING);
    }
    let options = batch::BatchOpts {
        recursive: targets.recursive,
        format,
        threshold,
        mask: opts,
    };
    let summary = match batch::run(
        std::path::Path::new(&targets.input),
        std::path::Path::new(output),
        tier,
        options,
        layers.l3,
        layers.l2,
        stderr,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            let _ = writeln!(stderr, "deid: {err}");
            return ExitCode::FAILURE;
        }
    };

    let _ = writeln!(
        stderr,
        "deid: {} masked, {} failed, {} directory(ies) not descended into, {} span(s) masked in total",
        summary.masked, summary.failed, summary.skipped_directories, summary.total_spans
    );
    // The failing PATHS are in the manifest and not on stderr: a clinical export
    // routinely names files after patients, and stderr goes to a log. The
    // operator is pointed at the file that does carry them.
    for (index, (_, failure)) in summary.failures().iter().enumerate() {
        let _ = writeln!(stderr, "deid: failure {}: the file {failure}", index + 1);
    }
    if summary.is_clean() {
        ExitCode::SUCCESS
    } else {
        let _ = writeln!(
            stderr,
            "deid: {} item(s) were NOT masked. Their paths are in {}/{}. Nothing was skipped silently, and this run exits non-zero.",
            summary.failed,
            output,
            batch::MANIFEST_NAME
        );
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (flags, layer_flags, command) = parse_args(&args);
    let (config, l3, l2) = load_config(&flags, &layer_flags);

    let mut stderr = std::io::stderr();
    // Before anything else, including before any check is spawned: nobody
    // discovers this tool's network behaviour from a packet capture.
    notice::show_once(&config, &mut stderr);

    match command {
        // NOTE TO ANY FUTURE EDITOR: this arm must not reference `update` or
        // `transport`. A clinical document is about to be in memory.
        // A FILE and a --batch directory together is a contradiction, and it is
        // refused rather than resolved. Silently preferring one would mask the
        // thing the operator did not name and leave the thing they did name
        // untouched, which in this tool means an unredacted document they
        // believe is redacted.
        Command::Mask {
            path: Some(_),
            batch: Some(_),
            ..
        } => {
            let _ = writeln!(
                stderr,
                "deid: --batch takes a directory and cannot be combined with a FILE argument. Run one or the other; nothing was masked."
            );
            ExitCode::FAILURE
        }
        Command::Mask {
            path: None,
            tier,
            opts,
            format,
            threshold,
            batch: Some(targets),
        } => run_batch(
            &targets,
            tier,
            opts,
            &Layers { l3: &l3, l2: &l2 },
            format,
            threshold,
            &mut stderr,
        ),
        Command::Mask {
            path,
            tier,
            opts,
            format,
            threshold,
            batch: None,
        } => {
            let mut stdout = std::io::stdout();
            match mask::run(
                path.as_deref(),
                &mask::Build {
                    tier,
                    opts,
                    l3: &l3,
                    l2: &l2,
                },
                format,
                threshold,
                &mut stdout,
                &mut stderr,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    let _ = writeln!(stderr, "deid: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        // Also a document arm: `maskfile` holds a clinical document in memory,
        // so it must not reference `update` or `transport` either.
        Command::MaskFile {
            input,
            out,
            tier,
            opts,
            input_format,
            allow_images,
        } => {
            let destination = match out.as_deref() {
                Some("-") => maskfile::Destination::Stdout,
                Some(path) => maskfile::Destination::Path(std::path::PathBuf::from(path)),
                None => {
                    let _ = writeln!(
                        stderr,
                        "deid: mask-file needs --out FILE (or --out - for stdout); nothing was masked."
                    );
                    return ExitCode::FAILURE;
                }
            };
            let mut stdout = std::io::stdout();
            match maskfile::run(
                std::path::Path::new(&input),
                &destination,
                &mask::Build {
                    tier,
                    opts,
                    l3: &l3,
                    l2: &l2,
                },
                input_format,
                allow_images,
                &mut stdout,
                &mut stderr,
            ) {
                Ok(_) => ExitCode::SUCCESS,
                Err(err) => {
                    let _ = writeln!(stderr, "deid: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::BadValue { flag } => {
            let _ = writeln!(
                stderr,
                "deid: {flag} needs a value this binary can parse; nothing was masked."
            );
            ExitCode::FAILURE
        }
        Command::Doctor => {
            // stdout, not stderr: this is the command's OUTPUT, and an operator
            // sending it to a colleague should be able to pipe it.
            let mut stdout = std::io::stdout();
            let _ = doctor::report(&l3, &l2, &mut stdout);
            ExitCode::SUCCESS
        }
        Command::Update => {
            // Explicit invocation: synchronous, and it clears any air-gap
            // suppression first, because a person typing `deid update` is
            // telling us the network situation may have changed.
            update::clear_air_gap(&config.state_dir);
            let outcome = update::run_check(
                &config,
                VERSION,
                &transport::TcpProbe::new(),
                &transport::HttpsSource,
                SystemTime::now(),
                std::env::current_exe().ok().as_deref(),
            );
            report(&outcome, &mut stderr);
            ExitCode::SUCCESS
        }
        Command::Pull { from } => {
            spawn_startup_check(&config);
            let _ = writeln!(
                stderr,
                "deid pull is NOT IMPLEMENTED yet: no model weights are fetched, staged, or verified by this build, and none are bundled. It lands with the L2 ensemble (M3). Nothing was downloaded."
            );
            if let Some(dir) = from {
                let _ = writeln!(
                    stderr,
                    "deid: --from {dir} was parsed but not used; the air-gapped bundle path lands with the same milestone."
                );
            }
            ExitCode::from(EXIT_UNIMPLEMENTED)
        }
        Command::Version => {
            spawn_startup_check(&config);
            let _ = writeln!(std::io::stdout(), "deid {VERSION}");
            ExitCode::SUCCESS
        }
        Command::Usage { unknown } => {
            let _ = writeln!(
                stderr,
                "usage: deid [--offline] <mask|mask-file|update|pull|version> [args]\n\
                 \n\
                   mask [FILE] [--tier safe-harbor|expert]  de-identify a document (stdin when FILE is omitted)\n\
                        [--format text|json|csv|html]       output shape (default text: the document, nothing else)\n\
                        [--confidence-threshold F]          filter the entity REPORT only; NEVER changes what is masked\n\
                        [--batch DIR --out DIR]             de-identify every file in DIR, writing to --out\n\
                        [--recursive]                       with --batch, descend into subdirectories\n\
                        [--placeholder-labels]              write [LABEL] instead of a surrogate; every patient in the note collapses onto one token\n\
                        [--no-medical-allowlist]            run L4 with no medical vocabulary; carcinoma, costa and Adalat will be masked\n\
                        [--model FILE.gguf]                 LOCAL weights for the L3 sweep; required by --tier expert\n\
                        [--runtime BIN]                     LOCAL inference executable for the L3 sweep; required by --tier expert\n\
                        [--l2-model DIR]                    LOCAL directory holding the L2 ONNX checkpoint and its tokenizer\n\
                   mask-file IN --out OUT                   de-identify a PDF, DOCX, CSV, JSON or JSONL file\n\
                        [--input-format auto|txt|csv|json|jsonl|docx|pdf]  default auto: content first, name second\n\
                        [--out -]                           write the redacted bytes to stdout instead of a file\n\
                        [--allow-images]                    process a PDF page that carries images anyway; without this such a page is REFUSED, and with it the images are still reported by page and pixel size\n\
                   doctor                                   report which layers can run here, and how to fix the ones that cannot\n\
                   update                                   check for a new release\n\
                   pull [--from DIR]                        fetch model weights (not implemented)\n\
                   version                                  print the version\n\
                 \n\
                 COVERAGE: rule-detectable identifiers only. This build has NO ONNX Runtime\n\
                 linked, so L2 cannot run and deid masks NO NAMES. TCKN, VKN, SGK, IBAN, phone, MRN, email and\n\
                 dates are masked; PATIENT_NAME, CLINICIAN_NAME and RELATIVE_NAME are not.\n\
                 --tier expert does not change that: it adds the L3 quasi-identifier sweep,\n\
                 which still masks no names. Run `deid doctor` for this machine's answer.\n\
                 \n\
                 --tier expert needs a LOCAL model you supply: --model FILE.gguf and\n\
                 --runtime BIN, or DEID_L3_MODEL / DEID_L3_RUNTIME, or l3_model / l3_runtime\n\
                 in your config file (flag > env > config file). No weights ship with this\n\
                 repository and nothing is downloaded at inference time. If L3 cannot be\n\
                 wired, the run FAILS -- it never falls back to Safe Harbor.\n\
                 \n\
                 --l2-model DIR names a checkpoint DIRECTORY on this machine (or DEID_L2_MODEL,\n\
                 or l2_model in your config file; flag > env > config file). It is never a\n\
                 model id and nothing is downloaded. This build validates the directory and\n\
                 then REFUSES, because no inference runtime is linked: it masks no names with\n\
                 the flag and no names without it, and it never falls back to running L1 alone\n\
                 after you asked for a model.\n\
                 \n\
                 A --batch run never skips a file: every entry gets a manifest record, every\n\
                 failure is recorded, the run continues, and the exit code is non-zero if any\n\
                 item failed.\n\
                 \n\
                 Automatic update checks are ON by default. Disable with --offline,\n\
                 DEID_NO_UPDATE=1, or auto_update = false in your config file."
            );
            if unknown {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn the_l2_model_flag_is_read_and_its_value_is_not_taken_for_the_document() {
        // The bug this listing exists to prevent: a valued flag missing from
        // `valued` makes its VALUE the positional input, so
        // `deid mask --l2-model ./ckpt note.txt` would try to mask `./ckpt` and
        // leave `note.txt` alone. In this tool that is an unredacted document
        // the operator believes was redacted.
        for raw in [
            vec!["mask", "--l2-model", "./ckpt", "note.txt"],
            vec!["mask", "note.txt", "--l2-model", "./ckpt"],
        ] {
            let (_, layers, command) = parse_args(&args(&raw));
            assert_eq!(layers.l2.model.as_deref(), Some("./ckpt"));
            match command {
                Command::Mask { path, .. } => assert_eq!(path.as_deref(), Some("note.txt")),
                _ => panic!("mask was not parsed"),
            }
        }

        // And `mask-file`, which has its own list and its own positional.
        let (_, layers, command) = parse_args(&args(&[
            "mask-file",
            "--l2-model",
            "./ckpt",
            "in.pdf",
            "--out",
            "out.pdf",
        ]));
        assert_eq!(layers.l2.model.as_deref(), Some("./ckpt"));
        match command {
            Command::MaskFile { input, .. } => assert_eq!(input, "in.pdf"),
            _ => panic!("mask-file was not parsed"),
        }
    }

    #[test]
    fn no_l2_flag_means_no_l2_configuration() {
        // The unchanged default path, asserted rather than assumed.
        let (_, layers, _) = parse_args(&args(&["mask", "note.txt"]));
        assert_eq!(layers.l2, L2Flags::default());
        assert!(l2::resolve(
            &layers.l2,
            &EnvView::default(),
            &config::FileConfig::default()
        )
        .is_unconfigured());
    }

    #[test]
    fn the_offline_flag_is_global_and_position_independent() {
        for raw in [
            vec!["--offline", "mask", "note.txt"],
            vec!["mask", "--offline", "note.txt"],
            vec!["mask", "note.txt", "--offline"],
        ] {
            let (flags, _, command) = parse_args(&args(&raw));
            assert!(flags.offline, "{raw:?}");
            assert!(matches!(command, Command::Mask { .. }));
        }
    }

    #[test]
    fn mask_parses_its_file_and_tier() {
        let (_, _, command) = parse_args(&args(&["mask", "note.txt", "--tier", "expert"]));
        match command {
            Command::Mask {
                path, tier, opts, ..
            } => {
                assert_eq!(path.as_deref(), Some("note.txt"));
                assert_eq!(tier, Tier::ExpertDetermination);
                // No flags means no opt-outs: the vocabulary and L5 are on.
                assert!(!opts.placeholder_labels);
                assert!(!opts.no_medical_allowlist);
            }
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn mask_defaults_to_safe_harbor_and_to_stdin() {
        let (_, _, command) = parse_args(&args(&["mask"]));
        match command {
            Command::Mask { path, tier, .. } => {
                assert_eq!(path, None);
                assert_eq!(
                    tier,
                    Tier::SafeHarbor,
                    "the expensive tier must never be entered implicitly"
                );
            }
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn the_degraded_configurations_are_opt_outs_and_are_parsed_as_such() {
        let (_, _, command) = parse_args(&args(&[
            "mask",
            "note.txt",
            "--placeholder-labels",
            "--no-medical-allowlist",
        ]));
        match command {
            Command::Mask { opts, .. } => {
                assert!(opts.placeholder_labels);
                assert!(opts.no_medical_allowlist);
            }
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn the_tier_value_is_not_mistaken_for_the_input_file() {
        let (_, _, command) = parse_args(&args(&["mask", "--tier", "expert"]));
        match command {
            Command::Mask { path, .. } => assert_eq!(path, None),
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn every_documented_verb_parses() {
        assert!(matches!(parse_args(&args(&["update"])).2, Command::Update));
        assert!(matches!(
            parse_args(&args(&["pull", "--from", "./bundle"])).2,
            Command::Pull { from: Some(_) }
        ));
        assert!(matches!(
            parse_args(&args(&["version"])).2,
            Command::Version
        ));
        assert!(matches!(
            parse_args(&args(&["frobnicate"])).2,
            Command::Usage { unknown: true }
        ));
    }

    #[test]
    fn a_blocked_outcome_names_the_switch_that_blocked_it() {
        // An operator told only "updates are disabled" edits the wrong file.
        let mut out = Vec::new();
        report(
            &update::Outcome::Blocked(update::Blocked::Disabled(config::DisabledBy::EnvVar)),
            &mut out,
        );
        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains(config::ENV_NO_UPDATE));
    }

    #[test]
    fn a_notify_only_outcome_says_it_did_not_install() {
        let mut out = Vec::new();
        report(
            &update::Outcome::NotifyOnly {
                version: "0.2.0".to_owned(),
                trust: verify::Trust::ChecksumOnlyNoPinnedKey,
            },
            &mut out,
        );
        let printed = String::from_utf8(out).expect("utf8");
        assert!(printed.contains("NOT installed"));
        assert!(printed.contains("signing key"));
    }
}
