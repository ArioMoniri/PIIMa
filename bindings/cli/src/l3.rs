//! L3 wiring: turning operator configuration into a LOCAL contextual sweep.
//!
//! # What was wrong before this module existed
//!
//! `Tier::ExpertDetermination` -> `Contextual` -> `ContextualSweep<M: LocalModel>`
//! -> `LocalGgufModel` was complete, tested and unreachable. `bindings/cli` did
//! not depend on `bindings/llm`, so no shipped binary could construct the chain,
//! and `deid mask --tier expert` failed with "requires a contextual (L3) layer,
//! none configured" on a machine that had both a model and a runtime installed.
//! The defect was a missing manifest line, not a design limit, and the error
//! taught the operator nothing about how to fix it.
//!
//! # The model is LOCAL, and nothing here can change that
//!
//! Two paths are configurable and both name things already on the filesystem: a
//! weights FILE and a runtime EXECUTABLE. There is no host, no endpoint, no
//! token and no download. `deid_tr_llm` cannot fetch weights -- its manifest has
//! no HTTP client -- and `gguf::AIRGAP_DENIED_ARGS` refuses the argument shapes
//! that would turn the local runtime into a network client. This module adds no
//! exception to either, and must not grow one.
//!
//! # Why the errors here name paths, when the rest of the CLI refuses to
//!
//! `mask.rs` and `batch.rs` deliberately never print a path, because a clinical
//! export is routinely named after the patient. The two paths in this module are
//! categorically different: they name a weights file and an inference binary
//! chosen by whoever installed the tool, never a document. And the operator
//! cannot act on "L3 unavailable" -- they can act on "the model file
//! /opt/models/x.gguf does not exist". A refusal that does not say what is
//! missing is a refusal that gets worked around by dropping back to Safe Harbor,
//! which is the one outcome this tier must never produce silently.

use std::fmt;
use std::path::{Path, PathBuf};

use deid_tr_core::context::{ContextualSweep, SweepConfig};
use deid_tr_core::{Contextual, Error as CoreError};
use deid_tr_llm::{CommandRunner, LocalGgufModel, ProcessRunner};

use crate::config::{EnvView, FileConfig};

/// `DEID_L3_MODEL` -- path to the local GGUF weights file.
pub const ENV_MODEL: &str = "DEID_L3_MODEL";
/// `DEID_L3_RUNTIME` -- path to the local inference executable.
pub const ENV_RUNTIME: &str = "DEID_L3_RUNTIME";

/// The seed every sweep is pinned to.
///
/// A CONSTANT rather than a flag. The seed exists so that one (model, backend,
/// quantization) triple gives the same findings twice; letting the operator vary
/// it per invocation would make two runs of the same note incomparable while
/// looking like a tuning knob. `SweepConfig` already forbids a non-zero
/// temperature for the same reason.
pub const SWEEP_SEED: u64 = 0;

/// The backend string recorded in the audit config.
///
/// Honest rather than aspirational: this binding knows it started a local
/// process and does not know which execution provider that process chose. A
/// binding that claimed "cpu" while the runtime used Metal would put a false
/// identity in an artifact whose entire purpose is pinning one.
pub const BACKEND: &str = "local-process";

/// Which layer of the precedence chain supplied a setting.
///
/// Carried rather than collapsed away so that `deid doctor` can say WHERE a path
/// came from. An operator staring at "model file not found" whose config file
/// and environment disagree needs to know which one won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A command-line flag.
    Flag,
    /// An environment variable.
    Env,
    /// The config file.
    ConfigFile,
}

impl Origin {
    /// The switch, spelled the way the operator would type it.
    pub const fn describe(self, what: What) -> &'static str {
        match (self, what) {
            (Self::Flag, What::Model) => "--model",
            (Self::Flag, What::Runtime) => "--runtime",
            (Self::Env, What::Model) => ENV_MODEL,
            (Self::Env, What::Runtime) => ENV_RUNTIME,
            (Self::ConfigFile, What::Model) => "l3_model in the config file",
            (Self::ConfigFile, What::Runtime) => "l3_runtime in the config file",
        }
    }
}

/// Which of the two L3 paths a message is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    /// The GGUF weights file.
    Model,
    /// The inference executable.
    Runtime,
}

impl fmt::Display for What {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Model => "model",
            Self::Runtime => "runtime",
        })
    }
}

/// One resolved path plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The path as the operator wrote it.
    pub path: PathBuf,
    /// The layer that supplied it.
    pub origin: Origin,
}

/// The L3 paths taken from the command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3Flags {
    /// `--model PATH`.
    pub model: Option<String>,
    /// `--runtime PATH`.
    pub runtime: Option<String>,
}

/// Everything L3 needs, after precedence has been applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3Config {
    /// The weights file, when one was configured anywhere.
    pub model: Option<Setting>,
    /// The inference executable, when one was configured anywhere.
    pub runtime: Option<Setting>,
}

/// Apply the documented precedence: flag > env > config file.
///
/// The same order and the same reasoning as `config::resolve`: the narrower and
/// more deliberate the scope of a setting, the more it must win. Resolved per
/// path rather than per group, so an operator can pin the runtime in a config
/// file for the whole machine and point `--model` at a different weights file
/// for one run, which is the shape every real deployment takes.
#[must_use]
pub fn resolve(flags: &L3Flags, env: &EnvView, file: &FileConfig) -> L3Config {
    let pick = |flag: Option<&String>, var: Option<&String>, conf: Option<&String>| {
        flag.map(|raw| Setting {
            path: PathBuf::from(raw),
            origin: Origin::Flag,
        })
        .or_else(|| {
            var.map(|raw| Setting {
                path: PathBuf::from(raw),
                origin: Origin::Env,
            })
        })
        .or_else(|| {
            conf.map(|raw| Setting {
                path: PathBuf::from(raw),
                origin: Origin::ConfigFile,
            })
        })
    };
    L3Config {
        model: pick(
            flags.model.as_ref(),
            env.l3_model.as_ref(),
            file.l3_model.as_ref(),
        ),
        runtime: pick(
            flags.runtime.as_ref(),
            env.l3_runtime.as_ref(),
            file.l3_runtime.as_ref(),
        ),
    }
}

/// Why the Expert Determination tier could not be entered.
///
/// EVERY PRECONDITION GETS ITS OWN VARIANT, and every variant names both what is
/// missing and what to do about it. A single "L3 unavailable" is the failure
/// this whole module exists to delete: it is indistinguishable from a design
/// limitation, so the operator concludes the tier does not work and runs Safe
/// Harbor instead -- getting a less-masked document than they asked for, which
/// is the worst outcome this tool can produce.
#[derive(Debug, thiserror::Error)]
pub enum L3Error {
    /// No weights path was configured at any layer.
    #[error(
        "--tier expert needs a local model and none is configured. \
         Pass --model PATH-TO.gguf, or set {ENV_MODEL}, or write `l3_model = \"PATH\"` \
         in your config file. No weights ship with this build and none are downloaded: \
         you supply the file. Nothing was masked."
    )]
    ModelNotConfigured,
    /// No runtime path was configured at any layer.
    #[error(
        "--tier expert needs a local inference runtime and none is configured. \
         Pass --runtime PATH-TO-llama-cli, or set {ENV_RUNTIME}, or write \
         `l3_runtime = \"PATH\"` in your config file. The runtime is a program on this \
         machine; nothing is fetched. Nothing was masked."
    )]
    RuntimeNotConfigured,
    /// A configured path does not name an existing regular file.
    #[error(
        "the L3 {what} path {path} (from {origin}) does not exist or is not a regular file. \
         Correct the path or install the {what} there. Nothing was masked."
    )]
    NotAFile {
        /// Which of the two paths.
        what: What,
        /// The path, as configured.
        path: String,
        /// The switch that supplied it.
        origin: &'static str,
    },
    /// The runtime exists but carries no execute permission.
    #[error(
        "the L3 runtime {path} (from {origin}) exists but is not executable. \
         Run `chmod +x {path}`. Nothing was masked."
    )]
    RuntimeNotExecutable {
        /// The path, as configured.
        path: String,
        /// The switch that supplied it.
        origin: &'static str,
    },
    /// The runtime started but could not produce a usable answer.
    ///
    /// `reason` is the core error's own rendering, which by construction carries
    /// a classification, offsets and lengths and never a byte of the document or
    /// of the model's response (I4). It is re-wrapped here only to attach the
    /// remedy, which core cannot know.
    #[error("the L3 sweep failed: {reason}. {fix} Nothing was masked.")]
    Sweep {
        /// The text-free classification from `deid-tr-core`.
        reason: String,
        /// What the operator should try.
        fix: &'static str,
    },
}

impl L3Error {
    /// Re-wrap an L3-shaped core error with a remedy, or leave it alone.
    ///
    /// Returns `None` for every error that is not L3's, so the caller passes
    /// unrelated pipeline failures through unchanged rather than blaming the
    /// contextual layer for a span-offset bug.
    #[must_use]
    pub fn from_core(error: &CoreError) -> Option<Self> {
        let fix = match error {
            CoreError::LocalModelFailed { .. } => {
                "Check that the runtime runs standalone over a short prompt and exits zero; \
                 its own diagnostics are discarded on purpose, because a local runtime echoes \
                 the prompt it was given and the prompt is the whole clinical note."
            }
            CoreError::MalformedContextualResponse { .. } => {
                "The model did not answer with the requested JSON array. This is usually a \
                 model too small to follow the schema, or a chat-tuned model that needs its \
                 own prompt template; try a larger instruct model. The response is NOT quoted \
                 back here, because a model asked to quote quasi-identifiers puts the \
                 patient's employer in its first field."
            }
            CoreError::ContextualLayerMissing => {
                "This build can wire L3: pass --model and --runtime. Run `deid doctor` for \
                 what is and is not installed."
            }
            _ => return None,
        };
        Some(Self::Sweep {
            reason: error.to_string(),
            fix,
        })
    }
}

/// True when the path names an existing regular file.
fn is_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// True when the path carries an execute bit for somebody.
///
/// Unix only. On other platforms executability is not a permission bit, so the
/// honest answer is "cannot tell" and the check reports success rather than
/// inventing a refusal -- a failed spawn is then reported by the runtime itself.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

/// The path rendered for a message, without guessing at an encoding.
fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Check both paths and report the FIRST thing an operator has to fix.
///
/// Ordered model-then-runtime and checked configured-then-present, so the
/// message is always about the earliest missing precondition rather than about
/// whichever check happened to be written first.
fn checked(config: &L3Config) -> Result<(&Setting, &Setting), L3Error> {
    let model = config.model.as_ref().ok_or(L3Error::ModelNotConfigured)?;
    let runtime = config
        .runtime
        .as_ref()
        .ok_or(L3Error::RuntimeNotConfigured)?;
    if !is_file(&model.path) {
        return Err(L3Error::NotAFile {
            what: What::Model,
            path: shown(&model.path),
            origin: model.origin.describe(What::Model),
        });
    }
    if !is_file(&runtime.path) {
        return Err(L3Error::NotAFile {
            what: What::Runtime,
            path: shown(&runtime.path),
            origin: runtime.origin.describe(What::Runtime),
        });
    }
    if !is_executable(&runtime.path) {
        return Err(L3Error::RuntimeNotExecutable {
            path: shown(&runtime.path),
            origin: runtime.origin.describe(What::Runtime),
        });
    }
    Ok((model, runtime))
}

/// The GGUF quantization tag in a weights file name, when it carries one.
///
/// GGUF distributions encode the quantization in the file name by convention
/// (`...-Q4_K_M.gguf`), and that convention is the only source available: this
/// binding does not read the file, and `core/` performs no I/O at all. A name
/// that does not follow it yields `unlabelled` rather than a guess, because a
/// wrong quantization in an audit record is worse than an absent one -- it makes
/// two incomparable runs look comparable.
fn quantization_of(weights: &Path) -> String {
    let stem = weights
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    stem.rsplit(['-', '.'])
        .find(|part| {
            let upper = part.to_ascii_uppercase();
            let mut chars = upper.chars();
            matches!(chars.next(), Some('Q') | Some('F') | Some('I'))
                && upper.len() >= 2
                && upper.chars().any(|c| c.is_ascii_digit())
                && upper.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map_or_else(|| "unlabelled".to_owned(), |tag| tag.to_ascii_uppercase())
}

/// The audit identity of the configured model.
///
/// The FILE NAME, not the full path: the name identifies the weights, while the
/// directory identifies this machine's layout and lands in an audit record that
/// may be shared.
fn model_id(weights: &Path) -> String {
    weights.file_name().map_or_else(
        || "unnamed.gguf".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Build the sweep against a caller-supplied process runner.
///
/// Generic over the runner so the CLI's own tests exercise this exact wiring
/// with `MockRunner` and no weights on disk. A test that needs a multi-gigabyte
/// file is a test that stops being run, and the wiring is precisely what was
/// untested before.
pub fn sweep_with<R: ProcessRunner>(
    config: &L3Config,
    runner: R,
) -> Result<ContextualSweep<LocalGgufModel<R>>, L3Error> {
    let (model, runtime) = checked(config)?;
    // The constructor re-checks both paths. That duplication is deliberate: it
    // is `deid-tr-llm`'s own guarantee and must not depend on a caller having
    // checked first, while the checks above are what turn its single
    // classification into a message naming the path and the switch.
    let local = LocalGgufModel::new(&runtime.path, &model.path, runner).map_err(|error| {
        L3Error::from_core(&error).unwrap_or(L3Error::NotAFile {
            what: What::Model,
            path: shown(&model.path),
            origin: model.origin.describe(What::Model),
        })
    })?;
    Ok(ContextualSweep::new(
        local,
        SweepConfig::deterministic(
            model_id(&model.path),
            BACKEND,
            quantization_of(&model.path),
            SWEEP_SEED,
        ),
    ))
}

/// The L3 layer the shipped binary installs: a local process, and nothing else.
pub fn contextual(config: &L3Config) -> Result<Box<dyn Contextual>, L3Error> {
    Ok(Box::new(sweep_with(config, CommandRunner)?))
}

#[cfg(test)]
mod tests {
    use deid_tr_core::error::ModelFailure;
    use deid_tr_llm::MockRunner;

    use super::*;

    /// Synthetic Turkish narrative. No real PHI (I8).
    const BODY: &str = "Hasta Merkez Bankasi'nda mufettis olarak calisiyor.";

    const CANNED: &str = r#"[{"quote": "Merkez Bankasi'nda mufettis olarak calisiyor",
                              "category": "EMPLOYER_ROLE",
                              "reason": "meslek tekillestirici"}]"#;

    /// Two files that exist. Empty, because nothing here reads their contents.
    ///
    /// EVERY CALL GETS ITS OWN DIRECTORY. An earlier revision shared one fixed
    /// path across every test in this module, and two of the tests below chmod
    /// the runtime to 0o644 and back to 0o755 to exercise the not-executable
    /// branch. Cargo runs tests in the same binary on parallel threads, so those
    /// chmods raced against every other test's executable check and
    /// `just test-airgapped` failed intermittently with
    /// `RuntimeNotExecutable`. A release gate that fails once in a while gets
    /// re-run until it passes, which is the same as not having it.
    fn installed() -> L3Config {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("deid-cli-l3-tests-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let runtime = dir.join("local-runtime");
        let weights = dir.join("model-Q4_K_M.gguf");
        for path in [&runtime, &weights] {
            std::fs::write(path, b"").expect("fixture file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        L3Config {
            model: Some(Setting {
                path: weights,
                origin: Origin::Flag,
            }),
            runtime: Some(Setting {
                path: runtime,
                origin: Origin::Flag,
            }),
        }
    }

    #[test]
    fn precedence_is_flag_then_env_then_config_file() {
        let flags = L3Flags {
            model: Some("/flag.gguf".to_owned()),
            runtime: None,
        };
        let env = EnvView {
            l3_model: Some("/env.gguf".to_owned()),
            l3_runtime: Some("/env-runtime".to_owned()),
            ..EnvView::default()
        };
        let file = FileConfig {
            l3_model: Some("/file.gguf".to_owned()),
            l3_runtime: Some("/file-runtime".to_owned()),
            ..FileConfig::default()
        };
        let resolved = resolve(&flags, &env, &file);
        let model = resolved.model.expect("model");
        assert_eq!(model.path, PathBuf::from("/flag.gguf"));
        assert_eq!(model.origin, Origin::Flag);
        // The runtime had no flag, so the environment wins over the file.
        let runtime = resolved.runtime.expect("runtime");
        assert_eq!(runtime.path, PathBuf::from("/env-runtime"));
        assert_eq!(runtime.origin, Origin::Env);

        // With neither flag nor environment, the file is used and reported.
        let only_file = resolve(&L3Flags::default(), &EnvView::default(), &file);
        assert_eq!(
            only_file.runtime.expect("runtime").origin,
            Origin::ConfigFile
        );
    }

    #[test]
    fn nothing_configured_names_the_flag_rather_than_saying_l3_is_unavailable() {
        let error = sweep_with(&L3Config::default(), MockRunner::answering(CANNED))
            .err()
            .expect("no model configured")
            .to_string();
        assert!(error.contains("--model"), "{error}");
        assert!(error.contains(ENV_MODEL), "{error}");
        assert!(
            error.contains("Nothing was masked"),
            "the refusal must say the document was not degraded to Safe Harbor"
        );
    }

    #[test]
    fn a_configured_model_with_no_runtime_names_the_runtime_flag() {
        let config = L3Config {
            model: Some(Setting {
                path: PathBuf::from("/opt/models/x.gguf"),
                origin: Origin::Flag,
            }),
            runtime: None,
        };
        let error = sweep_with(&config, MockRunner::answering(CANNED))
            .err()
            .expect("no runtime configured")
            .to_string();
        assert!(error.contains("--runtime"), "{error}");
    }

    #[test]
    fn a_missing_file_is_named_along_with_the_switch_that_supplied_it() {
        let mut config = installed();
        let absent = PathBuf::from("/nonexistent/weights-that-are-not-there.gguf");
        config.model = Some(Setting {
            path: absent.clone(),
            origin: Origin::Env,
        });
        let error = sweep_with(&config, MockRunner::answering(CANNED))
            .err()
            .expect("absent weights")
            .to_string();
        assert!(error.contains("weights-that-are-not-there.gguf"), "{error}");
        assert!(error.contains(ENV_MODEL), "{error}");

        let mut config = installed();
        config.runtime = Some(Setting {
            path: PathBuf::from("/nonexistent/llama-cli-that-is-not-there"),
            origin: Origin::Flag,
        });
        let error = sweep_with(&config, MockRunner::answering(CANNED))
            .err()
            .expect("absent runtime")
            .to_string();
        assert!(error.contains("llama-cli-that-is-not-there"), "{error}");
        assert!(error.contains("--runtime"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_without_an_execute_bit_is_refused_with_the_chmod_that_fixes_it() {
        use std::os::unix::fs::PermissionsExt;
        let config = installed();
        let runtime = &config.runtime.as_ref().expect("runtime").path;
        std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = sweep_with(&config, MockRunner::answering(CANNED))
            .err()
            .expect("not executable")
            .to_string();
        assert!(error.contains("chmod +x"), "{error}");
        // Leave the fixture as the other tests expect to find it.
        std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    #[test]
    fn the_document_never_reaches_the_argument_list_through_this_wiring() {
        // `bindings/llm` asserts this property of its own adapter. Asserted
        // AGAIN here, through the CLI's construction path, because the wiring is
        // what was untested: argv is world-readable via `ps`, so a document in
        // an argument list is a document handed to every local account.
        let sweep = sweep_with(&installed(), MockRunner::answering(CANNED)).expect("wiring");
        sweep.sweep(BODY).expect("sweep");
        let calls = sweep.model().runner().calls();
        assert_eq!(calls.len(), 1);
        for arg in &calls[0].args {
            assert!(!arg.contains("Merkez"), "an argument carried the document");
            assert!(!arg.contains("mufettis"));
        }
        assert!(
            calls[0].prompt_len > BODY.len(),
            "the whole document must travel on stdin"
        );
    }

    #[test]
    fn unparseable_model_output_fails_without_quoting_the_document_or_the_response() {
        let sweep =
            sweep_with(&installed(), MockRunner::answering("not json at all {{{")).expect("wiring");
        let error = sweep.sweep(BODY).expect_err("garbage in, error out");
        let wrapped = L3Error::from_core(&error).expect("an L3-shaped error");
        let rendered = wrapped.to_string();
        assert!(!rendered.contains("Merkez"), "{rendered}");
        assert!(!rendered.contains("mufettis"), "{rendered}");
        assert!(!rendered.contains("not json"), "{rendered}");
        assert!(rendered.contains("JSON"), "{rendered}");
    }

    #[test]
    fn a_runtime_that_exits_non_zero_is_reported_as_a_host_problem() {
        let sweep = sweep_with(
            &installed(),
            MockRunner::failing(ModelFailure::ExitedWithError),
        )
        .expect("wiring");
        let error = sweep.sweep(BODY).expect_err("the runtime failed");
        let rendered = L3Error::from_core(&error)
            .expect("an L3-shaped error")
            .to_string();
        assert!(rendered.contains("exits zero"), "{rendered}");
        assert!(!rendered.contains("Merkez"), "{rendered}");
    }

    #[test]
    fn an_unrelated_core_error_is_not_blamed_on_the_contextual_layer() {
        assert!(L3Error::from_core(&CoreError::SpanNotOrdered { start: 4, end: 2 }).is_none());
    }

    #[test]
    fn the_quantization_tag_comes_from_the_name_or_is_admitted_to_be_absent() {
        assert_eq!(
            quantization_of(Path::new("/m/gemma-2-2b-it-Q4_K_M.gguf")),
            "Q4_K_M"
        );
        assert_eq!(quantization_of(Path::new("/m/model.gguf")), "unlabelled");
        assert_eq!(model_id(Path::new("/opt/w/model.gguf")), "model.gguf");
    }
}
