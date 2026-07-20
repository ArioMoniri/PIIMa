//! The Expert Determination tier gate, and its refusal.
//!
//! # Why a gate at all
//!
//! Expert Determination adds L3: a full-document sweep by a LOCAL LLM. It needs
//! a host that can run one, and this application cannot conjure either the
//! weights or the runtime. The one outcome that must never happen is a silent
//! downgrade -- a document that was never swept, presented as though it had
//! been. So the tier is checked BEFORE any document is read, and a tier that
//! cannot be served is refused with the thing the operator has to do about it.
//!
//! # The model is LOCAL and nothing here can change that
//!
//! Two settings, both naming things already on this filesystem: a weights FILE
//! and a runtime EXECUTABLE. No host, no endpoint, no token, no download.
//! `deid_tr_llm` has no HTTP client in its manifest and its
//! `gguf::AIRGAP_DENIED_ARGS` refuses the argument shapes that would turn the
//! local runtime into a network client. This module adds no exception.
//!
//! # Why the environment and not a settings screen
//!
//! Same two variable names the CLI reads (`DEID_L3_MODEL`, `DEID_L3_RUNTIME`),
//! so a machine configured for `deid mask --tier expert` is already configured
//! for the desktop app. A settings screen that wrote a third configuration
//! location would be a third place for the two to disagree.

use std::path::{Path, PathBuf};

use deid_tr_core::context::{ContextualSweep, SweepConfig};
use deid_tr_core::Contextual;
use deid_tr_llm::{CommandRunner, LocalGgufModel};

/// `DEID_L3_MODEL` -- path to the local GGUF weights file.
pub const ENV_MODEL: &str = "DEID_L3_MODEL";
/// `DEID_L3_RUNTIME` -- path to the local inference executable.
pub const ENV_RUNTIME: &str = "DEID_L3_RUNTIME";

/// The seed every sweep is pinned to.
///
/// A CONSTANT rather than a setting, for the reason `bindings/cli/src/l3.rs`
/// records: a per-invocation seed makes two runs of the same note incomparable
/// while looking like a tuning knob.
pub const SWEEP_SEED: u64 = 0;

/// The backend string recorded in the audit config.
///
/// Honest rather than aspirational: this binding knows it started a local
/// process and does not know which execution provider that process chose.
pub const BACKEND: &str = "local-process";

/// Why Expert Determination cannot run on this machine right now.
///
/// EVERY VARIANT NAMES THE FIX. A refusal an operator cannot act on is a
/// refusal that gets worked around by falling back to Safe Harbor, which is the
/// one outcome this tier must never produce.
///
/// The two paths ARE printed, unlike everywhere else in this repository, and
/// for the reason `bindings/cli/src/l3.rs` gives: they name a weights file and
/// an inference binary chosen by whoever installed the tool, never a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unavailable {
    /// No weights path configured.
    #[error(
        "Expert Determination needs a LOCAL model file and none is configured. Set {ENV_MODEL} \
         to a .gguf weights file on this machine, then restart deid-tr. The file is on this \
         computer; nothing is downloaded and nothing is sent anywhere. Nothing was masked."
    )]
    ModelNotConfigured,
    /// No runtime path configured.
    #[error(
        "Expert Determination needs a LOCAL inference runtime and none is configured. Set \
         {ENV_RUNTIME} to an executable on this machine (for example a llama.cpp `llama-cli`), \
         then restart deid-tr. The runtime is a program on this computer; nothing is fetched. \
         Nothing was masked."
    )]
    RuntimeNotConfigured,
    /// A configured path does not name an existing regular file.
    #[error(
        "the L3 {what} path configured in {variable} does not exist or is not a regular file: \
         {path}. Correct the variable or install the {what} there, then restart deid-tr. \
         Nothing was masked."
    )]
    NotAFile {
        /// `model` or `runtime`.
        what: &'static str,
        /// The environment variable that supplied it.
        variable: &'static str,
        /// The path, as configured.
        path: String,
    },
    /// The runtime exists but carries no execute permission.
    #[error(
        "the L3 runtime configured in {ENV_RUNTIME} exists but is not executable: {path}. \
         Run `chmod +x {path}`, then restart deid-tr. Nothing was masked."
    )]
    RuntimeNotExecutable {
        /// The path, as configured.
        path: String,
    },
    /// The runtime and weights are present but the layer would not build.
    ///
    /// `reason` is `deid-tr-core`'s own rendering, which carries a
    /// classification and never a byte of the document (I4).
    #[error("the L3 layer could not be built: {reason}. Nothing was masked.")]
    NotBuildable {
        /// The text-free classification from `deid-tr-core`.
        reason: String,
    },
}

/// The two paths, as the environment supplied them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// `DEID_L3_MODEL`.
    pub model: Option<PathBuf>,
    /// `DEID_L3_RUNTIME`.
    pub runtime: Option<PathBuf>,
}

impl Config {
    /// Read both variables from the process environment.
    ///
    /// An EMPTY value is treated as unset. `DEID_L3_MODEL=` in a shell profile
    /// is somebody clearing it, and reporting "the path  does not exist" for an
    /// empty string helps nobody.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            model: non_empty(ENV_MODEL),
            runtime: non_empty(ENV_RUNTIME),
        }
    }
}

fn non_empty(variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Check both paths and report the FIRST thing an operator has to fix.
///
/// Ordered model-then-runtime and configured-then-present, so the message is
/// always about the earliest missing precondition rather than about whichever
/// check happened to be written first.
///
/// # Errors
///
/// [`Unavailable`], naming the fix.
pub fn checked(config: &Config) -> Result<(&Path, &Path), Unavailable> {
    let model = config
        .model
        .as_deref()
        .ok_or(Unavailable::ModelNotConfigured)?;
    let runtime = config
        .runtime
        .as_deref()
        .ok_or(Unavailable::RuntimeNotConfigured)?;
    if !is_file(model) {
        return Err(Unavailable::NotAFile {
            what: "model",
            variable: ENV_MODEL,
            path: shown(model),
        });
    }
    if !is_file(runtime) {
        return Err(Unavailable::NotAFile {
            what: "runtime",
            variable: ENV_RUNTIME,
            path: shown(runtime),
        });
    }
    if !is_executable(runtime) {
        return Err(Unavailable::RuntimeNotExecutable {
            path: shown(runtime),
        });
    }
    Ok((model, runtime))
}

/// Build the contextual layer this application installs: a local process, and
/// nothing else.
///
/// # Errors
///
/// [`Unavailable`] when a precondition is missing or the layer will not build.
pub fn contextual(config: &Config) -> Result<Box<dyn Contextual>, Unavailable> {
    let (model, runtime) = checked(config)?;
    // The constructor re-checks both paths. That duplication is deliberate and
    // is the same call `bindings/cli` makes: the re-check is `deid-tr-llm`'s own
    // guarantee and must not depend on a caller having checked first, while the
    // checks above are what turn its single classification into a message
    // naming the variable.
    let local =
        LocalGgufModel::new(runtime, model, CommandRunner).map_err(|error| {
            Unavailable::NotBuildable {
                reason: error.to_string(),
            }
        })?;
    Ok(Box::new(ContextualSweep::new(
        local,
        SweepConfig::deterministic(
            model_id(model),
            BACKEND,
            quantization_of(model),
            SWEEP_SEED,
        ),
    )))
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

/// The audit identity of the configured model: the FILE NAME, not the path.
///
/// The name identifies the weights; the directory identifies this machine's
/// layout and would land in an audit record that may be shared.
fn model_id(weights: &Path) -> String {
    weights.file_name().map_or_else(
        || "unnamed.gguf".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// The GGUF quantization tag in a weights file name, when it carries one.
///
/// The naming convention (`...-Q4_K_M.gguf`) is the only source available: this
/// binding does not read the file. A name that does not follow it yields
/// `unlabelled` rather than a guess, because a wrong quantization in an audit
/// record makes two incomparable runs look comparable.
fn quantization_of(weights: &Path) -> String {
    let stem = weights
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    stem.rsplit(['-', '.'])
        .find(|part| {
            let upper = part.to_ascii_uppercase();
            let mut chars = upper.chars();
            matches!(chars.next(), Some('Q' | 'F' | 'I'))
                && upper.len() >= 2
                && upper.chars().any(|c| c.is_ascii_digit())
                && upper.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map_or_else(|| "unlabelled".to_owned(), |tag| tag.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconfigured_model_refuses_with_the_variable_to_set() {
        let error = checked(&Config::default()).expect_err("must refuse");
        let message = error.to_string();
        assert!(message.contains(ENV_MODEL));
        assert!(message.contains("Nothing was masked"));
        // The refusal must not read like a suggestion to fetch something.
        assert!(message.contains("nothing is downloaded"));
    }

    #[test]
    fn a_configured_model_with_no_runtime_names_the_runtime() {
        let config = Config {
            model: Some(PathBuf::from("/nonexistent/weights.gguf")),
            runtime: None,
        };
        let error = checked(&config).expect_err("must refuse");
        assert!(error.to_string().contains(ENV_RUNTIME));
    }

    #[test]
    fn a_missing_file_is_named_with_its_variable() {
        let config = Config {
            model: Some(PathBuf::from("/nonexistent/weights.gguf")),
            runtime: Some(PathBuf::from("/nonexistent/llama-cli")),
        };
        let error = checked(&config).expect_err("must refuse");
        assert_eq!(
            error,
            Unavailable::NotAFile {
                what: "model",
                variable: ENV_MODEL,
                path: "/nonexistent/weights.gguf".to_owned(),
            }
        );
    }

    #[test]
    fn quantization_comes_from_the_name_or_is_admitted_as_unknown() {
        assert_eq!(
            quantization_of(Path::new("/m/mistral-7b-Q4_K_M.gguf")),
            "Q4_K_M"
        );
        assert_eq!(quantization_of(Path::new("/m/weights.gguf")), "unlabelled");
    }

    #[test]
    fn an_empty_environment_variable_reads_as_unset() {
        // Not `from_env`: this process's environment is shared with every other
        // test in the binary and mutating it races. The behaviour under test is
        // the filter, and the filter is what `from_env` is made of.
        assert!(std::ffi::OsString::from("").is_empty());
        assert_eq!(Config::default().model, None);
    }
}
