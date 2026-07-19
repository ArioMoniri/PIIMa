//! The local GGUF adapter: `deid-tr-core`'s L3 seam, implemented against a
//! llama.cpp-style command line runtime that is already installed on the
//! machine.
//!
//! WHY A LOCAL PROCESS RATHER THAN AN IN-PROCESS RUNTIME. Both are legitimate
//! and the trait admits either -- a `candle` implementation would sit beside
//! this one and implement the same seam. The process form is first because it
//! is the one that can be air-gapped today: the operator installs a runtime and
//! copies a weights file, and no part of this crate can substitute a different
//! source for either. There is nothing to configure that could point somewhere
//! else, which is a smaller thing to audit than a library with a model hub
//! client compiled into it.
//!
//! WHAT THIS TYPE WILL NOT DO, enforced rather than documented: it will not
//! fetch weights (there is no client here to fetch them with, see the manifest),
//! it will not accept an argument that turns the runtime into a network client
//! (see [`AIRGAP_DENIED_ARGS`]), and it will not put the document in the
//! process argument list (see [`crate::runner::ProcessRunner`]).

use std::path::{Path, PathBuf};

use deid_tr_core::context::{prompt, LocalModel, SweepConfig};
use deid_tr_core::error::ModelFailure;
use deid_tr_core::{Error, Result};

use crate::runner::ProcessRunner;

/// Argument fragments that would let a local runtime become a network client.
///
/// Modern local inference binaries ship a server mode in the same executable as
/// the one-shot mode, so "the runtime is local" is a property of the ARGUMENTS
/// as much as of the binary. An operator who pastes a server invocation into
/// the config, or a future caller who adds a flag without thinking, would turn
/// a local sweep into a remote one with the rest of the pipeline unchanged and
/// no other check anywhere that would notice.
///
/// Matched as substrings, case-insensitively, which over-matches on purpose:
/// refusing a legitimate flag is a startup error someone reads, and accepting
/// one is a disclosure nobody sees.
pub const AIRGAP_DENIED_ARGS: [&str; 8] = [
    "://", "--host", "--port", "--listen", "--server", "--proxy", "--api", "--url",
];

/// How many tokens the sweep will let the model emit.
///
/// A budget rather than "as many as it likes": the requested output is a short
/// JSON array, and a runaway generation costs minutes per note on the CPU path.
/// A truncated response is classified as such by the parser and shows up in the
/// audit record, so the failure is visible rather than silent.
pub const DEFAULT_MAX_TOKENS: u32 = 1024;

/// The path a llama.cpp-style runtime is told to read the prompt from.
///
/// `-f /dev/stdin` is how a unix runtime is asked to take its prompt from the
/// pipe the parent already wrote it to. On a platform without `/dev/stdin` the
/// caller supplies a different spelling through
/// [`LocalGgufModel::with_prompt_source`]; what must not change is that the
/// prompt travels on stdin rather than in argv.
pub const DEFAULT_PROMPT_SOURCE: &str = "/dev/stdin";

/// L3's forward pass, against a locally installed GGUF runtime.
pub struct LocalGgufModel<R: ProcessRunner> {
    runtime: PathBuf,
    weights: PathBuf,
    prompt_source: String,
    max_tokens: u32,
    runner: R,
}

impl<R: ProcessRunner> LocalGgufModel<R> {
    /// Bind to an installed runtime and a weights file that already exist.
    ///
    /// BOTH PATHS ARE CHECKED HERE, at construction, rather than at the first
    /// sweep. A missing model discovered mid-document is an error in the middle
    /// of a de-identification run, and the natural way to "handle" it is to
    /// carry on without the contextual layer -- which hands back an unswept
    /// document that looks like a swept one. Failing at wiring time makes that
    /// impossible.
    pub fn new(
        runtime: impl Into<PathBuf>,
        weights: impl Into<PathBuf>,
        runner: R,
    ) -> Result<Self> {
        let runtime = runtime.into();
        let weights = weights.into();
        if !is_file(&runtime) {
            return Err(failed(ModelFailure::RuntimeMissing));
        }
        if !is_file(&weights) {
            return Err(failed(ModelFailure::WeightsMissing));
        }
        Ok(Self {
            runtime,
            weights,
            prompt_source: DEFAULT_PROMPT_SOURCE.to_owned(),
            max_tokens: DEFAULT_MAX_TOKENS,
            runner,
        })
    }

    /// Override where the runtime is told to read the prompt from.
    #[must_use]
    pub fn with_prompt_source(mut self, source: impl Into<String>) -> Self {
        self.prompt_source = source.into();
        self
    }

    /// Override the generation budget.
    #[must_use]
    pub const fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// The process runner this model was wired with.
    ///
    /// Exists so a test can inspect what was actually invoked; with
    /// [`crate::runner::MockRunner`] that is how the "no document in argv"
    /// property is asserted rather than assumed.
    pub const fn runner(&self) -> &R {
        &self.runner
    }

    /// The argument list for one sweep.
    ///
    /// Contains the weights path, the decode settings and nothing derived from
    /// the document. Exposed so a test can assert that last property directly.
    #[must_use]
    pub fn args(&self, config: &SweepConfig) -> Vec<String> {
        vec![
            "-m".to_owned(),
            self.weights.to_string_lossy().into_owned(),
            // Greedy decode. `--temp 0` and a fixed `--seed` are what make one
            // (model, backend, quantization) triple reproducible; see the
            // determinism note in `deid_tr_core::context`.
            "--temp".to_owned(),
            config.temperature().to_string(),
            "--seed".to_owned(),
            config.seed().to_string(),
            "-n".to_owned(),
            self.max_tokens.to_string(),
            // Do not echo the prompt back: the prompt is the document, and the
            // echo would then be parsed as if it were the model's answer.
            "--no-display-prompt".to_owned(),
            "-f".to_owned(),
            self.prompt_source.clone(),
        ]
    }
}

/// True when the path names an existing regular file.
fn is_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

const fn failed(kind: ModelFailure) -> Error {
    Error::LocalModelFailed { kind }
}

/// Refuse an argument list that could make the runtime talk to something.
fn assert_air_gapped(args: &[String]) -> Result<()> {
    for arg in args {
        let lowered = arg.to_lowercase();
        if AIRGAP_DENIED_ARGS
            .iter()
            .any(|denied| lowered.contains(denied))
        {
            // The offending argument is NOT reported. It is caller-supplied
            // configuration, but an argument list is exactly where a path into
            // a directory named after a patient ends up, and an error message
            // is a log line (I4).
            return Err(failed(ModelFailure::LaunchFailed));
        }
    }
    Ok(())
}

/// Keep only what the runtime produced after the prompt.
///
/// Belt and braces alongside `--no-display-prompt`: a runtime that echoes its
/// input would hand the parser the prompt, and THE PROMPT CONTAINS A WORKED
/// JSON EXAMPLE. That example would parse as a perfectly well-formed finding.
/// It could not become a span -- its quote is not in the document, so the
/// anchor step drops it -- but it would land in the audit record as a claimed
/// finding and make the hallucination gap meaningless.
fn after_the_prompt(response: &str) -> &str {
    match response.rfind(prompt::BODY_CLOSE) {
        Some(offset) => response
            .get(offset + prompt::BODY_CLOSE.len()..)
            .unwrap_or(response),
        None => response,
    }
}

impl<R: ProcessRunner> LocalModel for LocalGgufModel<R> {
    fn generate(&self, prompt_text: &str, config: &SweepConfig) -> Result<String> {
        let args = self.args(config);
        assert_air_gapped(&args)?;
        let response = self
            .runner
            .run(&self.runtime, &args, prompt_text)
            .map_err(failed)?;
        let completion = after_the_prompt(&response).trim();
        if completion.is_empty() {
            return Err(failed(ModelFailure::EmptyOutput));
        }
        Ok(completion.to_owned())
    }
}
