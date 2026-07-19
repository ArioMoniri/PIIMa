//! The process seam.
//!
//! Everything that actually touches the operating system lives behind
//! [`ProcessRunner`], for two reasons that pull in the same direction.
//!
//! TESTABILITY. A test that needs a multi-gigabyte weights file and a compiled
//! inference binary is a test that runs on one machine and then stops running.
//! With the seam, the whole L3 path -- prompt construction, invocation,
//! response parsing, verbatim re-anchoring, the union, the audit record -- is
//! exercised in milliseconds by [`MockRunner`], and what is left untested is
//! only the twenty lines that spawn a child process.
//!
//! AUDITABILITY. There is exactly one implementation that can start anything,
//! it is immediately below, and it takes a path and an argument list from the
//! caller. A reviewer asking "can this reach the network?" reads one function
//! rather than the crate.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use deid_tr_core::error::ModelFailure;

/// Run a local program over a prompt and return what it printed.
///
/// THE PROMPT IS DELIVERED ON STDIN, NEVER IN THE ARGUMENT LIST, and this is a
/// privacy requirement rather than an ergonomic preference. A process's argv is
/// world-readable on every mainstream operating system: on a shared hospital
/// workstation any other user running `ps` sees the full command line of every
/// process. The L3 prompt contains the ENTIRE clinical note. Putting it in argv
/// would leak the whole document to every local account, on a tool whose single
/// promise is that the document never leaves the device (I1).
pub trait ProcessRunner {
    /// Start `program` with `args`, write `prompt` to its stdin, return stdout.
    fn run(&self, program: &Path, args: &[String], prompt: &str) -> Result<String, ModelFailure>;
}

/// The one implementation that starts a process.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommandRunner;

impl ProcessRunner for CommandRunner {
    fn run(&self, program: &Path, args: &[String], prompt: &str) -> Result<String, ModelFailure> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // STDERR IS DISCARDED ON PURPOSE. Local inference runtimes echo the
            // prompt they were given into their progress output, and the prompt
            // is the document. Inheriting stderr would print the clinical note
            // onto the terminal of whatever launched the CLI, and from there
            // into a scrollback buffer, a CI log or a support ticket (I4). The
            // cost is that a runtime's own diagnostics are invisible; the exit
            // status still distinguishes the failure modes that matter.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ModelFailure::LaunchFailed)?;

        // The prompt is written and the pipe CLOSED before the output is read.
        // Holding it open deadlocks against any runtime that reads to EOF, and
        // the resulting hang looks like a slow model rather than a bug.
        {
            let mut stdin = child.stdin.take().ok_or(ModelFailure::PromptNotDelivered)?;
            stdin
                .write_all(prompt.as_bytes())
                .map_err(|_| ModelFailure::PromptNotDelivered)?;
        }

        let finished = child
            .wait_with_output()
            .map_err(|_| ModelFailure::ExitedWithError)?;
        if !finished.status.success() {
            return Err(ModelFailure::ExitedWithError);
        }
        if finished.stdout.is_empty() {
            return Err(ModelFailure::EmptyOutput);
        }
        String::from_utf8(finished.stdout).map_err(|_| ModelFailure::OutputNotUtf8)
    }
}

/// A runner that starts nothing and answers with a canned completion.
///
/// Ships in the library rather than behind `#[cfg(test)]` because the CLI, the
/// eval harness and the MCP gateway all need to exercise the Expert
/// Determination tier without a model installed.
pub struct MockRunner {
    response: Result<String, ModelFailure>,
    calls: std::cell::RefCell<Vec<MockCall>>,
}

/// What a [`MockRunner`] was asked to do.
///
/// The prompt is recorded as a LENGTH, not a string. A mock exists to be
/// inspected in a failing test, and a failing test prints what it holds; the
/// prompt holds the document (I4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockCall {
    /// The program the adapter would have started.
    pub program: std::path::PathBuf,
    /// The argument list, which by construction contains no document text.
    pub args: Vec<String>,
    /// How many bytes of prompt were written to stdin.
    pub prompt_len: usize,
}

impl MockRunner {
    /// A mock that succeeds with `response`.
    #[must_use]
    pub fn answering(response: impl Into<String>) -> Self {
        Self {
            response: Ok(response.into()),
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// A mock that fails the way a real runtime fails.
    #[must_use]
    pub fn failing(kind: ModelFailure) -> Self {
        Self {
            response: Err(kind),
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Every invocation, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<MockCall> {
        self.calls.borrow().clone()
    }
}

impl ProcessRunner for MockRunner {
    fn run(&self, program: &Path, args: &[String], prompt: &str) -> Result<String, ModelFailure> {
        self.calls.borrow_mut().push(MockCall {
            program: program.to_path_buf(),
            args: args.to_vec(),
            prompt_len: prompt.len(),
        });
        self.response.clone()
    }
}
