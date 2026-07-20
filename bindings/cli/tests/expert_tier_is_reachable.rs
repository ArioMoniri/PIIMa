//! Can the SHIPPED `deid` binary reach the Expert Determination tier?
//!
//! # Why this file exists rather than another unit test
//!
//! `bindings/llm` proved the whole L3 path -- prompt, invocation, parse,
//! verbatim re-anchor, union, audit record -- with `MockRunner`, 604 lines of
//! it, and every one of those tests passed while no artifact a hospital
//! installs could construct a `LocalGgufModel`. `bindings/cli/Cargo.toml` did
//! not depend on `bindings/llm`, so `deid mask --tier expert` failed with "the
//! Expert Determination tier requires a contextual (L3) layer, none configured"
//! on a machine that had a model AND a runtime.
//!
//! That is the fourth component in this repository that was complete, tested and
//! wired to nothing. A test that builds its own pipeline cannot detect the
//! class; only one that execs `CARGO_BIN_EXE_deid` can. So nothing here imports
//! a builder.
//!
//! # What is asserted, and what deliberately is not
//!
//! ASSERTED: every precondition failure names the specific missing thing and the
//! switch that would supply it, and no failure ever produces a masked document.
//!
//! NOT ASSERTED HERE: a successful sweep. That needs a runtime process, and a
//! test needing a multi-gigabyte weights file is a test that stops being run.
//! The success path is covered by `src/l3.rs`'s `MockRunner` tests, which
//! exercise the same construction function this binary calls.
//!
//! Every fixture is synthetic (I8).

use std::io::Write;
use std::process::{Command, Output};

/// Synthetic Turkish narrative carrying a quasi-identifier and no direct PHI.
const NOTE: &str = "Hasta Merkez Bankasi'nda mufettis olarak calisiyor. \
Esi ilcedeki tek kadin hakim. Sikayeti dispne.\n";

/// Run the shipped binary over a document handed to it on stdin.
///
/// stdin rather than a path so no fixture is left on disk, and `--offline`
/// because a test must not depend on this machine's network posture.
fn deid(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn deid");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("deid exited")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

/// A file that exists on this machine, so a path check has something real.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("deid-expert-tier-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    std::fs::write(&path, b"").expect("fixture");
    path
}

#[test]
fn expert_without_a_model_names_the_flag_that_supplies_one() {
    let output = deid(&["mask", "--tier", "expert"], NOTE);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("--model"), "{stderr}");
    assert!(stderr.contains("DEID_L3_MODEL"), "{stderr}");
    assert!(stderr.contains("l3_model"), "{stderr}");
    // The old message, which taught nobody anything, must be gone.
    assert!(
        !stderr.contains("none configured"),
        "the generic refusal survived: {stderr}"
    );
}

#[test]
fn expert_with_a_model_but_no_runtime_names_the_runtime_flag() {
    let model = scratch("model-Q4_K_M.gguf");
    let output = deid(
        &[
            "mask",
            "--tier",
            "expert",
            "--model",
            model.to_str().expect("path"),
        ],
        NOTE,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("--runtime"), "{stderr}");
    assert!(stderr.contains("DEID_L3_RUNTIME"), "{stderr}");
}

#[test]
fn a_nonexistent_model_path_is_quoted_back_so_the_operator_can_fix_it() {
    let output = deid(
        &[
            "mask",
            "--tier",
            "expert",
            "--model",
            "/nonexistent/weights-not-installed.gguf",
            "--runtime",
            "/usr/bin/true",
        ],
        NOTE,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("weights-not-installed.gguf"), "{stderr}");
    assert!(stderr.contains("--model"), "{stderr}");
}

#[test]
fn a_nonexistent_runtime_path_is_quoted_back_too() {
    let model = scratch("model-Q4_K_M.gguf");
    let output = deid(
        &[
            "mask",
            "--tier",
            "expert",
            "--model",
            model.to_str().expect("path"),
            "--runtime",
            "/nonexistent/llama-cli-not-installed",
        ],
        NOTE,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("llama-cli-not-installed"), "{stderr}");
    assert!(stderr.contains("--runtime"), "{stderr}");
}

#[test]
fn expert_never_silently_degrades_to_safe_harbor() {
    // THE ASSERTION THIS FILE EXISTS FOR. Returning a less-masked document than
    // the caller asked for, without saying so, is the worst failure this tool
    // can have -- so on every L3 precondition failure stdout must be EMPTY. Not
    // "the document with fewer spans masked": nothing at all, and a non-zero
    // exit, so a shell pipeline cannot carry an under-masked note forward.
    for extra in [
        vec!["mask", "--tier", "expert"],
        vec![
            "mask",
            "--tier",
            "expert",
            "--model",
            "/nonexistent/w.gguf",
            "--runtime",
            "/nonexistent/r",
        ],
    ] {
        let output = deid(&extra, NOTE);
        assert!(!output.status.success(), "{extra:?} exited zero");
        assert!(
            output.stdout.is_empty(),
            "{extra:?} produced output while L3 was unavailable"
        );
        assert!(
            stderr_of(&output).contains("Nothing was masked"),
            "{extra:?} did not say the document was left alone"
        );
    }
}

#[test]
fn the_environment_and_the_config_file_reach_the_same_wiring_as_the_flags() {
    // The precedence chain is unit-tested in `src/l3.rs`; what is proved here is
    // that the env layer is actually CONSULTED by the shipped binary, which is
    // the half a unit test cannot see.
    let output = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .args(["mask", "--tier", "expert"])
        .env("DEID_L3_MODEL", "/nonexistent/env-supplied-weights.gguf")
        .env("DEID_L3_RUNTIME", "/nonexistent/env-supplied-runtime")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("deid exited");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("env-supplied-weights.gguf"), "{stderr}");
    assert!(stderr.contains("DEID_L3_MODEL"), "{stderr}");
}

#[test]
fn a_flag_beats_the_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .args([
            "mask",
            "--tier",
            "expert",
            "--model",
            "/nonexistent/flag-supplied-weights.gguf",
            "--runtime",
            "/nonexistent/r",
        ])
        .env("DEID_L3_MODEL", "/nonexistent/env-supplied-weights.gguf")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("deid exited");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("flag-supplied-weights.gguf"), "{stderr}");
    assert!(!stderr.contains("env-supplied-weights.gguf"), "{stderr}");
}

#[test]
fn doctor_reports_what_is_and_is_not_available_with_a_fix_for_each_gap() {
    let output = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .arg("doctor")
        .output()
        .expect("deid exited");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("L1 deterministic rules"), "{stdout}");
    assert!(stdout.contains("L3 contextual sweep"), "{stdout}");
    assert!(stdout.contains("--model"), "{stdout}");
    assert!(stdout.contains("--runtime"), "{stdout}");
    assert!(stdout.contains("fix:"), "{stdout}");
}

#[test]
fn doctor_states_that_no_names_are_masked_at_any_tier() {
    // The honesty requirement, through the shipped binary. `deid doctor` is the
    // most likely place for a future edit to make the tool sound better than it
    // is, and the one fact that must never be softened is that this build has no
    // L2 model and therefore masks ZERO names -- expert tier included.
    let output = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .arg("doctor")
        .output()
        .expect("deid exited");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("ZERO NAMES"), "{stdout}");
    assert!(stdout.contains("including --tier expert"), "{stdout}");
}

#[test]
fn safe_harbor_is_unaffected_by_the_new_wiring() {
    // The regression guard on the change itself: adding an L3 seam must not
    // make the default tier depend on a model that is not there.
    let output = deid(&["mask"], NOTE);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(String::from_utf8(output.stdout)
        .expect("utf8")
        .contains("dispne"));
}
