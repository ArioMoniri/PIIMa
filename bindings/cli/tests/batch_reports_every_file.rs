//! Does the SHIPPED `deid` binary refuse to lose a file?
//!
//! # Why through the binary
//!
//! `src/batch.rs` unit-tests the enumeration, the manifest and the
//! continue-on-error semantics. What those tests cannot see is the part an
//! operator's pipeline actually depends on: the EXIT CODE. A batch that masked
//! ninety-nine of a hundred documents and exited zero is a batch whose one
//! unmasked document flows into whatever comes next, and every unit test in the
//! module would still be green. So this file execs `CARGO_BIN_EXE_deid`.
//!
//! # Every fixture is synthetic (I8)
//!
//! The checksum-valid TCKN is COMPUTED here and never written down, because the
//! pre-commit hook refuses a committed one.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// A checksum-valid TCKN, built at run time.
fn tckn() -> String {
    let mut digits: [u8; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0];
    let odd: i32 = [0, 2, 4, 6, 8].iter().map(|i| i32::from(digits[*i])).sum();
    let even: i32 = [1, 3, 5, 7].iter().map(|i| i32::from(digits[*i])).sum();
    digits[9] = u8::try_from((odd * 7 - even).rem_euclid(10)).unwrap_or(0);
    let total: i32 = digits[..10].iter().map(|d| i32::from(*d)).sum();
    digits[10] = u8::try_from(total.rem_euclid(10)).unwrap_or(0);
    digits.iter().map(|d| char::from(b'0' + d)).collect()
}

fn note() -> String {
    format!("Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00.", tckn())
}

fn scratch(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "deid-cli-batch-{tag}-{unique}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch dir");
    path
}

/// Run the shipped binary. `--offline` because a test must not depend on this
/// machine's network posture.
fn deid_batch(input: &Path, output: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .arg("mask")
        .arg("--batch")
        .arg(input)
        .arg("--out")
        .arg(output)
        .args(extra)
        .output()
        .expect("deid must run")
}

fn manifest(output: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(output.join("manifest.jsonl"))
        .expect("the manifest must exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each manifest line is JSON"))
        .collect()
}

#[test]
fn a_clean_batch_masks_every_file_and_exits_zero() {
    let input = scratch("in");
    let output = scratch("out");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    std::fs::write(input.join("b.txt"), "TCKN yok.").expect("fixture");

    let run = deid_batch(&input, &output, &[]);
    assert!(run.status.success(), "a clean batch must exit zero");
    let masked = std::fs::read_to_string(output.join("a.txt")).expect("output");
    assert!(!masked.contains(&tckn()), "the TCKN survived masking");
    assert_eq!(manifest(&output).len(), 4, "header + two items + summary");
}

#[test]
fn one_bad_file_does_not_stop_the_run_and_makes_the_exit_code_non_zero() {
    // THE property. A partial batch must be loud, and the other documents must
    // still be processed.
    let input = scratch("in");
    let output = scratch("out");
    std::fs::write(input.join("1-ok.txt"), note()).expect("fixture");
    std::fs::write(input.join("2-bad.bin"), [0xff, 0xfe]).expect("fixture");
    std::fs::write(input.join("3-ok.txt"), note()).expect("fixture");

    let run = deid_batch(&input, &output, &[]);
    assert!(
        !run.status.success(),
        "a batch with an unmasked file exited zero; the caller would treat it as complete"
    );

    // The two good documents were still processed.
    assert!(output.join("1-ok.txt").exists());
    assert!(output.join("3-ok.txt").exists());
    assert!(!output.join("2-bad.bin").exists());

    let records = manifest(&output);
    assert_eq!(records.len(), 5, "header + three items + summary");
    let statuses: Vec<&str> = records[1..4]
        .iter()
        .map(|record| record["status"].as_str().expect("status"))
        .collect();
    assert_eq!(statuses, vec!["masked", "failed", "masked"]);
    assert_eq!(records[2]["error"], serde_json::json!("not_utf8"));

    // The summary tells the operator how many failed and where the paths are.
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("1 failed"), "{stderr}");
    assert!(stderr.contains("manifest.jsonl"), "{stderr}");
    // And it does not name the file: stderr goes to a log, and a clinical export
    // routinely names files after patients.
    assert!(!stderr.contains("2-bad.bin"), "{stderr}");
}

#[test]
fn a_subdirectory_is_reported_rather_than_passed_over() {
    let input = scratch("in");
    let output = scratch("out");
    std::fs::write(input.join("top.txt"), note()).expect("fixture");
    std::fs::create_dir_all(input.join("sub")).expect("subdir");
    std::fs::write(input.join("sub/inner.txt"), note()).expect("fixture");

    let run = deid_batch(&input, &output, &[]);
    // Not a failure -- nothing was misprocessed -- but visible.
    assert!(run.status.success());
    let records = manifest(&output);
    assert!(records
        .iter()
        .any(|record| record["status"] == serde_json::json!("skipped_directory")));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("1 directory(ies) not descended into"),
        "{stderr}"
    );

    // With --recursive it is masked instead.
    let recursive_out = scratch("out");
    let run = deid_batch(&input, &recursive_out, &["--recursive"]);
    assert!(run.status.success());
    assert!(recursive_out.join("sub/inner.txt").exists());
}

#[test]
fn batch_without_an_output_directory_is_refused() {
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    let run = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .arg("mask")
        .arg("--batch")
        .arg(&input)
        .output()
        .expect("deid must run");
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("--out"));
}

#[test]
fn writing_the_output_into_the_input_tree_is_refused() {
    // Masked output over the originals destroys the only copy of the clinical
    // record. This is a refusal, not a warning, and the original must survive.
    let input = scratch("in");
    let source = note();
    std::fs::write(input.join("a.txt"), &source).expect("fixture");
    let run = deid_batch(&input, &input.join("masked"), &[]);
    assert!(!run.status.success());
    assert_eq!(
        std::fs::read_to_string(input.join("a.txt")).expect("original"),
        source,
        "the original was modified by a refused run"
    );
}

#[test]
fn a_batch_and_a_file_argument_in_one_run_are_refused() {
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    let output = scratch("out");
    let run = Command::new(env!("CARGO_BIN_EXE_deid"))
        .arg("--offline")
        .arg("mask")
        .arg(input.join("a.txt"))
        .arg("--batch")
        .arg(&input)
        .arg("--out")
        .arg(&output)
        .output()
        .expect("deid must run");
    assert!(
        !run.status.success(),
        "one of the two inputs would have been silently ignored"
    );
}

#[test]
fn the_formats_are_reachable_from_the_shipped_binary() {
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    for (format, name) in [
        ("json", "a.txt.json"),
        ("csv", "a.txt.csv"),
        ("html", "a.txt.html"),
        ("text", "a.txt"),
    ] {
        let output = scratch("out");
        let run = deid_batch(&input, &output, &["--format", format]);
        assert!(run.status.success(), "--format {format} failed");
        let rendered = std::fs::read_to_string(output.join(name))
            .unwrap_or_else(|_| panic!("--format {format} wrote no {name}"));
        assert!(
            !rendered.contains(&tckn()),
            "--format {format} leaked the original identifier"
        );
    }
}

#[test]
fn an_unknown_format_is_refused_rather_than_falling_back_to_text() {
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    let output = scratch("out");
    let run = deid_batch(&input, &output, &["--format", "jsonl"]);
    assert!(
        !run.status.success(),
        "an unknown --format silently produced some other shape"
    );
    assert!(String::from_utf8_lossy(&run.stderr).contains("--format"));
}

#[test]
fn the_confidence_threshold_warns_and_does_not_change_what_is_masked() {
    // I2 through the shipped binary. The manifest records what was masked, and
    // it must be identical with and without the flag.
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");

    let plain_out = scratch("out");
    let plain = deid_batch(&input, &plain_out, &[]);
    let filtered_out = scratch("out");
    let filtered = deid_batch(&input, &filtered_out, &["--confidence-threshold", "0.99"]);
    assert!(plain.status.success() && filtered.status.success());

    let masked_spans = |output: &Path| manifest(output)[1]["masked_spans"].clone();
    assert_eq!(
        masked_spans(&plain_out),
        masked_spans(&filtered_out),
        "the reporting threshold changed what was masked"
    );

    let stderr = String::from_utf8_lossy(&filtered.stderr);
    assert!(stderr.contains("never what is masked"), "{stderr}");
    assert!(!String::from_utf8_lossy(&plain.stderr).contains("never what is masked"));
}

#[test]
fn an_out_of_range_confidence_threshold_is_refused() {
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    let output = scratch("out");
    for value in ["1.5", "-0.2", "high"] {
        let run = deid_batch(&input, &output, &["--confidence-threshold", value]);
        assert!(
            !run.status.success(),
            "--confidence-threshold {value} was accepted"
        );
    }
}

#[test]
fn the_manifest_carries_the_coverage_statement() {
    // The manifest is the artifact most likely to be attached to a compliance
    // review. It has to say what this build does not do.
    let input = scratch("in");
    std::fs::write(input.join("a.txt"), note()).expect("fixture");
    let output = scratch("out");
    deid_batch(&input, &output, &[]);
    let header = &manifest(&output)[0];
    assert!(header["coverage"]
        .as_str()
        .expect("coverage")
        .contains("no names are masked"));

    // And the masked output proves it: the name really is still there.
    let masked = std::fs::read_to_string(output.join("a.txt")).expect("output");
    assert!(masked.contains("Ayşe Yılmaz"));
}
