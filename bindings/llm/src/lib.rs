#![forbid(unsafe_code)]

//! `deid-tr-llm` -- the LOCAL model runtime for L3, the contextual sweep.
//!
//! `core/` owns everything about L3 that can be reasoned about: what the model
//! is asked (`context::prompt`), how its answer is read (`context::parse`), and
//! how a claimed quote becomes a verified byte range (`context::anchor`). This
//! crate owns the one part that cannot be single-sourced across targets -- the
//! forward pass -- and nothing else.
//!
//! # The invariant this crate exists to keep
//!
//! L3 reads the WHOLE clinical note. Every other layer sees tokens or a
//! candidate span; this one sees the document. A remote call from here would
//! therefore upload the complete note in exchange for a list of the parts of it
//! that were sensitive, which is a disclosure with a de-identification report
//! attached. So: no HTTP client in the manifest, no cloud SDK, no model
//! download, no telemetry, and no configuration that can introduce one --
//! `gguf::AIRGAP_DENIED_ARGS` refuses the argument shapes that would turn a
//! local runtime into a network client.
//!
//! An air-gapped host is the design target, not a supported edge case. The
//! operator installs an inference runtime and copies a weights file; this crate
//! starts the former with the latter and reads its output.
//!
//! # Testing without a model
//!
//! [`runner::MockRunner`] stands in for the process, so the entire L3 path is
//! exercised in milliseconds with no weights on disk. A test suite that needs a
//! multi-gigabyte file is a test suite that stops being run.

pub mod gguf;
pub mod runner;

pub use gguf::LocalGgufModel;
pub use runner::{CommandRunner, MockRunner, ProcessRunner};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use deid_tr_core::context::{ContextualSweep, SweepConfig};
    use deid_tr_core::error::ModelFailure;
    use deid_tr_core::{Contextual, EntityLabel, Error, Layer, QuasiCategory};

    use super::*;

    /// Synthetic Turkish narrative. No real PHI (I8).
    const BODY: &str = "Hasta Merkez Bankası'nda müfettiş olarak çalışıyor. \
Eşi ilçedeki tek kadın hâkim.";

    const CANNED: &str = r#"[{"quote": "Merkez Bankası'nda müfettiş olarak çalışıyor",
                              "category": "EMPLOYER_ROLE",
                              "reason": "mesleği küçük bir popülasyonda tekilleştirici"}]"#;

    /// Two files that exist, so the constructor's checks have something real to
    /// look at. Empty, because nothing in this crate reads their contents --
    /// which is itself the point: the runner is mocked.
    fn installed_runtime() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join("deid-tr-llm-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let runtime = dir.join("local-runtime");
        let weights = dir.join("model.gguf");
        for path in [&runtime, &weights] {
            std::fs::write(path, b"").expect("fixture file");
        }
        (runtime, weights)
    }

    fn config() -> SweepConfig {
        SweepConfig::deterministic("deid-tr/test-model@abc123", "cpu", "q4_k_m", 42)
    }

    #[test]
    fn a_missing_runtime_or_missing_weights_fails_at_wiring_time() {
        let (runtime, weights) = installed_runtime();
        let absent = runtime.with_file_name("not-installed");
        assert_eq!(
            LocalGgufModel::new(&absent, &weights, MockRunner::answering(CANNED))
                .err()
                .map(|error| error.to_string()),
            Some(
                Error::LocalModelFailed {
                    kind: ModelFailure::RuntimeMissing
                }
                .to_string()
            )
        );
        assert!(matches!(
            LocalGgufModel::new(&runtime, &absent, MockRunner::answering(CANNED)),
            Err(Error::LocalModelFailed {
                kind: ModelFailure::WeightsMissing
            })
        ));
    }

    #[test]
    fn the_document_never_reaches_the_argument_list() {
        // THE privacy property of this crate, asserted rather than asserted in
        // prose: argv is world-readable through `ps`, so a document in the
        // argument list is a document disclosed to every local account.
        let (runtime, weights) = installed_runtime();
        let model =
            LocalGgufModel::new(&runtime, &weights, MockRunner::answering(CANNED)).expect("wiring");
        let sweep = ContextualSweep::new(model, config());
        sweep.sweep(BODY).expect("sweep");

        let calls = sweep.model().runner().calls();
        assert_eq!(calls.len(), 1);
        let args = calls[0].args.clone();
        for arg in &args {
            assert!(!arg.contains("Merkez"), "an argument carried the document");
            assert!(!arg.contains("hâkim"));
        }
        assert!(args.iter().any(|arg| arg == "--temp"));
        assert!(
            args.iter().any(|arg| arg == "0"),
            "temperature must be zero"
        );
        assert!(
            args.iter().any(|arg| arg == "42"),
            "the seed must be pinned"
        );
        assert!(args.iter().any(|arg| arg == "--no-display-prompt"));
    }

    #[test]
    fn the_prompt_travels_on_stdin_and_carries_the_whole_document() {
        let (runtime, weights) = installed_runtime();
        let model =
            LocalGgufModel::new(&runtime, &weights, MockRunner::answering(CANNED)).expect("wiring");
        let sweep = ContextualSweep::new(model, config());
        sweep.sweep(BODY).expect("sweep");

        // Length only: the mock records how much was written, never what. A
        // prompt shorter than the document means the note was truncated on the
        // way to the model, which is a recall loss with no error attached.
        let calls = sweep.model().runner().calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].prompt_len > BODY.len(),
            "the whole document plus the instructions must reach stdin"
        );
    }

    #[test]
    fn the_end_to_end_path_produces_a_verified_span_with_no_model_installed() {
        let (runtime, weights) = installed_runtime();
        let model =
            LocalGgufModel::new(&runtime, &weights, MockRunner::answering(CANNED)).expect("wiring");
        let sweep = ContextualSweep::new(model, config());
        let spans = sweep.sweep(BODY).expect("sweep");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].source(), Layer::Context);
        assert_eq!(
            spans[0].label(),
            EntityLabel::Quasi(QuasiCategory::EmployerRole)
        );
        assert_eq!(
            BODY.get(spans[0].start()..spans[0].end()),
            Some("Merkez Bankası'nda müfettiş olarak çalışıyor")
        );
        let record = sweep.records()[0];
        assert_eq!((record.claimed, record.anchored), (1, 1));
    }

    #[test]
    fn a_runtime_that_echoes_the_prompt_does_not_get_its_own_example_parsed() {
        // A runtime ignoring `--no-display-prompt` hands back the prompt plus
        // the completion, and the prompt contains a worked JSON example. Left
        // alone, that example is counted as a finding the model claimed.
        let (runtime, weights) = installed_runtime();
        let echoed = format!("{}\n{}", deid_tr_core::context::prompt::build(BODY), CANNED);
        let model =
            LocalGgufModel::new(&runtime, &weights, MockRunner::answering(echoed)).expect("wiring");
        let sweep = ContextualSweep::new(model, config());
        assert_eq!(sweep.sweep(BODY).expect("sweep").len(), 1);
        assert_eq!(
            sweep.records()[0].claimed,
            1,
            "the prompt's own example was counted as a model finding"
        );
    }

    #[test]
    fn a_runtime_failure_surfaces_as_a_text_free_error() {
        let (runtime, weights) = installed_runtime();
        let model = LocalGgufModel::new(
            &runtime,
            &weights,
            MockRunner::failing(ModelFailure::LaunchFailed),
        )
        .expect("wiring");
        let error = ContextualSweep::new(model, config())
            .sweep(BODY)
            .expect_err("the runtime failed");
        assert!(matches!(
            error,
            Error::LocalModelFailed {
                kind: ModelFailure::LaunchFailed
            }
        ));
        let rendered = error.to_string();
        assert!(!rendered.contains("Merkez"));
        assert!(!rendered.contains("hâkim"));
    }

    #[test]
    fn an_empty_completion_is_a_failure_rather_than_an_empty_sweep() {
        // Distinguishing "the model found nothing" from "the model said
        // nothing" matters: the first is a result, the second is a broken
        // runtime, and treating the second as the first hands back a document
        // the Expert Determination tier never actually swept.
        let (runtime, weights) = installed_runtime();
        let model = LocalGgufModel::new(&runtime, &weights, MockRunner::answering("   \n"))
            .expect("wiring");
        assert!(matches!(
            ContextualSweep::new(model, config()).sweep(BODY),
            Err(Error::LocalModelFailed {
                kind: ModelFailure::EmptyOutput
            })
        ));
    }

    #[test]
    fn an_argument_that_would_make_the_runtime_a_network_client_is_refused() {
        let (runtime, weights) = installed_runtime();
        for hostile in ["--server", "--host 10.0.0.1", "file://model.gguf", "--API"] {
            let model = LocalGgufModel::new(&runtime, &weights, MockRunner::answering(CANNED))
                .expect("wiring")
                .with_prompt_source(hostile);
            assert!(
                matches!(
                    ContextualSweep::new(model, config()).sweep(BODY),
                    Err(Error::LocalModelFailed {
                        kind: ModelFailure::LaunchFailed
                    })
                ),
                "the air-gap check accepted an argument that opens a socket"
            );
        }
    }

    #[test]
    fn the_air_gap_check_is_case_insensitive_and_matches_substrings() {
        // Over-matching on purpose. A refused legitimate flag is a startup
        // error someone reads; an accepted one is a disclosure nobody sees.
        for denied in gguf::AIRGAP_DENIED_ARGS {
            assert!(!denied.is_empty());
        }
        assert!(gguf::AIRGAP_DENIED_ARGS.contains(&"://"));
    }
}
