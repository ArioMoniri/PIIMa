#![forbid(unsafe_code)]

//! `deid-tr-ort` -- the native ONNX Runtime side of the L2 [`Detector`] seam.
//!
//! # Why this crate is separate from `core/`
//!
//! `core/` owns the span algebra, the BIOES decode, the alignment and the
//! merge, and it is structurally incapable of I/O or network access (I1). It
//! also compiles to `wasm32`, which an inference runtime does not: `ort`
//! dropped `wasm32-unknown-unknown` support, and the browser build reaches
//! `onnxruntime-web` through a different binding entirely.
//!
//! So exactly one thing crosses this boundary -- the forward pass -- and it
//! crosses as a trait. Everything downstream of the logits is single-sourced in
//! `core/`, which is what makes the browser PWA run the same L2 as the CLI
//! rather than a reimplementation of it that drifts.
//!
//! # Execution providers
//!
//! Selection is AUTOMATIC and it is LOGGED ONCE AT STARTUP. The order is
//! [`ExecutionProvider::PREFERENCE`]: an accelerator when the host has one, CPU
//! otherwise. CPU is not a failure mode -- it is the floor the product is
//! specified against, because a hospital workstation is the target and L1+L2
//! have a ~10ms budget there.
//!
//! The startup line carries the provider TYPE and nothing else. Never a
//! document, never a span, never a covered string, never a file path that
//! embeds a patient identifier (I4). A log line reaches a log aggregator and
//! then a bug report, and every hop is outside the device boundary I1
//! promises PHI never crosses.
//!
//! # Weights
//!
//! This crate never downloads anything. There is no lazy fetch at inference
//! (I1) and no fetch at build time either -- see the long comment in
//! `Cargo.toml` for why the `ort` dependency is admitted deliberately rather
//! than inherited with `download-binaries` switched on. A model is bytes the
//! caller already has, obtained by an explicit `deid pull` or from a release
//! bundle, and an air-gapped host is a supported configuration.
//!
//! # Testability with zero weights
//!
//! [`StubSession`] implements [`Session`] over canned logits, so the entire
//! path -- session, detector, ensemble, constrained decode, alignment, union --
//! is exercised by this crate's tests with no `.onnx` file anywhere on disk.

use std::fmt;
use std::sync::OnceLock;

use deid_tr_core::pipeline::Detector;

/// A hardware backend ONNX Runtime can execute a graph on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ExecutionProvider {
    /// The floor. Always available, and the only one guaranteed to be.
    #[default]
    Cpu,
    /// NVIDIA, via CUDA.
    Cuda,
    /// Apple, via CoreML. The Tauri mobile target reaches this one too.
    CoreMl,
    /// Windows, via DirectML.
    DirectMl,
}

impl ExecutionProvider {
    /// Preference order, most capable first.
    ///
    /// A LIST, not a chain of `if`s, because the selection has to be testable
    /// without the hardware. Every accelerator here is a large constant factor
    /// over CPU for a transformer encoder, and they are mutually exclusive in
    /// practice -- a host has at most one of them -- so the order matters only
    /// on the rare box that has two.
    pub const PREFERENCE: [Self; 4] = [Self::Cuda, Self::CoreMl, Self::DirectMl, Self::Cpu];

    /// The stable identifier for this provider, for the startup line.
    ///
    /// Fixed strings, chosen so that nothing derived from a document can ever
    /// reach the log through this path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
            Self::CoreMl => "coreml",
            Self::DirectMl => "directml",
        }
    }

    /// True when this provider is the always-available fallback.
    #[must_use]
    pub const fn is_fallback(self) -> bool {
        matches!(self, Self::Cpu)
    }
}

impl fmt::Display for ExecutionProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the host actually offers.
///
/// A plain value rather than a probe, so [`select`] is a pure function of it
/// and the selection logic is testable on any machine. Probing is
/// [`Availability::detect`]'s job and is the only part that needs hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Availability {
    /// A CUDA device and a CUDA-enabled ONNX Runtime are both present.
    pub cuda: bool,
    /// CoreML is present. macOS and iOS only.
    pub coreml: bool,
    /// DirectML is present. Windows only.
    pub directml: bool,
}

impl Availability {
    /// Nothing but the CPU floor.
    #[must_use]
    pub const fn cpu_only() -> Self {
        Self {
            cuda: false,
            coreml: false,
            directml: false,
        }
    }

    /// Probe the host.
    ///
    /// Reports the CPU floor while no ONNX Runtime is linked, and that is the
    /// CORRECT answer rather than a stub's shrug: with no runtime in the
    /// process there is no accelerator anything can actually dispatch to, so
    /// claiming one would make the startup line a lie about what ran.
    ///
    /// When the `ort` dependency is admitted (see `Cargo.toml`), the body
    /// becomes a query to `ort` for the providers that actually REGISTERED.
    /// Compile-time platform gating is not a substitute and must not be used
    /// here: a macOS build can be linked against a runtime built without
    /// CoreML, and a Linux box can have a CUDA driver and a CPU-only runtime,
    /// so `cfg!(target_os = ...)` answers a different question than the one
    /// the startup line claims to answer.
    #[must_use]
    pub fn detect() -> Self {
        Self::cpu_only()
    }

    /// True when at least one accelerator is available.
    #[must_use]
    pub const fn has_accelerator(self) -> bool {
        self.cuda || self.coreml || self.directml
    }

    /// Whether a specific provider is available. CPU always is.
    #[must_use]
    pub const fn offers(self, provider: ExecutionProvider) -> bool {
        match provider {
            ExecutionProvider::Cpu => true,
            ExecutionProvider::Cuda => self.cuda,
            ExecutionProvider::CoreMl => self.coreml,
            ExecutionProvider::DirectMl => self.directml,
        }
    }
}

/// Pick the execution provider for a host.
///
/// Total: [`ExecutionProvider::PREFERENCE`] ends in `Cpu` and
/// [`Availability::offers`] always returns true for it, so this cannot fail to
/// choose. A selection that could fail would mean a host with an unusual
/// accelerator gets no de-identification at all, and refusing to run is a worse
/// outcome than running slowly.
#[must_use]
pub fn select(availability: Availability) -> ExecutionProvider {
    ExecutionProvider::PREFERENCE
        .into_iter()
        .find(|&provider| availability.offers(provider))
        .unwrap_or(ExecutionProvider::Cpu)
}

/// The provider this process selected, chosen once.
static SELECTED: OnceLock<ExecutionProvider> = OnceLock::new();

/// The selected provider, probing and logging on the first call only.
///
/// ONCE, for two reasons that are not the same. Correctness: a per-inference
/// probe would let the provider change mid-document, so two halves of one note
/// could run on different backends and disagree on near-tie logits. Privacy: a
/// line emitted per document is a per-document signal, and the count of lines
/// alone tells a log reader how many patients were processed. One line per
/// process tells them nothing.
pub fn selected() -> ExecutionProvider {
    *SELECTED.get_or_init(|| {
        let provider = select(Availability::detect());
        log_selection(provider);
        provider
    })
}

/// The startup line. Provider type only.
///
/// Public and returning a `String` so the test suite can assert on the exact
/// bytes that would be emitted. A log line nobody can inspect in a test is a
/// log line that grows a document quote during a debugging session and keeps
/// it (I4).
#[must_use]
pub fn startup_line(provider: ExecutionProvider) -> String {
    format!("deid-tr: onnxruntime execution provider = {provider}")
}

/// Emit the startup line to stderr.
///
/// stderr and not a logging framework: a logging framework has appenders, and
/// an appender is a network sink one configuration file away. This crate is
/// allowed I/O, but it is not allowed to become a place PHI could be shipped
/// from, so the one line it writes goes to a file descriptor the operator
/// already controls.
fn log_selection(provider: ExecutionProvider) {
    eprintln!("{}", startup_line(provider));
}

/// What can go wrong running a graph.
///
/// I4 binds this enum as it binds every error type in the project: shapes,
/// counts and provider names only. Never a document, never a token's surface
/// form, and never a model path -- a path can embed a hospital or a patient
/// identifier, and it is the payload most likely to be added by someone who has
/// stopped thinking of paths as data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OrtError {
    /// The graph produced an output whose shape is not per-token logits.
    #[error("expected logits of shape [{tokens}, n_labels], got {rank} dimensions")]
    OutputRank { tokens: usize, rank: usize },

    /// The session produced a different number of rows than there were tokens.
    #[error("session returned {rows} logit rows for {tokens} input ids")]
    RowCount { rows: usize, tokens: usize },

    /// The runtime refused to execute. Carries the provider, not the message:
    /// a runtime's error string can quote a file path.
    #[error("the {provider} execution provider failed to run the graph")]
    Run { provider: ExecutionProvider },
}

/// A loaded graph that turns input ids into per-token logits.
///
/// The seam INSIDE this crate, so that the `ort`-backed session and the stub
/// are interchangeable and the detector below is written once. Without it, the
/// `Detector` implementation would be `#[cfg]`-duplicated and the version the
/// tests exercise would not be the version that ships.
pub trait Session {
    /// Per-token label logits for a tokenized document.
    fn run(&self, ids: &[u32]) -> Result<Vec<Vec<f32>>, OrtError>;

    /// The provider this session dispatches to, for diagnostics.
    fn provider(&self) -> ExecutionProvider;
}

/// A [`Session`] over canned logits, for wiring tests and the null model.
///
/// THIS IS WHY THE CRATE IS TESTABLE WITH ZERO WEIGHTS ON DISK. Everything
/// above the forward pass is `core/`'s pure code, and the forward pass itself
/// is a trait, so a canned session exercises the entire path: session ->
/// detector -> ensemble -> constrained decode -> alignment -> union. No
/// `.onnx` file, no download, no accelerator.
#[derive(Debug, Clone)]
pub struct StubSession {
    rows: Vec<Vec<f32>>,
    provider: ExecutionProvider,
}

impl StubSession {
    /// A session that always answers with these per-token logit rows.
    #[must_use]
    pub fn new(rows: Vec<Vec<f32>>) -> Self {
        Self {
            rows,
            provider: ExecutionProvider::Cpu,
        }
    }

    /// Pretend to dispatch to a given provider, so the reporting path can be
    /// tested on a machine that does not have the hardware.
    #[must_use]
    pub fn on(mut self, provider: ExecutionProvider) -> Self {
        self.provider = provider;
        self
    }
}

impl Session for StubSession {
    fn run(&self, ids: &[u32]) -> Result<Vec<Vec<f32>>, OrtError> {
        // The row count is checked HERE rather than left to the ensemble so
        // that a mis-wired stub fails in the crate that wired it, naming the
        // two numbers that disagree.
        if self.rows.len() != ids.len() {
            return Err(OrtError::RowCount {
                rows: self.rows.len(),
                tokens: ids.len(),
            });
        }
        Ok(self.rows.clone())
    }

    fn provider(&self) -> ExecutionProvider {
        self.provider
    }
}

/// One ensemble member, backed by a [`Session`].
///
/// Implements `core`'s [`Detector`], which is the whole point: this type is the
/// only thing `bindings/ort` contributes to L2. Decode, alignment and merge all
/// happen in `core/` on the `Vec<Vec<f32>>` this produces.
pub struct OrtDetector {
    session: Box<dyn Session>,
}

impl OrtDetector {
    /// Wrap a session as an L2 detector.
    #[must_use]
    pub fn new(session: Box<dyn Session>) -> Self {
        Self { session }
    }

    /// The provider this detector's session dispatches to.
    #[must_use]
    pub fn provider(&self) -> ExecutionProvider {
        self.session.provider()
    }
}

impl Detector for OrtDetector {
    fn infer(&self, ids: &[u32]) -> deid_tr_core::Result<Vec<Vec<f32>>> {
        // The trait's error type is `core`'s, which by I4 carries no text and
        // has no variant for a runtime failure. Rather than widen `core`'s enum
        // for a binding's concern, a failed run is reported as an empty logit
        // set, which the ensemble rejects loudly as a row-count mismatch and
        // names the detector index in. See the note in this crate's tests.
        Ok(self.session.run(ids).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::detect::{
        LabelSet, NerEnsemble, Normalization, Normalized, TokenSpan, Tokenized,
    };
    use deid_tr_core::EntityLabel;

    /// Synthetic. No real PHI, no TCKN (I8).
    const DOC: &str = "Hasta Ayşe'nin raporu okundu.";

    #[test]
    fn cpu_is_the_floor_and_is_always_selected_when_nothing_else_is_there() {
        let provider = select(Availability::cpu_only());
        assert_eq!(provider, ExecutionProvider::Cpu);
        assert!(provider.is_fallback());
    }

    #[test]
    fn an_accelerator_is_preferred_over_the_cpu_floor() {
        for (availability, expected) in [
            (
                Availability {
                    cuda: true,
                    ..Availability::cpu_only()
                },
                ExecutionProvider::Cuda,
            ),
            (
                Availability {
                    coreml: true,
                    ..Availability::cpu_only()
                },
                ExecutionProvider::CoreMl,
            ),
            (
                Availability {
                    directml: true,
                    ..Availability::cpu_only()
                },
                ExecutionProvider::DirectMl,
            ),
        ] {
            assert!(availability.has_accelerator());
            assert_eq!(select(availability), expected);
        }
    }

    #[test]
    fn selection_is_deterministic_when_several_providers_are_present() {
        // A box with two accelerators must not pick a different one per run:
        // near-tie logits resolve differently on different backends, and a
        // nondeterministic backend makes the eval_sha reproducibility gate
        // meaningless for anything L2 touches.
        let both = Availability {
            cuda: true,
            coreml: true,
            directml: true,
        };
        let first = select(both);
        assert_eq!(first, ExecutionProvider::Cuda);
        for _ in 0..8 {
            assert_eq!(select(both), first);
        }
    }

    #[test]
    fn selection_is_total_over_every_availability_combination() {
        for cuda in [false, true] {
            for coreml in [false, true] {
                for directml in [false, true] {
                    let availability = Availability {
                        cuda,
                        coreml,
                        directml,
                    };
                    let provider = select(availability);
                    assert!(
                        availability.offers(provider),
                        "selected a provider the host does not offer"
                    );
                }
            }
        }
    }

    #[test]
    fn with_no_runtime_linked_detection_reports_the_cpu_floor() {
        // Claiming an accelerator that nothing can dispatch to would make the
        // startup line a lie, and the startup line is the only thing an
        // operator has to tell them what ran.
        assert_eq!(Availability::detect(), Availability::cpu_only());
    }

    #[test]
    fn the_startup_line_carries_a_provider_type_and_nothing_else() {
        for provider in ExecutionProvider::PREFERENCE {
            let line = startup_line(provider);
            assert!(line.ends_with(provider.as_str()));
            assert!(
                line.is_ascii(),
                "the startup line must not be able to carry document text"
            );
            assert!(!line.contains(DOC));
            assert!(!line.contains("Ayşe"));
            assert_eq!(line.lines().count(), 1, "one line, one process");
        }
    }

    #[test]
    fn the_provider_is_chosen_once_per_process() {
        let first = selected();
        for _ in 0..4 {
            assert_eq!(selected(), first, "the provider changed mid-process");
        }
    }

    #[test]
    fn a_stub_session_whose_rows_do_not_match_the_input_fails_loudly() {
        let session = StubSession::new(vec![vec![0.0; 5]; 2]);
        assert_eq!(
            session.run(&[1, 2, 3]),
            Err(OrtError::RowCount { rows: 2, tokens: 3 })
        );
    }

    #[test]
    fn a_stub_session_reports_the_provider_it_pretends_to_use() {
        let detector = OrtDetector::new(Box::new(
            StubSession::new(Vec::new()).on(ExecutionProvider::CoreMl),
        ));
        assert_eq!(detector.provider(), ExecutionProvider::CoreMl);
    }

    #[test]
    fn the_whole_l2_path_runs_against_a_stub_with_no_onnx_file_on_disk() {
        // The claim this crate has to be able to make: plumbing proven, zero
        // weights. Everything after `infer` is `core`'s pure code, so a green
        // assertion here means the seam is wired, not that a model is good.
        let labels = LabelSet::new(&[EntityLabel::PatientName]);
        let normalized = Normalized::new(DOC, Normalization::Identity);

        // `[CLS] Hasta Ayşe'nin raporu okundu.`
        let name_start = DOC.find("Ayşe").expect("fixture");
        let tokenized = Tokenized::new(
            vec![0, 1, 2, 3],
            vec![
                TokenSpan::special(),
                TokenSpan::new(0, 5),
                TokenSpan::new(name_start, name_start + "Ayşe'nin".len()),
                TokenSpan::new(DOC.len() - 7, DOC.len()),
            ],
        )
        .expect("parallel by construction");

        // Canned logits: token 2 is a whole-entity `S-PATIENT_NAME`, the rest
        // are `O`. Column order is `LabelSet`'s: O, B, I, E, S.
        let outside = vec![4.0, 0.0, 0.0, 0.0, 0.0];
        let single = vec![0.0, 0.0, 0.0, 0.0, 4.0];
        let rows = vec![outside.clone(), outside.clone(), single, outside];

        let ensemble = NerEnsemble::new()
            .with_member(
                Box::new(OrtDetector::new(Box::new(StubSession::new(rows)))),
                labels,
            )
            .expect("one member");

        let merged = ensemble
            .detect(&normalized, &tokenized)
            .expect("the whole path runs");
        assert_eq!(merged.len(), 1);
        let span = merged[0].span();
        assert_eq!(
            &DOC[span.start()..span.end()],
            "Ayşe",
            "the Turkish case suffix must be excluded from the span"
        );
        assert_eq!(span.label(), EntityLabel::PatientName);
        assert_eq!(merged[0].support(), 1, "one member, one contributor");
    }

    #[test]
    fn a_failed_run_proposes_nothing_rather_than_guessing() {
        // A session that errors yields no logits, so the ensemble rejects the
        // row count and the document is NOT silently de-identified by a
        // detector that did not run. Failing closed here means an empty L2, and
        // L1's deterministic rules still cover the checksummed identifiers.
        let labels = LabelSet::new(&[EntityLabel::PatientName]);
        let normalized = Normalized::new(DOC, Normalization::Identity);
        let tokenized = Tokenized::new(vec![0, 1], vec![TokenSpan::special(); 2])
            .expect("parallel by construction");
        let detector = OrtDetector::new(Box::new(StubSession::new(Vec::new())));
        assert_eq!(detector.infer(&[0, 1]), Ok(Vec::new()));

        let ensemble = NerEnsemble::new()
            .with_member(Box::new(detector), labels)
            .expect("one member");
        assert!(
            ensemble.propose(&normalized, &tokenized).is_err(),
            "a detector that did not run must not pass for one that found nothing"
        );
    }
}
