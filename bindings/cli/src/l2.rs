//! L2 wiring: turning operator configuration into a LOCAL NER ensemble.
//!
//! # The shape is L3's, deliberately
//!
//! `src/l3.rs` established the pattern and this module follows it line for line:
//! one setting, resolved flag > environment > config file, carried with the
//! [`Origin`] that supplied it, and every refusal names the path AND the switch
//! rather than saying a layer is unavailable. An operator who has to learn two
//! different configuration idioms for two layers of the same tool learns
//! neither, and a refusal that does not say what is missing is a refusal that
//! gets worked around by dropping the layer -- which for L2 means running with
//! rules only and not being told.
//!
//! # There is one path and it names a DIRECTORY on this machine
//!
//! Not a hub id, not a URL, not a cache key. `bindings/ort` has no HTTP client
//! and this module adds none. Weights arrive by `deid pull` or from a release
//! bundle; I1 forbids a fetch at inference, and an air-gapped host is a
//! supported configuration rather than a degraded one.
//!
//! # What this build actually does when the flag is passed
//!
//! It resolves the directory, checks that every required file is there, reads
//! the checkpoint's own label inventory out of `config.json`, derives the BIO
//! conversion, and then REFUSES -- because no ONNX Runtime is linked into this
//! build and there is therefore no forward pass to run. It refuses loudly,
//! naming the missing piece, and it does not fall back to running without L2.
//!
//! WITHOUT THE FLAG, BEHAVIOUR IS EXACTLY WHAT IT WAS. No ensemble is
//! installed, `Pipeline::propose_ner` returns nothing, and the disclosure the
//! binary prints is unchanged. This build masks ZERO names through L2 either
//! way; the difference is that passing the flag now tells you so instead of
//! being ignored.

use std::path::{Path, PathBuf};

use deid_tr_core::detect::{NerEnsemble, PieceLabels};
use deid_tr_ort::{ModelDir, ModelError};

use crate::config::{EnvView, FileConfig};

/// `DEID_L2_MODEL` -- directory holding the ONNX checkpoint and its tokenizer.
pub const ENV_MODEL: &str = "DEID_L2_MODEL";

/// `--l2-model DIR`, spelled the way the operator types it.
pub const FLAG: &str = "--l2-model";

/// `l2_model = "DIR"` in the config file.
pub const FILE_KEY: &str = "l2_model in the config file";

/// Which of a word's subword pieces the published checkpoints supervise.
///
/// A CONSTANT, not a flag. It is a fact about how a checkpoint was fine-tuned,
/// recorded on its card, and an operator has no way to know it and no business
/// guessing it -- guessing wrong does not fail, it silently decodes from rows
/// the training never constrained. Every checkpoint this project publishes is
/// trained with `is_split_into_words` and `-100` on continuation pieces, so the
/// value is fixed here and a checkpoint that differs needs a code change and a
/// review rather than a command line.
pub const PIECES: PieceLabels = PieceLabels::FirstPieceOnly;

/// Which layer of the precedence chain supplied the setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The command-line flag.
    Flag,
    /// The environment variable.
    Env,
    /// The config file.
    ConfigFile,
}

impl Origin {
    /// The switch, spelled the way the operator would type it.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Flag => FLAG,
            Self::Env => ENV_MODEL,
            Self::ConfigFile => FILE_KEY,
        }
    }
}

/// The resolved model directory plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The directory as the operator wrote it.
    pub path: PathBuf,
    /// The layer that supplied it.
    pub origin: Origin,
}

/// The L2 path taken from the command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L2Flags {
    /// `--l2-model DIR`.
    pub model: Option<String>,
}

/// L2's configuration after precedence has been applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L2Config {
    /// The checkpoint directory, when one was configured anywhere.
    pub model: Option<Setting>,
}

impl L2Config {
    /// True when no checkpoint was configured at any layer.
    ///
    /// The caller uses this to keep the unconfigured path byte-identical to
    /// what it was before this module existed.
    #[must_use]
    pub fn is_unconfigured(&self) -> bool {
        self.model.is_none()
    }
}

/// Apply the documented precedence: flag > env > config file.
///
/// The same order and the same reasoning as `config::resolve` and
/// `l3::resolve`: the narrower and more deliberate the scope of a setting, the
/// more it must win.
#[must_use]
pub fn resolve(flags: &L2Flags, env: &EnvView, file: &FileConfig) -> L2Config {
    let model = flags
        .model
        .as_ref()
        .map(|raw| Setting {
            path: PathBuf::from(raw),
            origin: Origin::Flag,
        })
        .or_else(|| {
            env.l2_model.as_ref().map(|raw| Setting {
                path: PathBuf::from(raw),
                origin: Origin::Env,
            })
        })
        .or_else(|| {
            file.l2_model.as_ref().map(|raw| Setting {
                path: PathBuf::from(raw),
                origin: Origin::ConfigFile,
            })
        });
    L2Config { model }
}

/// Why the NER ensemble could not be built.
///
/// One variant, wrapping `bindings/ort`'s own classification. The remedies live
/// there because that is where the file layout is known; this layer's only job
/// is to supply the origin string so the message names the switch the operator
/// used rather than the one the author happened to think of.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum L2Error {
    /// The configured checkpoint directory could not be turned into a detector.
    #[error(transparent)]
    Model(#[from] ModelError),
}

/// Validate the configured checkpoint and build the ensemble.
///
/// `Ok(None)` means NOTHING WAS CONFIGURED, which is not an error: L2 is
/// optional and a pipeline without it is the Safe Harbor pipeline this binary
/// has always shipped. `Err` means something WAS configured and could not be
/// used, which must never be downgraded to `Ok(None)` -- an operator who asked
/// for a model and got a rules-only run without being told has a document they
/// believe is more masked than it is.
pub fn ensemble(config: &L2Config) -> Result<Option<NerEnsemble>, L2Error> {
    let Some(setting) = config.model.as_ref() else {
        return Ok(None);
    };
    Ok(Some(build(&setting.path, setting.origin.describe())?))
}

/// Build one member's ensemble from a directory, naming `origin` in failures.
///
/// Split out from [`ensemble`] so the tests can drive it against a fixture
/// directory without going through the precedence chain, and so `deid doctor`
/// can report the same verdict `deid mask` would reach.
pub fn build(directory: &Path, origin: &'static str) -> Result<NerEnsemble, L2Error> {
    let model = ModelDir::open(directory, origin)?;
    // Derived BEFORE the load is attempted, so a checkpoint whose label
    // inventory this build cannot decode is reported as such rather than as a
    // missing runtime. The operator can fix a label map; they cannot fix a
    // build from the command line, and telling them the unfixable thing first
    // hides the fixable one.
    let scheme = model.scheme()?;
    // `load` cannot succeed in this build -- it returns `NotLinked` and says
    // so -- but the call, the wrapping and the assembly below are the real
    // ones, compiled and reachable. When the runtime is admitted, the session
    // it returns flows through here unchanged.
    let session = model.load()?;
    assemble(scheme, Box::new(deid_tr_ort::OrtDetector::new(session)))
}

/// Put one checkpoint's detector and its BIO head into an ensemble.
///
/// SEPARATE FROM [`build`] SO IT CAN BE TESTED WITH NO WEIGHTS. This is the
/// assembly that decides how the CLI decodes a checkpoint -- the BIO
/// conversion and [`PIECES`] -- and it is the part most likely to be wrong in a
/// way nothing notices, because a wrong setting still yields well-formed spans.
/// Driving it with a canned-logit detector proves the decision, and the one
/// thing it cannot prove is that a real graph produces those logits.
pub fn assemble(
    scheme: deid_tr_core::detect::BioScheme,
    detector: Box<dyn deid_tr_core::pipeline::Detector>,
) -> Result<NerEnsemble, L2Error> {
    NerEnsemble::new()
        .with_bio_member(detector, scheme, PIECES)
        .map_err(|_| {
            // `with_bio_member` is fallible only on detector-id overflow, which
            // needs 65 536 members and cannot arise from one.
            L2Error::Model(ModelError::NotLinked {
                path: String::new(),
                missing: "ensemble slot",
                origin: FLAG,
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A checkpoint directory with the right files and no weights in them.
    ///
    /// Zero-byte graph and tokenizer: nothing in this path opens either, which
    /// is what makes the whole wiring testable with no model on disk. Every
    /// call gets its own directory, for the reason `l3.rs` records.
    fn checkpoint(config: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("deid-cli-l2-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("model.onnx"), b"").expect("fixture");
        std::fs::write(dir.join("tokenizer.json"), b"").expect("fixture");
        std::fs::write(dir.join("config.json"), config).expect("fixture");
        dir
    }

    const BIO_CONFIG: &str =
        r#"{"id2label": {"0": "O", "1": "B-PER", "2": "I-PER"}, "model_type": "bert"}"#;

    #[test]
    fn precedence_is_flag_then_env_then_config_file() {
        let env = EnvView {
            l2_model: Some("/env/checkpoint".to_owned()),
            ..EnvView::default()
        };
        let file = FileConfig {
            l2_model: Some("/file/checkpoint".to_owned()),
            ..FileConfig::default()
        };

        let with_flag = resolve(
            &L2Flags {
                model: Some("/flag/checkpoint".to_owned()),
            },
            &env,
            &file,
        );
        let setting = with_flag.model.expect("model");
        assert_eq!(setting.path, PathBuf::from("/flag/checkpoint"));
        assert_eq!(setting.origin, Origin::Flag);

        let without_flag = resolve(&L2Flags::default(), &env, &file);
        assert_eq!(
            without_flag.model.expect("model").origin,
            Origin::Env,
            "the environment must beat the config file"
        );

        let only_file = resolve(&L2Flags::default(), &EnvView::default(), &file);
        assert_eq!(only_file.model.expect("model").origin, Origin::ConfigFile);
    }

    #[test]
    fn nothing_configured_is_not_an_error_and_installs_no_ensemble() {
        // The property that keeps the default path byte-identical: an operator
        // who passes no flag gets exactly the binary they had before.
        let config = L2Config::default();
        assert!(config.is_unconfigured());
        let built = ensemble(&config).expect("an absent model is not a failure");
        assert!(built.is_none());
    }

    #[test]
    fn a_missing_directory_names_the_path_and_the_switch_that_supplied_it() {
        for (origin, expected) in [
            (Origin::Flag, FLAG),
            (Origin::Env, ENV_MODEL),
            (Origin::ConfigFile, FILE_KEY),
        ] {
            let config = L2Config {
                model: Some(Setting {
                    path: PathBuf::from("/nonexistent/berturk-deid"),
                    origin,
                }),
            };
            let error = ensemble(&config)
                .err()
                .expect("an absent directory must refuse")
                .to_string();
            assert!(error.contains("/nonexistent/berturk-deid"), "{error}");
            assert!(error.contains(expected), "{error}");
            assert!(error.contains("Nothing was masked"), "{error}");
        }
    }

    #[test]
    fn a_configured_model_never_degrades_into_a_run_without_one() {
        // THE PROPERTY THAT MATTERS MORE THAN THE MESSAGE. There is no value of
        // the arguments on which a configured-but-unusable checkpoint yields
        // `Ok(None)`, so there is no path by which an operator who asked for L2
        // gets a rules-only document and is not told.
        for config in [
            r#"{"model_type": "bert"}"#,
            r#"{"id2label": {"0": "O", "1": "B-VESSEL_NAME"}}"#,
            BIO_CONFIG,
        ] {
            let dir = checkpoint(config);
            let outcome = ensemble(&L2Config {
                model: Some(Setting {
                    path: dir,
                    origin: Origin::Flag,
                }),
            });
            assert!(
                outcome.is_err(),
                "a configured checkpoint must not silently produce no ensemble"
            );
        }
    }

    #[test]
    fn a_valid_checkpoint_is_refused_with_the_reason_being_this_build() {
        // The honest end state of this milestone. The directory is complete,
        // the label inventory parses, the BIO conversion is derived -- and the
        // build still cannot run a forward pass, so it says exactly that and
        // masks nothing.
        let dir = checkpoint(BIO_CONFIG);
        let error = build(&dir, FLAG)
            .err()
            .expect("no runtime is linked into this build")
            .to_string();
        assert!(error.contains("masked NOTHING"), "{error}");
        assert!(error.contains("ONNX Runtime"), "{error}");
        assert!(
            error.contains("label inventory is valid"),
            "the checkpoint must be exonerated, not blamed: {error}"
        );
    }

    #[test]
    fn a_label_problem_is_reported_before_the_missing_runtime() {
        // Ordering matters: the operator can fix a label map and cannot fix
        // this build from the command line, so the fixable problem is the one
        // they are told about.
        let dir = checkpoint(r#"{"id2label": {"0": "O", "1": "B-VESSEL_NAME"}}"#);
        let error = build(&dir, FLAG).err().expect("unmapped type").to_string();
        assert!(error.contains("VESSEL_NAME"), "{error}");
        assert!(!error.contains("ONNX Runtime"), "{error}");
    }

    #[test]
    fn the_assembly_decodes_a_turkish_name_with_a_case_suffix_from_canned_logits() {
        // THE ONLY THING THAT CAN BE PROVEN WITHOUT WEIGHTS, proven. Given a
        // BIO head's logits, does the CLI's own assembly -- this crate's
        // `PIECES` setting, `bindings/ort`'s label mapping, `core`'s widening,
        // constrained decode, word anchoring and suffix trim -- put the span on
        // `Ayşe` at original byte offsets? It does, and that is a statement
        // about the wiring. It is NOT a statement that any checkpoint produces
        // these logits, and no message in this build claims one.
        use deid_tr_core::detect::{words, MockDetector, Normalization, Normalized, Tokenized};
        use deid_tr_ort::model::{id2label, ModelDir};

        const DOC: &str = "Hasta Ayşe'nin carcinoma'lı raporu okundu";

        let dir = checkpoint(BIO_CONFIG);
        let model = ModelDir::open(&dir, FLAG).expect("checkpoint");
        assert_eq!(
            id2label(BIO_CONFIG).expect("map").len(),
            3,
            "the fixture is the three-column head the assertions below assume"
        );
        let scheme = model.scheme().expect("BIO head");

        let normalized = Normalized::new(DOC, Normalization::Identity);
        let word_spans = words(normalized.text());
        // `[CLS] Hasta Ay ##şe ' nin carcinoma ##'lı raporu okundu [SEP]`
        let word_ids = [
            None,
            Some(0),
            Some(1),
            Some(1),
            Some(1),
            Some(1),
            Some(2),
            Some(2),
            Some(3),
            Some(4),
            None,
        ];
        let piece_spans = deid_tr_core::detect::word_piece_spans(&word_spans, &word_ids)
            .expect("word ids in range");
        let ids: Vec<u32> = (0..piece_spans.len() as u32).collect();
        let tokenized = Tokenized::new(ids, piece_spans).expect("parallel");

        // `B-PER` on the first piece of the name, `O` everywhere else --
        // including on `carcinoma'lı`, which must survive untouched.
        let mut rows = vec![vec![6.0_f32, 0.0, 0.0]; word_ids.len()];
        rows[2] = vec![0.0, 6.0, 0.0];

        let ensemble = assemble(scheme, Box::new(MockDetector::new(rows))).expect("assembly");
        let spans = ensemble
            .propose(&normalized, &tokenized)
            .expect("the whole L2 path runs");
        assert_eq!(spans.len(), 1);
        assert_eq!(&DOC[spans[0].start()..spans[0].end()], "Ayşe");
        assert_eq!(spans[0].label(), deid_tr_core::EntityLabel::PatientName);
    }

    #[test]
    fn the_piece_convention_is_fixed_rather_than_configurable() {
        // A regression guard on a constant, because the failure mode of getting
        // it wrong is silent: the decode still produces well-formed spans, it
        // just derives them from rows the fine-tune never supervised.
        assert_eq!(PIECES, PieceLabels::FirstPieceOnly);
    }
}
