//! `deid doctor` -- the honest answer to "why is the deep tier unavailable?",
//! delivered by the tool instead of by a maintainer.
//!
//! # Why a command and not a paragraph in the README
//!
//! Every layer's availability is a property of THIS machine: which weights are
//! installed, which runtime is on the disk, whether the execute bit survived the
//! copy. A document can only describe the general case, so an operator whose L3
//! is unavailable for a specific, fixable reason reads "requires a local model"
//! and concludes the feature does not exist. Then they run Safe Harbor and
//! believe they ran Expert Determination.
//!
//! # The rule this module is written to
//!
//! IT NEVER OVERSTATES. Where a layer is unavailable it says so in the same
//! words as the refusal the operator would otherwise hit, and where no remedy
//! exists in this build it says THAT rather than printing a command that will
//! not work. In particular L2 reports UNAVAILABLE with no fix, because no
//! trained detector ships and `deid` therefore masks no names -- the single
//! fact about this tool most likely to be misread, and the one a diagnostic
//! command would be most tempting to soften.

use std::io::Write;

use crate::l2::L2Config;
use crate::l3::{L3Config, Origin, What, ENV_MODEL, ENV_RUNTIME};

/// Whether a layer can actually run on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The layer runs.
    Available,
    /// The layer does not run, and something can be done about it.
    Unavailable,
}

impl State {
    const fn tag(self) -> &'static str {
        match self {
            Self::Available => "AVAILABLE  ",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

/// One line of the report.
struct Row {
    layer: &'static str,
    state: State,
    detail: String,
    /// What to do about it. Empty when there is nothing to do.
    fix: String,
}

/// True when the path names an existing regular file.
fn present(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// The L3 row, which is the whole reason this command exists.
///
/// Reports the two paths SEPARATELY and says where each came from, because the
/// commonest real failure is a config file and an environment variable
/// disagreeing about which weights are in use.
fn l3_row(config: &L3Config) -> Row {
    let mut detail = String::new();
    let mut fix = String::new();
    let mut state = State::Available;

    for (what, setting, env, flag) in [
        (
            What::Model,
            config.model.as_ref(),
            ENV_MODEL,
            "--model PATH-TO.gguf",
        ),
        (
            What::Runtime,
            config.runtime.as_ref(),
            ENV_RUNTIME,
            "--runtime PATH-TO-llama-cli",
        ),
    ] {
        match setting {
            None => {
                state = State::Unavailable;
                detail.push_str(&format!("{what}: not configured. "));
                fix.push_str(&format!(
                    "Set the {what} with `deid mask --tier expert {flag}`, or {env}=PATH, \
                     or `l3_{what} = \"PATH\"` in your config file. "
                ));
            }
            Some(setting) => {
                let shown = setting.path.to_string_lossy();
                let from = describe(setting.origin, what);
                if present(&setting.path) {
                    detail.push_str(&format!("{what}: {shown} (from {from}), present. "));
                } else {
                    state = State::Unavailable;
                    detail.push_str(&format!("{what}: {shown} (from {from}), MISSING. "));
                    fix.push_str(&format!(
                        "Install the {what} at {shown}, or point {from} somewhere else. "
                    ));
                }
            }
        }
    }
    if state == State::Available {
        detail.push_str(
            "Both are present, so `deid mask --tier expert` will run the local contextual sweep.",
        );
    }
    Row {
        layer: "L3 contextual sweep (local LLM)",
        state,
        detail,
        fix,
    }
}

/// The origin, spelled the way the operator would type it.
fn describe(origin: Origin, what: What) -> &'static str {
    origin.describe(what)
}

/// Write the report.
///
/// Takes the resolved config rather than reading the environment itself, so the
/// tests exercise every combination without mutating process-global state.
/// The L2 row. UNAVAILABLE in every configuration this build can be in.
///
/// The load-bearing sentence of this command, and it must survive every future
/// edit: no ONNX Runtime is linked, so `deid` masks ZERO NAMES whether or not a
/// checkpoint directory is configured. A diagnostic that let anyone infer
/// otherwise would be worse than no diagnostic at all -- which is why the
/// configured case gets a LONGER warning rather than a softer one. An operator
/// who has just pointed the tool at a checkpoint is exactly the operator most
/// likely to assume it is being used.
fn l2_row(config: &L2Config) -> Row {
    let detail = if config.is_unconfigured() {
        "No L2 checkpoint is configured and no ONNX Runtime is linked into this build, \
         so deid masks ZERO NAMES. PATIENT_NAME, CLINICIAN_NAME and RELATIVE_NAME are \
         never masked, at any tier, including --tier expert."
            .to_owned()
    } else {
        "An L2 checkpoint IS configured, and this build still has no ONNX Runtime linked, \
         so it masks ZERO NAMES. `deid mask` will refuse rather than run without the \
         model you asked for."
            .to_owned()
    };
    Row {
        layer: "L2 NER ensemble (names)",
        state: State::Unavailable,
        detail,
        fix: format!(
            "Not fixable from this machine: the inference runtime is a build-time \
             dependency (see bindings/ort/Cargo.toml). Configuring {} changes which \
             message you get, not whether names are masked.",
            crate::l2::FLAG
        ),
    }
}

pub fn report(config: &L3Config, l2: &L2Config, out: &mut dyn Write) -> std::io::Result<()> {
    let rows = [
        Row {
            layer: "L1 deterministic rules",
            state: State::Available,
            detail: "TCKN, VKN, SGK, IBAN, phone, MRN, date and email rules are compiled in \
                     and need no model."
                .to_owned(),
            fix: String::new(),
        },
        l2_row(l2),
        l3_row(config),
        Row {
            layer: "L4 router and allowlist",
            state: State::Available,
            detail: "The audited medical vocabulary is compiled in; opt out with \
                     --no-medical-allowlist."
                .to_owned(),
            fix: String::new(),
        },
        Row {
            layer: "L5 surrogates",
            state: State::Available,
            detail: "Format-preserving surrogates run by default from a per-run salt; opt \
                     out with --placeholder-labels."
                .to_owned(),
            fix: String::new(),
        },
    ];

    writeln!(out, "deid doctor: what this machine can and cannot do.\n")?;
    for row in &rows {
        writeln!(out, "{}  {}", row.state.tag(), row.layer)?;
        writeln!(out, "             {}", row.detail)?;
        if !row.fix.is_empty() {
            writeln!(out, "             fix: {}", row.fix.trim_end())?;
        }
        writeln!(out)?;
    }
    writeln!(
        out,
        "No model weights ship with this repository and none are ever downloaded at \
         inference time (I1). The L3 runtime is a program on this machine and the weights \
         are a file on this disk; you supply both."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::l3::Setting;

    use super::*;

    fn rendered(config: &L3Config) -> String {
        rendered_with(config, &L2Config::default())
    }

    fn rendered_with(config: &L3Config, l2: &L2Config) -> String {
        let mut out = Vec::new();
        report(config, l2, &mut out).expect("write");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn l2_is_unavailable_whether_or_not_a_checkpoint_is_configured() {
        // The sentence this command exists to keep true. A configured
        // checkpoint must not read as a working one, and the configured case
        // gets the LONGER warning because that operator is the one most likely
        // to assume the model is in use.
        let bare = rendered(&L3Config::default());
        assert!(bare.contains("UNAVAILABLE  L2 NER ensemble"));
        assert!(bare.contains("ZERO NAMES"));

        let configured = rendered_with(
            &L3Config::default(),
            &L2Config {
                model: Some(crate::l2::Setting {
                    path: std::path::PathBuf::from("/opt/models/berturk-deid"),
                    origin: crate::l2::Origin::Flag,
                }),
            },
        );
        assert!(configured.contains("UNAVAILABLE  L2 NER ensemble"));
        assert!(configured.contains("ZERO NAMES"));
        assert!(configured.contains("will refuse"));
        assert!(configured.contains(crate::l2::FLAG));
    }

    #[test]
    fn an_unconfigured_l3_is_reported_as_fixable_and_names_every_switch() {
        let printed = rendered(&L3Config::default());
        assert!(printed.contains("UNAVAILABLE  L3 contextual sweep"));
        assert!(printed.contains("--model"));
        assert!(printed.contains("--runtime"));
        assert!(printed.contains(ENV_MODEL));
        assert!(printed.contains(ENV_RUNTIME));
    }

    #[test]
    fn a_configured_but_absent_model_is_named_along_with_where_it_came_from() {
        let config = L3Config {
            model: Some(Setting {
                path: PathBuf::from("/nonexistent/weights-not-here.gguf"),
                origin: Origin::Env,
            }),
            runtime: None,
        };
        let printed = rendered(&config);
        assert!(printed.contains("weights-not-here.gguf"));
        assert!(printed.contains("MISSING"));
        assert!(printed.contains(ENV_MODEL));
    }

    #[test]
    fn a_fully_installed_l3_reports_available() {
        let dir = std::env::temp_dir().join("deid-cli-doctor-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let weights = dir.join("model.gguf");
        let runtime = dir.join("local-runtime");
        for path in [&weights, &runtime] {
            std::fs::write(path, b"").expect("fixture");
        }
        let config = L3Config {
            model: Some(Setting {
                path: weights,
                origin: Origin::Flag,
            }),
            runtime: Some(Setting {
                path: runtime,
                origin: Origin::ConfigFile,
            }),
        };
        let printed = rendered(&config);
        assert!(printed.contains("AVAILABLE    L3 contextual sweep"));
        assert!(printed.contains("l3_runtime in the config file"));
    }

    #[test]
    fn the_report_never_softens_the_fact_that_no_names_are_masked() {
        // The honesty invariant, asserted rather than trusted to review. A
        // future edit that makes this command reassuring fails here.
        let printed = rendered(&L3Config::default());
        assert!(printed.contains("ZERO NAMES"));
        assert!(printed.contains("UNAVAILABLE  L2 NER ensemble"));
        assert!(
            printed.contains("including --tier expert"),
            "expert must not read as the tier that finally masks names"
        );
    }
}
