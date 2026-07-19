//! `deid` — the native CLI.
//!
//! # Command surface
//!
//! ```text
//! deid mask [FILE] [--tier safe-harbor|expert]   de-identify a document
//! deid mask --placeholder-labels                 opt OUT of L5 surrogates
//! deid mask --no-medical-allowlist               opt OUT of the class C vocabulary
//! deid update [--check]                          check for a new release
//! deid pull [--from DIR]                         fetch model weights (M3)
//! deid version                                   print the version
//! deid --offline <command>                       disable all network activity
//! ```
//!
//! # Where the update check is allowed to happen
//!
//! At process start, before dispatch, for commands that never open a document —
//! and nowhere else. The `Command::Mask` arm below contains no reference to the
//! updater and neither does `src/mask.rs`; `tests/mask_path_is_offline.rs`
//! enforces both. `mask` is excluded even though the check would begin before the
//! document is read, because the check is asynchronous and would otherwise still
//! be in flight while the note is in memory.
//!
//! # Honesty about stubs
//!
//! `deid pull` is not implemented. It says so and exits non-zero rather than
//! printing a reassuring message and doing nothing, because a command that
//! appears to have fetched weights and did not is how a pipeline silently runs
//! with no detector.

mod config;
mod mask;
mod notice;
mod transport;
mod update;
mod verify;

use std::io::Write;
use std::process::ExitCode;
use std::time::SystemTime;

use config::{CliFlags, Config, EnvView};
use deid_tr_core::Tier;

/// The running version, from the workspace manifest.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for a command that exists but is not implemented yet.
const EXIT_UNIMPLEMENTED: u8 = 2;

enum Command {
    Mask {
        path: Option<String>,
        tier: Tier,
        opts: mask::Opts,
    },
    Update,
    Pull {
        from: Option<String>,
    },
    Version,
    Usage {
        unknown: bool,
    },
}

fn parse_args(args: &[String]) -> (CliFlags, Command) {
    let mut flags = CliFlags::default();
    let mut rest = Vec::new();
    for arg in args {
        if arg == "--offline" {
            flags.offline = true;
        } else {
            rest.push(arg.clone());
        }
    }

    let Some(verb) = rest.first().map(String::as_str) else {
        return (flags, Command::Usage { unknown: false });
    };
    let tail = &rest[1..];
    let value_of = |name: &str| {
        tail.iter()
            .position(|a| a == name)
            .and_then(|i| tail.get(i + 1))
            .cloned()
    };

    let command = match verb {
        "mask" => {
            let tier = match value_of("--tier").as_deref() {
                Some("expert") | Some("expert-determination") => Tier::ExpertDetermination,
                _ => Tier::SafeHarbor,
            };
            let path = tail
                .iter()
                .find(|a| !a.starts_with('-'))
                .filter(|a| Some(a.as_str()) != value_of("--tier").as_deref())
                .cloned();
            // Opt-OUTS, both of them. A caller who passes neither gets the
            // audited medical vocabulary and real surrogates; the degraded
            // configurations have to be asked for by name.
            let opts = mask::Opts {
                placeholder_labels: tail.iter().any(|a| a == "--placeholder-labels"),
                no_medical_allowlist: tail.iter().any(|a| a == "--no-medical-allowlist"),
            };
            Command::Mask { path, tier, opts }
        }
        "update" => Command::Update,
        "pull" => Command::Pull {
            from: value_of("--from"),
        },
        "version" | "--version" | "-V" => Command::Version,
        "help" | "--help" | "-h" => Command::Usage { unknown: false },
        _ => Command::Usage { unknown: true },
    };
    (flags, command)
}

fn load_config(flags: &CliFlags) -> Config {
    let env = EnvView::from_process();
    let file = config::load_file(&env).unwrap_or_default();
    config::resolve(flags, &env, &file)
}

/// Start a check on a detached thread and return immediately.
///
/// Deliberately never joined. If the process finishes its real work first the
/// check dies with it, which is the correct priority: the tool's job is masking,
/// and an update check has no claim on the operator's time. This is what makes
/// the check non-blocking in the strong sense — there is no code path on which
/// its duration is added to the command's duration.
fn spawn_startup_check(config: &Config) {
    if !config.checks_allowed() {
        return;
    }
    let config = config.clone();
    let install_target = std::env::current_exe().ok();
    std::thread::spawn(move || {
        // The result is intentionally discarded. Failure is silent and
        // non-fatal; a user who wants to know runs `deid update`.
        let _ = update::run_check(
            &config,
            VERSION,
            &transport::TcpProbe,
            &transport::HttpsSource,
            SystemTime::now(),
            install_target.as_deref(),
        );
    });
}

fn report(outcome: &update::Outcome, out: &mut dyn Write) {
    let _ = match outcome {
        update::Outcome::Blocked(update::Blocked::Disabled(by)) => writeln!(
            out,
            "deid: update checks are disabled by {}",
            by.as_str()
        ),
        update::Outcome::Blocked(update::Blocked::NoEndpoint) => writeln!(
            out,
            "deid: no release host is configured (set update_host in your config file), so nothing was sent"
        ),
        update::Outcome::Blocked(update::Blocked::AirGapSuppressed) => writeln!(
            out,
            "deid: a previous check found no route out, so checks are paused for 24h"
        ),
        update::Outcome::AirGapped => writeln!(
            out,
            "deid: the release host is unreachable; treating this install as air-gapped"
        ),
        update::Outcome::Unreachable => {
            writeln!(out, "deid: the update check did not complete")
        }
        update::Outcome::UpToDate => writeln!(out, "deid: {VERSION} is current"),
        update::Outcome::Installed { version } => {
            writeln!(out, "deid: verified and installed {version}")
        }
        update::Outcome::Staged { version, path } => writeln!(
            out,
            "deid: verified {version} but could not replace the running binary; it is staged at {}",
            path.display()
        ),
        update::Outcome::NotifyOnly { version, .. } => writeln!(
            out,
            "deid: {version} is available but was NOT installed, because no release signing key is pinned in this configuration. Set update_public_key, or upgrade manually."
        ),
        update::Outcome::Refused(err) => writeln!(out, "deid: {err}"),
    };
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (flags, command) = parse_args(&args);
    let config = load_config(&flags);

    let mut stderr = std::io::stderr();
    // Before anything else, including before any check is spawned: nobody
    // discovers this tool's network behaviour from a packet capture.
    notice::show_once(&config, &mut stderr);

    match command {
        // NOTE TO ANY FUTURE EDITOR: this arm must not reference `update` or
        // `transport`. A clinical document is about to be in memory.
        Command::Mask { path, tier, opts } => {
            let mut stdout = std::io::stdout();
            match mask::run(path.as_deref(), tier, opts, &mut stdout, &mut stderr) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    let _ = writeln!(stderr, "deid: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Update => {
            // Explicit invocation: synchronous, and it clears any air-gap
            // suppression first, because a person typing `deid update` is
            // telling us the network situation may have changed.
            update::clear_air_gap(&config.state_dir);
            let outcome = update::run_check(
                &config,
                VERSION,
                &transport::TcpProbe,
                &transport::HttpsSource,
                SystemTime::now(),
                std::env::current_exe().ok().as_deref(),
            );
            report(&outcome, &mut stderr);
            ExitCode::SUCCESS
        }
        Command::Pull { from } => {
            spawn_startup_check(&config);
            let _ = writeln!(
                stderr,
                "deid pull is NOT IMPLEMENTED yet: no model weights are fetched, staged, or verified by this build, and none are bundled. It lands with the L2 ensemble (M3). Nothing was downloaded."
            );
            if let Some(dir) = from {
                let _ = writeln!(
                    stderr,
                    "deid: --from {dir} was parsed but not used; the air-gapped bundle path lands with the same milestone."
                );
            }
            ExitCode::from(EXIT_UNIMPLEMENTED)
        }
        Command::Version => {
            spawn_startup_check(&config);
            let _ = writeln!(std::io::stdout(), "deid {VERSION}");
            ExitCode::SUCCESS
        }
        Command::Usage { unknown } => {
            let _ = writeln!(
                stderr,
                "usage: deid [--offline] <mask|update|pull|version> [args]\n\
                 \n\
                   mask [FILE] [--tier safe-harbor|expert]  de-identify a document (stdin when FILE is omitted)\n\
                        [--placeholder-labels]              write [LABEL] instead of a surrogate; every patient in the note collapses onto one token\n\
                        [--no-medical-allowlist]            run L4 with no medical vocabulary; carcinoma, costa and Adalat will be masked\n\
                   update                                   check for a new release\n\
                   pull [--from DIR]                        fetch model weights (not implemented)\n\
                   version                                  print the version\n\
                 \n\
                 Automatic update checks are ON by default. Disable with --offline,\n\
                 DEID_NO_UPDATE=1, or auto_update = false in your config file."
            );
            if unknown {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn the_offline_flag_is_global_and_position_independent() {
        for raw in [
            vec!["--offline", "mask", "note.txt"],
            vec!["mask", "--offline", "note.txt"],
            vec!["mask", "note.txt", "--offline"],
        ] {
            let (flags, command) = parse_args(&args(&raw));
            assert!(flags.offline, "{raw:?}");
            assert!(matches!(command, Command::Mask { .. }));
        }
    }

    #[test]
    fn mask_parses_its_file_and_tier() {
        let (_, command) = parse_args(&args(&["mask", "note.txt", "--tier", "expert"]));
        match command {
            Command::Mask { path, tier, opts } => {
                assert_eq!(path.as_deref(), Some("note.txt"));
                assert_eq!(tier, Tier::ExpertDetermination);
                // No flags means no opt-outs: the vocabulary and L5 are on.
                assert!(!opts.placeholder_labels);
                assert!(!opts.no_medical_allowlist);
            }
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn mask_defaults_to_safe_harbor_and_to_stdin() {
        let (_, command) = parse_args(&args(&["mask"]));
        match command {
            Command::Mask { path, tier, .. } => {
                assert_eq!(path, None);
                assert_eq!(
                    tier,
                    Tier::SafeHarbor,
                    "the expensive tier must never be entered implicitly"
                );
            }
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn the_degraded_configurations_are_opt_outs_and_are_parsed_as_such() {
        let (_, command) = parse_args(&args(&[
            "mask",
            "note.txt",
            "--placeholder-labels",
            "--no-medical-allowlist",
        ]));
        match command {
            Command::Mask { opts, .. } => {
                assert!(opts.placeholder_labels);
                assert!(opts.no_medical_allowlist);
            }
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn the_tier_value_is_not_mistaken_for_the_input_file() {
        let (_, command) = parse_args(&args(&["mask", "--tier", "expert"]));
        match command {
            Command::Mask { path, .. } => assert_eq!(path, None),
            _ => panic!("expected mask"),
        }
    }

    #[test]
    fn every_documented_verb_parses() {
        assert!(matches!(parse_args(&args(&["update"])).1, Command::Update));
        assert!(matches!(
            parse_args(&args(&["pull", "--from", "./bundle"])).1,
            Command::Pull { from: Some(_) }
        ));
        assert!(matches!(
            parse_args(&args(&["version"])).1,
            Command::Version
        ));
        assert!(matches!(
            parse_args(&args(&["frobnicate"])).1,
            Command::Usage { unknown: true }
        ));
    }

    #[test]
    fn a_blocked_outcome_names_the_switch_that_blocked_it() {
        // An operator told only "updates are disabled" edits the wrong file.
        let mut out = Vec::new();
        report(
            &update::Outcome::Blocked(update::Blocked::Disabled(config::DisabledBy::EnvVar)),
            &mut out,
        );
        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains(config::ENV_NO_UPDATE));
    }

    #[test]
    fn a_notify_only_outcome_says_it_did_not_install() {
        let mut out = Vec::new();
        report(
            &update::Outcome::NotifyOnly {
                version: "0.2.0".to_owned(),
                trust: verify::Trust::ChecksumOnlyNoPinnedKey,
            },
            &mut out,
        );
        let printed = String::from_utf8(out).expect("utf8");
        assert!(printed.contains("NOT installed"));
        assert!(printed.contains("signing key"));
    }
}
