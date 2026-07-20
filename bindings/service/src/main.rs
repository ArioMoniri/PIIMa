//! `deid-serve` -- the local REST surface.
//!
//! # Command surface
//!
//! ```text
//! deid-serve                                  bind 127.0.0.1:8787
//! deid-serve --port 9000                      a different loopback port
//! deid-serve --host <ADDR> --expose --token X bind one specific non-loopback address
//! deid-serve --tier expert                    Expert Determination (needs a local LLM)
//! deid-serve --placeholder-labels             opt OUT of L5 surrogates
//! deid-serve --no-medical-allowlist           opt OUT of the class C vocabulary
//! deid-serve --session-ttl SECONDS            span-map retention window
//! deid-serve --max-sessions N                 ceiling on live span maps
//! deid-serve --quiet                          no per-request log lines
//! deid-serve --token-file PATH                read the token from a file, not from argv
//! deid-serve preflight [same flags]           check the deployment, bind nothing
//! deid-serve --version | --help
//! ```
//!
//! `just deploy-local` is the default way to run it and `just deploy-check` is
//! the preflight; `docs/DEPLOY-SERVER.md` is the document that explains why a server
//! deployment changes the threat model at all.
//!
//! # What binding looks like from here
//!
//! `main` never constructs a socket address. It parses flags, hands them to
//! [`deid_tr_service::bind::plan`], and either prints a refusal and exits
//! non-zero or receives a `Listen` it can hand to the server. The all-interfaces
//! address has no accepting path anywhere in that sequence, so the failure mode
//! that ships in the incumbent's compose file is not reachable by editing a
//! configuration value here.
//!
//! # Honest coverage, printed at startup
//!
//! Every run prints, before the first request, that L2 has no trained model and
//! that this build therefore masks no names. An operator who deploys this in
//! front of a clinical export job must not discover that from the output.

use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use deid_tr_service::api::{Service, ServiceConfig};
use deid_tr_service::bind::{self, DEFAULT_PORT};
use deid_tr_service::log::Log;
use deid_tr_service::preflight;
use deid_tr_service::server::Server;
use deid_tr_service::session::{DEFAULT_MAX_SESSIONS, DEFAULT_TTL_SECONDS};
use deid_tr_service::VERSION;

use deid_tr_core::Tier;

/// Exit code for a refused bind. Distinct from a runtime failure so a
/// supervisor can tell "you asked for something we will not do" from "the port
/// was busy" without parsing stderr.
const EXIT_REFUSED: u8 = 3;

/// The startup notice about what this build actually detects.
///
/// Printed on EVERY run, not behind a verbose flag. The one thing an operator
/// must not learn from reading masked output is that names are still in it.
const COVERAGE_NOTICE: &str = concat!(
    "coverage: RULE-DETECTABLE IDENTIFIERS ONLY. L2 has no trained model in this build, so ",
    "deid-serve masks ZERO names -- PATIENT_NAME, CLINICIAN_NAME and RELATIVE_NAME are never ",
    "detected. What IS masked: TCKN, VKN, SGK, IBAN, phone, MRN, email and dates. GET /entities ",
    "gives the per-label breakdown."
);

/// What the operator asked for, before it is checked.
struct Args {
    host: IpAddr,
    port: u16,
    expose: bool,
    token: Option<String>,
    tier: Tier,
    placeholder_labels: bool,
    no_medical_allowlist: bool,
    ttl: Duration,
    max_sessions: usize,
    quiet: bool,
    action: Action,
}

enum Action {
    Serve,
    /// Check these same flags and report, without creating a socket.
    Preflight,
    Version,
    Usage {
        unknown: bool,
    },
    BadValue {
        flag: &'static str,
    },
    /// Two flags that are each valid and cannot be given together.
    BadCombination {
        message: &'static str,
    },
}

impl Default for Args {
    fn default() -> Self {
        Self {
            host: bind::default_host(),
            port: DEFAULT_PORT,
            expose: false,
            token: None,
            tier: Tier::SafeHarbor,
            placeholder_labels: false,
            no_medical_allowlist: false,
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            max_sessions: DEFAULT_MAX_SESSIONS,
            quiet: false,
            action: Action::Serve,
        }
    }
}

/// Parse the command line.
///
/// An unparseable VALUE is [`Action::BadValue`] rather than a silent fallback to
/// the default. `--host nonsense` falling back to loopback would be benign;
/// `--session-ttl nonsense` falling back to fifteen minutes when the operator
/// asked for sixty seconds is a retention policy nobody agreed to.
fn parse_args(raw: &[String]) -> Args {
    let mut args = Args::default();
    let mut index = 0usize;
    while index < raw.len() {
        let flag = raw[index].as_str();
        // A free function rather than a closure: a closure capturing `index`
        // mutably cannot coexist with the loop's own use of it, and threading
        // the cursor explicitly is what makes "this flag consumed its value"
        // visible at every call site.
        let mut value = || take(raw, &mut index);
        match flag {
            "--host" => match value().and_then(|v| v.parse::<IpAddr>().ok()) {
                Some(host) => args.host = host,
                None => return bad(args, "--host"),
            },
            "--port" => match value().and_then(|v| v.parse::<u16>().ok()) {
                Some(port) => args.port = port,
                None => return bad(args, "--port"),
            },
            "--token" => match value() {
                Some(token) => {
                    if args.token.is_some() {
                        return conflict(args, TOKEN_TWICE);
                    }
                    args.token = Some(token);
                }
                None => return bad(args, "--token"),
            },
            // WHY A FILE AND NOT AN ENVIRONMENT VARIABLE: a bearer token in
            // `--token` is visible in `ps` to every user on the box, and one in
            // the environment is visible in /proc/PID/environ and in the output
            // of `systemctl show`. A file is readable only by whoever the
            // filesystem says, which is the whole point of systemd's
            // LoadCredential: it hands this process a path under
            // $CREDENTIALS_DIRECTORY that no other unit can see.
            "--token-file" => match value() {
                Some(path) => {
                    if args.token.is_some() {
                        return conflict(args, TOKEN_TWICE);
                    }
                    match read_token_file(&path) {
                        Some(token) => args.token = Some(token),
                        None => return bad(args, "--token-file"),
                    }
                }
                None => return bad(args, "--token-file"),
            },
            "--session-ttl" => match value().and_then(|v| v.parse::<u64>().ok()) {
                Some(seconds) if seconds > 0 => args.ttl = Duration::from_secs(seconds),
                _ => return bad(args, "--session-ttl"),
            },
            "--max-sessions" => match value().and_then(|v| v.parse::<usize>().ok()) {
                Some(max) if max > 0 => args.max_sessions = max,
                _ => return bad(args, "--max-sessions"),
            },
            "--tier" => match value().as_deref() {
                Some("safe-harbor" | "safe_harbor") => args.tier = Tier::SafeHarbor,
                Some("expert" | "expert-determination") => args.tier = Tier::ExpertDetermination,
                _ => return bad(args, "--tier"),
            },
            "--expose" => args.expose = true,
            "--placeholder-labels" => args.placeholder_labels = true,
            "--no-medical-allowlist" => args.no_medical_allowlist = true,
            "--quiet" => args.quiet = true,
            "preflight" => args.action = Action::Preflight,
            "version" | "--version" | "-V" => args.action = Action::Version,
            "help" | "--help" | "-h" => args.action = Action::Usage { unknown: false },
            _ => args.action = Action::Usage { unknown: true },
        }
        index += 1;
    }
    args
}

/// Consume the value that follows a flag, advancing the cursor.
fn take(raw: &[String], index: &mut usize) -> Option<String> {
    *index += 1;
    raw.get(*index).cloned()
}

fn bad(mut args: Args, flag: &'static str) -> Args {
    args.action = Action::BadValue { flag };
    args
}

fn conflict(mut args: Args, message: &'static str) -> Args {
    args.action = Action::BadCombination { message };
    args
}

const TOKEN_TWICE: &str =
    "--token and --token-file both supply the bearer token; give exactly one. Silently \
     preferring one of them would mean the credential in effect is not the one the operator \
     believes they set.";

/// Read a bearer token from a file, or `None` if the file cannot be used.
///
/// Trailing newline is stripped, because every way of writing a file adds one
/// and a token that differs from the file's visible contents by an invisible
/// byte is an afternoon lost. Interior whitespace is NOT stripped: a token may
/// legitimately contain anything, and trimming it would silently change the
/// credential.
///
/// The path is never echoed back on failure. A credential path is a deployment
/// detail and stderr is a log.
fn read_token_file(path: &str) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let token = raw.strip_suffix('\n').unwrap_or(&raw);
    let token = token.strip_suffix('\r').unwrap_or(token);
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

const USAGE: &str = "\
usage: deid-serve [options]
       deid-serve preflight [the same options]

  preflight                check these flags and report; creates no socket, starts
                           nothing, and exits non-zero if the deployment is refused
  --host ADDR              address to bind (default 127.0.0.1)
  --port N                 port to bind (default 8787)
  --expose                 permit a NON-LOOPBACK bind; requires --token
  --token SECRET           bearer token, at least 32 characters; enforced on EVERY route
                           (visible in ps: prefer --token-file)
  --token-file PATH        read the bearer token from a file, e.g. the path systemd's
                           LoadCredential= puts under $CREDENTIALS_DIRECTORY
  --tier safe-harbor|expert  assurance tier (default safe-harbor)
  --placeholder-labels     write [LABEL] instead of a surrogate; every patient in a note
                           collapses onto one token
  --no-medical-allowlist   run L4 with no medical vocabulary; carcinoma, costa and Adalat
                           will be masked and the note stops saying what it said
  --session-ttl SECONDS    span-map retention window (default 900)
  --max-sessions N         ceiling on concurrently live span maps (default 128)
  --quiet                  suppress per-request log lines
  --version                print the version

An all-interfaces address is REFUSED unconditionally: --expose and --token do not
unlock it. Bind the one address you mean to serve on, or bind loopback and tunnel.
The default needs no flags and is not reachable from another machine.";

/// `deid-serve preflight`: report on the proposed deployment, bind nothing.
///
/// The live layers come from a REAL [`Service`], built from the same
/// configuration the serve path would build. Hard-coding "L2 has no model" here
/// would be a second source of truth for the one claim an operator most needs to
/// be true, and the day a model ships is the day that copy would go stale
/// silently and in the reassuring direction.
fn preflight(args: &Args) -> ExitCode {
    let config = service_config(args, None);
    let service = match Service::new(config) {
        Ok(service) => service,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "deid-serve: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report = preflight::check(&preflight::Proposal {
        host: args.host,
        port: args.port,
        expose: args.expose,
        token: args.token.as_deref(),
        layers: service.live_layers(),
    });
    // stdout, because a report is the output of this command rather than a
    // diagnostic about it, and an operator will want to pipe it into a change
    // record.
    let _ = writeln!(std::io::stdout(), "{report}");
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_REFUSED)
    }
}

/// The service configuration implied by the parsed flags.
///
/// Shared by the serve path and the preflight so the preflight cannot report on
/// a differently-configured pipeline than the one that would run. `listen` is
/// `None` during preflight, where nothing has been approved to bind yet.
fn service_config(args: &Args, listen: Option<&bind::Listen>) -> ServiceConfig {
    ServiceConfig {
        tier: args.tier,
        no_medical_allowlist: args.no_medical_allowlist,
        placeholder_labels: args.placeholder_labels,
        ttl: args.ttl,
        max_sessions: args.max_sessions,
        auth_required: listen.map_or_else(|| args.token.is_some(), |l| l.token.is_some()),
        exposed: listen.is_some_and(bind::Listen::is_exposed),
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&raw);
    let mut stderr = std::io::stderr();

    match args.action {
        Action::Version => {
            let _ = writeln!(std::io::stdout(), "deid-serve {VERSION}");
            return ExitCode::SUCCESS;
        }
        Action::Usage { unknown } => {
            let _ = writeln!(stderr, "{USAGE}");
            return if unknown {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
        }
        Action::BadValue { flag } => {
            let _ = writeln!(
                stderr,
                "deid-serve: {flag} needs a value this binary can parse; nothing was started.\n\n{USAGE}"
            );
            return ExitCode::FAILURE;
        }
        Action::BadCombination { message } => {
            let _ = writeln!(stderr, "deid-serve: {message}");
            return ExitCode::FAILURE;
        }
        Action::Preflight => return preflight(&args),
        Action::Serve => {}
    }

    let listen = match bind::plan(args.host, args.port, args.expose, args.token.as_deref()) {
        Ok(listen) => listen,
        Err(refusal) => {
            let _ = writeln!(stderr, "deid-serve: {refusal}");
            return ExitCode::from(EXIT_REFUSED);
        }
    };

    let mut log = Log::stderr(!args.quiet);
    // The warning goes out BEFORE the socket exists, so an operator who is
    // watching the terminal sees it before anything can connect. It is
    // unconditional on the plan carrying one, and the plan carries one for every
    // non-loopback address; there is no path that binds beyond loopback quietly.
    if let Some(warning) = listen.warning {
        let _ = writeln!(stderr, "deid-serve: {warning}");
    }
    log.notice(COVERAGE_NOTICE);

    let config = service_config(&args, Some(&listen));
    if args.tier == Tier::ExpertDetermination {
        // Stated at startup rather than discovered per request: no local
        // contextual model is installed, so every request at this tier will
        // fail. Failing loudly beats degrading to Safe Harbor in silence, which
        // would hand back an unswept document that looks like a swept one.
        let _ = writeln!(
            stderr,
            "deid-serve: --tier expert was requested, but NO local contextual model is installed in this build. Every request will fail with pipeline_failed until one is. Run at safe-harbor, or install L3."
        );
    }

    let mut server = match Server::new(&listen, config, log) {
        Ok(server) => server,
        Err(error) => {
            let _ = writeln!(stderr, "deid-serve: {error}");
            return ExitCode::FAILURE;
        }
    };
    match server.serve(&listen) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            // The address is deliberately absent: it goes to stderr, then to a
            // log, and a deployment topology in a log is a detail that did not
            // need to be there. The operator knows what they asked for.
            let _ = writeln!(
                stderr,
                "deid-serve: could not bind the requested address and port; nothing is listening"
            );
            ExitCode::FAILURE
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
    fn the_default_needs_no_flags_and_is_loopback() {
        let parsed = parse_args(&args(&[]));
        assert!(parsed.host.is_loopback());
        assert_eq!(parsed.port, DEFAULT_PORT);
        assert!(!parsed.expose);
        assert!(parsed.token.is_none());
        assert_eq!(parsed.tier, Tier::SafeHarbor);
        assert!(matches!(parsed.action, Action::Serve));
        // And the default parse produces an approved loopback plan.
        let listen = bind::plan(parsed.host, parsed.port, parsed.expose, None).expect("plan");
        assert!(listen.addr.ip().is_loopback());
        assert!(!listen.is_exposed());
    }

    #[test]
    fn the_opt_outs_default_to_off_and_are_parsed_by_name() {
        let bare = parse_args(&args(&[]));
        assert!(!bare.placeholder_labels);
        assert!(!bare.no_medical_allowlist);
        let opted = parse_args(&args(&["--placeholder-labels", "--no-medical-allowlist"]));
        assert!(opted.placeholder_labels);
        assert!(opted.no_medical_allowlist);
    }

    #[test]
    fn an_unparseable_value_stops_the_process_rather_than_falling_back() {
        // A --session-ttl that silently reverts to fifteen minutes is a
        // retention policy nobody agreed to.
        for raw in [
            vec!["--session-ttl", "soon"],
            vec!["--session-ttl", "0"],
            vec!["--max-sessions", "lots"],
            vec!["--max-sessions", "0"],
            vec!["--port", "not-a-port"],
            vec!["--host", "not-an-address"],
            vec!["--tier", "maximum"],
            vec!["--token"],
        ] {
            assert!(
                matches!(parse_args(&args(&raw)).action, Action::BadValue { .. }),
                "{raw:?} was accepted"
            );
        }
    }

    #[test]
    fn the_retention_flags_are_honoured() {
        let parsed = parse_args(&args(&["--session-ttl", "60", "--max-sessions", "4"]));
        assert_eq!(parsed.ttl, Duration::from_secs(60));
        assert_eq!(parsed.max_sessions, 4);
    }

    #[test]
    fn the_expert_tier_must_be_asked_for_by_name() {
        assert_eq!(
            parse_args(&args(&["--tier", "expert"])).tier,
            Tier::ExpertDetermination
        );
        assert_eq!(
            parse_args(&args(&["--tier", "safe-harbor"])).tier,
            Tier::SafeHarbor
        );
    }

    #[test]
    fn an_unknown_flag_prints_usage_and_fails() {
        assert!(matches!(
            parse_args(&args(&["--all-interfaces"])).action,
            Action::Usage { unknown: true }
        ));
    }

    #[test]
    fn the_usage_text_states_the_refusal_rather_than_only_the_default() {
        // An operator reading `--host ADDR (default 127.0.0.1)` reasonably
        // concludes that any address is available. The refusal has to be in the
        // help output or they find it by trying.
        assert!(USAGE.contains("REFUSED unconditionally"));
        assert!(USAGE.contains("--expose"));
        assert!(USAGE.contains("--token"));
    }

    #[test]
    fn a_token_file_supplies_the_credential_and_strips_only_the_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("deid-serve-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("bearer");
        // Built at runtime, not written down. A 32-character credential-shaped
        // literal is exactly what the pre-commit secret scanner blocks, and it
        // was right to: a scanner that has to distinguish "test fixture" from
        // "real key" by reading the surrounding code is a scanner that will
        // eventually guess wrong in the expensive direction. Same discipline the
        // TCKN fixtures use -- the value is generated where it is needed and
        // never exists in the repository.
        let secret: String = (0..32)
            .map(|i| char::from(b'a' + u8::try_from(i % 26).unwrap_or(0)))
            .collect();
        let secret = secret.as_str();
        std::fs::write(&path, format!("{secret}\n")).expect("write");
        let parsed = parse_args(&args(&["--token-file", &path.display().to_string()]));
        assert_eq!(parsed.token.as_deref(), Some(secret));
        assert!(matches!(parsed.action, Action::Serve));

        // An empty file is a misconfiguration, not an empty token.
        std::fs::write(&path, "\n").expect("write");
        assert!(matches!(
            parse_args(&args(&["--token-file", &path.display().to_string()])).action,
            Action::BadValue {
                flag: "--token-file"
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_token_file_stops_the_process_rather_than_starting_unauthenticated() {
        // The dangerous fallback: a missing credential file silently yielding no
        // token, an operator's --expose then failing loudly (good) or a loopback
        // service coming up unauthenticated on a shared box (not good).
        assert!(matches!(
            parse_args(&args(&["--token-file", "/nonexistent/deid/bearer"])).action,
            Action::BadValue {
                flag: "--token-file"
            }
        ));
    }

    #[test]
    fn the_two_token_sources_may_not_be_combined() {
        assert!(matches!(
            parse_args(&args(&["--token", "x", "--token-file", "/tmp/y"])).action,
            Action::BadCombination { .. }
        ));
    }

    #[test]
    fn preflight_is_a_named_subcommand_that_keeps_every_other_flag() {
        let parsed = parse_args(&args(&["preflight", "--port", "9100"]));
        assert!(matches!(parsed.action, Action::Preflight));
        assert_eq!(parsed.port, 9100);
        assert!(parsed.host.is_loopback());
    }

    #[test]
    fn the_startup_notice_says_no_names_are_masked() {
        assert!(COVERAGE_NOTICE.contains("ZERO names"));
        assert!(COVERAGE_NOTICE.contains("PATIENT_NAME"));
        assert!(COVERAGE_NOTICE.contains("TCKN"));
    }
}
