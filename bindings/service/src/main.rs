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
//! deid-serve --version | --help
//! ```
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

use deid_tr_service::api::ServiceConfig;
use deid_tr_service::bind::{self, DEFAULT_PORT};
use deid_tr_service::log::Log;
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
    Version,
    Usage { unknown: bool },
    BadValue { flag: &'static str },
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
                Some(token) => args.token = Some(token),
                None => return bad(args, "--token"),
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

const USAGE: &str = "\
usage: deid-serve [options]

  --host ADDR              address to bind (default 127.0.0.1)
  --port N                 port to bind (default 8787)
  --expose                 permit a NON-LOOPBACK bind; requires --token
  --token SECRET           bearer token, at least 32 characters; enforced on EVERY route
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

    let config = ServiceConfig {
        tier: args.tier,
        no_medical_allowlist: args.no_medical_allowlist,
        placeholder_labels: args.placeholder_labels,
        ttl: args.ttl,
        max_sessions: args.max_sessions,
        auth_required: listen.token.is_some(),
        exposed: listen.is_exposed(),
    };
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
    fn the_startup_notice_says_no_names_are_masked() {
        assert!(COVERAGE_NOTICE.contains("ZERO names"));
        assert!(COVERAGE_NOTICE.contains("PATIENT_NAME"));
        assert!(COVERAGE_NOTICE.contains("TCKN"));
    }
}
