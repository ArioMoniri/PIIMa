//! `deid-mcp` -- the stdio MCP gateway binary.
//!
//! ```text
//! deid-mcp [--tier safe-harbor|expert] [--session-ttl SECONDS]
//!          [--max-sessions N] [--max-document-bytes N] [--quiet]
//! deid-mcp --version | --help
//! ```
//!
//! # I3, in the one place it could go wrong
//!
//! The transport is stdin/stdout. This binary contains no socket, links no socket-capable
//! dependency, and takes no address, port or interface argument -- so there is no default to
//! get wrong and no flag that could widen one. The flags that WOULD open a socket in a
//! conventional server (`--expose`, `--port`, `--listen`, `--host`, `--http`) are recognised
//! only in order to be REFUSED with an explanation, because the failure mode worth designing
//! against is an operator who assumes the feature exists, passes the flag, sees no complaint,
//! and believes the resulting process is reachable and authenticated when it is neither.
//!
//! If a socket transport is ever added it is loopback-only, and exposure needs the explicit
//! flag AND a bearer token AND a startup warning together. See README.md.

use std::io::{BufReader, Write};
use std::process::ExitCode;
use std::time::Duration;

use deid_tr_mcp::server::{parse_tier, Server, ServerConfig};
use deid_tr_mcp::telemetry::Telemetry;
use deid_tr_mcp::VERSION;

/// Exit code for a refused invocation.
const EXIT_REFUSED: u8 = 2;

/// Flags a conventional server would use to open a socket. Recognised only to be refused.
const SOCKET_FLAGS: [&str; 6] = [
    "--expose", "--port", "--listen", "--host", "--http", "--bind",
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("deid-mcp {VERSION}");
        return ExitCode::SUCCESS;
    }
    if let Some(flag) = args
        .iter()
        .find(|arg| SOCKET_FLAGS.iter().any(|known| arg.starts_with(known)))
    {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "deid-mcp: refusing {flag}: this build has no socket transport.\n  \
             deid-mcp speaks JSON-RPC over stdin/stdout and is started by an MCP client.\n  \
             It holds the span map -- the mapping from surrogate back to real patient \
             identifiers -- precisely because it cannot send it anywhere."
        );
        return ExitCode::from(EXIT_REFUSED);
    }

    let config = match parse_config(&args) {
        Ok(config) => config,
        Err(message) => {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "deid-mcp: {message}\n\n{USAGE}");
            return ExitCode::from(EXIT_REFUSED);
        }
    };

    let quiet = args.iter().any(|arg| arg == "--quiet");
    let mut log = Telemetry::stderr(!quiet);
    log.notice("ready transport=stdio listening=false");

    let mut server = match Server::new(config, log) {
        Ok(server) => server,
        Err(error) => {
            let mut stderr = std::io::stderr();
            // The message is the error's own closed vocabulary; it names no
            // document and no path (I4).
            let _ = writeln!(stderr, "deid-mcp: {error}");
            return ExitCode::from(EXIT_REFUSED);
        }
    };
    let stdin = BufReader::new(std::io::stdin());
    let mut stdout = std::io::stdout();
    match server.run(stdin, &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = std::io::stderr();
            // `error.kind()` and nothing else. An io::Error's Display can name a path, and a
            // path in this tool is routinely the name of a file holding a clinical note (I4).
            let _ = writeln!(stderr, "deid-mcp: transport failed ({:?})", error.kind());
            ExitCode::from(EXIT_REFUSED)
        }
    }
}

/// Parse the flags, refusing anything unrecognised.
fn parse_config(args: &[String]) -> core::result::Result<ServerConfig, String> {
    let mut config = ServerConfig::default();
    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].as_str();
        let value = || {
            args.get(index + 1)
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg {
            "--quiet" => index += 1,
            "--tier" => {
                let raw = value()?;
                config.tier = parse_tier(&raw)
                    .map_err(|_| "--tier must be safe-harbor or expert".to_owned())?;
                index += 2;
            }
            "--session-ttl" => {
                let seconds: u64 = value()?
                    .parse()
                    .map_err(|_| "--session-ttl must be a whole number of seconds".to_owned())?;
                if seconds == 0 {
                    // A zero TTL is not "no expiry", it is "expired on arrival", and either
                    // reading is a footgun: one holds PHI forever, the other makes every round
                    // trip fail in a way that looks like a bug in the client.
                    return Err("--session-ttl must be at least 1 second".to_owned());
                }
                config.ttl = Duration::from_secs(seconds);
                index += 2;
            }
            "--max-sessions" => {
                config.max_sessions = value()?
                    .parse()
                    .map_err(|_| "--max-sessions must be a whole number".to_owned())?;
                if config.max_sessions == 0 {
                    return Err("--max-sessions must be at least 1".to_owned());
                }
                index += 2;
            }
            "--max-document-bytes" => {
                config.max_document_bytes = value()?
                    .parse()
                    .map_err(|_| "--max-document-bytes must be a whole number".to_owned())?;
                index += 2;
            }
            // Opt-OUTS. A gateway started with neither runs with the audited
            // class C vocabulary in L4 and L5 installed, which is the safe
            // configuration and must be the one nobody has to ask for.
            "--no-medical-allowlist" => {
                config.no_medical_allowlist = true;
                index += 1;
            }
            "--placeholder-labels" => {
                config.placeholder_labels = true;
                index += 1;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(config)
}

/// Usage text. Written out rather than generated so the retention policy is stated where an
/// operator will actually read it.
const USAGE: &str = concat!(
    "deid-mcp -- stdio MCP gateway for deid-tr\n",
    "\n",
    "USAGE:\n",
    "  deid-mcp [OPTIONS]\n",
    "\n",
    "Speaks newline-delimited JSON-RPC over stdin/stdout. Started by an MCP client, not by\n",
    "hand. There is no socket transport and no listening address.\n",
    "\n",
    "OPTIONS:\n",
    "  --tier safe-harbor|expert   Assurance tier. Default: safe-harbor.\n",
    "  --session-ttl SECONDS       Span-map retention window. Default: 900 (15 minutes).\n",
    "  --max-sessions N            Concurrently live span maps. Default: 128.\n",
    "  --max-document-bytes N      Ceiling on one document. Default: 1048576.\n",
    "  --quiet                     Suppress the stderr diagnostic stream.\n",
    "  --no-medical-allowlist      Run L4 with NO medical vocabulary. carcinoma, costa and\n",
    "                              Adalat are then masked whenever a detector proposes them.\n",
    "  --placeholder-labels        Run without L5 surrogates.\n",
    "  --version, --help\n",
    "\n",
    "RETENTION:\n",
    "  A session holds the span map: the mapping from surrogate back to the real patient\n",
    "  identifier. It lives in memory only, is never written to disk, is never logged, and\n",
    "  is destroyed and its buffers overwritten when the TTL elapses, when `forget` is\n",
    "  called, or when stdin closes. The TTL runs from creation, not from last use.\n",
);

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::Tier;
    use deid_tr_mcp::server::DEFAULT_MAX_DOCUMENT_BYTES;
    use deid_tr_mcp::session::{DEFAULT_MAX_SESSIONS, DEFAULT_TTL_SECONDS};

    #[test]
    fn defaults_are_the_documented_ones() {
        let config = parse_config(&[]).expect("no flags");
        assert_eq!(config.tier, Tier::SafeHarbor);
        assert_eq!(config.ttl, Duration::from_secs(DEFAULT_TTL_SECONDS));
        assert_eq!(config.max_sessions, DEFAULT_MAX_SESSIONS);
        assert_eq!(config.max_document_bytes, DEFAULT_MAX_DOCUMENT_BYTES);
    }

    fn flags(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_retention_window_is_configurable() {
        let config = parse_config(&flags(&["--session-ttl", "60"])).expect("parse");
        assert_eq!(config.ttl, Duration::from_secs(60));
    }

    #[test]
    fn a_zero_retention_window_is_refused_rather_than_interpreted() {
        assert!(parse_config(&flags(&["--session-ttl", "0"])).is_err());
        assert!(parse_config(&flags(&["--max-sessions", "0"])).is_err());
    }

    #[test]
    fn a_mistyped_tier_is_refused_and_never_defaulted() {
        // Defaulting a typo to Safe Harbor would hand back an unswept document to a caller who
        // believes quasi-identifiers were removed.
        assert!(parse_config(&flags(&["--tier", "expret"])).is_err());
        assert_eq!(
            parse_config(&flags(&["--tier", "expert"]))
                .expect("parse")
                .tier,
            Tier::ExpertDetermination
        );
    }

    #[test]
    fn an_unknown_option_is_refused() {
        assert!(parse_config(&flags(&["--verbose"])).is_err());
    }

    #[test]
    fn every_socket_flag_is_recognised_only_to_be_refused() {
        // The list must stay in step with the refusal branch in `main`. If a flag were added to
        // the parser instead, this test is what notices.
        for flag in SOCKET_FLAGS {
            assert!(
                parse_config(&flags(&[flag, "9000"])).is_err(),
                "{flag} was accepted by the option parser"
            );
        }
    }
}
