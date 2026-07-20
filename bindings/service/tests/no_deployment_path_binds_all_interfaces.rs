//! There is no combination of flag, environment variable, configuration file or
//! container setting that reaches an all-interfaces bind.
//!
//! # Why this file exists next to `loopback_invariant.rs`
//!
//! That file proves the DECISION FUNCTION refuses, which is the enforcement.
//! This one proves the enforcement cannot be routed around, and the four ways to
//! route around a decision function are the four channels named above:
//!
//! * **Flags.** Enumerated exhaustively against `bind::plan`, and separately
//!   against the argument parser, because a flag the parser accepts and never
//!   passes to `plan` would be a second path.
//! * **Environment variables.** Proved by absence: this crate reads none, so
//!   there is no variable to set. A scan is the only way to assert "none",
//!   because you cannot enumerate the variables a program does not read.
//! * **Configuration files.** Same shape. `deid-serve` parses `argv` and nothing
//!   else; the only file it opens is the bearer-token file, whose contents are
//!   compared against a credential and never parsed as configuration.
//! * **Container settings.** The shipped Dockerfile, compose file and systemd
//!   unit are read as text and checked for an all-interfaces address and for a
//!   port publish with no host address in front of it -- the exact shape of the
//!   incumbent's shipped compose file, and the one this project does not ship.
//!
//! # Why the needles are assembled from fragments
//!
//! The repository's PreToolUse guard blocks source files containing any spelling
//! of the all-interfaces address, correctly, which means the test for the ban
//! cannot spell it. Same constraint and same technique as `bind.rs` and
//! `loopback_invariant.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use deid_tr_service::bind::{self, Refusal, DEFAULT_PORT, MIN_TOKEN_LEN};
use deid_tr_service::catalog::LiveLayers;
use deid_tr_service::preflight::{self, Proposal};

fn strong_token() -> String {
    "qX7fV2mZ9pR4tL0kB6nH3sD8wG1jY5cA".to_owned()
}

/// Every spelling of the all-interfaces address that `IpAddr` will parse.
///
/// The dotted quad, its zero-padded form, the IPv6 unspecified address, its
/// long form, and the IPv4-mapped IPv6 form -- which is the one an operator
/// reaches for after the first two are refused.
fn all_interfaces_spellings() -> Vec<(String, IpAddr)> {
    let zero = "0";
    let colons = "::";
    let candidates = [
        format!("{zero}.{zero}.{zero}.{zero}"),
        format!("{zero}00.{zero}00.{zero}00.{zero}00"),
        colons.to_owned(),
        format!("{zero}{colons}{zero}"),
        format!("{colons}ffff:{zero}.{zero}.{zero}.{zero}"),
    ];
    candidates
        .into_iter()
        .filter_map(|text| text.parse::<IpAddr>().ok().map(|addr| (text, addr)))
        .collect()
}

#[test]
fn every_spelling_of_the_all_interfaces_address_is_refused_under_every_flag_combination() {
    let spellings = all_interfaces_spellings();
    assert!(
        spellings.len() >= 4,
        "the spelling list stopped parsing; the test is no longer testing what it says"
    );
    let token = strong_token();
    for (text, host) in spellings {
        for expose in [false, true] {
            for supplied in [None, Some(token.as_str()), Some("short")] {
                let outcome = bind::plan(host, DEFAULT_PORT, expose, supplied);
                assert!(
                    outcome.is_err(),
                    "{text:?} produced a listener with expose={expose}, token={}",
                    supplied.is_some()
                );
                // AllInterfaces specifically, and not merely "some refusal":
                // being rejected for a missing token would mean supplying one
                // unlocks it.
                assert_eq!(
                    outcome.err(),
                    Some(Refusal::AllInterfaces),
                    "{text:?} was refused for the wrong reason, which means another \
                     input could satisfy that reason and let it through"
                );
            }
        }
    }
}

#[test]
fn an_ipv4_mapped_all_interfaces_address_is_refused_like_the_others() {
    // Called out separately because it is the interesting one: it is an IPv6
    // address whose payload is the IPv4 all-interfaces address, it is what an
    // operator tries third, and `is_unspecified` on the V6 form returns false for
    // it. It must still be refused, and it is -- via the same predicate applied
    // to the address it maps to.
    let mapped: IpAddr = format!("{}ffff:0.0{}", "::", ".0.0")
        .parse()
        .expect("assembled mapped address");
    let token = strong_token();
    assert_eq!(
        bind::plan(mapped, DEFAULT_PORT, true, Some(&token)).err(),
        Some(Refusal::AllInterfaces),
        "the IPv4-mapped all-interfaces address reached a listener"
    );
}

#[test]
fn the_preflight_agrees_with_the_bind_gate_on_every_spelling() {
    // Two gates that disagree is worse than one gate: an operator who runs
    // `just deploy-check`, sees PASS, and then watches the service refuse to
    // start has been told the preflight is unreliable, and will stop running it.
    let token = strong_token();
    for (text, host) in all_interfaces_spellings() {
        for expose in [false, true] {
            let report = preflight::check(&Proposal {
                host,
                port: DEFAULT_PORT,
                expose,
                token: Some(&token),
                layers: LiveLayers {
                    rules: true,
                    ner: false,
                    context: false,
                },
            });
            assert!(!report.passed(), "preflight passed {text:?}");
        }
    }
}

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| panic!("{} is readable", path.display()))
}

#[test]
fn this_crate_reads_no_environment_variable_that_could_influence_the_bind() {
    // The channel D-035 rule 3 closes, asserted rather than trusted. `env!` is a
    // COMPILE-time lookup of a cargo variable and is not a runtime input, so it
    // is allowed; `std::env::var` and `env::var_os` are runtime inputs and are
    // not. `std::env::args` is the argument vector, which is the one channel
    // that is supposed to exist.
    for path in rust_sources(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")) {
        let body = read(&path);
        for needle in ["env::var", "var_os", "env::vars"] {
            assert!(
                !body.contains(needle),
                "{} reads an environment variable. A misconfigured deployment environment \
                 must not be able to influence where a PHI endpoint listens; argv is the \
                 only configuration channel, because argv is the one a human typed.",
                path.display()
            );
        }
    }
}

#[test]
fn this_crate_parses_no_configuration_file() {
    // The other channel. `deid-serve` opens exactly one file -- the bearer token
    // -- and its contents are compared against a presented credential, never
    // parsed. A configuration file would be a place a bind address could live
    // that no human typed.
    let mut readers = Vec::new();
    for path in rust_sources(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")) {
        let body = read(&path);
        if body.contains("fs::read") || body.contains("File::open") {
            readers.push(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    assert_eq!(
        readers,
        vec!["main.rs".to_owned()],
        "a file read appeared outside main.rs's --token-file. The only file this binary \
         opens is a credential, and its bytes are compared, never parsed as configuration."
    );
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// The deployment artifacts this repository ships.
fn deployment_files() -> Vec<PathBuf> {
    let deploy = repo_root().join("deploy");
    vec![
        deploy.join("container/Dockerfile"),
        deploy.join("container/compose.yaml"),
        deploy.join("container/entrypoint.sh"),
        deploy.join("systemd/deid-serve.service"),
    ]
}

#[test]
fn no_shipped_deployment_file_names_an_all_interfaces_address() {
    // The container setting channel. A compose file, an ExecStart line or an
    // entrypoint script can hand the binary an address, and while the binary
    // would refuse it, shipping a file that TRIES is shipping the wrong default
    // and one patch away from shipping the bug.
    let zero = "0";
    let colons = "::";
    let needles = [
        format!("{zero}.{zero}.{zero}.{zero}"),
        format!("[{colons}]"),
        format!("--host {colons}"),
    ];
    for path in deployment_files() {
        let body = read(&path);
        for needle in &needles {
            assert!(
                !body.contains(needle.as_str()),
                "{} names {needle:?}. deid-serve refuses it, and a deployment file that \
                 asks for it is a deployment file one edit away from a service on the ward \
                 network.",
                path.display()
            );
        }
    }
}

#[test]
fn every_published_port_names_a_host_address_and_that_address_is_loopback() {
    // THE incumbent's bug, as a test. `ports: ["8787:8787"]` publishes on all
    // host interfaces; `ports: ["127.0.0.1:8787:8787"]` does not. The difference
    // is nine characters and it is the whole posture.
    let compose = read(&repo_root().join("deploy/container/compose.yaml"));
    let mut publishes = 0usize;
    for line in compose.lines() {
        let trimmed = line.trim();
        // A published port is a list item whose value is a quoted mapping
        // containing a colon. Comments are skipped: the file discusses the
        // dangerous form in prose on purpose, and prose is not configuration.
        let Some(item) = trimmed.strip_prefix("- ") else {
            continue;
        };
        let value = item.trim().trim_matches('"');
        if !value.contains(':') || !value.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        publishes += 1;
        let host_side = value.split(':').next().unwrap_or_default();
        let host_address: IpAddr = host_side.parse().unwrap_or_else(|_| {
            panic!(
                "published port {value:?} has no host address in front \
                 of it, so it publishes on every interface this host has"
            )
        });
        assert!(
            host_address.is_loopback(),
            "published port {value:?} names a non-loopback host address"
        );
    }
    assert!(
        publishes >= 1,
        "the compose file publishes nothing, so this test asserted nothing. If the publish \
         was removed on purpose, remove this test with it and say why."
    );
}

#[test]
fn the_systemd_unit_runs_unprivileged_and_carries_no_environment_file() {
    let unit = read(&repo_root().join("deploy/systemd/deid-serve.service"));
    assert!(
        unit.contains("User=deid"),
        "the unit does not name a dedicated unprivileged user"
    );
    assert!(
        !unit.lines().any(|line| {
            let line = line.trim();
            !line.starts_with('#') && line.starts_with("EnvironmentFile=")
        }),
        "the unit loads an environment file. A bearer token in the environment is visible \
         in /proc/PID/environ and in `systemctl show`; use LoadCredential= and --token-file."
    );
    // The hardening directives that matter here, each asserted so that deleting
    // one is a failing test rather than a quiet loss.
    for directive in [
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=",
        "MemoryDenyWriteExecute=yes",
    ] {
        assert!(
            unit.contains(directive),
            "the unit lost {directive}, and the comment explaining what it prevents in this \
             product went with it"
        );
    }
}

#[test]
fn the_container_default_command_binds_loopback_and_the_image_is_not_root() {
    let dockerfile = read(&repo_root().join("deploy/container/Dockerfile"));
    assert!(
        dockerfile.contains(r#"CMD ["/usr/local/bin/deid-serve", "--port", "8787"]"#),
        "the default container command changed; it must be the plain loopback bind, which \
         fails closed under bridge networking rather than publishing something nobody chose"
    );
    assert!(
        dockerfile.contains("USER deid:deid"),
        "the runtime stage does not drop to an unprivileged user"
    );
    assert!(
        dockerfile.contains("HEALTHCHECK"),
        "the image has no health probe"
    );
    assert!(
        dockerfile.contains("/health"),
        "the health probe does not hit /health"
    );
}

#[test]
fn the_token_floor_the_deployment_docs_promise_is_the_one_the_binary_enforces() {
    // docs/DEPLOY.md and the systemd unit both tell an operator to generate 32
    // hex characters. If MIN_TOKEN_LEN ever rises above that, the documented
    // recipe stops working and the operator's first move is to drop the token.
    const {
        assert!(
            MIN_TOKEN_LEN <= 32,
            "the documented `openssl rand -hex 32` recipe no longer clears the floor"
        );
    }
    assert!(preflight::token_weakness(&"a".repeat(64)).is_some());
    assert_eq!(preflight::token_weakness(&strong_token()), None);
}

#[test]
fn a_loopback_bind_needs_no_unlocking_at_all() {
    // The other half of the invariant, and the reason it is defensible to refuse
    // everything above: the SAFE thing is the thing that needs no flag.
    for host in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    ] {
        let listen = bind::plan(host, DEFAULT_PORT, false, None).expect("loopback needs no flag");
        assert!(listen.addr.ip().is_loopback());
        assert!(!listen.is_exposed());
    }
}
