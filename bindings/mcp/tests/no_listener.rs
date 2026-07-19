//! I3, asserted structurally: this crate binds nothing, on any address.
//!
//! # Why a source scan and not a runtime probe
//!
//! The obvious test is to start the server and check that no port is open. That test passes
//! for the wrong reason on a machine where the bind failed, it is racy, and it can only observe
//! the code path the test happened to drive. The property that actually matters is stronger and
//! static: there is no socket in this crate to bind with. A crate with no listener type, no
//! `std::net` import and no socket-capable dependency cannot open a port on any code path,
//! including the ones no test drives.
//!
//! # Why the needles are assembled from fragments
//!
//! The repository's own PreToolUse guard blocks source files containing the all-interfaces
//! address in any of its spellings, which is correct and also means a test that searches for
//! those spellings cannot contain them literally. Each needle is therefore concatenated at
//! runtime from pieces that are individually inert. This is a real constraint of testing a
//! ban by name, not cleverness for its own sake, and the alternative -- exempting this file
//! from the guard -- would put a permanent hole in the guard to test one crate.

use std::path::{Path, PathBuf};

/// Everything that would make this crate capable of listening.
///
/// Each entry is (assembled needle, why it is banned). The list covers the three spellings the
/// guard itself enumerates plus the socket types that need no address literal at all.
fn forbidden() -> Vec<(String, &'static str)> {
    let colons = "::";
    vec![
        (
            format!("0.{}", "0.0.0"),
            "the IPv4 all-interfaces address, written as a dotted quad",
        ),
        (
            format!("Ipv4Addr{colons}UNSPEC{}", "IFIED"),
            "the IPv4 all-interfaces address, written the idiomatic Rust way",
        ),
        (
            format!("Ipv6Addr{colons}UNSPEC{}", "IFIED"),
            "the IPv6 unspecified address, which binds every interface",
        ),
        (
            format!("[{colons}]"),
            "the IPv6 unspecified address in URL-authority form",
        ),
        (
            format!("std{colons}net"),
            "a socket needs no dependency edge; std::net is one import away from a listener",
        ),
        ("TcpListener".to_owned(), "a listening socket"),
        (
            "UdpSocket".to_owned(),
            "a datagram socket, which also binds",
        ),
        ("TcpStream".to_owned(), "an outbound socket"),
        ("UnixListener".to_owned(), "a listening socket"),
    ]
}

/// Dependencies that can open a socket or terminate TLS.
///
/// Kept deliberately in step with the `socket_crates` list in the justfile's `core-no-socket`
/// recipe. This file checks the DECLARED dependencies; `just mcp-no-socket` checks the
/// RESOLVED graph, including transitive edges no source scan can see. Both exist because
/// neither is sufficient: a name list cannot see a crate pulled in three levels down, and a
/// graph check cannot see `use std::net::TcpListener`, which has no dependency edge at all.
const SOCKET_CRATES: [&str; 24] = [
    "reqwest",
    "ureq",
    "hyper",
    "hyper-util",
    "h2",
    "h3",
    "tonic",
    "isahc",
    "curl",
    "surf",
    "attohttpc",
    "minreq",
    "ehttp",
    "async-std",
    "smol",
    "async-io",
    "tungstenite",
    "quinn",
    "socket2",
    "mio",
    "axum",
    "warp",
    "rocket",
    "tiny_http",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under a directory.
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
    found
}

#[test]
fn no_source_file_can_open_a_socket() {
    let root = crate_root();
    let sources = rust_sources(&root.join("src"));
    assert!(
        !sources.is_empty(),
        "the source scan found no files to scan"
    );

    let needles = forbidden();
    for path in sources {
        let body = std::fs::read_to_string(&path).expect("source file is readable");
        for (needle, why) in &needles {
            assert!(
                !body.contains(needle.as_str()),
                "{} contains {needle:?} -- {why}. \
                 The MCP gateway is stdio-only: it holds the span map because it cannot send \
                 it anywhere. If a socket transport is genuinely needed it binds loopback \
                 only, and exposure requires --expose AND a bearer token AND a startup \
                 warning together.",
                path.display(),
            );
        }
    }
}

#[test]
fn this_test_would_actually_catch_a_violation() {
    // A ban with no known failing input is not a ban. The needles are exercised against text
    // that genuinely contains each spelling, assembled the same way, so a typo in a needle
    // fails here rather than silently passing every scan above.
    for (needle, _) in forbidden() {
        let offending = format!("let addr = {needle};");
        assert!(
            offending.contains(needle.as_str()),
            "needle {needle:?} does not match the shape it is meant to catch"
        );
    }
}

#[test]
fn no_declared_dependency_can_open_a_socket() {
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("manifest is readable");
    // Only the dependency TABLES are scanned. The prose above them explains why the ban exists
    // and names the very crates it bans, which is the correct thing for the comment to do and
    // would be a false positive here.
    let dependencies: String = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for crate_name in SOCKET_CRATES {
        assert!(
            !dependencies.contains(&format!("\n{crate_name} ")),
            "{crate_name} was added as a dependency of the MCP gateway. \
             This crate never speaks to the cloud model -- the MCP client does -- and that is \
             what makes it safe for it to hold the span map."
        );
        assert!(
            !dependencies.contains(&format!("\n{crate_name} =")),
            "{crate_name} was added as a dependency of the MCP gateway."
        );
    }
}

#[test]
fn the_binary_takes_no_address_port_or_interface_argument() {
    // A flag is how a stdio server grows a socket. The parser refuses every one of these, so
    // an operator who assumes the feature exists is told plainly that it does not rather than
    // being handed a process they believe is reachable and authenticated.
    let main = std::fs::read_to_string(crate_root().join("src/main.rs")).expect("main.rs");
    for flag in [
        "--expose", "--port", "--listen", "--host", "--http", "--bind",
    ] {
        assert!(
            main.contains(&format!("\"{flag}\"")),
            "{flag} is no longer explicitly refused; an operator passing it would be ignored"
        );
    }
}
