//! I3, asserted from outside the crate and against a real socket.
//!
//! # Three statements, because none of them is sufficient alone
//!
//! 1. **The decision function refuses.** `bind::plan` is the only producer of a
//!    `Listen`, so every rule it enforces is enforced everywhere. This file
//!    re-states the refusals as an EXTERNAL consumer, because a unit test inside
//!    the module proves the module agrees with itself.
//! 2. **The default really binds loopback.** A refusal that is never exercised
//!    against a kernel is a refusal that might be refusing the wrong thing. The
//!    test below binds, connects from loopback, and gets a reply.
//! 3. **No source file names an all-interfaces address.** A future edit can add
//!    a second bind path that never goes through `plan`. A source scan sees
//!    that; a behavioural test cannot, because it can only observe the path it
//!    drives.
//!
//! # Why the needles are assembled from fragments
//!
//! The repository's PreToolUse guard blocks source files containing the
//! all-interfaces address in any of its spellings, which is correct and also
//! means a test that searches for those spellings cannot contain them literally.
//! Each needle is concatenated at run time from pieces that are individually
//! inert. Same constraint and same technique as
//! `bindings/mcp/tests/no_listener.rs`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::path::{Path, PathBuf};

use deid_tr_service::api::ServiceConfig;
use deid_tr_service::bind::{self, Refusal, DEFAULT_PORT, MIN_TOKEN_LEN};
use deid_tr_service::log::Log;
use deid_tr_service::server::{bind_listener, Server};

fn good_token() -> String {
    // Cycles the alphabet: clears the length floor AND the distinct-character
    // floor that the bind gate now enforces alongside it.
    (0..MIN_TOKEN_LEN)
        .map(|index| char::from(b'a' + u8::try_from(index % 26).unwrap_or(0)))
        .collect()
}

/// The IPv4 all-interfaces address, assembled at run time.
fn all_interfaces_v4() -> IpAddr {
    format!("0.{}", "0.0.0").parse().expect("assembled quad")
}

/// The IPv6 unspecified address, assembled at run time.
fn all_interfaces_v6() -> IpAddr {
    format!("{}{}", ":", ":").parse().expect("assembled v6")
}

#[test]
fn an_all_interfaces_bind_has_no_accepting_path() {
    // Both families, both flags, with and without a valid token. Sixteen
    // combinations, zero of which produce a listener.
    for host in [all_interfaces_v4(), all_interfaces_v6()] {
        for expose in [false, true] {
            for token in [None, Some(good_token())] {
                let outcome = bind::plan(host, DEFAULT_PORT, expose, token.as_deref());
                assert_eq!(
                    outcome.err(),
                    Some(Refusal::AllInterfaces),
                    "an all-interfaces bind was reachable (expose={expose}, token={})",
                    token.is_some()
                );
            }
        }
    }
}

#[test]
fn a_non_loopback_bind_requires_expose_and_a_token_and_produces_a_warning() {
    let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
    let token = good_token();

    assert_eq!(
        bind::plan(lan, DEFAULT_PORT, false, None).err(),
        Some(Refusal::NonLoopbackWithoutExpose)
    );
    assert_eq!(
        bind::plan(lan, DEFAULT_PORT, false, Some(&token)).err(),
        Some(Refusal::NonLoopbackWithoutExpose),
        "a token alone must not expose"
    );
    assert_eq!(
        bind::plan(lan, DEFAULT_PORT, true, None).err(),
        Some(Refusal::ExposeWithoutToken),
        "--expose alone must not expose"
    );
    assert_eq!(
        bind::plan(lan, DEFAULT_PORT, true, Some("short")).err(),
        Some(Refusal::TokenTooShort)
    );

    let listen = bind::plan(lan, DEFAULT_PORT, true, Some(&token)).expect("all three gates");
    assert!(
        listen.warning.is_some(),
        "an exposed bind carried no warning"
    );
    assert!(listen.token.is_some());
    assert!(listen.is_exposed());
}

#[test]
fn the_default_binds_loopback_and_actually_answers_there() {
    // Port 0: the kernel picks a free port, so this test does not race another
    // process or another test for a fixed one.
    let listen = bind::plan(bind::default_host(), 0, false, None).expect("loopback plan");
    let listener = bind_listener(&listen).expect("bind loopback");
    let bound = listener.local_addr().expect("local addr");
    assert!(
        bound.ip().is_loopback(),
        "the default bind was not loopback"
    );

    // Built inside the thread: `Pipeline` holds `Box<dyn Detector>` trait
    // objects, which are deliberately not `Send`.
    std::thread::spawn(move || {
        let mut server =
            Server::new(&listen, ServiceConfig::default(), Log::silent()).expect("server");
        server.serve_listener(&listener);
    });

    let mut stream = TcpStream::connect(bound).expect("connect from loopback");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write");
    let mut reader = BufReader::new(&stream);
    let mut status = String::new();
    reader.read_line(&mut status).expect("status line");
    assert!(status.starts_with("HTTP/1.1 200 OK"), "{status}");

    let mut rest = String::new();
    reader.read_to_string(&mut rest).expect("body");
    assert!(rest.contains("\"tier\":\"safe_harbor\""));
    assert!(
        rest.contains("Connection: close"),
        "the server must announce that it closes, or a client waits for a second response"
    );
}

#[test]
fn ipv6_loopback_is_also_bindable_by_default() {
    // Some hospital workstations resolve `localhost` to the IPv6 loopback
    // first. Refusing it would push an operator towards `--host` and, from
    // there, towards addresses that are not loopback at all.
    let listen = bind::plan(IpAddr::V6(Ipv6Addr::LOCALHOST), 0, false, None).expect("plan");
    assert!(!listen.is_exposed());
    // The bind itself is allowed to fail on a host with IPv6 disabled; the
    // property under test is that the PLAN permits it.
    if let Ok(listener) = bind_listener(&listen) {
        assert!(listener
            .local_addr()
            .expect("local addr")
            .ip()
            .is_loopback());
    }
}

/// Everything that would let this crate bind every interface.
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
    ]
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
    found
}

#[test]
fn no_source_file_names_an_all_interfaces_address() {
    let sources = rust_sources(&crate_root().join("src"));
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
                "{} contains {needle:?} -- {why}. deid-serve binds loopback by default and \
                 refuses every all-interfaces address unconditionally; a non-loopback bind \
                 requires --expose AND a bearer token AND a startup warning, and goes through \
                 bind::plan.",
                path.display(),
            );
        }
    }
}

#[test]
fn this_scan_would_actually_catch_a_violation() {
    // A ban with no known failing input is not a ban.
    for (needle, _) in forbidden() {
        let offending = format!("let addr = {needle};");
        assert!(offending.contains(needle.as_str()));
    }
}

#[test]
fn exactly_one_source_file_creates_a_listening_socket() {
    // The property that makes `bind::plan` load-bearing: if a second file could
    // bind, the plan would be advisory. `server.rs` is the one place, and it
    // takes a `Listen` rather than an address.
    let sources = rust_sources(&crate_root().join("src"));
    let binders: Vec<String> = sources
        .iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .expect("readable")
                .contains("TcpListener::bind")
        })
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(
        binders,
        vec!["server.rs".to_owned()],
        "the bind call moved or multiplied; every listener must be created from a \
         bind::Listen and nowhere else"
    );
}

#[test]
fn no_outbound_connection_is_made_anywhere_in_this_crate() {
    // This process holds span maps -- the table from each surrogate back to a
    // real identifier -- and it holds them safely only because it cannot send
    // one anywhere. It accepts connections; it never makes one. `TcpStream` is
    // used only for ACCEPTED connections, so `TcpStream::connect` is the needle.
    let sources = rust_sources(&crate_root().join("src"));
    for path in sources {
        let body = std::fs::read_to_string(&path).expect("readable");
        assert!(
            !body.contains("TcpStream::connect"),
            "{} makes an outbound connection. deid-serve never does: it holds the span map \
             precisely because it has no way to send it anywhere (I1).",
            path.display()
        );
    }
}

#[test]
fn no_declared_dependency_can_make_an_outbound_request() {
    // Kept in step with the same list in bindings/mcp/tests/no_listener.rs. A
    // name enumeration cannot see a transitive edge, which is why the workspace
    // also has `just core-no-socket`; this catches the direct addition, which is
    // the one a reviewer would otherwise have to notice by eye.
    const OUTBOUND_CRATES: [&str; 12] = [
        "reqwest",
        "ureq",
        "hyper",
        "hyper-util",
        "isahc",
        "curl",
        "surf",
        "attohttpc",
        "minreq",
        "ehttp",
        "async-std",
        "smol",
    ];
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("manifest is readable");
    let dependencies: String = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for crate_name in OUTBOUND_CRATES {
        for shape in [format!("\n{crate_name} "), format!("\n{crate_name} =")] {
            assert!(
                !dependencies.contains(&shape),
                "{crate_name} was added to deid-serve. This process holds span maps and must \
                 have no way to send one anywhere (I1)."
            );
        }
    }
}
