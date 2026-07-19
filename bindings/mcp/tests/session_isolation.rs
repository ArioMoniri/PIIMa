//! Concurrent sessions must not bleed into each other.
//!
//! "Bleed" has a precise and dangerous meaning here. The span map maps a surrogate back to a
//! real patient identifier, so a session that restores using the WRONG map writes one
//! patient's name into another patient's record. That is not a corruption bug, it is a
//! disclosure: the clinician reads a correct-looking note about the wrong person.
//!
//! Three properties are asserted, and the third is the one a naive implementation fails:
//!   1. two live sessions each restore their own document correctly;
//!   2. destroying one leaves the other intact;
//!   3. a token minted in session A is INERT in session B -- not merely wrong, but not
//!      substituted at all -- because each document's tokens carry a fresh random nonce.

use serde_json::{json, Value};

use deid_tr_mcp::fixtures;
use deid_tr_mcp::server::{Server, ServerConfig};
use deid_tr_mcp::telemetry::Telemetry;

fn server() -> Server {
    Server::new(ServerConfig::default(), Telemetry::silent()).expect("entropy")
}

fn call(server: &mut Server, tool: &str, arguments: Value) -> Value {
    let line = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": arguments },
    });
    let response: Value = serde_json::from_str(
        &server
            .handle(&line.to_string())
            .expect("a request with an id must be answered"),
    )
    .expect("valid JSON");
    response["result"]["structuredContent"].clone()
}

struct Opened {
    handle: String,
    body: String,
    source: String,
}

fn open(server: &mut Server, source: String) -> Opened {
    let masked = call(server, "deidentify", json!({ "text": source }));
    Opened {
        handle: masked["session"].as_str().expect("handle").to_owned(),
        body: masked["text"].as_str().expect("text").to_owned(),
        source,
    }
}

/// Two distinct synthetic patients. The TCKNs are built at runtime (I8).
fn two_notes() -> (String, String) {
    (
        format!(
            "Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00.",
            fixtures::tckn()
        ),
        format!(
            "Hasta Şükrü Gökçe, TCKN {}, tel 0(533) 111 11 11.",
            fixtures::other_tckn()
        ),
    )
}

#[test]
fn two_interleaved_sessions_each_restore_their_own_document() {
    let mut server = server();
    let (first_note, second_note) = two_notes();

    // Interleaved on purpose: open both BEFORE restoring either, so the store is holding two
    // span maps at the moment each lookup happens.
    let first = open(&mut server, first_note);
    let second = open(&mut server, second_note);

    let restored_second = call(
        &mut server,
        "reidentify",
        json!({ "text": second.body, "session": second.handle }),
    );
    let restored_first = call(
        &mut server,
        "reidentify",
        json!({ "text": first.body, "session": first.handle }),
    );

    assert_eq!(restored_first["text"].as_str().expect("text"), first.source);
    assert_eq!(
        restored_second["text"].as_str().expect("text"),
        second.source
    );
}

#[test]
fn a_token_from_one_session_is_inert_in_another() {
    // THE bleed test. Restoring session A's masked document under session B's handle must
    // produce session A's document unchanged -- no substitution at all. The dangerous failure
    // would be a partial substitution that silently mixes two patients.
    let mut server = server();
    let (first_note, second_note) = two_notes();
    let first = open(&mut server, first_note);
    let second = open(&mut server, second_note);

    let crossed = call(
        &mut server,
        "reidentify",
        json!({ "text": first.body, "session": second.handle }),
    );
    assert_eq!(
        crossed["text"].as_str().expect("text"),
        first.body,
        "one session's span map substituted into another session's document"
    );
    assert_eq!(crossed["substitutions"], json!(0));
    assert!(
        !crossed["text"]
            .as_str()
            .expect("text")
            .contains(&fixtures::other_tckn()),
        "the wrong patient's identifier was written into this document"
    );
}

#[test]
fn the_same_document_masked_twice_yields_two_independent_sessions() {
    // The subtle case: identical input. Nothing about the document may make two sessions share
    // tokens, or a client juggling handles restores from whichever map it happens to reach.
    let mut server = server();
    let source = format!("Hasta Ayşe Yılmaz, TCKN {}.", fixtures::tckn());
    let first = open(&mut server, source.clone());
    let second = open(&mut server, source.clone());

    assert_ne!(first.handle, second.handle);
    assert_ne!(
        first.body, second.body,
        "two sessions minted identical tokens for identical input"
    );

    let crossed = call(
        &mut server,
        "reidentify",
        json!({ "text": first.body, "session": second.handle }),
    );
    assert_eq!(crossed["substitutions"], json!(0));

    // Each still restores itself.
    for opened in [first, second] {
        let restored = call(
            &mut server,
            "reidentify",
            json!({ "text": opened.body, "session": opened.handle }),
        );
        assert_eq!(restored["text"].as_str().expect("text"), source);
    }
}

#[test]
fn destroying_one_session_leaves_the_others_intact() {
    let mut server = server();
    let (first_note, second_note) = two_notes();
    let first = open(&mut server, first_note);
    let second = open(&mut server, second_note);

    call(&mut server, "forget", json!({ "session": first.handle }));

    let survivor = call(
        &mut server,
        "reidentify",
        json!({ "text": second.body, "session": second.handle }),
    );
    assert_eq!(survivor["text"].as_str().expect("text"), second.source);

    let health = call(&mut server, "health", json!({}));
    assert_eq!(health["sessions"]["live"], json!(1));
}

#[test]
fn many_live_sessions_stay_separate() {
    // Wider than two, because an off-by-one in a lookup key shows up at scale and not at N=2.
    let mut server = server();
    let opened: Vec<Opened> = (0..16)
        .map(|n| {
            open(
                &mut server,
                format!("Hasta {n} icin tel 0(53{}) 000 00 0{n}.", n % 10),
            )
        })
        .collect();

    for entry in &opened {
        let restored = call(
            &mut server,
            "reidentify",
            json!({ "text": entry.body.clone(), "session": entry.handle.clone() }),
        );
        assert_eq!(
            restored["text"].as_str().expect("text"),
            entry.source,
            "a span map was served under the wrong handle"
        );
    }
}
