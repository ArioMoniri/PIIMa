//! The property M2 exists to deliver: mask on the way out, restore on the way back, exactly.
//!
//! These drive the server through its real JSON-RPC surface rather than calling the internals,
//! because the surface is what an MCP client actually touches and a round trip that only works
//! through the private API is not a shippable one.

use serde_json::{json, Value};

use deid_tr_mcp::fixtures;
use deid_tr_mcp::server::{Server, ServerConfig};
use deid_tr_mcp::telemetry::Telemetry;

/// A server with the shipping defaults and no diagnostics.
fn server() -> Server {
    Server::new(ServerConfig::default(), Telemetry::silent()).expect("entropy")
}

/// Send one request and return the parsed response envelope.
fn request(server: &mut Server, id: i64, method: &str, params: Value) -> Value {
    let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let response = server
        .handle(&line.to_string())
        .expect("a request with an id must be answered");
    serde_json::from_str(&response).expect("the server emitted invalid JSON")
}

/// Call a tool and return its `structuredContent`, asserting it did not report an error.
fn call_ok(server: &mut Server, tool: &str, arguments: Value) -> Value {
    let envelope = request(
        server,
        1,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    );
    let result = &envelope["result"];
    assert_eq!(
        result["isError"],
        json!(false),
        "{tool} failed: {}",
        result["structuredContent"]["error"]
    );
    result["structuredContent"].clone()
}

/// Call a tool expecting failure, and return its `structuredContent`.
fn call_err(server: &mut Server, tool: &str, arguments: Value) -> Value {
    let envelope = request(
        server,
        1,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    );
    assert_eq!(
        envelope["result"]["isError"],
        json!(true),
        "{tool} succeeded"
    );
    envelope["result"]["structuredContent"].clone()
}

/// A synthetic Turkish note. Every identifier in it is fabricated, and the TCKN is built at
/// runtime by `fixtures` so that no checksum-valid number is ever written into this file (I8).
fn note() -> String {
    format!(
        "Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00. \
         Op. Dr. Şükrü Gökçe tarafından görüldü. Hastada carcinoma şüphesi, MRI'da bulgu var.",
        fixtures::tckn()
    )
}

#[test]
fn mask_then_reidentify_reproduces_the_original_exactly() {
    let mut server = server();
    let source = note();

    let masked = call_ok(&mut server, "deidentify", json!({ "text": source }));
    let handle = masked["session"].as_str().expect("a session handle");
    let body = masked["text"].as_str().expect("masked text");

    assert_ne!(body, source, "nothing was masked");
    assert!(
        !body.contains(&fixtures::tckn()),
        "the identifier survived masking"
    );

    let restored = call_ok(
        &mut server,
        "reidentify",
        json!({ "text": body, "session": handle }),
    );
    assert_eq!(
        restored["text"].as_str().expect("restored text"),
        source,
        "the round trip was not byte-exact"
    );
}

#[test]
fn a_model_response_quoting_placeholders_is_restored_in_place() {
    // The real shape of the workflow: the cloud model does not echo the document back, it
    // writes prose that mentions the placeholders. Restoration has to work on arbitrary text
    // that merely CONTAINS tokens, not only on the masked document.
    let mut server = server();
    let source = note();
    let masked = call_ok(&mut server, "deidentify", json!({ "text": source }));
    let handle = masked["session"].as_str().expect("handle").to_owned();

    let spans = masked["spans"].as_array().expect("spans");
    let name_token = spans
        .iter()
        .find(|span| span["label"] == json!("TCKN"))
        .map(|span| {
            span["placeholder"]
                .as_str()
                .expect("placeholder")
                .to_owned()
        })
        .expect("the TCKN reached the span map");

    let model_reply = format!("Ozet: {name_token} numarali hastanin takibi onerilir. {name_token}");
    let restored = call_ok(
        &mut server,
        "reidentify",
        json!({ "text": model_reply, "session": handle }),
    );
    let tckn = fixtures::tckn();
    assert_eq!(
        restored["text"].as_str().expect("text"),
        format!("Ozet: {tckn} numarali hastanin takibi onerilir. {tckn}")
    );
    assert_eq!(restored["substitutions"], json!(2), "one token, seen twice");
    assert_eq!(restored["entities_restored"], json!(1));
}

#[test]
fn a_document_with_nothing_to_mask_still_round_trips() {
    let mut server = server();
    let source = "Hastada carcinoma'lı bulgu yok. PET-CT'de patoloji saptanmadı.";
    let masked = call_ok(&mut server, "deidentify", json!({ "text": source }));
    assert_eq!(masked["text"].as_str().expect("text"), source);
    assert_eq!(masked["masked_spans"], json!(0));

    let handle = masked["session"].as_str().expect("handle");
    let restored = call_ok(
        &mut server,
        "reidentify",
        json!({ "text": source, "session": handle }),
    );
    assert_eq!(restored["text"].as_str().expect("text"), source);
}

#[test]
fn an_unknown_session_handle_is_indistinguishable_from_an_expired_one() {
    // The oracle this test exists to deny: a caller holding a guessed handle must not learn
    // whether it was ever real. `forget` produces a genuinely-expired handle, which is the
    // closest observable analogue to a TTL lapse without waiting fifteen minutes.
    let mut server = server();
    let masked = call_ok(&mut server, "deidentify", json!({ "text": note() }));
    let handle = masked["session"].as_str().expect("handle").to_owned();
    call_ok(&mut server, "forget", json!({ "session": handle.clone() }));

    let after_forget = call_err(
        &mut server,
        "reidentify",
        json!({ "text": "x", "session": handle }),
    );
    let never_existed = call_err(
        &mut server,
        "reidentify",
        json!({ "text": "x", "session": "0123456789abcdef0123456789abcdef" }),
    );

    assert_eq!(
        after_forget, never_existed,
        "the gateway told the caller whether a handle had ever existed"
    );
    assert_eq!(after_forget["error"], json!("session_not_found"));
    assert_eq!(after_forget["message"], json!("session not found"));
}

#[test]
fn a_forgotten_session_cannot_be_used_again() {
    let mut server = server();
    let masked = call_ok(&mut server, "deidentify", json!({ "text": note() }));
    let handle = masked["session"].as_str().expect("handle").to_owned();
    let forgotten = call_ok(&mut server, "forget", json!({ "session": handle.clone() }));
    assert_eq!(forgotten["forgotten"], json!(true));
    assert!(forgotten["entities_destroyed"].as_u64().expect("count") > 0);

    let again = call_err(&mut server, "forget", json!({ "session": handle }));
    assert_eq!(again["error"], json!("session_not_found"));
}

#[test]
fn no_error_path_echoes_the_document() {
    // I4 at the surface. Every failure a caller can provoke while holding a note is checked
    // against the note's contents, because an error message is the classic egress path.
    let mut server = server();
    let phi = format!("Ayşe Yılmaz TCKN {}", fixtures::tckn());

    let mut rendered = Vec::new();

    rendered.push(
        call_err(
            &mut server,
            "reidentify",
            json!({ "text": phi.clone(), "session": "not-a-real-handle" }),
        )
        .to_string(),
    );
    rendered.push(call_err(&mut server, "deidentify", json!({ "note": phi.clone() })).to_string());
    // An unknown TOOL is a protocol error rather than a tool-level one, so it comes back as a
    // JSON-RPC error envelope and is checked in that shape.
    rendered.push(
        request(
            &mut server,
            1,
            "tools/call",
            json!({ "name": "unknown-tool", "arguments": { "text": phi.clone() } }),
        )
        .to_string(),
    );
    rendered.push(
        server
            .handle(&format!(
                r#"{{"id":1,"method":"tools/call","params":{{"x":"{phi}"#
            ))
            .expect("a malformed line is answered"),
    );
    rendered.push(
        request(
            &mut server,
            1,
            "no/such/method",
            json!({ "text": phi.clone() }),
        )
        .to_string(),
    );

    for message in rendered {
        assert!(
            !message.contains("Ayşe"),
            "an error path egressed document text: {message}"
        );
        assert!(
            !message.contains(&fixtures::tckn()),
            "an error path egressed an identifier: {message}"
        );
    }
}

#[test]
fn a_document_over_the_ceiling_is_refused_without_opening_a_session() {
    let mut server = Server::new(
        ServerConfig {
            max_document_bytes: 64,
            ..ServerConfig::default()
        },
        Telemetry::silent(),
    )
    .expect("entropy");
    let refused = call_err(&mut server, "deidentify", json!({ "text": "x".repeat(65) }));
    assert_eq!(refused["error"], json!("document_too_large"));
    let health = call_ok(&mut server, "health", json!({}));
    assert_eq!(health["sessions"]["live"], json!(0));
}
