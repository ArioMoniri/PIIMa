//! The transport itself: newline-delimited JSON-RPC over a reader and a writer.
//!
//! Everything else tests `Server::handle` one line at a time. This drives `Server::run`, which
//! is what `main` calls, so the framing, the notification handling and the shutdown sweep are
//! exercised the way a real MCP client exercises them.

use std::io::BufReader;

use serde_json::{json, Value};

use deid_tr_mcp::fixtures;
use deid_tr_mcp::server::{Server, ServerConfig};
use deid_tr_mcp::telemetry::Telemetry;
use deid_tr_mcp::{PROTOCOL_VERSION, SERVER_NAME};

/// Feed a script of messages through the loop and return one response per line written.
fn converse(script: &[Value]) -> Vec<Value> {
    let session: String = script
        .iter()
        .map(|message| format!("{message}\n"))
        .collect();
    let mut written: Vec<u8> = Vec::new();
    Server::new(ServerConfig::default(), Telemetry::silent())
        .expect("entropy")
        .run(BufReader::new(session.as_bytes()), &mut written)
        .expect("the loop must finish cleanly when the peer closes stdin");
    String::from_utf8(written)
        .expect("responses must be UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each response line is one JSON value"))
        .collect()
}

fn call(id: i64, tool: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": tool, "arguments": arguments },
    })
}

#[test]
fn the_handshake_reports_the_protocol_version_and_the_tools() {
    let responses = converse(&[
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    ]);

    assert_eq!(
        responses.len(),
        2,
        "a notification must produce no response line"
    );
    assert_eq!(responses[0]["id"], json!(1));
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        json!(PROTOCOL_VERSION)
    );
    assert_eq!(
        responses[0]["result"]["serverInfo"]["name"],
        json!(SERVER_NAME)
    );

    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("a tool list");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("a tool name"))
        .collect();
    for required in ["deidentify", "reidentify", "health"] {
        assert!(names.contains(&required), "{required} is not advertised");
    }
}

#[test]
fn a_batch_of_messages_is_answered_in_order_over_one_connection() {
    // Response ordering matters: a client correlates by id, but a server that reordered or
    // dropped a line would still "pass" any single-message test.
    let source = format!("Hasta Ayşe Yılmaz, TCKN {}.", fixtures::tckn());
    let responses = converse(&[
        json!({ "jsonrpc": "2.0", "id": 10, "method": "ping" }),
        call(11, "deidentify", json!({ "text": source })),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        call(12, "health", json!({})),
    ]);

    assert_eq!(responses.len(), 3, "the notification must not be answered");
    let ids: Vec<Value> = responses.iter().map(|r| r["id"].clone()).collect();
    assert_eq!(ids, vec![json!(10), json!(11), json!(12)]);

    let masked = &responses[1]["result"]["structuredContent"];
    assert!(
        !masked["text"]
            .as_str()
            .expect("masked text")
            .contains(&fixtures::tckn()),
        "the identifier crossed the transport unmasked"
    );
    // The session opened by message 11 is visible to message 12, which is the property that
    // makes a round trip possible at all over one long-lived connection.
    assert_eq!(
        responses[2]["result"]["structuredContent"]["sessions"]["live"],
        json!(1)
    );
}

#[test]
fn a_masked_document_is_restored_within_one_connection() {
    // Written as a driven conversation rather than a static script, because the handle from the
    // first response is the input to the second.
    let mut server = Server::new(ServerConfig::default(), Telemetry::silent()).expect("entropy");
    let source = format!(
        "Hasta Şükrü Gökçe, tel 0(532) 000 00 00, TCKN {}.",
        fixtures::tckn()
    );

    let opened: Value = serde_json::from_str(
        &server
            .handle(&call(1, "deidentify", json!({ "text": source })).to_string())
            .expect("answered"),
    )
    .expect("valid JSON");
    let masked = &opened["result"]["structuredContent"];

    let restored: Value = serde_json::from_str(
        &server
            .handle(
                &call(
                    2,
                    "reidentify",
                    json!({
                        "text": masked["text"].clone(),
                        "session": masked["session"].clone(),
                    }),
                )
                .to_string(),
            )
            .expect("answered"),
    )
    .expect("valid JSON");
    assert_eq!(
        restored["result"]["structuredContent"]["text"]
            .as_str()
            .expect("text"),
        source
    );
}

#[test]
fn blank_lines_are_ignored_rather_than_answered() {
    // Clients and shells emit stray newlines. Answering one with a parse error would look like
    // a protocol fault to the client for something that is not a message at all.
    let mut written: Vec<u8> = Vec::new();
    let script = "\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n";
    Server::new(ServerConfig::default(), Telemetry::silent())
        .expect("entropy")
        .run(BufReader::new(script.as_bytes()), &mut written)
        .expect("clean finish");
    assert_eq!(
        String::from_utf8(written).expect("utf-8").lines().count(),
        1
    );
}

#[test]
fn a_malformed_line_is_answered_with_a_null_id_rather_than_silence() {
    let mut written: Vec<u8> = Vec::new();
    Server::new(ServerConfig::default(), Telemetry::silent())
        .expect("entropy")
        .run(BufReader::new(&b"{not json"[..]), &mut written)
        .expect("clean finish");
    let response: Value =
        serde_json::from_str(String::from_utf8(written).expect("utf-8").trim()).expect("JSON");
    assert_eq!(response["id"], Value::Null);
    assert_eq!(response["error"]["code"], json!(-32700));
}

#[test]
fn health_reports_the_transport_the_layers_and_the_retention_policy() {
    let responses = converse(&[call(1, "health", json!({}))]);
    let health = &responses[0]["result"]["structuredContent"];

    assert_eq!(health["transport"], json!("stdio"));
    assert_eq!(
        health["listening"],
        json!(false),
        "the gateway must report that it binds nothing (I3)"
    );
    assert_eq!(health["tier"], json!("safe_harbor"));
    assert_eq!(health["sessions"]["storage"], json!("memory-only"));
    assert_eq!(health["sessions"]["ttl_seconds"], json!(900));
    assert!(health["version"].is_string());
    assert!(
        health["models_loaded"]
            .as_array()
            .expect("a list")
            .is_empty(),
        "no weights ship yet, and the honest answer is an empty list"
    );

    let layers = health["layers"].as_array().expect("a layer list");
    let rules = layers
        .iter()
        .find(|layer| layer["id"] == json!("L1"))
        .expect("L1 is reported");
    assert_eq!(rules["live"], json!(true));
    let ner = layers
        .iter()
        .find(|layer| layer["id"] == json!("L2"))
        .expect("L2 is reported");
    assert_eq!(
        ner["live"],
        json!(false),
        "reporting a stub layer as live would tell an operator names are masked when they are not"
    );
}
