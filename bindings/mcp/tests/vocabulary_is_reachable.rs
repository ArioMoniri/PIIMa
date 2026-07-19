//! Does the SHIPPED gateway carry the audited medical vocabulary and L5?
//!
//! The gateway used to build `Pipeline::new(tier)` and nothing else, so L4
//! consulted an EMPTY class C vocabulary and L5 was never installed. Every
//! collision test in `core/` passed against a vocabulary the binary did not
//! have. These tests therefore drive the server's real JSON-RPC surface -- the
//! same one an MCP client touches -- and none of them constructs a pipeline.
//!
//! # What this file asserts and what it cannot
//!
//! The KEEP direction is fully observable here: a term the vocabulary vouches
//! for is left in the body the model receives, and the same document through a
//! gateway started with `--no-medical-allowlist` has it masked. That A/B is the
//! proof, because the only difference between the two runs is the vocabulary.
//!
//! The MASK direction is observable as "a token appeared", but not as "a
//! surrogate appeared": `surrogate.rs` deliberately re-renders every masked
//! span with the gateway's own reversible token, so L5's output never reaches
//! the wire here. L5's presence is asserted through `Server::pipeline()`
//! instead, and the reason it is installed at all despite being re-rendered is
//! stated on `ServerConfig::placeholder_labels`.
//!
//! The brief's `Prof. Dr. Marco Costa` half is not reachable from this binary
//! for a reason that has nothing to do with the allowlist: nothing in a shipped
//! gateway proposes a name span. L1 has no name rule, L2 ships empty, and L3 is
//! tier-gated on a local model the gateway cannot start. See
//! `bindings/cli/tests/vocabulary_is_reachable.rs` for the same note.
//!
//! Every fixture is synthetic (I8).

use serde_json::{json, Value};

use deid_tr_mcp::server::{Server, ServerConfig};
use deid_tr_mcp::telemetry::Telemetry;

/// The brief's canonical medical-register document, synthetic.
const COSTA_NOTE: &str = "\
GÖĞÜS CERRAHİSİ KONSÜLTASYON NOTU
Konsültan: Prof. Dr. Marco Costa

Tetkikler: Toraks BT'de sol 5. costa'da deplase olmayan fraktür izlendi.
Hasta carcinoma'lı değil; MRI'da ek patoloji yok.
";

fn server_with(config: ServerConfig) -> Server {
    Server::new(config, Telemetry::silent()).expect("entropy")
}

fn deidentify(server: &mut Server, text: &str) -> Value {
    let line = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "deidentify", "arguments": { "text": text } },
    });
    let response = server.handle(&line.to_string()).expect("answered");
    let envelope: Value = serde_json::from_str(&response).expect("valid JSON");
    assert_eq!(
        envelope["result"]["isError"],
        json!(false),
        "deidentify failed: {}",
        envelope["result"]["structuredContent"]["error"]
    );
    envelope["result"]["structuredContent"].clone()
}

#[test]
fn the_body_handed_to_the_cloud_model_keeps_its_medical_register() {
    let mut server = server_with(ServerConfig::default());
    let out = deidentify(&mut server, COSTA_NOTE);
    let body = out["text"].as_str().expect("a body");
    assert!(body.contains("costa'da deplase"), "{body}");
    assert!(body.contains("carcinoma'lı"), "{body}");
    assert!(body.contains("MRI'da"), "{body}");
}

#[test]
fn the_shipped_vocabulary_is_what_decides_an_allowlisted_term() {
    // `B12` is a lab analyte AND a record-number-shaped token that `rules::mrn`
    // proposes after a cue word, at a confidence below the escalation ceiling.
    // It is the one place a shipped gateway can exercise L4's allowlist path
    // end to end, because it is the one place a shipped gateway produces a
    // demotable candidate at all.
    let note = "Dosya No: B12\n";

    let mut default_server = server_with(ServerConfig::default());
    let kept = deidentify(&mut default_server, note);
    assert_eq!(
        kept["masked_spans"], 0,
        "the gateway masked a lab analyte, so L4 consulted no vocabulary: {}",
        kept["text"]
    );
    assert!(kept["text"]
        .as_str()
        .expect("a body")
        .contains("Dosya No: B12"));

    let mut bare_server = server_with(ServerConfig {
        no_medical_allowlist: true,
        ..ServerConfig::default()
    });
    let masked = deidentify(&mut bare_server, note);
    assert_eq!(
        masked["masked_spans"], 1,
        "the opt-out did not disable the vocabulary"
    );
    assert!(!masked["text"].as_str().expect("a body").contains("B12"));
}

#[test]
fn the_default_gateway_is_built_with_the_vocabulary_and_with_l5() {
    let server = server_with(ServerConfig::default());
    assert!(server.pipeline().allowlist().contains("costa"));
    assert!(server.pipeline().allowlist().contains("carcinoma"));
    assert!(
        server.pipeline().surrogate().is_some(),
        "L5 must be installed by default, in every binding without exception"
    );

    let opted_out = server_with(ServerConfig {
        no_medical_allowlist: true,
        placeholder_labels: true,
        ..ServerConfig::default()
    });
    assert!(!opted_out.pipeline().allowlist().contains("costa"));
    assert!(opted_out.pipeline().surrogate().is_none());
}

#[test]
fn a_masked_span_reaches_the_model_as_a_distinguishing_token_not_a_bare_label() {
    // The gateway's contract for what replaces an identifier. A bare `[MRN]`
    // would collapse two different record numbers onto one string, and
    // restoring from that map would put one patient's number onto another
    // patient's finding.
    let note = "Protokol No: 4471928 ve Dosya No: ACL-2026-004212 kayitlidir.\n";
    let mut server = server_with(ServerConfig::default());
    let out = deidentify(&mut server, note);
    let body = out["text"].as_str().expect("a body");

    assert!(!body.contains("[MRN]"), "bare label placeholder: {body}");
    let placeholders: Vec<&str> = out["spans"]
        .as_array()
        .expect("spans")
        .iter()
        .map(|span| span["placeholder"].as_str().expect("a placeholder"))
        .collect();
    assert_eq!(placeholders.len(), 2, "{body}");
    assert_ne!(
        placeholders[0], placeholders[1],
        "two distinct identifiers collapsed onto one token: {body}"
    );
    for placeholder in placeholders {
        assert!(body.contains(placeholder), "{body}");
    }
}
