//! Every endpoint, over a real loopback socket.
//!
//! # Why over a socket and not against `Service::handle`
//!
//! `Service::handle` is unit-tested in `src/api.rs`, and those tests are the
//! ones that enumerate the failure shapes. What they cannot see is the seam:
//! framing, `Content-Length`, the bearer check, the status line, and the
//! `Connection: close` that a client depends on to know the response ended. Every
//! one of those has been a source of "it works in the tests" in some other
//! project, so the endpoint suite drives the wire.
//!
//! # No PHI in this file
//!
//! Every fixture is synthetic. The TCKN is built at run time by
//! `deid_tr_service::fixtures` and is never written down (I8).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use deid_tr_service::api::ServiceConfig;
use deid_tr_service::bind;
use deid_tr_service::fixtures::{note, tckn};
use deid_tr_service::log::Log;
use deid_tr_service::server::{bind_listener, Server};
use serde_json::{json, Value};

/// Start a server on a kernel-chosen loopback port and return its address.
fn start(config: ServiceConfig) -> SocketAddr {
    let listen = bind::plan(bind::default_host(), 0, false, None).expect("loopback plan");
    let listener = bind_listener(&listen).expect("bind");
    let addr = listener.local_addr().expect("local addr");
    // The Server is constructed INSIDE the thread. `Pipeline` holds
    // `Box<dyn Detector>` trait objects, which are deliberately not `Send` --
    // an inference session is not a thing to move between threads behind the
    // author's back -- so the server is built where it runs. Detached: the
    // thread dies with the test process. Joining would mean a shutdown path
    // exercised only by tests, which is a shutdown path that does not match
    // production.
    std::thread::spawn(move || {
        let mut server = Server::new(&listen, config, Log::silent()).expect("server");
        server.serve_listener(&listener);
    });
    addr
}

/// One request, one response. Returns `(status, body)`.
fn request(addr: SocketAddr, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
    let rendered = body
        .map(std::string::ToString::to_string)
        .unwrap_or_default();
    let mut stream = TcpStream::connect(addr).expect("connect");
    let wire = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{rendered}",
        rendered.len()
    );
    stream.write_all(wire.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in the response"));
    let payload = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    (status, serde_json::from_str(payload).expect("json body"))
}

fn get(addr: SocketAddr, path: &str) -> (u16, Value) {
    request(addr, "GET", path, None)
}

fn post(addr: SocketAddr, path: &str, body: &Value) -> (u16, Value) {
    request(addr, "POST", path, Some(body))
}

#[test]
fn health_reports_version_tier_layers_and_loaded_models() {
    let addr = start(ServiceConfig::default());
    let (status, body) = get(addr, "/health");
    assert_eq!(status, 200);
    assert_eq!(body["status"], json!("ok"));
    assert_eq!(body["service"], json!("deid-serve"));
    assert_eq!(body["version"], json!(deid_tr_service::VERSION));
    assert_eq!(body["tier"], json!("safe_harbor"));
    assert_eq!(body["models_loaded"], json!([]));
    assert_eq!(body["bind"]["exposed"], json!(false));
    assert_eq!(body["bind"]["auth_required"], json!(false));

    // Which layers are live, and the honest statement of what the dead one
    // costs. This is the assertion that fails if someone quietly softens the
    // wording.
    assert_eq!(body["layers"]["l1_rules"]["live"], json!(true));
    assert_eq!(body["layers"]["l2_ner"]["live"], json!(false));
    assert!(body["layers"]["l2_ner"]["detail"]
        .as_str()
        .expect("detail")
        .contains("ZERO names"));
    assert_eq!(body["layers"]["l3_contextual"]["live"], json!(false));
    assert_eq!(body["layers"]["l4_router"]["live"], json!(true));
    assert_eq!(body["layers"]["l5_surrogates"]["live"], json!(true));
}

#[test]
fn entities_serves_the_catalog_with_per_label_honesty() {
    let addr = start(ServiceConfig::default());
    let (status, body) = get(addr, "/entities");
    assert_eq!(status, 200);
    assert_eq!(body["source"], json!("eval/schema.yaml"));

    let direct = body["direct_identifiers"].as_array().expect("direct");
    assert!(direct.len() > 30);
    let by_id = |id: &str| -> Value {
        direct
            .iter()
            .find(|entry| entry["id"] == json!(id))
            .unwrap_or_else(|| panic!("{id} missing from the catalog"))
            .clone()
    };

    // A rule-detectable identifier is live.
    let tckn_entry = by_id("TCKN");
    assert_eq!(tckn_entry["detector"], json!("rules"));
    assert_eq!(tckn_entry["checksum_validatable"], json!(true));
    assert_eq!(tckn_entry["precision_threshold"], json!(1.0));
    assert_eq!(tckn_entry["detected_by_this_build"], json!(true));

    // A name is not, and the catalog says why.
    let name_entry = by_id("PATIENT_NAME");
    assert_eq!(name_entry["detector"], json!("ner"));
    assert_eq!(name_entry["detected_by_this_build"], json!(false));
    assert!(name_entry["detection_note"]
        .as_str()
        .expect("note")
        .contains("ZERO names"));

    assert_eq!(
        body["quasi_identifiers"].as_array().expect("quasi").len(),
        5
    );
}

#[test]
fn analyze_returns_labels_offsets_and_confidence() {
    let addr = start(ServiceConfig::default());
    let source = note();
    let (status, body) = post(addr, "/analyze", &json!({ "text": source }));
    assert_eq!(status, 200);

    let entities = body["entities"].as_array().expect("entities");
    let found = entities
        .iter()
        .find(|entity| entity["label"] == json!("TCKN"))
        .expect("the TCKN reached the report");
    assert_eq!(found["confidence"], json!(1.0));
    assert_eq!(found["checksum_validated"], json!(true));
    assert_eq!(found["layer"], json!("rules"));

    let start_offset = found["start"].as_u64().expect("start") as usize;
    let end_offset = found["end"].as_u64().expect("end") as usize;
    assert_eq!(&source[start_offset..end_offset], tckn());

    // The response is metadata: no covered text anywhere in it.
    let rendered = body.to_string();
    assert!(!rendered.contains(&tckn()));
    assert!(!rendered.contains("Ayşe"));
}

#[test]
fn a_confidence_threshold_never_changes_what_is_masked() {
    // I2, over the wire. The masked output must be byte-identical with and
    // without the flag; only the report shrinks.
    let addr = start(ServiceConfig::default());
    let source = note();
    let (_, wide) = post(addr, "/analyze", &json!({ "text": source }));
    let (_, narrow) = post(
        addr,
        "/analyze",
        &json!({ "text": source, "confidence_threshold": 0.99 }),
    );
    assert_eq!(wide["masked"], narrow["masked"]);
    assert_eq!(wide["count"], narrow["count"]);
    assert!(narrow["threshold_warning"]
        .as_str()
        .expect("warning")
        .contains("never what is masked"));
}

#[test]
fn deidentify_masks_returns_a_span_map_and_a_session_handle() {
    let addr = start(ServiceConfig::default());
    let source = note();
    let (status, body) = post(addr, "/deidentify", &json!({ "text": source }));
    assert_eq!(status, 200);

    let masked = body["text"].as_str().expect("masked text");
    assert!(!masked.contains(&tckn()), "the TCKN survived masking");
    assert!(masked.contains("carcinoma'lı"), "a medical term was masked");
    // The honest boundary, asserted rather than asserted-away: no name is
    // masked, because L2 has no model.
    assert!(masked.contains("Ayşe Yılmaz"));

    let handle = body["session"].as_str().expect("handle");
    assert_eq!(handle.len(), 32);
    assert!(body["masked"].as_u64().expect("masked") >= 1);

    let spans = body["spans"].as_array().expect("spans");
    for span in spans {
        // Both offset systems, and never the original.
        assert!(span["start"].is_u64());
        assert!(span["output_start"].is_u64());
        assert!(span.get("original").is_none());
    }
}

#[test]
fn a_round_trip_through_the_service_is_byte_exact() {
    let addr = start(ServiceConfig::default());
    let source = note();
    let (_, masked) = post(addr, "/deidentify", &json!({ "text": source }));
    let handle = masked["session"].as_str().expect("handle").to_owned();
    assert_ne!(masked["text"].as_str().expect("masked"), source);

    let (status, restored) = post(addr, "/reidentify", &json!({ "session": handle }));
    assert_eq!(status, 200);
    assert_eq!(
        restored["text"].as_str().expect("restored"),
        source,
        "the round trip was not byte-exact"
    );
    // Byte-for-byte, stated as bytes, because a `==` on `&str` that passed on a
    // normalised comparison would not be the property being sold.
    assert_eq!(
        restored["text"].as_str().expect("restored").as_bytes(),
        source.as_bytes()
    );
}

#[test]
fn a_round_trip_survives_a_document_that_is_almost_entirely_multibyte() {
    // The offset walk is the place a char-index bug hides, so the fixture puts
    // multi-byte Turkish before, between and after every replacement.
    let addr = start(ServiceConfig::default());
    let source = format!(
        "Şükrü Gökçe'nin TCKN'si {}, eşi Ayşe'nin telefonu 0(532) 000 00 00. \
         carcinoma'lı hastada MRI'da şüpheli lezyon; İzmir'e sevk edildi.",
        tckn()
    );
    let (_, masked) = post(addr, "/deidentify", &json!({ "text": source }));
    let handle = masked["session"].as_str().expect("handle").to_owned();
    let (_, restored) = post(addr, "/reidentify", &json!({ "session": handle }));
    assert_eq!(restored["text"].as_str().expect("restored"), source);
}

#[test]
fn a_released_session_cannot_be_used_again() {
    let addr = start(ServiceConfig::default());
    let (_, masked) = post(addr, "/deidentify", &json!({ "text": note() }));
    let handle = masked["session"].as_str().expect("handle").to_owned();

    let (status, first) = post(
        addr,
        "/reidentify",
        &json!({ "session": handle, "release": true }),
    );
    assert_eq!(status, 200);
    assert_eq!(first["session_released"], json!(true));

    let (status, second) = post(addr, "/reidentify", &json!({ "session": handle }));
    assert_eq!(status, 404);
    assert_eq!(second["error"]["code"], json!("session_not_found"));
}

#[test]
fn a_batch_reports_every_document_including_the_ones_that_failed() {
    let addr = start(ServiceConfig::default());
    let (status, body) = post(
        addr,
        "/batch",
        &json!({
            "operation": "deidentify",
            "documents": [
                { "id": "note-1", "text": note() },
                { "id": "note-2" },
                { "id": "note-3", "text": 42 },
                { "id": "note-4", "text": "" },
                { "id": "note-5", "text": "carcinoma'lı hasta." },
            ],
        }),
    );
    assert_eq!(status, 200);
    assert_eq!(body["total"], json!(5));
    assert_eq!(body["successful"], json!(3));
    assert_eq!(body["failed"], json!(2));

    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 5, "a batch dropped a document");
    let ids: Vec<&str> = items
        .iter()
        .map(|item| item["id"].as_str().expect("id"))
        .collect();
    assert_eq!(
        ids,
        vec!["note-1", "note-2", "note-3", "note-4", "note-5"],
        "items are not in request order, or one is missing"
    );
    // Both failures carry a machine-readable code, so a caller can act on them
    // rather than merely notice a count.
    for index in [1usize, 2] {
        assert_eq!(items[index]["success"], json!(false));
        assert_eq!(items[index]["error"]["code"], json!("bad_request"));
    }
    assert!(body["completeness_note"]
        .as_str()
        .expect("note")
        .contains("never skips"));
}

#[test]
fn every_batch_item_round_trips_independently() {
    let addr = start(ServiceConfig::default());
    let first_source = note();
    let second_source = format!("Ikinci hasta, TCKN {}, tel 0(533) 000 00 00.", tckn());
    let (_, body) = post(
        addr,
        "/batch",
        &json!({
            "documents": [
                { "id": "a", "text": first_source },
                { "id": "b", "text": second_source },
            ],
        }),
    );
    let items = body["items"].as_array().expect("items");
    for (item, expected) in items.iter().zip([&first_source, &second_source]) {
        let handle = item["result"]["session"].as_str().expect("handle");
        let (status, restored) = post(addr, "/reidentify", &json!({ "session": handle }));
        assert_eq!(status, 200);
        assert_eq!(restored["text"].as_str().expect("restored"), expected);
    }
}

#[test]
fn an_unknown_route_is_a_404_and_a_wrong_method_is_a_405() {
    let addr = start(ServiceConfig::default());
    let (status, _) = get(addr, "/pii/extract");
    assert_eq!(status, 404);
    let (status, body) = get(addr, "/deidentify");
    assert_eq!(status, 405);
    assert_eq!(body["error"]["code"], json!("method_not_allowed"));
}

#[test]
fn a_malformed_body_is_refused_without_being_quoted_back() {
    let addr = start(ServiceConfig::default());
    let mut stream = TcpStream::connect(addr).expect("connect");
    let body = "Hasta Ayşe Yılmaz";
    stream
        .write_all(
            format!(
                "POST /deidentify HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 400 "));
    assert!(
        !response.contains("Ayşe"),
        "the error response quoted the request body"
    );
}

#[test]
fn responses_declare_no_store_and_a_json_content_type() {
    // A de-identification response is either PHI (the restored document) or
    // metadata about PHI. Neither belongs in an intermediary cache.
    let addr = start(ServiceConfig::default());
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.contains("Cache-Control: no-store"));
    assert!(response.contains("Content-Type: application/json; charset=utf-8"));
    assert!(response.contains("X-Content-Type-Options: nosniff"));
    assert!(response.contains("Connection: close"));
}

#[test]
fn a_bearer_token_on_a_loopback_bind_is_enforced_on_every_route() {
    // A token is honoured on loopback too -- an operator sharing a workstation
    // has a real reason to authenticate a local service, and silently dropping
    // the credential they configured would be a control that reports success and
    // does nothing.
    let secret = "k".repeat(deid_tr_service::MIN_TOKEN_LEN);
    let listen = bind::plan(bind::default_host(), 0, false, Some(&secret)).expect("plan");
    let listener = bind_listener(&listen).expect("bind");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let mut server = Server::new(
            &listen,
            ServiceConfig {
                auth_required: true,
                ..ServiceConfig::default()
            },
            Log::silent(),
        )
        .expect("server");
        server.serve_listener(&listener);
    });

    let (status, body) = get(addr, "/health");
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], json!("unauthorized"));

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .write_all(
            format!("GET /health HTTP/1.1\r\nAuthorization: Bearer {secret}\r\n\r\n").as_bytes(),
        )
        .expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(
        !response.contains(&secret),
        "the response echoed the bearer token"
    );
}
