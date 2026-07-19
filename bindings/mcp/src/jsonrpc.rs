//! JSON-RPC 2.0 envelopes over the MCP stdio framing.
//!
//! MCP's stdio transport is newline-delimited JSON: one JSON-RPC message per line, no
//! `Content-Length` header. That is not the LSP framing it is often confused with, and getting
//! it wrong makes the server look hung rather than broken.
//!
//! Nothing in this module ever formats a `params` value into a message. `params` is where the
//! clinical note arrives, so a parse error that quoted its input would print the note (I4).

use core::fmt;

use serde_json::{json, Value};

use crate::error::{ArgumentName, GatewayError, Result};

/// A parsed request envelope.
///
/// NO `#[derive(Debug)]`, for the same reason `core`'s `DeidResult` hand-writes one: `params`
/// is where the clinical note arrives, so a derived Debug would print the note into any
/// `{:?}`, any failing assertion and any panic message (I4). The hand-written impl below
/// reports the routing information and redacts the payload.
pub struct Request {
    /// Absent for a notification, which takes no response.
    pub id: Option<Value>,
    /// The JSON-RPC method.
    pub method: String,
    /// The parameters, defaulted to an empty object so callers need no null handling.
    pub params: Value,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("is_notification", &self.is_notification())
            .field("params", &"<redacted>")
            .finish()
    }
}

impl Request {
    /// True when the peer expects no response.
    pub const fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Read a required string argument out of `params`.
    pub fn string_arg(&self, key: &str, argument: ArgumentName) -> Result<&str> {
        self.params
            .get(key)
            .and_then(Value::as_str)
            .ok_or(GatewayError::BadArgument { argument })
    }
}

/// Parse one line of the transport.
pub fn parse(line: &str) -> Result<Request> {
    let value: Value = serde_json::from_str(line).map_err(|error| {
        // The serde error's Display quotes the offending input, so only its POSITION is kept.
        // `column` is 1-based and counts characters; it is reported as a byte-ish locator for a
        // developer holding the message in memory, and is useless to anyone who is not.
        GatewayError::MalformedRequest {
            byte_offset: error.column(),
            request_len: line.len(),
        }
    })?;
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or(GatewayError::BadArgument {
            argument: ArgumentName::Envelope,
        })?
        .to_owned();
    Ok(Request {
        // A null id is a notification per JSON-RPC 2.0, and treating it as a request id would
        // send a response nobody is reading.
        id: value.get("id").filter(|id| !id.is_null()).cloned(),
        method,
        params: value.get("params").cloned().unwrap_or_else(|| json!({})),
    })
}

/// A successful response envelope.
#[must_use]
pub fn success(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// An error response envelope.
///
/// The message comes from [`GatewayError`]'s `Display`, which is text-free by construction, and
/// there is no `data` field: `data` is where a helpful implementation attaches "the input that
/// failed", which is the note.
#[must_use]
pub fn failure(id: &Value, error: &GatewayError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": error.json_rpc_code(), "message": error.to_string() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_with_an_id_expects_a_response() {
        let request = parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).expect("parse");
        assert!(!request.is_notification());
        assert_eq!(request.method, "ping");
    }

    #[test]
    fn a_message_without_an_id_is_a_notification() {
        let request =
            parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).expect("parse");
        assert!(request.is_notification());
    }

    #[test]
    fn a_null_id_is_a_notification_too() {
        let request = parse(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).expect("parse");
        assert!(request.is_notification());
    }

    #[test]
    fn missing_params_defaults_to_an_empty_object() {
        let request = parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).expect("parse");
        assert_eq!(request.params, json!({}));
    }

    #[test]
    fn a_parse_failure_reports_a_position_and_never_the_payload() {
        let phi = "Ayşe Yılmaz";
        let line = format!(r#"{{"method":"tools/call","params":{{"text":"{phi}"}}"#);
        let error = parse(&line).expect_err("unterminated object must fail");
        assert!(matches!(error, GatewayError::MalformedRequest { .. }));
        assert!(
            !error.to_string().contains(phi),
            "the parse error egressed the document (I4)"
        );
    }

    #[test]
    fn an_envelope_without_a_method_is_rejected() {
        let error = parse(r#"{"jsonrpc":"2.0","id":1}"#).expect_err("no method");
        assert_eq!(
            error,
            GatewayError::BadArgument {
                argument: ArgumentName::Envelope
            }
        );
    }

    #[test]
    fn an_error_envelope_carries_no_data_field() {
        let envelope = failure(&json!(1), &GatewayError::SessionNotFound);
        assert_eq!(envelope["error"]["code"], json!(-32001));
        assert_eq!(envelope["error"]["message"], json!("session not found"));
        assert!(
            envelope["error"].get("data").is_none(),
            "the data field is where the failing input gets attached"
        );
    }
}
