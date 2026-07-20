//! A deliberately small HTTP/1.1 subset.
//!
//! # What is implemented, and what is refused
//!
//! Implemented: the request line, headers, a `Content-Length` body, and a
//! single response per connection. Refused, by not existing: keep-alive,
//! chunked transfer encoding, pipelining, `Expect: 100-continue`, upgrades,
//! compression, multipart, cookies, redirects.
//!
//! That list is the security argument, not an apology. Every one of those
//! features is state carried between a request and the next thing the server
//! does, and this process holds span maps. A request smuggling bug needs a
//! disagreement between two framing mechanisms to exploit; there is exactly one
//! framing mechanism here, and a body that does not declare its length is
//! rejected rather than guessed at.
//!
//! # Bounds
//!
//! Both the header block and the body are bounded before a single byte is
//! buffered, because an unbounded read from a socket is a memory exhaustion
//! primitive that needs no vulnerability at all. The body ceiling is the
//! document ceiling: a clinical note is not fifty megabytes, and a caller who
//! sends one is either wrong or hostile.

use std::io::{BufRead, Write};

/// The largest request line plus header block accepted, in bytes.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The largest request body accepted, in bytes.
///
/// One megabyte. A Turkish discharge summary is a few kilobytes; a batch of a
/// hundred of them is a few hundred. The ceiling exists so that a single
/// connection cannot make this process allocate without bound, and it is
/// deliberately far below what a general-purpose server would allow.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Why a request could not be read.
///
/// CARRIES NO BYTES OF THE REQUEST (I4). A malformed request from a clinical
/// system may well contain a fragment of a note, and an error type that quotes
/// what it could not parse is a log line containing PHI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The connection ended before a complete request line arrived.
    #[error("the connection closed before a request was received")]
    Incomplete,
    /// The request line or a header line was not valid HTTP.
    #[error("the request could not be parsed as HTTP/1.1")]
    Malformed,
    /// The header block exceeded [`MAX_HEADER_BYTES`].
    #[error("the header block exceeds the {MAX_HEADER_BYTES}-byte limit")]
    HeadersTooLarge,
    /// The declared body exceeded [`MAX_BODY_BYTES`].
    #[error("the request body exceeds the {MAX_BODY_BYTES}-byte limit")]
    BodyTooLarge,
    /// A body arrived with no `Content-Length`, or with a length that does not
    /// parse.
    ///
    /// Refused rather than inferred. Reading until close and calling that the
    /// body is how two intermediaries end up disagreeing about where one request
    /// stops and the next begins.
    #[error(
        "a request body requires a valid Content-Length header; chunked encoding is not supported"
    )]
    UnframedBody,
    /// The body was not valid UTF-8.
    #[error("the request body is not valid UTF-8")]
    NotUtf8,
    /// The socket failed.
    #[error("the connection failed")]
    Io,
}

impl HttpError {
    /// The status code this failure is reported as.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::HeadersTooLarge => 431,
            Self::BodyTooLarge => 413,
            Self::Io | Self::Incomplete => 400,
            Self::Malformed | Self::UnframedBody | Self::NotUtf8 => 400,
        }
    }
}

/// One parsed request.
///
/// `Debug` is derived and that is safe ONLY because `body` is not a field here
/// -- it is returned separately and never travels inside a printable struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// `GET`, `POST`, and whatever else a caller sent.
    pub method: String,
    /// The path with any query string removed.
    pub path: String,
    /// Header names lower-cased; values trimmed.
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// The first value for a header name, which must already be lower-case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The credential from an `Authorization: Bearer ...` header.
    #[must_use]
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
    }
}

/// A parsed request: metadata, then the body.
///
/// NO `Debug`. The body is the clinical note, so a derive here would put a
/// document one `{:?}` away from stderr (I4).
pub struct Request {
    /// Method, path and headers.
    pub head: Head,
    /// The body as UTF-8. PHI whenever the caller sent a note.
    pub body: String,
}

/// Read one request from a connection.
///
/// # Errors
///
/// One [`HttpError`] per failure in that enum. A caller reports the status and
/// closes the connection; there is no recovery path, by design.
pub fn read_request<R: BufRead>(reader: &mut R) -> Result<Request, HttpError> {
    let head = read_head(reader)?;
    let declared = head.header("content-length");
    let length = match declared {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| HttpError::UnframedBody)?,
        None => {
            // A transfer-encoding header with no content-length is the chunked
            // case, and it is named explicitly so the operator is told the
            // feature is absent rather than left to infer it from an empty body.
            if head.header("transfer-encoding").is_some() {
                return Err(HttpError::UnframedBody);
            }
            0
        }
    };
    if length > MAX_BODY_BYTES {
        return Err(HttpError::BodyTooLarge);
    }
    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .map_err(|_| HttpError::Incomplete)?;
    let body = String::from_utf8(buffer).map_err(|_| HttpError::NotUtf8)?;
    Ok(Request { head, body })
}

/// Read the request line and header block.
fn read_head<R: BufRead>(reader: &mut R) -> Result<Head, HttpError> {
    let mut consumed = 0usize;
    let mut line = String::new();
    read_line(reader, &mut line, &mut consumed)?;
    if line.is_empty() {
        return Err(HttpError::Incomplete);
    }
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(HttpError::Malformed)?.to_owned();
    let target = parts.next().ok_or(HttpError::Malformed)?;
    let version = parts.next().ok_or(HttpError::Malformed)?;
    if !version.starts_with("HTTP/1.") || method.is_empty() || target.is_empty() {
        return Err(HttpError::Malformed);
    }
    // The query string is dropped rather than parsed. Nothing this service
    // accepts belongs in a URL: a query string reaches access logs, browser
    // history and referrer headers, and a document does not go in any of those.
    let path = target
        .split('?')
        .next()
        .unwrap_or(target)
        .trim_end_matches('/')
        .to_owned();
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };

    let mut headers = Vec::new();
    loop {
        line.clear();
        read_line(reader, &mut line, &mut consumed)?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(Head {
        method,
        path,
        headers,
    })
}

/// Read one CRLF-or-LF terminated line, enforcing the header-block ceiling.
fn read_line<R: BufRead>(
    reader: &mut R,
    line: &mut String,
    consumed: &mut usize,
) -> Result<(), HttpError> {
    line.clear();
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return Err(HttpError::Io),
        }
        *consumed += 1;
        if *consumed > MAX_HEADER_BYTES {
            return Err(HttpError::HeadersTooLarge);
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
    }
    while bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    // Header bytes are ASCII by specification; anything else is a malformed
    // request rather than something to transcode.
    let decoded = String::from_utf8(bytes).map_err(|_| HttpError::Malformed)?;
    line.push_str(&decoded);
    Ok(())
}

/// Write one JSON response and close.
///
/// `Connection: close` on every response, unconditionally. It is the honest
/// header for a server that does not implement keep-alive, and a server that
/// claims persistence it does not have desynchronises the client on the second
/// request.
///
/// # Errors
///
/// The underlying write failure, which the caller logs as a count and drops.
pub fn write_response<W: Write>(writer: &mut W, status: u16, body: &str) -> std::io::Result<()> {
    let reason = reason_phrase(status);
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         \r\n",
        body.len()
    )?;
    writer.write_all(body.as_bytes())?;
    writer.flush()
}

/// The reason phrase for the statuses this service emits.
const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(wire: &str) -> Result<Request, HttpError> {
        read_request(&mut Cursor::new(wire.as_bytes().to_vec()))
    }

    #[test]
    fn a_post_with_a_body_parses() {
        let request = parse(
            "POST /analyze HTTP/1.1\r\n\
             Host: 127.0.0.1:8787\r\n\
             Content-Length: 9\r\n\
             \r\n\
             {\"a\": 1}\n",
        )
        .expect("parse");
        assert_eq!(request.head.method, "POST");
        assert_eq!(request.head.path, "/analyze");
        assert_eq!(request.head.header("host"), Some("127.0.0.1:8787"));
        assert_eq!(request.body, "{\"a\": 1}\n");
    }

    #[test]
    fn header_names_are_matched_case_insensitively() {
        let request = parse("GET /health HTTP/1.1\r\nCoNtEnT-LeNgTh: 0\r\n\r\n").expect("parse");
        assert_eq!(request.head.header("content-length"), Some("0"));
    }

    #[test]
    fn a_query_string_is_discarded_rather_than_parsed() {
        // Nothing this service accepts belongs in a URL, and a URL reaches
        // access logs. The router must never see one.
        let request = parse("GET /entities?class=direct HTTP/1.1\r\n\r\n").expect("parse");
        assert_eq!(request.head.path, "/entities");
    }

    #[test]
    fn a_trailing_slash_addresses_the_same_route() {
        assert_eq!(
            parse("GET /health/ HTTP/1.1\r\n\r\n")
                .expect("parse")
                .head
                .path,
            "/health"
        );
        assert_eq!(
            parse("GET / HTTP/1.1\r\n\r\n").expect("parse").head.path,
            "/"
        );
    }

    #[test]
    fn a_bearer_credential_is_extracted_and_trimmed() {
        let request =
            parse("GET /health HTTP/1.1\r\nAuthorization: Bearer  abc123 \r\n\r\n").expect("parse");
        assert_eq!(request.head.bearer(), Some("abc123"));
        let bare = parse("GET /health HTTP/1.1\r\n\r\n").expect("parse");
        assert_eq!(bare.head.bearer(), None);
    }

    #[test]
    fn a_body_with_no_content_length_is_refused_rather_than_guessed_at() {
        assert_eq!(
            parse("POST /analyze HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                .err(),
            Some(HttpError::UnframedBody),
            "reading until close and calling that the body is a smuggling primitive"
        );
    }

    #[test]
    fn an_oversized_body_is_refused_before_it_is_buffered() {
        let wire = format!(
            "POST /analyze HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        // The declared length alone is enough to refuse: no byte of the body is
        // read, so a hostile declaration costs nothing to reject.
        assert_eq!(parse(&wire).err(), Some(HttpError::BodyTooLarge));
    }

    #[test]
    fn an_oversized_header_block_is_refused() {
        let mut wire = String::from("GET /health HTTP/1.1\r\n");
        while wire.len() < MAX_HEADER_BYTES + 64 {
            wire.push_str("X-Padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        wire.push_str("\r\n");
        assert_eq!(parse(&wire).err(), Some(HttpError::HeadersTooLarge));
    }

    #[test]
    fn a_non_http_request_is_rejected() {
        assert_eq!(
            parse("hello there\r\n\r\n").err(),
            Some(HttpError::Malformed)
        );
        assert_eq!(parse("").err(), Some(HttpError::Incomplete));
    }

    #[test]
    fn a_non_utf8_body_is_rejected_rather_than_lossily_decoded() {
        // Lossy decoding would silently change the byte offsets of every span
        // after the replacement character, which is a correctness failure in a
        // masking pipeline and not merely an encoding nicety.
        let mut wire = b"POST /analyze HTTP/1.1\r\nContent-Length: 2\r\n\r\n".to_vec();
        wire.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(
            read_request(&mut Cursor::new(wire)).err(),
            Some(HttpError::NotUtf8)
        );
    }

    #[test]
    fn no_error_variant_can_carry_a_fragment_of_the_request() {
        // I4 at the type level: every variant is a unit variant, so there is no
        // field a document byte could travel in.
        for error in [
            HttpError::Incomplete,
            HttpError::Malformed,
            HttpError::HeadersTooLarge,
            HttpError::BodyTooLarge,
            HttpError::UnframedBody,
            HttpError::NotUtf8,
            HttpError::Io,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(error.status() >= 400);
        }
    }

    #[test]
    fn a_response_declares_its_length_and_closes() {
        let mut out = Vec::new();
        write_response(&mut out, 200, "{\"ok\":true}").expect("write");
        let wire = String::from_utf8(out).expect("utf8");
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("Content-Length: 11\r\n"));
        assert!(wire.contains("Connection: close\r\n"));
        assert!(wire.contains("Cache-Control: no-store\r\n"));
        assert!(wire.ends_with("\r\n\r\n{\"ok\":true}"));
    }

    #[test]
    fn a_response_length_counts_bytes_and_not_characters() {
        // Turkish is multi-byte. A Content-Length computed from a character
        // count truncates the response inside a letter, which is the same class
        // of bug as a span built from char indices.
        let body = "{\"label\":\"Şükrü\"}";
        let mut out = Vec::new();
        write_response(&mut out, 200, body).expect("write");
        let wire = String::from_utf8(out).expect("utf8");
        assert!(wire.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(body.len() > body.chars().count());
    }
}
