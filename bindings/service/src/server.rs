//! The accept loop, the bearer check, and the one place a socket is created.
//!
//! # One connection at a time
//!
//! The loop is single-threaded and every connection carries read and write
//! deadlines. That is a deliberate trade and not an oversight.
//!
//! What it costs: throughput. A second caller waits for the first, and a caller
//! that stalls mid-request holds the service for up to [`IO_TIMEOUT`].
//!
//! What it buys: this process holds span maps, which are the table from each
//! surrogate back to a real patient identifier. A thread pool would put that
//! store behind a lock, and a lock is a place where a poisoning panic, a
//! deadlock, or a subtle ordering bug becomes an availability failure in a
//! clinical tool -- or, worse, a place where one caller's session can be
//! observed by another. `deid-serve` is a LOCAL service for one workstation or
//! one batch job. It is not a shared cluster endpoint, and building it as if it
//! were would mean carrying concurrency risk to serve a load that does not
//! exist.
//!
//! # Where the socket is
//!
//! Here, and nowhere else in the crate. The address is not a parameter of this
//! module: it arrives as a [`Listen`], which can only be produced by
//! [`crate::bind::plan`], which refuses every all-interfaces address
//! unconditionally and every other non-loopback address without `--expose`, a
//! bearer token and a startup warning together.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::api::{ApiError, Service, ServiceConfig};
use crate::bind::{Listen, Token};
use crate::http::{self, HttpError};
use crate::log::{Event, Log};

/// How long one connection may stall before it is dropped.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The body returned when a bearer token is required and not presented.
fn unauthorized() -> serde_json::Value {
    serde_json::json!({
        "error": {
            "code": "unauthorized",
            "message": "this deid-serve instance requires a bearer token: send Authorization: Bearer <token>",
        }
    })
}

/// Create the listening socket for an approved plan.
///
/// THE ONLY `TcpListener::bind` IN THE CRATE, and it takes a [`Listen`] rather
/// than an address. A caller cannot reach this function with an address of their
/// own choosing, because a `Listen` can only be produced by
/// [`crate::bind::plan`].
///
/// # Errors
///
/// The bind failure: the port is in use, or the address is not one this machine
/// holds.
pub fn bind_listener(listen: &Listen) -> std::io::Result<TcpListener> {
    TcpListener::bind(listen.addr)
}

/// The listening service.
pub struct Server {
    service: Service,
    token: Option<Token>,
    log: Log,
}

impl Server {
    /// Build a server around an approved listener configuration.
    ///
    /// # Errors
    ///
    /// Whatever [`Service::new`] returns, which is the entropy failure.
    pub fn new(listen: &Listen, config: ServiceConfig, log: Log) -> Result<Self, ApiError> {
        Ok(Self {
            service: Service::new(config)?,
            token: listen.token.clone(),
            log,
        })
    }

    /// Serve until the listener fails.
    ///
    /// # Errors
    ///
    /// The bind failure, which is what an operator needs to see: the port is in
    /// use, or the address is not one this machine holds.
    pub fn serve(&mut self, listen: &Listen) -> std::io::Result<()> {
        let listener = bind_listener(listen)?;
        // The BOUND address, not the requested one. They differ when the
        // operator asked for port 0, and an operator who reads the requested
        // port from a log and then cannot connect has been told a lie by their
        // own tooling.
        let bound = listener.local_addr()?;
        // The scheme is spelled out in words rather than as a URL prefix. This
        // binary terminates no TLS, and the repository's egress guard reads any
        // scheme-prefixed non-loopback host in source as an exfiltration risk --
        // correctly, since it cannot know this one is an address we BIND rather
        // than one we connect to.
        self.log
            .notice(&format!("listening on {bound}, plain HTTP, no TLS"));
        self.serve_listener(&listener);
        Ok(())
    }

    /// Serve on an already-bound listener until it fails.
    ///
    /// Split out from [`Server::serve`] so an integration test can bind port 0,
    /// learn the port the kernel chose, and then drive the real socket path.
    /// Discovering a free port by binding one, dropping it and hoping is a race,
    /// and a racy test of the one invariant this crate exists to hold is worse
    /// than no test.
    pub fn serve_listener(&mut self, listener: &TcpListener) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => self.serve_one(stream),
                // A failed accept is one client, not the service. Counted and
                // continued, because exiting would let any local process kill a
                // clinician's batch by opening and dropping a connection.
                Err(_) => self
                    .log
                    .emit(&Event::new("accept").tag("outcome", "failed")),
            }
        }
    }

    /// Handle one accepted connection.
    fn serve_one(&mut self, stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let Ok(writer) = stream.try_clone() else {
            self.log
                .emit(&Event::new("connection").tag("outcome", "clone_failed"));
            return;
        };
        let mut reader = BufReader::new(stream);
        self.exchange(&mut reader, writer);
    }

    /// Read one request, produce one response, log one line.
    ///
    /// Generic over the streams so the whole exchange -- framing, the bearer
    /// check, the status, the log line -- is testable without a socket. The
    /// socket-bearing path above is then three lines of plumbing rather than
    /// three lines of untested policy.
    pub fn exchange<R: std::io::BufRead, W: Write>(&mut self, reader: &mut R, mut writer: W) {
        let began = Instant::now();
        let request = match http::read_request(reader) {
            Ok(request) => request,
            Err(error) => {
                self.respond(
                    &mut writer,
                    error.status(),
                    &framing_error(error),
                    |event| event.tag("route", "unread"),
                );
                return;
            }
        };

        // THE BEARER CHECK, before dispatch and before any route is matched, so
        // an unauthenticated caller cannot learn which endpoints exist. /health
        // is not exempt: an unauthenticated health endpoint on an exposed
        // service publishes the tier, the layer inventory and the session
        // ceiling to anyone who can route to it.
        if let Some(token) = &self.token {
            let presented = request.head.bearer().unwrap_or("");
            if !token.verify(presented) {
                self.respond(&mut writer, 401, &unauthorized(), |event| {
                    event.tag("route", "unauthorized")
                });
                return;
            }
        }

        let reply = self
            .service
            .handle(&request.head.method, &request.head.path, &request.body);
        let route = reply.route;
        let sequence = reply.sequence;
        let labels = reply.labels.clone();
        let source_bytes = request.body.len();
        let status = reply.status;
        self.respond(&mut writer, status, &reply.body, move |mut event| {
            event = event
                .tag("route", route)
                .count("source_bytes", source_bytes)
                .millis(began.elapsed().as_millis());
            if let Some(sequence) = sequence {
                event = event.sequence(sequence);
            }
            if labels.is_empty() {
                event
            } else {
                event.labels(&labels)
            }
        });
    }

    /// Write a response and log it.
    ///
    /// The log line is built by the caller's closure from offsets, counts,
    /// labels and closed vocabularies only. There is no parameter here that
    /// accepts a fragment of the request or of the response (I4).
    fn respond<W: Write>(
        &mut self,
        writer: &mut W,
        status: u16,
        body: &serde_json::Value,
        decorate: impl FnOnce(Event) -> Event,
    ) {
        let rendered = body.to_string();
        let outcome = if http::write_response(writer, status, &rendered).is_ok() {
            "sent"
        } else {
            "write_failed"
        };
        let event = decorate(Event::new("request"))
            .count("status", usize::from(status))
            .count("response_bytes", rendered.len())
            .tag("outcome", outcome);
        self.log.emit(&event);
    }

    /// Release every live session. Called at shutdown.
    pub fn shutdown(&mut self) -> usize {
        self.service.shutdown()
    }
}

/// The body for a request that could not be framed.
///
/// Reports the CLASS of the framing failure and never a byte of what arrived: a
/// malformed request from a clinical system may well contain a fragment of a
/// note.
fn framing_error(error: HttpError) -> serde_json::Value {
    serde_json::json!({
        "error": { "code": "malformed_request", "message": error.to_string() }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::{plan, DEFAULT_PORT, MIN_TOKEN_LEN};
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback_server() -> (Listen, Server) {
        let listen = plan(crate::bind::default_host(), DEFAULT_PORT, false, None).expect("plan");
        let server = Server::new(&listen, ServiceConfig::default(), Log::silent()).expect("server");
        (listen, server)
    }

    fn exchange(server: &mut Server, wire: &str) -> String {
        let mut reader = Cursor::new(wire.as_bytes().to_vec());
        let mut out = Vec::new();
        server.exchange(&mut reader, &mut out);
        String::from_utf8(out).expect("utf8 response")
    }

    fn status_of(response: &str) -> u16 {
        response
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status line")
    }

    fn body_of(response: &str) -> serde_json::Value {
        let body = response.split("\r\n\r\n").nth(1).expect("body");
        serde_json::from_str(body).expect("json body")
    }

    #[test]
    fn a_health_request_is_served_over_the_wire() {
        let (_, mut server) = loopback_server();
        let response = exchange(
            &mut server,
            "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(status_of(&response), 200);
        assert_eq!(body_of(&response)["status"], serde_json::json!("ok"));
    }

    #[test]
    fn a_post_with_a_body_reaches_the_handler() {
        let (_, mut server) = loopback_server();
        let body = "{\"text\":\"carcinoma'lı hasta\"}";
        let response = exchange(
            &mut server,
            &format!(
                "POST /deidentify HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert_eq!(status_of(&response), 200);
        assert!(body_of(&response)["session"].is_string());
    }

    #[test]
    fn a_malformed_request_is_answered_without_quoting_it() {
        let (_, mut server) = loopback_server();
        let response = exchange(&mut server, "GARBLED /Ayşe HTTP/9\r\n\r\n");
        assert_eq!(status_of(&response), 400);
        assert!(
            !response.contains("Ayşe"),
            "the response quoted the request"
        );
    }

    #[test]
    fn a_configured_token_is_enforced_on_every_route_including_health() {
        // An unauthenticated /health on an exposed service publishes the tier,
        // the layer inventory and the session ceiling to anyone who can route
        // to it, so there is no exemption.
        // Cycles the alphabet: clears the length floor AND the distinct-character
        // floor. A single repeated character clears only the first, and the bind
        // gate now refuses it -- see bind::tests::a_long_but_repetitive_token_is_refused.
        let secret: String = (0..MIN_TOKEN_LEN)
            .map(|index| char::from(b'a' + u8::try_from(index % 26).unwrap_or(0)))
            .collect();
        let listen = plan(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            DEFAULT_PORT,
            true,
            Some(&secret),
        )
        .expect("plan");
        let mut server = Server::new(
            &listen,
            ServiceConfig {
                auth_required: true,
                exposed: true,
                ..ServiceConfig::default()
            },
            Log::silent(),
        )
        .expect("server");

        for path in ["/health", "/entities", "/analyze"] {
            let response = exchange(
                &mut server,
                &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            );
            assert_eq!(
                status_of(&response),
                401,
                "{path} was served unauthenticated"
            );
            assert_eq!(
                body_of(&response)["error"]["code"],
                serde_json::json!("unauthorized")
            );
        }

        let response = exchange(
            &mut server,
            &format!("GET /health HTTP/1.1\r\nAuthorization: Bearer {secret}\r\n\r\n"),
        );
        assert_eq!(status_of(&response), 200);
    }

    #[test]
    fn a_wrong_token_is_refused_and_the_response_does_not_reveal_the_right_one() {
        // Cycles the alphabet: clears the length floor AND the distinct-character
        // floor. A single repeated character clears only the first, and the bind
        // gate now refuses it -- see bind::tests::a_long_but_repetitive_token_is_refused.
        let secret: String = (0..MIN_TOKEN_LEN)
            .map(|index| char::from(b'a' + u8::try_from(index % 26).unwrap_or(0)))
            .collect();
        let listen = plan(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            DEFAULT_PORT,
            true,
            Some(&secret),
        )
        .expect("plan");
        let mut server =
            Server::new(&listen, ServiceConfig::default(), Log::silent()).expect("server");
        let response = exchange(
            &mut server,
            "GET /health HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n",
        );
        assert_eq!(status_of(&response), 401);
        assert!(!response.contains(&secret));
    }

    #[test]
    fn a_loopback_server_with_no_token_serves_without_authorization() {
        let (_, mut server) = loopback_server();
        let response = exchange(&mut server, "GET /health HTTP/1.1\r\n\r\n");
        assert_eq!(status_of(&response), 200);
    }

    #[test]
    fn shutdown_releases_every_session() {
        let (_, mut server) = loopback_server();
        let body = "{\"text\":\"TCKN 12345678951 gecersiz.\"}";
        exchange(
            &mut server,
            &format!(
                "POST /deidentify HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert_eq!(server.shutdown(), 1);
        assert_eq!(server.shutdown(), 0);
    }
}
