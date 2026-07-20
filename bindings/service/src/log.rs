//! Structured stderr logging that cannot carry document text.
//!
//! # The rule, made structural
//!
//! I4 says no request or response text reaches a log. Restating that as "be
//! careful" lasts until the first hard bug, so this module does not ACCEPT text:
//! an [`Event`] is built from an operation name, a status, byte offsets, entity
//! labels and counts, and there is no field, method or escape hatch on it that
//! takes a document, a surrogate value, a session handle or a bearer token.
//!
//! Three things are excluded that the instinct is to log, each for its own
//! reason:
//!
//! * **The session handle.** It is a bearer capability over a span map. Logging
//!   it puts a live credential for a table of real patient identifiers into
//!   stderr, then a log file, then a log aggregator.
//!   [`crate::session::Session::sequence`] exists to correlate a `deidentify`
//!   with its `reidentify` while granting nothing.
//! * **The request path's query string.** [`crate::http`] discards it before the
//!   router sees it, so there is nothing here to omit.
//! * **The peer address.** An exposed deployment's client list is a deployment
//!   topology, and this process has no use for it. Refusals are counted, not
//!   attributed.
//!
//! # Why stderr
//!
//! stdout is not a transport here -- the responses go to sockets -- but stderr
//! stays the diagnostic channel anyway, so that redirecting one stream never
//! captures the other.

use std::io::Write;

use deid_tr_core::EntityLabel;

/// One line of diagnostics.
pub struct Event {
    operation: &'static str,
    fields: Vec<(&'static str, String)>,
}

impl Event {
    /// Begin an event for a named operation.
    #[must_use]
    pub fn new(operation: &'static str) -> Self {
        Self {
            operation,
            fields: Vec::new(),
        }
    }

    /// Attach a count, a length, a byte offset or a status code.
    #[must_use]
    pub fn count(mut self, key: &'static str, value: usize) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }

    /// Attach a millisecond duration.
    #[must_use]
    pub fn millis(self, value: u128) -> Self {
        self.count("ms", usize::try_from(value).unwrap_or(usize::MAX))
    }

    /// Attach the session correlation number. NOT the handle.
    #[must_use]
    pub fn sequence(self, value: u64) -> Self {
        self.count("session_seq", usize::try_from(value).unwrap_or(usize::MAX))
    }

    /// Attach a value from a CLOSED vocabulary: a route, a tier, an outcome.
    ///
    /// `&'static str` is the guardrail, not a convenience. A `&str` parameter
    /// would accept a slice of the document; a `'static` one can only be a
    /// literal compiled into the binary. This is why routes are logged from a
    /// match on the parsed path rather than from the path string itself -- an
    /// unrouted request logs `route=unmatched`, and the URL it asked for is
    /// never written down.
    #[must_use]
    pub fn tag(mut self, key: &'static str, value: &'static str) -> Self {
        self.fields.push((key, value.to_owned()));
        self
    }

    /// Attach the histogram of entity labels that were masked.
    ///
    /// Labels are schema metadata -- `TCKN`, `PATIENT_NAME` -- and say what KIND
    /// of identifier was found, never which one. That is precisely the
    /// distinction I4 draws.
    #[must_use]
    pub fn labels(mut self, histogram: &[(EntityLabel, usize)]) -> Self {
        let rendered = histogram
            .iter()
            .map(|(label, n)| format!("{}:{n}", label.as_str()))
            .collect::<Vec<_>>()
            .join(",");
        self.fields.push(("labels", rendered));
        self
    }
}

/// The diagnostics sink.
pub struct Log {
    sink: Box<dyn Write + Send>,
    enabled: bool,
}

impl Log {
    /// Log to the given sink.
    #[must_use]
    pub fn new(sink: Box<dyn Write + Send>, enabled: bool) -> Self {
        Self { sink, enabled }
    }

    /// Log to stderr.
    #[must_use]
    pub fn stderr(enabled: bool) -> Self {
        Self::new(Box::new(std::io::stderr()), enabled)
    }

    /// Discard everything.
    #[must_use]
    pub fn silent() -> Self {
        Self::new(Box::new(std::io::sink()), false)
    }

    /// Emit one event.
    ///
    /// I/O failure is swallowed. A service that dies because its log pipe closed
    /// drops a clinician's request over a diagnostic, and the diagnostic is the
    /// less important of the two.
    pub fn emit(&mut self, event: &Event) {
        if !self.enabled {
            return;
        }
        let mut line = String::from("deid-serve op=");
        line.push_str(event.operation);
        for (key, value) in &event.fields {
            line.push(' ');
            line.push_str(key);
            line.push('=');
            line.push_str(value);
        }
        let _ = writeln!(self.sink, "{line}");
        let _ = self.sink.flush();
    }

    /// Emit a plain operational notice: startup, exposure warning, shutdown.
    ///
    /// `&'static str` for the same reason [`Event::tag`] takes one.
    pub fn notice(&mut self, message: &str) {
        let _ = writeln!(self.sink, "deid-serve: {message}");
        let _ = self.sink.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
        }
    }

    #[test]
    fn an_event_renders_as_key_value_pairs() {
        let captured = Captured::default();
        let mut log = Log::new(Box::new(captured.clone()), true);
        log.emit(
            &Event::new("deidentify")
                .tag("route", "/deidentify")
                .tag("tier", "safe_harbor")
                .count("status", 200)
                .count("source_bytes", 128)
                .count("masked_spans", 3)
                .sequence(7)
                .labels(&[(EntityLabel::Tckn, 1), (EntityLabel::Phone, 2)]),
        );
        let line = captured.contents();
        assert!(line.starts_with("deid-serve op=deidentify"));
        assert!(line.contains("route=/deidentify"));
        assert!(line.contains("status=200"));
        assert!(line.contains("masked_spans=3"));
        assert!(line.contains("session_seq=7"));
        assert!(line.contains("labels=TCKN:1,PHONE:2"));
    }

    #[test]
    fn a_disabled_sink_writes_nothing() {
        let captured = Captured::default();
        let mut log = Log::new(Box::new(captured.clone()), false);
        log.emit(&Event::new("deidentify").count("source_bytes", 1));
        assert!(captured.contents().is_empty());
    }
}
