//! Structured stderr logging that cannot carry PHI.
//!
//! # The rule, and how it is made structural
//!
//! I4 says no request or response text may reach a log. Restating that as "be careful" would
//! last exactly until the first hard bug. So this module does not accept text at all: an
//! [`Event`] is built from an operation name, entity labels, byte offsets and counts, and there
//! is no field, method or escape hatch on it that takes a document, a model response, a
//! surrogate value or a session handle.
//!
//! A session handle is excluded for a reason worth stating separately, because it is not PHI
//! and the instinct is to log it as a correlation id. A handle is a bearer capability over a
//! span map. Logging it puts a live credential for a table of real patient identifiers into
//! stderr, then into a log file, then into a log aggregator. [`crate::session::Session`] carries
//! a sequence number for exactly this purpose: it correlates a `deidentify` with the
//! `reidentify` that follows it and grants nothing.
//!
//! # Why stderr and never stdout
//!
//! stdout IS the JSON-RPC transport. A stray `println!` does not merely leak, it corrupts the
//! protocol frame and desynchronises the client. Everything diagnostic goes to stderr.

use std::io::Write;

use deid_tr_core::EntityLabel;

/// One line of diagnostics.
///
/// Deliberately not `Display` over arbitrary data: every constructor takes numbers and closed
/// vocabularies, so there is no path from a document to a log line.
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

    /// Attach a count, a length, or an offset.
    #[must_use]
    pub fn count(mut self, key: &'static str, value: usize) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }

    /// Attach the session correlation number. NOT the handle -- see the module header.
    #[must_use]
    pub fn sequence(self, value: u64) -> Self {
        self.count("session_seq", usize::try_from(value).unwrap_or(usize::MAX))
    }

    /// Attach a value from a closed vocabulary: a tier, an outcome, a defect class.
    ///
    /// `&'static str` is the guardrail. A `&str` parameter would accept a slice of the
    /// document; a `'static` one can only be a literal compiled into the binary.
    #[must_use]
    pub fn tag(mut self, key: &'static str, value: &'static str) -> Self {
        self.fields.push((key, value.to_owned()));
        self
    }

    /// Attach the histogram of entity labels that were masked.
    ///
    /// Labels are schema metadata -- `TCKN`, `PATIENT_NAME` -- and say what KIND of identifier
    /// was found, never which one. That is precisely the distinction I4 draws.
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
pub struct Telemetry {
    sink: Box<dyn Write + Send>,
    enabled: bool,
}

impl Telemetry {
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

    /// Discard everything. Used by tests that assert on other channels.
    #[must_use]
    pub fn silent() -> Self {
        Self::new(Box::new(std::io::sink()), false)
    }

    /// Emit one event.
    ///
    /// I/O failure is swallowed. A gateway that dies because its log pipe closed is a gateway
    /// that drops a clinician's request over a diagnostic, and the diagnostic is the less
    /// important of the two.
    pub fn emit(&mut self, event: &Event) {
        if !self.enabled {
            return;
        }
        let mut line = String::from("deid-mcp op=");
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

    /// Emit a plain operational notice: startup, shutdown, refusal.
    pub fn notice(&mut self, message: &'static str) {
        let _ = writeln!(self.sink, "deid-mcp {message}");
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
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
        }
    }

    #[test]
    fn an_event_renders_as_key_value_pairs() {
        let captured = Captured::default();
        let mut log = Telemetry::new(Box::new(captured.clone()), true);
        log.emit(
            &Event::new("deidentify")
                .tag("tier", "safe_harbor")
                .count("source_bytes", 128)
                .count("masked_spans", 3)
                .sequence(7)
                .labels(&[(EntityLabel::Tckn, 1), (EntityLabel::Phone, 2)]),
        );
        let line = captured.text();
        assert!(line.starts_with("deid-mcp op=deidentify"));
        assert!(line.contains("tier=safe_harbor"));
        assert!(line.contains("masked_spans=3"));
        assert!(line.contains("session_seq=7"));
        assert!(line.contains("labels=TCKN:1,PHONE:2"));
    }

    #[test]
    fn a_disabled_sink_writes_nothing() {
        let captured = Captured::default();
        let mut log = Telemetry::new(Box::new(captured.clone()), false);
        log.emit(&Event::new("deidentify").count("source_bytes", 1));
        assert!(captured.text().is_empty());
    }
}
