//! In-memory span-map storage, with expiry and best-effort zeroisation.
//!
//! # What is stored, and why it is the most sensitive thing here
//!
//! A span map is, for each masked entity, the surrogate that appears in the
//! de-identified output and the ORIGINAL identifier it replaced. It is strictly
//! more sensitive than the note it came from: it is the note's PHI with the
//! narrative stripped away and an index attached. Everything below follows from
//! that.
//!
//! * Memory only. There is no path in this crate that writes a session to a
//!   file, and no serialisation of a [`Restoration`] exists.
//! * Never logged. `Debug` on the store prints counts; `Debug` on a stored
//!   identifier prints `<redacted>`.
//! * Expiring, on a deadline from CREATION rather than from last use. A sliding
//!   window lets a chatty client hold a span map open forever, which is the
//!   failure the deadline exists to bound.
//! * Zeroised. The buffer holding the identifier is overwritten before it is
//!   freed.
//!
//! # Why this is not `bindings/mcp`'s store
//!
//! The MCP gateway stores a placeholder and the identifier it stands for,
//! because its restoration is a SEARCH through a cloud model's free-text answer.
//! This service restores by OFFSET: `/reidentify` reproduces the exact input
//! document from the masked output, so a session has to carry the masked text
//! and both offset systems. Sharing one type would have meant one of the two
//! carrying fields it does not use, and an unused field in a PHI store is a
//! field nobody maintains.
//!
//! # The limits of zeroisation, stated honestly
//!
//! [`Secret`] overwrites its heap buffer in `Drop`, without `unsafe`. It does
//! not erase copies the process made elsewhere: a `String` that reallocated
//! while growing left its old buffer behind, the kernel may have paged the
//! memory to swap, and the value passed through stack slots on the way in.
//! Zeroisation shrinks the window in which a core dump is a breach; it does not
//! close it. The deadline is the primary control and this is defence in depth.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use deid_tr_core::{Decision, DeidResult, EntityLabel};

/// The default session lifetime, in seconds.
///
/// Fifteen minutes: comfortably longer than a `deidentify` / inspect /
/// `reidentify` round trip at a desk, and far shorter than a working day.
pub const DEFAULT_TTL_SECONDS: u64 = 900;

/// The default ceiling on concurrently live sessions.
///
/// A ceiling rather than unbounded growth, because each live session pins a span
/// map in memory and an unbounded store is an unbounded quantity of resident PHI
/// reachable by a core dump. A full store REFUSES a new session rather than
/// evicting an old one: evicting would let any caller destroy another caller's
/// in-flight round trip by opening sessions in a loop.
pub const DEFAULT_MAX_SESSIONS: usize = 128;

/// Bytes of entropy in a session handle. 128 bits, treated as a bearer
/// capability over a span map rather than as a database key.
const HANDLE_BYTES: usize = 16;

/// Why a session operation failed.
///
/// One undifferentiated not-found, deliberately: see [`SessionStore::get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The handle is expired, released, or was never issued.
    #[error("no such session")]
    NotFound,
    /// The store is at its ceiling.
    #[error("the session store is full; retry after an existing session expires")]
    Full,
    /// The operating system would not produce entropy for a handle.
    #[error("the operating system entropy source is unavailable")]
    EntropyUnavailable,
}

/// A heap buffer holding an identifier, overwritten before it is freed.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Take ownership of an identifier.
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    /// Borrow the identifier for substitution.
    ///
    /// Falls back to the empty string rather than panicking on invalid UTF-8,
    /// which can only happen after `Drop` has already zeroed the buffer. A panic
    /// in a clinical tool prints a backtrace, and a backtrace is a log line.
    #[must_use]
    pub fn expose(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One masked entity, in both offset systems.
#[derive(Debug)]
pub struct Restoration {
    /// The schema label. Metadata, safe to report.
    pub label: EntityLabel,
    /// Inclusive byte offset in the ORIGINAL document.
    pub start: usize,
    /// Exclusive byte offset in the ORIGINAL document.
    pub end: usize,
    /// Inclusive byte offset in the MASKED document.
    ///
    /// Carried rather than recomputed, because a surrogate deliberately does not
    /// preserve the original's length: every replacement shifts everything after
    /// it, and no arithmetic on the input offsets recovers the output ones.
    pub output_start: usize,
    /// Exclusive byte offset in the MASKED document.
    pub output_end: usize,
    /// THE PHI.
    original: Secret,
}

/// A span map plus its deadline.
#[derive(Debug)]
pub struct Session {
    /// The de-identified document. Not PHI, which is the whole point of it.
    masked: String,
    entries: Vec<Restoration>,
    expires_at: Instant,
    /// A monotonically increasing number used in log lines INSTEAD of the
    /// handle. The handle is a live capability over a table of real patient
    /// identifiers; the sequence number correlates two log lines and grants
    /// nothing.
    sequence: u64,
}

impl Session {
    /// The restorations, in document order.
    #[must_use]
    pub fn entries(&self) -> &[Restoration] {
        &self.entries
    }

    /// The correlation id for logging. Never the handle.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// How many entities this span map can restore.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing was masked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Rebuild the original document from the masked one.
    ///
    /// BYTE-EXACT BY CONSTRUCTION, and the reason the output offsets are stored:
    /// the masked text is walked, each replacement is swapped for the identifier
    /// it stands for, and everything between is copied through unchanged. No
    /// searching, no re-detection, no arithmetic on the input offsets.
    ///
    /// `get` rather than indexing throughout: this method is infallible by
    /// contract, and a store corrupted by some future edit must degrade to a
    /// wrong string rather than to a panic in a clinical tool.
    #[must_use]
    pub fn restore(&self) -> String {
        let mut out = String::with_capacity(self.masked.len());
        let mut cursor = 0usize;
        for entry in &self.entries {
            let Some(between) = self.masked.get(cursor..entry.output_start) else {
                continue;
            };
            out.push_str(between);
            out.push_str(entry.original.expose());
            cursor = entry.output_end;
        }
        if let Some(tail) = self.masked.get(cursor..) {
            out.push_str(tail);
        }
        out
    }
}

/// Build the storable span map from a pipeline result.
///
/// KEPT SPANS ARE NOT STORED. L4 decided to leave those bytes alone, so their
/// output bytes ARE their original bytes and there is nothing to restore --
/// storing them would put an identifier-shaped string that was deliberately not
/// masked into the most sensitive structure in the process, for no gain.
#[must_use]
pub fn restorations(result: &DeidResult) -> Vec<Restoration> {
    result
        .span_map
        .iter()
        .filter(|mapped| mapped.decision == Decision::Mask)
        .map(|mapped| Restoration {
            label: mapped.span.label(),
            start: mapped.span.start(),
            end: mapped.span.end(),
            output_start: mapped.output_start,
            output_end: mapped.output_end,
            original: Secret::new(mapped.original()),
        })
        .collect()
}

/// The clock the store reads.
///
/// A trait so expiry can be tested by advancing time rather than by sleeping. A
/// test that proves a fifteen-minute TTL by waiting fifteen minutes is a test
/// that gets deleted.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real, monotonic clock.
///
/// `Instant` and not `SystemTime`: a deadline that can be defeated by moving the
/// system clock backwards is not a deadline.
#[derive(Debug, Clone, Copy, Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The live span maps, keyed by session handle.
pub struct SessionStore {
    sessions: HashMap<String, Session>,
    ttl: Duration,
    max_sessions: usize,
    next_sequence: u64,
    clock: Box<dyn Clock>,
}

impl fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither handles nor entries appear: handles are capabilities and
        // entries are PHI. Counts and configuration are the whole safe surface.
        f.debug_struct("SessionStore")
            .field("live", &self.sessions.len())
            .field("ttl_seconds", &self.ttl.as_secs())
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}

impl SessionStore {
    /// A store with the given retention policy and the real clock.
    #[must_use]
    pub fn new(ttl: Duration, max_sessions: usize) -> Self {
        Self::with_clock(ttl, max_sessions, Box::new(MonotonicClock))
    }

    /// A store reading a caller-supplied clock, for tests.
    #[must_use]
    pub fn with_clock(ttl: Duration, max_sessions: usize, clock: Box<dyn Clock>) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
            max_sessions,
            next_sequence: 1,
            clock,
        }
    }

    /// The configured retention window, for `/health`.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The configured ceiling, for `/health`.
    #[must_use]
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// How many sessions are live after expiring anything past its deadline.
    pub fn live(&mut self) -> usize {
        self.expire();
        self.sessions.len()
    }

    /// Store a span map and return its handle.
    ///
    /// # Errors
    ///
    /// [`SessionError::Full`] at the ceiling, [`SessionError::EntropyUnavailable`]
    /// when the OS will not produce a handle.
    pub fn insert(
        &mut self,
        masked: String,
        entries: Vec<Restoration>,
    ) -> Result<String, SessionError> {
        self.expire();
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::Full);
        }
        let handle = new_handle()?;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.sessions.insert(
            handle.clone(),
            Session {
                masked,
                entries,
                expires_at: self.clock.now() + self.ttl,
                sequence,
            },
        );
        Ok(handle)
    }

    /// Look a span map up, or fail with the one undifferentiated error.
    ///
    /// The sweep runs FIRST. Without it an expired session would still be found
    /// by the map lookup and the deadline would be advisory, which is the
    /// difference between a retention policy and a comment claiming there is
    /// one.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotFound`], for expired, released and invented handles
    /// alike. Distinguishing them would be an existence oracle over a table of
    /// real patient identifiers.
    pub fn get(&mut self, handle: &str) -> Result<&Session, SessionError> {
        self.expire();
        self.sessions.get(handle).ok_or(SessionError::NotFound)
    }

    /// Destroy a session now, zeroising its span map.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotFound`], on the same terms as [`SessionStore::get`].
    pub fn forget(&mut self, handle: &str) -> Result<usize, SessionError> {
        self.expire();
        let session = self.sessions.remove(handle).ok_or(SessionError::NotFound)?;
        let count = session.len();
        drop(session);
        Ok(count)
    }

    /// Drop every session past its deadline, returning how many were swept.
    ///
    /// `retain` drops the removed values in place, which runs `Secret::drop` and
    /// therefore zeroes each buffer.
    pub fn expire(&mut self) -> usize {
        let now = self.clock.now();
        let before = self.sessions.len();
        self.sessions.retain(|_, session| session.expires_at > now);
        before - self.sessions.len()
    }

    /// Destroy every session. Called at shutdown.
    pub fn clear(&mut self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        count
    }
}

/// A fresh 128-bit handle, lower-case hex.
fn new_handle() -> Result<String, SessionError> {
    let mut bytes = [0u8; HANDLE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| SessionError::EntropyUnavailable)?;
    Ok(hex(&bytes))
}

/// Lower-case hex, written out rather than pulled in as a dependency.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    struct FakeClock {
        origin: Instant,
        offset_millis: Arc<AtomicU64>,
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.origin + Duration::from_millis(self.offset_millis.load(Ordering::SeqCst))
        }
    }

    fn fake_clock() -> (Arc<AtomicU64>, Box<dyn Clock>) {
        let offset_millis = Arc::new(AtomicU64::new(0));
        let clock = FakeClock {
            origin: Instant::now(),
            offset_millis: Arc::clone(&offset_millis),
        };
        (offset_millis, Box::new(clock))
    }

    fn restoration(original: &str, output_start: usize, output_end: usize) -> Restoration {
        Restoration {
            label: EntityLabel::PatientName,
            start: 0,
            end: original.len(),
            output_start,
            output_end,
            original: Secret::new(original),
        }
    }

    #[test]
    fn a_stored_span_map_comes_back_under_its_handle() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(
                "Hasta [PATIENT_NAME].".to_owned(),
                vec![restoration("Ayşe Yılmaz", 6, 20)],
            )
            .expect("insert");
        let session = store.get(&handle).expect("lookup");
        assert_eq!(session.len(), 1);
        assert_eq!(session.entries()[0].original.expose(), "Ayşe Yılmaz");
    }

    #[test]
    fn restore_rebuilds_the_original_across_a_length_changing_replacement() {
        // The property /reidentify sells. The surrogate is deliberately a
        // different length from the identifier, so the only way the tail lands
        // correctly is by walking the OUTPUT offsets.
        let masked = "Hasta Zeynep Kara, TCKN [TCKN], taburcu.";
        let start = masked.find("[TCKN]").expect("fixture");
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(
                masked.to_owned(),
                // Checksum-INVALID by construction (I8): the trailing digit is
                // one off, so this string can never be a real national ID. The
                // test needs an opaque payload of the right shape, not a valid
                // identifier.
                vec![restoration("10000000147", start, start + "[TCKN]".len())],
            )
            .expect("insert");
        assert_eq!(
            store.get(&handle).expect("lookup").restore(),
            "Hasta Zeynep Kara, TCKN 10000000147, taburcu."
        );
    }

    #[test]
    fn restore_is_byte_exact_through_multibyte_turkish() {
        // Two replacements, with multi-byte letters before, between and after
        // them. A char-index bug anywhere in the walk corrupts this.
        let masked = "Şükrü [PATIENT_NAME] ile [CLINICIAN_NAME]'yi gördü.";
        let first = masked.find("[PATIENT_NAME]").expect("fixture");
        let second = masked.find("[CLINICIAN_NAME]").expect("fixture");
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(
                masked.to_owned(),
                vec![
                    restoration("Ayşe Yılmaz", first, first + "[PATIENT_NAME]".len()),
                    Restoration {
                        label: EntityLabel::ClinicianName,
                        start: 0,
                        end: 0,
                        output_start: second,
                        output_end: second + "[CLINICIAN_NAME]".len(),
                        original: Secret::new("Gökçe Öztürk"),
                    },
                ],
            )
            .expect("insert");
        assert_eq!(
            store.get(&handle).expect("lookup").restore(),
            "Şükrü Ayşe Yılmaz ile Gökçe Öztürk'yi gördü."
        );
    }

    #[test]
    fn a_session_with_nothing_masked_restores_the_document_unchanged() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(
                "carcinoma'lı hasta, MRI'da lezyon yok.".to_owned(),
                Vec::new(),
            )
            .expect("insert");
        assert_eq!(
            store.get(&handle).expect("lookup").restore(),
            "carcinoma'lı hasta, MRI'da lezyon yok."
        );
    }

    #[test]
    fn handles_are_unique_and_wide() {
        let mut store = SessionStore::new(Duration::from_secs(60), 64);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let handle = store.insert(String::new(), Vec::new()).expect("insert");
            assert_eq!(
                handle.len(),
                HANDLE_BYTES * 2,
                "handle is not 128 bits of hex"
            );
            assert!(seen.insert(handle), "the CSPRNG repeated a session handle");
        }
    }

    #[test]
    fn a_session_expires_and_is_then_indistinguishable_from_fiction() {
        let (offset_millis, clock) = fake_clock();
        let mut store = SessionStore::with_clock(Duration::from_secs(900), 8, clock);
        let handle = store
            .insert(
                "[PATIENT_NAME]".to_owned(),
                vec![restoration("Ayşe", 0, 14)],
            )
            .expect("insert");

        offset_millis.store(899_000, Ordering::SeqCst);
        assert!(store.get(&handle).is_ok(), "expired one second early");

        offset_millis.store(900_001, Ordering::SeqCst);
        let expired = store.get(&handle).expect_err("must be gone");
        let invented = store
            .get("00000000000000000000000000000000")
            .expect_err("fiction");
        assert_eq!(expired, SessionError::NotFound);
        assert_eq!(
            expired, invented,
            "an expired handle must be indistinguishable from one that never existed"
        );
        assert_eq!(store.live(), 0);
    }

    #[test]
    fn a_full_store_refuses_rather_than_evicting_a_live_session() {
        let mut store = SessionStore::new(Duration::from_secs(60), 2);
        let first = store.insert(String::new(), Vec::new()).expect("a");
        store.insert(String::new(), Vec::new()).expect("b");
        assert_eq!(
            store.insert(String::new(), Vec::new()).err(),
            Some(SessionError::Full)
        );
        assert!(
            store.get(&first).is_ok(),
            "a full store must not destroy an in-flight round trip"
        );
    }

    #[test]
    fn forget_destroys_one_session_and_leaves_the_others_alone() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let first = store
            .insert("a".to_owned(), vec![restoration("one", 0, 1)])
            .expect("a");
        let second = store
            .insert("b".to_owned(), vec![restoration("two", 0, 1)])
            .expect("b");
        assert_eq!(store.forget(&first).expect("forget"), 1);
        assert_eq!(store.get(&first).err(), Some(SessionError::NotFound));
        assert_eq!(store.get(&second).expect("survivor").len(), 1);
        assert_eq!(store.forget("deadbeef").err(), Some(SessionError::NotFound));
    }

    #[test]
    fn a_secret_zeroes_its_buffer_before_it_is_freed() {
        // Reading freed memory would be undefined behaviour and needs `unsafe`,
        // which this crate does not have. The observable statement is that
        // `fill(0)` is what Drop does and that the buffer is the one holding the
        // identifier.
        let mut secret = Secret::new("Ayşe Yılmaz");
        assert_eq!(secret.expose(), "Ayşe Yılmaz");
        secret.0.fill(0);
        assert!(secret.0.iter().all(|byte| *byte == 0));
        assert_eq!(secret.expose(), "\0".repeat(13));
    }

    #[test]
    fn debug_never_prints_an_identifier_or_a_handle() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(
                "[PATIENT_NAME]".to_owned(),
                vec![restoration("Ayşe Yılmaz", 0, 14)],
            )
            .expect("insert");
        let rendered = format!("{store:?}");
        assert!(
            !rendered.contains("Ayşe"),
            "Debug on the store egressed PHI"
        );
        assert!(
            !rendered.contains(&handle),
            "Debug on the store egressed a live capability"
        );
        assert!(rendered.contains("live: 1"));

        let session = store.get(&handle).expect("lookup");
        let rendered = format!("{:?}", session.entries());
        assert!(!rendered.contains("Ayşe"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn clear_destroys_everything() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        store.insert(String::new(), Vec::new()).expect("a");
        store.insert(String::new(), Vec::new()).expect("b");
        assert_eq!(store.clear(), 2);
        assert_eq!(store.live(), 0);
    }
}
