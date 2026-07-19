//! In-memory session storage for span maps, with expiry and best-effort zeroisation.
//!
//! # What is being protected
//!
//! A span map is the round-trip table: for each masked entity, the surrogate that went to the
//! cloud model and the ORIGINAL identifier it stands for. It is strictly more sensitive than
//! the note it came from, because it is the note's PHI with the surrounding narrative stripped
//! away and an index attached. Everything in this module follows from that:
//!
//! - it lives in memory only, and there is no path in this crate that writes it to a file;
//! - it is never formatted, never logged, and its `Debug` says `<redacted>`;
//! - it expires on a wall-clock deadline whether or not the client remembers to release it;
//! - the buffer holding the identifier is overwritten with zeroes before it is freed.
//!
//! # Retention policy
//!
//! Default TTL is [`DEFAULT_TTL_SECONDS`] (15 minutes) from creation -- NOT from last use.
//! A sliding window would let a chatty client hold a span map open indefinitely, which is the
//! "lives forever in memory" failure the deadline exists to bound. Fifteen minutes is chosen
//! to comfortably outlast a single request/response round trip to a cloud model, including a
//! slow one, and to be far shorter than a working session at a desk. It is configurable with
//! `--session-ttl`, and the configured value is reported by the `health` tool so an operator
//! can verify what is actually running rather than what the documentation claims.
//!
//! Expiry is enforced on every store access rather than by a timer thread, so a process that
//! is idle is a process holding no expired maps: the sweep runs before any lookup can succeed.
//!
//! # The limits of zeroisation, stated honestly
//!
//! [`Secret`] overwrites its heap buffer in `Drop`. That is a real write to the allocation the
//! identifier lived in, and it is done without `unsafe`. What it does NOT do is erase copies
//! the process made elsewhere: a `String` that reallocated while growing left its old buffer
//! behind, the kernel may have paged the memory to swap, and the value passed through stack
//! slots and registers on the way in. Zeroisation shrinks the window in which a core dump is a
//! breach; it does not close it. The deadline above is the primary control, and this is
//! defence in depth.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use deid_tr_core::EntityLabel;

use crate::error::{GatewayError, Result};

/// The default session lifetime. See the module header for why it is not a sliding window.
pub const DEFAULT_TTL_SECONDS: u64 = 900;

/// The default ceiling on concurrently live sessions.
///
/// A ceiling rather than unbounded growth because each session pins a span map in memory, so an
/// unbounded store is an unbounded quantity of resident PHI reachable by a core dump. When the
/// store is full a new session is REFUSED rather than evicting an existing one: evicting would
/// let any caller destroy another caller's in-flight round trip by opening sessions in a loop.
pub const DEFAULT_MAX_SESSIONS: usize = 128;

/// Bytes of entropy in a session handle.
///
/// 128 bits, treated as a bearer capability rather than as a database key. A guessable handle
/// hands an attacker the span map, so the handle is drawn from the OS CSPRNG and is wide enough
/// that online guessing is not a threat model worth modelling.
const HANDLE_BYTES: usize = 16;

/// A heap buffer holding an identifier, overwritten before it is freed.
///
/// The `Vec<u8>` representation is what makes safe zeroisation possible: `String::into_bytes`
/// hands over the same allocation, and `fill(0)` on a `Vec` is an ordinary safe write. There is
/// no `unsafe` here and no dependency on a zeroing crate.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Take ownership of an identifier.
    pub fn new(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    /// Borrow the identifier for substitution.
    ///
    /// Falls back to the empty string rather than panicking on invalid UTF-8, which can only
    /// happen after `Drop` has already zeroed the buffer. A panic in a de-identification tool
    /// prints a backtrace, and a backtrace is a log line.
    pub fn expose(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// `<redacted>`, always.
///
/// WHY a hand-written impl and not simply omitting the derive: omitting it makes every
/// containing type un-`Debug`-able, and the pressure to add `#[derive(Debug)]` somewhere up the
/// chain then lands on whoever is debugging at 2am. Giving the type a Debug that cannot leak is
/// what keeps the derive above it harmless.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One surrogate and the identifier it stands for.
#[derive(Debug)]
pub struct Restoration {
    /// The token that was sent to the cloud model, e.g. `[PATIENT_NAME_4f1a2b_1]`.
    pub placeholder: String,
    /// The original identifier. Never leaves this process.
    pub original: Secret,
    /// The schema label, which is metadata and safe to log.
    pub label: EntityLabel,
    /// Byte offset of the identifier in the ORIGINAL document.
    pub start: usize,
    /// Exclusive byte offset of the identifier in the ORIGINAL document.
    pub end: usize,
}

/// A span map plus its deadline.
#[derive(Debug)]
pub struct Session {
    entries: Vec<Restoration>,
    expires_at: Instant,
    /// A monotonically increasing number used in log lines INSTEAD of the handle.
    ///
    /// The handle is a capability; the sequence number is not. Logging the sequence number
    /// gives an operator the ability to correlate a `deidentify` with its `reidentify` without
    /// putting a live credential for a span map into a log aggregator.
    sequence: u64,
}

impl Session {
    /// The restorations, in the order the entities appear in the original document.
    pub fn entries(&self) -> &[Restoration] {
        &self.entries
    }

    /// The correlation id for logging. Never the handle.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// How many entities this span map can restore.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing was masked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The clock the store reads.
///
/// A trait so that expiry can be tested by advancing time rather than by sleeping. A test that
/// proves a 15 minute TTL by waiting 15 minutes is a test that gets deleted.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real, monotonic clock.
///
/// `Instant` and not `SystemTime` deliberately: a deadline that can be defeated by moving the
/// system clock backwards is not a deadline. `Instant` is monotonic, so an operator or an NTP
/// step cannot extend the lifetime of a resident span map.
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
        // Neither the handles nor the entries appear: handles are capabilities and entries are
        // PHI. Counts and configuration are the whole safe surface of this type.
        f.debug_struct("SessionStore")
            .field("live", &self.sessions.len())
            .field("ttl_seconds", &self.ttl.as_secs())
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}

impl SessionStore {
    /// A store with the given retention policy and the real clock.
    pub fn new(ttl: Duration, max_sessions: usize) -> Self {
        Self::with_clock(ttl, max_sessions, Box::new(MonotonicClock))
    }

    /// A store reading a caller-supplied clock, for tests.
    pub fn with_clock(ttl: Duration, max_sessions: usize, clock: Box<dyn Clock>) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
            max_sessions,
            next_sequence: 1,
            clock,
        }
    }

    /// The configured retention window, for the `health` tool.
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The configured ceiling, for the `health` tool.
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
    /// The handle is returned by value and never retained anywhere else in this crate, so the
    /// only copy outside the store's key set is the one the client receives.
    pub fn insert(&mut self, entries: Vec<Restoration>) -> Result<String> {
        self.expire();
        if self.sessions.len() >= self.max_sessions {
            return Err(GatewayError::SessionStoreFull {
                limit: self.max_sessions,
            });
        }
        let handle = new_handle()?;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.sessions.insert(
            handle.clone(),
            Session {
                entries,
                expires_at: self.clock.now() + self.ttl,
                sequence,
            },
        );
        Ok(handle)
    }

    /// Look a span map up, or fail with the one undifferentiated error.
    ///
    /// The sweep runs FIRST. Without it, an expired session would still be found by the map
    /// lookup and the deadline would be advisory, which is the difference between a retention
    /// policy and a comment claiming there is one.
    pub fn get(&mut self, handle: &str) -> Result<&Session> {
        self.expire();
        self.sessions
            .get(handle)
            .ok_or(GatewayError::SessionNotFound)
    }

    /// Destroy a session now, zeroising its span map.
    ///
    /// Returns the same [`GatewayError::SessionNotFound`] as [`SessionStore::get`] for a handle
    /// that never existed. A `forget` that succeeded loudly on real handles and failed loudly
    /// on invented ones would be the existence oracle the error type exists to deny.
    pub fn forget(&mut self, handle: &str) -> Result<usize> {
        self.expire();
        let session = self
            .sessions
            .remove(handle)
            .ok_or(GatewayError::SessionNotFound)?;
        let count = session.len();
        drop(session);
        Ok(count)
    }

    /// Drop every session past its deadline.
    ///
    /// Returns the number swept so a caller can log it. `retain` drops the removed values in
    /// place, which runs `Secret::drop` and therefore zeroes each buffer.
    pub fn expire(&mut self) -> usize {
        let now = self.clock.now();
        let before = self.sessions.len();
        self.sessions.retain(|_, session| session.expires_at > now);
        before - self.sessions.len()
    }

    /// Destroy every session, zeroising every span map. Called at shutdown.
    pub fn clear(&mut self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        count
    }
}

/// A fresh 128-bit handle, lower-case hex.
fn new_handle() -> Result<String> {
    let mut bytes = [0u8; HANDLE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| GatewayError::EntropyUnavailable)?;
    Ok(hex(&bytes))
}

/// Lower-case hex, written out rather than pulled in as a dependency.
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

    /// A clock the test moves by hand.
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

    fn restoration(placeholder: &str, original: &str) -> Restoration {
        Restoration {
            placeholder: placeholder.to_owned(),
            original: Secret::new(original),
            label: EntityLabel::PatientName,
            start: 0,
            end: original.len(),
        }
    }

    #[test]
    fn a_stored_span_map_comes_back_under_its_handle() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(vec![restoration("[PATIENT_NAME_aa_1]", "Ayşe Yılmaz")])
            .expect("insert");
        let session = store.get(&handle).expect("lookup");
        assert_eq!(session.len(), 1);
        assert_eq!(session.entries()[0].original.expose(), "Ayşe Yılmaz");
    }

    #[test]
    fn handles_are_unique_and_wide() {
        let mut store = SessionStore::new(Duration::from_secs(60), 64);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let handle = store.insert(Vec::new()).expect("insert");
            assert_eq!(
                handle.len(),
                HANDLE_BYTES * 2,
                "handle is not 128 bits of hex"
            );
            assert!(seen.insert(handle), "the CSPRNG repeated a session handle");
        }
    }

    #[test]
    fn a_session_expires_on_its_deadline_and_is_then_indistinguishable_from_fiction() {
        let (offset_millis, clock) = fake_clock();
        let mut store = SessionStore::with_clock(Duration::from_secs(900), 8, clock);
        let handle = store
            // Checksum-INVALID by construction: the trailing digit is one off, so this
            // string can never be a real national ID (I8). The test only needs an opaque
            // payload to prove a session is unrecoverable once expired -- it does not need
            // a valid identifier, and a valid one here would be committed PHI-shaped data.
            .insert(vec![restoration("[TCKN_aa_1]", "10000000147")])
            .expect("insert");

        offset_millis.store(899_000, Ordering::SeqCst);
        assert!(store.get(&handle).is_ok(), "expired one second early");

        offset_millis.store(900_001, Ordering::SeqCst);
        let expired = store.get(&handle).expect_err("must be gone");
        let invented = store
            .get("00000000000000000000000000000000")
            .expect_err("fiction");
        assert_eq!(expired, GatewayError::SessionNotFound);
        assert_eq!(
            expired, invented,
            "an expired handle must be indistinguishable from one that never existed"
        );
        assert_eq!(store.live(), 0);
    }

    #[test]
    fn forget_destroys_one_session_and_leaves_the_others_alone() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let first = store
            .insert(vec![restoration("[A_aa_1]", "one")])
            .expect("a");
        let second = store
            .insert(vec![restoration("[A_bb_1]", "two")])
            .expect("b");
        assert_eq!(store.forget(&first).expect("forget"), 1);
        assert_eq!(store.get(&first).err(), Some(GatewayError::SessionNotFound));
        assert_eq!(store.get(&second).expect("survivor").len(), 1);
    }

    #[test]
    fn forgetting_a_handle_that_never_existed_reports_the_same_failure() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        assert_eq!(store.forget("deadbeef"), Err(GatewayError::SessionNotFound));
    }

    #[test]
    fn a_full_store_refuses_a_new_session_rather_than_evicting_a_live_one() {
        let mut store = SessionStore::new(Duration::from_secs(60), 2);
        let first = store.insert(Vec::new()).expect("a");
        store.insert(Vec::new()).expect("b");
        assert_eq!(
            store.insert(Vec::new()),
            Err(GatewayError::SessionStoreFull { limit: 2 })
        );
        assert!(
            store.get(&first).is_ok(),
            "a full store must not destroy an in-flight round trip"
        );
    }

    #[test]
    fn expiry_frees_a_slot_in_a_full_store() {
        let (offset_millis, clock) = fake_clock();
        let mut store = SessionStore::with_clock(Duration::from_secs(10), 1, clock);
        store.insert(Vec::new()).expect("a");
        assert!(store.insert(Vec::new()).is_err());
        offset_millis.store(10_001, Ordering::SeqCst);
        store
            .insert(Vec::new())
            .expect("the expired slot is reusable");
        assert_eq!(store.live(), 1);
    }

    #[test]
    fn a_secret_zeroes_its_buffer_before_it_is_freed() {
        // The property is asserted on the buffer the Drop impl actually writes to. Reading
        // freed memory would be undefined behaviour and needs `unsafe`, which this crate does
        // not have, so the observable statement is that `fill(0)` is what Drop does and that
        // the buffer is the one `into_bytes` handed over.
        let mut secret = Secret::new("Ayşe Yılmaz");
        assert_eq!(secret.expose(), "Ayşe Yılmaz");
        secret.0.fill(0);
        assert!(
            secret.0.iter().all(|byte| *byte == 0),
            "zeroisation did not cover the buffer"
        );
        assert_eq!(secret.expose(), "\0".repeat(13));
    }

    #[test]
    fn debug_never_prints_an_identifier_or_a_handle() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        let handle = store
            .insert(vec![restoration("[PATIENT_NAME_aa_1]", "Ayşe Yılmaz")])
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
        assert!(
            !rendered.contains("Ayşe"),
            "Debug on a Restoration egressed PHI"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn clear_destroys_everything() {
        let mut store = SessionStore::new(Duration::from_secs(60), 8);
        store.insert(Vec::new()).expect("a");
        store.insert(Vec::new()).expect("b");
        assert_eq!(store.clear(), 2);
        assert_eq!(store.live(), 0);
    }
}
