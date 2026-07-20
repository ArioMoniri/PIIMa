#![forbid(unsafe_code)]

//! `deid-tr-service` -- `deid-serve`, a LOCAL HTTP/JSON de-identification service.
//!
//! # What this is for
//!
//! A hospital already has systems that speak HTTP and do not speak Rust: a
//! LIS, an export job, a Python notebook, a Java integration engine. This is the
//! surface they can reach without embedding anything. It runs on the same
//! machine as the data, it never makes an outbound connection, and it holds the
//! span map -- the table from each surrogate back to the real identifier --
//! precisely because it cannot send one anywhere.
//!
//! ```text
//! POST /analyze      entities: label, byte offsets, confidence, decision
//! POST /deidentify   masked text + span map + session handle
//! POST /reidentify   the original document, from a session handle
//! POST /batch        many documents, one result per document, never fewer
//! GET  /health       version, tier, which layers are live, which models are loaded
//! GET  /entities     the entity catalog from eval/schema.yaml
//! ```
//!
//! # The invariants this crate is responsible for
//!
//! **I3 -- never bind all interfaces.** [`bind::plan`] is the only way to obtain
//! a [`bind::Listen`], and [`server::Server::serve`] is the only place a socket
//! is created. An all-interfaces address is refused unconditionally -- `--expose`
//! and a bearer token do not unlock it. Any other non-loopback address requires
//! `--expose` AND a bearer token AND a startup warning, together; the warning is
//! a field on the returned value rather than a step `main` might forget.
//! `tests/loopback_invariant.rs` asserts this from outside the crate.
//!
//! **I4 -- no request or response text in any log.** [`log::Event`] accepts an
//! operation name, a status, counts, byte offsets and entity labels, and there
//! is no method on it that takes a document, a surrogate, a session handle or a
//! bearer token. Routes are logged from a closed match on the parsed path, so an
//! unmatched request logs `route=unmatched` and the URL it asked for is never
//! written down. [`http`] discards the query string before the router sees it.
//!
//! **I1 -- PHI never leaves the device.** There is no outbound HTTP client in
//! this crate's dependency list and there never will be. This process accepts
//! connections; it never makes one. The pipeline it runs is `deid-tr-core`,
//! which performs no I/O at all.
//!
//! # Honest coverage
//!
//! L2 has no trained model in this build, so **deid-tr masks ZERO names**.
//! Coverage today is rule-detectable identifiers: TCKN, VKN, SGK, IBAN, phone,
//! MRN, email and dates. `GET /health` and `GET /entities` both say so in the
//! payload, per label, because a machine consumer reads the payload and not the
//! README.

pub mod api;
pub mod bind;
pub mod catalog;
pub mod http;
pub mod log;
pub mod server;
pub mod session;

pub use api::{ApiError, Service, ServiceConfig};
pub use bind::{plan, Listen, Refusal, Token, DEFAULT_PORT, EXPOSURE_WARNING, MIN_TOKEN_LEN};
pub use server::Server;
pub use session::{SessionStore, DEFAULT_MAX_SESSIONS, DEFAULT_TTL_SECONDS};

/// The running version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Synthetic identifier generation for tests.
///
/// PUBLIC AND `doc(hidden)` ON PURPOSE. Invariant I8 forbids a checksum-valid
/// TCKN from appearing in any committed file, so every test that needs one must
/// BUILD it at run time. Integration tests under `tests/` compile against this
/// crate as an external consumer and cannot reach a `pub(crate)` helper, and
/// duplicating the checksum into each test file is how one copy eventually
/// drifts and starts emitting a number that is not valid.
#[doc(hidden)]
pub mod fixtures {
    /// A TCKN that passes the real checksum, constructed at run time.
    ///
    /// Rules, from the brief: 11 digits, `d1 != 0`,
    /// `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`,
    /// `d11 = (d1+..+d10) mod 10`.
    #[must_use]
    pub fn checksum_valid_tckn(seed: [u8; 9]) -> String {
        let mut digits = [0u8; 11];
        digits[..9].copy_from_slice(&seed);
        // A leading zero is not a TCKN, so it is nudged rather than trusted.
        if digits[0] == 0 {
            digits[0] = 1;
        }
        let odd: i32 = [0, 2, 4, 6, 8].iter().map(|i| i32::from(digits[*i])).sum();
        let even: i32 = [1, 3, 5, 7].iter().map(|i| i32::from(digits[*i])).sum();
        digits[9] = u8::try_from((odd * 7 - even).rem_euclid(10)).unwrap_or(0);
        let total: i32 = digits[..10].iter().map(|d| i32::from(*d)).sum();
        digits[10] = u8::try_from(total.rem_euclid(10)).unwrap_or(0);
        digits.iter().map(|d| char::from(b'0' + d)).collect()
    }

    /// The default synthetic TCKN.
    #[must_use]
    pub fn tckn() -> String {
        checksum_valid_tckn([1, 2, 3, 4, 5, 6, 7, 8, 9])
    }

    /// A synthetic Turkish clinical note carrying rule-detectable identifiers.
    ///
    /// Deliberately also carries a name and two code-switched medical terms, so
    /// that a test can assert both what IS masked and what is NOT.
    #[must_use]
    pub fn note() -> String {
        format!(
            "Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00. carcinoma'lı, MRI'da lezyon yok.",
            tckn()
        )
    }
}
