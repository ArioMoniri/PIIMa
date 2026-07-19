#![forbid(unsafe_code)]

//! `deid-tr-mcp` -- the stdio JSON-RPC MCP gateway.
//!
//! # What this is for
//!
//! A clinician wants to ask a cloud model about a Turkish clinical note. The note contains
//! PHI. This gateway sits in the middle: it masks the note on the way OUT, and it restores the
//! real identifiers in the model's answer on the way BACK, so the clinician reads a reply that
//! names their actual patient while the cloud provider only ever saw surrogates.
//!
//! ```text
//!   note ---> [deidentify] ---> masked note ---> MCP client ---> cloud model
//!                  |                                                  |
//!             span map (in memory, never written, never logged)       |
//!                  |                                                  v
//!   answer <-- [reidentify] <-- masked answer <-- MCP client <--------+
//! ```
//!
//! # The invariants this crate is responsible for
//!
//! **I3 -- never bind all interfaces.** The transport is stdin/stdout. There is no socket in
//! this crate and no socket-capable dependency beneath it, so there is no address to get wrong.
//! `tests/no_listener.rs` asserts that structurally. A socket transport, if it is ever added,
//! is loopback-only and requires an explicit flag, a bearer token and a startup warning
//! together; the flag alone is not enough and neither is the token alone.
//!
//! **I4 -- no request or response text in any log or error.** [`error::GatewayError`] carries
//! counts, byte offsets and closed vocabularies. [`telemetry`] writes labels, offsets and
//! counts to stderr and nothing else. Session handles are on the same footing as PHI: a handle
//! is a bearer capability over a span map, so it is never logged either.
//!
//! **I1 -- PHI never leaves the device.** The gateway does not speak to the cloud model; the
//! MCP client does. This process holds the span map precisely because it has no way to send it
//! anywhere.
//!
//! # The span map
//!
//! It is the single most sensitive structure in the product: the literal mapping from surrogate
//! back to real PHI, with the narrative stripped away. [`session`] documents its retention
//! policy, its expiry and its zeroisation, and why each of those is not optional.

pub mod error;
pub mod jsonrpc;
pub mod server;
pub mod session;
pub mod surrogate;
pub mod telemetry;

pub use error::{ArgumentName, GatewayError, Result};
pub use server::{Server, ServerConfig};
pub use session::{SessionStore, DEFAULT_MAX_SESSIONS, DEFAULT_TTL_SECONDS};

/// The MCP protocol revision this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// The server name reported in `initialize`.
pub const SERVER_NAME: &str = "deid-tr";

/// The running version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Synthetic identifier generation for tests.
///
/// PUBLIC AND `doc(hidden)` ON PURPOSE. Invariant I8 forbids a checksum-valid TCKN from
/// appearing in any committed file, so every test that needs one must BUILD it at runtime.
/// Integration tests under `tests/` compile against this crate as an external consumer and
/// therefore cannot reach a `pub(crate)` helper, and duplicating the checksum into each test
/// file is how one copy eventually drifts and starts emitting a number that is not valid. One
/// implementation, reachable from both kinds of test, is the honest resolution.
#[doc(hidden)]
pub mod fixtures {
    /// A TCKN that passes the real checksum, constructed at runtime.
    ///
    /// Rules, from the brief: 11 digits, `d1 != 0`,
    /// `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`, `d11 = (d1+..+d10) mod 10`.
    #[must_use]
    pub fn checksum_valid_tckn(seed: [u8; 9]) -> String {
        let mut digits = [0u8; 11];
        digits[..9].copy_from_slice(&seed);
        // A leading zero is not a TCKN, so it is nudged rather than trusted from the seed.
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

    /// A second, different synthetic TCKN.
    #[must_use]
    pub fn other_tckn() -> String {
        checksum_valid_tckn([2, 4, 6, 8, 1, 3, 5, 7, 9])
    }
}
