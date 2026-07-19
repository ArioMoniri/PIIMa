//! The gateway error type.
//!
//! Same rule as `core/src/error.rs`, restated here because this crate is where the rule is
//! hardest to keep: every variant carries counts, offsets, byte lengths and closed
//! vocabularies, and none carries document text, response text, or a session handle.
//!
//! The session handle is on that list for a reason that is not obvious. A handle is not PHI,
//! but it is a bearer capability over a span map, and a span map is the mapping from surrogate
//! back to real patient identifiers. A handle in a log line is a stolen span map for as long as
//! the session lives, so it is treated exactly like a password: never formatted, never
//! displayed, never carried by an error.

/// Result alias for the gateway.
pub type Result<T> = core::result::Result<T, GatewayError>;

/// Everything the gateway can refuse to do.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum GatewayError {
    /// The named session does not exist RIGHT NOW.
    ///
    /// DELIBERATELY UNDIFFERENTIATED, and this is a security property rather than laziness.
    /// "expired" and "never existed" are the same answer, because distinguishing them turns
    /// the gateway into an oracle: an attacker holding a guessed or leaked handle learns
    /// whether that handle was ever real, which confirms that a de-identification run happened
    /// and narrows a brute-force search. There is no `SessionExpired` variant and there must
    /// never be one.
    #[error("session not found")]
    SessionNotFound,

    /// The request was not a JSON value the gateway could parse.
    ///
    /// Carries the position and the total length, never the bytes. An MCP request body holds
    /// the clinical note in its `text` argument, so a parse error that quoted its input would
    /// print the note into stderr on the very first malformed message.
    #[error("request was not valid JSON at byte {byte_offset} of {request_len} bytes")]
    MalformedRequest {
        byte_offset: usize,
        request_len: usize,
    },

    /// A required argument was missing or had the wrong JSON type.
    #[error("argument {argument} is missing or has the wrong type")]
    BadArgument { argument: ArgumentName },

    /// The method or tool name is not one this server implements.
    #[error("no such method or tool")]
    UnknownMethod,

    /// The document exceeded the configured size ceiling.
    ///
    /// A ceiling exists because a span map is held in memory for the whole session lifetime,
    /// and an unbounded document is an unbounded quantity of PHI resident in a process that a
    /// core dump can capture.
    #[error("document of {request_len} bytes exceeds the {limit} byte ceiling")]
    DocumentTooLarge { request_len: usize, limit: usize },

    /// The store is already holding its maximum number of live sessions.
    #[error("all {limit} session slots are in use")]
    SessionStoreFull { limit: usize },

    /// A surrogate could not be minted without colliding with existing document content.
    #[error("could not mint a collision-free surrogate after {attempts} attempts")]
    SurrogateCollision { attempts: usize },

    /// The OS entropy source refused to produce bytes.
    ///
    /// Fatal on purpose: a session handle drawn from a degraded source is a guessable
    /// capability over a span map, and falling back to a timestamp would be worse than
    /// refusing to open the session at all.
    #[error("the operating system entropy source is unavailable")]
    EntropyUnavailable,

    /// The pure core refused the operation. `core::Error` is already text-free.
    #[error(transparent)]
    Core(#[from] deid_tr_core::Error),
}

/// Which argument was wrong.
///
/// A closed vocabulary rather than a `String`, for the same reason the rest of this enum takes
/// no strings: an argument NAME looks harmless until a caller sends a JSON object whose keys
/// are patient identifiers, and then the "name" being echoed back is the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArgumentName {
    /// The document or model response to operate on.
    Body,
    /// The session handle.
    Session,
    /// The assurance tier.
    Tier,
    /// The `tools/call` tool name.
    ToolName,
    /// The JSON-RPC envelope itself was not an object with a `method`.
    Envelope,
}

impl core::fmt::Display for ArgumentName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Body => "text",
            Self::Session => "session",
            Self::Tier => "tier",
            Self::ToolName => "name",
            Self::Envelope => "method",
        })
    }
}

impl GatewayError {
    /// The JSON-RPC error code this maps to.
    ///
    /// `SessionNotFound` gets its own application code so a client can branch on it without
    /// string-matching a message, and every OTHER failure that could conceivably be probed
    /// stays on a generic code. The codes are as undifferentiated as the messages.
    pub const fn json_rpc_code(&self) -> i64 {
        match self {
            Self::UnknownMethod => -32601,
            Self::MalformedRequest { .. } => -32700,
            Self::BadArgument { .. } => -32602,
            Self::SessionNotFound => -32001,
            _ => -32000,
        }
    }
}
