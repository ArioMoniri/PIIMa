#![forbid(unsafe_code)]

//! `deid-tr-core` -- the pure de-identification core for Turkish clinical text.
//!
//! This crate owns the span type that every layer of the pipeline speaks and
//! the orchestrator seam they plug into: L1 deterministic rules, L2 the NER
//! ensemble, L3 the local contextual sweep, L4 adjudication, L5 surrogates.
//!
//! # Invariants that bind this crate
//!
//! **I1 -- PHI never leaves the device.** This crate performs no I/O and has
//! no network dependency. There is no HTTP client, no telemetry, no crash
//! reporter and no lazy model download anywhere beneath it, and there never
//! will be: model weights and files are the caller's problem, passed in as
//! `&str` and `&[u8]`. The ban is written into `core/Cargo.toml` where a hook
//! can enforce it, because an invariant that lives only in prose is a wish.
//!
//! **I4 -- errors are a PHI egress path.** No [`Error`] variant carries
//! document text, covered text, or a model rationale. Offsets, lengths,
//! labels and layers only. An error message ends up in a log aggregator and
//! then in a bug report; text placed in one has left the device.
//!
//! **Portability.** The crate compiles to native targets and to `wasm32`, so
//! the browser PWA runs the same rules, the same span algebra and the same
//! surrogates as the CLI. Only the model forward pass differs per target,
//! which is why inference sits behind the [`Detector`] and [`Contextual`]
//! traits rather than inside this crate.
//!
//! **Offset discipline.** All offsets are BYTE offsets into the ORIGINAL
//! document and must land on UTF-8 character boundaries. Turkish is multi-byte
//! (`ş`, `ğ`, `İ`), so byte offsets and char indices diverge constantly, and
//! tokenizer- or LLM-reported positions are re-anchored to the original text
//! rather than trusted. [`Span::new`] refuses to build a span that splits a
//! character.
//!
//! [`Error`]: error::Error
//! [`Detector`]: pipeline::Detector
//! [`Contextual`]: pipeline::Contextual

pub mod audit;
pub mod context;
pub mod detect;
pub mod error;
pub mod label;
pub mod output;
pub mod pipeline;
pub mod redact;
pub mod route;
pub mod rules;
pub mod span;
pub mod surrogate;
pub mod text;

pub use error::{Error, Result};
pub use label::{EntityLabel, QuasiCategory};
pub use output::{EntityRow, HtmlOptions, Report};
pub use pipeline::{
    Contextual, DeidResult, Detector, MappedSpan, Pipeline, RuleSet, Tier, Tokenizer,
};
pub use redact::{
    Blackout, HashKey, RedactError, Redacted, RedactedSpan, RedactionMethod, RedactionPolicy,
    Redactor, Rendered,
};
// The allowlist and the surrogate engine are re-exported from the layers that
// OWN them, not from `pipeline`. `pipeline` used to define a stub of each under
// the same name; a caller who reached for `deid_tr_core::MedicalAllowlist` got
// the stub whose `contains` answered `false` for every term, which is the
// medical-term false-positive gate silently disabled. There is now exactly one
// type with each name in the crate.
pub use route::{Adjudicator, MedicalAllowlist, Verdict};
pub use span::{union_widest, Decision, DetectorId, Layer, Merged, Span};
pub use surrogate::{Salt, SaltScope, SurrogateEngine};
