#![forbid(unsafe_code)]

//! `deid-tr-tauri` -- the desktop application, minus the window.
//!
//! # What this crate is for
//!
//! A clinician who has a PDF and no terminal. Everything the CLI can do to a
//! document, done by picking the file in a file dialog.
//!
//! # Why it calls the Rust crates directly and not the wasm binding
//!
//! `bindings/wasm` exists because the browser cannot link `ort` or read a PDF
//! off a disk. Neither limitation applies here: the desktop process IS a native
//! process, so it links `deid-tr-core` and `deid-tr-files` directly. Going
//! through WebAssembly on a host that can run the native crate would cost the
//! real file formats (PDF and `.docx` handling lives in `deid-tr-files`, which
//! the wasm surface reaches only through a re-implementation) and would put a
//! second copy of the pipeline in the product for no gain.
//!
//! The consequence worth stating: **the webview never sees a document.** The
//! bytes are read by Rust, masked by Rust, and written by Rust. What crosses
//! the IPC boundary into the web page is the masked TEXT the user typed, or --
//! for a file -- nothing but counts and labels. There is no upload because
//! there is nothing to upload to, and there is no copy of the note in the
//! webview process either.
//!
//! # Invariants this crate is responsible for
//!
//! * **I1.** No network, in the pipeline or in the shell around it. The webview
//!   gets a CSP with `default-src 'none'` (`tauri.conf.json`), the capability
//!   file grants `core:default` and nothing else, the auto-updater is not
//!   enabled and points nowhere, and there is no telemetry. The application
//!   runs air-gapped, which `just test-tauri-airgapped` proves rather than
//!   asserts.
//! * **I4.** Nothing that crosses the IPC boundary carries document text except
//!   the de-identified text the user asked for. Every error type here is a
//!   classification; every span record is a label, a length and a synthetic
//!   replacement. The file path a user picked never goes back to the page.
//!
//! # THE DISCLOSURE
//!
//! This build masks **zero names**. L2 has no trained model and no weights
//! ship, so `PATIENT_NAME`, `CLINICIAN_NAME` and `RELATIVE_NAME` pass through
//! untouched. [`disclosure()`] is the sentence, taken from
//! `deid_tr_files::Report` so it cannot drift into something more reassuring,
//! and `ui/index.html` shows it in the main view above every result -- not in
//! an About box, because nobody opens an About box before trusting an output.

pub mod l3;
pub mod pipeline;

use serde::Serialize;

pub use pipeline::{DesktopError, FileOutcome, LayerReport, SpanRow, TextOutcome, TierChoice};

/// The sentence every surface must show next to a result.
///
/// Delegated to `deid-tr-files` rather than written here: three surfaces
/// describing the same gap in three tones is how one of them ends up sounding
/// like a footnote.
#[must_use]
pub fn disclosure() -> &'static str {
    deid_tr_files::Report::rule_detectable_only()
}

/// What the application will tell you about itself before you feed it anything.
///
/// Returned by the `about` command and rendered into the main view at startup.
/// `masks_names` is a separate boolean from the prose deliberately: prose can be
/// skimmed past, and a UI that wants to draw a red box needs a field to key off.
#[derive(Debug, Clone, Serialize)]
pub struct About {
    /// The crate version.
    pub version: &'static str,
    /// The disclosure sentence.
    pub disclosure: &'static str,
    /// Always false in this build, and the reason the banner is red.
    pub masks_names: bool,
    /// True when this binary can reach a network. Always false; see the module
    /// docs for what enforces it.
    pub network_capable: bool,
}

impl Default for About {
    fn default() -> Self {
        Self::new()
    }
}

impl About {
    /// The honest description of this build.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            disclosure: disclosure(),
            // NOT COMPUTED FROM ANYTHING. It is a constant because the fact is
            // a constant: `Pipeline::new` installs an empty L2 ensemble and no
            // code path in this application installs a member. The day a model
            // ships, this field becomes a read of the ensemble and the test
            // below fails until somebody updates it on purpose.
            masks_names: false,
            network_capable: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_disclosure_says_names_are_not_masked() {
        // THE HONESTY TEST, in the same shape as the one in
        // `deid-tr-files`: if a build ever starts masking names, this is one of
        // the places that has to change with it.
        assert!(disclosure().contains("does NOT mask person names"));
        assert!(!About::new().masks_names);
        assert!(!About::new().network_capable);
    }
}
