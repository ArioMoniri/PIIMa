#![forbid(unsafe_code)]
// A desktop application should not also open a console window on Windows. The
// attribute is release-only so a debug build still prints panics somewhere
// visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The window, and the four commands behind it.
//!
//! Everything here is thin on purpose: open a dialog, read bytes, call
//! [`deid_tr_tauri::pipeline`], write bytes. The behaviour lives in the library
//! half so it is tested without a webview.
//!
//! # The command surface, and why it is this small
//!
//! ```text
//! about              what this build is and what it does not do
//! layer_report       which layers are live, and why not when they are not
//! expert_tier_gate   whether Expert Determination can run, and the fix if not
//! deidentify_text    de-identify text the user typed
//! redact_document    pick a file, redact it, save it -- all inside Rust
//! ```
//!
//! There is no command that returns a path, no command that reads an arbitrary
//! path the page names, and no command that writes one. `redact_document` takes
//! NO arguments except the tier: the file it reads is the file the user picked
//! in the OS dialog a moment earlier, and the file it writes is the one they
//! named in the save dialog. A page that could name a path would be a page that
//! could be made to read `~/.ssh/id_rsa`, and the whole point of this surface is
//! that the webview is not trusted with documents.
//!
//! # Why the dialogs are opened from Rust and not from JavaScript
//!
//! `tauri-plugin-dialog` also has a JS API. Using it would require granting
//! `dialog:allow-open` and `dialog:allow-save` to the webview, which is a
//! capability the page then holds permanently. Calling the same plugin from
//! Rust needs no capability at all, which is why `capabilities/default.json`
//! grants `core:default` and nothing else. Least privilege here is not
//! theoretical: the page is the only component in this process that renders
//! anything a document influenced.

use deid_tr_tauri::pipeline::{FileOutcome, LayerReport, Session, TextOutcome, TierChoice};
use deid_tr_tauri::{About, DesktopError};
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;

/// The honest description of this build.
#[tauri::command]
fn about() -> About {
    About::new()
}

/// Which layers are live.
#[tauri::command]
fn layer_report(session: State<'_, Session>) -> LayerReport {
    session.layer_report()
}

/// Whether Expert Determination can run, and the fix when it cannot.
///
/// Returns `Ok(())` when the tier is available. The page uses this to disable
/// the tier control BEFORE a user selects it, so the refusal is a label rather
/// than a failed run.
#[tauri::command]
fn expert_tier_gate(session: State<'_, Session>) -> Result<(), String> {
    session
        .expert_tier_gate()
        .map_err(|error| error.to_string())
}

/// De-identify text the user typed or pasted.
#[tauri::command]
fn deidentify_text(
    session: State<'_, Session>,
    tier: TierChoice,
    text: String,
) -> Result<TextOutcome, String> {
    session
        .deidentify_text(tier, &text)
        .map_err(|error| error.to_string())
}

/// Pick a document, de-identify it, and save the result.
///
/// Returns `None` when the user cancelled either dialog -- a cancellation is not
/// an error, and reporting it as one trains people to ignore error text.
///
/// # What is deliberately not returned
///
/// No path, in either direction. The page is told what was removed and how the
/// output was verified; it is not told what the file was called, because a
/// clinical export is routinely named after the patient (I4).
#[tauri::command]
async fn redact_document(
    app: tauri::AppHandle,
    session: State<'_, Session>,
    tier: TierChoice,
) -> Result<Option<FileOutcome>, String> {
    // Checked BEFORE the dialog. Asking someone to find their file and then
    // telling them the tier they chose cannot run is a worse refusal than the
    // same sentence one click earlier.
    if tier == TierChoice::ExpertDetermination {
        session.expert_tier_gate().map_err(|e| e.to_string())?;
    }

    // `blocking_*` is correct here and only here: a `#[tauri::command] async fn`
    // is polled on the async runtime, never on the main thread, which is the
    // one place these calls must not run.
    let Some(input) = app
        .dialog()
        .file()
        .add_filter("Documents deid-tr can open", &openable())
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let input = input
        .into_path()
        .map_err(|_| "that selection is not a file on this machine".to_owned())?;

    let bytes = std::fs::read(&input).map_err(|error| {
        DesktopError::Read {
            kind: error.kind().to_string(),
        }
        .to_string()
    })?;
    let name = input.file_name().and_then(|name| name.to_str());

    let redacted = session
        .redact_file(tier, &bytes, name)
        .map_err(|error| error.to_string())?;

    let Some(destination) = app
        .dialog()
        .file()
        .set_file_name(suggested_name(&input))
        .blocking_save_file()
    else {
        // The masking succeeded and the user chose not to keep it. Nothing is
        // written and nothing is retained: `redacted` is dropped here.
        return Ok(None);
    };
    let destination = destination
        .into_path()
        .map_err(|_| "that destination is not a path on this machine".to_owned())?;

    std::fs::write(&destination, &redacted.bytes).map_err(|error| {
        DesktopError::Write {
            kind: error.kind().to_string(),
        }
        .to_string()
    })?;

    Ok(Some(redacted.outcome))
}

/// The extensions the open dialog offers.
fn openable() -> Vec<&'static str> {
    deid_tr_tauri::pipeline::openable_extensions()
}

/// `note.pdf` -> `note-deid.pdf`.
///
/// A SUGGESTION IN THE SAVE DIALOG, which the user sees and can change, so it
/// is not an output this application chose on its own. The suffix is there
/// because the most expensive mistake available here is overwriting the
/// original with the redacted copy and losing the ability to check the work.
fn suggested_name(input: &std::path::Path) -> String {
    let stem = input.file_stem().map_or_else(
        || "document".to_owned(),
        |s| s.to_string_lossy().into_owned(),
    );
    match input.extension().and_then(|e| e.to_str()) {
        Some(extension) => format!("{stem}-deid.{extension}"),
        None => format!("{stem}-deid"),
    }
}

fn main() {
    // The salt is drawn ONCE, before the window exists, and a failure is fatal.
    // There is no honest fallback: a salt derived from a clock is a salt an
    // attacker can reconstruct, and running without L5 would produce
    // `[LABEL]`-shaped output that a clinician would have to read to discover.
    let session = match Session::new() {
        Ok(session) => session,
        Err(error) => {
            // stderr, not a dialog: this happens before there is a window, and
            // the message is a classification with no document in it.
            eprintln!("deid-tr: cannot start: {error}");
            std::process::exit(1);
        }
    };

    tauri::Builder::default()
        // The dialog plugin is the ONLY plugin. No shell, no fs, no http, no
        // updater, no notification, no clipboard. Each of those is a capability
        // this application would then have to argue it never uses; not linking
        // them is a shorter argument.
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            app.manage(session);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            about,
            layer_report,
            expert_tier_gate,
            deidentify_text,
            redact_document
        ])
        .run(tauri::generate_context!())
        .expect("the webview host failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_suggested_name_never_overwrites_the_original() {
        assert_eq!(
            suggested_name(std::path::Path::new("/tmp/note.pdf")),
            "note-deid.pdf"
        );
        assert_eq!(
            suggested_name(std::path::Path::new("/tmp/note")),
            "note-deid"
        );
    }

    #[test]
    fn the_dialog_offers_only_formats_the_masker_opens() {
        assert!(!openable().is_empty());
    }
}
