//! Tauri's build step: it parses `tauri.conf.json`, checks the capability
//! files against the permissions the linked plugins actually define, and emits
//! the context `tauri::generate_context!` expands to.
//!
//! It runs at BUILD time and does no I/O beyond this crate's own directory.

fn main() {
    tauri_build::build();
}
