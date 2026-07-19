//! The first-run disclosure.
//!
//! Auto-update is ON by default in this product. That is the project owner's
//! decision, and it is defensible; what is not defensible is a PHI tool making an
//! outbound connection that the person running it never agreed to and was never
//! told about. So the very first invocation on a machine prints one line saying
//! that checks are on and naming all three ways to turn them off, before any
//! check is spawned.
//!
//! WHY stderr and not stdout: `deid mask` writes the de-identified document to
//! stdout and people pipe it. A notice on stdout would corrupt a clinical
//! document, which is a worse outcome than a notice nobody reads.
//!
//! WHY only once: a line printed on every run is a line that gets filtered out of
//! logs within a week, and a disclosure nobody reads is not a disclosure. The
//! marker lives in the state directory; deleting it shows the notice again.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::Config;

/// One line. It has to fit in a terminal or it will not be read.
pub const NOTICE: &str = "deid: automatic update checks are ON (a static release manifest is fetched; no document text, no usage data, no identifiers are ever sent). Turn them off with --offline, DEID_NO_UPDATE=1, or auto_update = false in your config file.";

fn marker(state_dir: &Path) -> PathBuf {
    state_dir.join("first-run-notice-shown")
}

/// True when this machine has not yet been told.
pub fn is_first_run(state_dir: &Path) -> bool {
    !marker(state_dir).exists()
}

/// Print the notice once, then record that it was printed.
///
/// Returns whether it printed, so the caller can be tested without capturing
/// stderr. Never returns an error: a read-only state directory is a reason to
/// print the notice again next time, not a reason to fail the command.
pub fn show_once(config: &Config, out: &mut dyn Write) -> bool {
    // WHY the notice is skipped when checks are already off: telling an
    // air-gapped operator that a feature they have disabled is enabled is worse
    // than saying nothing. The disclosure exists to warn about traffic that will
    // actually happen.
    if !config.auto_update {
        return false;
    }
    if !is_first_run(&config.state_dir) {
        return false;
    }
    let _ = writeln!(out, "{NOTICE}");
    let _ = std::fs::create_dir_all(&config.state_dir);
    let _ = std::fs::write(marker(&config.state_dir), b"");
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CliFlags, EnvView, FileConfig, ENV_NO_UPDATE};
    use std::time::Duration;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deid-notice-{name}-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn config(state_dir: PathBuf, offline: bool) -> Config {
        let mut config = crate::config::resolve(
            &CliFlags { offline },
            &EnvView::default(),
            &FileConfig {
                host: Some("releases.example.invalid".to_owned()),
                ..FileConfig::default()
            },
        );
        state_dir.clone_into(&mut config.state_dir);
        config.timeout = Duration::from_millis(1);
        config
    }

    #[test]
    fn the_notice_prints_once_and_names_all_three_off_switches() {
        let config = config(scratch("once"), false);
        let mut first = Vec::new();
        assert!(show_once(&config, &mut first));
        let printed = String::from_utf8(first).expect("utf8");

        assert!(printed.contains("--offline"));
        assert!(printed.contains(ENV_NO_UPDATE));
        assert!(printed.contains("auto_update = false"));
        assert!(printed.contains("ON"));
        assert_eq!(printed.lines().count(), 1, "a multi-line notice is a wall");

        let mut second = Vec::new();
        assert!(!show_once(&config, &mut second));
        assert!(second.is_empty());
    }

    #[test]
    fn no_notice_is_printed_when_checks_are_already_disabled() {
        let config = config(scratch("offline"), true);
        let mut out = Vec::new();
        assert!(!show_once(&config, &mut out));
        assert!(out.is_empty());
        assert!(
            is_first_run(&config.state_dir),
            "a disabled run must not consume the disclosure the first enabled run owes"
        );
    }
}
