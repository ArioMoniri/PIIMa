//! Configuration resolution.
//!
//! # Precedence, highest wins
//!
//! 1. **CLI flag** — `--offline`. The operator typing the command right now.
//! 2. **Environment variable** — `DEID_NO_UPDATE=1`. The wrapper script, the
//!    container image, the CI job.
//! 3. **Config file** — `auto_update = false`. The machine's standing policy.
//! 4. **Compiled default** — `auto_update = true`.
//!
//! WHY this order and not the reverse: the narrower and more deliberate the
//! scope of a setting, the more it must win. A hospital that has written
//! `auto_update = false` into an image has made a policy decision, but an
//! engineer who types `--offline` on an air-gapped terminal has made a decision
//! about THIS invocation, and a tool that ignores the thing you just typed is a
//! tool people stop trusting.
//!
//! WHY all three exist rather than one: the config file is the air-gapped
//! hospital's standing answer, the env var is the only mechanism available
//! inside a container or a CI runner with no writable home directory, and the
//! flag is the only mechanism available when you have inherited someone else's
//! machine. Removing any one of them makes a real deployment impossible, which
//! is why the off switch is a functional requirement and not a preference.
//!
//! The same three-layer order governs the L3 paths — `--model` / `--runtime`,
//! then `DEID_L3_MODEL` / `DEID_L3_RUNTIME`, then `l3_model` / `l3_runtime` in
//! the file — and is applied in `src/l3.rs`. It lives there rather than here
//! because those two settings are paths to a weights file and an executable,
//! not switches, and resolving them has nothing to do with the updater.
//!
//! Note that the precedence is stated in terms of DISABLING. Nothing in this
//! file can enable auto-update where a lower-precedence layer disabled it,
//! because there is no `--online` flag and no truthy value of `DEID_NO_UPDATE`
//! that turns the updater back on. The switch is one-way by construction: every
//! layer may veto, none may un-veto.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Set to any value other than `0`, `false` or empty to disable update checks.
pub const ENV_NO_UPDATE: &str = "DEID_NO_UPDATE";
/// Overrides the config file location.
pub const ENV_CONFIG: &str = "DEID_CONFIG";
/// Overrides the state directory (first-run marker, staged downloads).
pub const ENV_STATE_DIR: &str = "DEID_STATE_DIR";

/// The default port for the release host. Named rather than inlined so that the
/// one place a network port is chosen is greppable.
pub const DEFAULT_PORT: u16 = 443;

/// The hard ceiling on an update check, start to finish.
///
/// WHY two seconds and not thirty: an update check that can delay startup is an
/// update check that will eventually be blamed for a clinician waiting. The
/// budget is small enough that a firewall which blackholes packets — the normal
/// behaviour of a restricted hospital network, as opposed to a clean refusal —
/// costs less than the process spends on dynamic linking.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Where the update check would go. There is no compiled-in default.
///
/// WHY no default host: the release host does not exist yet, and a placeholder
/// would mean every install in the field quietly resolving a domain somebody
/// else can register. An unconfigured endpoint disables the updater, which is
/// the safe direction to fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Hostname of the release server. Never a hardcoded literal in source.
    pub host: String,
    /// TCP port, defaulting to [`DEFAULT_PORT`].
    pub port: u16,
}

/// Which layer of the precedence chain turned auto-update off.
///
/// Carried rather than collapsed to a bool so that `deid update` can tell the
/// operator WHICH switch is holding it off. "Updates are disabled" without a
/// reason sends people editing the wrong file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledBy {
    /// `--offline` was passed.
    CliFlag,
    /// `DEID_NO_UPDATE` was set to a truthy value.
    EnvVar,
    /// `auto_update = false` in the config file.
    ConfigFile,
}

impl DisabledBy {
    /// The switch, spelled the way the operator would type it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CliFlag => "--offline",
            Self::EnvVar => "DEID_NO_UPDATE",
            Self::ConfigFile => "auto_update = false",
        }
    }
}

/// Flags parsed from the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CliFlags {
    /// Disables every outbound network operation for this invocation.
    pub offline: bool,
}

/// The slice of the environment this crate reads.
///
/// A struct rather than direct `std::env` calls so that resolution is a pure
/// function of its inputs and the tests never mutate process-global state — two
/// tests setting `DEID_NO_UPDATE` in parallel would otherwise flake, and a
/// flaky test on the off switch is a test that gets deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvView {
    /// Raw value of [`ENV_NO_UPDATE`].
    pub no_update: Option<String>,
    /// Raw value of [`ENV_CONFIG`].
    pub config_path: Option<String>,
    /// Raw value of [`ENV_STATE_DIR`].
    pub state_dir: Option<String>,
    /// `XDG_STATE_HOME`, used to site the state directory.
    pub xdg_state_home: Option<String>,
    /// `XDG_CONFIG_HOME`, used to site the config file.
    pub xdg_config_home: Option<String>,
    /// `HOME`, the fallback for both.
    pub home: Option<String>,
    /// `DEID_L3_MODEL`: the local GGUF weights file for the L3 sweep.
    pub l3_model: Option<String>,
    /// `DEID_L3_RUNTIME`: the local inference executable for the L3 sweep.
    pub l3_runtime: Option<String>,
}

impl EnvView {
    /// Read the environment once, at startup.
    pub fn from_process() -> Self {
        let get = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        Self {
            no_update: get(ENV_NO_UPDATE),
            config_path: get(ENV_CONFIG),
            state_dir: get(ENV_STATE_DIR),
            xdg_state_home: get("XDG_STATE_HOME"),
            xdg_config_home: get("XDG_CONFIG_HOME"),
            home: get("HOME"),
            l3_model: get(crate::l3::ENV_MODEL),
            l3_runtime: get(crate::l3::ENV_RUNTIME),
        }
    }

    /// Whether [`ENV_NO_UPDATE`] is set to something that means "off".
    ///
    /// WHY `0`, `false` and empty are the only falsey spellings: everything else
    /// disables. Someone who exports `DEID_NO_UPDATE=please` meant to turn it
    /// off, and guessing the other way sends a packet they did not want sent.
    fn env_disables(&self) -> bool {
        match self.no_update.as_deref() {
            None => false,
            Some(raw) => !matches!(raw.trim().to_ascii_lowercase().as_str(), "" | "0" | "false"),
        }
    }
}

/// A parse failure in the config file.
///
/// Every variant carries a LINE NUMBER and nothing else. A config file sits next
/// to clinical work and can be pasted into a bug report; an error that echoes the
/// offending value would carry whatever the operator put there (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A non-comment, non-empty line with no `=`.
    #[error("config line {line}: expected `key = value`")]
    MalformedLine {
        /// 1-indexed line number.
        line: usize,
    },
    /// A key this build does not know.
    #[error("config line {line}: unknown key")]
    UnknownKey {
        /// 1-indexed line number.
        line: usize,
    },
    /// A boolean-valued key whose value was not `true` or `false`.
    #[error("config line {line}: expected `true` or `false`")]
    NotABool {
        /// 1-indexed line number.
        line: usize,
    },
    /// A port outside `1..=65535`.
    #[error("config line {line}: expected a TCP port in 1..=65535")]
    NotAPort {
        /// 1-indexed line number.
        line: usize,
    },
}

/// The config file, after parsing and before precedence is applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileConfig {
    /// `auto_update`. `None` means the file did not mention it.
    pub auto_update: Option<bool>,
    /// `update_host`.
    pub host: Option<String>,
    /// `update_port`.
    pub port: Option<u16>,
    /// `update_public_key`, a minisign public key in base64.
    pub public_key: Option<String>,
    /// `l3_model`: the local GGUF weights file for the L3 contextual sweep.
    ///
    /// A LOCAL PATH and never a host, an endpoint or a repository id. There is
    /// no key here that can point L3 at something that is not on this disk; see
    /// `src/l3.rs` for why that is structural rather than a convention.
    pub l3_model: Option<String>,
    /// `l3_runtime`: the local inference executable for the L3 sweep.
    pub l3_runtime: Option<String>,
}

/// Parse `key = value` lines, `#` to end of line is a comment.
///
/// WHY a hand-written parser and not a TOML crate: the file has four keys, the
/// grammar below fits on a screen, and a reviewer auditing what this tool can be
/// told to do should not have to audit a parser to do it.
pub fn parse_file(text: &str) -> Result<FileConfig, ConfigError> {
    let mut out = FileConfig::default();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let body = raw.split('#').next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        let (key, value) = body
            .split_once('=')
            .ok_or(ConfigError::MalformedLine { line })?;
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "auto_update" => {
                out.auto_update = Some(match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err(ConfigError::NotABool { line }),
                });
            }
            "update_host" => out.host = Some(value.to_owned()),
            "update_port" => {
                out.port = Some(value.parse().map_err(|_| ConfigError::NotAPort { line })?);
            }
            "update_public_key" => out.public_key = Some(value.to_owned()),
            "l3_model" => out.l3_model = Some(value.to_owned()),
            "l3_runtime" => out.l3_runtime = Some(value.to_owned()),
            _ => return Err(ConfigError::UnknownKey { line }),
        }
    }
    Ok(out)
}

/// A release manifest or config-shaped document, parsed into key/value pairs.
///
/// Shared with the update manifest deliberately: one parser, one set of tests,
/// and a wire format small enough that a reviewer can read a real manifest in
/// full. Reused rather than duplicated because two parsers drift.
pub fn parse_pairs(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in text.lines() {
        let body = raw.split('#').next().unwrap_or("").trim();
        if let Some((key, value)) = body.split_once('=') {
            out.insert(
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            );
        }
    }
    out
}

/// The resolved configuration this process runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// False when any layer of the precedence chain vetoed.
    pub auto_update: bool,
    /// Which layer vetoed, when one did.
    pub disabled_by: Option<DisabledBy>,
    /// Where to check. `None` disables the updater regardless of `auto_update`.
    pub endpoint: Option<Endpoint>,
    /// The pinned release signing key, base64. `None` forbids auto-install.
    pub public_key: Option<String>,
    /// First-run marker and staged downloads live here.
    pub state_dir: PathBuf,
    /// The hard ceiling on a check.
    pub timeout: Duration,
}

impl Config {
    /// True only when every layer agrees a check may happen.
    pub fn checks_allowed(&self) -> bool {
        self.auto_update && self.disabled_by.is_none() && self.endpoint.is_some()
    }
}

/// Apply the documented precedence.
pub fn resolve(cli: &CliFlags, env: &EnvView, file: &FileConfig) -> Config {
    // Ordered highest-precedence first; the first veto found is the one reported.
    let disabled_by = if cli.offline {
        Some(DisabledBy::CliFlag)
    } else if env.env_disables() {
        Some(DisabledBy::EnvVar)
    } else if file.auto_update == Some(false) {
        Some(DisabledBy::ConfigFile)
    } else {
        None
    };

    let endpoint = file.host.as_ref().map(|host| Endpoint {
        host: host.clone(),
        port: file.port.unwrap_or(DEFAULT_PORT),
    });

    Config {
        auto_update: disabled_by.is_none(),
        disabled_by,
        endpoint,
        public_key: file.public_key.clone(),
        state_dir: state_dir(env),
        timeout: CHECK_TIMEOUT,
    }
}

/// Where the first-run marker and staged downloads live.
fn state_dir(env: &EnvView) -> PathBuf {
    if let Some(explicit) = &env.state_dir {
        return PathBuf::from(explicit);
    }
    if let Some(xdg) = &env.xdg_state_home {
        return PathBuf::from(xdg).join("deid-tr");
    }
    match &env.home {
        Some(home) => PathBuf::from(home).join(".local/state/deid-tr"),
        // A process with no HOME (a locked-down service account) still needs
        // somewhere to record that it printed the notice. Falling back to the
        // working directory keeps the notice from repeating on every run.
        None => PathBuf::from(".deid-tr"),
    }
}

/// The config file path, honouring `DEID_CONFIG` then XDG then `HOME`.
pub fn config_path(env: &EnvView) -> Option<PathBuf> {
    if let Some(explicit) = &env.config_path {
        return Some(PathBuf::from(explicit));
    }
    if let Some(xdg) = &env.xdg_config_home {
        return Some(PathBuf::from(xdg).join("deid-tr/config.toml"));
    }
    env.home
        .as_ref()
        .map(|home| PathBuf::from(home).join(".config/deid-tr/config.toml"))
}

/// Read and parse the config file, treating "absent" as "empty".
pub fn load_file(env: &EnvView) -> Result<FileConfig, ConfigError> {
    let Some(path) = config_path(env) else {
        return Ok(FileConfig::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_file(&text),
        // An unreadable config file must not be a startup failure: the tool's
        // job is masking, and a permissions problem in a dotfile is not a reason
        // to refuse to de-identify a document.
        Err(_) => Ok(FileConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(no_update: Option<&str>) -> EnvView {
        EnvView {
            no_update: no_update.map(str::to_owned),
            home: Some("/home/tester".to_owned()),
            ..EnvView::default()
        }
    }

    fn configured() -> FileConfig {
        FileConfig {
            host: Some("releases.example.invalid".to_owned()),
            ..FileConfig::default()
        }
    }

    #[test]
    fn auto_update_is_on_by_default() {
        // The owner's choice, stated as an executable fact rather than a comment:
        // with nothing configured anywhere, checks are allowed.
        let config = resolve(&CliFlags::default(), &env_with(None), &configured());
        assert!(config.auto_update);
        assert_eq!(config.disabled_by, None);
        assert!(config.checks_allowed());
    }

    #[test]
    fn the_cli_flag_alone_disables_updates() {
        let config = resolve(
            &CliFlags { offline: true },
            &env_with(None),
            &FileConfig {
                auto_update: Some(true),
                ..configured()
            },
        );
        assert_eq!(config.disabled_by, Some(DisabledBy::CliFlag));
        assert!(!config.checks_allowed());
    }

    #[test]
    fn the_env_var_alone_disables_updates() {
        let config = resolve(
            &CliFlags::default(),
            &env_with(Some("1")),
            &FileConfig {
                auto_update: Some(true),
                ..configured()
            },
        );
        assert_eq!(config.disabled_by, Some(DisabledBy::EnvVar));
        assert!(!config.checks_allowed());
    }

    #[test]
    fn the_config_key_alone_disables_updates() {
        let config = resolve(
            &CliFlags::default(),
            &env_with(None),
            &FileConfig {
                auto_update: Some(false),
                ..configured()
            },
        );
        assert_eq!(config.disabled_by, Some(DisabledBy::ConfigFile));
        assert!(!config.checks_allowed());
    }

    #[test]
    fn no_layer_can_re_enable_what_a_lower_one_disabled() {
        // The one-way property: the file says on, the env says off, and the
        // result is off. There is no spelling of any input that reverses this.
        let config = resolve(
            &CliFlags::default(),
            &env_with(Some("yes")),
            &FileConfig {
                auto_update: Some(true),
                ..configured()
            },
        );
        assert!(!config.auto_update);
    }

    #[test]
    fn the_highest_precedence_veto_is_the_one_reported() {
        let config = resolve(
            &CliFlags { offline: true },
            &env_with(Some("1")),
            &FileConfig {
                auto_update: Some(false),
                ..configured()
            },
        );
        assert_eq!(config.disabled_by, Some(DisabledBy::CliFlag));
    }

    #[test]
    fn falsey_spellings_of_the_env_var_do_not_disable() {
        for raw in ["0", "false", "FALSE", " ", ""] {
            let config = resolve(&CliFlags::default(), &env_with(Some(raw)), &configured());
            assert!(config.auto_update, "{raw:?} should not disable");
        }
    }

    #[test]
    fn any_other_spelling_of_the_env_var_disables() {
        for raw in ["1", "yes", "please", "off", "true"] {
            let config = resolve(&CliFlags::default(), &env_with(Some(raw)), &configured());
            assert!(!config.auto_update, "{raw:?} should disable");
        }
    }

    #[test]
    fn an_unconfigured_endpoint_disables_checks_without_disabling_the_feature() {
        // Distinct states on purpose: the feature is on, but there is nowhere to
        // ask, so nothing is sent. `deid update` can then say which it is.
        let config = resolve(
            &CliFlags::default(),
            &env_with(None),
            &FileConfig::default(),
        );
        assert!(config.auto_update);
        assert!(!config.checks_allowed());
    }

    #[test]
    fn the_file_parses_the_documented_keys() {
        let parsed = parse_file(
            "# machine policy\nauto_update = false\nupdate_host = \"r.example.invalid\"\nupdate_port = 8443\nupdate_public_key = RWQf6\n",
        )
        .expect("valid config");
        assert_eq!(parsed.auto_update, Some(false));
        assert_eq!(parsed.host.as_deref(), Some("r.example.invalid"));
        assert_eq!(parsed.port, Some(8443));
        assert_eq!(parsed.public_key.as_deref(), Some("RWQf6"));
    }

    #[test]
    fn the_file_parses_the_l3_paths() {
        let parsed =
            parse_file("l3_model = \"/opt/m.gguf\"\nl3_runtime = \"/usr/bin/llama-cli\"\n")
                .expect("valid config");
        assert_eq!(parsed.l3_model.as_deref(), Some("/opt/m.gguf"));
        assert_eq!(parsed.l3_runtime.as_deref(), Some("/usr/bin/llama-cli"));
    }

    #[test]
    fn a_malformed_file_reports_a_line_number_and_no_content() {
        let err = parse_file("auto_update = maybe\n").expect_err("bad bool");
        assert_eq!(err, ConfigError::NotABool { line: 1 });
        assert!(
            !format!("{err}").contains("maybe"),
            "a config error must not echo the value back"
        );
        assert_eq!(
            parse_file("\n\nnonsense\n").expect_err("no equals"),
            ConfigError::MalformedLine { line: 3 }
        );
        assert_eq!(
            parse_file("auto_updates = true\n").expect_err("typo"),
            ConfigError::UnknownKey { line: 1 }
        );
        assert_eq!(
            parse_file("update_port = 70000\n").expect_err("out of range"),
            ConfigError::NotAPort { line: 1 }
        );
    }

    #[test]
    fn the_default_port_is_used_when_the_file_omits_it() {
        let config = resolve(&CliFlags::default(), &env_with(None), &configured());
        assert_eq!(
            config.endpoint.expect("endpoint").port,
            DEFAULT_PORT,
            "an omitted port must not silently become a plaintext one"
        );
    }

    #[test]
    fn the_state_directory_follows_the_documented_search_order() {
        let explicit = EnvView {
            state_dir: Some("/var/lib/deid".to_owned()),
            xdg_state_home: Some("/xdg".to_owned()),
            home: Some("/home/tester".to_owned()),
            ..EnvView::default()
        };
        assert_eq!(state_dir(&explicit), PathBuf::from("/var/lib/deid"));

        let xdg = EnvView {
            xdg_state_home: Some("/xdg".to_owned()),
            home: Some("/home/tester".to_owned()),
            ..EnvView::default()
        };
        assert_eq!(state_dir(&xdg), PathBuf::from("/xdg/deid-tr"));

        let home = EnvView {
            home: Some("/home/tester".to_owned()),
            ..EnvView::default()
        };
        assert_eq!(
            state_dir(&home),
            PathBuf::from("/home/tester/.local/state/deid-tr")
        );
    }
}
