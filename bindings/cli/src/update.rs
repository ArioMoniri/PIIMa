//! The auto-updater.
//!
//! # WHAT THIS COMPONENT SENDS — the complete list
//!
//! Two HTTP GET requests to the configured release host, and nothing else:
//!
//! 1. `GET /deid-tr/latest.manifest` and `GET /deid-tr/latest.manifest.minisig`
//! 2. `GET <artifact path named in the manifest>`, only if a newer version exists
//!
//! Every one of those is a static path. There is no query string, no request
//! body, no custom header carrying a value derived from this machine, and no
//! cookie jar. The version comparison happens LOCALLY against a static manifest,
//! which means the server is not told what version is running — strictly less
//! than the "current version only" this component was specified to send, and the
//! reason it is done this way.
//!
//! # WHAT THIS COMPONENT NEVER SENDS
//!
//! No document text. No span, offset, count, or label. No entity statistics. No
//! file names or paths. No install identifier, machine identifier, or generated
//! UUID. No operating system, architecture, locale, or hostname. No timing,
//! usage, feature, or error data. No crash reports. No cryptographic hash of
//! anything local.
//!
//! WHY this list is written out rather than summarised as "no telemetry": this
//! module is the only component in the product that is allowed to talk to the
//! network, so it is the single most plausible future home for a telemetry
//! regression, and every such regression arrives as a small reasonable-looking
//! addition. "We should know which platforms to build for" is an install-id.
//! "We should know if updates are failing" is an error beacon. Both are refused.
//! The server learns one thing it cannot avoid learning: that some IP address
//! fetched a static file. Reducing that further is impossible without abandoning
//! updates entirely, which is the trade recorded in docs/DECISIONS.md D-020.
//!
//! # WHEN IT RUNS
//!
//! At explicit process start for commands that do not touch documents, and on an
//! explicit `deid update`. Never during `deidentify()` and never on the `mask`
//! path — see `src/mask.rs`, which does not reference this module, and the
//! structural test in `tests/mask_path_is_offline.rs`, which fails if it ever
//! does. A network call made while a clinical note is resident in memory is the
//! exact shape of an exfiltration bug, so the defence is structural rather than
//! a matter of ordering statements correctly.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{Config, DisabledBy, Endpoint};
use crate::verify::{self, Action, Trust, VerifyError};

/// The static path of the release manifest on the configured host.
pub const MANIFEST_PATH: &str = "/deid-tr/latest.manifest";
/// The static path of the manifest's detached signature.
pub const SIGNATURE_PATH: &str = "/deid-tr/latest.manifest.minisig";

/// How long a detected air-gap suppresses further probing.
///
/// WHY suppression exists: constraint 4 says an air-gapped install must disable
/// itself QUIETLY rather than retry. Without this, a hospital with no egress pays
/// the timeout on every single invocation forever, which is both a startup tax
/// and a repeated outbound connection attempt that shows up in their firewall
/// logs as this tool trying to phone home. One failed probe buys a day of silence.
pub const SUPPRESSION: Duration = Duration::from_secs(24 * 60 * 60);

/// Why no check will be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// An off switch was thrown; which one is carried so the operator is told.
    Disabled(DisabledBy),
    /// No release host is configured, so there is nowhere to ask.
    NoEndpoint,
    /// A previous probe found no route out and suppression has not expired.
    AirGapSuppressed,
}

/// What a check concluded. Every variant is non-fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No check was attempted.
    Blocked(Blocked),
    /// The release host was unreachable. Detection, not an error.
    AirGapped,
    /// The host answered but the exchange failed. Silent and non-fatal.
    Unreachable,
    /// The running version is current, or newer than the manifest.
    UpToDate,
    /// Verified end to end and written over the running binary.
    Installed {
        /// The version now on disk.
        version: String,
    },
    /// Verified, written to the state directory, but activation failed.
    ///
    /// A separate state from [`Outcome::Installed`] because the difference
    /// matters to the operator: the bytes are trustworthy and present, and only
    /// the final move failed — typically a read-only install directory, which is
    /// how a packaged or containerised deployment is supposed to look.
    Staged {
        /// The version sitting in the state directory.
        version: String,
        /// Where it is, so the operator can move it themselves.
        path: PathBuf,
    },
    /// A newer version exists but this configuration may not install it.
    NotifyOnly {
        /// The version available.
        version: String,
        /// How far verification got.
        trust: Trust,
    },
    /// Verification failed. The download is discarded and nothing is installed.
    Refused(VerifyError),
}

/// A reachability probe, injected so tests never open a socket.
pub trait Reachability {
    /// True when a TCP connection to the endpoint completes within `timeout`.
    fn reachable(&self, endpoint: &Endpoint, timeout: Duration) -> bool;
}

/// Failure to complete an HTTP exchange. Deliberately opaque.
///
/// WHY there is one variant and it carries nothing: transport failures on this
/// path are all handled identically — stay quiet, do not retry, do not block —
/// so distinguishing them would produce information the caller must then be
/// trusted not to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release host exchange did not complete")]
pub struct TransportError;

/// The manifest and its detached signature, as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    /// The exact bytes the signature covers.
    pub bytes: Vec<u8>,
    /// The detached signature, absent when the host served none.
    pub signature: Option<String>,
}

/// Where releases are fetched from, injected so tests never open a socket.
pub trait ReleaseSource {
    /// Fetch the static manifest and its signature.
    fn manifest(
        &self,
        endpoint: &Endpoint,
        timeout: Duration,
    ) -> Result<SignedManifest, TransportError>;
    /// Fetch one artifact by the path the manifest named.
    fn artifact(
        &self,
        endpoint: &Endpoint,
        path: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError>;
}

/// The manifest fields this build understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The latest released version.
    pub version: String,
    /// Path of the artifact on the release host.
    pub artifact_path: String,
    /// Lowercase hex SHA-256 of the artifact.
    pub sha256: String,
}

impl Manifest {
    /// Parse the key=value manifest. Absent or empty fields are a parse failure.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let pairs = crate::config::parse_pairs(text);
        let take = |key: &str| pairs.get(key).filter(|v| !v.is_empty()).cloned();
        Some(Self {
            version: take("version")?,
            artifact_path: take("artifact_path")?,
            sha256: take("sha256")?,
        })
    }
}

/// Is `candidate` a strictly newer release than `current`?
///
/// WHY a downgrade is not an update: a release host that has been rolled back,
/// or an attacker who can serve an OLD signed manifest, would otherwise move
/// every install to a version with a known and published defect. Signature
/// verification does not help — the old manifest was genuinely signed.
pub fn is_newer(current: &str, candidate: &str) -> bool {
    let parts = |v: &str| {
        v.trim()
            .split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (current, candidate) = (parts(current), parts(candidate));
    let width = current.len().max(candidate.len());
    for index in 0..width {
        let left = current.get(index).copied().unwrap_or(0);
        let right = candidate.get(index).copied().unwrap_or(0);
        if right != left {
            return right > left;
        }
    }
    false
}

/// Decide whether a check may happen at all, without touching the network.
pub fn policy(config: &Config, now: SystemTime, state_dir: &Path) -> Result<Endpoint, Blocked> {
    if let Some(by) = config.disabled_by {
        return Err(Blocked::Disabled(by));
    }
    if !config.auto_update {
        return Err(Blocked::Disabled(DisabledBy::ConfigFile));
    }
    let endpoint = config.endpoint.clone().ok_or(Blocked::NoEndpoint)?;
    if air_gap_suppressed(state_dir, now) {
        return Err(Blocked::AirGapSuppressed);
    }
    Ok(endpoint)
}

/// The whole check, as a pure function of its injected collaborators.
///
/// `install_target` is the binary that a verified release replaces. It is a
/// parameter rather than `std::env::current_exe()` so the tests drive the real
/// staging and activation logic against a scratch file: a self-replacement path
/// exercised only in production is a path nobody has watched work.
pub fn run_check(
    config: &Config,
    current_version: &str,
    probe: &dyn Reachability,
    source: &dyn ReleaseSource,
    now: SystemTime,
    install_target: Option<&Path>,
) -> Outcome {
    let endpoint = match policy(config, now, &config.state_dir) {
        Ok(endpoint) => endpoint,
        Err(blocked) => return Outcome::Blocked(blocked),
    };

    if !probe.reachable(&endpoint, config.timeout) {
        // Quiet, non-fatal, and remembered so the next run does not pay for it.
        record_air_gap(&config.state_dir, now);
        return Outcome::AirGapped;
    }

    let Ok(signed) = source.manifest(&endpoint, config.timeout) else {
        return Outcome::Unreachable;
    };
    let Some(manifest) = Manifest::parse(&signed.bytes) else {
        return Outcome::Unreachable;
    };
    if !is_newer(current_version, &manifest.version) {
        return Outcome::UpToDate;
    }

    let Ok(artifact) = source.artifact(&endpoint, &manifest.artifact_path, config.timeout) else {
        return Outcome::Unreachable;
    };

    match verify::verify(
        &signed.bytes,
        signed.signature.as_deref(),
        config.public_key.as_deref(),
        &artifact,
        &manifest.sha256,
    ) {
        Err(err) => Outcome::Refused(err),
        Ok(trust) => match trust.action() {
            Action::NotifyOnly => Outcome::NotifyOnly {
                version: manifest.version,
                trust,
            },
            Action::Install => match stage(&config.state_dir, &manifest.version, &artifact) {
                // A staging failure is a local disk problem, not a security
                // event, and still must not be fatal to the command the operator
                // actually ran.
                Err(_) => Outcome::Unreachable,
                Ok(staged) => match install_target {
                    Some(target) if activate(&staged, target).is_ok() => Outcome::Installed {
                        version: manifest.version,
                    },
                    // Verified bytes that could not be moved into place are still
                    // verified bytes, and telling the operator where they are
                    // beats silently discarding a download they can use.
                    _ => Outcome::Staged {
                        version: manifest.version,
                        path: staged,
                    },
                },
            },
        },
    }
}

/// Write a VERIFIED artifact into the state directory, executable.
///
/// Staging and activation are separate steps on purpose: the bytes reach the
/// filesystem only after [`verify::verify`] returned [`Trust::Full`], and the
/// running binary is replaced only by [`activate`], which takes the staged path.
/// Nothing in this module can write an executable that has not been through the
/// verifier, because this is the only function that writes one and it is only
/// reachable from the `Action::Install` arm above.
pub fn stage(state_dir: &Path, version: &str, artifact: &[u8]) -> io::Result<PathBuf> {
    let dir = state_dir.join("staged");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("deid-{version}"));
    std::fs::write(&path, artifact)?;
    set_executable(&path)?;
    Ok(path)
}

/// Replace `target` with the staged artifact, keeping the previous binary.
///
/// `target` is a parameter rather than `current_exe()` so the tests exercise the
/// real replacement logic against a scratch file. A self-replacing code path that
/// is only ever run in production is a code path nobody has seen work.
pub fn activate(staged: &Path, target: &Path) -> io::Result<()> {
    let backup = target.with_extension("previous");
    if target.exists() {
        // Kept, not deleted: a rollback with no artifact to roll back to is a
        // reinstall over a network that may be the thing that broke.
        std::fs::rename(target, &backup)?;
    }
    // Rename rather than copy so an interrupted activation cannot leave a
    // half-written executable where a working one used to be.
    match std::fs::rename(staged, target) {
        Ok(()) => Ok(()),
        Err(err) => {
            // Cross-device rename is the ordinary failure here (state dir on a
            // different mount from the binary); fall back to copy, and restore
            // the backup if even that fails.
            if std::fs::copy(staged, target).is_ok() {
                set_executable(target)?;
                return Ok(());
            }
            if backup.exists() {
                std::fs::rename(&backup, target)?;
            }
            Err(err)
        }
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // 0o755: owner writes, everyone executes. Deliberately not 0o777.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn suppression_marker(state_dir: &Path) -> PathBuf {
    state_dir.join("air-gap-detected")
}

fn record_air_gap(state_dir: &Path, now: SystemTime) {
    let Ok(stamp) = now.duration_since(UNIX_EPOCH) else {
        return;
    };
    // Best effort: a read-only state directory must not turn a failed update
    // check into a failed command.
    let _ = std::fs::create_dir_all(state_dir);
    let _ = std::fs::write(suppression_marker(state_dir), stamp.as_secs().to_string());
}

fn air_gap_suppressed(state_dir: &Path, now: SystemTime) -> bool {
    let Ok(raw) = std::fs::read_to_string(suppression_marker(state_dir)) else {
        return false;
    };
    let Ok(recorded) = raw.trim().parse::<u64>() else {
        return false;
    };
    let Ok(stamp) = now.duration_since(UNIX_EPOCH) else {
        return false;
    };
    stamp.as_secs().saturating_sub(recorded) < SUPPRESSION.as_secs()
}

/// Clear the air-gap suppression so the next run probes again.
pub fn clear_air_gap(state_dir: &Path) {
    let _ = std::fs::remove_file(suppression_marker(state_dir));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CHECK_TIMEOUT;
    use crate::verify::sha256_hex;
    use minisign::KeyPair;
    use std::cell::Cell;
    use std::io::Cursor;

    struct Probe(bool);
    impl Reachability for Probe {
        fn reachable(&self, _endpoint: &Endpoint, _timeout: Duration) -> bool {
            self.0
        }
    }

    /// Counts fetches so "no packet was sent" can be asserted, not assumed.
    struct SpySource {
        manifest_bytes: Vec<u8>,
        signature: Option<String>,
        artifact: Vec<u8>,
        manifest_calls: Cell<usize>,
        artifact_calls: Cell<usize>,
    }

    impl ReleaseSource for SpySource {
        fn manifest(
            &self,
            _endpoint: &Endpoint,
            _timeout: Duration,
        ) -> Result<SignedManifest, TransportError> {
            self.manifest_calls.set(self.manifest_calls.get() + 1);
            Ok(SignedManifest {
                bytes: self.manifest_bytes.clone(),
                signature: self.signature.clone(),
            })
        }

        fn artifact(
            &self,
            _endpoint: &Endpoint,
            _path: &str,
            _timeout: Duration,
        ) -> Result<Vec<u8>, TransportError> {
            self.artifact_calls.set(self.artifact_calls.get() + 1);
            Ok(self.artifact.clone())
        }
    }

    const ARTIFACT: &[u8] = b"the 0.2.0 release binary";

    fn manifest_bytes(version: &str, sha256: &str) -> Vec<u8> {
        format!("version = {version}\nartifact_path = /deid-tr/0.2.0/deid\nsha256 = {sha256}\n")
            .into_bytes()
    }

    fn source(bytes: Vec<u8>, signature: Option<String>, artifact: Vec<u8>) -> SpySource {
        SpySource {
            manifest_bytes: bytes,
            signature,
            artifact,
            manifest_calls: Cell::new(0),
            artifact_calls: Cell::new(0),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deid-update-{name}-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn config(state_dir: PathBuf, public_key: Option<String>) -> Config {
        Config {
            auto_update: true,
            disabled_by: None,
            endpoint: Some(Endpoint {
                host: "releases.example.invalid".to_owned(),
                port: 443,
            }),
            public_key,
            state_dir,
            timeout: CHECK_TIMEOUT,
        }
    }

    fn signed_pair(bytes: &[u8]) -> (String, String) {
        let pair = KeyPair::generate_unencrypted_keypair().expect("keypair");
        let signature =
            minisign::sign(None, &pair.sk, Cursor::new(bytes), None, None).expect("sign");
        (pair.pk.to_base64(), signature.into_string())
    }

    #[test]
    fn an_unreachable_host_disables_the_check_quietly_and_sends_nothing() {
        // Air-gap detection: the probe fails, and the release source is never
        // asked, so no HTTP request leaves the machine.
        let dir = scratch("airgap");
        let src = source(manifest_bytes("0.2.0", "x"), None, ARTIFACT.to_vec());
        let outcome = run_check(
            &config(dir.clone(), None),
            "0.1.0",
            &Probe(false),
            &src,
            SystemTime::now(),
            None,
        );
        assert_eq!(outcome, Outcome::AirGapped);
        assert_eq!(src.manifest_calls.get(), 0);
        assert_eq!(src.artifact_calls.get(), 0);
    }

    #[test]
    fn a_detected_air_gap_suppresses_the_next_probe_entirely() {
        // Constraint 4: disable quietly rather than retry. The second run does
        // not even reach the probe, so a hospital firewall sees one attempt a
        // day rather than one per invocation.
        let dir = scratch("suppress");
        let src = source(manifest_bytes("0.2.0", "x"), None, ARTIFACT.to_vec());
        let cfg = config(dir.clone(), None);
        let now = SystemTime::now();
        assert_eq!(
            run_check(&cfg, "0.1.0", &Probe(false), &src, now, None),
            Outcome::AirGapped
        );
        assert_eq!(
            run_check(&cfg, "0.1.0", &Probe(true), &src, now, None),
            Outcome::Blocked(Blocked::AirGapSuppressed),
            "a live probe must not even be attempted while suppression holds"
        );
        assert_eq!(src.manifest_calls.get(), 0);

        // And it expires rather than disabling updates forever.
        let later = now + SUPPRESSION + Duration::from_secs(1);
        assert!(!matches!(
            run_check(&cfg, "0.1.0", &Probe(true), &src, later, None),
            Outcome::Blocked(Blocked::AirGapSuppressed)
        ));
    }

    #[test]
    fn each_off_switch_stops_the_check_before_any_probe() {
        let dir = scratch("switches");
        let src = source(manifest_bytes("0.2.0", "x"), None, ARTIFACT.to_vec());
        for by in [
            DisabledBy::CliFlag,
            DisabledBy::EnvVar,
            DisabledBy::ConfigFile,
        ] {
            let mut cfg = config(dir.clone(), None);
            cfg.auto_update = false;
            cfg.disabled_by = Some(by);
            assert_eq!(
                run_check(&cfg, "0.1.0", &Probe(true), &src, SystemTime::now(), None),
                Outcome::Blocked(Blocked::Disabled(by))
            );
        }
        assert_eq!(
            src.manifest_calls.get(),
            0,
            "a disabled updater sent a request"
        );
    }

    #[test]
    fn an_unconfigured_endpoint_blocks_the_check() {
        let dir = scratch("noendpoint");
        let mut cfg = config(dir, None);
        cfg.endpoint = None;
        let src = source(manifest_bytes("0.2.0", "x"), None, ARTIFACT.to_vec());
        assert_eq!(
            run_check(&cfg, "0.1.0", &Probe(true), &src, SystemTime::now(), None),
            Outcome::Blocked(Blocked::NoEndpoint)
        );
    }

    #[test]
    fn a_checksum_mismatch_refuses_to_install() {
        let dir = scratch("badsum");
        let bytes = manifest_bytes("0.2.0", &sha256_hex(b"a different artifact"));
        let (key, signature) = signed_pair(&bytes);
        let src = source(bytes, Some(signature), ARTIFACT.to_vec());
        let outcome = run_check(
            &config(dir.clone(), Some(key)),
            "0.1.0",
            &Probe(true),
            &src,
            SystemTime::now(),
            None,
        );
        assert_eq!(outcome, Outcome::Refused(VerifyError::ChecksumMismatch));
        assert!(
            !dir.join("staged").exists(),
            "a refused artifact must never reach the filesystem"
        );
    }

    #[test]
    fn a_verified_release_replaces_the_binary_and_keeps_a_rollback() {
        let dir = scratch("install");
        let target = dir.join("deid");
        std::fs::write(&target, b"the old binary").expect("seed target");

        let bytes = manifest_bytes("0.2.0", &sha256_hex(ARTIFACT));
        let (key, signature) = signed_pair(&bytes);
        let src = source(bytes, Some(signature), ARTIFACT.to_vec());
        let outcome = run_check(
            &config(dir.clone(), Some(key)),
            "0.1.0",
            &Probe(true),
            &src,
            SystemTime::now(),
            Some(&target),
        );
        assert_eq!(
            outcome,
            Outcome::Installed {
                version: "0.2.0".to_owned()
            }
        );
        assert_eq!(std::fs::read(&target).expect("new binary"), ARTIFACT);
        assert_eq!(
            std::fs::read(dir.join("deid.previous")).expect("backup"),
            b"the old binary",
            "the replaced binary must remain rollback-able"
        );
    }

    #[test]
    fn a_verified_release_with_nowhere_to_install_stays_staged() {
        // A packaged or read-only deployment. The bytes are trustworthy, so they
        // are kept and their location reported rather than silently discarded.
        let dir = scratch("staged");
        let bytes = manifest_bytes("0.2.0", &sha256_hex(ARTIFACT));
        let (key, signature) = signed_pair(&bytes);
        let src = source(bytes, Some(signature), ARTIFACT.to_vec());
        assert_eq!(
            run_check(
                &config(dir.clone(), Some(key)),
                "0.1.0",
                &Probe(true),
                &src,
                SystemTime::now(),
                None,
            ),
            Outcome::Staged {
                version: "0.2.0".to_owned(),
                path: dir.join("staged/deid-0.2.0"),
            }
        );
    }

    #[test]
    fn without_a_pinned_key_a_new_release_notifies_and_never_installs() {
        // The shipped default until the project owner pins a release key.
        let dir = scratch("nokey");
        let bytes = manifest_bytes("0.2.0", &sha256_hex(ARTIFACT));
        let src = source(bytes, None, ARTIFACT.to_vec());
        let outcome = run_check(
            &config(dir.clone(), None),
            "0.1.0",
            &Probe(true),
            &src,
            SystemTime::now(),
            None,
        );
        assert_eq!(
            outcome,
            Outcome::NotifyOnly {
                version: "0.2.0".to_owned(),
                trust: Trust::ChecksumOnlyNoPinnedKey,
            }
        );
        assert!(!dir.join("staged").exists());
    }

    #[test]
    fn a_current_or_older_manifest_never_downloads_an_artifact() {
        let dir = scratch("uptodate");
        for version in ["0.1.0", "0.0.9"] {
            let src = source(
                manifest_bytes(version, &sha256_hex(ARTIFACT)),
                None,
                ARTIFACT.to_vec(),
            );
            assert_eq!(
                run_check(
                    &config(dir.clone(), None),
                    "0.1.0",
                    &Probe(true),
                    &src,
                    SystemTime::now(),
                    None,
                ),
                Outcome::UpToDate
            );
            assert_eq!(
                src.artifact_calls.get(),
                0,
                "a downgrade must not even be downloaded"
            );
        }
    }

    #[test]
    fn version_ordering_is_numeric_not_lexicographic() {
        assert!(is_newer("0.9.0", "0.10.0"));
        assert!(!is_newer("0.10.0", "0.9.0"));
        assert!(!is_newer("1.2.3", "1.2.3"));
        assert!(is_newer("1.2.3", "1.2.4"));
        assert!(!is_newer("1.2", "1.2.0"));
    }

    #[test]
    fn a_malformed_manifest_is_silent_and_non_fatal() {
        let dir = scratch("garbage");
        let src = source(b"<html>404</html>".to_vec(), None, ARTIFACT.to_vec());
        assert_eq!(
            run_check(
                &config(dir, None),
                "0.1.0",
                &Probe(true),
                &src,
                SystemTime::now(),
                None,
            ),
            Outcome::Unreachable
        );
    }
}
