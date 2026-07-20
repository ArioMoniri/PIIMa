//! The only socket in the product.
//!
//! Everything network-capable in `deid-tr` is in this file and reachable only
//! from `src/update.rs`. `core/` cannot compile a socket (I1); `src/mask.rs` does
//! not reference this module; the structural test in
//! `tests/mask_path_is_offline.rs` fails if that changes.
//!
//! WHY the scheme and the host are assembled rather than written as one literal:
//! there is no release host compiled into this binary. The host comes from the
//! operator's config file, because a placeholder domain baked into a release is a
//! domain somebody else can register, and because the shipped default is to have
//! nowhere to ask. `scripts/hooks/guard_invariants.sh` blocks remote `https` URL
//! literals repository-wide to keep the L3 contextual layer local, and this file
//! genuinely contains no remote host to block — but the assembly below is the
//! shape a reviewer should look at twice, which is why it is called out here and
//! recorded in docs/DECISIONS.md D-020.

use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::config::Endpoint;
use crate::update::{
    Reachability, ReleaseSource, SignedManifest, TransportError, MANIFEST_PATH, SIGNATURE_PATH,
};

/// TLS is not optional and is not configurable.
const SCHEME: &str = "https";

/// Manifests are three short lines; anything larger is not our manifest.
const MANIFEST_LIMIT: u64 = 8 * 1024;
/// A ceiling on a release artifact, so a hostile or broken host cannot fill the
/// disk of a machine whose disk holds clinical records.
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;

/// The real reachability probe: one TCP connect, hard-bounded.
///
/// WHY a TCP connect rather than an HTTP request as the air-gap test: a
/// restricted hospital network usually blackholes packets rather than refusing
/// them, so the distinguishing signal is a connect that does not complete. This
/// costs one SYN and tells us to stay quiet for a day (see `update::SUPPRESSION`)
/// instead of paying a full TLS handshake timeout on every invocation.
pub struct TcpProbe<D = SystemDialer> {
    dialer: D,
}

impl TcpProbe<SystemDialer> {
    /// The probe as shipped: the operating system's resolver and a real socket.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dialer: SystemDialer,
        }
    }
}

impl Default for TcpProbe<SystemDialer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Dial> Reachability for TcpProbe<D> {
    fn reachable(&self, endpoint: &Endpoint, timeout: Duration) -> bool {
        let Some(addrs) = self.dialer.resolve(&endpoint.host, endpoint.port) else {
            // DNS failure is the most common air-gap signature of all.
            return false;
        };
        addrs
            .into_iter()
            .any(|addr| self.dialer.connect(addr, timeout))
    }
}

/// Name resolution and connection, as two steps this crate can substitute.
///
/// WHY this is a seam and not two inlined stdlib calls: the unresolvable-host
/// test used to hand a `.invalid` name to the SYSTEM resolver and assert a
/// wall-clock budget. That budget measures whatever DNS the machine happens to
/// be pointed at — a captive portal, a VPN resolver mid-reconnect, a cold cache
/// — none of which is a property of this code, and one run in four went red for
/// it. A release gate that flakes is a gate people learn to re-run rather than
/// read, and this one guards I1. The BEHAVIOUR that matters — a name that does
/// not resolve is reported unreachable and no connection is attempted, and the
/// caller's timeout reaches the socket unchanged — is asserted here against a
/// substituted dialer, with no clock and no packet involved.
pub trait Dial {
    /// The addresses to try, or `None` when the name does not resolve.
    fn resolve(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>>;
    /// True when a connection completes inside `timeout`.
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> bool;
}

/// The real one: the OS resolver and one bounded TCP connect.
pub struct SystemDialer;

impl Dial for SystemDialer {
    fn resolve(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().ok().map(Iterator::collect)
    }

    fn connect(&self, addr: SocketAddr, timeout: Duration) -> bool {
        TcpStream::connect_timeout(&addr, timeout).is_ok()
    }
}

/// The real release source: two GETs, no query strings, no request body.
pub struct HttpsSource;

impl HttpsSource {
    fn get(
        endpoint: &Endpoint,
        path: &str,
        timeout: Duration,
        limit: u64,
    ) -> Result<Vec<u8>, TransportError> {
        let url = format!(
            "{SCHEME}://{host}:{port}{path}",
            host = endpoint.host,
            port = endpoint.port
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // A redirect is an instruction from the network to fetch something
            // else from somewhere else. On the one path in this product that
            // downloads executable bytes, that instruction is refused.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| TransportError)?;

        let response = client.get(&url).send().map_err(|_| TransportError)?;
        if !response.status().is_success() {
            return Err(TransportError);
        }
        let mut body = Vec::new();
        // `take` bounds the read itself rather than trusting Content-Length,
        // which the server chooses.
        response
            .take(limit)
            .read_to_end(&mut body)
            .map_err(|_| TransportError)?;
        Ok(body)
    }
}

impl ReleaseSource for HttpsSource {
    fn manifest(
        &self,
        endpoint: &Endpoint,
        timeout: Duration,
    ) -> Result<SignedManifest, TransportError> {
        let bytes = Self::get(endpoint, MANIFEST_PATH, timeout, MANIFEST_LIMIT)?;
        // A missing signature is not a transport failure: the verifier decides
        // what an unsigned manifest is worth, and it decides "not installable".
        let signature = Self::get(endpoint, SIGNATURE_PATH, timeout, MANIFEST_LIMIT)
            .ok()
            .and_then(|raw| String::from_utf8(raw).ok());
        Ok(SignedManifest { bytes, signature })
    }

    fn artifact(
        &self,
        endpoint: &Endpoint,
        path: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        // The path comes from a manifest whose signature has NOT been checked
        // yet, so it is treated as hostile input: absolute, no traversal, no
        // authority section that would move the request to another host.
        if !path.starts_with('/') || path.contains("..") || path.starts_with("//") {
            return Err(TransportError);
        }
        Self::get(endpoint, path, timeout, ARTIFACT_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn endpoint() -> Endpoint {
        Endpoint {
            // RFC 2606 reserves `.invalid`, so this name can never resolve and
            // the test cannot accidentally reach a real host.
            host: "releases.example.invalid".to_owned(),
            port: 443,
        }
    }

    /// A dialer that resolves to a fixed answer and records what it was asked to
    /// connect to. Nothing here touches DNS or a socket, so the assertions below
    /// hold identically on a laptop, in CI and inside `unshare -rn`.
    struct FakeDialer {
        answer: Option<Vec<SocketAddr>>,
        succeed_on: Option<SocketAddr>,
        attempts: RefCell<Vec<(SocketAddr, Duration)>>,
    }

    impl FakeDialer {
        fn resolving_to(answer: Option<Vec<SocketAddr>>) -> Self {
            Self {
                answer,
                succeed_on: None,
                attempts: RefCell::new(Vec::new()),
            }
        }
    }

    impl Dial for FakeDialer {
        fn resolve(&self, _host: &str, _port: u16) -> Option<Vec<SocketAddr>> {
            self.answer.clone()
        }

        fn connect(&self, addr: SocketAddr, timeout: Duration) -> bool {
            self.attempts.borrow_mut().push((addr, timeout));
            self.succeed_on == Some(addr)
        }
    }

    fn addr(last: u8) -> SocketAddr {
        // TEST-NET-1 (RFC 5737): documentation-only, never routed.
        SocketAddr::from(([192, 0, 2, last], 443))
    }

    #[test]
    fn an_unresolvable_host_reads_as_unreachable_and_opens_no_socket() {
        let probe = TcpProbe {
            dialer: FakeDialer::resolving_to(None),
        };
        assert!(!probe.reachable(&endpoint(), Duration::from_millis(200)));
        assert!(
            probe.dialer.attempts.borrow().is_empty(),
            "a name that does not resolve must not become a connect attempt"
        );
    }

    #[test]
    fn the_callers_timeout_reaches_every_connect_unchanged() {
        // The startup delay this bounds is the sum of the per-address timeouts,
        // so a probe that silently widened or dropped the caller's budget would
        // be the actual hang the old test was reaching for.
        let budget = Duration::from_millis(200);
        let probe = TcpProbe {
            dialer: FakeDialer::resolving_to(Some(vec![addr(1), addr(2)])),
        };
        assert!(!probe.reachable(&endpoint(), budget));
        assert_eq!(
            *probe.dialer.attempts.borrow(),
            vec![(addr(1), budget), (addr(2), budget)]
        );
    }

    #[test]
    fn a_host_that_answers_on_a_later_address_is_reachable() {
        let mut dialer = FakeDialer::resolving_to(Some(vec![addr(1), addr(2)]));
        dialer.succeed_on = Some(addr(2));
        let probe = TcpProbe { dialer };
        assert!(probe.reachable(&endpoint(), Duration::from_millis(200)));
    }

    #[test]
    fn an_artifact_path_that_could_leave_the_configured_host_is_refused() {
        // The manifest is unverified at the moment this path is read, so these
        // are the shapes an attacker would put in it.
        for hostile in [
            "//evil.example.invalid/payload",
            "/releases/../../etc/passwd",
            "releases/deid",
        ] {
            assert_eq!(
                HttpsSource.artifact(&endpoint(), hostile, Duration::from_millis(1)),
                Err(TransportError),
                "{hostile} was not refused"
            );
        }
    }
}
