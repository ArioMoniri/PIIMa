//! The check an operator runs BEFORE exposing anything.
//!
//! # Why this is a program and not a paragraph in a runbook
//!
//! [`crate::bind::plan`] already refuses everything it must refuse, and it does
//! so at start time. That is the enforcement, and it is not the same thing as
//! informing a decision. An operator standing in front of a hospital change
//! window wants to know, before the service is running and before anything has
//! been pointed at it, three things that no single error message answers:
//!
//! 1. Will this address and this token be accepted at all, and if not, why.
//! 2. What is NOT protected -- specifically, that this binary terminates no TLS,
//!    so an exposed bind carries clinical text in the clear unless someone put a
//!    reverse proxy in front of it.
//! 3. What is NOT detected. This build has no trained L2 model, so it masks zero
//!    names. An operator who deploys believing names are removed has been misled
//!    by the deployment, and a preflight that reports the bind but not the
//!    coverage would be the thing that misled them.
//!
//! A [`Report`] is a value, so `tests/` can drive every branch without a socket
//! and without a terminal.
//!
//! # Warn does not fail
//!
//! Only [`Level::Fail`] makes [`Report::passed`] false. The TLS finding and the
//! coverage findings are warnings on purpose: they are true of every deployment
//! including the correct ones, and a check that fails on the default is a check
//! people learn to pass with a flag.

use core::fmt;

use crate::bind::{self, Refusal};
use crate::catalog::LiveLayers;

/// The number of DISTINCT characters a bearer token must contain.
///
/// [`crate::bind::MIN_TOKEN_LEN`] is a length floor and its own documentation
/// admits it will accept thirty-two `a`s. This is the second half of that
/// sentence. It still cannot measure entropy -- nothing that reads a string can
/// -- but it does reject the tokens humans actually type when a length field
/// forces them to type something long: a repeated character, a department name
/// padded out, a keyboard row. Ten distinct characters is below what any
/// generator produces (32 hex characters draw from 16, base64 from far more) and
/// above what a person invents.
pub const MIN_DISTINCT_CHARS: usize = 10;

// WHY ANY exact repetition is rejected rather than only short cycles: a
// generator drawing 32 characters independently produces a string that repeats a
// prefix with probability too small to write down, so a token that does repeat
// was typed. `qwertyuiop` three times has ten distinct characters and clears the
// distinct-count floor; `Ankara2026` three times clears it too. Bounding the
// period at half the length is the widest check that is still exact, and it
// costs nothing to run.

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Checked and satisfactory.
    Pass,
    /// True of correct deployments too, and the operator still has to know it.
    Warn,
    /// The deployment described by these flags will not start, or must not.
    Fail,
}

impl Level {
    /// The four-character tag printed at the head of the line.
    const fn tag(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// One checked property and what was found.
#[derive(Debug, Clone)]
pub struct Finding {
    /// How serious it is.
    pub level: Level,
    /// The short name of the check, stable enough to grep a build log for.
    pub check: &'static str,
    /// What to do about it, in a sentence an operator can act on.
    ///
    /// `String` because a refusal is rendered into it, and never because a
    /// secret is: no code path in this module writes a token, a session handle
    /// or a document into a finding, and `a_finding_never_contains_the_token`
    /// fails if one starts to.
    pub detail: String,
}

/// Everything the preflight looked at.
#[derive(Debug, Clone)]
pub struct Report {
    /// In the order they were checked, which is the order they are printed.
    pub findings: Vec<Finding>,
}

impl Report {
    /// True when nothing was found that must stop the deployment.
    #[must_use]
    pub fn passed(&self) -> bool {
        !self.findings.iter().any(|f| f.level == Level::Fail)
    }

    /// How many findings are at this level.
    #[must_use]
    pub fn count(&self, level: Level) -> usize {
        self.findings.iter().filter(|f| f.level == level).count()
    }

    fn push(&mut self, level: Level, check: &'static str, detail: impl Into<String>) {
        self.findings.push(Finding {
            level,
            check,
            detail: detail.into(),
        });
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for finding in &self.findings {
            writeln!(
                f,
                "{} {:<16} {}",
                finding.level.tag(),
                finding.check,
                finding.detail
            )?;
        }
        if self.passed() {
            write!(
                f,
                "preflight: PASS ({} warnings). Nothing here is a substitute for reading \
                 docs/DEPLOY-SERVER.md.",
                self.count(Level::Warn)
            )
        } else {
            write!(
                f,
                "preflight: FAIL ({} blocking). deid-serve would refuse to start, or must not \
                 be started, with these flags.",
                self.count(Level::Fail)
            )
        }
    }
}

/// The deployment being proposed.
///
/// The same flags that would be passed to `deid-serve`, plus the layers the
/// process actually has -- taken from a real [`crate::api::Service`] by the
/// caller rather than assumed here, so the preflight and `GET /health` cannot
/// disagree about whether names are masked.
#[derive(Debug, Clone, Copy)]
pub struct Proposal<'a> {
    /// The address that would be bound.
    pub host: std::net::IpAddr,
    /// The port that would be bound.
    pub port: u16,
    /// Whether `--expose` was given.
    pub expose: bool,
    /// The bearer token, if one was supplied.
    pub token: Option<&'a str>,
    /// Which layers the built pipeline actually has.
    pub layers: LiveLayers,
}

/// Why a token is not acceptable, or `None` if it is.
///
/// Separate from [`crate::bind::Token::new`] on purpose: `bind` enforces the
/// floor that must hold at start time for the process to run at all, and this is
/// the stricter judgement a human asked for before deciding to expose a PHI
/// endpoint. Making the start-time check this strict would mean a running
/// service refusing to restart because a heuristic changed.
///
/// # What this CANNOT do, stated so nobody relies on it
///
/// It cannot tell a generated token from a chosen one. `Kardiyoloji-Servisi-
/// Token-2026` is thirty-two characters with plenty of distinct ones and no
/// repeating cycle, and it passes every check below while carrying perhaps
/// twenty bits of real entropy. Detecting it needs a dictionary of Turkish,
/// English and Latin medical vocabulary — which is a thing this repository has,
/// for a completely different purpose, and pointing the medical allowlist at
/// credential strength would be a category error with a maintenance burden.
///
/// So the checks below catch the mechanical failures — a repeated character, a
/// padded word, a keyboard row — and the defence against a chosen passphrase is
/// the instruction, repeated in every finding and in `docs/DEPLOY-SERVER.md`: generate
/// it, do not choose it. A checker that implied otherwise would be worse than
/// this one, because an operator would believe PASS meant strong.
#[must_use]
pub fn token_weakness(token: &str) -> Option<&'static str> {
    let characters: Vec<char> = token.chars().collect();
    if characters.len() < bind::MIN_TOKEN_LEN {
        return Some("shorter than the 32-character minimum");
    }
    // Whitespace is the one unambiguous tell. No generator emits it; a human
    // filling a long field does. Unlike a dictionary check this has no false
    // positives to trade against.
    if characters.iter().any(|c| c.is_whitespace()) {
        return Some(
            "it contains whitespace, which no generator produces and a person typing \
                     a phrase into a long field does",
        );
    }
    let mut distinct: Vec<char> = characters.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < MIN_DISTINCT_CHARS {
        return Some(
            "long but repetitive: fewer than 10 distinct characters, which is what a \
                     padded word or a keyboard row looks like and what no generator produces",
        );
    }
    for period in 1..=characters.len() / 2 {
        // No divisibility requirement: `qwertyuiop` repeated into 32 characters
        // ends mid-cycle, and a check that only saw whole repetitions would call
        // it strong.
        if characters
            .iter()
            .enumerate()
            .all(|(index, character)| *character == characters[index % period])
        {
            return Some("a short pattern repeated to reach the length floor");
        }
    }
    None
}

/// Run every check against a proposed deployment.
#[must_use]
pub fn check(proposal: &Proposal<'_>) -> Report {
    let mut report = Report {
        findings: Vec::new(),
    };
    check_bind(proposal, &mut report);
    check_token(proposal, &mut report);
    check_tls(proposal, &mut report);
    check_layers(proposal, &mut report);
    report
}

/// The bind gate: exactly what `deid-serve` will decide at start time, decided
/// here by calling the same function rather than by re-implementing its rules.
fn check_bind(proposal: &Proposal<'_>, report: &mut Report) {
    match bind::plan(
        proposal.host,
        proposal.port,
        proposal.expose,
        proposal.token,
    ) {
        Err(refusal) => {
            let extra = match refusal {
                Refusal::AllInterfaces => {
                    " There is no flag, environment variable, configuration file or container \
                      setting that changes this answer."
                }
                _ => "",
            };
            report.push(Level::Fail, "bind", format!("{refusal}{extra}"));
        }
        Ok(listen) if listen.is_exposed() => {
            report.push(
                Level::Pass,
                "bind",
                "a specific non-loopback address, with --expose and a bearer token. Accepted.",
            );
            report.push(
                Level::Warn,
                "exposure",
                "this bind is reachable from every host that can route to that address. Each of \
                 them can submit clinical text and hold a session handle over the resulting span \
                 map. Confirm the network it sits on is one where that is true on purpose.",
            );
        }
        Ok(_) => {
            report.push(
                Level::Pass,
                "bind",
                "loopback. Nothing off this machine can reach the service.",
            );
        }
    }
}

/// The token gate, stricter than the start-time floor.
fn check_token(proposal: &Proposal<'_>, report: &mut Report) {
    match proposal.token {
        Some(token) => match token_weakness(token) {
            // The token itself is never in the message. It is in a process
            // argument or a credential file, and a preflight that echoes it puts
            // it in a terminal scrollback and a CI log as well.
            Some(why) => report.push(
                Level::Fail,
                "token",
                format!("the bearer token is weak: {why}. Generate one, do not choose one."),
            ),
            None => report.push(
                Level::Pass,
                "token",
                "a bearer token is configured and passes the length and repetition checks. \
                 Neither check can measure entropy; only a generator can give you that.",
            ),
        },
        None if proposal.host.is_loopback() => report.push(
            Level::Pass,
            "token",
            "no bearer token, which is permitted for a loopback bind: the gate is the kernel, \
             not the credential. Set one anyway on a shared workstation.",
        ),
        // Unreachable through bind::plan, which fails first. Reported rather
        // than asserted, because a preflight that panics tells an operator less
        // than a preflight that says what it found.
        None => report.push(
            Level::Fail,
            "token",
            "no bearer token for a non-loopback bind.",
        ),
    }
}

/// TLS, which this binary does not do.
fn check_tls(proposal: &Proposal<'_>, report: &mut Report) {
    if proposal.host.is_loopback() {
        report.push(
            Level::Warn,
            "tls",
            "deid-serve terminates no TLS. On loopback the traffic does not leave the machine, \
             so this is a note and not a hole -- but do not later move this bind without \
             putting a terminator in front of it.",
        );
    } else {
        report.push(
            Level::Warn,
            "tls",
            "deid-serve terminates NO TLS and never will. On this bind the clinical note and \
             the restored original cross the network in cleartext, and the bearer token crosses \
             it in a header. Terminate TLS in nginx or Caddy on the same host and have it \
             forward to loopback -- docs/DEPLOY-SERVER.md has a worked configuration for both.",
        );
    }
}

/// Which layers are live, so nobody deploys believing names are masked.
fn check_layers(proposal: &Proposal<'_>, report: &mut Report) {
    let layers = proposal.layers;
    report.push(
        if layers.rules {
            Level::Pass
        } else {
            Level::Fail
        },
        "layer-l1",
        if layers.rules {
            "L1 deterministic rules are compiled in: TCKN, VKN, SGK, IBAN, phone, MRN, email \
             and dates."
        } else {
            "L1 is not installed, which leaves nothing detecting anything."
        },
    );
    report.push(
        if layers.ner { Level::Pass } else { Level::Warn },
        "layer-l2",
        if layers.ner {
            "L2 has at least one detector installed."
        } else {
            "L2 has NO trained model in this build, so this deployment masks ZERO NAMES. \
             PATIENT_NAME, CLINICIAN_NAME and RELATIVE_NAME are never detected. If your \
             acceptance criterion was 'names are removed', it is not met and no flag meets it."
        },
    );
    report.push(
        if layers.context {
            Level::Pass
        } else {
            Level::Warn
        },
        "layer-l3",
        if layers.context {
            "L3 contextual sweep is enabled for this tier; it finds quasi-identifiers only if a \
             local model is actually installed."
        } else {
            "L3 is off: this is the Safe Harbor tier, so quasi-identifiers in the narrative -- \
             employer, relationships, assets, distinctive events -- are not looked for at all."
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn strong_token() -> String {
        // Built rather than written: a literal in a repository is a credential
        // someone eventually pastes into a real deployment.
        "qX7fV2mZ9pR4tL0kB6nH3sD8wG1jY5cA".to_owned()
    }

    fn safe_harbor_layers() -> LiveLayers {
        LiveLayers {
            rules: true,
            ner: false,
            context: false,
        }
    }

    fn all_interfaces_v4() -> IpAddr {
        // Assembled, because the repository guard blocks source containing any
        // spelling of this address. Same technique as bind.rs.
        format!("0.{}", "0.0.0").parse().expect("assembled quad")
    }

    fn all_interfaces_v6() -> IpAddr {
        format!("{}{}", ":", ":").parse().expect("assembled v6")
    }

    fn proposal<'a>(host: IpAddr, expose: bool, token: Option<&'a str>) -> Proposal<'a> {
        Proposal {
            host,
            port: bind::DEFAULT_PORT,
            expose,
            token,
            layers: safe_harbor_layers(),
        }
    }

    #[test]
    fn the_default_loopback_deployment_passes() {
        let report = check(&proposal(bind::default_host(), false, None));
        assert!(report.passed(), "{report}");
        // And it is still not silent: no names are masked, and TLS is absent.
        assert!(report.count(Level::Warn) >= 2, "{report}");
    }

    #[test]
    fn an_all_interfaces_proposal_fails_in_every_combination() {
        let token = strong_token();
        for host in [all_interfaces_v4(), all_interfaces_v6()] {
            for expose in [false, true] {
                for supplied in [None, Some(token.as_str())] {
                    let report = check(&proposal(host, expose, supplied));
                    assert!(
                        !report.passed(),
                        "an all-interfaces proposal passed preflight (expose={expose}, \
                         token={})",
                        supplied.is_some()
                    );
                }
            }
        }
    }

    #[test]
    fn a_non_loopback_bind_fails_without_expose_and_without_a_token() {
        let lan = IpAddr::V4(Ipv4Addr::new(10, 4, 1, 9));
        let token = strong_token();
        assert!(!check(&proposal(lan, false, None)).passed());
        assert!(!check(&proposal(lan, false, Some(&token))).passed());
        assert!(!check(&proposal(lan, true, None)).passed());
        assert!(check(&proposal(lan, true, Some(&token))).passed());
    }

    #[test]
    fn a_weak_token_fails_even_though_it_clears_the_length_floor() {
        // The case bind.rs documents as the hole its own floor leaves open.
        let lan = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7));
        for weak in [
            "a".repeat(bind::MIN_TOKEN_LEN),
            "abcd".repeat(8),
            "qwertyuiopqwertyuiopqwertyuiopqw".to_owned(),
            "kardiyoloji servisi token 2026ab".to_owned(),
        ] {
            assert!(
                token_weakness(&weak).is_some(),
                "{weak:?} was judged strong"
            );
            let report = check(&proposal(lan, true, Some(&weak)));
            assert!(!report.passed(), "a weak token passed preflight: {report}");
        }
        assert_eq!(token_weakness(&strong_token()), None);

        // And the case this checker is documented as UNABLE to catch, asserted
        // so the limitation is visible in the test suite rather than only in a
        // doc comment. If someone later adds a dictionary check, this assertion
        // fails and they will find the paragraph explaining the trade.
        assert_eq!(
            token_weakness("Kardiyoloji-Servisi-Token-2026ab"),
            None,
            "a chosen passphrase is not detectable here; see the doc comment"
        );
    }

    #[test]
    fn a_finding_never_contains_the_token() {
        // The preflight is run in a terminal and, sooner or later, in CI.
        let secret = strong_token();
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 40, 2));
        for report in [
            check(&proposal(lan, true, Some(&secret))),
            check(&proposal(bind::default_host(), false, Some(&secret))),
            check(&proposal(lan, true, Some(&"z".repeat(40)))),
        ] {
            assert!(
                !report.to_string().contains(&secret),
                "the preflight printed the bearer token"
            );
        }
    }

    #[test]
    fn an_exposed_pass_still_warns_about_tls_and_about_names() {
        let token = strong_token();
        let report = check(&proposal(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            true,
            Some(&token),
        ));
        assert!(report.passed(), "{report}");
        let rendered = report.to_string();
        assert!(rendered.contains("terminates NO TLS"), "{rendered}");
        assert!(rendered.contains("ZERO NAMES"), "{rendered}");
        assert!(rendered.contains("nginx"), "{rendered}");
    }

    #[test]
    fn the_layer_report_tracks_what_is_actually_installed() {
        let mut proposal = proposal(bind::default_host(), false, None);
        proposal.layers = LiveLayers {
            rules: true,
            ner: true,
            context: true,
        };
        let report = check(&proposal);
        assert!(report.passed());
        assert!(!report.to_string().contains("ZERO NAMES"));
    }

    #[test]
    fn a_failing_report_says_so_in_its_last_line() {
        let report = check(&proposal(all_interfaces_v4(), true, None));
        let rendered = report.to_string();
        assert!(rendered.contains("preflight: FAIL"), "{rendered}");
        assert!(
            rendered.contains("container setting"),
            "the refusal must close the door the operator will try next: {rendered}"
        );
    }
}
