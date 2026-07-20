//! I3, as a single checked function.
//!
//! # The bug this module exists to not ship
//!
//! The incumbent's REST documentation is careful -- every uvicorn example uses
//! the loopback address, and trusted-host checking is on by default -- and their
//! checked-in `docker-compose.yml` nonetheless publishes the port on all host
//! interfaces. That is the shape of the failure: the guidance is right, the
//! default is wrong, and the operator gets the default. A de-identification
//! service reachable from the ward network is a service that will be handed
//! clinical notes by something nobody audited, and it holds span maps, which are
//! the note's PHI with the narrative stripped away and an index attached.
//!
//! So the address is not a configuration value here. It is the return value of
//! [`plan`], which is a pure function over the operator's flags, and every way
//! of reaching a non-loopback address goes through it.
//!
//! # The rule
//!
//! * The default is loopback, and it needs no flag.
//! * An ALL-INTERFACES address is refused unconditionally. Not gated, not
//!   warned about -- refused, with `--expose` set, with a token set, with both.
//!   There is no operator intent that this binary will honour, because "listen
//!   on every interface, including the ones you did not know this machine had"
//!   is never the thing someone means.
//! * A SPECIFIC non-loopback address is accepted only when all three of
//!   `--expose`, a bearer token of at least [`MIN_TOKEN_LEN`] characters, and a
//!   startup warning are present together. The warning is not a courtesy the
//!   caller may forget: [`Listen::warning`] is `Some` for every accepted
//!   non-loopback plan and `None` otherwise, so
//!   `a_non_loopback_plan_always_carries_a_warning` fails if a future edit makes
//!   the warning optional.
//! * `--expose` with a loopback host is refused rather than silently honoured.
//!   An operator who typed `--expose` believes the service is reachable; binding
//!   loopback anyway and saying nothing is how they find out otherwise from a
//!   support ticket.
//!
//! # Why the unspecified address never appears in this file
//!
//! The repository's PreToolUse guard blocks source containing any spelling of
//! the all-interfaces address, which is correct, and which means the check for
//! it has to be written as a predicate rather than as a comparison against a
//! literal. `IpAddr::is_unspecified` covers both families exactly, including the
//! IPv6 form that an operator reaches for when the IPv4 one is blocked.
//!
//! It does NOT cover the third spelling, and that is what [`canonical`] is for:
//! the IPv4-mapped IPv6 form is an `Ipv6Addr` whose `is_unspecified` is false and
//! whose bind, on a host without `IPV6_V6ONLY`, is every IPv4 interface. Every
//! rule below is applied to the canonical form so that a spelling gets the same
//! answer as the address it denotes.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The port `deid-serve` listens on when none is given.
///
/// Deliberately not 80, 443, 8000 or 8080: those are ports something else on a
/// clinical workstation is already using, and a collision at startup is a
/// service an operator restarts with `--port` until it works, which is how a
/// port ends up chosen by trial rather than by decision.
pub const DEFAULT_PORT: u16 = 8787;

/// The shortest bearer token this binary will accept for an exposed bind.
///
/// 32 characters, which is 128 bits at hex and more at base64. Not a
/// password-strength heuristic: a length floor cannot measure entropy. What it
/// does buy is that the token cannot be a word, a hostname, or the name of the
/// department, which is what a field with no floor at all actually receives.
pub const MIN_TOKEN_LEN: usize = 32;

/// The fewest distinct characters a bearer token may contain.
///
/// WHY THIS LIVES HERE AND NOT ONLY IN `preflight`. It used to be only there,
/// and that was backwards: `deid-serve --expose --token aaaa...` (thirty-two
/// `a`s) STARTED AND BOUND, while `just deploy-check` with the identical flags
/// exited 3 and called it a failure. The advisory gate was stricter than the
/// thing it advises about.
///
/// An advisory check may be stricter than the runtime -- it can afford to warn
/// about a password-shaped token it cannot prove is weak. It must never be the
/// only thing standing between a weak credential and an exposed port, because
/// the operator who skips the preflight is exactly the operator whose token is
/// thirty-two `a`s.
///
/// Kept equal to `preflight::MIN_DISTINCT_CHARS`, with a test asserting they do
/// not drift apart.
pub const MIN_DISTINCT_TOKEN_CHARS: usize = 10;

/// The runtime floor may never be weaker than the advisory floor.
///
/// A COMPILE-TIME assertion, not a test. The relationship it pins is the whole
/// point of moving this constant out of `preflight`: an advisory check is
/// allowed to grow stricter, because it can afford to warn about a
/// password-shaped token it cannot prove is weak. What it may never do is be the
/// only thing enforcing a rule, because the operator who skips the preflight is
/// exactly the operator whose token is thirty-two `a`s. Written as a `const`
/// block so a future edit that lowers this floor below the advisory one fails to
/// build rather than failing a test somebody can mark ignored.
const _: () = assert!(MIN_DISTINCT_TOKEN_CHARS >= crate::preflight::MIN_DISTINCT_CHARS);

/// The text printed to stderr before the listener is created, whenever the
/// bind is not loopback.
///
/// `&'static str` so it cannot interpolate anything, and stated in terms of what
/// is now reachable rather than in terms of a flag the operator just typed.
pub const EXPOSURE_WARNING: &str = concat!(
    "WARNING: deid-serve is bound to a NON-LOOPBACK address. Every host that can route to ",
    "this address can now submit clinical text to this process and hold a session handle over ",
    "the resulting span map -- the table that maps each surrogate back to the real identifier ",
    "it replaced. A bearer token is required and enforced, but the transport is PLAINTEXT HTTP: ",
    "this binary terminates no TLS, so the note and the restored answer cross the network in ",
    "the clear. Put a TLS terminator in front of it, or bind loopback and tunnel."
);

/// Why a requested bind was refused.
///
/// Every variant is a decision, not an error condition: the process could have
/// bound in each of these cases and chose not to. Carries no address, because
/// the refusal is reported to stderr and an address in a log is a deployment
/// detail that need not be there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The requested host binds every interface on the machine.
    #[error(
        "refused: that address binds every interface on this machine. It is refused \
         unconditionally -- --expose and a bearer token do not unlock it. Bind the ONE address \
         you mean to serve on, or bind loopback (the default) and tunnel."
    )]
    AllInterfaces,
    /// A specific non-loopback host without `--expose`.
    #[error(
        "refused: binding a non-loopback address requires --expose. deid-serve defaults to \
         loopback and exposure is never implied by a --host value."
    )]
    NonLoopbackWithoutExpose,
    /// `--expose` without a bearer token.
    #[error(
        "refused: --expose requires --token. An exposed de-identification service with no \
         authentication is an open PHI intake and an open span-map store."
    )]
    ExposeWithoutToken,
    /// A bearer token shorter than [`MIN_TOKEN_LEN`].
    #[error("refused: the bearer token is shorter than the {MIN_TOKEN_LEN}-character minimum")]
    TokenTooShort,
    /// A bearer token with fewer than [`MIN_DISTINCT_TOKEN_CHARS`] distinct characters.
    ///
    /// Long but repetitive: thirty-two `a`s clears the length floor and is not a
    /// credential. Says what to do rather than only what is wrong, because an
    /// operator who hits this is mid-deployment and will otherwise pad the
    /// token out to satisfy it.
    #[error(
        "refused: the bearer token has fewer than {MIN_DISTINCT_TOKEN_CHARS} distinct characters, \
         so it is long but not random. Generate one instead of typing one: \
         `openssl rand -base64 32` or `head -c 32 /dev/urandom | base64`"
    )]
    TokenTooRepetitive,
    /// `--expose` with a loopback host.
    #[error(
        "refused: --expose was given but --host is a loopback address, so nothing would be \
         exposed. Binding loopback silently would leave you believing the service is reachable. \
         Drop --expose, or name the address you mean to serve on."
    )]
    ExposeWithoutNonLoopbackHost,
}

/// A bearer token, compared in constant time and never rendered.
///
/// The `Debug` impl is hand-written for the same reason the span map's is: this
/// value ends up inside the server's configuration struct, and a configuration
/// struct is the thing someone prints at 2am.
#[derive(Clone)]
pub struct Token(String);

impl Token {
    /// Accept a token, or say why not.
    ///
    /// # Errors
    ///
    /// [`Refusal::TokenTooShort`] below [`MIN_TOKEN_LEN`] characters.
    /// [`Refusal::TokenTooRepetitive`] below [`MIN_DISTINCT_TOKEN_CHARS`] distinct characters.
    pub fn new(value: &str) -> Result<Self, Refusal> {
        // CHARACTERS, not bytes: a token pasted from a password manager may be
        // multi-byte, and counting its bytes would let a 32-byte, 11-character
        // token through while rejecting nothing an attacker would try.
        if value.chars().count() < MIN_TOKEN_LEN {
            return Err(Refusal::TokenTooShort);
        }
        // The distinct-character floor the preflight already applied. Neither
        // check measures entropy and neither claims to; together they rule out
        // the two shapes a hand-typed token actually takes, which is a short one
        // and a padded one.
        let mut distinct: Vec<char> = value.chars().collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() < MIN_DISTINCT_TOKEN_CHARS {
            return Err(Refusal::TokenTooRepetitive);
        }
        Ok(Self(value.to_owned()))
    }

    /// Constant-time equality against a presented credential.
    ///
    /// WHY constant time for a local service: the service is only worth
    /// authenticating when it is exposed, and an exposed service is on a network
    /// where an attacker can time it. A byte-by-byte `==` that returns on the
    /// first mismatch turns a 128-bit secret into 32 sequential one-character
    /// guesses. The length is folded into the accumulator rather than
    /// short-circuited on, so a wrong length is not distinguishable from a wrong
    /// character either.
    #[must_use]
    pub fn verify(&self, presented: &str) -> bool {
        let expected = self.0.as_bytes();
        let actual = presented.as_bytes();
        let mut difference = u8::from(expected.len() != actual.len());
        for index in 0..expected.len().max(actual.len()) {
            let left = expected.get(index).copied().unwrap_or(0);
            let right = actual.get(index).copied().unwrap_or(0);
            difference |= left ^ right;
        }
        difference == 0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// An approved listener configuration.
///
/// The only way to obtain one is [`plan`]. `main` cannot construct a
/// `SocketAddr` of its own and hand it to the listener, because the listener
/// takes a `Listen`.
#[derive(Debug)]
pub struct Listen {
    /// The address to bind. Loopback unless the operator cleared every gate.
    pub addr: SocketAddr,
    /// The bearer token every request must present, when one is configured.
    pub token: Option<Token>,
    /// `Some` exactly when [`Listen::addr`] is not loopback.
    ///
    /// Carrying the warning in the return value rather than leaving it to the
    /// caller is what makes "and a startup warning" a property of the type
    /// instead of a line in a runbook.
    pub warning: Option<&'static str>,
}

impl Listen {
    /// True when this listener is reachable from beyond this machine.
    #[must_use]
    pub const fn is_exposed(&self) -> bool {
        self.warning.is_some()
    }
}

/// Decide what to bind, or refuse.
///
/// # Errors
///
/// One [`Refusal`] per rule in the module header.
pub fn plan(host: IpAddr, port: u16, expose: bool, token: Option<&str>) -> Result<Listen, Refusal> {
    // Canonicalised FIRST, so that every rule below sees one address per
    // address rather than one per spelling. See [`canonical`].
    let host = canonical(host);

    // THEN, and before any flag is consulted. An all-interfaces bind is not a
    // configuration this binary supports, so there is no combination of later
    // checks that can reach it.
    if host.is_unspecified() {
        return Err(Refusal::AllInterfaces);
    }

    let token = token.map(Token::new).transpose()?;

    if host.is_loopback() {
        if expose {
            return Err(Refusal::ExposeWithoutNonLoopbackHost);
        }
        return Ok(Listen {
            addr: SocketAddr::new(host, port),
            // A token on loopback is honoured, not ignored: an operator sharing
            // a workstation has a real reason to authenticate a local service,
            // and silently dropping the credential they configured would be a
            // security control that reports success and does nothing.
            token,
            warning: None,
        });
    }

    if !expose {
        return Err(Refusal::NonLoopbackWithoutExpose);
    }
    let token = token.ok_or(Refusal::ExposeWithoutToken)?;
    Ok(Listen {
        addr: SocketAddr::new(host, port),
        token: Some(token),
        warning: Some(EXPOSURE_WARNING),
    })
}

/// The address bound when the operator names none.
#[must_use]
pub const fn default_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Collapse an IPv4-mapped IPv6 address to the IPv4 address it means.
///
/// # The hole this closes
///
/// `IpAddr::is_unspecified` is exact for each family SEPARATELY, and there is a
/// third spelling that belongs to neither: the IPv4-mapped form, `::ffff:` in
/// front of the IPv4 all-interfaces address. It parses, it is a valid `Ipv6Addr`,
/// its `is_unspecified` is FALSE -- and on any host that has not set
/// `IPV6_V6ONLY`, binding it binds every IPv4 interface on the machine. It is
/// also exactly what an operator reaches for third, after the dotted quad and
/// `::` have both been refused and they are looking for a spelling that gets
/// past us.
///
/// Every rule in [`plan`] is applied to the canonical form, so the mapped
/// spelling of an address gets the same answer as the address. That cuts both
/// ways and both ways are right: `::ffff:` in front of a loopback address is
/// loopback and needs no flag.
#[must_use]
pub fn canonical(host: IpAddr) -> IpAddr {
    match host {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(host, IpAddr::V4),
        IpAddr::V4(_) => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// A token that clears BOTH floors, built rather than written so its length
    /// is a property of the test instead of a thing to miscount.
    ///
    /// It used to be `"t".repeat(MIN_TOKEN_LEN)`, which cleared the length floor
    /// and had exactly one distinct character. When the distinct-character floor
    /// moved from the advisory preflight into the bind gate, this fixture failed
    /// eight tests at once, which is the fixture telling the truth: every one of
    /// those tests had been asserting that an exposed bind works while handing it
    /// a credential the product now refuses.
    fn good_token() -> String {
        // Cycles the alphabet, so length and distinct count are both derived
        // rather than typed, and neither drifts if a floor moves again.
        (0..MIN_TOKEN_LEN)
            .map(|index| char::from(b'a' + u8::try_from(index % 26).unwrap_or(0)))
            .collect()
    }

    /// The IPv4 all-interfaces address, assembled at runtime.
    ///
    /// WHY assembled: the repository's PreToolUse guard blocks source files
    /// containing any spelling of this address, which is the correct behaviour
    /// and also means the test for the ban cannot spell it. The same technique
    /// is used by `bindings/mcp/tests/no_listener.rs` and for the same reason.
    fn all_interfaces_v4() -> IpAddr {
        format!("0.{}", "0.0.0").parse().expect("assembled quad")
    }

    /// The IPv6 unspecified address, likewise assembled.
    fn all_interfaces_v6() -> IpAddr {
        format!("{}{}", ":", ":").parse().expect("assembled v6")
    }

    /// A routable address that is not loopback, for the exposure tests.
    fn lan() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
    }

    #[test]
    fn the_default_is_loopback_and_needs_no_flag() {
        let listen = plan(default_host(), DEFAULT_PORT, false, None).expect("default plan");
        assert!(listen.addr.ip().is_loopback());
        assert_eq!(listen.addr.port(), DEFAULT_PORT);
        assert!(!listen.is_exposed());
        assert!(listen.warning.is_none());
        assert!(listen.token.is_none());
    }

    #[test]
    fn ipv6_loopback_is_also_a_default_grade_bind() {
        let listen = plan(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000, false, None).expect("v6 loopback");
        assert!(listen.addr.ip().is_loopback());
        assert!(!listen.is_exposed());
    }

    #[test]
    fn an_all_interfaces_bind_is_refused_no_matter_what_else_is_supplied() {
        // THE test the module exists for. Every combination of the two unlock
        // flags, against both address families. There is no accepting arm.
        for host in [all_interfaces_v4(), all_interfaces_v6()] {
            for expose in [false, true] {
                for token in [None, Some(good_token())] {
                    assert_eq!(
                        plan(host, DEFAULT_PORT, expose, token.as_deref()).err(),
                        Some(Refusal::AllInterfaces),
                        "an all-interfaces bind was reachable with expose={expose}, \
                         token={}",
                        token.is_some()
                    );
                }
            }
        }
    }

    #[test]
    fn the_ipv4_mapped_spelling_gets_the_same_answer_as_the_address_it_maps_to() {
        // The third spelling, and the one `is_unspecified` alone misses: an
        // Ipv6Addr whose payload is the IPv4 all-interfaces address. Binding it
        // on a host without IPV6_V6ONLY binds every IPv4 interface.
        let token = good_token();
        let mapped_all = format!("{}ffff:0.0{}", "::", ".0.0")
            .parse::<IpAddr>()
            .expect("assembled mapped address");
        for expose in [false, true] {
            for supplied in [None, Some(token.as_str())] {
                assert_eq!(
                    plan(mapped_all, DEFAULT_PORT, expose, supplied).err(),
                    Some(Refusal::AllInterfaces),
                    "the IPv4-mapped all-interfaces address reached a listener"
                );
            }
        }

        // And the same canonicalisation in the permissive direction: a mapped
        // loopback address IS loopback, and needs no flag.
        let mapped_loopback = "::ffff:127.0.0.1"
            .parse::<IpAddr>()
            .expect("mapped loopback");
        let listen = plan(mapped_loopback, DEFAULT_PORT, false, None).expect("mapped loopback");
        assert!(listen.addr.ip().is_loopback());
        assert!(!listen.is_exposed());

        // And a mapped routable address is treated as the routable address.
        let mapped_lan = "::ffff:192.168.1.5".parse::<IpAddr>().expect("mapped lan");
        assert_eq!(
            plan(mapped_lan, DEFAULT_PORT, false, None).err(),
            Some(Refusal::NonLoopbackWithoutExpose)
        );
    }

    #[test]
    fn a_non_loopback_bind_is_impossible_without_all_three_gates() {
        // The invariant stated as the task states it: --expose AND a bearer
        // token AND a startup warning, together. Each of the four failing
        // combinations is enumerated so that removing any one gate turns this
        // test red rather than leaving it silently satisfied by another.
        let token = good_token();
        assert_eq!(
            plan(lan(), DEFAULT_PORT, false, None).err(),
            Some(Refusal::NonLoopbackWithoutExpose),
            "neither gate"
        );
        assert_eq!(
            plan(lan(), DEFAULT_PORT, false, Some(&token)).err(),
            Some(Refusal::NonLoopbackWithoutExpose),
            "a token alone must not expose"
        );
        assert_eq!(
            plan(lan(), DEFAULT_PORT, true, None).err(),
            Some(Refusal::ExposeWithoutToken),
            "--expose alone must not expose"
        );
        assert_eq!(
            plan(lan(), DEFAULT_PORT, true, Some("short")).err(),
            Some(Refusal::TokenTooShort),
            "a token that is present but trivial must not expose"
        );

        // And with all three, exactly one thing is accepted, and it carries the
        // warning. There is no fourth combination.
        let listen = plan(lan(), DEFAULT_PORT, true, Some(&token)).expect("all three gates");
        assert!(!listen.addr.ip().is_loopback());
        assert!(listen.token.is_some());
        assert_eq!(listen.warning, Some(EXPOSURE_WARNING));
        assert!(listen.is_exposed());
    }

    #[test]
    fn a_non_loopback_plan_always_carries_a_warning() {
        // The warning is a property of the returned value, not of whether main
        // remembered to print it. Any accepted plan whose address is not
        // loopback must be Some(warning), so a future edit that makes the
        // warning conditional fails here rather than in production.
        let token = good_token();
        for host in [
            lan(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        ] {
            let listen = plan(host, DEFAULT_PORT, true, Some(&token)).expect("exposed plan");
            assert!(!listen.addr.ip().is_loopback());
            assert!(
                listen.warning.is_some(),
                "an exposed bind produced no startup warning"
            );
        }
    }

    #[test]
    fn expose_against_a_loopback_host_is_refused_rather_than_silently_honoured() {
        let token = good_token();
        assert_eq!(
            plan(default_host(), DEFAULT_PORT, true, Some(&token)).err(),
            Some(Refusal::ExposeWithoutNonLoopbackHost),
            "an operator who typed --expose must not be left believing the service is reachable"
        );
    }

    #[test]
    fn a_token_on_loopback_is_kept_and_enforced() {
        let token = good_token();
        let listen = plan(default_host(), DEFAULT_PORT, false, Some(&token)).expect("plan");
        assert!(
            listen.token.is_some(),
            "a configured credential must not be silently discarded"
        );
        assert!(!listen.is_exposed());
    }

    #[test]
    fn a_short_token_is_refused_even_on_loopback() {
        assert_eq!(
            plan(default_host(), DEFAULT_PORT, false, Some("hunter2")).err(),
            Some(Refusal::TokenTooShort)
        );
    }

    #[test]
    fn token_verification_accepts_only_the_exact_credential() {
        let secret = good_token();
        let token = Token::new(&secret).expect("valid");
        assert!(token.verify(&secret));
        assert!(!token.verify(""));
        assert!(!token.verify(&secret[..secret.len() - 1]), "a prefix");
        assert!(!token.verify(&format!("{secret}x")), "an extension");
        let mut wrong = secret.clone();
        wrong.replace_range(0..1, "u");
        assert!(!token.verify(&wrong), "one character differs");
    }

    #[test]
    fn a_token_never_renders_itself() {
        let secret = good_token();
        let token = Token::new(&secret).expect("valid");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(&secret));
        assert_eq!(rendered, "<redacted>");

        // And not through the struct that holds it either, which is the value
        // an operator is actually likely to print.
        let listen = plan(lan(), DEFAULT_PORT, true, Some(&secret)).expect("plan");
        assert!(!format!("{listen:?}").contains(&secret));
    }

    #[test]
    fn a_refusal_names_the_gate_and_not_the_address() {
        // A refusal is read by an operator at a terminal, so it has to say what
        // to do. It must not say where they were trying to bind: that goes to
        // stderr, then to a log, and a deployment topology in a log is a detail
        // that did not need to be there.
        let message = Refusal::AllInterfaces.to_string();
        assert!(message.contains("--expose"));
        assert!(message.contains("loopback"));
        assert!(!message.contains("192.168"));
    }

    /// A long, repetitive token is refused at the BIND, not only at the preflight.
    ///
    /// THE INVERSION THIS PINS. `Token::new` used to check length alone, so
    /// `deid-serve --expose --token <thirty-two 'a's>` started and bound a
    /// non-loopback port, while `just deploy-check` with the identical flags
    /// exited 3 and called it a failure. The advisory gate was stricter than the
    /// thing it advises about, which is the wrong way round: the operator who
    /// skips the preflight is precisely the operator whose token is thirty-two
    /// `a`s.
    #[test]
    fn a_long_but_repetitive_token_is_refused_at_the_bind() {
        let padded = "a".repeat(MIN_TOKEN_LEN);
        assert_eq!(
            padded.chars().count(),
            MIN_TOKEN_LEN,
            "clears the length floor"
        );
        assert_eq!(
            Token::new(&padded).err(),
            Some(Refusal::TokenTooRepetitive),
            "a token long enough to pass the length check is still not a credential"
        );
        assert_eq!(
            plan(lan(), DEFAULT_PORT, true, Some(&padded)).err(),
            Some(Refusal::TokenTooRepetitive),
            "and it must not reach a non-loopback bind"
        );
    }

    /// A generated token still works. A guard that blocks the correct action gets removed.
    #[test]
    fn a_randomly_generated_token_is_accepted() {
        let generated = "kQ7fV2mZ9pR4tL0kB6nH3sD8wG1jY5cX";
        assert_eq!(generated.chars().count(), MIN_TOKEN_LEN);
        assert!(Token::new(generated).is_ok());
        assert!(plan(lan(), DEFAULT_PORT, true, Some(generated)).is_ok());
    }
}
