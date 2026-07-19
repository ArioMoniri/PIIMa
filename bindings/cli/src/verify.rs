//! Release verification: signature first, then checksum.
//!
//! # Threat model, stated plainly
//!
//! This binary runs on machines that process patient records. An auto-installing
//! updater that applies an unverified download is a remote-code-execution channel
//! into exactly those machines — a strictly worse defect than any bug the updater
//! exists to fix. So the rule here is not "verify if we can": it is that
//! [`Trust::Full`] is the ONLY state that permits installation, and it is
//! unreachable without a valid Ed25519 signature over the manifest AND a matching
//! SHA-256 over the artifact bytes.
//!
//! # The chain, and why it has two links
//!
//! The signature covers the MANIFEST. The manifest names the artifact's SHA-256.
//! The checksum covers the ARTIFACT. Neither link alone is sufficient:
//!
//! - Checksum alone is worthless against an attacker who controls the response,
//!   because they serve both the artifact and the digest of it. A checksum
//!   defends against a truncated download, not against a hostile one.
//! - Signature alone would work if we signed each artifact, but signing the
//!   manifest instead means one signature covers every platform's artifact, and
//!   a mirror can host the large files without holding anything signed.
//!
//! # What cannot verify, does not install
//!
//! Three states short of [`Trust::Full`] exist, and all three refuse to install:
//! no pinned key, no signature in the manifest, invalid signature. The first is
//! the state a fresh checkout is in and the reason the shipped default is
//! notify-only until the project owner pins a release key.

use sha2::{Digest, Sha256};

/// Why a release could not be trusted enough to install.
///
/// No variant carries the artifact, the manifest, or any digest. WHY: this type
/// is Displayed into stderr and, on a bad day, into a support ticket. Digests of
/// public release artifacts are not PHI, but the habit of putting payload-derived
/// data into an error type is precisely the habit that leaks one (I4), and an
/// operator does not debug a signature failure from a hex string anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The artifact's SHA-256 did not match the value in the signed manifest.
    #[error("artifact checksum does not match the signed manifest; refusing to install")]
    ChecksumMismatch,
    /// The manifest carried no signature.
    #[error("release manifest is unsigned; refusing to install")]
    MissingSignature,
    /// The signature did not verify against the pinned key.
    #[error("release signature does not verify against the pinned key; refusing to install")]
    BadSignature,
    /// The signature or the pinned key could not be decoded.
    #[error("release signature or pinned key is malformed; refusing to install")]
    MalformedSignature,
}

/// How far a release got through verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Signature verified against the pinned key AND checksum matched.
    /// The only state that may be installed.
    Full,
    /// Checksum matched, but no release key is pinned in this configuration.
    /// Notify only.
    ChecksumOnlyNoPinnedKey,
}

/// What the updater is allowed to do with a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Write the artifact into place.
    Install,
    /// Tell the operator a version exists and stop.
    NotifyOnly,
}

impl Trust {
    /// The single decision point between "tell someone" and "run code".
    ///
    /// Written as a total function over the enum rather than an `if` at the call
    /// site so that adding a new trust state forces a decision here, in the file
    /// whose header explains the threat model, instead of defaulting to install.
    pub const fn action(self) -> Action {
        match self {
            Self::Full => Action::Install,
            Self::ChecksumOnlyNoPinnedKey => Action::NotifyOnly,
        }
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Verify a manifest's signature and an artifact's checksum.
///
/// `manifest_bytes` are the exact bytes the signature covers, byte for byte as
/// received — re-serialising a parsed manifest before verifying is the classic
/// way to verify something other than what was signed.
pub fn verify(
    manifest_bytes: &[u8],
    signature: Option<&str>,
    pinned_key: Option<&str>,
    artifact: &[u8],
    expected_sha256: &str,
) -> Result<Trust, VerifyError> {
    // Checksum first: it is arithmetic on bytes already in hand, it cannot be
    // influenced by key configuration, and failing here means the download is
    // wrong regardless of who signed what.
    if !constant_time_eq(
        sha256_hex(artifact).as_bytes(),
        expected_sha256.trim().to_ascii_lowercase().as_bytes(),
    ) {
        return Err(VerifyError::ChecksumMismatch);
    }

    let Some(key) = pinned_key else {
        // No key pinned. The download is intact but unattributed, which is
        // exactly the situation an attacker who controls the response produces.
        return Ok(Trust::ChecksumOnlyNoPinnedKey);
    };
    let signature = signature.ok_or(VerifyError::MissingSignature)?;

    let public_key = minisign_verify::PublicKey::from_base64(key.trim())
        .map_err(|_| VerifyError::MalformedSignature)?;
    let decoded = minisign_verify::Signature::decode(signature)
        .map_err(|_| VerifyError::MalformedSignature)?;

    // `allow_legacy: false` refuses the pre-hashed-signature downgrade. A
    // verifier that accepts the legacy algorithm accepts whatever an attacker
    // prefers to produce.
    public_key
        .verify(manifest_bytes, &decoded, false)
        .map_err(|_| VerifyError::BadSignature)?;
    Ok(Trust::Full)
}

/// Compare without an early exit on the first differing byte.
///
/// A digest comparison is not a secret comparison, so this is belt and braces
/// rather than a load-bearing defence. It costs one loop and removes the need to
/// argue about it in review.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use minisign::{KeyPair, SignatureBox};
    use std::io::Cursor;

    const MANIFEST: &[u8] = b"version = 0.2.0\nsha256 = deadbeef\n";
    const ARTIFACT: &[u8] = b"a plausible release binary";

    /// A real minisign keypair and a real signature over `data`.
    ///
    /// WHY the signer runs in the test rather than a checked-in fixture: a
    /// fixture signature proves the decoder still parses; generating one proves
    /// the verifier accepts a signature an actual signing tool produced.
    fn signed(data: &[u8]) -> (String, String) {
        let pair = KeyPair::generate_unencrypted_keypair().expect("keypair");
        let signature: SignatureBox =
            minisign::sign(None, &pair.sk, Cursor::new(data), None, None).expect("sign");
        (pair.pk.to_base64(), signature.into_string())
    }

    #[test]
    fn a_signed_release_with_a_matching_checksum_installs() {
        let (key, signature) = signed(MANIFEST);
        let trust = verify(
            MANIFEST,
            Some(&signature),
            Some(&key),
            ARTIFACT,
            &sha256_hex(ARTIFACT),
        )
        .expect("verification");
        assert_eq!(trust, Trust::Full);
        assert_eq!(trust.action(), Action::Install);
    }

    #[test]
    fn a_checksum_mismatch_refuses_to_install() {
        // The headline requirement: a tampered or truncated artifact never runs.
        let (key, signature) = signed(MANIFEST);
        let tampered = b"a plausible release binary, plus one extra byte";
        assert_eq!(
            verify(
                MANIFEST,
                Some(&signature),
                Some(&key),
                tampered,
                &sha256_hex(ARTIFACT),
            ),
            Err(VerifyError::ChecksumMismatch)
        );
    }

    #[test]
    fn a_signature_from_a_different_key_refuses_to_install() {
        let (_, signature) = signed(MANIFEST);
        let (other_key, _) = signed(b"unrelated");
        assert_eq!(
            verify(
                MANIFEST,
                Some(&signature),
                Some(&other_key),
                ARTIFACT,
                &sha256_hex(ARTIFACT),
            ),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn a_signature_over_different_manifest_bytes_refuses_to_install() {
        // Proves the signature is checked against the bytes as received. A
        // verifier that re-serialises before checking would pass this.
        let (key, signature) = signed(MANIFEST);
        let swapped = b"version = 9.9.9\nsha256 = deadbeef\n";
        assert_eq!(
            verify(
                swapped,
                Some(&signature),
                Some(&key),
                ARTIFACT,
                &sha256_hex(ARTIFACT),
            ),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn a_pinned_key_with_no_signature_refuses_to_install() {
        let (key, _) = signed(MANIFEST);
        assert_eq!(
            verify(MANIFEST, None, Some(&key), ARTIFACT, &sha256_hex(ARTIFACT)),
            Err(VerifyError::MissingSignature)
        );
    }

    #[test]
    fn a_malformed_key_refuses_to_install() {
        let (_, signature) = signed(MANIFEST);
        assert_eq!(
            verify(
                MANIFEST,
                Some(&signature),
                Some("not-a-key"),
                ARTIFACT,
                &sha256_hex(ARTIFACT),
            ),
            Err(VerifyError::MalformedSignature)
        );
    }

    #[test]
    fn without_a_pinned_key_a_valid_checksum_is_notify_only() {
        // The state a fresh checkout ships in. Intact, unattributed, not run.
        let trust = verify(MANIFEST, None, None, ARTIFACT, &sha256_hex(ARTIFACT))
            .expect("checksum verification");
        assert_eq!(trust, Trust::ChecksumOnlyNoPinnedKey);
        assert_eq!(trust.action(), Action::NotifyOnly);
    }

    #[test]
    fn no_error_message_carries_a_digest_or_the_payload() {
        for err in [
            VerifyError::ChecksumMismatch,
            VerifyError::MissingSignature,
            VerifyError::BadSignature,
            VerifyError::MalformedSignature,
        ] {
            let rendered = format!("{err}");
            assert!(!rendered.contains(&sha256_hex(ARTIFACT)));
            assert!(rendered.contains("refusing to install"));
        }
    }

    #[test]
    fn the_checksum_comparison_ignores_case_and_surrounding_space() {
        let (key, signature) = signed(MANIFEST);
        let upper = format!("  {}  ", sha256_hex(ARTIFACT).to_ascii_uppercase());
        assert_eq!(
            verify(MANIFEST, Some(&signature), Some(&key), ARTIFACT, &upper),
            Ok(Trust::Full)
        );
    }
}
