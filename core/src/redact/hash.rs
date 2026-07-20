//! The key, and the digest, behind [`RedactionMethod::Hash`].
//!
//! # Why the key is mandatory and not optional
//!
//! An UNKEYED hash of a short name is not a one-way function in any sense that
//! matters here. Turkish given names number in the low tens of thousands and
//! surnames in the hundreds of thousands; an attacker holding a hashed
//! transcript enumerates the product, hashes each candidate with the same
//! public algorithm, and reads the patient's name off the match table. The work
//! is seconds on a laptop. That is not a theoretical weakness -- it is the
//! whole attack, and it is the reason `Span::text_hash` (64 bits of unkeyed
//! FNV-1a) is documented in this crate as a known weakness rather than as a
//! privacy control.
//!
//! Under a keyed hash the same enumeration additionally requires the key. The
//! key is caller-supplied, never written into any output this module produces,
//! and never derivable from a digest. So [`Redactor`] refuses to apply
//! [`RedactionMethod::Hash`] without one ([`RedactError::HashKeyRequired`])
//! instead of quietly falling back to an unkeyed digest -- a fallback that
//! silently downgrades a privacy control to a lookup table is worse than an
//! error, because nobody reads the output and notices.
//!
//! # What the digest still leaks, stated plainly
//!
//! Consistency and secrecy are in tension and this method picks consistency.
//! The digest is a deterministic function of (key, label family, folded text),
//! so the SAME entity yields the SAME token throughout the document -- which is
//! the point, because cross-references have to survive -- and that means an
//! attacker can still count occurrences and see co-occurrence structure. It
//! also means an attacker who GUESSES the key, or who obtains it, can confirm a
//! guessed name. Under [`SaltScope::Patient`]-style reuse of one key across a
//! corpus, the token becomes a stable pseudonym and cross-document linkage is
//! preserved for the attacker as well as for the researcher. Use a per-document
//! key unless linkage is a requirement.
//!
//! [`RedactionMethod::Hash`]: super::RedactionMethod::Hash
//! [`Redactor`]: super::Redactor
//! [`RedactError::HashKeyRequired`]: super::RedactError::HashKeyRequired
//! [`SaltScope::Patient`]: crate::surrogate::SaltScope::Patient

use crate::label::EntityLabel;
use crate::surrogate::keyed_hash::{Blake2s, DIGEST_LEN};

use super::RedactError;

/// Key width in bytes.
pub const HASH_KEY_LEN: usize = DIGEST_LEN;

/// The shortest key material [`HashKey::derive`] accepts.
///
/// 128 bits, the same floor [`crate::surrogate::MIN_KEY_MATERIAL`] sets, and
/// for the same reason: below it the dictionary attack this key exists to
/// prevent becomes cheaper than the corpus is worth.
pub const MIN_HASH_KEY_MATERIAL: usize = 16;

/// How many hex characters of the digest are emitted.
///
/// 16, so 64 bits. Truncation is a readability decision, not a security one --
/// a full 256-bit token in the middle of a clinical sentence makes the sentence
/// unreadable, and unreadable output does not get deployed. 64 bits still puts
/// a within-document collision (birthday bound ~2^32 distinct entities) far
/// beyond any document, and the secrecy of the mapping rests on the key rather
/// than on the digest width.
pub const HASH_HEX_LEN: usize = 16;

/// The secret that keys every [`RedactionMethod::Hash`] digest.
///
/// NO `Debug`, NO `Display`, NO `PartialEq`, for the reasons
/// [`crate::surrogate::Salt`] states: rendering a key is a key disclosure
/// reached by a path nobody chose, and a byte-wise comparison that
/// short-circuits is a timing oracle no caller here needs.
///
/// THIS CRATE DOES NOT GENERATE KEYS. `core/` performs no I/O (I1), so it has
/// no CSPRNG and cannot honestly claim to produce unpredictable bytes. A key
/// invented from a counter is not a key.
///
/// [`RedactionMethod::Hash`]: super::RedactionMethod::Hash
#[derive(Clone)]
pub struct HashKey([u8; HASH_KEY_LEN]);

impl HashKey {
    /// Adopt exactly [`HASH_KEY_LEN`] bytes of caller-supplied key material.
    #[must_use]
    pub const fn from_bytes(key: [u8; HASH_KEY_LEN]) -> Self {
        Self(key)
    }

    /// Derive a key from at least [`MIN_HASH_KEY_MATERIAL`] bytes.
    ///
    /// Runs the material through the keyed hash rather than truncating or
    /// zero-padding it, so a passphrase and a 64-byte token both yield
    /// full-width key material, and material that is too short is refused
    /// rather than silently stretched into the appearance of a secret.
    ///
    /// # Errors
    ///
    /// [`RedactError::HashKeyTooShort`] when the material is under the floor.
    pub fn derive(key_material: &[u8]) -> Result<Self, RedactError> {
        if key_material.len() < MIN_HASH_KEY_MATERIAL {
            return Err(RedactError::HashKeyTooShort {
                len: key_material.len(),
            });
        }
        let mut hasher = Blake2s::keyed(key_material);
        hasher.update_field(b"deid-tr/redact/hash-key/v1");
        hasher.update_field(key_material);
        Ok(Self(hasher.finalize()))
    }

    /// The token that replaces one entity.
    ///
    /// The LABEL IS BOUND IN, so a phone number and a patient name that happen
    /// to share a surface form do not share a token: reusing one token across
    /// two entity types would assert an identity the document never claimed.
    /// The text is case-folded first (see [`fold`]) so that `AYŞE` and `Ayşe`
    /// are one entity, which is what makes the cross-reference survive.
    pub(super) fn token(&self, label: EntityLabel, original: &str) -> String {
        let mut hasher = Blake2s::keyed(&self.0);
        // Length-prefixed fields, so ("AB", "C") and ("A", "BC") cannot encode
        // to the same message and collapse two entities onto one token.
        hasher.update_field(b"deid-tr/redact/hash/v1");
        hasher.update_field(label.as_str().as_bytes());
        hasher.update_field(fold(original).as_bytes());
        let digest = hasher.finalize();

        let mut hex = String::with_capacity(HASH_HEX_LEN);
        for byte in digest.iter().take(HASH_HEX_LEN.div_ceil(2)) {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex.truncate(HASH_HEX_LEN);
        format!("[{}:{hex}]", label.as_str())
    }
}

/// Turkish-aware case folding.
///
/// `str::to_lowercase` maps `I` to `i` and `İ` to `i` plus a combining dot,
/// which merges two of Turkish's four distinct `i` letters and corrupts the
/// other, so the two capitals are mapped explicitly before the Unicode fold
/// runs. Deliberately the same mapping L5's own fold applies; the two must not
/// drift, because a deployment that hashes some spans and surrogates others
/// would otherwise disagree about whether `AYŞE` and `Ayşe` are one person.
fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            'I' => out.push('ı'),
            'İ' => out.push('i'),
            other => out.extend(other.to_lowercase()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> HashKey {
        HashKey::from_bytes([byte; HASH_KEY_LEN])
    }

    #[test]
    fn a_token_is_stable_for_one_key_and_entity() {
        let key = key(1);
        assert_eq!(
            key.token(EntityLabel::PatientName, "Ayşe Yılmaz"),
            key.token(EntityLabel::PatientName, "Ayşe Yılmaz")
        );
    }

    #[test]
    fn a_different_key_gives_a_different_token() {
        // The whole security argument, as one assertion: without this the
        // digest is a public function of the name and the enumeration attack
        // in the module header succeeds.
        assert_ne!(
            key(1).token(EntityLabel::PatientName, "Ayşe Yılmaz"),
            key(2).token(EntityLabel::PatientName, "Ayşe Yılmaz")
        );
    }

    #[test]
    fn the_label_is_bound_into_the_token() {
        let key = key(3);
        assert_ne!(
            key.token(EntityLabel::PatientName, "0532 000 00 00"),
            key.token(EntityLabel::Phone, "0532 000 00 00")
        );
    }

    #[test]
    fn casing_variants_fold_onto_one_token() {
        let key = key(4);
        assert_eq!(
            key.token(EntityLabel::PatientName, "AYŞE"),
            key.token(EntityLabel::PatientName, "Ayşe")
        );
    }

    #[test]
    fn folding_keeps_the_four_turkish_i_letters_distinct() {
        // `I` folds to dotless `ı` and `İ` to dotted `i`. The naive
        // `to_lowercase` maps both onto `i`, which merges `Işıl` and `İşil`
        // into one entity and hands two patients the same token.
        assert_eq!(fold("IŞIL"), "ışıl");
        assert_eq!(fold("İŞİL"), "işil");
        assert_ne!(fold("IŞIL"), fold("İŞİL"));
    }

    #[test]
    fn a_token_is_the_configured_width_and_reveals_no_length() {
        let key = key(5);
        let short = key.token(EntityLabel::PatientName, "Ali");
        let long = key.token(
            EntityLabel::PatientName,
            "Abdurrahman Şahinoğlu Karahisarlı",
        );
        assert_eq!(short.len(), long.len());
        assert!(short.starts_with("[PATIENT_NAME:"));
        assert!(short.ends_with(']'));
    }

    #[test]
    fn key_material_below_the_floor_is_refused() {
        assert_eq!(
            HashKey::derive(b"too short").map(|_| ()),
            Err(RedactError::HashKeyTooShort { len: 9 })
        );
        assert!(HashKey::derive(&[7u8; MIN_HASH_KEY_MATERIAL]).is_ok());
    }

    #[test]
    fn derived_keys_differ_with_their_material() {
        let a = HashKey::derive(&[1u8; 32]).expect("key");
        let b = HashKey::derive(&[2u8; 32]).expect("key");
        assert_ne!(
            a.token(EntityLabel::Mrn, "0001"),
            b.token(EntityLabel::Mrn, "0001")
        );
    }
}
