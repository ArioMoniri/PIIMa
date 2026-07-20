//! L5 -- consistent, format-preserving surrogates.
//!
//! The contract: masked spans plus the original text plus a per-document salt
//! go in; de-identified text plus the round-trip [`SpanMap`] come out. Three
//! properties, all mandatory, and each one is a defence against a different
//! attack:
//!
//! **(a) Preserve type and format.** A name becomes a Turkish name, a TCKN
//! becomes a CHECKSUM-VALID fake TCKN, an IBAN becomes a mod-97-valid fake TR
//! IBAN, a phone number becomes a valid Turkish shape. The threat this answers
//! is not re-identification, it is abandonment: a note whose identifier fields
//! no longer validate is rejected by the hospital system that has to ingest it,
//! and a de-identification tool nobody can deploy protects nobody. See
//! [`format`].
//!
//! **(b) Consistent within a document.** The same entity always maps to the
//! same surrogate, keyed by a KEYED hash of the covered text under the salt, so
//! `Ayşe Yılmaz` in the history and `Ayşe Yılmaz` in the discharge summary are
//! still the same person to a reader. Without this the note stops being
//! clinically readable and stops being usable as research data.
//!
//! **(c) Break structural tells, EXCEPT the date format.** Length and casing
//! are not preserved for names, addresses, identifiers or contact details: if a
//! four-letter name always became a four-letter name, the span map's shape
//! alone narrows the candidate list, and `structural leakage` is one of L6's
//! seven attack classes. Surrogate length there is drawn from the keyed stream
//! and never reads the original's length.
//!
//! DATES ARE A DELIBERATE, MEASURED EXCEPTION. A date surrogate re-emits the
//! original's WRITTEN FORM so downstream parsers keep working (see `DateStyle`
//! in [`format`]), and since a format determines a width, date length tracks
//! date length. Measured over the committed corpus by
//! `length_correlation_by_label_over_the_committed_corpus`: r = 0.85 for
//! `DATE_BIRTH`, 0.89 for `DATE_ADMISSION`, 1.0000 for `DATE_DEATH`, against
//! -0.06 for `PATIENT_NAME` and 0.17 for `CLINICIAN_NAME`. What leaks is the
//! AUTHOR'S TEMPLATE, which the surrounding unmasked prose already shows, not
//! the value, which the shift destroys. ADR D-028 records the trade and the
//! numbers; the flat claim "length is not preserved" was false as written.
//!
//! # Date shifting
//!
//! Dates take a SINGLE per-salt offset, so INTERVALS survive exactly while
//! absolute dates are fake. This is clinically necessary rather than a nicety:
//! a chemotherapy cycle three weeks after admission has to still be three weeks
//! after admission, or the de-identified record cannot support the research it
//! was de-identified for. `date_shifting_preserves_intervals_exactly` and
//! `date_shifting_moves_absolute_dates` state both halves.
//!
//! # The salt, and the tension the red team will attack
//!
//! [`SaltScope`] is an explicit configuration choice because the two options
//! are a genuine trade with no free answer, and the trade is the first thing an
//! adversary will probe:
//!
//! - [`SaltScope::Document`] (the DEFAULT): a fresh salt per document. The same
//!   patient in two notes receives two different surrogates, so CROSS-DOCUMENT
//!   LINKAGE IS BROKEN -- an attacker who obtains a corpus cannot chain notes
//!   together into a longitudinal profile, which is the single most effective
//!   re-identification technique against a de-identified corpus. The cost is
//!   real and falls on research: LONGITUDINAL LINKAGE IS ALSO BROKEN, so no
//!   downstream study can follow one patient's trajectory across encounters.
//! - [`SaltScope::Patient`]: one salt per patient across every document. The
//!   trajectory survives and cohort studies become possible; so does the
//!   attacker's linkage, because a surrogate is now a stable pseudonym and
//!   every quasi-identifier that leaks in any one note narrows the whole chain.
//!
//! The default is the privacy-preserving option, and the utility-preserving one
//! has to be selected deliberately. That direction is I2's reasoning applied to
//! the surrogate layer: an unusable research dataset is a papercut, a linkable
//! corpus is a breach.
//!
//! # Security note on `text_hash`
//!
//! `Span::text_hash` is 64 bits of UNKEYED FNV-1a. An attacker holding a span
//! map can enumerate Turkish given names, hash each, and confirm whether a
//! specific patient appears -- which partially defeats "never store the text".
//! THIS MODULE DOES NOT USE IT. Surrogate identity is keyed on a BLAKE2s-256
//! digest under the per-document salt (see [`keyed_hash`]), so the same
//! enumeration additionally requires key material that is never written to the
//! map. The `u64` stays on `Span` because changing its type is an API break for
//! every binding; it is left as an internal merge-consistency aid and is no
//! longer load-bearing for privacy. Recorded as ADR D-024.
//!
//! **Residual exposure, stated precisely.** The [`SpanMap`] itself holds the
//! original text in cleartext, because re-identification is impossible
//! otherwise -- a map is as sensitive as the document it came from, and the
//! keyed hash protects the DERIVATION, not the table. What the key buys is
//! this: an attacker who obtains a `Span` (offsets, label, hash) WITHOUT the
//! map, or who obtains derived keys, cannot confirm a guessed name. An attacker
//! who obtains the map has the document.

mod format;
// VISIBLE TO THE CRATE, not just to L5. `redact::Hash` needs a keyed hash for
// exactly the reason L5 does, and the alternative to sharing this one was a
// second from-scratch BLAKE2s in `redact/`. Two implementations of one
// primitive means two sets of test vectors, and the one that rots is the one
// nobody looks at. The module stays private to the crate: it is not a public
// cryptographic API and must not become one.
pub(crate) mod keyed_hash;
mod map;
mod pools;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::label::EntityLabel;
use crate::span::Span;

use keyed_hash::{Blake2s, Stream, DIGEST_LEN};

pub use map::{SpanMap, SurrogateEntry};

/// Salt width in bytes.
pub const SALT_LEN: usize = DIGEST_LEN;

/// The shortest key material [`Salt::derive`] will accept.
///
/// 128 bits, because the salt is the only thing standing between a span map's
/// derived keys and a dictionary attack over Turkish given names; a
/// sixteen-byte floor makes that attack cost more than the corpus is worth.
pub const MIN_KEY_MATERIAL: usize = 16;

/// The widest a date shift can be, in days either direction.
///
/// Two years. Wide enough that the shifted date carries no usable information
/// about the true one, narrow enough that a note still reads as belonging to
/// roughly the era it was written in -- a discharge summary shifted by a decade
/// would mention drugs that did not exist, which is itself a tell.
pub const MAX_DATE_SHIFT_DAYS: i64 = 730;

/// How many times a surrogate is re-derived before the engine gives up.
///
/// A bound rather than an unbounded loop, because "regenerate on collision" with
/// no ceiling is a hang under an adversarial input, and a masking pipeline that
/// hangs is a masking pipeline that gets switched off.
const MAX_ATTEMPTS: usize = 64;

/// Everything L5 can refuse to do.
///
/// I4 applies here as it does to [`crate::Error`]: no variant carries document
/// text, covered text, or a surrogate. Offsets, counts and lengths only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SurrogateError {
    /// Key material shorter than [`MIN_KEY_MATERIAL`].
    #[error("salt key material of {len} bytes is below the minimum accepted width")]
    KeyMaterialTooShort { len: usize },

    /// Two spans handed to [`SurrogateEngine::apply`] cover the same bytes.
    ///
    /// Not resolved silently. Overlap resolution is `union_widest`'s job in the
    /// span algebra, and an L5 that quietly picked a winner would be a second,
    /// invisible merge rule with different semantics from the documented one.
    #[error("spans {left_start}..{left_end} and {right_start}..{right_end} overlap")]
    OverlappingSpans {
        left_start: usize,
        left_end: usize,
        right_start: usize,
        right_end: usize,
    },

    /// A span points outside the document it was applied to.
    #[error("span offset {offset} lies outside a document of {doc_len} bytes")]
    SpanOutOfBounds { offset: usize, doc_len: usize },

    /// Every re-derivation collided with the allowlist or with another
    /// surrogate.
    ///
    /// REACHABLE, and only for the closed-vocabulary families. A name is drawn
    /// from a combinatorial space (given x given x surname) that no real
    /// document exhausts, but `ADDRESS_CITY` draws from 32 provinces and
    /// `FACILITY_NAME` from 96 combinations, so a document naming more distinct
    /// cities than Turkey has provinces has nowhere left to go.
    ///
    /// FAILING IS THE CORRECT ANSWER THERE, and the alternative is worse:
    /// handing two different cities the same surrogate makes
    /// [`SpanMap::reidentify`] ambiguous, so the gateway would silently restore
    /// the wrong one on the way back. A loud error is a deployment problem; a
    /// silent mis-restoration is a clinical one.
    #[error("no distinct surrogate found for a {label} span after {attempts} attempts")]
    Exhausted { label: EntityLabel, attempts: usize },
}

/// Whose secret the salt is.
///
/// See the module header for the full statement of the trade. In one line: the
/// default breaks the attacker's cross-document linkage AND the researcher's
/// longitudinal linkage, and the alternative preserves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaltScope {
    /// One salt per document. Privacy-preserving; the default.
    #[default]
    Document,
    /// One salt per patient across documents. Utility-preserving; opt in.
    Patient,
}

impl SaltScope {
    /// The tag bound into every derivation under this scope.
    ///
    /// Bound in so that the same key material used at two scopes cannot yield
    /// the same surrogates: a deployment that switches from per-document to
    /// per-patient salting must not accidentally make its old documents
    /// linkable to its new ones.
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::Document => b"scope/document",
            Self::Patient => b"scope/patient",
        }
    }
}

/// The secret that keys every derivation for one document or one patient.
///
/// NO `Debug`, NO `Display`, NO `PartialEq`. A `{:?}` on a key is a key
/// disclosure taken by a path nobody chose, which is exactly the argument
/// `AuditEntry` makes about rationales (D-013) applied to key material;
/// equality is omitted because a comparison that short-circuits on the first
/// differing byte is a timing oracle, and no caller in this crate needs one.
///
/// THE CRATE DOES NOT GENERATE SALTS. `core/` performs no I/O (I1), so it has
/// no access to an operating-system CSPRNG and cannot honestly claim to produce
/// unpredictable bytes. Key material is the caller's responsibility -- a
/// binding calls `getrandom` or the platform keystore and passes the bytes in.
/// A core that invented its own randomness would be inventing it from a
/// counter, and a salt an attacker can guess is not a salt.
#[derive(Clone)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    /// Adopt exactly [`SALT_LEN`] bytes of caller-supplied key material.
    #[must_use]
    pub const fn from_bytes(key: [u8; SALT_LEN]) -> Self {
        Self(key)
    }

    /// Derive a salt from at least [`MIN_KEY_MATERIAL`] bytes.
    ///
    /// The derivation runs the material through the keyed hash rather than
    /// truncating or padding it, so a caller who supplies a passphrase or a
    /// 64-byte token gets full-width key material either way, and a short one
    /// is refused rather than silently stretched.
    pub fn derive(key_material: &[u8]) -> Result<Self, SurrogateError> {
        if key_material.len() < MIN_KEY_MATERIAL {
            return Err(SurrogateError::KeyMaterialTooShort {
                len: key_material.len(),
            });
        }
        let mut hasher = Blake2s::keyed(key_material);
        hasher.update_field(b"deid-tr/L5/salt/v1");
        hasher.update_field(key_material);
        Ok(Self(hasher.finalize()))
    }

    fn hasher(&self, domain: &[u8]) -> Blake2s {
        let mut hasher = Blake2s::keyed(&self.0);
        hasher.update_field(domain);
        hasher
    }
}

/// Turkish-aware case folding.
///
/// `str::to_lowercase` maps `I` to `i` and `İ` to `i` plus a combining dot,
/// which merges two of Turkish's four distinct `i` letters and corrupts the
/// other. The two capitals are therefore mapped explicitly before the Unicode
/// fold runs. Folding matters twice here: it is how `AYŞE` and `Ayşe` reach the
/// same surrogate (property (b) across casing variants, which also destroys the
/// casing tell of property (c)), and it is how a surrogate is compared against
/// the medical allowlist.
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

/// The class C allowlist, folded, loaded once.
///
/// Built from [`crate::route::vocabulary`] rather than from a second list of
/// `include_str!` calls. It used to hold its own copy of the nine file names,
/// which meant a term file added to the append-only `eval/allowlist/`
/// directory had to be remembered in two places and L5 would silently keep
/// minting surrogates that collide with a vocabulary L4 already knew about.
/// One list, one drift test.
///
/// A surrogate that collides with a medical term is the failure this exists to
/// prevent -- minting the surname `Deva` or `Costa` puts a word in the note
/// that L4 will subsequently argue is vocabulary, and a surrogate that reads as
/// a drug name changes what the note appears to say.
fn allowlist() -> &'static BTreeSet<String> {
    static CELL: OnceLock<BTreeSet<String>> = OnceLock::new();
    CELL.get_or_init(|| crate::route::vocabulary::terms().map(fold).collect())
}

/// True when the candidate, or any word in it, is medical vocabulary.
///
/// Word-level as well as whole-string, because a surrogate is often a phrase
/// (`Umut Deva`, `Beyaz Zambak Tıp Merkezi`) and a single allowlisted word
/// inside it is enough to make the note read wrongly.
fn collides_with_allowlist(candidate: &str) -> bool {
    let list = allowlist();
    let folded = fold(candidate);
    if list.contains(&folded) {
        return true;
    }
    folded
        .split(|c: char| c.is_whitespace() || c == '.' || c == ',')
        .any(|word| !word.is_empty() && list.contains(word))
}

/// What kind of thing a label is, for the purpose of minting a replacement.
///
/// KEYED ON THE FAMILY, NOT THE LABEL, and that is what makes cross-references
/// hold. A person named as `PATIENT_NAME` in the history and as
/// `RELATIVE_NAME` in the social section is one person, and giving them two
/// surrogates would silently split them into two -- destroying exactly the
/// readability property (b) exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Name,
    Tckn,
    Vkn,
    Iban,
    Phone,
    Email,
    NumericId,
    DateLike,
    City,
    District,
    Street,
    PostalCode,
    Facility,
    Plate,
    Passport,
    Url,
    IpAddress,
    /// No format worth preserving; a labelled placeholder instead.
    Opaque,
}

impl Family {
    const fn of(label: EntityLabel) -> Self {
        match label {
            EntityLabel::PatientName | EntityLabel::ClinicianName | EntityLabel::RelativeName => {
                Self::Name
            }
            EntityLabel::Tckn => Self::Tckn,
            EntityLabel::Vkn => Self::Vkn,
            EntityLabel::Iban => Self::Iban,
            EntityLabel::Phone => Self::Phone,
            EntityLabel::Email => Self::Email,
            EntityLabel::Url => Self::Url,
            EntityLabel::IpAddress => Self::IpAddress,
            EntityLabel::Date
            | EntityLabel::DateBirth
            | EntityLabel::DateAdmission
            | EntityLabel::DateDischarge
            | EntityLabel::DateDeath => Self::DateLike,
            EntityLabel::AddressCity => Self::City,
            EntityLabel::AddressDistrict => Self::District,
            EntityLabel::AddressStreet => Self::Street,
            EntityLabel::PostalCode => Self::PostalCode,
            EntityLabel::FacilityName => Self::Facility,
            EntityLabel::LicensePlate => Self::Plate,
            EntityLabel::PassportNo => Self::Passport,
            EntityLabel::Mrn
            | EntityLabel::SgkNo
            | EntityLabel::DeviceId
            | EntityLabel::VehicleId
            | EntityLabel::HealthPlanId
            | EntityLabel::AccountNo
            | EntityLabel::CertificateNo
            | EntityLabel::OtherUniqueId => Self::NumericId,
            // AGE_OVER_89, BIOMETRIC_ID, PHOTO_REF and every quasi-identifier.
            //
            // A quasi-identifier is a MEANING ("works at the Central Bank"),
            // not a value with a format, so there is nothing to preserve and
            // substituting a plausible-sounding employer would FABRICATE
            // clinical content -- inventing a fact about a patient is worse
            // than an obvious placeholder. An age over 89 is aggregated by
            // Safe Harbor rather than replaced, for the same reason.
            _ => Self::Opaque,
        }
    }

    /// The tag bound into the derivation, so two families never share a key.
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::Name => b"name",
            Self::Tckn => b"tckn",
            Self::Vkn => b"vkn",
            Self::Iban => b"iban",
            Self::Phone => b"phone",
            Self::Email => b"email",
            Self::NumericId => b"numeric-id",
            Self::DateLike => b"date",
            Self::City => b"city",
            Self::District => b"district",
            Self::Street => b"street",
            Self::PostalCode => b"postal-code",
            Self::Facility => b"facility",
            Self::Plate => b"plate",
            Self::Passport => b"passport",
            Self::Url => b"url",
            Self::IpAddress => b"ip",
            Self::Opaque => b"opaque",
        }
    }
}

/// L5, configured.
///
/// No `Debug`: it holds a [`Salt`].
pub struct SurrogateEngine {
    salt: Salt,
    scope: SaltScope,
    date_shift: i64,
}

impl SurrogateEngine {
    /// An engine at the default (privacy-preserving) salt scope.
    #[must_use]
    pub fn new(salt: Salt) -> Self {
        Self::with_scope(salt, SaltScope::default())
    }

    /// An engine at an explicitly chosen salt scope.
    ///
    /// Choosing [`SaltScope::Patient`] is a decision to preserve longitudinal
    /// linkage for research AND for an attacker; see the module header.
    #[must_use]
    pub fn with_scope(salt: Salt, scope: SaltScope) -> Self {
        let date_shift = derive_date_shift(&salt, scope);
        Self {
            salt,
            scope,
            date_shift,
        }
    }

    /// The configured scope.
    #[must_use]
    pub const fn scope(&self) -> SaltScope {
        self.scope
    }

    /// The single offset applied to every date under this salt.
    ///
    /// Exposed because it is the number that makes intervals verifiable: a
    /// reviewer asking "did this pipeline preserve the chemotherapy interval"
    /// is asking whether one offset was used, and an engine that could not
    /// state its offset could not be audited. It is NOT a secret in the way the
    /// salt is -- knowing the shift lets an attacker recover absolute dates, so
    /// it must be treated as part of the span map, not published alongside the
    /// de-identified text.
    #[must_use]
    pub const fn date_shift_days(&self) -> i64 {
        self.date_shift
    }

    /// A fresh, empty assignment table over this engine.
    #[must_use]
    pub fn assigner(&self) -> Assigner<'_> {
        Assigner {
            engine: self,
            by_key: BTreeMap::new(),
            taken: BTreeMap::new(),
        }
    }

    /// De-identify `text`, replacing every span with its surrogate.
    ///
    /// Spans may arrive in any order but must not overlap: resolving overlaps
    /// is the span algebra's job (`union_widest`), and doing it again here with
    /// possibly different semantics is how two merge rules end up in one
    /// pipeline.
    pub fn apply(&self, text: &str, spans: &[Span]) -> Result<(String, SpanMap), SurrogateError> {
        let mut ordered: Vec<&Span> = spans.iter().collect();
        ordered.sort_by_key(|span| (span.start(), span.end()));
        for pair in ordered.windows(2) {
            let (left, right) = (pair[0], pair[1]);
            if left.end() > right.start() {
                return Err(SurrogateError::OverlappingSpans {
                    left_start: left.start(),
                    left_end: left.end(),
                    right_start: right.start(),
                    right_end: right.end(),
                });
            }
        }

        let mut assigner = self.assigner();
        let mut out = String::with_capacity(text.len());
        let mut span_map = SpanMap::new();
        let mut cursor = 0usize;

        for span in ordered {
            let original = slice(text, span.start(), span.end())?;
            out.push_str(slice(text, cursor, span.start())?);
            let output_start = out.len();
            let surrogate = assigner.assign(span.label(), original)?;
            out.push_str(&surrogate);
            let output_end = out.len();
            cursor = span.end();
            span_map.push(SurrogateEntry::new(
                span.label(),
                span.start(),
                span.end(),
                output_start,
                output_end,
                original.to_owned(),
                surrogate,
            ));
        }
        out.push_str(slice(text, cursor, text.len())?);
        Ok((out, span_map))
    }

    /// Derive the identity key for one entity.
    fn entity_key(&self, family: Family, original: &str) -> [u8; DIGEST_LEN] {
        let mut hasher = self.salt.hasher(b"deid-tr/L5/entity/v1");
        hasher.update_field(self.scope.tag());
        hasher.update_field(family.tag());
        // FOLDED, so casing variants of one entity share a key. This is both
        // half of property (b) and half of property (c): the surrogate cannot
        // echo the original's casing because the derivation never saw it.
        hasher.update_field(fold(original).as_bytes());
        hasher.finalize()
    }

    /// Mint a candidate surrogate for one attempt number.
    fn mint(&self, family: Family, label: EntityLabel, original: &str, attempt: usize) -> String {
        let mut hasher = self.salt.hasher(b"deid-tr/L5/seed/v1");
        hasher.update_field(&self.entity_key(family, original));
        hasher.update(&(attempt as u64).to_le_bytes());
        let mut stream = Stream::new(hasher.finalize());

        match family {
            Family::Name => name(&mut stream),
            Family::Tckn => format::tckn(&mut stream),
            Family::Vkn => format::vkn(&mut stream),
            Family::Iban => format::iban(&mut stream),
            Family::Phone => format::phone(&mut stream),
            Family::Email => email(&mut stream),
            Family::NumericId => format::digits(&mut stream, 6, 12),
            Family::PostalCode => format::digits(&mut stream, 5, 5),
            Family::DateLike => date(original, self.date_shift, &mut stream),
            Family::City => pick(&mut stream, &pools::CITIES),
            Family::District => pick(&mut stream, &pools::DISTRICTS),
            Family::Street => street(&mut stream),
            Family::Facility => facility(&mut stream),
            Family::Plate => plate(&mut stream),
            Family::Passport => passport(&mut stream),
            Family::Url => url(&mut stream),
            Family::IpAddress => ip(&mut stream),
            Family::Opaque => format!("[{}]", label.as_str()),
        }
    }
}

/// The single per-salt date offset.
///
/// Never zero: a zero shift leaves every date in the note true, which is the
/// one outcome the shift exists to prevent, and it would happen once in every
/// 1461 salts if the residue were used directly. The draw is therefore over
/// `1..=2*MAX` and mapped onto the two non-zero halves.
fn derive_date_shift(salt: &Salt, scope: SaltScope) -> i64 {
    let mut hasher = salt.hasher(b"deid-tr/L5/date-shift/v1");
    hasher.update_field(scope.tag());
    let digest = hasher.finalize();
    let mut value = 0u64;
    for byte in digest.iter().take(8) {
        value = (value << 8) | u64::from(*byte);
    }
    let span = (MAX_DATE_SHIFT_DAYS as u64) * 2;
    let offset = (value % span) as i64;
    if offset < MAX_DATE_SHIFT_DAYS {
        offset - MAX_DATE_SHIFT_DAYS
    } else {
        offset - MAX_DATE_SHIFT_DAYS + 1
    }
}

/// A Turkish name of one to three tokens.
///
/// THE TOKEN COUNT IS DRAWN, not copied. Replacing a one-token original with a
/// one-token surrogate would preserve "this note referred to the patient by
/// given name only", which is a habit that identifies the AUTHOR and correlates
/// with the department -- another structural tell.
fn name(stream: &mut Stream) -> String {
    let given = pick(stream, &pools::GIVEN_NAMES);
    match stream.below(4) {
        0 => given,
        1 => format!("{given} {}", pick(stream, &pools::SURNAMES)),
        2 => format!(
            "{given} {} {}",
            pick(stream, &pools::GIVEN_NAMES),
            pick(stream, &pools::SURNAMES)
        ),
        _ => format!("{given} {}", pick(stream, &pools::SURNAMES)),
    }
}

fn email(stream: &mut Stream) -> String {
    let local = format!(
        "{}.{}",
        fold(&pick(stream, &pools::GIVEN_NAMES)),
        fold(&pick(stream, &pools::SURNAMES))
    );
    // ASCII-fold the local part: an address with `ş` in it is legal under
    // SMTPUTF8 and rejected by a great many validators, and property (a) is
    // about the output still being accepted.
    let local: String = local
        .chars()
        .map(|c| match c {
            'ç' => 'c',
            'ğ' => 'g',
            'ı' => 'i',
            'ö' => 'o',
            'ş' => 's',
            'ü' => 'u',
            other => other,
        })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();
    format!("{local}@{}", pick(stream, &pools::EMAIL_DOMAINS))
}

fn street(stream: &mut Stream) -> String {
    let stem = pick(stream, &pools::STREETS);
    let kind = match stream.below(3) {
        0 => "Cad.",
        1 => "Sok.",
        _ => "Bulvarı",
    };
    format!("{stem} {kind} No: {}", stream.between(1, 240))
}

fn facility(stream: &mut Stream) -> String {
    format!(
        "{} {}",
        pick(stream, &pools::FACILITY_STEMS),
        pick(stream, &pools::FACILITY_KINDS)
    )
}

/// A Turkish licence plate: province code, letters, digits.
fn plate(stream: &mut Stream) -> String {
    let letters = pick(stream, &pools::PLATE_LETTERS);
    let digit_count = if letters.len() == 3 { 2 } else { 4 };
    let number: String = (0..digit_count)
        .map(|_| char::from(b'0' + stream.digit()))
        .collect();
    format!("{:02} {letters} {number}", stream.between(1, 81))
}

fn passport(stream: &mut Stream) -> String {
    let letter = char::from(b'A' + stream.below(26) as u8);
    format!("{letter}{}", format::digits(stream, 8, 8))
}

fn url(stream: &mut Stream) -> String {
    // `.example` and `example.tr` are reserved for documentation, so a
    // surrogate URL can never resolve to somebody's real site.
    format!(
        "https://{}.example.tr/kayit/{}",
        fold(&pick(stream, &pools::FACILITY_STEMS))
            .replace(' ', "-")
            .replace(['ç', 'ğ', 'ı', 'ö', 'ş', 'ü'], "-"),
        format::digits(stream, 4, 8)
    )
}

fn ip(stream: &mut Stream) -> String {
    // RFC 1918 space: a surrogate address that routes on the public internet
    // could point a downstream system at a stranger's host.
    format!(
        "10.{}.{}.{}",
        stream.below(256),
        stream.below(256),
        stream.between(1, 254)
    )
}

/// A shifted date, or a synthesised one when the original did not parse.
fn date(original: &str, shift: i64, stream: &mut Stream) -> String {
    match format::parse_date(original) {
        Some(parsed) => parsed.shifted(shift),
        // AN UNPARSEABLE DATE IS STILL MASKED, and this is the recall-safe
        // direction (I2): some layer labelled these bytes a date, and emitting
        // the original because L5 could not read it would leave the identifier
        // in the document. A synthesised date is the honest failure -- it does
        // not preserve the interval, because there was no interval to read.
        None => format!(
            "{:02}.{:02}.{:04}",
            stream.between(1, 28),
            stream.between(1, 12),
            stream.between(1990, 2024)
        ),
    }
}

fn pick(stream: &mut Stream, pool: &[&str]) -> String {
    stream
        .pick(pool)
        .map_or_else(String::new, |s| (*s).to_owned())
}

fn slice(text: &str, start: usize, end: usize) -> Result<&str, SurrogateError> {
    text.get(start..end).ok_or(SurrogateError::SpanOutOfBounds {
        offset: end,
        doc_len: text.len(),
    })
}

/// The assignment table for one document.
///
/// Separate from [`SurrogateEngine`] because the engine is a pure function of
/// its salt and can be shared, while the table is the mutable state that makes
/// property (b) true and has to be discarded with the document.
pub struct Assigner<'a> {
    engine: &'a SurrogateEngine,
    /// Identity key -> (folded original, surrogate).
    ///
    /// The folded original is kept ALONGSIDE the key so a digest collision can
    /// be DETECTED rather than assumed away; see [`Assigner::assign`].
    by_key: BTreeMap<[u8; DIGEST_LEN], (String, String)>,
    /// Surrogate -> the key that owns it.
    taken: BTreeMap<String, [u8; DIGEST_LEN]>,
}

impl Assigner<'_> {
    /// The surrogate for one entity, minting it on first sight.
    ///
    /// COLLISIONS ARE HANDLED, NOT ASSUMED AWAY, and there are two distinct
    /// kinds that need two different answers:
    ///
    /// 1. **Derivation collision** -- two different originals hashing to the
    ///    same 256-bit key. Astronomically improbable, and handled anyway,
    ///    because "improbable" is how a round-trip table silently starts
    ///    mapping two patients onto one name. Detected by keeping the folded
    ///    original next to the key and comparing; a mismatch falls through to a
    ///    fresh derivation salted with the original itself.
    /// 2. **Surrogate collision** -- two different entities drawing the same
    ///    replacement out of the pools. Not improbable at all: with 48 given
    ///    names, two single-token names collide roughly once in 48. Detected
    ///    against `taken` and resolved by re-deriving at the next attempt
    ///    number, which is deterministic, so the same document always resolves
    ///    the same way.
    ///
    /// An allowlist hit is treated as a third rejection condition on the same
    /// loop: a surrogate that reads as a drug or a diagnosis is regenerated.
    pub fn assign(&mut self, label: EntityLabel, original: &str) -> Result<String, SurrogateError> {
        let family = Family::of(label);
        let folded = fold(original);
        let key = self.engine.entity_key(family, original);

        // Cloned out of the map before any mutation, so the collision branch
        // can take `&mut self` without holding a borrow of the entry.
        if let Some((seen, surrogate)) = self.by_key.get(&key).cloned() {
            if seen == folded {
                return Ok(surrogate);
            }
            // Kind 1. Two distinct entities under one key: reusing the
            // surrogate would make re-identification ambiguous, so the second
            // entity is pushed onto a disjoint derivation instead.
            let mut hasher = self.engine.salt.hasher(b"deid-tr/L5/collision/v1");
            hasher.update_field(&key);
            hasher.update_field(folded.as_bytes());
            let disjoint = hasher.finalize();
            return self.mint_unique(family, label, original, disjoint);
        }

        self.mint_unique(family, label, original, key)
    }

    /// Every entity assigned so far, as (key-scoped) surrogate strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// True when nothing has been assigned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    fn mint_unique(
        &mut self,
        family: Family,
        label: EntityLabel,
        original: &str,
        key: [u8; DIGEST_LEN],
    ) -> Result<String, SurrogateError> {
        let folded = fold(original);
        for attempt in 0..MAX_ATTEMPTS {
            let candidate = self.engine.mint(family, label, original, attempt);

            // DATES ARE EXEMPT FROM THE UNIQUENESS LOOP, deliberately. A date
            // surrogate is not a draw from a pool, it is the original moved by
            // the one per-patient offset, and re-deriving it at a different
            // attempt number would produce a different offset for that one date
            // -- destroying exactly the interval property the shift exists to
            // preserve. Two different original dates cannot collide anyway,
            // because adding a constant is injective; and a date cannot collide
            // with a name (names carry no digits) or with a bare numeric id
            // (those carry no separators).
            //
            // Opaque placeholders are exempt for the same structural reason:
            // `[EMPLOYER_ROLE]` is meant to repeat.
            let exempt = matches!(family, Family::DateLike | Family::Opaque);

            if !exempt {
                if collides_with_allowlist(&candidate) {
                    continue;
                }
                if self
                    .taken
                    .get(&candidate)
                    .is_some_and(|owner| *owner != key)
                {
                    continue;
                }
            }

            self.by_key.insert(key, (folded.clone(), candidate.clone()));
            self.taken.insert(candidate.clone(), key);
            return Ok(candidate);
        }
        Err(SurrogateError::Exhausted {
            label,
            attempts: MAX_ATTEMPTS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::QuasiCategory;
    use crate::span::DetectorId;

    /// Fixed key material so every test is reproducible. Not a secret and not
    /// derived from anything real -- a deployment supplies its own from the
    /// platform CSPRNG, which is why `core/` cannot generate one (I1).
    const KEY: [u8; SALT_LEN] = [0x5a; SALT_LEN];

    fn engine() -> SurrogateEngine {
        SurrogateEngine::new(Salt::from_bytes(KEY))
    }

    fn other_engine() -> SurrogateEngine {
        let mut key = KEY;
        key[0] = 0x5b;
        SurrogateEngine::new(Salt::from_bytes(key))
    }

    fn assign(engine: &SurrogateEngine, label: EntityLabel, text: &str) -> String {
        engine
            .assigner()
            .assign(label, text)
            .expect("a surrogate exists")
    }

    /// The committed corpus, embedded at compile time so `core/` still does no
    /// runtime I/O (I1). Every fixture is synthetic (I8).
    const CORPUS: &[&str] = &[
        include_str!("../../../eval/gold/gold_001_020.jsonl"),
        include_str!("../../../eval/gold/gold_021_040.jsonl"),
        include_str!("../../../eval/gold/gold_041_060.jsonl"),
        include_str!("../../../eval/gold/gold_061_080.jsonl"),
        include_str!("../../../eval/gold/gold_081_100.jsonl"),
        include_str!("../../../eval/gold/gold_101_112.jsonl"),
        include_str!("../../../eval/gold/gold_113_116.jsonl"),
        include_str!("../../../eval/adversarial/adv_codeswitch.jsonl"),
        include_str!("../../../eval/adversarial/adv_contextual.jsonl"),
        include_str!("../../../eval/adversarial/adv_direct.jsonl"),
        include_str!("../../../eval/adversarial/adv_eponym.jsonl"),
        include_str!("../../../eval/adversarial/adv_medical_term.jsonl"),
    ];

    /// Below this many pairs a correlation is noise, not a measurement.
    const MIN_CORRELATION_PAIRS: usize = 20;

    /// Below this many pairs a correlation is not worth printing either.
    const MIN_REPORT_PAIRS: usize = 5;

    /// True when every value is the same, which makes Pearson's r undefined.
    fn is_constant(values: &[f64]) -> bool {
        values.windows(2).all(|pair| pair[0] == pair[1])
    }

    /// The `(quote, label)` pairs of one fixture line's DIRECT spans.
    ///
    /// A scan rather than a JSON parser because `core/`'s dependency list is an
    /// enforced invariant (I1) and the fixtures are machine-written with a
    /// fixed key order. The `quasi_spans` array is deliberately excluded: those
    /// are L3's business and are not surrogated. If the format ever changes
    /// this returns nothing and the caller's `assert!` on the pair count fails
    /// loudly, rather than the measurement silently reporting an empty corpus.
    fn corpus_spans(line: &str) -> Vec<(String, EntityLabel)> {
        let mut out = Vec::new();
        let Some(open) = line.find("\"spans\": [") else {
            return out;
        };
        let region = &line[open..];
        let region = match region.find("], \"quasi_spans\"") {
            Some(close) => &region[..close],
            None => region,
        };
        let mut rest = region;
        while let Some(at) = rest.find("\"quote\": \"") {
            rest = &rest[at + "\"quote\": \"".len()..];
            let Some(quote) = json_string(rest) else {
                break;
            };
            let Some(at_label) = rest.find("\"label\": \"") else {
                break;
            };
            let after_label = &rest[at_label + "\"label\": \"".len()..];
            if let Some(name) = json_string(after_label) {
                if let Ok(label) = EntityLabel::from_id(&name) {
                    out.push((quote, label));
                }
            }
            rest = after_label;
        }
        out
    }

    /// One JSON string body, from just after its opening quote to its closing
    /// quote, with the standard escapes resolved.
    fn json_string(rest: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => return Some(out),
                '\\' => match chars.next()? {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    other => out.push(other),
                },
                other => out.push(other),
            }
        }
        None
    }

    fn span(doc: &str, needle: &str, label: EntityLabel) -> Span {
        let start = doc.find(needle).expect("fixture contains the needle");
        Span::new(
            doc,
            start,
            start + needle.len(),
            label,
            DetectorId::Ner(0),
            0.9,
        )
        .expect("valid span")
    }

    // --- property (a): type and format survive -----------------------------

    #[test]
    fn a_name_becomes_a_plausible_turkish_name() {
        let surrogate = assign(&engine(), EntityLabel::PatientName, "Ayşe Yılmaz");
        assert!(!surrogate.is_empty());
        assert!(
            surrogate.chars().all(|c| c.is_alphabetic() || c == ' '),
            "a name surrogate must not carry digits or punctuation: {surrogate}"
        );
        assert_ne!(surrogate, "Ayşe Yılmaz");
    }

    #[test]
    fn a_tckn_becomes_a_checksum_valid_tckn() {
        // The generated value is checksum-VALID and is produced at run time; no
        // valid TCKN is written into this file (I8).
        let surrogate = assign(&engine(), EntityLabel::Tckn, "12345678951");
        assert_eq!(surrogate.len(), 11);
        let digits: Vec<u32> = surrogate.chars().filter_map(|c| c.to_digit(10)).collect();
        assert_eq!(digits.len(), 11);
        assert_ne!(digits[0], 0);
        let odd: u32 = (0..9).step_by(2).map(|i| digits[i]).sum();
        let even: u32 = (1..9).step_by(2).map(|i| digits[i]).sum();
        assert_eq!(digits[9], (odd * 7 + 100 - even) % 10);
        assert_eq!(digits[10], digits[..10].iter().sum::<u32>() % 10);
    }

    #[test]
    fn an_iban_becomes_a_mod_97_valid_tr_iban() {
        let surrogate = assign(&engine(), EntityLabel::Iban, "TR330006100519786457841326");
        assert_eq!(surrogate.len(), 26);
        assert!(surrogate.starts_with("TR"));
        // mod-97 restated here so the assertion does not simply call the
        // generator's own helper back.
        let rearranged = format!(
            "{}{}",
            surrogate.get(4..).expect("body"),
            surrogate.get(..4).expect("head")
        );
        let mut remainder: u32 = 0;
        for ch in rearranged.chars() {
            let value = ch.to_digit(36).expect("alphanumeric");
            remainder = (if value < 10 {
                remainder * 10 + value
            } else {
                remainder * 100 + value
            }) % 97;
        }
        assert_eq!(remainder, 1);
    }

    #[test]
    fn a_phone_becomes_a_valid_shaped_turkish_number() {
        let surrogate = assign(&engine(), EntityLabel::Phone, "0(532) 111 22 33");
        let bare: String = surrogate.chars().filter(char::is_ascii_digit).collect();
        assert!(matches!(bare.len(), 11 | 12), "{surrogate}");
    }

    #[test]
    fn an_email_stays_an_address_and_stays_ascii() {
        let surrogate = assign(&engine(), EntityLabel::Email, "ayse.yilmaz@hastane.gov.tr");
        assert_eq!(surrogate.matches('@').count(), 1);
        assert!(surrogate.is_ascii(), "{surrogate} is not deliverable ASCII");
        let (local, domain) = surrogate.split_once('@').expect("one at-sign");
        assert!(!local.is_empty() && domain.contains('.'));
    }

    #[test]
    fn every_direct_label_produces_a_non_empty_surrogate() {
        // A label with no arm would silently fall through to a placeholder; a
        // label producing an empty string would delete text. Both are caught
        // here rather than in a note.
        let engine = engine();
        for label in EntityLabel::DIRECT {
            let surrogate = assign(&engine, label, "Ayşe 12345678951 01.02.2026");
            assert!(!surrogate.is_empty(), "{label} produced nothing");
        }
    }

    #[test]
    fn a_quasi_identifier_gets_a_placeholder_rather_than_a_fabrication() {
        // Substituting "works at the Ziraat Bankası" for "works at the Merkez
        // Bankası" would invent a fact about a patient. The placeholder is the
        // honest answer.
        let surrogate = assign(
            &engine(),
            EntityLabel::Quasi(QuasiCategory::EmployerRole),
            "Merkez Bankası'nda çalışıyor",
        );
        assert_eq!(surrogate, "[EMPLOYER_ROLE]");
    }

    // --- property (b): consistency within a document -----------------------

    #[test]
    fn the_same_entity_gets_the_same_surrogate_throughout_a_document() {
        let engine = engine();
        let mut assigner = engine.assigner();
        let first = assigner
            .assign(EntityLabel::PatientName, "Ayşe Yılmaz")
            .expect("assigned");
        let again = assigner
            .assign(EntityLabel::PatientName, "Ayşe Yılmaz")
            .expect("assigned");
        assert_eq!(first, again);
        assert_eq!(assigner.len(), 1);
    }

    #[test]
    fn casing_variants_of_one_entity_share_a_surrogate() {
        // `AYŞE YILMAZ` in a header and `Ayşe Yılmaz` in the body are one
        // person. Turkish folding is what makes this true for `I`/`İ`.
        let engine = engine();
        let mut assigner = engine.assigner();
        let title = assigner
            .assign(EntityLabel::PatientName, "İnci Işık")
            .expect("assigned");
        let upper = assigner
            .assign(EntityLabel::PatientName, "İNCİ IŞIK")
            .expect("assigned");
        assert_eq!(title, upper);
    }

    #[test]
    fn one_person_named_in_two_roles_keeps_one_surrogate() {
        // Property (b)'s real purpose: cross-references stay coherent. Keyed on
        // the FAMILY, so PATIENT_NAME and RELATIVE_NAME do not split a person.
        let engine = engine();
        let mut assigner = engine.assigner();
        let as_patient = assigner
            .assign(EntityLabel::PatientName, "Ayşe Yılmaz")
            .expect("assigned");
        let as_relative = assigner
            .assign(EntityLabel::RelativeName, "Ayşe Yılmaz")
            .expect("assigned");
        assert_eq!(as_patient, as_relative);
    }

    #[test]
    fn two_different_entities_get_two_different_surrogates() {
        let engine = engine();
        let mut assigner = engine.assigner();
        let a = assigner
            .assign(EntityLabel::PatientName, "Ayşe Yılmaz")
            .expect("assigned");
        let b = assigner
            .assign(EntityLabel::PatientName, "Mehmet Demir")
            .expect("assigned");
        assert_ne!(a, b);
    }

    #[test]
    fn a_surrogate_collision_is_resolved_rather_than_shared() {
        // The pools are finite, so two names WILL draw the same replacement. If
        // that were accepted, the round-trip table would map one surrogate to
        // two originals and re-identification would silently pick the wrong
        // patient. 400 distinct originals against 48 given names guarantees the
        // collision path runs many times.
        let engine = engine();
        let mut assigner = engine.assigner();
        let mut seen = BTreeSet::new();
        for i in 0..400 {
            let original = format!("Hasta{i} Soyad{i}");
            let surrogate = assigner
                .assign(EntityLabel::PatientName, &original)
                .expect("assigned");
            assert!(
                seen.insert(surrogate.clone()),
                "surrogate {surrogate} was handed to two different entities"
            );
        }
    }

    #[test]
    fn assignment_is_deterministic_across_engines_with_the_same_salt() {
        assert_eq!(
            assign(&engine(), EntityLabel::PatientName, "Ayşe Yılmaz"),
            assign(&engine(), EntityLabel::PatientName, "Ayşe Yılmaz")
        );
    }

    #[test]
    fn a_different_salt_gives_a_different_surrogate() {
        // The salt is what makes a span map from one document useless against
        // another; if it were not load-bearing, cross-document linkage would
        // survive de-identification.
        assert_ne!(
            assign(&engine(), EntityLabel::PatientName, "Ayşe Yılmaz"),
            assign(&other_engine(), EntityLabel::PatientName, "Ayşe Yılmaz")
        );
    }

    #[test]
    fn the_salt_scope_changes_the_derivation() {
        let document = SurrogateEngine::with_scope(Salt::from_bytes(KEY), SaltScope::Document);
        let patient = SurrogateEngine::with_scope(Salt::from_bytes(KEY), SaltScope::Patient);
        assert_eq!(document.scope(), SaltScope::Document);
        assert_ne!(
            assign(&document, EntityLabel::PatientName, "Ayşe Yılmaz"),
            assign(&patient, EntityLabel::PatientName, "Ayşe Yılmaz")
        );
    }

    #[test]
    fn the_default_scope_is_the_privacy_preserving_one() {
        assert_eq!(SaltScope::default(), SaltScope::Document);
        assert_eq!(engine().scope(), SaltScope::Document);
    }

    // --- property (c): structural tells are broken -------------------------

    #[test]
    fn surrogate_length_does_not_correlate_with_original_length() {
        // THE RED TEAM'S STRUCTURAL-LEAKAGE ATTACK, as a measurement. If a
        // four-letter name reliably became a four-letter name, the span map's
        // shape alone would narrow the candidate list. Pearson's r over 300
        // originals spanning 2 to 20 characters must be near zero; the 0.25
        // ceiling leaves room for sampling noise while still failing loudly if
        // anyone reintroduces length matching.
        let engine = engine();
        let mut assigner = engine.assigner();
        let mut xs: Vec<f64> = Vec::new();
        let mut ys: Vec<f64> = Vec::new();
        for i in 0..300 {
            let original = "a".repeat(2 + (i % 19)) + &i.to_string();
            let surrogate = assigner
                .assign(EntityLabel::PatientName, &original)
                .expect("assigned");
            xs.push(original.chars().count() as f64);
            ys.push(surrogate.chars().count() as f64);
        }
        let r = pearson(&xs, &ys);
        assert!(
            r.abs() < 0.25,
            "surrogate length correlates with original length (r = {r})"
        );
    }

    /// The same measurement over the COMMITTED CORPUS, per label -- and the
    /// reason the claim above had to be narrowed.
    ///
    /// The test above draws its originals from one label and one shape, so it
    /// measures the name pool and nothing else. Run over the real corpus it
    /// reads r = 0.86 overall, and the whole DATE family sits between 0.80 and
    /// 1.00 with `DATE_DEATH` at exactly 1.0000. That is not a bug in the pool:
    /// a date surrogate deliberately re-emits the ORIGINAL'S FORMAT
    /// (`14.06.1959` -> another `dd.mm.yyyy`, `14 Haziran 1959` -> another
    /// `d MMMM yyyy`), so the two lengths track each other by construction.
    /// The tell is of FORMAT, not of value, and it is narrower than a name
    /// length tell -- but "length is not preserved" was false as written, and
    /// D-028 records the trade and these numbers rather than quietly widening
    /// the assertion.
    ///
    /// Gated where the guarantee is real (the name family), reported where it
    /// is a known, argued exception (dates).
    #[test]
    fn length_correlation_by_label_over_the_committed_corpus() {
        let engine = engine();
        let mut assigner = engine.assigner();
        let mut all_x: Vec<f64> = Vec::new();
        let mut all_y: Vec<f64> = Vec::new();
        let mut per_label: Vec<(&'static str, Vec<f64>, Vec<f64>)> = Vec::new();

        for file in CORPUS {
            for line in file.lines().filter(|line| !line.trim().is_empty()) {
                for (quote, label) in corpus_spans(line) {
                    let surrogate = assigner.assign(label, &quote).expect("assigned");
                    let (before, after) = (
                        quote.chars().count() as f64,
                        surrogate.chars().count() as f64,
                    );
                    all_x.push(before);
                    all_y.push(after);
                    let name = label.as_str();
                    match per_label.iter_mut().find(|(key, _, _)| *key == name) {
                        Some((_, xs, ys)) => {
                            xs.push(before);
                            ys.push(after);
                        }
                        None => per_label.push((name, vec![before], vec![after])),
                    }
                }
            }
        }

        assert!(all_x.len() > 500, "the corpus did not load");
        let overall = pearson(&all_x, &all_y);
        println!(
            "length correlation over {} pairs: r = {overall:.4}",
            all_x.len()
        );
        per_label.sort_by(|left, right| left.0.cmp(right.0));
        for (name, xs, ys) in &per_label {
            // Reported from a lower bar than it is GATED on: a label with a
            // dozen pairs is too thin to fail a build over and still worth
            // seeing, because the DATE family is small and is the finding.
            if xs.len() < MIN_REPORT_PAIRS {
                continue;
            }
            // `pearson` returns 0.0 when either side has no variance, which
            // reads as "no correlation" and means the opposite: every original
            // was the same length, so the surrogate could not have failed to
            // match it. Saying so is the difference between a measurement and a
            // reassuring number.
            if is_constant(xs) || is_constant(ys) {
                println!(
                    "  {name:<16} n={:<4} r=n/a (one side has no length variance)",
                    xs.len()
                );
            } else {
                println!("  {name:<16} n={:<4} r={:.4}", xs.len(), pearson(xs, ys));
            }
        }

        // The guarantee that is actually claimed, gated: a name surrogate must
        // not carry the original's length. Dates are the argued exception and
        // are excluded here by name rather than by loosening the bound, so an
        // accidental regression in the name pool still fails this test.
        for (name, xs, ys) in &per_label {
            if xs.len() < MIN_CORRELATION_PAIRS || !name.ends_with("NAME") {
                continue;
            }
            let r = pearson(xs, ys);
            assert!(
                r.abs() < 0.35,
                "{name} surrogate length correlates with original length (r = {r})"
            );
        }
    }

    #[test]
    fn surrogate_length_varies_for_a_fixed_original_length() {
        // The complement of the correlation test: zero correlation is also what
        // a constant-length surrogate would produce, and a constant length is
        // its own tell.
        let engine = engine();
        let mut assigner = engine.assigner();
        let lengths: BTreeSet<usize> = (0..60)
            .map(|i| {
                assigner
                    .assign(EntityLabel::PatientName, &format!("abcde{i:03}"))
                    .expect("assigned")
                    .chars()
                    .count()
            })
            .collect();
        assert!(
            lengths.len() > 5,
            "surrogate length barely varies: {lengths:?}"
        );
    }

    #[test]
    fn casing_patterns_are_not_preserved() {
        // An ALL-CAPS original must not yield an ALL-CAPS surrogate: casing is
        // a per-form convention that identifies the source system.
        let surrogate = assign(&engine(), EntityLabel::PatientName, "AYŞE YILMAZ");
        assert!(
            surrogate.chars().any(char::is_lowercase),
            "the surrogate echoed the original's casing: {surrogate}"
        );
    }

    #[test]
    fn a_surrogate_never_collides_with_a_medical_allowlist_term() {
        // `Deva` is a given name and a pharma brand; `Costa` is a Latin rib and
        // a surname. Minting one puts a word into the note that changes what
        // the note appears to say, and that L4 will later argue is vocabulary.
        let engine = engine();
        let mut assigner = engine.assigner();
        // Draw counts are bounded by each family's vocabulary: names come from
        // a combinatorial space, cities from the 32 provinces in the pool.
        for (label, draws) in [
            (EntityLabel::PatientName, 500),
            (EntityLabel::AddressCity, 25),
            (EntityLabel::FacilityName, 25),
            (EntityLabel::AddressStreet, 100),
            (EntityLabel::Email, 100),
        ] {
            for i in 0..draws {
                let surrogate = assigner
                    .assign(label, &format!("Orijinal{label}{i}"))
                    .expect("assigned");
                assert!(
                    !collides_with_allowlist(&surrogate),
                    "surrogate {surrogate} is a medical allowlist term"
                );
            }
        }
    }

    #[test]
    fn exhausting_a_closed_vocabulary_is_a_loud_error_not_a_duplicate() {
        // 32 provinces in the pool. The 33rd distinct city has nowhere to go,
        // and reusing one would make `reidentify` restore the wrong city on the
        // way back -- so the engine refuses instead. This test exists to pin
        // the direction of that failure, not to bless the pool size.
        let engine = engine();
        let mut assigner = engine.assigner();
        let mut minted = BTreeSet::new();
        let mut exhausted = false;
        for i in 0..200 {
            match assigner.assign(EntityLabel::AddressCity, &format!("Sehir{i}")) {
                Ok(surrogate) => assert!(minted.insert(surrogate), "a city was handed out twice"),
                Err(SurrogateError::Exhausted { label, .. }) => {
                    assert_eq!(label, EntityLabel::AddressCity);
                    exhausted = true;
                    break;
                }
                Err(other) => panic!("unexpected failure: {other}"),
            }
        }
        assert!(exhausted, "the closed vocabulary never ran out");
        assert!(
            minted.len() >= 30,
            "the pool gave up early: {}",
            minted.len()
        );
    }

    #[test]
    fn the_allowlist_actually_loaded() {
        // Guards the test above from passing vacuously on an empty set.
        assert!(allowlist().len() > 500);
        assert!(collides_with_allowlist("carcinoma"));
        assert!(collides_with_allowlist("Metformin"));
        assert!(!collides_with_allowlist("Zeynep Yavuz"));
    }

    // --- date shifting ------------------------------------------------------

    #[test]
    fn date_shifting_preserves_intervals_exactly() {
        // The clinical requirement: a chemotherapy cycle three weeks after
        // admission must still be three weeks after admission.
        let engine = engine();
        let mut assigner = engine.assigner();
        let admission = assigner
            .assign(EntityLabel::DateAdmission, "03.02.2026")
            .expect("assigned");
        let cycle = assigner
            .assign(EntityLabel::Date, "24.02.2026")
            .expect("assigned");
        assert_eq!(days_between(&admission, &cycle), 21);

        // And across a year boundary, where naive arithmetic breaks.
        let a = assign(&engine, EntityLabel::Date, "28.12.2025");
        let b = assign(&engine, EntityLabel::Date, "04.01.2026");
        assert_eq!(days_between(&a, &b), 7);
    }

    #[test]
    fn date_shifting_moves_absolute_dates() {
        let engine = engine();
        assert_ne!(engine.date_shift_days(), 0, "a zero shift is no shift");
        assert!(engine.date_shift_days().abs() <= MAX_DATE_SHIFT_DAYS);
        for original in ["03.02.2026", "2026-02-03", "3 Şubat 2026"] {
            let shifted = assign(&engine, EntityLabel::Date, original);
            assert_ne!(shifted, original, "the absolute date survived");
        }
    }

    #[test]
    fn one_offset_covers_every_date_under_one_salt() {
        // "A SINGLE per-patient offset" is the property; two dates shifted by
        // two offsets would preserve nothing.
        let engine = engine();
        let shift = engine.date_shift_days();
        for (original, expected_days) in [("01.01.2020", 0), ("15.06.2021", 531)] {
            let shifted = assign(&engine, EntityLabel::Date, original);
            let base = days("01.01.2020") + shift;
            assert_eq!(days(&shifted) - base, expected_days);
        }
    }

    #[test]
    fn the_written_date_style_survives_so_downstream_parsers_still_work() {
        let engine = engine();
        assert!(assign(&engine, EntityLabel::Date, "2026-02-03").starts_with("20"));
        assert_eq!(
            assign(&engine, EntityLabel::Date, "03/02/2026")
                .matches('/')
                .count(),
            2
        );
    }

    #[test]
    fn an_unreadable_date_is_still_replaced() {
        // I2's direction: some layer said these bytes are a date. Emitting them
        // unchanged because L5 could not parse them would leave the identifier
        // in the document.
        let surrogate = assign(&engine(), EntityLabel::Date, "geçen salı");
        assert_ne!(surrogate, "geçen salı");
        assert!(!surrogate.is_empty());
    }

    // --- the round trip -----------------------------------------------------

    #[test]
    fn apply_rewrites_at_byte_offsets_and_builds_the_round_trip_table() {
        let doc = "Hasta Ayşe Yılmaz, giriş 03.02.2026, Dr. Şükrü Gökçe.";
        let spans = [
            span(doc, "Ayşe Yılmaz", EntityLabel::PatientName),
            span(doc, "03.02.2026", EntityLabel::DateAdmission),
            span(doc, "Şükrü Gökçe", EntityLabel::ClinicianName),
        ];
        let engine = engine();
        let (text, map) = engine.apply(doc, &spans).expect("apply");

        assert!(!text.contains("Ayşe Yılmaz"));
        assert!(!text.contains("Şükrü Gökçe"));
        assert!(!text.contains("03.02.2026"));
        // The prose around the spans survives byte-exactly, multi-byte letters
        // included.
        assert!(text.starts_with("Hasta "));
        assert!(text.contains(", giriş "));
        assert!(text.ends_with('.'));
        assert_eq!(map.len(), 3);

        for entry in map.entries() {
            assert_eq!(
                text.get(entry.output_start..entry.output_end),
                Some(entry.surrogate()),
                "output offsets must address the surrogate in the OUTPUT text"
            );
            assert_eq!(
                doc.get(entry.start..entry.end),
                Some(entry.original()),
                "input offsets must address the original in the INPUT text"
            );
        }
    }

    #[test]
    fn the_span_map_round_trips_model_output_back_to_the_original() {
        // The gateway's inbound path: the model saw only surrogates, so its
        // answer quotes them, and the table has to put the patient back.
        let doc = "Hasta Ayşe Yılmaz kontrole geldi. Ayşe Yılmaz stabil.";
        let spans = [span(doc, "Ayşe Yılmaz", EntityLabel::PatientName), {
            let second = doc.rfind("Ayşe Yılmaz").expect("second mention");
            Span::new(
                doc,
                second,
                second + "Ayşe Yılmaz".len(),
                EntityLabel::PatientName,
                DetectorId::Ner(0),
                0.9,
            )
            .expect("valid span")
        }];
        let (text, map) = engine().apply(doc, &spans).expect("apply");
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.entries()[0].surrogate(),
            map.entries()[1].surrogate(),
            "both mentions must be the same person"
        );
        let model_said = format!("{} stabil görünüyor.", map.entries()[0].surrogate());
        assert_eq!(map.reidentify(&model_said), "Ayşe Yılmaz stabil görünüyor.");
        assert_eq!(map.reidentify(&text), doc);
    }

    #[test]
    fn reidentification_prefers_the_longest_surrogate() {
        // Two surrogates where one is a prefix of the other. Replacing the
        // short one first would rewrite the first half of the long one and
        // leave an orphaned tail.
        let mut map = SpanMap::new();
        map.push(SurrogateEntry::new(
            EntityLabel::PatientName,
            0,
            1,
            0,
            1,
            "Ayşe Yılmaz".to_owned(),
            "Kerem".to_owned(),
        ));
        map.push(SurrogateEntry::new(
            EntityLabel::ClinicianName,
            2,
            3,
            2,
            3,
            "Şükrü Gökçe".to_owned(),
            "Kerem Yavuz".to_owned(),
        ));
        assert_eq!(map.reidentify("Kerem Yavuz"), "Şükrü Gökçe");
    }

    #[test]
    fn overlapping_spans_are_refused_rather_than_silently_resolved() {
        let doc = "Hasta Ayşe Yılmaz geldi.";
        let wide = span(doc, "Ayşe Yılmaz", EntityLabel::PatientName);
        let narrow = span(doc, "Ayşe", EntityLabel::PatientName);
        assert!(matches!(
            engine().apply(doc, &[wide, narrow]),
            Err(SurrogateError::OverlappingSpans { .. })
        ));
    }

    #[test]
    fn adjacent_spans_are_accepted() {
        let doc = "Ayşe Yılmaz";
        let left = span(doc, "Ayşe ", EntityLabel::PatientName);
        let right = span(doc, "Yılmaz", EntityLabel::PatientName);
        assert!(engine().apply(doc, &[left, right]).is_ok());
    }

    #[test]
    fn a_document_with_no_spans_comes_back_unchanged() {
        let doc = "Hastanın carcinoma'lı akciğer grafisi normal.";
        let (text, map) = engine().apply(doc, &[]).expect("apply");
        assert_eq!(text, doc);
        assert!(map.is_empty());
    }

    #[test]
    fn spans_may_arrive_in_any_order() {
        let doc = "Ayşe Yılmaz, Dr. Şükrü Gökçe";
        let a = span(doc, "Ayşe Yılmaz", EntityLabel::PatientName);
        let b = span(doc, "Şükrü Gökçe", EntityLabel::ClinicianName);
        let forward = engine().apply(doc, &[a, b]).expect("apply").0;
        let reversed = engine().apply(doc, &[b, a]).expect("apply").0;
        assert_eq!(forward, reversed);
    }

    // --- I4: the map is the one structure holding PHI ----------------------

    #[test]
    fn debug_on_the_span_map_never_prints_an_original() {
        // The span map is the ONLY place original PHI text lives in memory next
        // to its offsets, so it is the value most likely to egress through a
        // `{:?}`, a failing assertion or a panic message (I4, D-013).
        const PHI: &str = "Ayşe Yılmaz";
        let doc = "Hasta Ayşe Yılmaz geldi.";
        let (_, map) = engine()
            .apply(doc, &[span(doc, PHI, EntityLabel::PatientName)])
            .expect("apply");
        let rendered = format!("{map:?}");
        assert!(!rendered.contains(PHI), "Debug on a SpanMap egressed PHI");
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("PatientName"),
            "the label must stay visible"
        );
        let entry_rendered = format!("{:?}", map.entries()[0]);
        assert!(!entry_rendered.contains(PHI));
        assert!(entry_rendered.contains(map.entries()[0].surrogate()));
    }

    #[test]
    fn the_debug_rendering_does_not_leak_the_original_length() {
        // A `Debug` that printed `original: 11 bytes` would hand back exactly
        // the length tell the rest of L5 destroys.
        let doc = "Hasta Ayşe Yılmaz ve Su Ak geldi.";
        let (_, map) = engine()
            .apply(
                doc,
                &[
                    span(doc, "Ayşe Yılmaz", EntityLabel::PatientName),
                    span(doc, "Su Ak", EntityLabel::RelativeName),
                ],
            )
            .expect("apply");
        let long = format!("{:?}", map.entries()[0]);
        let short = format!("{:?}", map.entries()[1]);
        let redacted_part = |s: &str| {
            s.split("original: ")
                .nth(1)
                .and_then(|tail| tail.split(',').next())
                .map(str::to_owned)
        };
        assert_eq!(redacted_part(&long), redacted_part(&short));
    }

    #[test]
    fn no_error_variant_carries_text() {
        // I4 as a test rather than a review note: every variant renders from
        // offsets, counts and labels only.
        let errors = [
            SurrogateError::KeyMaterialTooShort { len: 4 },
            SurrogateError::OverlappingSpans {
                left_start: 6,
                left_end: 17,
                right_start: 6,
                right_end: 10,
            },
            SurrogateError::SpanOutOfBounds {
                offset: 99,
                doc_len: 24,
            },
            SurrogateError::Exhausted {
                label: EntityLabel::PatientName,
                attempts: MAX_ATTEMPTS,
            },
        ];
        for error in errors {
            let rendered = error.to_string();
            assert!(!rendered.contains("Ayşe"));
            assert!(!rendered.is_empty());
        }
    }

    // --- salt handling ------------------------------------------------------

    #[test]
    fn short_key_material_is_refused() {
        // Matched rather than unwrapped: `Salt` deliberately has no `Debug`,
        // so `unwrap_err` does not compile against it -- which is the property
        // being relied on, not an inconvenience.
        assert!(matches!(
            Salt::derive(b"kisa"),
            Err(SurrogateError::KeyMaterialTooShort { len: 4 })
        ));
        assert!(Salt::derive(&[7u8; MIN_KEY_MATERIAL]).is_ok());
    }

    #[test]
    fn derived_salts_differ_when_the_key_material_differs() {
        let a = SurrogateEngine::new(Salt::derive(&[1u8; 32]).expect("salt"));
        let b = SurrogateEngine::new(Salt::derive(&[2u8; 32]).expect("salt"));
        assert_ne!(
            assign(&a, EntityLabel::PatientName, "Ayşe Yılmaz"),
            assign(&b, EntityLabel::PatientName, "Ayşe Yılmaz")
        );
    }

    // --- helpers ------------------------------------------------------------

    /// Day count of a `dd.mm.yyyy` surrogate, for the interval assertions.
    fn days(date: &str) -> i64 {
        let parts: Vec<i64> = date
            .split(['.', '-', '/'])
            .filter_map(|p| p.parse().ok())
            .collect();
        assert_eq!(parts.len(), 3, "unparsed surrogate date {date}");
        let (year, month, day) = if parts[0] > 31 {
            (parts[0], parts[1], parts[2])
        } else {
            (parts[2], parts[1], parts[0])
        };
        let year = if month <= 2 { year - 1 } else { year };
        let era = year / 400;
        let yoe = year - era * 400;
        let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    fn days_between(a: &str, b: &str) -> i64 {
        days(b) - days(a)
    }

    fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
        let n = xs.len() as f64;
        let mean_x = xs.iter().sum::<f64>() / n;
        let mean_y = ys.iter().sum::<f64>() / n;
        let mut cov = 0.0;
        let mut var_x = 0.0;
        let mut var_y = 0.0;
        for (x, y) in xs.iter().zip(ys) {
            cov += (x - mean_x) * (y - mean_y);
            var_x += (x - mean_x).powi(2);
            var_y += (y - mean_y).powi(2);
        }
        if var_x == 0.0 || var_y == 0.0 {
            return 0.0;
        }
        cov / (var_x.sqrt() * var_y.sqrt())
    }
}
