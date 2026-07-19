//! The label vocabulary.
//!
//! SOURCE OF TRUTH: `eval/schema.yaml`. This enum is a projection of that
//! file, not an independent list. When a label is added, removed or renamed in
//! the schema, this enum must be regenerated to match -- the test at the
//! bottom of this file reads `eval/schema.yaml` at compile time and fails the
//! build if the two ever drift. A label that exists here but not in the schema
//! has no recall threshold and no annotation guideline, which means it is
//! unmeasured, and an unmeasured identifier is an unmeasured breach.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Result};

/// A label attached to a detected span.
///
/// The split between named direct variants and a single [`Quasi`] wrapper
/// mirrors the schema's split between two things that are scored by two
/// different mechanisms: direct identifiers carry per-type numeric recall
/// gates, quasi-identifiers are validated only by the L6 re-identification red
/// team and are forbidden from being reported as an F1. Keeping them in one
/// enum but distinguishable by construction is what lets the eval harness
/// refuse to blend the two numbers.
///
/// [`Quasi`]: EntityLabel::Quasi
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EntityLabel {
    // --- Class A: direct identifiers (HIPAA Safe Harbor 18, Turkish mapping).
    PatientName,
    ClinicianName,
    RelativeName,
    Tckn,
    Vkn,
    SgkNo,
    Mrn,
    PassportNo,
    Iban,
    Phone,
    Email,
    Url,
    IpAddress,
    /// A date whose ROLE L1 could not see a cue for; L2/L4 refine it into one
    /// of the four below. Guessing a role turns one found date into two
    /// errors, because the eval matches on label as well as offsets.
    Date,
    DateBirth,
    DateAdmission,
    DateDischarge,
    DateDeath,
    AgeOver89,
    AddressStreet,
    AddressCity,
    AddressDistrict,
    PostalCode,
    FacilityName,
    DeviceId,
    LicensePlate,
    VehicleId,
    BiometricId,
    HealthPlanId,
    AccountNo,
    CertificateNo,
    PhotoRef,
    OtherUniqueId,

    // --- Class B: contextual quasi-identifiers (Expert Determination, L3).
    Quasi(QuasiCategory),
}

/// The contextual quasi-identifier categories.
///
/// These are meanings rather than entities: no annotator can enumerate every
/// phrase that narrows a candidate population, so there is no denominator and
/// therefore no recall to compute. Their gate is the red team's re-ID rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum QuasiCategory {
    EmployerRole,
    RelationshipRef,
    AssetLocation,
    DistinctiveEvent,
    RareAttributeCombo,
}

impl QuasiCategory {
    /// Every quasi category, in schema order.
    pub const ALL: [Self; 5] = [
        Self::EmployerRole,
        Self::RelationshipRef,
        Self::AssetLocation,
        Self::DistinctiveEvent,
        Self::RareAttributeCombo,
    ];

    /// The schema `id` for this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmployerRole => "EMPLOYER_ROLE",
            Self::RelationshipRef => "RELATIONSHIP_REF",
            Self::AssetLocation => "ASSET_LOCATION",
            Self::DistinctiveEvent => "DISTINCTIVE_EVENT",
            Self::RareAttributeCombo => "RARE_ATTRIBUTE_COMBO",
        }
    }
}

impl EntityLabel {
    /// Every direct-identifier label, in schema order.
    pub const DIRECT: [Self; 33] = [
        Self::PatientName,
        Self::ClinicianName,
        Self::RelativeName,
        Self::Tckn,
        Self::Vkn,
        Self::SgkNo,
        Self::Mrn,
        Self::PassportNo,
        Self::Iban,
        Self::Phone,
        Self::Email,
        Self::Url,
        Self::IpAddress,
        Self::Date,
        Self::DateBirth,
        Self::DateAdmission,
        Self::DateDischarge,
        Self::DateDeath,
        Self::AgeOver89,
        Self::AddressStreet,
        Self::AddressCity,
        Self::AddressDistrict,
        Self::PostalCode,
        Self::FacilityName,
        Self::DeviceId,
        Self::LicensePlate,
        Self::VehicleId,
        Self::BiometricId,
        Self::HealthPlanId,
        Self::AccountNo,
        Self::CertificateNo,
        Self::PhotoRef,
        Self::OtherUniqueId,
    ];

    /// The schema `id` for this label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PatientName => "PATIENT_NAME",
            Self::ClinicianName => "CLINICIAN_NAME",
            Self::RelativeName => "RELATIVE_NAME",
            Self::Tckn => "TCKN",
            Self::Vkn => "VKN",
            Self::SgkNo => "SGK_NO",
            Self::Mrn => "MRN",
            Self::PassportNo => "PASSPORT_NO",
            Self::Iban => "IBAN",
            Self::Phone => "PHONE",
            Self::Email => "EMAIL",
            Self::Url => "URL",
            Self::IpAddress => "IP_ADDRESS",
            Self::Date => "DATE",
            Self::DateBirth => "DATE_BIRTH",
            Self::DateAdmission => "DATE_ADMISSION",
            Self::DateDischarge => "DATE_DISCHARGE",
            Self::DateDeath => "DATE_DEATH",
            Self::AgeOver89 => "AGE_OVER_89",
            Self::AddressStreet => "ADDRESS_STREET",
            Self::AddressCity => "ADDRESS_CITY",
            Self::AddressDistrict => "ADDRESS_DISTRICT",
            Self::PostalCode => "POSTAL_CODE",
            Self::FacilityName => "FACILITY_NAME",
            Self::DeviceId => "DEVICE_ID",
            Self::LicensePlate => "LICENSE_PLATE",
            Self::VehicleId => "VEHICLE_ID",
            Self::BiometricId => "BIOMETRIC_ID",
            Self::HealthPlanId => "HEALTH_PLAN_ID",
            Self::AccountNo => "ACCOUNT_NO",
            Self::CertificateNo => "CERTIFICATE_NO",
            Self::PhotoRef => "PHOTO_REF",
            Self::OtherUniqueId => "OTHER_UNIQUE_ID",
            Self::Quasi(q) => q.as_str(),
        }
    }

    /// Parse a schema `id` into a label.
    ///
    /// The error deliberately reports only the length of the rejected id; see
    /// [`Error::UnknownEntityLabel`].
    pub fn from_id(id: &str) -> Result<Self> {
        for label in Self::DIRECT {
            if label.as_str() == id {
                return Ok(label);
            }
        }
        for quasi in QuasiCategory::ALL {
            if quasi.as_str() == id {
                return Ok(Self::Quasi(quasi));
            }
        }
        Err(Error::UnknownEntityLabel { id_len: id.len() })
    }

    /// True for the Safe Harbor direct identifiers, which carry recall gates.
    pub const fn is_direct(self) -> bool {
        !self.is_quasi()
    }

    /// True for the contextual categories, which are never scored by F1.
    pub const fn is_quasi(self) -> bool {
        matches!(self, Self::Quasi(_))
    }
}

impl fmt::Display for EntityLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for QuasiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EntityLabel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_id(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema, embedded at compile time so the drift test cannot be
    /// skipped by a missing file at runtime and needs no I/O to run.
    const SCHEMA: &str = include_str!("../../eval/schema.yaml");

    /// Collect the `id` values under one top-level schema section.
    fn schema_ids(section: &str) -> Vec<&'static str> {
        let mut inside = false;
        let mut ids = Vec::new();
        for line in SCHEMA.lines() {
            let is_top_level_key = !line.starts_with(char::is_whitespace)
                && !line.starts_with('#')
                && line.contains(':');
            if is_top_level_key {
                inside = line.starts_with(section) && line[section.len()..].starts_with(':');
                continue;
            }
            if inside {
                if let Some(id) = line.trim_start().strip_prefix("- id: ") {
                    ids.push(id.trim());
                }
            }
        }
        ids
    }

    #[test]
    fn every_direct_schema_id_maps_to_a_variant() {
        let ids = schema_ids("direct_identifiers");
        assert!(!ids.is_empty(), "schema parse found no direct identifiers");
        for id in &ids {
            let label = EntityLabel::from_id(id).expect("schema id has no EntityLabel variant");
            assert!(label.is_direct(), "{id} parsed as a quasi label");
        }
        assert_eq!(
            ids.len(),
            EntityLabel::DIRECT.len(),
            "enum and schema disagree on the number of direct identifiers"
        );
    }

    #[test]
    fn every_quasi_schema_id_maps_to_a_variant() {
        let ids = schema_ids("quasi_identifiers");
        assert!(!ids.is_empty(), "schema parse found no quasi identifiers");
        for id in &ids {
            let label = EntityLabel::from_id(id).expect("schema id has no EntityLabel variant");
            assert!(label.is_quasi(), "{id} parsed as a direct label");
        }
        assert_eq!(ids.len(), QuasiCategory::ALL.len());
    }

    #[test]
    fn allowlist_categories_are_not_entity_labels() {
        // Class C is a negative set, not a label vocabulary. If DIAGNOSIS ever
        // becomes constructible as an EntityLabel, something can be masked as
        // one.
        for id in schema_ids("allowlist_categories") {
            assert!(
                EntityLabel::from_id(id).is_err(),
                "{id} leaked into the label enum"
            );
        }
    }

    #[test]
    fn label_ids_round_trip() {
        for label in EntityLabel::DIRECT {
            assert_eq!(EntityLabel::from_id(label.as_str()), Ok(label));
            assert_eq!(label.as_str().parse(), Ok(label));
        }
        for quasi in QuasiCategory::ALL {
            let label = EntityLabel::Quasi(quasi);
            assert_eq!(EntityLabel::from_id(label.as_str()), Ok(label));
        }
    }

    #[test]
    fn unknown_id_error_carries_only_a_length() {
        let err = EntityLabel::from_id("AYSE_YILMAZ").expect_err("must reject unknown id");
        assert_eq!(err, Error::UnknownEntityLabel { id_len: 11 });
        assert!(!err.to_string().contains("AYSE"));
    }
}
