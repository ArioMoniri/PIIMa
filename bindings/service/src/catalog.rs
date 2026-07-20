//! `GET /entities`: the entity catalog, read from `eval/schema.yaml`.
//!
//! # Why the schema and not a hand-written list
//!
//! `eval/schema.yaml` is the single source of truth for the label vocabulary --
//! `EntityLabel`, the eval harness, the annotation guidelines, the L4 allowlist
//! loader and every model card key off its `id` fields, and `core/src/label.rs`
//! has a compile-time test that fails the build when the enum drifts from it. An
//! endpoint that published its own list would be a fourth copy, and the one
//! nobody regenerates.
//!
//! `include_str!` rather than a runtime read: the endpoint then answers the same
//! way regardless of the working directory the operator started the process in,
//! and a missing file is a build failure rather than a 500 in a hospital.
//!
//! # The honesty this endpoint is responsible for
//!
//! The catalog says what the SCHEMA defines. That is not the same question as
//! what this build DETECTS, and publishing only the first is how a catalog turns
//! into a capability claim. Every entry therefore carries `detected_by_this_build`
//! together with the reason, computed from the layers the running process
//! actually has. Today that means: the `detector: rules` entries are live, and
//! **every `detector: ner` entry -- which is every NAME label -- reports false,
//! because L2 has no trained model in this build and deid-tr masks no names at
//! all.** A caller who reads this endpoint and believes names are covered has
//! been misled by us, not by themselves.
//!
//! # The parser
//!
//! Hand-written line scanning, in the same shape and for the same reason as the
//! schema-drift test in `core/src/label.rs`: the file is machine-regular, a YAML
//! dependency is not in the workspace lock file, and acquiring one would break
//! the air-gapped build. It reads exactly the flat `key: value` pairs it needs
//! and ignores the nested `examples_synthetic` lists -- which is deliberate on a
//! second count, since those examples are fixture material and not something an
//! HTTP endpoint should be handing out.

use serde_json::{json, Value};

/// The schema, embedded at build time.
const SCHEMA: &str = include_str!("../../../eval/schema.yaml");

/// Which layer a schema entry says should find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    /// L1, deterministic regex plus checksum.
    Rules,
    /// L2, the token-classifier ensemble.
    Ner,
    /// L3, the local contextual sweep.
    Llm,
    /// A `detector:` value this build does not recognise.
    Unknown,
}

impl Detector {
    fn parse(value: &str) -> Self {
        match value {
            "rules" => Self::Rules,
            "ner" => Self::Ner,
            "llm" => Self::Llm,
            _ => Self::Unknown,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::Ner => "ner",
            Self::Llm => "llm",
            Self::Unknown => "unknown",
        }
    }
}

/// One catalog entry, as the schema defines it.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The schema `id`, which is also the `EntityLabel`.
    pub id: String,
    /// `direct` or `quasi`.
    pub identifier_class: String,
    /// Which layer is supposed to find it.
    pub detector: Detector,
    /// The HIPAA Safe Harbor category, for direct identifiers.
    pub hipaa_category: Option<String>,
    /// True for identifiers that only exist in the Turkish context.
    pub tr_specific: bool,
    /// True when an arithmetic check can prove a match.
    pub checksum_validatable: bool,
    /// The recall floor from the schema, for direct identifiers.
    pub recall_threshold: Option<f64>,
    /// The annotation guideline, one line.
    pub description: String,
}

/// Which layers the running process actually has.
///
/// Passed in rather than read from a global, so `/health` and `/entities` cannot
/// disagree about what is installed.
#[derive(Debug, Clone, Copy)]
pub struct LiveLayers {
    /// L1. Always true: the rules are compiled in.
    pub rules: bool,
    /// L2. True only when an ensemble with at least one member is installed.
    pub ner: bool,
    /// L3. True only in the Expert Determination tier with a local model.
    pub context: bool,
}

impl Entry {
    /// Whether THIS BUILD can find this identifier, and why not when it cannot.
    ///
    /// Returns `(detected, reason)`. The reason is a `&'static str` so it can
    /// only ever be a literal compiled into the binary.
    #[must_use]
    pub const fn detected_by(&self, layers: LiveLayers) -> (bool, &'static str) {
        match self.detector {
            Detector::Rules if layers.rules => (true, "L1 deterministic rules are compiled in"),
            Detector::Rules => (false, "the rules layer is not installed"),
            Detector::Ner if layers.ner => (true, "an L2 ensemble member is loaded"),
            Detector::Ner => (
                false,
                "L2 has no trained model in this build, so nothing detects this label. \
                 Every NAME label is in this state: deid-tr masks ZERO names today.",
            ),
            Detector::Llm if layers.context => (true, "an L3 local contextual model is installed"),
            Detector::Llm => (
                false,
                "L3 is tier-gated and no local contextual model is installed",
            ),
            Detector::Unknown => (false, "this build does not recognise that detector value"),
        }
    }
}

/// Parse one top-level section of the schema into entries.
fn section(name: &str) -> Vec<Entry> {
    let mut inside = false;
    let mut entries: Vec<Entry> = Vec::new();
    for line in SCHEMA.lines() {
        let is_top_level_key =
            !line.starts_with(char::is_whitespace) && !line.starts_with('#') && line.contains(':');
        if is_top_level_key {
            inside = line.starts_with(name) && line[name.len()..].starts_with(':');
            continue;
        }
        if !inside {
            continue;
        }
        let trimmed = line.trim_start();
        if let Some(id) = trimmed.strip_prefix("- id: ") {
            entries.push(Entry {
                id: unquote(id).to_owned(),
                identifier_class: String::new(),
                detector: Detector::Unknown,
                hipaa_category: None,
                tr_specific: false,
                checksum_validatable: false,
                recall_threshold: None,
                description: String::new(),
            });
            continue;
        }
        // Only the FLAT key/value pairs of the entry currently being built are
        // read. A nested list item (`      - "Ayşe Yılmaz"`) has no colon at
        // this level and falls through, which is how `examples_synthetic` stays
        // out of the endpoint's output.
        let Some(entry) = entries.last_mut() else {
            continue;
        };
        let Some((key, value)) = trimmed.split_once(": ") else {
            continue;
        };
        let value = unquote(value.trim());
        match key {
            "identifier_class" => entry.identifier_class = value.to_owned(),
            "detector" => entry.detector = Detector::parse(value),
            "hipaa_category" => entry.hipaa_category = Some(value.to_owned()),
            "tr_specific" => entry.tr_specific = value == "true",
            "checksum_validatable" => entry.checksum_validatable = value == "true",
            "recall_threshold" => entry.recall_threshold = value.parse().ok(),
            "description" => entry.description = value.to_owned(),
            _ => {}
        }
    }
    entries
}

/// Strip one layer of surrounding double quotes.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}

/// Every direct identifier the schema defines, in schema order.
#[must_use]
pub fn direct() -> Vec<Entry> {
    section("direct_identifiers")
}

/// Every contextual quasi-identifier the schema defines, in schema order.
#[must_use]
pub fn quasi() -> Vec<Entry> {
    section("quasi_identifiers")
}

/// The schema version from the `meta` block.
#[must_use]
pub fn schema_version() -> String {
    for line in SCHEMA.lines() {
        if let Some(value) = line.trim_start().strip_prefix("schema_version: ") {
            return unquote(value.trim()).to_owned();
        }
    }
    "unknown".to_owned()
}

/// Render one entry as JSON.
fn render(entry: &Entry, layers: LiveLayers) -> Value {
    let (detected, reason) = entry.detected_by(layers);
    json!({
        "id": entry.id,
        "identifier_class": entry.identifier_class,
        "detector": entry.detector.as_str(),
        "hipaa_category": entry.hipaa_category,
        "tr_specific": entry.tr_specific,
        "checksum_validatable": entry.checksum_validatable,
        // A checksum-validatable identifier carries precision 1.000 by
        // definition: an arithmetic check that passed is not a threshold that
        // was cleared, and such a span is never demotable by L4.
        "precision_threshold": if entry.checksum_validatable { Some(1.0) } else { None },
        "recall_threshold": entry.recall_threshold,
        "description": entry.description,
        "detected_by_this_build": detected,
        "detection_note": reason,
    })
}

/// The whole `GET /entities` body.
#[must_use]
pub fn body(layers: LiveLayers) -> Value {
    let direct = direct();
    let quasi = quasi();
    let undetected = direct
        .iter()
        .chain(quasi.iter())
        .filter(|entry| !entry.detected_by(layers).0)
        .count();
    json!({
        "schema_version": schema_version(),
        "source": "eval/schema.yaml",
        "language": ["tr"],
        "medical_register": ["la", "en"],
        "counts": {
            "direct": direct.len(),
            "quasi": quasi.len(),
            "detected_by_this_build": direct.len() + quasi.len() - undetected,
            "not_detected_by_this_build": undetected,
        },
        // Stated in the payload and not only in the docs, because a machine
        // consumer reads the payload. Scoping a claim to what is measurable is
        // the entire disagreement this project has with the incumbent's Turkish
        // model cards; publishing an aspirational catalog here would be the same
        // mistake in a different file format.
        "honesty_note": "This catalog lists what the SCHEMA defines, not what this build detects. \
                         Check detected_by_this_build on every entry. L2 has no trained model in \
                         this build, so deid-tr currently masks ZERO names -- PATIENT_NAME, \
                         CLINICIAN_NAME and RELATIVE_NAME are defined and undetected. Only \
                         rule-detectable identifiers are covered today.",
        "direct_identifiers": direct.iter().map(|e| render(e, layers)).collect::<Vec<_>>(),
        "quasi_identifiers": quasi.iter().map(|e| render(e, layers)).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deid_tr_core::EntityLabel;

    const NOTHING_BUT_RULES: LiveLayers = LiveLayers {
        rules: true,
        ner: false,
        context: false,
    };

    #[test]
    fn every_direct_schema_entry_parses_and_maps_to_a_label() {
        let entries = direct();
        assert_eq!(
            entries.len(),
            EntityLabel::DIRECT.len(),
            "the catalog and the label enum disagree about the schema"
        );
        for entry in &entries {
            EntityLabel::from_id(&entry.id).expect("catalog id has no EntityLabel");
            assert_eq!(entry.identifier_class, "direct", "{}", entry.id);
            assert_ne!(entry.detector, Detector::Unknown, "{}", entry.id);
            assert!(entry.hipaa_category.is_some(), "{}", entry.id);
            assert!(!entry.description.is_empty(), "{}", entry.id);
            assert!(
                entry.recall_threshold.is_some_and(|t| t > 0.0),
                "{} has no recall floor",
                entry.id
            );
        }
    }

    #[test]
    fn every_quasi_schema_entry_parses_and_is_scored_differently() {
        let entries = quasi();
        assert_eq!(entries.len(), 5);
        for entry in &entries {
            let label = EntityLabel::from_id(&entry.id).expect("catalog id has no EntityLabel");
            assert!(label.is_quasi(), "{}", entry.id);
            assert_eq!(entry.detector, Detector::Llm);
            // Quasi-identifiers have no denominator, so they carry no recall
            // gate. Publishing one would invite someone to report an F1 for
            // them, which is exactly what the schema's three-class split exists
            // to prevent.
            assert!(entry.recall_threshold.is_none(), "{}", entry.id);
        }
    }

    #[test]
    fn the_checksum_validatable_entries_are_the_arithmetic_ones() {
        let checksummed: Vec<String> = direct()
            .into_iter()
            .filter(|entry| entry.checksum_validatable)
            .map(|entry| entry.id)
            .collect();
        for expected in ["TCKN", "VKN", "IBAN"] {
            assert!(
                checksummed.iter().any(|id| id == expected),
                "{expected} lost its checksum_validatable flag"
            );
        }
    }

    #[test]
    fn no_name_label_claims_to_be_detected_by_this_build() {
        // THE honesty test. L2 has no trained model, so every NER-detected
        // label -- which is every name -- must report false, and must say why.
        // If a future build loads an ensemble this test still passes for the
        // right reason, because it asserts against the same LiveLayers the
        // endpoint is given.
        for id in ["PATIENT_NAME", "CLINICIAN_NAME", "RELATIVE_NAME"] {
            let entry = direct()
                .into_iter()
                .find(|entry| entry.id == id)
                .expect("schema entry");
            assert_eq!(entry.detector, Detector::Ner);
            let (detected, reason) = entry.detected_by(NOTHING_BUT_RULES);
            assert!(!detected, "{id} claimed detection with no L2 model loaded");
            assert!(reason.contains("ZERO names"));
        }
    }

    #[test]
    fn the_rule_detectable_identifiers_are_reported_live() {
        for id in ["TCKN", "PHONE", "EMAIL"] {
            let entry = direct()
                .into_iter()
                .find(|entry| entry.id == id)
                .expect("schema entry");
            assert_eq!(entry.detector, Detector::Rules);
            assert!(entry.detected_by(NOTHING_BUT_RULES).0, "{id} is not live");
        }
    }

    #[test]
    fn the_body_carries_the_honesty_note_and_the_counts_agree() {
        let body = body(NOTHING_BUT_RULES);
        assert_eq!(body["schema_version"], json!(schema_version()));
        let note = body["honesty_note"].as_str().expect("note");
        assert!(note.contains("ZERO names"));
        let direct_len = body["direct_identifiers"].as_array().expect("array").len();
        let quasi_len = body["quasi_identifiers"].as_array().expect("array").len();
        assert_eq!(body["counts"]["direct"], json!(direct_len));
        assert_eq!(body["counts"]["quasi"], json!(quasi_len));
        let detected = body["counts"]["detected_by_this_build"]
            .as_u64()
            .expect("count");
        let missing = body["counts"]["not_detected_by_this_build"]
            .as_u64()
            .expect("count");
        assert_eq!(
            detected + missing,
            (direct_len + quasi_len) as u64,
            "the two counts must partition the catalog"
        );
        assert!(
            missing > 0,
            "no build detects everything; saying so would lie"
        );
    }

    #[test]
    fn no_fixture_example_reaches_the_endpoint() {
        // examples_synthetic is fixture material. It is synthetic, so it is not
        // a PHI leak, but it is also not something an HTTP endpoint should hand
        // out, and its presence would mean the parser is picking up nested list
        // items it does not understand.
        let rendered = body(NOTHING_BUT_RULES).to_string();
        assert!(!rendered.contains("Ayşe Yılmaz"));
        assert!(!rendered.contains("examples_synthetic"));
    }
}
