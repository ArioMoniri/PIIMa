//! A checkpoint on THIS MACHINE, in a directory the operator named.
//!
//! # There is no hub id here, and there never will be
//!
//! Every path in this module is a path on the local filesystem. There is no
//! model id, no revision, no cache directory, no resolver and no HTTP client --
//! `bindings/ort`'s manifest has none and must not acquire one. I1 forbids a
//! fetch at inference outright, and `deid pull` is the one sanctioned way
//! weights arrive: an explicit command, a progress bar, a printed checksum, or
//! `--from ./bundle` on an air-gapped host. A directory that is not there is a
//! refusal, never a download.
//!
//! # Why these errors name the path, when `core/` never does
//!
//! The same argument `bindings/cli/src/l3.rs` makes for the L3 weights file. A
//! clinical document's path can embed a patient identifier and is therefore
//! withheld everywhere (I4). A MODEL directory is chosen by whoever installed
//! the tool, contains no patient data, and is the single fact the operator needs
//! in order to fix the problem. "L2 unavailable" is a message that gets worked
//! around by running without L2, which is the outcome that must never happen
//! quietly.
//!
//! # What is honest to claim here today
//!
//! This module RESOLVES and VALIDATES a checkpoint directory and derives the
//! [`BioScheme`] its head is decoded through. It does not run one. Loading the
//! graph needs `ort` and tokenizing needs `tokenizers`, and neither is a
//! dependency of this crate yet -- see the long comment in `Cargo.toml` for why
//! admitting them is a deliberate, reviewed, online act rather than something
//! that happens on the next `cargo build`. Until that happens, [`ModelDir::load`]
//! returns [`ModelError::NotLinked`] and says so in one sentence. THE BUILD
//! MASKS ZERO NAMES THROUGH L2. Wiring is not working, and a message that
//! blurred the two would be the most expensive lie this repository could tell.

use std::path::{Path, PathBuf};

use deid_tr_core::detect::{BioScheme, BioTag};
use deid_tr_core::EntityLabel;

/// The graph, as `transformers` writes it out.
pub const MODEL_FILE: &str = "model.onnx";
/// The serialised fast tokenizer.
pub const TOKENIZER_FILE: &str = "tokenizer.json";
/// The label inventory, as `id2label`.
pub const CONFIG_FILE: &str = "config.json";

/// Every file a checkpoint directory must contain, in the order they are
/// checked, so the message is always about the first thing to fix.
pub const REQUIRED_FILES: [&str; 3] = [MODEL_FILE, TOKENIZER_FILE, CONFIG_FILE];

/// Why a checkpoint directory could not be turned into an L2 detector.
///
/// Every variant names the DIRECTORY and the SWITCH that supplied it, because
/// those are the two things an operator can act on. None of them can carry
/// document text: the only string payloads are a path the operator typed, a
/// fixed file name, and a label name out of a model's own `config.json` -- which
/// is a constant of the checkpoint, not a fragment of a note.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// The directory does not exist, or is not a directory.
    #[error(
        "the L2 model directory {path} (from {origin}) does not exist or is not a directory. \
         Fetch a checkpoint with `deid pull`, or point {origin} at one you already have. \
         No weights ship with this build and none are downloaded at inference. Nothing was masked."
    )]
    NotADirectory {
        /// The directory, as configured.
        path: String,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// The directory exists but is missing one of [`REQUIRED_FILES`].
    #[error(
        "the L2 model directory {path} (from {origin}) has no {file}. \
         A checkpoint directory needs all of: {required}. \
         Re-run `deid pull`, or point {origin} at a complete export. Nothing was masked."
    )]
    MissingFile {
        /// The directory, as configured.
        path: String,
        /// The file that is not there.
        file: &'static str,
        /// Every file that must be there, so one message ends the round trip.
        required: String,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// `config.json` could not be read at all.
    #[error(
        "the L2 model directory {path} (from {origin}) has a {file} that cannot be read. \
         Check its permissions. Nothing was masked."
    )]
    Unreadable {
        /// The directory, as configured.
        path: String,
        /// Which file.
        file: &'static str,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// `config.json` has no usable `id2label`.
    ///
    /// FATAL RATHER THAN DEFAULTED. A default label inventory would decode one
    /// checkpoint's columns against another's tag order, which produces
    /// confident, well-formed, entirely wrong labels -- the failure mode that is
    /// invisible in a demo and is a leak in production.
    #[error(
        "the L2 model directory {path} (from {origin}) has a {file} with no usable id2label map. \
         The label inventory cannot be guessed: decoding a head against the wrong tag order \
         produces confident, wrong labels. Re-export the checkpoint. Nothing was masked."
    )]
    NoLabelMap {
        /// The directory, as configured.
        path: String,
        /// Which file.
        file: &'static str,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// `id2label` does not cover `0..n` exactly once.
    #[error(
        "the L2 model directory {path} (from {origin}) declares {count} labels but no entry for \
         id {missing}, so the head's column order is unknown. Nothing was masked."
    )]
    LabelIdsNotContiguous {
        /// The directory, as configured.
        path: String,
        /// How many entries the map has.
        count: usize,
        /// The first id it does not have.
        missing: usize,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// A declared label has no entry in [`ALIASES`].
    ///
    /// REFUSED RATHER THAN FOLDED INTO `O`. Folding it in silently discards
    /// every span of an entity type the checkpoint CAN find, which is a recall
    /// loss chosen by a lookup miss rather than by a person, and I2 does not
    /// allow recall to be traded away quietly. The fix is one line in `ALIASES`
    /// and it should be written by someone who decided what the type means.
    #[error(
        "the L2 checkpoint in {path} (from {origin}) declares the entity type {label}, which \
         this build has no schema label for. Masking would silently drop every span of that \
         type. Map it in bindings/ort's ALIASES table, or use a checkpoint whose label set \
         this build knows. Nothing was masked."
    )]
    UnmappedLabel {
        /// The directory, as configured.
        path: String,
        /// The entity type, as the checkpoint spells it. A model constant.
        label: String,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// A declared label is not a well-formed BIO tag.
    #[error(
        "the L2 checkpoint in {path} (from {origin}) declares the tag {label}, which is not O, \
         B-<TYPE> or I-<TYPE>. This build decodes BIO heads. Nothing was masked."
    )]
    NotBioTag {
        /// The directory, as configured.
        path: String,
        /// The tag, as the checkpoint spells it.
        label: String,
        /// The switch that supplied it.
        origin: &'static str,
    },

    /// The label inventory is well-formed and this crate cannot execute it.
    ///
    /// THE HONEST VARIANT. It exists so that no other part of the system has to
    /// pretend: the directory was found, the head was understood, and this build
    /// still cannot run a forward pass, so it masks nothing through L2.
    #[error(
        "the L2 checkpoint in {path} (from {origin}) was found and its label inventory is \
         valid, but this build has no {missing} linked, so it cannot run the model. \
         L2 masked NOTHING. Rebuild with the inference runtime enabled \
         (see bindings/ort/Cargo.toml) or run without {origin}."
    )]
    NotLinked {
        /// The directory, as configured.
        path: String,
        /// What is not linked: an inference runtime, or a tokenizer.
        missing: &'static str,
        /// The switch that supplied it.
        origin: &'static str,
    },
}

/// Checkpoint label names this build knows, mapped onto the project schema.
///
/// AN EXPLICIT TABLE, and short on purpose. Every row is a decision about what
/// an upstream label means in this pipeline, and the decisions are not all
/// obvious: `PER` on a Turkish clinical NER checkpoint covers patients,
/// relatives and clinicians without distinguishing them, and it is mapped to
/// [`EntityLabel::PatientName`] because that is the class whose recall gate is
/// strictest -- over-classifying a clinician as a patient masks a name that
/// should be masked anyway, while the reverse would relax the gate that matters.
/// A name not in this table is an error, never a silent `O`; see
/// [`ModelError::UnmappedLabel`].
///
/// A checkpoint that spells its labels with this project's own schema ids
/// (`PATIENT_NAME`, `TCKN`, ...) needs no row here: those parse directly.
pub const ALIASES: [(&str, EntityLabel); 12] = [
    ("PER", EntityLabel::PatientName),
    ("PERSON", EntityLabel::PatientName),
    ("PATIENT", EntityLabel::PatientName),
    ("NAME", EntityLabel::PatientName),
    ("DOCTOR", EntityLabel::ClinicianName),
    ("CLINICIAN", EntityLabel::ClinicianName),
    ("LOC", EntityLabel::AddressCity),
    ("LOCATION", EntityLabel::AddressCity),
    ("CITY", EntityLabel::AddressCity),
    ("ORG", EntityLabel::FacilityName),
    ("HOSPITAL", EntityLabel::FacilityName),
    ("FACILITY", EntityLabel::FacilityName),
];

/// Resolve an upstream entity type onto a schema label.
///
/// The schema id is tried FIRST so that a checkpoint this project fine-tuned
/// itself is never re-interpreted through an alias meant for someone else's
/// label vocabulary.
#[must_use]
pub fn resolve_entity(name: &str) -> Option<EntityLabel> {
    if let Ok(label) = name.parse::<EntityLabel>() {
        return Some(label);
    }
    let upper = name.to_ascii_uppercase();
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == upper)
        .map(|&(_, label)| label)
}

/// A validated checkpoint directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDir {
    directory: PathBuf,
    origin: &'static str,
    labels: Vec<String>,
}

impl ModelDir {
    /// Validate a directory and read its label inventory.
    ///
    /// Reads `config.json` and nothing else. The graph and the tokenizer are
    /// checked for EXISTENCE only, because opening either needs a dependency
    /// this crate does not have, and because a caller who is going to be told
    /// "no runtime linked" should be told it after every fixable problem has
    /// already been reported rather than instead of them.
    pub fn open(directory: &Path, origin: &'static str) -> Result<Self, ModelError> {
        let shown = shown(directory);
        if !std::fs::metadata(directory).is_ok_and(|meta| meta.is_dir()) {
            return Err(ModelError::NotADirectory {
                path: shown,
                origin,
            });
        }
        for file in REQUIRED_FILES {
            if !std::fs::metadata(directory.join(file)).is_ok_and(|meta| meta.is_file()) {
                return Err(ModelError::MissingFile {
                    path: shown,
                    file,
                    required: REQUIRED_FILES.join(", "),
                    origin,
                });
            }
        }

        let config = std::fs::read_to_string(directory.join(CONFIG_FILE)).map_err(|_| {
            ModelError::Unreadable {
                path: shown.clone(),
                file: CONFIG_FILE,
                origin,
            }
        })?;
        let labels = id2label(&config).ok_or(ModelError::NoLabelMap {
            path: shown.clone(),
            file: CONFIG_FILE,
            origin,
        })?;
        if let Some(missing) = labels.iter().position(Option::is_none) {
            return Err(ModelError::LabelIdsNotContiguous {
                path: shown,
                count: labels.len(),
                missing,
                origin,
            });
        }
        let labels: Vec<String> = labels.into_iter().flatten().collect();
        if labels.is_empty() {
            return Err(ModelError::NoLabelMap {
                path: shown,
                file: CONFIG_FILE,
                origin,
            });
        }

        Ok(Self {
            directory: directory.to_path_buf(),
            origin,
            labels,
        })
    }

    /// The directory, as the operator wrote it.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The graph file.
    #[must_use]
    pub fn graph(&self) -> PathBuf {
        self.directory.join(MODEL_FILE)
    }

    /// The serialised tokenizer.
    #[must_use]
    pub fn tokenizer(&self) -> PathBuf {
        self.directory.join(TOKENIZER_FILE)
    }

    /// The checkpoint's label names, in ITS column order.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// The BIO conversion this checkpoint's head decodes through.
    pub fn scheme(&self) -> Result<BioScheme, ModelError> {
        let mut columns = Vec::with_capacity(self.labels.len());
        for label in &self.labels {
            columns.push(self.column(label)?);
        }
        BioScheme::new(columns).map_err(|_| ModelError::NoLabelMap {
            path: shown(&self.directory),
            file: CONFIG_FILE,
            origin: self.origin,
        })
    }

    /// One `config.json` label name as a BIO column.
    fn column(&self, label: &str) -> Result<BioTag, ModelError> {
        let trimmed = label.trim();
        if trimmed.eq_ignore_ascii_case("O") {
            return Ok(BioTag::Outside);
        }
        // `B-` / `I-` only. `E-`, `S-` and `L-`/`U-` are other schemes, and a
        // checkpoint using one of them is not a BIO checkpoint: accepting the
        // prefix and treating it as `I` would mis-place every chunk boundary.
        let (prefix, entity) = trimmed
            .split_once(['-', '_'])
            .ok_or_else(|| self.not_bio(trimmed))?;
        let entity = resolve_entity(entity).ok_or_else(|| ModelError::UnmappedLabel {
            path: shown(&self.directory),
            label: entity.to_owned(),
            origin: self.origin,
        })?;
        match prefix {
            "B" | "b" => Ok(BioTag::Begin(entity)),
            "I" | "i" => Ok(BioTag::Inside(entity)),
            _ => Err(self.not_bio(trimmed)),
        }
    }

    fn not_bio(&self, label: &str) -> ModelError {
        ModelError::NotBioTag {
            path: shown(&self.directory),
            label: label.to_owned(),
            origin: self.origin,
        }
    }

    /// Open the graph as a runnable [`Session`][crate::Session].
    ///
    /// TODAY THIS ALWAYS FAILS, and it says which piece is absent rather than
    /// which layer is unavailable. See this module's header: the two registry
    /// crates that would make it a real load are admitted by a reviewed, online
    /// act, and until then no string anywhere in this repository may suggest L2
    /// is masking.
    ///
    /// The SIGNATURE is the real one rather than a placeholder, so that every
    /// caller downstream -- the CLI's ensemble assembly, its error reporting,
    /// its precedence chain -- is written against the shape it will keep, is
    /// compiled today, and is tested today against a canned-logit detector.
    /// A seam whose type changes when the dependency lands is a seam whose
    /// callers were never really written.
    pub fn load(&self) -> Result<Box<dyn crate::Session>, ModelError> {
        Err(ModelError::NotLinked {
            path: shown(&self.directory),
            missing: "ONNX Runtime",
            origin: self.origin,
        })
    }
}

/// The path rendered for a message, without guessing at an encoding.
fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Extract `id2label` from a `config.json`, indexed by id.
///
/// A NARROW SCANNER RATHER THAN A JSON CRATE, for the reason
/// `bindings/cli/src/format.rs` gives for hand-writing its encoder: the shipped
/// binary handles clinical documents, and every parser linked into it is
/// attack surface for input that is not a clinical document. The shape accepted
/// here is one flat object of string keys to string values, which is the only
/// shape `transformers` ever writes for this field, and anything else yields
/// `None` -- which the caller turns into a refusal rather than a default.
///
/// Returns a vector indexed by label id, so a gap shows up as `None` at that
/// index rather than as a silently renumbered inventory.
#[must_use]
pub fn id2label(config: &str) -> Option<Vec<Option<String>>> {
    let start = config.find("\"id2label\"")?;
    let open = config[start..].find('{')? + start;

    let mut entries: Vec<(usize, String)> = Vec::new();
    let mut chars = config[open + 1..].char_indices().peekable();
    let mut pending_key: Option<usize> = None;
    // A truncated file must not read as a complete map: without this the loop
    // simply runs out of input and the entries seen so far look like the whole
    // inventory, which would silently decode a head against a short label set.
    let mut closed = false;
    while let Some((_, character)) = chars.next() {
        match character {
            '}' => {
                closed = true;
                break;
            }
            // Nested structure means this is not the flat map we accept.
            '{' | '[' => return None,
            '"' => {
                let mut literal = String::new();
                loop {
                    let (_, next) = chars.next()?;
                    match next {
                        '"' => break,
                        // One escape form is enough: `transformers` writes label
                        // names that are ASCII identifiers, and anything with a
                        // backslash in it is not one, so the whole map is
                        // rejected rather than half-decoded.
                        '\\' => return None,
                        other => literal.push(other),
                    }
                }
                match pending_key.take() {
                    Some(id) => entries.push((id, literal)),
                    None => pending_key = Some(literal.parse::<usize>().ok()?),
                }
            }
            _ => {}
        }
    }
    if !closed || entries.is_empty() || pending_key.is_some() {
        return None;
    }

    let width = entries.iter().map(|&(id, _)| id).max()? + 1;
    let mut out = vec![None; width];
    for (id, name) in entries {
        let slot = out.get_mut(id)?;
        if slot.is_some() {
            // A duplicate id means the column order is ambiguous.
            return None;
        }
        *slot = Some(name);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAG: &str = "--l2-model";

    /// A checkpoint directory with the right files and no weights in them.
    ///
    /// EVERY CALL GETS ITS OWN DIRECTORY, for the reason `bindings/cli`'s L3
    /// fixtures record: cargo runs these on parallel threads and a shared path
    /// makes one test's edits another test's flake.
    fn checkpoint(config: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("deid-ort-model-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        // Zero bytes. Nothing in this module opens either of them, which is
        // exactly why the whole path is testable with no weights on disk.
        std::fs::write(dir.join(MODEL_FILE), b"").expect("fixture");
        std::fs::write(dir.join(TOKENIZER_FILE), b"").expect("fixture");
        std::fs::write(dir.join(CONFIG_FILE), config).expect("fixture");
        dir
    }

    const BIO_CONFIG: &str = r#"{
        "architectures": ["BertForTokenClassification"],
        "id2label": {"0": "O", "1": "B-PER", "2": "I-PER", "3": "B-LOC", "4": "I-LOC"},
        "label2id": {"O": 0},
        "model_type": "bert"
    }"#;

    #[test]
    fn a_missing_directory_names_the_path_and_the_flag() {
        let error = ModelDir::open(Path::new("/nonexistent/checkpoint-dir"), FLAG)
            .expect_err("absent directory")
            .to_string();
        assert!(error.contains("/nonexistent/checkpoint-dir"), "{error}");
        assert!(error.contains(FLAG), "{error}");
        assert!(error.contains("deid pull"), "{error}");
        assert!(
            error.contains("Nothing was masked"),
            "a refusal must say the document was not silently degraded"
        );
    }

    #[test]
    fn each_missing_file_is_named_along_with_the_full_required_set() {
        for missing in REQUIRED_FILES {
            let dir = checkpoint(BIO_CONFIG);
            std::fs::remove_file(dir.join(missing)).expect("fixture");
            let error = ModelDir::open(&dir, FLAG)
                .expect_err("incomplete checkpoint")
                .to_string();
            assert!(error.contains(missing), "{error}");
            assert!(error.contains(FLAG), "{error}");
            for file in REQUIRED_FILES {
                assert!(error.contains(file), "the message must end the round trip");
            }
        }
    }

    #[test]
    fn a_complete_directory_yields_the_checkpoints_own_column_order() {
        let dir = checkpoint(BIO_CONFIG);
        let model = ModelDir::open(&dir, FLAG).expect("a complete checkpoint");
        assert_eq!(model.labels(), ["O", "B-PER", "I-PER", "B-LOC", "I-LOC"]);
        assert_eq!(model.graph(), dir.join(MODEL_FILE));
        assert_eq!(model.tokenizer(), dir.join(TOKENIZER_FILE));

        let scheme = model.scheme().expect("a BIO head");
        assert_eq!(scheme.width(), 5);
        assert_eq!(
            scheme.columns(),
            [
                BioTag::Outside,
                BioTag::Begin(EntityLabel::PatientName),
                BioTag::Inside(EntityLabel::PatientName),
                BioTag::Begin(EntityLabel::AddressCity),
                BioTag::Inside(EntityLabel::AddressCity),
            ]
        );
    }

    #[test]
    fn a_config_with_no_label_map_is_refused_rather_than_defaulted() {
        let dir = checkpoint(r#"{"model_type": "bert"}"#);
        let error = ModelDir::open(&dir, FLAG)
            .expect_err("no id2label")
            .to_string();
        assert!(error.contains("id2label"), "{error}");
        assert!(error.contains("cannot be guessed"), "{error}");
    }

    #[test]
    fn a_gap_in_the_label_ids_names_the_missing_column() {
        let dir = checkpoint(r#"{"id2label": {"0": "O", "2": "B-PER"}}"#);
        let error = ModelDir::open(&dir, FLAG)
            .expect_err("a gap in the ids")
            .to_string();
        assert!(error.contains("id 1"), "{error}");
    }

    #[test]
    fn an_entity_type_this_build_has_no_label_for_is_refused_not_dropped() {
        // I2: recall is never traded away by a lookup miss. A checkpoint that
        // can find licence plates and a build that maps the type to nothing
        // must not quietly agree to leave licence plates in the note.
        let dir = checkpoint(r#"{"id2label": {"0": "O", "1": "B-VESSEL_NAME"}}"#);
        let model = ModelDir::open(&dir, FLAG).expect("the map itself is well-formed");
        let error = model.scheme().expect_err("unmapped type").to_string();
        assert!(error.contains("VESSEL_NAME"), "{error}");
        assert!(error.contains("ALIASES"), "{error}");
        assert!(error.contains("silently drop"), "{error}");
    }

    #[test]
    fn a_non_bio_tagging_scheme_is_refused_rather_than_read_as_bio() {
        // A BIOES or BILOU export decoded as BIO puts every chunk boundary in
        // the wrong place, and the output still looks well-formed.
        for label in ["E-PER", "S-PER", "U-PER", "PER"] {
            let dir = checkpoint(&format!(r#"{{"id2label": {{"0": "O", "1": "{label}"}}}}"#));
            let model = ModelDir::open(&dir, FLAG).expect("well-formed map");
            let error = model.scheme().expect_err("not BIO").to_string();
            assert!(error.contains("B-<TYPE>"), "{label}: {error}");
        }
    }

    #[test]
    fn this_projects_own_schema_ids_resolve_without_an_alias() {
        assert_eq!(
            resolve_entity("PATIENT_NAME"),
            Some(EntityLabel::PatientName)
        );
        assert_eq!(resolve_entity("TCKN"), Some(EntityLabel::Tckn));
        // And the alias table covers the upstream vocabulary, case-insensitively.
        assert_eq!(resolve_entity("per"), Some(EntityLabel::PatientName));
        assert_eq!(resolve_entity("ORG"), Some(EntityLabel::FacilityName));
        assert_eq!(resolve_entity("nonsense"), None);
    }

    #[test]
    fn loading_admits_it_cannot_run_the_model_instead_of_implying_it_did() {
        // THE HONESTY TEST. A build with no runtime linked masks zero names
        // through L2, and the message has to say so in the words an operator
        // will act on rather than in a status code they will ignore.
        let dir = checkpoint(BIO_CONFIG);
        let model = ModelDir::open(&dir, FLAG).expect("a complete checkpoint");
        // `dyn Session` has no `Debug`, so the Ok side is discarded explicitly
        // rather than through `expect_err`.
        let error = match model.load() {
            Ok(_) => panic!("a build with no runtime must not produce a session"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("masked NOTHING"), "{error}");
        assert!(error.contains("ONNX Runtime"), "{error}");
        assert!(error.contains(FLAG), "{error}");
    }

    #[test]
    fn the_label_map_scanner_accepts_what_transformers_writes_and_nothing_else() {
        assert_eq!(
            id2label(r#"{"id2label": {"0": "O", "1": "B-PER"}}"#),
            Some(vec![Some("O".to_owned()), Some("B-PER".to_owned())])
        );
        // Whitespace and ordering are the writer's business, not ours.
        assert_eq!(
            id2label("{ \"id2label\" : {\n \"1\" : \"B-PER\" ,\n \"0\" : \"O\"\n} }"),
            Some(vec![Some("O".to_owned()), Some("B-PER".to_owned())])
        );
        // A gap is reported as a gap rather than silently renumbered.
        assert_eq!(
            id2label(r#"{"id2label": {"0": "O", "2": "B-PER"}}"#),
            Some(vec![Some("O".to_owned()), None, Some("B-PER".to_owned())])
        );
        // Everything the scanner does not accept is rejected outright.
        assert_eq!(id2label(r#"{"label2id": {"O": 0}}"#), None);
        assert_eq!(id2label(r#"{"id2label": {"0": {"x": "y"}}}"#), None);
        assert_eq!(id2label(r#"{"id2label": {"0": "O", "0": "B-PER"}}"#), None);
        assert_eq!(id2label(r#"{"id2label": {"not-a-number": "O"}}"#), None);
        assert_eq!(id2label(r#"{"id2label": {"0": "a\"b"}}"#), None);
        assert_eq!(id2label(r#"{"id2label": {}}"#), None);
        assert_eq!(id2label(r#"{"id2label": {"0": "O""#), None);
    }

    #[test]
    fn no_error_variant_can_carry_document_text() {
        // The same structural check `core/src/detect/mod.rs` runs on its own
        // enum. Every payload here is a path the operator typed, a fixed file
        // name, a count, or a label name out of a model's config -- and the
        // rendering is asserted to contain none of a document's characteristic
        // content. What makes it load-bearing is that it fails the moment
        // somebody adds a payload sourced from a note.
        let dir = checkpoint(BIO_CONFIG);
        let model = ModelDir::open(&dir, FLAG).expect("checkpoint");
        for error in [
            ModelDir::open(Path::new("/nope"), FLAG).expect_err("absent"),
            match model.load() {
                Ok(_) => panic!("a build with no runtime must not produce a session"),
                Err(error) => error,
            },
            ModelError::UnmappedLabel {
                path: "/models/x".to_owned(),
                label: "VESSEL_NAME".to_owned(),
                origin: FLAG,
            },
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("Ayşe"), "{rendered}");
            assert!(!rendered.contains("carcinoma"), "{rendered}");
        }
    }
}
