//! Everything the desktop application actually does, with no window attached.
//!
//! The commands in `main.rs` are thin: they open a dialog, read bytes, call
//! into here, and write bytes. All of the behaviour is in this module, as plain
//! functions over plain values, so it is tested by `cargo test` rather than by
//! a person clicking. A desktop binding whose logic is only reachable by
//! launching a window is a desktop binding with no tests.
//!
//! # What crosses the IPC boundary
//!
//! [`TextOutcome`] carries the DE-IDENTIFIED text, which is what the user asked
//! for, plus a span map that is labels, lengths and synthetic replacements.
//! [`FileOutcome`] carries no document bytes at all: a file is read, masked and
//! written entirely inside the Rust process, and the page is told counts and
//! structural names. Neither carries the path the user picked.
//!
//! That is I4 applied to a GUI: the same rule that keeps a TCKN out of a log
//! keeps it out of a webview's heap, its devtools, and any crash dump the OS
//! takes of the renderer.

use deid_tr_core::surrogate::SALT_LEN;
use deid_tr_core::{Pipeline, Salt, SurrogateEngine, Tier};
use deid_tr_files::{detect_format, mask_file, Format, Masker, SpanRecord};
use serde::{Deserialize, Serialize};

use crate::l3;

/// The assurance tier, as the front end names it.
///
/// A closed vocabulary rather than a free string: an unrecognised tier must be
/// a deserialisation failure, not a silent fall back to Safe Harbor. A silent
/// downgrade is an unswept document presented as a swept one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TierChoice {
    /// L1 + L4 + L5. The default, and the only tier that needs nothing
    /// installed.
    #[default]
    SafeHarbor,
    /// Adds L3, the full-document sweep by a local LLM.
    ExpertDetermination,
}

impl From<TierChoice> for Tier {
    fn from(choice: TierChoice) -> Self {
        match choice {
            TierChoice::SafeHarbor => Self::SafeHarbor,
            TierChoice::ExpertDetermination => Self::ExpertDetermination,
        }
    }
}

/// Anything the desktop application can refuse to do.
///
/// NO VARIANT CARRIES DOCUMENT TEXT OR A DOCUMENT PATH (I4). The I/O variants
/// carry an `io::ErrorKind` rendering rather than the underlying error, because
/// some platforms put the path into an `io::Error`'s `Display` and a clinical
/// export is routinely named after the patient.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DesktopError {
    /// The OS entropy source failed, so L5 has no salt.
    ///
    /// FATAL RATHER THAN A DEGRADATION to placeholder labels: a run that
    /// silently drops L5 produces output the operator has to read to discover,
    /// and a salt derived from a clock is a salt an attacker can reconstruct.
    #[error("the operating system entropy source is unavailable, so surrogates cannot be keyed")]
    Entropy,
    /// The Expert Determination tier was asked for and cannot be served.
    #[error("{0}")]
    TierUnavailable(#[from] l3::Unavailable),
    /// The pipeline refused the document.
    #[error("de-identification failed: {0}")]
    Pipeline(#[from] deid_tr_core::Error),
    /// The container could not be opened, rewritten or verified.
    #[error("{0}")]
    File(#[from] deid_tr_files::FileError),
    /// The bytes are not a format this build can open.
    #[error(
        "this file is not a format deid-tr can open. Supported: PDF, DOCX, TXT, CSV, JSON and \
         JSON Lines. Nothing was masked and nothing was written."
    )]
    UnknownFormat,
    /// The chosen file could not be read.
    #[error("the file could not be read ({kind}). Nothing was masked and nothing was written.")]
    Read {
        /// The `io::ErrorKind`, rendered. Never the path.
        kind: String,
    },
    /// The output could not be written.
    ///
    /// Distinguished from [`DesktopError::Read`] because the two mean opposite
    /// things about what happened to the document: a read failure means nothing
    /// was processed, a write failure means the masking succeeded and the result
    /// was lost.
    #[error(
        "the de-identified file could not be written ({kind}). The masking succeeded; the \
         result was NOT saved."
    )]
    Write {
        /// The `io::ErrorKind`, rendered. Never the path.
        kind: String,
    },
}

/// One span the pipeline removed, described without the text it covered.
///
/// A projection of `deid_tr_files::SpanRecord` for serialisation. It is a
/// separate type rather than a `serde` derive on the original because
/// `deid-tr-files` has no `serde` dependency and should not acquire one to suit
/// a GUI.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpanRow {
    /// The schema label, e.g. `TCKN`, `PHONE`, `EMAIL`.
    pub label: String,
    /// Which layer proposed the span: `rules`, `ner` or `context`.
    pub layer: String,
    /// Length in bytes of what was removed. A length is not an identifier.
    pub byte_len: usize,
    /// Confidence at the point of decision.
    pub confidence: f32,
    /// True when an arithmetic check actually passed on the covered bytes.
    pub checksum_validated: bool,
    /// What was put in its place. Synthetic by construction, so not PHI.
    pub replacement: String,
}

impl From<SpanRecord> for SpanRow {
    fn from(record: SpanRecord) -> Self {
        Self {
            label: record.label,
            layer: record.layer,
            byte_len: record.byte_len,
            confidence: record.confidence,
            checksum_validated: record.checksum_validated,
            replacement: record.replacement,
        }
    }
}

/// The result of de-identifying text the user typed or pasted.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TextOutcome {
    /// The de-identified document.
    pub text: String,
    /// What was removed. Never where, never what it said.
    pub spans: Vec<SpanRow>,
    /// The tier that actually ran, echoed back so the page cannot display a
    /// tier the run did not use.
    pub tier: TierChoice,
    /// The names-are-not-masked sentence, carried WITH every result so a
    /// surface cannot render one without the other.
    pub disclosure: &'static str,
}

/// The result of redacting a file on disk.
///
/// Carries no bytes and no paths: the file was read, masked and written by the
/// Rust side, and the page is told what happened rather than shown it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileOutcome {
    /// The format that was detected: `pdf`, `docx`, `txt`, `csv`, `json`,
    /// `jsonl`.
    pub format: &'static str,
    /// How many spans were removed across the whole document.
    pub masked: usize,
    /// How many discrete locations were rewritten -- pages, records, parts.
    pub locations: usize,
    /// Per page or per package part, with what was removed from each.
    ///
    /// STRUCTURAL NAMES ONLY. A reviewer needs to see that page 4 of a 6-page
    /// document yielded nothing, which is the difference between "clean" and
    /// "not read".
    pub parts: Vec<PartRow>,
    /// Structures removed wholesale rather than rewritten, by name.
    pub stripped: Vec<String>,
    /// What was removed. Never where, never what it said.
    pub spans: Vec<SpanRow>,
    /// The sentence that goes with a document carrying unread images, and the
    /// pages it applies to. `None` when every page was text this build read.
    ///
    /// AN OPTION AND NOT AN EMPTY LIST, so a surface that forgets to render it
    /// is a surface that fails to compile its own template rather than one that
    /// quietly shows nothing.
    pub images_not_read: Option<ImagesNotRead>,
    /// Which verifier ran on the output bytes: `pdf-reopen` or `output-scan`.
    pub verification_method: &'static str,
    /// What it checked, in the order it checked it.
    pub verification_checks: Vec<&'static str>,
    /// How many removed identifiers were hunted for in the output bytes.
    ///
    /// ZERO IS NOT A PASS TO BOAST ABOUT: it means nothing was removed, so the
    /// scan had nothing to look for. The UI says "nothing detected" for it.
    pub identifiers_checked: usize,
    /// The tier that actually ran.
    pub tier: TierChoice,
    /// The names-are-not-masked sentence.
    pub disclosure: &'static str,
}

/// Pages whose pixels were not read, and the sentence that explains them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImagesNotRead {
    /// The standing sentence from `deid-tr-files`.
    pub warning: &'static str,
    /// One-based page numbers carrying images, with how many on each.
    pub pages: Vec<ImagePage>,
}

/// One page carrying images this build did not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImagePage {
    /// One-based page number.
    pub page: usize,
    /// How many images are on it.
    pub images: usize,
    /// How many of those are too large to dismiss as decoration.
    pub plausible_content: usize,
}

/// One page or package part, and what was removed from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartRow {
    /// A structural name: `page 1`, `word/document.xml`, `document`.
    pub name: String,
    /// How many spans were removed from it.
    pub masked: usize,
}

/// Which layers this build actually has, and why not when it does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerReport {
    /// One row per layer, in pipeline order.
    pub layers: Vec<LayerRow>,
    /// The names-are-not-masked sentence.
    pub disclosure: &'static str,
}

/// One layer's honest status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerRow {
    /// `L1` .. `L5`.
    pub id: &'static str,
    /// What the layer is for.
    pub name: &'static str,
    /// Whether this build has it.
    pub live: bool,
    /// The reason, whether or not it is live. A `&'static str`, so it can only
    /// ever be a literal compiled into the binary.
    pub detail: &'static str,
}

/// The de-identified file, plus what to tell the user about it.
///
/// `bytes` is the ONLY document-derived value this module returns, and it never
/// crosses the IPC boundary: `main.rs` writes it to the path the save dialog
/// returned and hands the page the [`FileOutcome`] alone.
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted {
    /// The rewritten file.
    pub bytes: Vec<u8>,
    /// What happened, for the page.
    pub outcome: FileOutcome,
}

/// The application's per-process state: one salt.
///
/// # Why one salt for the process and not one per document
///
/// Within a session the same identifier gets the same surrogate across
/// documents, which is what makes a batch of one patient's notes internally
/// consistent. Across sessions it does not, so two runs are not linkable. An
/// operator who needs longitudinal linkage across restarts needs a salt that
/// outlives the process, and that is a key-management decision this application
/// must not make silently on their behalf.
///
/// No `Debug` and no `Serialize`: it is key material.
pub struct Session {
    salt: [u8; SALT_LEN],
    l3: l3::Config,
}

impl Session {
    /// Draw a salt from the operating system and read the L3 configuration.
    ///
    /// # Errors
    ///
    /// [`DesktopError::Entropy`] when the OS will not produce one. Fatal at
    /// startup rather than degraded at first use: see the variant's docs.
    pub fn new() -> Result<Self, DesktopError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| DesktopError::Entropy)?;
        Ok(Self {
            salt,
            l3: l3::Config::from_env(),
        })
    }

    /// A session with an explicit salt and L3 configuration, for tests.
    #[must_use]
    pub const fn with_salt(salt: [u8; SALT_LEN], l3: l3::Config) -> Self {
        Self { salt, l3 }
    }

    /// Whether Expert Determination can be served, and why not when it cannot.
    ///
    /// Checked WITHOUT a document in hand, so the refusal arrives before the
    /// user has pasted a note or picked a file.
    ///
    /// # Errors
    ///
    /// [`l3::Unavailable`], naming the fix.
    pub fn expert_tier_gate(&self) -> Result<(), l3::Unavailable> {
        l3::checked(&self.l3).map(|_| ())
    }

    /// Build the pipeline for one run.
    ///
    /// L3 IS INSTALLED WHENEVER THE TIER ASKS FOR IT, and its absence is fatal
    /// here rather than at the first document: `Pipeline::propose` would refuse
    /// an Expert Determination run with no contextual layer anyway, but that
    /// refusal arrives with a clinical note already in memory and says only that
    /// none is configured.
    fn build(&self, tier: TierChoice) -> Result<Pipeline, DesktopError> {
        let mut pipeline = Pipeline::new(tier.into());
        if tier == TierChoice::ExpertDetermination {
            pipeline = pipeline.with_context(l3::contextual(&self.l3)?);
        }
        // L5 IS ALWAYS INSTALLED. The CLI can be asked for `[LABEL]`
        // placeholders; this surface cannot, because the only reason to want
        // them is machine-readable output and this surface produces documents a
        // person reads.
        Ok(pipeline.with_surrogates(SurrogateEngine::new(Salt::from_bytes(self.salt))))
    }

    /// De-identify text the user typed or pasted.
    ///
    /// # Errors
    ///
    /// [`DesktopError`]. Nothing partial is returned: either the whole document
    /// was processed or nothing was.
    pub fn deidentify_text(
        &self,
        tier: TierChoice,
        text: &str,
    ) -> Result<TextOutcome, DesktopError> {
        let pipeline = self.build(tier)?;
        let masker = Masker::new(&pipeline);
        // `Masked::originals` is PHI. It is bound here, used for nothing, and
        // dropped at the end of this expression -- it never reaches a return
        // value, a log or the IPC boundary.
        let masked = masker.mask(text)?;
        Ok(TextOutcome {
            text: masked.text,
            spans: masker.take_records().into_iter().map(SpanRow::from).collect(),
            tier,
            disclosure: crate::disclosure(),
        })
    }

    /// De-identify a whole file, in memory.
    ///
    /// `name` is the file name the user picked, used ONLY to disambiguate
    /// formats that share a magic prefix (a `.docx` is a zip). It is not
    /// returned, not logged, and not stored.
    ///
    /// # Errors
    ///
    /// [`DesktopError`]. A document whose redaction cannot be VERIFIED returns
    /// an error and no bytes -- `deid-tr-files` re-opens a redacted PDF and
    /// scans every output for every identifier it removed.
    pub fn redact_file(
        &self,
        tier: TierChoice,
        bytes: &[u8],
        name: Option<&str>,
    ) -> Result<Redacted, DesktopError> {
        let format = detect_format(bytes, name).ok_or(DesktopError::UnknownFormat)?;
        let pipeline = self.build(tier)?;
        let masker = Masker::new(&pipeline);
        let output = mask_file(&masker, bytes, format)?;
        let report = output.report;
        let images_not_read = if report.images.is_empty() {
            None
        } else {
            Some(ImagesNotRead {
                warning: deid_tr_files::Report::images_not_read(),
                pages: report
                    .images
                    .iter()
                    .map(|page| ImagePage {
                        page: page.page,
                        images: page.images.len(),
                        plausible_content: page.plausible_content(),
                    })
                    .collect(),
            })
        };
        Ok(Redacted {
            bytes: output.bytes,
            outcome: FileOutcome {
                format: report.format,
                masked: report.masked,
                locations: report.locations,
                parts: report
                    .parts
                    .iter()
                    .map(|part| PartRow {
                        name: part.name.clone(),
                        masked: part.masked,
                    })
                    .collect(),
                stripped: report.stripped,
                spans: report.spans.into_iter().map(SpanRow::from).collect(),
                images_not_read,
                verification_method: output.verification.method,
                verification_checks: output.verification.checks,
                identifiers_checked: output.verification.identifiers_checked,
                tier,
                disclosure: crate::disclosure(),
            },
        })
    }

    /// Which layers this build has.
    ///
    /// Read from a freshly built Safe Harbor pipeline rather than from
    /// configuration, so the answer is what is INSTALLED and not what was asked
    /// for. The L3 row reflects the environment, which is the same check the
    /// tier gate makes, so the status panel and the refusal cannot disagree.
    #[must_use]
    pub fn layer_report(&self) -> LayerReport {
        let ner_live = !Pipeline::new(Tier::SafeHarbor).ensemble().is_empty();
        LayerReport {
            layers: vec![
                LayerRow {
                    id: "L1",
                    name: "Deterministic rules (regex + checksum)",
                    live: true,
                    detail: "Compiled in. Finds TCKN, VKN, IBAN, phone, e-mail, MRN and dates, \
                             checksum-validated where the format carries a checksum.",
                },
                LayerRow {
                    id: "L2",
                    name: "NER ensemble (names)",
                    live: ner_live,
                    detail: "NO TRAINED MODEL IN THIS BUILD, and no weights ship. Every NAME \
                             label is in this state: patient, clinician and relative names are \
                             NOT masked. A name you paste stays in the output.",
                },
                LayerRow {
                    id: "L3",
                    name: "Contextual sweep (local LLM)",
                    live: self.expert_tier_gate().is_ok(),
                    detail: "Tier-gated. Needs a local GGUF model and a local runtime named by \
                             DEID_L3_MODEL and DEID_L3_RUNTIME. Nothing is ever downloaded and \
                             no cloud model is contacted.",
                },
                LayerRow {
                    id: "L4",
                    name: "Router + adjudication (medical allowlist)",
                    live: true,
                    detail: "Compiled in, with the audited medical vocabulary. Argues down \
                             false positives so a term like carcinoma survives; it can only \
                             ever keep a span, never invent one.",
                },
                LayerRow {
                    id: "L5",
                    name: "Consistent surrogates",
                    live: true,
                    detail: "Installed, keyed by a salt drawn from this machine at startup. \
                             Consistent within this session and not linkable across sessions.",
                },
            ],
            disclosure: crate::disclosure(),
        }
    }
}

/// The formats the file dialog offers, as (label, extensions).
///
/// Derived from what `deid_tr_files::Format` can open rather than hand-listed,
/// so a dialog can never offer a format the masker will then refuse.
#[must_use]
pub fn openable_extensions() -> Vec<&'static str> {
    ["pdf", "docx", "txt", "csv", "json", "jsonl"]
        .into_iter()
        .filter(|extension| Format::from_extension(extension).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed salt, so a test asserts on behaviour and not on entropy.
    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    fn session() -> Session {
        Session::with_salt(SALT, l3::Config::default())
    }

    /// A checksum-VALID TCKN, built at runtime.
    ///
    /// I8: the same number written as a literal would be refused by the
    /// pre-commit PHI scan, correctly -- a committed checksum-valid TCKN is
    /// indistinguishable from a real one to every tool that reads this repo.
    fn tckn() -> String {
        let digits: [i32; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
        let even = digits[1] + digits[3] + digits[5] + digits[7];
        // `rem_euclid` and not `%`: the subtraction can go negative for other
        // digit sets, and Rust's `%` would then yield a negative remainder and
        // a check digit that is not a digit.
        let d10 = (odd * 7 - even).rem_euclid(10);
        let d11 = (digits.iter().sum::<i32>() + d10).rem_euclid(10);
        digits
            .iter()
            .chain([&d10, &d11])
            .map(|digit| char::from(b'0' + u8::try_from(*digit).expect("single digit")))
            .collect()
    }

    #[test]
    fn a_rule_detectable_identifier_is_removed_from_text() {
        let tckn = tckn();
        let outcome = session()
            .deidentify_text(TierChoice::SafeHarbor, &format!("TCKN {tckn} kayitli."))
            .expect("safe harbor must run with nothing installed");
        assert!(!outcome.text.contains(&tckn));
        assert_eq!(outcome.spans.len(), 1);
        assert_eq!(outcome.spans[0].label, "TCKN");
        assert!(outcome.spans[0].checksum_validated);
    }

    #[test]
    fn a_name_survives_and_the_outcome_says_so() {
        // THE HONESTY TEST for this surface. L2 has no trained model, so the
        // name is still there. If this ever fails because a name IS masked, the
        // disclosure string and the UI banner have to change with it, which is
        // why both assertions live in one test.
        let outcome = session()
            .deidentify_text(TierChoice::SafeHarbor, "Hasta Ayse Yilmaz muayene edildi.")
            .expect("safe harbor");
        assert!(outcome.text.contains("Ayse Yilmaz"));
        assert!(outcome.spans.is_empty());
        assert!(outcome.disclosure.contains("does NOT mask person names"));
    }

    #[test]
    fn the_span_map_that_crosses_the_boundary_carries_no_identifier() {
        // I4 AT THE IPC BOUNDARY. Serialise exactly what the page receives and
        // assert the identifier is not in the bytes.
        let tckn = tckn();
        let outcome = session()
            .deidentify_text(TierChoice::SafeHarbor, &format!("TCKN: {tckn}"))
            .expect("safe harbor");
        let wire = serde_json::to_string(&outcome.spans).expect("serialise");
        assert!(!wire.contains(&tckn));
        assert!(wire.contains("TCKN"));
    }

    #[test]
    fn expert_determination_is_refused_before_a_document_is_read() {
        // THE GATE. Nothing is masked and the message names the variable to
        // set, rather than reporting that a tier is "unavailable".
        let error = session()
            .deidentify_text(TierChoice::ExpertDetermination, "Hasta bir sey soyledi.")
            .expect_err("expert determination must refuse with nothing installed");
        let message = error.to_string();
        assert!(message.contains(l3::ENV_MODEL));
        assert!(message.contains("Nothing was masked"));
    }

    #[test]
    fn the_layer_report_admits_l2_is_absent() {
        let report = session().layer_report();
        let l2 = report
            .layers
            .iter()
            .find(|row| row.id == "L2")
            .expect("L2 row");
        assert!(!l2.live);
        assert!(l2.detail.contains("NO TRAINED MODEL"));
        let l1 = report
            .layers
            .iter()
            .find(|row| row.id == "L1")
            .expect("L1 row");
        assert!(l1.live);
    }

    #[test]
    fn a_text_file_is_redacted_and_verified() {
        let tckn = tckn();
        let source = format!("Hasta kaydi\nTCKN {tckn}\n");
        let redacted = session()
            .redact_file(TierChoice::SafeHarbor, source.as_bytes(), Some("note.txt"))
            .expect("txt redaction");
        assert_eq!(redacted.outcome.format, "txt");
        assert_eq!(redacted.outcome.masked, 1);
        assert_eq!(redacted.outcome.identifiers_checked, 1);
        assert!(!String::from_utf8_lossy(&redacted.bytes).contains(&tckn));
        // The bytes are the only document-derived value, and they are NOT part
        // of what the page is told.
        let wire = serde_json::to_string(&redacted.outcome).expect("serialise");
        assert!(!wire.contains(&tckn));
    }

    #[test]
    fn an_unknown_container_is_refused_rather_than_guessed() {
        let error = session()
            .redact_file(TierChoice::SafeHarbor, &[0x00, 0x01, 0x02, 0x03], None)
            .expect_err("must refuse");
        assert_eq!(error, DesktopError::UnknownFormat);
        assert!(error.to_string().contains("nothing was written"));
    }

    #[test]
    fn every_offered_extension_is_one_the_masker_opens() {
        let offered = openable_extensions();
        assert!(offered.contains(&"pdf"));
        assert!(offered.contains(&"docx"));
        for extension in offered {
            assert!(Format::from_extension(extension).is_some());
        }
    }

    #[test]
    fn surrogates_are_consistent_within_a_session() {
        // L5's within-document consistency is what makes a masked note
        // readable. Two runs in ONE session must agree; that is the property a
        // per-process salt buys.
        let tckn = tckn();
        let session = session();
        let first = session
            .deidentify_text(TierChoice::SafeHarbor, &format!("TCKN {tckn}"))
            .expect("first");
        let second = session
            .deidentify_text(TierChoice::SafeHarbor, &format!("TCKN {tckn}"))
            .expect("second");
        assert_eq!(first.spans[0].replacement, second.spans[0].replacement);
    }
}
