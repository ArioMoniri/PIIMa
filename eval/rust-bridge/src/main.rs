//! Run the real `core::Pipeline` over a corpus and emit its actual output.
//!
//! This is the bridge that lets `eval/redteam/` attack the PRODUCT instead of a
//! reference instrument. It reads one JSON object from stdin and writes one JSON
//! object to stdout:
//!
//! ```text
//! in : {"tier": "safe_harbor", "documents": [{"doc_id": "...", "text": "..."}]}
//! out: {"tier": "safe_harbor", "detector": "pipeline:safe_harbor",
//!       "documents": [{"doc_id": "...", "deid_text": "...",
//!                      "spans": [{"start":0,"end":11,"label":"TCKN",
//!                                 "decision":"mask","replacement":"...",
//!                                 "confidence":1.0,"checksum_validated":true,
//!                                 "rationale":"protected"}]}]}
//! ```
//!
//! # Why the span map is printed here and nowhere else
//!
//! A span map is a document-equivalent secret and the product CLI will not emit
//! one. This binary is an eval instrument: the only corpus it is ever pointed at
//! is `eval/gold` and `eval/adversarial`, which I8 requires to be synthetic. The
//! red team cannot ask "did the pipeline mask this region" without the map, and
//! answering that question by string-searching the output is wrong the moment a
//! surrogate happens to contain the same substring.
//!
//! # I4
//!
//! No error, diagnostic or panic here carries a fragment of a document. Failures
//! are shaped as a code plus offsets, and every fallible step returns `Err`
//! rather than unwrapping, so a malformed corpus is a non-zero exit and not a
//! stack trace containing a note.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use deid_tr_core::route::Rationale;
use deid_tr_core::span::Decision;
use deid_tr_core::surrogate::{Salt, SurrogateEngine};
use deid_tr_core::{Pipeline, Tier};
use serde_json::{json, Map, Value};

/// The salt domain. Fixed and derived from the doc_id so that two runs over the
/// same corpus produce the same surrogates: an eval number that changes between
/// two runs of the same committed code cannot be cited by a model card (I5).
/// This is an EVAL construction. A deployment draws salts from the OS CSPRNG;
/// `core/` deliberately cannot (see the `Salt` header).
const SALT_DOMAIN: &[u8] = b"deid-tr/eval/pipeline-bridge/v1/salt/";

/// What went wrong, with no fragment of any document in it (I4).
#[derive(Debug, thiserror::Error)]
enum BridgeError {
    #[error("could not read stdin")]
    Read(#[source] io::Error),
    #[error("could not write stdout")]
    Write(#[source] io::Error),
    #[error("stdin was not a JSON object of the expected shape")]
    Malformed,
    #[error("unknown tier requested")]
    UnknownTier,
    #[error("the surrogate engine refused the derived salt")]
    Salt,
    #[error("the pipeline refused document #{index}")]
    Pipeline {
        index: usize,
        #[source]
        source: deid_tr_core::Error,
    },
}

fn tier_from(name: &str) -> Result<Tier, BridgeError> {
    match name {
        "safe_harbor" => Ok(Tier::SafeHarbor),
        // Expert Determination needs an L3 local model the eval host does not
        // install. Refusing beats silently scoring a Safe Harbor run as though
        // the contextual sweep had run: that is exactly the class of substituted
        // number this bridge exists to eliminate.
        "expert_determination" => Err(BridgeError::UnknownTier),
        _ => Err(BridgeError::UnknownTier),
    }
}

fn rationale_str(rationale: Rationale) -> &'static str {
    match rationale {
        Rationale::Protected => "protected",
        Rationale::NotVocabulary => "not_vocabulary",
        Rationale::VocabularyUncontested => "vocabulary_uncontested",
        Rationale::PersonEvidenceDecisive => "person_evidence_decisive",
        Rationale::AdjudicatorAgreed => "adjudicator_agreed",
        Rationale::AdjudicatorDisagreed => "adjudicator_disagreed",
        Rationale::AdjudicatorUnavailable => "adjudicator_unavailable",
    }
}

/// Per-document salt, keyed on the doc_id.
///
/// `SaltScope::Document` is the product default, so the eval run measures the
/// linkability the product actually has rather than a scope chosen to score
/// well.
fn engine_for(doc_id: &str) -> Result<SurrogateEngine, BridgeError> {
    let mut material = Vec::with_capacity(SALT_DOMAIN.len() + doc_id.len());
    material.extend_from_slice(SALT_DOMAIN);
    material.extend_from_slice(doc_id.as_bytes());
    let salt = Salt::derive(&material).map_err(|_| BridgeError::Salt)?;
    Ok(SurrogateEngine::new(salt))
}

fn mask_one(index: usize, doc_id: &str, text: &str, tier: Tier) -> Result<Value, BridgeError> {
    let pipeline = Pipeline::new(tier).with_surrogates(engine_for(doc_id)?);
    let result = pipeline
        .deidentify(text)
        .map_err(|source| BridgeError::Pipeline { index, source })?;

    let spans: Vec<Value> = result
        .span_map
        .iter()
        .map(|mapped| {
            json!({
                "start": mapped.span.start(),
                "end": mapped.span.end(),
                "label": mapped.span.label().as_str(),
                "source": format!("{:?}", mapped.span.source()).to_lowercase(),
                "decision": match mapped.decision {
                    Decision::Mask => "mask",
                    Decision::Keep => "keep",
                },
                "replacement": mapped.replacement.clone(),
                "confidence": mapped.span.confidence(),
                // The field the checksum-precision gate needs. A label is what a
                // human wrote in a fixture; THIS is what the checksum actually
                // said, and the two are not the same claim.
                "checksum_validated": mapped.span.is_checksum_validated(),
                "rationale": rationale_str(mapped.rationale),
            })
        })
        .collect();

    Ok(json!({
        "doc_id": doc_id,
        "deid_text": result.text,
        "spans": spans,
    }))
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, BridgeError> {
    object.get(key).ok_or(BridgeError::Malformed)
}

fn run(input: &str) -> Result<String, BridgeError> {
    let parsed: Value = serde_json::from_str(input).map_err(|_| BridgeError::Malformed)?;
    let request = parsed.as_object().ok_or(BridgeError::Malformed)?;
    let tier_name = field(request, "tier")?
        .as_str()
        .ok_or(BridgeError::Malformed)?;
    let tier = tier_from(tier_name)?;

    let documents = field(request, "documents")?
        .as_array()
        .ok_or(BridgeError::Malformed)?;

    let mut out = Vec::with_capacity(documents.len());
    for (index, entry) in documents.iter().enumerate() {
        let object = entry.as_object().ok_or(BridgeError::Malformed)?;
        let doc_id = field(object, "doc_id")?
            .as_str()
            .ok_or(BridgeError::Malformed)?;
        let text = field(object, "text")?
            .as_str()
            .ok_or(BridgeError::Malformed)?;
        out.push(mask_one(index, doc_id, text, tier)?);
    }

    let response = json!({
        "tier": tier_name,
        // The identity the red-team report records and eval/harness.py matches
        // against the detector being scored. A rate produced here may only ever
        // populate the gate of a run scoring this same detector.
        "detector": format!("pipeline:{tier_name}"),
        "documents": out,
    });
    serde_json::to_string(&response).map_err(|_| BridgeError::Malformed)
}

fn main() -> ExitCode {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        return fail(&BridgeError::Read(error));
    }
    let rendered = match run(&input) {
        Ok(rendered) => rendered,
        Err(error) => return fail(&error),
    };
    match io::stdout().write_all(rendered.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&BridgeError::Write(error)),
    }
}

fn fail(error: &BridgeError) -> ExitCode {
    let _ = writeln!(io::stderr(), "deid-eval-bridge: {error}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_round_trips_with_a_span_map() {
        let request = json!({
            "tier": "safe_harbor",
            "documents": [{"doc_id": "d1", "text": "Iletisim: hasta@example.com"}],
        })
        .to_string();
        let out: Value = serde_json::from_str(&run(&request).expect("run")).expect("json");
        let documents = out["documents"].as_array().expect("documents");
        assert_eq!(documents.len(), 1);
        assert_eq!(out["detector"], "pipeline:safe_harbor");
        assert!(!documents[0]["spans"].as_array().expect("spans").is_empty());
    }

    #[test]
    fn expert_determination_is_refused_rather_than_silently_downgraded() {
        let request = json!({"tier": "expert_determination", "documents": []}).to_string();
        assert!(matches!(run(&request), Err(BridgeError::UnknownTier)));
    }

    #[test]
    fn a_failure_names_no_document_content() {
        let request = json!({"documents": [], "tier": "safe_harbor", "x": "Ayse Yilmaz"});
        let error = run("not json").expect_err("malformed");
        assert!(!format!("{error}").contains("Ayse"));
        // The well-formed request stays well-formed: the assertion above is
        // about the error text, not about rejecting extra keys.
        assert!(run(&request.to_string()).is_ok());
    }
}
