//! The whole pipeline, from the public API only, with mocks for every seam.
//!
//! WHY AN INTEGRATION TEST AND NOT MORE UNIT TESTS: every layer already proves
//! its own behaviour against its own inputs. What no unit test can prove is that
//! the layers were WIRED the way the architecture says -- that L3 is actually
//! gated on the tier, that L1's checksum span actually reaches L4 still carrying
//! its protection, that a lone L2 proposal actually survives a merge that also
//! saw agreement elsewhere. Those are properties of the composition, and a
//! composition is only observable from outside the crate.
//!
//! Every fixture here is synthetic (I8). The one TCKN is built at RUNTIME by
//! `valid_tckn` below and never appears in this file as a literal, because a
//! checksum-valid TCKN in a committed file is what the pre-commit hook exists to
//! block.

use deid_tr_core::detect::{
    LabelSet, MockDetector, NerEnsemble, Normalization, TokenSpan, Tokenized,
};
use deid_tr_core::route::{AllowlistCategory, MedicalAllowlist};
use deid_tr_core::span::Layer;
use deid_tr_core::surrogate::{Salt, SurrogateEngine};
use deid_tr_core::{
    Contextual, Decision, DetectorId, EntityLabel, Error, Merged, Pipeline, QuasiCategory, Result,
    Span, Tier, Tokenizer,
};

use std::cell::Cell;
use std::rc::Rc;

// ---------------------------------------------------------------- test doubles

/// An L3 that counts how often it was asked, so tier gating is OBSERVED rather
/// than inferred from an empty span list -- a layer that ran and found nothing
/// and a layer that never ran produce identical output.
struct SpyContextual {
    calls: Rc<Cell<usize>>,
    spans: Vec<Span>,
}

impl Contextual for SpyContextual {
    fn sweep(&self, _doc: &str) -> Result<Vec<Span>> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.spans.clone())
    }
}

fn spy(spans: Vec<Span>) -> (Rc<Cell<usize>>, Box<dyn Contextual>) {
    let calls = Rc::new(Cell::new(0));
    (Rc::clone(&calls), Box::new(SpyContextual { calls, spans }))
}

/// Whitespace tokenization, which is all L2's offset machinery needs to be
/// exercised: the real vocabulary is a file, and `core/` performs no I/O (I1).
///
/// Emits a leading special token, the way every real encoder emits `[CLS]`, so
/// the test also covers the case where logit row 0 covers no document bytes.
struct WordTokenizer;

fn word_spans(text: &str) -> Vec<TokenSpan> {
    let mut spans = vec![TokenSpan::special()];
    let mut open: Option<usize> = None;
    for (offset, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = open.take() {
                spans.push(TokenSpan::new(start, offset));
            }
        } else {
            open.get_or_insert(offset);
        }
    }
    if let Some(start) = open {
        spans.push(TokenSpan::new(start, text.len()));
    }
    spans
}

impl Tokenizer for WordTokenizer {
    fn encode(&self, normalized: &str) -> Result<Tokenized> {
        let spans = word_spans(normalized);
        let ids: Vec<u32> = (0..spans.len() as u32).collect();
        Ok(Tokenized::new(ids, spans)?)
    }
}

/// Canned logits tagging exactly the given token indices as whole-entity
/// `S-<label>`, everything else `O`.
///
/// Column order is `LabelSet`'s contract: O, B, I, E, S per entity.
fn single_entity_rows(tokens: usize, tagged: &[usize], margin: f32) -> Vec<Vec<f32>> {
    (0..tokens)
        .map(|index| {
            let mut row = vec![0.0_f32; 5];
            if tagged.contains(&index) {
                row[4] = margin;
            } else {
                row[0] = 4.0;
            }
            row
        })
        .collect()
}

fn token_index(text: &str, needle: &str) -> usize {
    let start = text.find(needle).expect("fixture contains the needle");
    word_spans(text)
        .iter()
        .position(|token| token.start <= start && start < token.end)
        .expect("the needle lies inside a token")
}

/// A checksum-valid TCKN, computed here so no such number is ever committed.
///
/// `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`, then
/// `d11 = (d1+..+d10) mod 10`, with `d1 != 0`.
fn valid_tckn() -> String {
    let head = [1_u32, 9, 8, 7, 6, 5, 4, 3, 2];
    let odd: u32 = head[0] + head[2] + head[4] + head[6] + head[8];
    let even: u32 = head[1] + head[3] + head[5] + head[7];
    // `+ 70` keeps the unsigned subtraction non-negative: the even-position sum
    // is at most 36, so the bias is larger than anything it can remove, and it
    // is a multiple of 10 so it cannot change the result.
    let tenth = (odd * 7 + 70 - even) % 10;
    let sum: u32 = head.iter().sum::<u32>() + tenth;
    let eleventh = sum % 10;
    head.iter()
        .chain([&tenth, &eleventh])
        .map(|digit| char::from_digit(*digit, 10).expect("a decimal digit"))
        .collect()
}

fn medical_vocabulary() -> MedicalAllowlist {
    MedicalAllowlist::from_sources(&[
        (AllowlistCategory::Anatomy, "costa\nhepaticus\n"),
        (AllowlistCategory::Diagnosis, "carcinoma\npneumonia\n"),
    ])
}

fn salted_engine() -> SurrogateEngine {
    // Fixed key material: this is a test, and a deterministic salt is what makes
    // the round-trip assertion reproducible. A binding supplies real entropy.
    SurrogateEngine::new(Salt::derive(b"deid-tr integration test key").expect("key material"))
}

// ------------------------------------------------------------------- the tier

const QUASI_DOC: &str = "Hasta Merkez Bankası'nda çalışıyor.";

fn employer_span(confidence: f32) -> Span {
    let start = QUASI_DOC.find("Merkez").expect("fixture");
    Span::new(
        QUASI_DOC,
        start,
        start + "Merkez Bankası".len(),
        EntityLabel::Quasi(QuasiCategory::EmployerRole),
        DetectorId::Context,
        confidence,
    )
    .expect("valid span")
}

#[test]
fn safe_harbor_never_invokes_the_contextual_layer() {
    // The tier gate, observed with a spy rather than inferred from the output.
    // L3 is a full-document read of a local LLM, and the whole cost argument
    // for the default tier is that it does not happen.
    let (calls, context) = spy(vec![employer_span(0.9)]);
    let result = Pipeline::new(Tier::SafeHarbor)
        .with_context(context)
        .deidentify(QUASI_DOC)
        .expect("safe harbor run");

    assert_eq!(calls.get(), 0, "L3 ran in the Safe Harbor tier");
    assert_eq!(result.text, QUASI_DOC);
    assert!(result.span_map.is_empty());
}

#[test]
fn expert_determination_invokes_the_contextual_layer_and_masks_what_it_finds() {
    let (calls, context) = spy(vec![employer_span(0.9)]);
    let result = Pipeline::new(Tier::ExpertDetermination)
        .with_context(context)
        .deidentify(QUASI_DOC)
        .expect("expert determination run");

    assert_eq!(calls.get(), 1, "L3 did not run in the Expert tier");
    assert_eq!(result.span_map.len(), 1);
    assert_eq!(result.span_map[0].decision, Decision::Mask);
    assert_eq!(result.span_map[0].span.source(), Layer::Context);
    // The Turkish case suffix survives on the far side of a multi-byte `ı`,
    // which only happens if the rewrite used byte offsets throughout.
    assert_eq!(result.text, "Hasta [EMPLOYER_ROLE]'nda çalışıyor.");
}

#[test]
fn the_expert_tier_without_a_local_model_refuses_rather_than_degrading() {
    // Silently falling back to Safe Harbor would hand the caller an unswept
    // document that is indistinguishable from a swept one.
    assert_eq!(
        Pipeline::new(Tier::ExpertDetermination).deidentify(QUASI_DOC),
        Err(Error::ContextualLayerMissing)
    );
}

// ------------------------------------------------------- L1 through the union

#[test]
fn a_checksum_valid_tckn_reaches_mask_and_is_never_demoted() {
    // The strongest claim in the product: a TCKN whose arithmetic passes is not
    // a false positive, so no later layer may argue it away. The whole path is
    // exercised -- L1 finds it, the union keeps its flag, L4's router auto-masks
    // it without adjudication, L5 replaces it.
    let tckn = valid_tckn();
    let doc = format!("Hasta Ayşe Yılmaz, TCKN {tckn}, costa fraktürü mevcut.");

    let result = Pipeline::new(Tier::SafeHarbor)
        .with_allowlist(medical_vocabulary())
        .with_surrogates(salted_engine())
        .deidentify(&doc)
        .expect("safe harbor run");

    let mapped = result
        .span_map
        .iter()
        .find(|m| m.span.label() == EntityLabel::Tckn)
        .expect("the TCKN reached the span map");

    assert_eq!(mapped.decision, Decision::Mask);
    assert!(mapped.span.is_checksum_validated());
    assert_eq!(mapped.span.source(), Layer::Rules);
    assert!(!result.text.contains(&tckn), "the TCKN survived masking");
    // Auto-masked on the checksum, so it never entered adjudication at all.
    assert_eq!(result.routing.checksum_validated, 1);
    assert_eq!(result.routing.escalated, 0);
    assert_eq!(result.routing.demoted, 0);

    // And the guardrail refuses even a direct request to demote it.
    assert!(matches!(
        deid_tr_core::pipeline::demote_to_keep(&Merged::single(mapped.span)),
        Err(Error::ProtectedSpanDemotion { .. })
    ));

    // Format-preserving: L5 minted another eleven digits, not a placeholder.
    let surrogate = mapped.replacement.as_deref().expect("a surrogate");
    assert_eq!(surrogate.len(), 11);
    assert!(surrogate.chars().all(|c| c.is_ascii_digit()));
    assert_ne!(surrogate, tckn);
}

#[test]
fn a_single_source_ner_span_survives_the_union_and_is_masked() {
    // THE invariant that stops the union from becoming a majority vote. One
    // ensemble member sees the clinician's name, the other does not, and the
    // lone proposal has to come out the other side masked. A council that
    // majority-votes it away is a breach machine (I2).
    const DOC: &str = "Konsültasyon: Şükrü Gökçe değerlendirdi.";
    let labels = LabelSet::new(&[EntityLabel::ClinicianName]);
    let tokens = word_spans(DOC).len();
    let seen = token_index(DOC, "Şükrü");

    let ensemble = NerEnsemble::new()
        .with_member(
            Box::new(MockDetector::new(single_entity_rows(tokens, &[seen], 4.0))),
            labels.clone(),
        )
        .expect("member 0")
        // The second member tags nothing. Its silence must not be a veto.
        .with_member(
            Box::new(MockDetector::new(single_entity_rows(tokens, &[], 4.0))),
            labels,
        )
        .expect("member 1");

    let result = Pipeline::new(Tier::SafeHarbor)
        .with_ensemble(ensemble)
        .with_tokenizer(Box::new(WordTokenizer), Normalization::Identity)
        .with_allowlist(medical_vocabulary())
        .deidentify(DOC)
        .expect("run");

    let mapped = result
        .span_map
        .iter()
        .find(|m| m.span.label() == EntityLabel::ClinicianName)
        .expect("the lone proposal was dropped by the union");

    assert_eq!(mapped.decision, Decision::Mask);
    assert_eq!(mapped.span.detector_id(), DetectorId::Ner(0));
    assert_eq!(mapped.original(), "Şükrü");
    assert_eq!(
        Merged::single(mapped.span).support(),
        1,
        "exactly one detector saw it, and it survived anyway"
    );
    assert!(!result.text.contains("Şükrü"));
}

// -------------------------------------------------- L4 and the allowlist

/// Synthetic. `costa` appears as anatomy AND as a surname, in one document, so
/// no context-free rule can pass both halves at once.
const COLLISION_DOC: &str =
    "Toraks BT'de sol 5. costa'da fraktür izlendi. Op. Dr. Andrea Costa değerlendirdi.";

#[test]
fn an_allowlist_term_is_kept_while_a_colliding_surname_is_masked() {
    // ADR D-010 at the end of the real path. A deterministic "allowlist hit is
    // a Keep" rule passes the anatomy half and LEAKS the surgeon; a rule that
    // masks every occurrence destroys the note. Only the context-sensitive rule
    // gets both, and only the assembled pipeline can be asked for both at once.
    let labels = LabelSet::new(&[EntityLabel::ClinicianName]);
    let tokens = word_spans(COLLISION_DOC).len();
    let anatomy = token_index(COLLISION_DOC, "costa'da");
    let surname = token_index(COLLISION_DOC, "Costa ");

    let ensemble = NerEnsemble::new()
        .with_member(
            Box::new(MockDetector::new(single_entity_rows(
                tokens,
                &[anatomy, surname],
                // Deliberately weak and single-source: the only kind of span L4
                // is ever permitted to demote. A confident span would be
                // auto-masked and this test would prove nothing.
                0.35,
            ))),
            labels,
        )
        .expect("one member");

    let result = Pipeline::new(Tier::SafeHarbor)
        .with_ensemble(ensemble)
        .with_tokenizer(Box::new(WordTokenizer), Normalization::Identity)
        .with_allowlist(medical_vocabulary())
        .deidentify(COLLISION_DOC)
        .expect("run");

    let decision_over = |needle: &str| {
        let start = COLLISION_DOC.find(needle).expect("fixture");
        result
            .span_map
            .iter()
            .find(|m| m.span.start() == start)
            .map(|m| m.decision)
            .expect("both surfaces must reach the span map")
    };

    assert_eq!(
        decision_over("costa'da"),
        Decision::Keep,
        "masking the rib destroys the note"
    );
    assert_eq!(
        decision_over("Costa "),
        Decision::Mask,
        "the allowlist collision leaked a clinician's surname"
    );

    assert!(result.text.contains("costa'da fraktür"));
    assert!(!result.text.contains("Dr. Costa"));
    assert_eq!(result.routing.escalated, 2, "both were argued about");
    assert_eq!(result.routing.demoted, 1, "exactly one was argued down");
}

#[test]
fn an_empty_allowlist_vouches_for_nothing_and_therefore_demotes_nothing() {
    // The safe direction under I2, stated as a test: a pipeline that has been
    // EXPLICITLY stripped of its vocabulary over-masks. The bug this guards
    // against is the opposite -- a stub allowlist that answers `false` while a
    // caller believes it is loaded is a silently disabled false-positive gate,
    // but a stub that answers `true` would be a silently disabled RECALL gate.
    //
    // `without_medical_allowlist` is spelled out because it is no longer what
    // `Pipeline::new` gives you. It was, for the whole of M4, which is why
    // every binding shipped with L4 consulting nothing.
    let labels = LabelSet::new(&[EntityLabel::ClinicianName]);
    let tokens = word_spans(COLLISION_DOC).len();
    let anatomy = token_index(COLLISION_DOC, "costa'da");

    let ensemble = NerEnsemble::new()
        .with_member(
            Box::new(MockDetector::new(single_entity_rows(
                tokens,
                &[anatomy],
                0.35,
            ))),
            labels,
        )
        .expect("one member");

    let result = Pipeline::new(Tier::SafeHarbor)
        .without_medical_allowlist()
        .with_ensemble(ensemble)
        .with_tokenizer(Box::new(WordTokenizer), Normalization::Identity)
        .deidentify(COLLISION_DOC)
        .expect("run");

    assert_eq!(result.span_map[0].decision, Decision::Mask);
    assert_eq!(result.routing.demoted, 0);
}

// ------------------------------------------------------------- the round trip

#[test]
fn the_span_map_round_trips_the_document_byte_for_byte() {
    // What M2's gateway depends on: a model answers about the de-identified
    // text, and the clinician has to read the answer about their own patient.
    // Byte-for-byte and not "close enough" -- an off-by-one here corrupts a
    // multi-byte Turkish letter and a clinician reads a mangled note.
    let tckn = valid_tckn();
    let doc = format!(
        "Hasta Ayşe Yılmaz, TCKN {tckn}, tel 0(532) 000 00 00.\n\
         Şükrü Gökçe'nin carcinoma'lı akciğer grafisi ve costa'daki fraktür \
         değerlendirildi. E-posta: klinik@ornek.example"
    );

    let labels = LabelSet::new(&[EntityLabel::ClinicianName]);
    let tokens = word_spans(&doc).len();
    let clinician = token_index(&doc, "Şükrü");
    let ensemble = NerEnsemble::new()
        .with_member(
            Box::new(MockDetector::new(single_entity_rows(
                tokens,
                &[clinician],
                4.0,
            ))),
            labels,
        )
        .expect("one member");

    let (_, context) = spy(Vec::new());
    let result = Pipeline::new(Tier::ExpertDetermination)
        .with_ensemble(ensemble)
        .with_tokenizer(Box::new(WordTokenizer), Normalization::Identity)
        .with_context(context)
        .with_allowlist(medical_vocabulary())
        .with_surrogates(salted_engine())
        .deidentify(&doc)
        .expect("run");

    // The masking actually happened, or the round trip is vacuous.
    assert!(result.span_map.iter().any(|m| m.decision == Decision::Mask));
    assert_ne!(result.text, doc);
    assert!(!result.text.contains(&tckn));
    // A surrogate does not preserve length, so the output offsets cannot be
    // derived from the input ones -- which is exactly why the map stores both.
    assert_ne!(result.text.len(), doc.len());

    assert_eq!(
        result.reidentify(),
        doc,
        "the span map did not reproduce the original document"
    );

    // The code-switched medical vocabulary is untouched in both directions.
    assert!(result.text.contains("carcinoma'lı"));
    assert!(result.text.contains("costa'daki"));

    for mapped in &result.span_map {
        assert_eq!(
            &doc[mapped.span.start()..mapped.span.end()],
            mapped.original(),
            "an input offset pair no longer addresses its own original"
        );
        let masked = mapped.decision == Decision::Mask;
        assert_eq!(masked, mapped.replacement.is_some());
        let written = &result.text[mapped.output_start..mapped.output_end];
        match mapped.replacement.as_deref() {
            Some(surrogate) => assert_eq!(written, surrogate),
            None => assert_eq!(written, mapped.original()),
        }
    }
}

#[test]
fn one_entity_gets_one_surrogate_everywhere_in_a_document() {
    // L5 property (b), which is what makes the de-identified note still READ as
    // a note: the same patient must not become three different people.
    let doc = "Şükrü Gökçe geldi. Şükrü Gökçe muayene edildi. Şükrü Gökçe taburcu.";
    let labels = LabelSet::new(&[EntityLabel::PatientName]);
    let tokens = word_spans(doc).len();
    let tagged: Vec<usize> = word_spans(doc)
        .iter()
        .enumerate()
        .filter(|(_, token)| doc.get(token.start..token.end) == Some("Şükrü"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(tagged.len(), 3, "the fixture must repeat the entity");

    let ensemble = NerEnsemble::new()
        .with_member(
            Box::new(MockDetector::new(single_entity_rows(tokens, &tagged, 4.0))),
            labels,
        )
        .expect("one member");

    let result = Pipeline::new(Tier::SafeHarbor)
        .with_ensemble(ensemble)
        .with_tokenizer(Box::new(WordTokenizer), Normalization::Identity)
        .with_surrogates(salted_engine())
        .deidentify(doc)
        .expect("run");

    let surrogates: Vec<&str> = result
        .span_map
        .iter()
        .filter_map(|m| m.replacement.as_deref())
        .collect();
    assert_eq!(surrogates.len(), 3);
    assert!(
        surrogates.windows(2).all(|pair| pair[0] == pair[1]),
        "the same entity received different surrogates within one document"
    );
    assert_eq!(result.reidentify(), doc);
}

// -------------------------------------------------------------- egress checks

#[test]
fn nothing_the_pipeline_can_print_carries_an_original() {
    // I4 at the widest surface: `DeidResult` is the value every binding returns
    // and therefore the value most likely to land in a `{:?}`, a failing
    // assertion or a panic message.
    let tckn = valid_tckn();
    let doc = format!("Hasta Ayşe Yılmaz, TCKN {tckn}.");
    let result = Pipeline::new(Tier::SafeHarbor)
        .with_surrogates(salted_engine())
        .deidentify(&doc)
        .expect("run");

    let rendered = format!("{result:?}");
    assert!(!rendered.contains(&tckn), "Debug egressed the TCKN");
    assert!(rendered.contains("<redacted>"));
    assert!(result.audit.is_redacted());
    for entry in result.audit.entries() {
        assert!(entry.rationale().is_none());
    }
}
