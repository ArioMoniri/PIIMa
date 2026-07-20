//! L4 -- the router and the adjudicator.
//!
//! Input is the union of the L1, L2 and L3 proposals, the document text, and
//! the class C allowlist. Output is one [`crate::span::Decision`] per candidate.
//!
//! Two sub-steps, for two different reasons.
//!
//! 1. [`router`] is about COST. High-confidence spans -- checksum-validated,
//!    agreed by several detectors, or simply confident -- are masked without
//!    asking anyone. Only the low-confidence single-source minority escalates.
//! 2. [`adjudicate`] is about PRECISION, over the escalated spans only, and it
//!    asks exactly one question: is this real PHI, or a Latin/English medical
//!    term, drug or anatomy?
//!
//! [`allowlist`] is the runtime class C vocabulary, with the Turkish-correct
//! casefold, and [`evidence`] is the context-sensitive allowlisting that
//! resolves ADR D-010.
//!
//! # The guardrail
//!
//! L4 may only DEMOTE, `Mask -> Keep`. It may never invent a span. It may
//! demote only when the span is on the allowlist AND the surrounding context
//! does not independently mark it as a person -- or, in the ambiguous middle,
//! when an adjudicator explicitly agrees. A checksum-validated span and a
//! multi-detector-agreed span are never demoted; every demotion in this module
//! goes through [`crate::pipeline::demote_to_keep`], which returns
//! `Err(ProtectedSpanDemotion)` for those.

pub mod adjudicate;
pub mod allowlist;
pub mod evidence;
pub mod router;
pub mod vocabulary;

pub use adjudicate::{
    adjudicate, Adjudication, AdjudicationQuery, Adjudicator, Rationale, Verdict,
};
pub use allowlist::{turkish_casefold, AllowlistCategory, AllowlistEntry, MedicalAllowlist};
pub use evidence::{Assessment, PersonEvidence, PersonSignal};
pub use router::{route, route_all, AutoMaskReason, Route, Routed, RoutingStats};
pub use vocabulary::bundled as bundled_allowlist;

#[cfg(test)]
mod corpus_measurement {
    //! What the escalation rate ACTUALLY is on the committed corpus.
    //!
    //! The cost bound is the claim that makes the tier cheap, so it is measured
    //! here rather than asserted in a comment. THIS MODULE HOLDS TWO
    //! MEASUREMENTS WITH DIFFERENT DENOMINATORS and they are not
    //! interchangeable: the test below counts VOCABULARY OCCURRENCES (3.83%),
    //! and `report_the_router_escalation_rate_over_routed_candidates` counts
    //! ROUTED CANDIDATES (40.5%). Quoting the first against the brief's 2-5%
    //! claim, which is about the second, is the error D-027 corrects.
    //!
    //! The measurement below is deliberately narrow about what it can and
    //! cannot know:
    //!
    //! * WHAT IS MEASURED: for every occurrence of a class C vocabulary term in
    //!   the gold and adversarial corpus, whether the surrounding context sends
    //!   it to the adjudicator MODEL. That is the expensive path, and it is the
    //!   part of the escalation rate this layer controls.
    //! * WHAT IS NOT MEASURED: the L2 ensemble's confidence distribution. L2 is
    //!   a stub, so the fraction of spans that arrive single-source and below
    //!   the escalation ceiling is not yet observable, and inventing it here
    //!   would produce a number that looks measured and is not.
    //!
    //! MEASURED, 2026-07-20, over 190 documents and 1934 vocabulary
    //! occurrences: 1843 kept deterministically, 17 masked on decisive person
    //! evidence, 74 escalated to the adjudicator model -- 3.83% OF VOCABULARY
    //! OCCURRENCES. That is not the brief's 2-5%, which is a fraction of routed
    //! candidates; see D-027 and D-037. The number is printed on every run so a
    //! regression shows up as a changed line rather than as a silently slower
    //! pipeline.
    //!
    //! The corpus text is embedded with `include_str!`, so this stays
    //! compile-time and `core/` still performs no runtime I/O (I1). Every
    //! fixture is synthetic (I8).
    //!
    //! `CORPUS` IS MAINTAINED BY HAND AND WILL DRIFT. `include_str!` needs
    //! literal paths, so this list cannot glob the way `eval/build_gold.py`
    //! does -- and it silently fell behind by 12 documents once already, which
    //! left a published escalation rate describing a smaller corpus than the
    //! benchmark printed beside it (D-037). `tests/test_corpus_manifest.py`
    //! now compares this list against the fixtures on disk and fails when they
    //! disagree, because the failure mode is a number that stays plausible
    //! rather than a build that breaks.

    use super::allowlist::is_word_char;
    use super::evidence::{Assessment, PersonEvidence};
    use super::vocabulary::bundled as bundled_allowlist;

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
        include_str!("../../../eval/adversarial/adv_unicode.jsonl"),
    ];

    /// Pull the `text` field out of one JSONL record without a JSON parser.
    ///
    /// A parser would mean a dependency, and `core`'s dependency list is an
    /// enforced invariant (I1). The fixtures are machine-written with a fixed
    /// key order, so a scan for the key plus a standard unescape is sufficient
    /// -- and if the format ever changes, this returns `None` and the
    /// measurement fails loudly on an empty corpus rather than silently
    /// reporting zero.
    fn document_text(line: &str) -> Option<String> {
        let start = line.find("\"text\": \"")? + "\"text\": \"".len();
        let mut out = String::new();
        let mut chars = line[start..].chars();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => return Some(out),
                '\\' => match chars.next()? {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        let code = u32::from_str_radix(&hex, 16).ok()?;
                        out.push(char::from_u32(code)?);
                    }
                    other => out.push(other),
                },
                other => out.push(other),
            }
        }
        None
    }

    /// Word tokens as `(byte_start, byte_end)`.
    fn tokens(text: &str) -> Vec<(usize, usize)> {
        let mut found = Vec::new();
        let mut open: Option<usize> = None;
        for (offset, ch) in text.char_indices() {
            if is_word_char(ch) {
                open.get_or_insert(offset);
            } else if let Some(start) = open.take() {
                found.push((start, offset));
            }
        }
        if let Some(start) = open {
            found.push((start, text.len()));
        }
        found
    }

    #[test]
    fn report_the_escalation_rate_over_the_committed_corpus() {
        let allowlist = bundled_allowlist();
        let (mut documents, mut occurrences) = (0usize, 0usize);
        let (mut absent, mut suggestive, mut decisive) = (0usize, 0usize, 0usize);

        for file in CORPUS {
            for line in file.lines().filter(|line| !line.trim().is_empty()) {
                let text = document_text(line).expect("fixture line carries a text field");
                documents += 1;
                for (start, end) in tokens(&text) {
                    if !allowlist.contains(&text[start..end]) {
                        continue;
                    }
                    occurrences += 1;
                    let ev = PersonEvidence::gather(&text, start, end, allowlist);
                    match ev.assessment() {
                        Assessment::Absent => absent += 1,
                        Assessment::Suggestive => {
                            suggestive += 1;
                            println!("DBG {:?} {:?}", &text[start..end], ev.signals());
                        }
                        Assessment::Decisive => decisive += 1,
                    }
                }
            }
        }

        let rate = suggestive as f64 / occurrences as f64;
        println!(
            "corpus: {documents} documents, {occurrences} allowlist occurrences\n  \
             kept deterministically (no person evidence) : {absent}\n  \
             masked on decisive person evidence         : {decisive}\n  \
             escalated to the adjudicator model         : {suggestive} ({:.2}%)",
            rate * 100.0
        );

        assert!(documents >= 100, "the corpus did not load");
        assert!(
            occurrences > 1000,
            "the vocabulary did not match the corpus"
        );
        // A LOOSE bound, and loose on purpose. The tight number belongs in the
        // eval report, where it is tracked over time; a tight assertion here
        // would fail on the next legitimate append to the append-only corpus
        // and invite someone to weaken the rule to make the build green.
        assert!(
            rate < 0.10,
            "context-sensitive allowlisting escalated {:.1}% of vocabulary \
             occurrences, which is past the point where the Safe Harbor tier \
             is still cheap",
            rate * 100.0
        );
    }

    /// The escalation rate over ROUTED CANDIDATES, which is the denominator the
    /// cost claim is actually about -- and a completely different number from
    /// the one above.
    ///
    /// WHY BOTH EXIST, stated here because confusing them is what produced a
    /// wrong cost model in the first place:
    ///
    /// * The measurement above counts VOCABULARY OCCURRENCES: every time a
    ///   class C medical term appears anywhere in the corpus, whether or not
    ///   any detector proposed a span there. It answers "how often does
    ///   context-sensitive allowlisting turn a term into a question".
    /// * This one counts ROUTED CANDIDATES: spans that actually reached
    ///   [`route`]. It answers "what fraction of the pipeline's output costs an
    ///   adjudication", which is the quantity the Safe Harbor tier's economics
    ///   depend on.
    ///
    /// The second is the smaller denominator by an order of magnitude, so the
    /// same corpus reports a far higher rate here. Neither number is wrong;
    /// quoting one against the other's claim is.
    ///
    /// WHAT IS NOT MEASURED: L2. The ensemble is a stub, so these candidates
    /// are L1's alone, and L1 emits either a checksum-validated span (protected,
    /// never escalated) or a low-confidence one (escalated). Wiring a real L2
    /// will move this number, and it can only move it in one direction --
    /// agreement between detectors auto-masks.
    #[test]
    fn report_the_router_escalation_rate_over_routed_candidates() {
        use crate::route::router::{route, AutoMaskReason, Route};
        use crate::rules::RuleSet;
        use crate::span::union_widest;

        let rules = RuleSet;
        let (mut records, mut candidates, mut escalated) = (0usize, 0usize, 0usize);
        let (mut checksum, mut agreement, mut confident) = (0usize, 0usize, 0usize);
        // Which labels pay the bill. A single number says the tier is more
        // expensive than claimed; the breakdown says which rule module to look
        // at, and that is the difference between a fact and an action.
        let mut by_label: Vec<(&'static str, usize)> = Vec::new();

        for file in CORPUS {
            for line in file.lines().filter(|line| !line.trim().is_empty()) {
                let body = document_text(line).expect("fixture line carries a text field");
                records += 1;
                let found = rules.detect(&body);
                let merged = union_widest(&body, &found).expect("L1 spans address the document");
                for candidate in &merged {
                    candidates += 1;
                    match route(candidate) {
                        Route::AutoMask(AutoMaskReason::ChecksumValidated) => checksum += 1,
                        Route::AutoMask(AutoMaskReason::DetectorAgreement) => agreement += 1,
                        Route::AutoMask(AutoMaskReason::HighConfidence) => confident += 1,
                        Route::Escalate => {
                            escalated += 1;
                            let name = candidate.span().label().as_str();
                            match by_label.iter_mut().find(|(key, _)| *key == name) {
                                Some((_, count)) => *count += 1,
                                None => by_label.push((name, 1)),
                            }
                        }
                    }
                }
            }
        }

        by_label.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(right.0)));
        let rate = escalated as f64 / candidates as f64;
        println!(
            "router: {records} records, {candidates} routed candidates\n  \
             auto-masked, checksum validated : {checksum}\n  \
             auto-masked, detector agreement : {agreement}\n  \
             auto-masked, high confidence    : {confident}\n  \
             escalated to adjudication       : {escalated} ({:.1}%)",
            rate * 100.0
        );
        for (name, count) in &by_label {
            println!("  escalated {name:<12} : {count}");
        }

        assert!(records >= 100, "the corpus did not load");
        assert!(candidates > 100, "L1 proposed nothing over the corpus");
        // Reported, not gated, and deliberately so. The measured rate is far
        // above the 2-5% the brief assumed (D-027), and the honest response to
        // that is an ADR correcting the claim -- not an assertion here that
        // would either fail the build for reporting a true number or invite
        // someone to move ESCALATION_CONFIDENCE_MAX until the number looked
        // right, which is tuning a metric rather than measuring one.
    }
}

#[cfg(test)]
mod collision_tests {
    //! THE HIGHEST-VALUE TESTS IN THIS LAYER.
    //!
    //! Every collision ADR D-010 names, in BOTH directions, inside ONE
    //! document -- because a rule that masks `Costa` everywhere passes the
    //! surname half and fails the anatomy half, a rule that keeps it everywhere
    //! does the reverse, and only a context-sensitive rule passes both at once
    //! on the same text.
    //!
    //! The document is synthetic and contains no identifier of any kind (I8).

    use super::allowlist::MedicalAllowlist;
    use super::router::route_all;
    use super::vocabulary::bundled as bundled_allowlist;
    use crate::label::EntityLabel;
    use crate::span::{Decision, DetectorId, Merged, Span};

    /// Synthetic. Each colliding surface form appears as a person AND as
    /// vocabulary, in the registers the real fixtures use.
    const DOC: &str = "\
GÖĞÜS CERRAHİSİ KONSÜLTASYON NOTU
Hasta Adı: Deva Ergüven
Konsültan: Op. Dr. Andrea Costa

Anamnez: Deva Hanım, iki haftadır devam eden öksürük ile başvurdu. Eczaneden \
aldığı Deva marka parasetamol preparatını kullanmış. Hipertansiyon nedeniyle \
dış merkezde Adalat CR 30 mg başlanmış; Adalat Crono tedavisi düzenlendi.

Tetkikler: Toraks BT'de sol 4. ve 5. costa'da deplase olmayan fraktür, costa 6 \
düzeyinde fissür izlendi. Costa fraktürlerine eşlik eden pnömotoraks yok.

Sonuç: Analjezi önerildi. Dr. Costa tarafından değerlendirildi. Refakatçi \
Adalet Sarıkaya bilgilendirildi.";

    /// A single-source, low-confidence NER proposal -- the only kind of span
    /// L4 is ever allowed to demote.
    fn lone_guess(needle: &str, occurrence: usize, label: EntityLabel) -> Merged {
        let start = nth_occurrence(needle, occurrence);
        Merged::single(
            Span::new(
                DOC,
                start,
                start + needle.len(),
                label,
                DetectorId::Ner(0),
                0.35,
            )
            .expect("valid span"),
        )
    }

    fn nth_occurrence(needle: &str, occurrence: usize) -> usize {
        DOC.match_indices(needle)
            .nth(occurrence - 1)
            .unwrap_or_else(|| panic!("fixture must contain occurrence {occurrence} of the needle"))
            .0
    }

    fn decide(needle: &str, occurrence: usize, label: EntityLabel) -> Decision {
        decide_with(bundled_allowlist(), needle, occurrence, label)
    }

    fn decide_with(
        allowlist: &MedicalAllowlist,
        needle: &str,
        occurrence: usize,
        label: EntityLabel,
    ) -> Decision {
        let candidate = lone_guess(needle, occurrence, label);
        let (routed, _) = route_all(DOC, &[candidate], allowlist, None).expect("route");
        routed[0].decision
    }

    #[test]
    fn costa_the_surname_is_masked_and_costa_the_rib_is_kept() {
        // `Op. Dr. Andrea Costa` -- a title two tokens back.
        assert_eq!(
            decide("Costa", 1, EntityLabel::ClinicianName),
            Decision::Mask
        );
        // `Dr. Costa tarafından` -- a title directly before.
        assert_eq!(
            decide("Costa", 3, EntityLabel::ClinicianName),
            Decision::Mask
        );
        // `costa'da`, `costa 6` -- anatomy, lower case, no person context.
        assert_eq!(decide("costa", 1, EntityLabel::PatientName), Decision::Keep);
        assert_eq!(decide("costa", 2, EntityLabel::PatientName), Decision::Keep);
        // `Costa fraktürlerine` -- capitalised only because it opens a
        // sentence, which carries no information about ribs versus surgeons.
        assert_eq!(decide("Costa", 2, EntityLabel::PatientName), Decision::Keep);
    }

    #[test]
    fn deva_the_given_name_is_masked_and_deva_the_brand_is_kept() {
        // `Hasta Adı: Deva Ergüven` -- a name-bearing field.
        assert_eq!(decide("Deva", 1, EntityLabel::PatientName), Decision::Mask);
        // `Deva Hanım` -- a trailing honorific.
        assert_eq!(decide("Deva", 2, EntityLabel::PatientName), Decision::Mask);
        // `Deva marka parasetamol` -- a brand, followed by a common noun.
        assert_eq!(decide("Deva", 3, EntityLabel::PatientName), Decision::Keep);
    }

    #[test]
    fn adalat_the_drug_is_kept_and_adalet_the_given_name_is_masked() {
        // `Adalat CR` -- the neighbour is an all-caps formulation code, not a
        // surname, so nothing escalates.
        assert_eq!(
            decide("Adalat", 1, EntityLabel::PatientName),
            Decision::Keep
        );
        // `Adalat Crono` -- the neighbour is the rest of the drug name.
        assert_eq!(
            decide("Adalat", 2, EntityLabel::PatientName),
            Decision::Keep
        );
        // `Adalet Sarıkaya` differs from the drug by one vowel the Turkish
        // fold does not touch, so it is not vocabulary and is masked.
        assert_eq!(
            decide("Adalet", 1, EntityLabel::PatientName),
            Decision::Mask
        );
    }

    #[test]
    fn the_deterministic_keep_rule_this_replaces_would_leak_all_three_names() {
        // The DEFECT, stated as a test. Under D-010's original rule -- an
        // allowlist hit is a deterministic Keep -- every one of these surfaces
        // is on the allowlist, so all three would have been kept and leaked.
        let allowlist = bundled_allowlist();
        for (needle, occurrence) in [("Costa", 1), ("Costa", 3), ("Deva", 1), ("Deva", 2)] {
            let start = nth_occurrence(needle, occurrence);
            let surface = &DOC[start..start + needle.len()];
            assert!(
                allowlist.contains(surface),
                "{surface} must collide with the vocabulary or this test is vacuous"
            );
            assert_eq!(
                decide_with(allowlist, needle, occurrence, EntityLabel::PatientName),
                Decision::Mask,
                "an allowlist collision leaked a person at occurrence {occurrence} of {needle}"
            );
        }
    }

    #[test]
    fn a_protected_span_over_a_vocabulary_term_is_still_never_demoted() {
        // The guardrail, at the end of the real path: two distinct detectors
        // agreeing on `costa` outranks the allowlist entirely.
        let start = nth_occurrence("costa", 1);
        let from = |detector| {
            Span::new(
                DOC,
                start,
                start + "costa".len(),
                EntityLabel::PatientName,
                detector,
                0.1,
            )
            .expect("valid span")
        };
        let merged =
            crate::span::union_widest(DOC, &[from(DetectorId::Ner(0)), from(DetectorId::Ner(1))])
                .expect("merge");
        let (routed, stats) = route_all(DOC, &merged, bundled_allowlist(), None).expect("route");
        assert_eq!(routed[0].decision, Decision::Mask);
        assert_eq!(stats.escalated, 0);
        assert_eq!(stats.demoted, 0);
    }

    #[test]
    fn every_decision_in_the_document_is_mask_or_a_justified_keep() {
        // Sweeps every colliding surface at once and reports the routing stats,
        // so the cost bound is exercised on a realistically dense document
        // rather than only on single spans.
        let allowlist = bundled_allowlist();
        let candidates: Vec<_> = [
            ("Deva", 1),
            ("Deva", 2),
            ("Deva", 3),
            ("Costa", 1),
            ("Costa", 2),
            ("Costa", 3),
            ("costa", 1),
            ("costa", 2),
            ("Adalat", 1),
            ("Adalat", 2),
            ("Adalet", 1),
        ]
        .into_iter()
        .map(|(needle, occurrence)| lone_guess(needle, occurrence, EntityLabel::PatientName))
        .collect();

        let (routed, stats) = route_all(DOC, &candidates, allowlist, None).expect("route");
        assert_eq!(
            routed.len(),
            candidates.len(),
            "L4 invented or dropped a span"
        );
        // Every candidate is a lone low-confidence guess, so all of them
        // escalate: this document is the pathological case for the cost bound,
        // not a sample of it.
        assert_eq!(stats.escalated, candidates.len());
        assert_eq!(stats.demoted, 6, "the six vocabulary readings must be kept");
    }
}
