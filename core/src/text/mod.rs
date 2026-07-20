//! Unicode hardening: the text a matcher sees, and the index back to the bytes.
//!
//! Four evasions live in this module, and all four are the same evasion wearing
//! different clothes: **write an identifier so that it reads correctly to a
//! human and does not compare equal to what the matcher is looking for.**
//!
//! | Written as | Defeats | Handled by |
//! |---|---|---|
//! | fullwidth or Arabic-Indic digits | `[0-9]{11}` | [`digits`] |
//! | split by a zero-width joiner or soft hyphen | any contiguous match | [`invisible`] |
//! | a Cyrillic or Greek homoglyph | exact string equality | [`confusables`] |
//! | wrapped in a bidi override | the stored order is not the read order | [`invisible`] |
//!
//! [`normalize`] composes the four into ONE pass over ONE index, which is the
//! only arrangement that is safe: two passes mean two offset maps, and two
//! offset maps that stack silently instead of composing is the bug class this
//! whole module exists inside.
//!
//! # Who calls this
//!
//! L1, and L4's allowlist. `core/src/rules/mod.rs`'s `Doc` -- the buffer every
//! rule module matches against and the index every L1 span is re-anchored
//! through -- IS a [`Skeleton`] at [`Fold::Skeleton`], which is what makes the
//! table above a statement of what is ENFORCED rather than of what is
//! available. `route::allowlist::MedicalAllowlist::lookup` calls
//! [`is_mixed_script`] to refuse a `Keep` to a disguised term. Nothing else in
//! the crate normalises text for matching; a second normaliser stacked on this
//! one would compose two offset maps by accident, which is the failure the
//! single index prevents.
//!
//! The remaining public items -- [`Fold::Compose`],
//! [`Skeleton::original_slice`], [`invisible::contains_invisible`] and
//! [`invisible::contains_bidi_control`] -- are SIGNALS AND BUILDING BLOCKS
//! offered to bindings, not controls this crate enforces anywhere. Nothing in
//! the pipeline consults them today, and no doc string here may imply it does.
//!
//! # The rule every caller is bound by
//!
//! The folded buffer is FOR MATCHING. It is never emitted, never persisted,
//! never hashed into a [`Span`](crate::span::Span). A match found in it is
//! mapped back to ORIGINAL byte offsets with
//! [`Skeleton::original_range`](normalize::Skeleton::original_range) IMMEDIATELY,
//! and the span is constructed against the original text. A `Span` that briefly
//! holds skeleton offsets is a `Span` that will eventually be sliced out of the
//! original document, and the two strings agree on nothing.
//!
//! This is also why the module does not offer a "clean the document" function.
//! Stripping zero-width characters out of a clinical note is an unrequested edit
//! to a medical record, and it would break the round-trip property
//! `DeidResult::reidentify` depends on.
//!
//! # Turkish safety
//!
//! The pass only ever COMPOSES; it never decomposes, never applies NFKC as a
//! blanket transform, and never case-folds. `İ` U+0130 decomposes under NFD to
//! `I` + U+0307 and `ı` U+0131 does not decompose at all, so any decomposing
//! step followed by any mark-dropping step collapses two of Turkish's four `i`
//! letters into one. [`normalize`] and [`confusables`] each carry the argument
//! in full, and each carries the test that fails if the direction is reversed.
//!
//! # What this does and does not buy, stated exactly
//!
//! It closes these evasions for the identifiers **L1 can prove** -- TCKN, VKN,
//! IBAN, SGK, phone, email, MRN, date -- and for the class C medical allowlist.
//!
//! It does NOT make the pipeline detect names. `deid-tr` masks zero person
//! names today: L2 has no trained model, `Pipeline::new` installs an empty
//! ensemble, and `pipeline.rs::the_rules_layer_is_live_in_the_safe_harbor_path`
//! asserts in-tree that `Ayşe Yılmaz` survives a Safe Harbor run. Folding a
//! Cyrillic homoglyph out of `Аyşe` yields a clean `Ayşe` that nothing is
//! currently looking for. The fold is the precondition for a gazetteer or a
//! checkpoint to work at all; it is not itself a detector, and no comment, doc
//! string or UI text built on this module may imply otherwise.

pub mod confusables;
pub mod digits;
pub mod invisible;
pub mod normalize;

pub use confusables::{is_mixed_script, Script};
pub use normalize::{Fold, Skeleton};

/// The adversarial suite: one test per evasion, each proving the identifier is
/// still found AND that the span lands on correct ORIGINAL byte offsets.
///
/// WHY IT LIVES HERE and not beside each table: every one of these is an
/// end-to-end claim across [`normalize`], [`digits`], [`invisible`],
/// [`confusables`] and L1. A test filed under one of those modules would be
/// asserting a property none of them owns alone, and the property that matters
/// -- "the evasion is closed all the way to a span" -- is exactly the one that
/// falls through the gaps between unit tests.
#[cfg(test)]
mod adversarial {
    use super::normalize::{Fold, Skeleton};
    use super::{confusables, invisible};
    use crate::label::EntityLabel;
    use crate::rules::RuleSet;
    use crate::span::Span;

    /// Run the LIVE L1 path.
    ///
    /// A one-line indirection kept for the name: every case below is a claim
    /// about what the shipping pipeline detects, not about what this module
    /// could detect if something called it. `RuleSet::detect` builds its `Doc`
    /// on a `Skeleton`, so the fold and the re-anchoring are both already
    /// inside it -- including the checksum flag, which is set by the module
    /// that ran the arithmetic and is therefore carried rather than re-derived.
    fn detect_over_skeleton(doc: &str) -> Vec<Span> {
        RuleSet.detect(doc)
    }

    /// Every span must be sliceable out of the ORIGINAL on character boundaries.
    ///
    /// Asserted on every case rather than only where it is likely to break: an
    /// offset that lands inside a `ş` is the failure this module was written to
    /// make impossible, so it is checked wherever a span is produced.
    fn assert_anchored(doc: &str, spans: &[Span]) {
        for span in spans {
            assert!(
                doc.is_char_boundary(span.start()),
                "span start {} is inside a character",
                span.start()
            );
            assert!(
                doc.is_char_boundary(span.end()),
                "span end {} is inside a character",
                span.end()
            );
            assert!(span.end() <= doc.len());
            assert!(doc.get(span.start()..span.end()).is_some());
        }
    }

    /// Rewrite ASCII digits into another decimal system.
    fn in_system(digits: &str, base: u32) -> String {
        digits
            .chars()
            .map(|c| {
                c.to_digit(10)
                    .and_then(|d| char::from_u32(base + d))
                    .unwrap_or(c)
            })
            .collect()
    }

    fn tckn_of(doc: &str, spans: &[Span]) -> String {
        let span = spans
            .iter()
            .find(|s| s.label() == EntityLabel::Tckn)
            .expect("the TCKN must survive the evasion");
        assert!(
            span.is_checksum_validated(),
            "the checksum flag must be carried through the re-anchoring, \
             or L4 may demote a national ID"
        );
        doc[span.start()..span.end()].to_owned()
    }

    #[test]
    fn a_checksum_valid_tckn_written_in_fullwidth_digits_is_still_detected() {
        // Built at run time; a checksum-valid national ID is never a literal in
        // a committed file (I8).
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let wide = in_system(&tckn, 0xFF10);
        let doc = format!("Hasta Ayşe Yılmaz, T.C. Kimlik No: {wide} olarak kayıtlı.");

        let spans = detect_over_skeleton(&doc);
        assert_anchored(&doc, &spans);
        assert_eq!(
            tckn_of(&doc, &spans),
            wide,
            "the span must cover the ORIGINAL fullwidth digits, not the folded copy"
        );
        // Three bytes per fullwidth digit: if the span were anchored to the
        // skeleton it would be 11 bytes long and would end mid-character.
        assert_eq!(wide.len(), 33);
    }

    #[test]
    fn a_tckn_split_by_a_zero_width_joiner_is_still_detected() {
        // The evasion that used to reach L4 as nothing at all: before `Doc` was
        // backed by a `Skeleton` it folded digits and not zero-width
        // characters, so this run was 3 digits and 8 digits and matched nothing.
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let split = format!(
            "{}\u{200D}{}\u{00AD}{}",
            &tckn[..3],
            &tckn[3..7],
            &tckn[7..]
        );
        let doc = format!("T.C. Kimlik No: {split}\nDoğum: 12.03.1968");

        let spans = detect_over_skeleton(&doc);
        assert_anchored(&doc, &spans);
        assert_eq!(
            tckn_of(&doc, &spans),
            split,
            "the span must cover the original bytes INCLUDING the interior \
             zero-width characters, which is what L5 has to replace"
        );
        assert!(invisible::contains_invisible(&doc));
    }

    #[test]
    fn a_tckn_wrapped_in_a_bidi_override_is_still_detected_and_flagged() {
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let doc = format!("Kimlik: \u{202E}{tckn}\u{202C} kaydı açıldı.");

        let spans = detect_over_skeleton(&doc);
        assert_anchored(&doc, &spans);
        assert_eq!(
            tckn_of(&doc, &spans),
            tckn,
            "the override characters sit at the edges of the run and must stay \
             OUTSIDE the span"
        );
        // The bidi control is reported as its own signal. A soft hyphen in a
        // note is formatting; an RLO in a Turkish clinical note is not.
        assert!(invisible::contains_bidi_control(&doc));
    }

    #[test]
    fn a_tckn_written_in_arabic_indic_digits_inside_turkish_text_is_still_detected() {
        // Multi-byte Turkish BEFORE the identifier, so an implementation that
        // counted characters instead of bytes lands short and inside a letter.
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let written = in_system(&tckn, 0x0660);
        let doc = format!("Şükrü Gökçe'nin İş yeri kaydı, kimlik {written} ile eşleşti.");

        let spans = detect_over_skeleton(&doc);
        assert_anchored(&doc, &spans);
        assert_eq!(tckn_of(&doc, &spans), written);
    }

    #[test]
    fn a_turkish_name_with_a_cyrillic_homoglyph_folds_onto_its_plain_form() {
        // HONEST SCOPE, and the reason this test asserts a fold rather than a
        // mask: deid-tr detects ZERO person names today. L2 has no trained
        // model and L1 does not guess at names, so nothing in the pipeline is
        // looking for `Ayşe` in any spelling. What this module can prove -- and
        // all it can prove -- is that the homoglyph no longer hides the name
        // from whatever does the looking, and that the offsets come back exact.
        const PLAIN: &str = "Ayşe Yılmaz";
        // Only the `А` is a homoglyph: the `ı` in `Yılmaz` is the genuine
        // Turkish dotless i, and it must come through the fold untouched.
        const DOC: &str = "Hasta Adı: \u{0410}yşe Yılmaz\nServis: Kardiyoloji";
        let doc = DOC.to_owned();
        let skeleton = Skeleton::new(&doc, Fold::Skeleton);

        let start = skeleton
            .text()
            .find(PLAIN)
            .expect("the homoglyph must fold onto the plain form");
        let (from, to) = skeleton
            .original_range(start, start + PLAIN.len())
            .expect("the folded name maps back");
        assert_eq!(&doc[from..to], "\u{0410}yşe Y\u{0131}lmaz");
        assert!(doc.is_char_boundary(from) && doc.is_char_boundary(to));
        assert!(
            !doc.contains(PLAIN),
            "the fixture must not contain the plain form"
        );

        // The mirror-image signal, which runs the other way: the token is Latin
        // with one Cyrillic letter, which is an anomaly whatever it matches. It
        // escalates to L4 and must never earn an allowlist `Keep` (I2).
        assert!(confusables::is_mixed_script("\u{0410}yşe"));

        // And the honest part, recorded so the boundary cannot rot: the Safe
        // Harbor pipeline masks neither spelling.
        let masked = crate::pipeline::Pipeline::new(crate::pipeline::Tier::SafeHarbor)
            .deidentify(&doc)
            .expect("safe harbor run");
        assert_eq!(
            masked.text, doc,
            "no name is masked, in either spelling, because L2 has no model"
        );
    }

    #[test]
    fn a_name_wrapped_in_bidi_overrides_folds_onto_its_plain_form() {
        const PLAIN: &str = "Şükrü Gökçe";
        let doc = format!("Konsültasyon: Uz. Dr. \u{202D}{PLAIN}\u{202C}, dahiliye.");
        let skeleton = Skeleton::new(&doc, Fold::Skeleton);

        let start = skeleton
            .text()
            .find(PLAIN)
            .expect("the overrides must not hide the name from the matcher");
        let (from, to) = skeleton
            .original_range(start, start + PLAIN.len())
            .expect("the folded name maps back");
        assert_eq!(
            &doc[from..to],
            PLAIN,
            "the overrides sit at the edges and must stay outside the range"
        );
        assert!(doc.is_char_boundary(from) && doc.is_char_boundary(to));
        assert!(invisible::contains_bidi_control(&doc));

        // Same honest boundary as above: nothing masks a name today.
        let masked = crate::pipeline::Pipeline::new(crate::pipeline::Tier::SafeHarbor)
            .deidentify(&doc)
            .expect("safe harbor run");
        assert_eq!(masked.text, doc);
    }

    #[test]
    fn a_medical_term_written_with_a_homoglyph_is_not_thereby_allowlisted() {
        // The asymmetry L4 must respect. `carcinom` + Cyrillic `а` folds to
        // `carcinoma`, which IS on the allowlist -- so the fold alone would hand
        // an attacker a deterministic `Keep` for any string they can disguise as
        // a medical term. Mixed script makes the token ineligible for the
        // allowlist short-circuit; it escalates instead. Recall never loses to
        // the allowlist (I2).
        const DISGUISED: &str = "carcinom\u{0430}";
        let skeleton = Skeleton::new(DISGUISED, Fold::Skeleton);
        assert_eq!(skeleton.text(), "carcinoma");
        assert!(
            confusables::is_mixed_script(DISGUISED),
            "a disguised term must be flagged as mixed-script, or the fold is a \
             precision gift to an attacker"
        );
        // The genuine term is not mixed-script and keeps its protection.
        assert!(!confusables::is_mixed_script("carcinoma"));
    }

    #[test]
    fn an_identifier_hidden_by_several_evasions_at_once_is_still_detected() {
        // The combination, because the individual defences composing is the
        // claim the module makes and defences that each work alone routinely
        // fail together.
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        let wide = in_system(&tckn, 0xFF10);
        let wide: Vec<char> = wide.chars().collect();
        let mut hidden = String::from("\u{202E}");
        for (index, digit) in wide.iter().enumerate() {
            hidden.push(*digit);
            if index == 4 {
                hidden.push('\u{200B}');
            }
            if index == 7 {
                hidden.push('\u{00AD}');
            }
        }
        hidden.push('\u{202C}');
        let doc = format!("Hasta Ayşe Yılmaz — T.C. Kimlik No: {hidden}\nTaburcu edildi.");

        let spans = detect_over_skeleton(&doc);
        assert_anchored(&doc, &spans);
        let covered = tckn_of(&doc, &spans);
        assert!(
            covered.contains('\u{200B}') && covered.contains('\u{00AD}'),
            "interior invisible characters belong inside the span, or L5 leaves \
             fragments of the identifier in the output"
        );
        assert!(
            !covered.starts_with('\u{202E}') && !covered.ends_with('\u{202C}'),
            "the bidi wrapper is outside the identifier and must stay outside it"
        );
    }

    #[test]
    fn hardening_does_not_invent_identifiers_in_a_clean_note() {
        // The precision side. A fold that manufactured a match would be a
        // masking bug that destroys the note, and the cheapest way for one to
        // arrive is a confusable table that maps a Turkish letter onto a digit.
        const CLEAN: &str = "Hasta Ayşe Yılmaz, İzmir'de yaşıyor. carcinoma'lı akciğer \
                             grafisi Dr. Şükrü Gökçe tarafından okundu. MRI'da özellik yok.";
        let hardened = detect_over_skeleton(CLEAN);
        assert!(
            hardened.is_empty(),
            "the fold manufactured an identifier in a note that has none"
        );
        assert_anchored(CLEAN, &hardened);
    }
}
