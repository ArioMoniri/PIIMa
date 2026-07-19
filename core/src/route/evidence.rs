//! Does the surrounding text independently mark this span as a PERSON?
//!
//! This module is the whole content of the D-010 resolution. The old rule was
//! "check the allowlist first, and an allowlist hit is a deterministic Keep".
//! That rule leaks, because a NAME is neither checksum-validatable nor
//! guaranteed to be seen by more than one model: a single-model span over
//! `Costa`, `Deva` or `Adalat` collides with real vocabulary and is silently
//! suppressed. Recall loses to precision, which I2 forbids.
//!
//! So an allowlist entry may demote a span ONLY when the surrounding evidence
//! does not independently mark it as a person. This module weighs that
//! evidence. It is HEURISTIC and it is graded, not boolean: decisive signals
//! settle the question, suggestive ones send the span to the adjudicator rather
//! than short-circuiting either way.
//!
//! Every signal reads the ORIGINAL document at BYTE offsets. Nothing here
//! copies covered text into an error, a log or a `Debug` rendering (I4).

use crate::route::allowlist::{is_word_char, turkish_casefold, MedicalAllowlist, APOSTROPHES};

/// Turkish clinical titles, casefolded, longest first.
///
/// The highest-yield name signal the language has: a title followed by a
/// capitalised token is a person, essentially without exception, and no
/// medical term is ever preceded by one. `Op.` and `Uz.` appear alone in older
/// dictation as well as in the `Op. Dr.` compound, so both are listed.
const TITLES: &[&str] = &[
    "yrd. doç. dr.",
    "prof. dr.",
    "doç. dr.",
    "uzm. dr.",
    "uz. dr.",
    "op. dr.",
    "hemşire",
    "hemş.",
    "prof.",
    "doç.",
    "uzm.",
    "uz.",
    "op.",
    "dr.",
];

/// Honorifics that FOLLOW a personal name.
///
/// `Deva Hanım` and `Adalet Hanım` are the exact corpus collisions: the word
/// after the span is what distinguishes a woman from a pharmaceutical brand.
const HONORIFICS: &[&str] = &[
    "bey",
    "hanım",
    "beyefendi",
    "hanımefendi",
    "hoca",
    "hocam",
    "abla",
    "amca",
    "teyze",
];

/// Field labels whose value position holds a person's name.
///
/// Turkish clinical notes are heavily form-shaped, so position in a
/// name-bearing field is close to a declaration. Compared casefolded, against
/// the text immediately before the `:` that opens the value.
const NAME_FIELDS: &[&str] = &[
    "hasta adı soyadı",
    "hasta adı",
    "adı soyadı",
    "ad soyad",
    "hasta",
    "doktor",
    "hekim",
    "sorumlu hekim",
    "konsültan",
    "konsultan",
    "operatör",
    "cerrah",
    "anne adı",
    "baba adı",
    "refakatçi",
    "hasta yakını",
    "yakını",
    "raporu veren",
    "istem yapan",
];

/// Genitive endings that mark a possessor, which in clinical prose is a person
/// far more often than a term.
///
/// Deliberately NOT the locative (`-da/-de`): `costa'da fraktür` is the
/// commonest anatomical form in the corpus, and treating it as a person signal
/// would escalate every rib in every trauma note.
const PERSON_CASE_SUFFIXES: &[&str] = &["ın", "in", "un", "ün", "nın", "nin", "nun", "nün"];

/// One reason to believe the span names a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersonSignal {
    /// A Turkish title precedes the span, possibly across a given name.
    TitlePrefix,
    /// An honorific (`Bey`, `Hanım`) follows the span.
    Honorific,
    /// The span sits in the value position of a name-bearing field.
    NameField,
    /// An adjacent capitalised token forms a plausible given-name plus
    /// surname pair.
    CapitalisedNeighbour,
    /// The surface is capitalised where its allowlist entry is lower case, and
    /// not because it opens a sentence.
    CasingMismatch,
    /// The span carries a genitive suffix typical of a person reference.
    PersonCaseSuffix,
}

impl PersonSignal {
    /// True when this signal alone settles the question.
    ///
    /// The three decisive signals are the ones no medical term produces: a
    /// title, a trailing honorific, and a name-bearing field. Everything else
    /// is real evidence that is also produced by ordinary prose, so it argues
    /// for escalation rather than for a verdict.
    #[must_use]
    pub const fn is_decisive(self) -> bool {
        matches!(self, Self::TitlePrefix | Self::Honorific | Self::NameField)
    }
}

/// How strongly the context marks the span as a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    /// Nothing in the context suggests a person. The allowlist may demote.
    Absent,
    /// Real but non-conclusive evidence. Escalate; never short-circuit.
    Suggestive,
    /// A title, an honorific or a name-bearing field. Mask.
    Decisive,
}

/// The collected reasons, in a stable order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonEvidence {
    signals: Vec<PersonSignal>,
}

impl PersonEvidence {
    /// The signals found, sorted and deduplicated.
    #[must_use]
    pub fn signals(&self) -> &[PersonSignal] {
        &self.signals
    }

    /// The graded verdict.
    #[must_use]
    pub fn assessment(&self) -> Assessment {
        if self.signals.iter().copied().any(PersonSignal::is_decisive) {
            Assessment::Decisive
        } else if self.signals.is_empty() {
            Assessment::Absent
        } else {
            Assessment::Suggestive
        }
    }

    fn push(&mut self, signal: PersonSignal) {
        if let Err(index) = self.signals.binary_search(&signal) {
            self.signals.insert(index, signal);
        }
    }

    /// Weigh the context around `text[start..end]`.
    ///
    /// `allowlist` is consulted for two things a bare string scan cannot know:
    /// the register an entry is normally written in, and whether the span plus
    /// its neighbour is itself a longer vocabulary term (`Adalat Crono`).
    #[must_use]
    pub fn gather(text: &str, start: usize, end: usize, allowlist: &MedicalAllowlist) -> Self {
        let mut evidence = Self::default();
        let Some(surface) = text.get(start..end) else {
            // An out-of-range span cannot be assessed. Returning no evidence
            // here would ARGUE FOR DEMOTION, so the caller is told nothing was
            // found and the caller's default is to mask.
            return evidence;
        };
        let prefix = line_prefix(text, start);

        if title_precedes(prefix) {
            evidence.push(PersonSignal::TitlePrefix);
        }
        if name_field_precedes(prefix) {
            evidence.push(PersonSignal::NameField);
        }
        let opens_line = line_prefix(text, start).trim().is_empty();
        if let Some(next) = next_token(text, end) {
            if is_honorific(next) {
                evidence.push(PersonSignal::Honorific);
            }
            // A line-opening capitalised token followed by another one is a
            // HEADING (`Triyaj Notu`, `Ameliyat Notu`, `Anestezi
            // Degerlendirmesi`), not a given-name plus surname pair: both
            // capitals are positional. Twenty-odd distinct section headings in
            // the corpus escalated on this before the guard.
            //
            // THE RESIDUAL, recorded rather than hidden: a person whose given
            // name is itself class C vocabulary, standing at the start of a
            // line with no title, no honorific and no field label -- a bare
            // signature line -- loses this one signal. It does not become
            // demotable on that account; it still has to be on the allowlist
            // and to produce no other signal. No such configuration occurs in
            // the corpus.
            if !opens_line && is_name_shaped(next) && !pair_is_vocabulary(surface, next, allowlist)
            {
                evidence.push(PersonSignal::CapitalisedNeighbour);
            }
        }
        if let Some((previous, previous_start)) = last_token(text, start) {
            // The preceding token must be capitalised BY CHOICE, not by
            // position. A given name before a surname sits mid-sentence;
            // `Bilinen hipertansiyon'u` and `Pretibial ödem saptanmadı` open
            // sentences, and reading their capital as a given name escalated
            // several hundred ordinary vocabulary occurrences in the corpus.
            if is_bare_word(previous)
                && is_name_shaped(previous)
                && !starts_sentence(text, previous_start)
                && !pair_is_vocabulary(previous, surface, allowlist)
            {
                evidence.push(PersonSignal::CapitalisedNeighbour);
            }
        }
        if casing_conflicts(text, start, surface, allowlist) {
            evidence.push(PersonSignal::CasingMismatch);
        }
        if carries_person_case_suffix(text, start, end) {
            evidence.push(PersonSignal::PersonCaseSuffix);
        }
        evidence
    }
}

/// Everything on the span's line, up to the span.
fn line_prefix(text: &str, start: usize) -> &str {
    let head = text.get(..start).unwrap_or("");
    match head.rfind('\n') {
        Some(newline) => &head[newline + 1..],
        None => head,
    }
}

/// The last whitespace-separated token before `start`, and where it begins.
///
/// The offset is returned rather than recomputed by the caller because the
/// preceding-neighbour rule has to ask whether THAT token opens a sentence, and
/// searching for it again would find the wrong occurrence in any note that
/// repeats a word -- which a clinical note does constantly.
fn last_token(text: &str, start: usize) -> Option<(&str, usize)> {
    let prefix = line_prefix(text, start);
    if !prefix.ends_with(|ch: char| ch.is_whitespace()) {
        return None;
    }
    let trimmed = prefix.trim_end();
    let token = trimmed.split_whitespace().next_back()?;
    Some((token, start - (prefix.len() - trimmed.len()) - token.len()))
}

/// The next whitespace-separated word token after `end`.
fn next_token(text: &str, end: usize) -> Option<&str> {
    let tail = text.get(end..)?;
    let trimmed = tail.trim_start_matches(|ch: char| ch.is_whitespace());
    if trimmed.len() == tail.len() {
        // No separator: the "next token" is the rest of the same word, which is
        // a suffix, not a neighbour.
        return None;
    }
    let token: &str = trimmed.split(|ch: char| !is_word_char(ch)).next()?;
    (!token.is_empty()).then_some(token)
}

/// True when the token carries no attached punctuation.
///
/// The guard on the PRECEDING neighbour, and it is load-bearing: `Tetkikler:`
/// and `Dr.` are both capitalised and both pass the name shape test, so
/// without it every field label and every title in the corpus counted as a
/// given name and escalated the term that followed it. A real given name in
/// running text carries no colon and no full stop.
fn is_bare_word(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|ch| ch.is_alphanumeric() || APOSTROPHES.contains(ch))
}

/// True when the token could be a Turkish given name or surname.
///
/// Requires an initial capital AND a following lower-case letter: `CR`, `USG`
/// and `BT` are abbreviations, not names, and treating an all-caps neighbour
/// as a surname would escalate every `Adalat CR` in the corpus. Two letters is
/// too short to be a name and is almost always a unit or an abbreviation.
fn is_name_shaped(token: &str) -> bool {
    // Judge the ROOT, before any Turkish suffix. `BT'de` is an abbreviation
    // carrying a locative, and reading its suffix as the lower-case tail of a
    // name made every `Toraks BT'de costa ...` in the corpus escalate.
    // `Yılmaz'ın` still qualifies, because its root does.
    let root = token
        .split(|ch: char| APOSTROPHES.contains(ch))
        .next()
        .unwrap_or(token);
    let core = root.trim_matches(|ch: char| !ch.is_alphanumeric());
    let mut chars = core.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_uppercase() && core.chars().count() >= 3 && chars.any(char::is_lowercase)
}

/// True when the two tokens together are themselves a vocabulary term.
///
/// `Adalat Crono` is one drug, so `Crono` is not a surname argument. Without
/// this the longest entry in the drug file would defeat its own shorter form.
fn pair_is_vocabulary(left: &str, right: &str, allowlist: &MedicalAllowlist) -> bool {
    let mut pair = String::with_capacity(left.len() + right.len() + 1);
    pair.push_str(left);
    pair.push(' ');
    pair.push_str(right);
    allowlist.contains(&pair)
}

/// True when the token is a post-nominal honorific, suffix and all.
fn is_honorific(token: &str) -> bool {
    let folded = turkish_casefold(token);
    let root = folded
        .split(|ch: char| APOSTROPHES.contains(ch))
        .next()
        .unwrap_or(&folded);
    HONORIFICS.contains(&root)
}

/// True when a Turkish title opens the name this span belongs to.
///
/// Looks back across up to two capitalised tokens, because the title attaches
/// to the GIVEN name and the colliding span is usually the surname:
/// `Op. Dr. Andrea Costa` must find `Op. Dr.` from `Costa`, two tokens away.
fn title_precedes(prefix: &str) -> bool {
    let mut window = prefix;
    for _ in 0..3 {
        let folded = turkish_casefold(window.trim_end());
        if TITLES.iter().any(|title| folded.ends_with(title)) {
            return true;
        }
        match strip_trailing_name_token(window) {
            Some(shorter) => window = shorter,
            None => return false,
        }
    }
    false
}

/// True when the span sits in the value position of a name-bearing field.
fn name_field_precedes(prefix: &str) -> bool {
    let mut window = prefix;
    for _ in 0..3 {
        let trimmed = window.trim_end();
        if let Some(label) = trimmed.strip_suffix(':') {
            let folded = turkish_casefold(label.trim());
            // Suffix match, not equality: the label may be preceded by other
            // text on the same line, as in `Konsültan Hekim:`.
            if NAME_FIELDS.iter().any(|field| folded.ends_with(field)) {
                return true;
            }
            return false;
        }
        match strip_trailing_name_token(window) {
            Some(shorter) => window = shorter,
            None => return false,
        }
    }
    false
}

/// Drop one trailing capitalised token, so the scan can look further back.
fn strip_trailing_name_token(window: &str) -> Option<&str> {
    let trimmed = window.trim_end();
    let boundary = trimmed
        .char_indices()
        .rev()
        .find(|(_, ch)| !is_word_char(*ch))
        .map_or(0, |(index, ch)| index + ch.len_utf8());
    let token = &trimmed[boundary..];
    is_name_shaped(token).then(|| &trimmed[..boundary])
}

/// True when the surface is capitalised but its vocabulary entry is not, and
/// the capital is not simply sentence-initial.
///
/// Sentence position is checked FIRST because it is the dominant source of
/// false alarms: `Costa fraktürlerine eşlik eden...` opens a sentence, so the
/// capital carries no information about whether it is a rib or a surgeon.
fn casing_conflicts(text: &str, start: usize, surface: &str, allowlist: &MedicalAllowlist) -> bool {
    if starts_sentence(text, start) {
        return false;
    }
    let capitalised = surface.chars().next().is_some_and(char::is_uppercase);
    capitalised
        && allowlist
            .lookup(surface)
            .iter()
            .any(super::allowlist::AllowlistEntry::is_lowercase_register)
}

/// True when `start` opens a sentence, a line or the document.
///
/// The line case is checked FIRST and separately, because trimming trailing
/// whitespace off the preceding text eats the newline along with it and then
/// reports the last letter of the previous line. Section headings and field
/// labels all open lines, so getting this wrong made every title-cased heading
/// in the corpus look like a deliberate mid-sentence capital.
fn starts_sentence(text: &str, start: usize) -> bool {
    if line_prefix(text, start).trim().is_empty() {
        return true;
    }
    let head = text.get(..start).unwrap_or("");
    match head.trim_end().chars().next_back() {
        None => true,
        Some(ch) => matches!(ch, '.' | '!' | '?' | ':' | ';' | '('),
    }
}

/// True when the span is immediately followed by an apostrophe plus a genitive.
fn carries_person_case_suffix(text: &str, start: usize, end: usize) -> bool {
    // Two places the suffix can sit: inside the span, when the detector
    // swallowed it, or immediately after, when it did not.
    let inside = text.get(start..end).unwrap_or("");
    // The trailing region is the bytes IMMEDIATELY after the span, and the
    // apostrophe has to be the very first of them. Scanning the whole rest of
    // the document for one found the next suffixed word anywhere downstream:
    // `metformin` matched the genitive on a name four sentences later, which
    // escalated most of the drug vocabulary in the corpus.
    let after = text.get(end..).unwrap_or("");
    suffix_after_apostrophe(inside).is_some_and(is_person_case)
        || after
            .chars()
            .next()
            .is_some_and(|ch| APOSTROPHES.contains(ch))
            && suffix_after_apostrophe(after).is_some_and(is_person_case)
}

fn suffix_after_apostrophe(region: &str) -> Option<&str> {
    let index = region.find(|ch: char| APOSTROPHES.contains(ch))?;
    let ch = region[index..].chars().next()?;
    let tail = &region[index + ch.len_utf8()..];
    let end = tail
        .char_indices()
        .find(|(_, c)| !is_word_char(*c))
        .map_or(tail.len(), |(offset, _)| offset);
    Some(&tail[..end])
}

fn is_person_case(suffix: &str) -> bool {
    let folded = turkish_casefold(suffix);
    PERSON_CASE_SUFFIXES.contains(&folded.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::allowlist::AllowlistCategory;

    fn vocabulary() -> MedicalAllowlist {
        MedicalAllowlist::from_sources(&[
            (AllowlistCategory::Anatomy, "costa\ncostae\n"),
            (AllowlistCategory::Drug, "Adalat\nAdalat Crono\nDeva\n"),
        ])
    }

    fn assess(text: &str, needle: &str) -> Assessment {
        let start = text.find(needle).expect("fixture contains the needle");
        PersonEvidence::gather(text, start, start + needle.len(), &vocabulary()).assessment()
    }

    fn signals(text: &str, needle: &str) -> Vec<PersonSignal> {
        let start = text.find(needle).expect("fixture contains the needle");
        PersonEvidence::gather(text, start, start + needle.len(), &vocabulary())
            .signals()
            .to_vec()
    }

    #[test]
    fn a_title_two_tokens_back_still_marks_the_surname() {
        let text = "Konsültan: Op. Dr. Andrea Costa\n";
        assert!(signals(text, "Costa").contains(&PersonSignal::TitlePrefix));
        assert_eq!(assess(text, "Costa"), Assessment::Decisive);
    }

    #[test]
    fn a_title_directly_before_the_span_marks_it() {
        let text = "Analjezi önerildi. Dr. Costa tarafından değerlendirildi.";
        assert!(signals(text, "Costa").contains(&PersonSignal::TitlePrefix));
    }

    #[test]
    fn every_turkish_title_form_is_recognised() {
        for title in ["Dr.", "Op. Dr.", "Prof. Dr.", "Uz. Dr.", "Hemş."] {
            let text = format!("Muayene: {title} Costa notu girdi.");
            assert!(
                title_precedes(&text[..text.find("Costa").expect("fixture")]),
                "title {title} was not recognised"
            );
        }
    }

    #[test]
    fn an_honorific_after_the_span_marks_it() {
        let text = "Anamnez: Deva Hanım, iki haftadır öksürüyor.";
        assert!(signals(text, "Deva").contains(&PersonSignal::Honorific));
        assert_eq!(assess(text, "Deva"), Assessment::Decisive);
        // The honorific may itself be inflected.
        let possessive = "Adalat Hanım'ın reçetesi";
        assert!(is_honorific(next_token(possessive, 6).expect("token")));
    }

    #[test]
    fn a_name_bearing_field_marks_the_value() {
        let text = "Hasta Adı: Deva Ergüven\nProtokol No: 2026-0018806\n";
        assert!(signals(text, "Deva").contains(&PersonSignal::NameField));
        assert_eq!(assess(text, "Deva"), Assessment::Decisive);
    }

    #[test]
    fn a_field_that_does_not_bear_a_name_is_not_a_signal() {
        let text = "Sonuç/Plan: Adalat dozu 60 mg'a çıkarıldı.";
        assert!(!signals(text, "Adalat").contains(&PersonSignal::NameField));
        assert_eq!(assess(text, "Adalat"), Assessment::Absent);
    }

    #[test]
    fn a_capitalised_neighbour_is_suggestive_but_never_decisive() {
        let text = "İlaç kutularını refakatçi kızı Deva Çınar getirmiştir.";
        assert_eq!(
            signals(text, "Deva"),
            vec![PersonSignal::CapitalisedNeighbour]
        );
        assert_eq!(assess(text, "Deva"), Assessment::Suggestive);
    }

    #[test]
    fn an_all_caps_neighbour_is_an_abbreviation_not_a_surname() {
        // The measured false alarm this guard exists for: `Adalat CR 30 mg`
        // would otherwise escalate on every hypertension note in the corpus.
        let text = "dış merkezde Adalat CR 30 mg başlanmış";
        assert_eq!(assess(text, "Adalat"), Assessment::Absent);
    }

    #[test]
    fn a_longer_vocabulary_term_is_not_a_surname_pair() {
        let text = "Dış merkezde başlanan Adalat Crono 30 mg tedavisi";
        assert_eq!(
            assess(text, "Adalat"),
            Assessment::Absent,
            "`Crono` is the rest of the drug name, not a surname"
        );
    }

    #[test]
    fn a_sentence_initial_capital_is_not_a_casing_conflict() {
        // The dominant false alarm for lower-case vocabulary. `costa` is a rib
        // whether or not it happens to open the sentence.
        let text = "Pnömotoraks saptanmadı. Costa fraktürlerine analjezi verildi.";
        assert_eq!(assess(text, "Costa"), Assessment::Absent);
        let after_colon = "Tetkikler: Costa fraktürü izlendi.";
        assert_eq!(assess(after_colon, "Costa"), Assessment::Absent);
    }

    #[test]
    fn a_mid_sentence_capital_on_lower_case_vocabulary_is_a_conflict() {
        let text = "hastanın Costa isimli hekimi";
        assert!(signals(text, "Costa").contains(&PersonSignal::CasingMismatch));
    }

    #[test]
    fn a_locative_suffix_on_an_anatomical_term_is_not_a_person_signal() {
        // `costa'da` is the commonest anatomical surface form in the trauma
        // notes. Reading its suffix as a person reference would escalate every
        // rib fracture in the corpus.
        let text = "Toraks BT'de sol 4. ve 5. costa'da fraktür izlendi.";
        assert_eq!(assess(text, "costa"), Assessment::Absent);
    }

    #[test]
    fn a_genitive_suffix_is_suggestive() {
        let text = "hastanın costa'nın üzerinde";
        assert!(signals(text, "costa").contains(&PersonSignal::PersonCaseSuffix));
        assert_eq!(assess(text, "costa"), Assessment::Suggestive);
    }

    #[test]
    fn plain_anatomical_prose_produces_no_evidence_at_all() {
        let text = "Toraks BT'de costa 6 düzeyinde fissür izlendi, costae posteriorlarda normal.";
        assert_eq!(assess(text, "costa 6"), Assessment::Absent);
        assert_eq!(assess(text, "costae"), Assessment::Absent);
        // The specific false alarm: `BT'de` is an abbreviation plus a
        // locative, not a given name, so it must not make the term after it
        // look like a surname.
        assert!(!is_name_shaped("BT'de"));
        assert!(is_name_shaped("Yılmaz'ın"));
    }

    #[test]
    fn a_field_label_before_the_span_is_not_a_given_name() {
        // `Tetkikler:` is capitalised and name-shaped. Counting it as a given
        // name escalated the vocabulary term after every field label in the
        // corpus, which is most of a Turkish clinical note.
        let text = "Tetkikler: Costa fraktürü izlendi.";
        assert_eq!(assess(text, "Costa"), Assessment::Absent);
        assert!(!is_bare_word("Tetkikler:"));
        assert!(!is_bare_word("Dr."));
        assert!(is_bare_word("Andrea"));
    }

    #[test]
    fn an_out_of_range_span_reports_no_evidence_and_never_panics() {
        // Gathering evidence must not panic on a bad range. Reporting nothing
        // is safe only because the adjudicator slices the covered text FIRST
        // and fails with `SpanOutOfBounds` before it ever weighs evidence.
        let evidence = PersonEvidence::gather("kısa", 0, 999, &vocabulary());
        assert_eq!(evidence.assessment(), Assessment::Absent);
    }
}
