//! Class C, the medical-term allowlist, as a runtime type.
//!
//! This is L4's negative set: Latin, English and Turkish medical vocabulary
//! that must never be masked, because masking `carcinoma` destroys the clinical
//! meaning of the note. The term files live in `eval/allowlist/*.txt` and are
//! append-only; this module turns their CONTENTS into a lookup index.
//!
//! CONTENTS, not paths, and that is invariant I1 rather than a style choice.
//! `core/` performs no I/O, so the caller reads the files and hands the bytes
//! in. A loader that opened a path here would put a filesystem call underneath
//! the crate that touches PHI, and would not compile for `wasm32` either.
//!
//! The normalisation mirrors `eval/allowlist.py` deliberately: two artifacts
//! that answer the same question with different code drift, and the Python
//! side is what the medical-term false-positive gate is scored with. Every
//! rule below has a counterpart there.

use std::collections::{BTreeMap, BTreeSet};

/// The combining dot above, U+0307.
///
/// `char::to_lowercase('İ')` emits `i` followed by this mark, and a stray
/// combining dot makes the folded form unmatchable against the vocabulary.
const COMBINING_DOT_ABOVE: char = '\u{0307}';

/// Every apostrophe a Turkish writer might type between a root and its suffix.
///
/// The typographic ones are not decoration: they arrive from word processors
/// and PDF exports, and a matcher that only knows `'` fails on every note that
/// went through one.
pub const APOSTROPHES: &str = "'\u{2019}\u{02bc}\u{00b4}\u{2018}`";

/// Characters that stay INSIDE a word token.
///
/// `PET-CT`, `BI-RADS`, `CA 15-3` and `Cheyne-Stokes` are single medical terms.
/// Splitting on the hyphen makes them unmatchable, which turns real vocabulary
/// into false positives at exactly the code-switch boundary L4 exists for.
const WORD_EXTRA: &str = "-+/";

/// Which term file an entry came from, mirroring `allowlist_categories` in
/// `eval/schema.yaml`.
///
/// An enum rather than a string because the category is read by the
/// adjudicator -- an `ANATOMY` collision and a `DRUG` collision are different
/// arguments -- and a typo'd string category would silently never match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AllowlistCategory {
    /// `eval/allowlist/diagnosis.txt`
    Diagnosis,
    /// `eval/allowlist/anatomy.txt`
    Anatomy,
    /// `eval/allowlist/drug.txt`
    Drug,
    /// `eval/allowlist/abbreviation.txt`
    Abbreviation,
    /// `eval/allowlist/procedure.txt`
    Procedure,
    /// `eval/allowlist/lab_analyte.txt`
    LabAnalyte,
    /// `eval/allowlist/microorganism.txt`
    Microorganism,
    /// `eval/allowlist/device.txt`
    Device,
    /// `eval/allowlist/code_switched.txt`
    CodeSwitched,
}

impl AllowlistCategory {
    /// The schema id, as written in `eval/schema.yaml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Diagnosis => "DIAGNOSIS",
            Self::Anatomy => "ANATOMY",
            Self::Drug => "DRUG",
            Self::Abbreviation => "ABBREVIATION",
            Self::Procedure => "PROCEDURE",
            Self::LabAnalyte => "LAB_ANALYTE",
            Self::Microorganism => "MICROORGANISM",
            Self::Device => "DEVICE",
            Self::CodeSwitched => "CODE_SWITCHED",
        }
    }

    /// Parse a schema id. `None` for anything the schema does not declare.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "DIAGNOSIS" => Self::Diagnosis,
            "ANATOMY" => Self::Anatomy,
            "DRUG" => Self::Drug,
            "ABBREVIATION" => Self::Abbreviation,
            "PROCEDURE" => Self::Procedure,
            "LAB_ANALYTE" => Self::LabAnalyte,
            "MICROORGANISM" => Self::Microorganism,
            "DEVICE" => Self::Device,
            "CODE_SWITCHED" => Self::CodeSwitched,
            _ => return None,
        })
    }
}

/// Casefold without destroying the Turkish dotted/dotless distinction.
///
/// `İ i I ı` are FOUR letters, not two. `str::to_lowercase` implements the
/// English assumption that `I` is the uppercase of `i`: it maps `ISIL` to
/// `isil` where Turkish requires `ısıl`, and `İREM` to `i` + U+0307 + `rem`
/// with a stray combining mark. Both outputs then fail to match the vocabulary
/// they were meant to match, and I6 forbids an `*-uncased` backbone for the
/// same reason -- casing is the strongest name signal Turkish has.
///
/// The decomposed spelling of `İ` (`I` + U+0307) is handled explicitly rather
/// than by an NFC pass, because normalisation would mean a Unicode-tables
/// dependency and this crate's dependency list is an enforced invariant. A
/// bare `I` maps to `ı`; an `I` whose next code point is the combining dot is
/// the decomposed `İ` and maps to `i`.
#[must_use]
pub fn turkish_casefold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            'İ' => out.push('i'),
            'I' => {
                if chars.peek() == Some(&COMBINING_DOT_ABOVE) {
                    chars.next();
                    out.push('i');
                } else {
                    out.push('ı');
                }
            }
            // An orphan combining dot after anything else carries no meaning
            // the matcher can use, and leaving it in makes the key unmatchable.
            COMBINING_DOT_ABOVE => {}
            other => out.extend(other.to_lowercase()),
        }
    }
    out
}

/// True when `key` is Latin/English vocabulary rather than a Turkish word.
///
/// The test is: unify the dotted/dotless pair and see whether anything
/// non-ASCII survives. `mrı` becomes `mri`, all ASCII, so `MRI` is English.
/// `dış` becomes `diş`, still carrying `ş`, so it is Turkish and must NOT be
/// given both readings -- `dış` ("outer") and `diş` ("tooth") are different
/// words and merging them hands a common function word an allowlist `Keep`.
fn is_ascii_origin(key: &str) -> bool {
    key.replace('ı', "i").is_ascii()
}

/// The loaded class C vocabulary: L4's runtime reference.
#[derive(Debug, Clone)]
pub struct MedicalAllowlist {
    by_key: BTreeMap<String, Vec<AllowlistEntry>>,
    /// Recognised apostrophe-separated Turkish suffixes, generated from
    /// vowel-harmony templates rather than hardcoded.
    suffixes: BTreeSet<String>,
    max_words: usize,
}

/// One vocabulary line, with the file it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    term: String,
    category: AllowlistCategory,
}

impl AllowlistEntry {
    /// The surface form exactly as written in the term file.
    ///
    /// Its CASING is load-bearing downstream: `costa` is written lower case
    /// because that is the register an anatomical term appears in, and `Adalat`
    /// upper case because a brand is a proper noun. The context-sensitive
    /// allowlist rule reads that register to detect a surface form that is
    /// capitalised where its entry is not.
    #[must_use]
    pub fn term(&self) -> &str {
        &self.term
    }

    /// Which term file declared it.
    #[must_use]
    pub const fn category(&self) -> AllowlistCategory {
        self.category
    }

    /// True when the entry is normally written lower case.
    #[must_use]
    pub fn is_lowercase_register(&self) -> bool {
        // Asked via the Turkish fold rather than `char::is_lowercase`, so
        // that a term opening with `I` is judged by the letter it folds to.
        self.term
            .chars()
            .next()
            .is_some_and(|first| !first.is_uppercase())
    }
}

/// Vowel-harmony expansion classes.
///
/// `A` is the two-way low vowel, `I` the four-way high vowel, `D` the voicing
/// alternation of the consonant, `C` its affricate counterpart. One Turkish
/// suffix surfaces in several forms (`-de/-da/-te/-ta`, `-li/-lı/-lu/-lü`);
/// hardcoding one variant misses the others, which is the failure the brief
/// calls out by name.
const HARMONY: &[(char, &[char])] = &[
    ('A', &['a', 'e']),
    ('I', &['ı', 'i', 'u', 'ü']),
    ('D', &['d', 't']),
    ('C', &['c', 'ç']),
];

/// Suffix templates in the archiphoneme notation above.
///
/// These are the case, possessive, relational and derivational endings that
/// actually attach to a code-switched medical root in clinical prose. Kept in
/// step with `_SUFFIX_TEMPLATES` in `eval/allowlist.py`.
const SUFFIX_TEMPLATES: &[&str] = &[
    "A", "yA", "I", "yI", "In", "nIn", "sI", "sInA", "sInI", "sInDA", "sInDAn", "DA", "DAn", "nDA",
    "nDAn", "nI", "nA", "lI", "lIk", "lIğI", "lArI", "lAr", "lArDA", "lArDAn", "lArIn", "lA",
    "ylA", "DIr", "ydI", "yDI", "ken", "sIz", "CI", "CIsI", "e", "a", "i", "ı", "u", "ü", "n", "m",
    "t",
];

fn expand(template: &str, out: &mut BTreeSet<String>) {
    for (index, ch) in template.char_indices() {
        if let Some((_, variants)) = HARMONY.iter().find(|(class, _)| *class == ch) {
            let head = &template[..index];
            let tail = &template[index + ch.len_utf8()..];
            for variant in *variants {
                let mut next = String::with_capacity(template.len() + 1);
                next.push_str(head);
                next.push(*variant);
                next.push_str(tail);
                expand(&next, out);
            }
            return;
        }
    }
    out.insert(turkish_casefold(template));
}

fn build_suffixes() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for template in SUFFIX_TEMPLATES {
        expand(template, &mut out);
    }
    out
}

impl Default for MedicalAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

impl MedicalAllowlist {
    /// An empty allowlist with the suffix set built.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_key: BTreeMap::new(),
            suffixes: build_suffixes(),
            max_words: 1,
        }
    }

    /// Index the CONTENTS of one term file.
    ///
    /// Format, matching `eval/allowlist/*.txt`: one term per line, UTF-8, `#`
    /// comments, blank lines ignored. Takes `&str` and not a path because
    /// `core/` does no I/O (I1).
    pub fn insert_terms(&mut self, category: AllowlistCategory, contents: &str) {
        for line in contents.lines() {
            let term = line.trim();
            if term.is_empty() || term.starts_with('#') {
                continue;
            }
            self.insert_term(category, term);
        }
    }

    /// Index one term.
    pub fn insert_term(&mut self, category: AllowlistCategory, term: &str) {
        let entry = AllowlistEntry {
            term: term.to_string(),
            category,
        };
        let key = self.normalise(term);
        self.max_words = self.max_words.max(key.split_whitespace().count().max(1));
        for variant in self.key_variants(term) {
            let bucket = self.by_key.entry(variant).or_default();
            if !bucket.contains(&entry) {
                bucket.push(entry.clone());
            }
        }
    }

    /// Build an allowlist from several term files at once.
    #[must_use]
    pub fn from_sources(sources: &[(AllowlistCategory, &str)]) -> Self {
        let mut allowlist = Self::new();
        for (category, contents) in sources {
            allowlist.insert_terms(*category, contents);
        }
        allowlist
    }

    /// Remove an apostrophe-separated Turkish suffix from one casefolded token.
    ///
    /// `carcinoma'lı` becomes `carcinoma`, but only when what follows the
    /// apostrophe is a recognised vowel-harmony variant: `d'Amico` is a proper
    /// noun, not a suffixed root. Only APOSTROPHE-separated suffixes are
    /// stripped, because stripping a bare word-final `-ta` would turn the
    /// anatomical term `costa` into `cos`.
    #[must_use]
    pub fn strip_turkish_suffix<'a>(&self, token: &'a str) -> &'a str {
        for (index, ch) in token.char_indices() {
            if APOSTROPHES.contains(ch) {
                let root = &token[..index];
                let tail = &token[index + ch.len_utf8()..];
                if !root.is_empty() && self.suffixes.contains(tail) {
                    return root;
                }
            }
        }
        token
    }

    /// Casefold and collapse whitespace WITHOUT stripping suffixes.
    #[must_use]
    pub fn fold(term: &str) -> String {
        turkish_casefold(term)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The lookup key: casefolded, whitespace-collapsed, suffix-stripped.
    #[must_use]
    pub fn normalise(&self, term: &str) -> String {
        Self::fold(term)
            .split_whitespace()
            .map(|token| self.strip_turkish_suffix(token))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every dotted/dotless reading of `term`'s lookup key.
    ///
    /// WHY this exists and why it does not weaken [`turkish_casefold`]: class C
    /// is Latin and English vocabulary, languages in which `I` and `i` are one
    /// letter. A Turkish writer typing `Infective endocarditis` produces a
    /// capital `I` that a Turkish-correct fold reads as `ı` -- correctly,
    /// because in Turkish that IS a different letter. Both readings have to be
    /// indexed or a correct fold makes the English vocabulary unmatchable.
    ///
    /// WHY the expansion is gated on ASCII origin: applied indiscriminately it
    /// merges Turkish words that are not the same word. `dış` and `diş` differ
    /// only in that pair, so an unconditional expansion made every occurrence
    /// of a common function word count as an ANATOMY term -- and at L4 runtime
    /// it hands `dış` an allowlist `Keep`, which is the suppression D-010 is
    /// about. This is the lesson `eval/allowlist.py` records as D-017.
    #[must_use]
    pub fn key_variants(&self, term: &str) -> Vec<String> {
        let key = self.normalise(term);
        if !is_ascii_origin(&key) {
            return vec![key];
        }
        let mut variants = vec![key.clone()];
        // The `ı`->`i` reading only makes sense for an `ı` the fold PRODUCED
        // from an ASCII capital `I`. A written lowercase `ı` is a letter the
        // author chose, so `sıvı` must not also index `sivi`.
        if term.contains('I') {
            variants.push(key.replace('ı', "i"));
        }
        // The reverse reading: an ASCII-origin term written lower case, met in
        // a document that upper-cased it (`INFECTIVE`).
        variants.push(key.replace('i', "ı"));
        variants.dedup();
        variants
    }

    /// Every entry whose normalised form equals `term`'s.
    ///
    /// A MIXED-SCRIPT TOKEN NEVER MATCHES, whatever it folds to. `carcinom` +
    /// Cyrillic `а` skeletons to `carcinoma`, which is on this list, so without
    /// this check the fold would hand an attacker a deterministic `Keep` for any
    /// string they can disguise as a medical term -- recall losing to the
    /// allowlist, which I2 forbids. Returning no entry does not mask anything by
    /// itself; it withdraws the short-circuit so the span reaches the
    /// adjudicator on its own evidence. A genuine `carcinoma` is single-script
    /// and keeps its protection.
    #[must_use]
    pub fn lookup(&self, term: &str) -> &[AllowlistEntry] {
        if crate::text::is_mixed_script(term) {
            return &[];
        }
        for variant in self.key_variants(term) {
            if let Some(hit) = self.by_key.get(&variant) {
                return hit;
            }
        }
        &[]
    }

    /// True when the surface form is legitimate medical vocabulary.
    #[must_use]
    pub fn contains(&self, term: &str) -> bool {
        !self.lookup(term).is_empty()
    }

    /// The longest indexed term, in whitespace-separated words.
    #[must_use]
    pub const fn max_words(&self) -> usize {
        self.max_words
    }

    /// How many distinct keys are indexed, including dotted/dotless variants.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.by_key.len()
    }
}

/// True when `ch` belongs inside a word token.
#[must_use]
pub fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || APOSTROPHES.contains(ch) || WORD_EXTRA.contains(ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drug() -> MedicalAllowlist {
        MedicalAllowlist::from_sources(&[(
            AllowlistCategory::Drug,
            "# a comment\n\nAdalat\nAdalat Crono\nDeva\nmetformin\n",
        )])
    }

    #[test]
    fn casefold_keeps_the_four_turkish_letters_distinct() {
        // The whole reason this function exists instead of `to_lowercase`.
        assert_eq!(turkish_casefold("ISIL"), "ısıl");
        assert_eq!(turkish_casefold("İREM"), "irem");
        assert_eq!(turkish_casefold("Iğdır"), "ığdır");
        assert_eq!(turkish_casefold("İstanbul"), "istanbul");
        // `str::to_lowercase` gets both of these wrong, which is the bug.
        assert_ne!(turkish_casefold("ISIL"), "ISIL".to_lowercase());
        assert!("İREM".to_lowercase().contains(COMBINING_DOT_ABOVE));
        assert!(!turkish_casefold("İREM").contains(COMBINING_DOT_ABOVE));
    }

    #[test]
    fn casefold_handles_the_decomposed_spelling_of_dotted_capital_i() {
        // `I` + U+0307 is the NFD spelling of `İ`. Read naively the `I` folds
        // to `ı` and the word becomes a different word.
        let decomposed = "I\u{0307}stanbul";
        assert_eq!(turkish_casefold(decomposed), "istanbul");
    }

    #[test]
    fn dis_does_not_match_dis() {
        // THE lesson from eval/allowlist.py: an indiscriminate dotted/dotless
        // expansion merges `dış` ("outer") with `diş` ("tooth"), so a common
        // Turkish function word starts matching an anatomy term -- and at L4
        // runtime an allowlist hit is a demotion argument.
        let mut allowlist = MedicalAllowlist::new();
        allowlist.insert_term(AllowlistCategory::Anatomy, "diş");
        assert!(allowlist.contains("diş"));
        assert!(allowlist.contains("Diş"));
        assert!(
            !allowlist.contains("dış"),
            "the dotted/dotless expansion merged two distinct Turkish words"
        );
        assert!(!allowlist.contains("Dış"));
        assert!(!is_ascii_origin("diş"));
        assert!(is_ascii_origin("mrı"));
    }

    #[test]
    fn ascii_origin_vocabulary_is_indexed_under_both_readings() {
        let mut allowlist = MedicalAllowlist::new();
        allowlist.insert_term(AllowlistCategory::Abbreviation, "MRI");
        // A Turkish-correct fold of `MRI` yields `mrı`; the English reading
        // `mri` must be indexed too or the vocabulary is unmatchable.
        assert!(allowlist.contains("MRI"));
        assert!(allowlist.contains("mri"));
        assert!(allowlist.contains("MRI'da"));
    }

    #[test]
    fn apostrophe_suffixes_are_stripped_only_when_they_are_suffixes() {
        let allowlist = drug();
        assert!(allowlist.contains("metformin'e"));
        assert!(
            allowlist.contains("metformin\u{2019}e"),
            "typographic quote"
        );
        // `d'Amico` is a proper noun; `Amico` is not a vowel-harmony ending.
        assert_eq!(allowlist.strip_turkish_suffix("d'amico"), "d'amico");
    }

    #[test]
    fn a_bare_word_final_suffix_is_never_stripped() {
        // Stripping bare `-ta` would turn the anatomical term `costa` into
        // `cos`, which matches nothing and un-protects a real medical word.
        let mut allowlist = MedicalAllowlist::new();
        allowlist.insert_term(AllowlistCategory::Anatomy, "costa");
        assert_eq!(allowlist.strip_turkish_suffix("costa"), "costa");
        assert!(allowlist.contains("costa"));
        assert!(allowlist.contains("costa'da"));
    }

    #[test]
    fn a_homoglyph_disguised_term_earns_no_allowlist_keep() {
        // I2's precedence rule, enforced rather than described. The disguised
        // form folds onto a real term, so without the mixed-script check any
        // span could buy a deterministic `Keep` by swapping one letter.
        let list = drug();
        assert!(list.contains("Adalat"), "the genuine term is protected");
        assert!(
            !list.contains("Ad\u{0430}lat"),
            "a Cyrillic `а` must not buy an allowlist Keep"
        );
        assert!(list.lookup("Ad\u{0430}lat").is_empty());
        // Turkish is Latin script throughout: the four i letters and the rest of
        // the alphabet must never read as mixed script and lose their entries.
        assert!(!crate::text::is_mixed_script("İnfeksiyon şüphesi ığdır"));
    }

    #[test]
    fn adalat_and_adalet_are_different_words() {
        // They differ in a vowel the fold does not touch, so no amount of
        // casefolding may collapse the drug into the given name.
        let allowlist = drug();
        assert!(allowlist.contains("Adalat"));
        assert!(allowlist.contains("adalat"));
        assert!(!allowlist.contains("Adalet"));
        assert!(!allowlist.contains("Adalet'in"));
    }

    #[test]
    fn multi_word_terms_set_the_match_width() {
        let allowlist = drug();
        assert_eq!(allowlist.max_words(), 2);
        assert!(allowlist.contains("Adalat Crono"));
        assert!(allowlist.contains("adalat  crono"), "whitespace collapses");
    }

    #[test]
    fn comments_and_blank_lines_are_not_vocabulary() {
        let allowlist = drug();
        assert!(!allowlist.contains("# a comment"));
        assert!(!allowlist.contains("a comment"));
    }

    #[test]
    fn an_entry_reports_its_register_and_category() {
        let allowlist = drug();
        let entry = &allowlist.lookup("Adalat")[0];
        assert_eq!(entry.category(), AllowlistCategory::Drug);
        assert_eq!(entry.term(), "Adalat");
        assert!(!entry.is_lowercase_register());
        let mut anatomy = MedicalAllowlist::new();
        anatomy.insert_term(AllowlistCategory::Anatomy, "costa");
        assert!(anatomy.lookup("costa")[0].is_lowercase_register());
    }

    #[test]
    fn category_ids_round_trip_through_the_schema_spelling() {
        for category in [
            AllowlistCategory::Diagnosis,
            AllowlistCategory::Anatomy,
            AllowlistCategory::Drug,
            AllowlistCategory::Abbreviation,
            AllowlistCategory::Procedure,
            AllowlistCategory::LabAnalyte,
            AllowlistCategory::Microorganism,
            AllowlistCategory::Device,
            AllowlistCategory::CodeSwitched,
        ] {
            assert_eq!(
                AllowlistCategory::from_id(category.as_str()),
                Some(category)
            );
        }
        assert_eq!(AllowlistCategory::from_id("PATIENT_NAME"), None);
    }

    #[test]
    fn the_real_vocabulary_files_load() {
        let allowlist = crate::route::vocabulary::bundled();
        // Every collision D-010 names must actually be in the vocabulary, or
        // the context-sensitive tests below would pass vacuously.
        for term in ["costa", "Adalat", "Deva", "carcinoma"] {
            assert!(
                allowlist.contains(term),
                "{term} missing from eval/allowlist"
            );
        }
        assert!(!allowlist.contains("Adalet"));
        assert!(!allowlist.contains("Yılmaz"));
    }
}
