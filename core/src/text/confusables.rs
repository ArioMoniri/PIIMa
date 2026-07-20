//! Homoglyph folding: a curated UTS #39 skeleton for Turkish clinical text.
//!
//! Two strings are confusable, in the sense of UTS #39, exactly when their
//! SKELETONS are equal. `Аyşe` written with a Cyrillic `А` U+0410 is a different
//! byte string from `Ayşe` and the same thing on the page, so an exact matcher
//! -- a gazetteer, an allowlist, a rule -- sees nothing and a human sees a name.
//! Folding both to the same skeleton is what closes that.
//!
//! # Why a curated table rather than a crate
//!
//! `unicode-security` implements UTS #39 properly, is pure Rust and is
//! `no_std`-capable, so it would satisfy I1. It is not used here for two
//! reasons, and the second is the load-bearing one:
//!
//! 1. `core/Cargo.toml` is where I1 is ENFORCED, and every entry in it argues
//!    for itself in place because the pre-commit hook reads that file. Adding a
//!    dependency plus its `unicode-normalization` and `unicode-script` graph to
//!    fold roughly two hundred code points is a poor trade against an auditable
//!    table.
//! 2. **The full UTS #39 skeleton is not safe for Turkish unmodified.** The
//!    confusables data folds across the dotted/dotless `i` family, which is
//!    precisely the distinction Turkish orthography carries and I6 protects. A
//!    general skeleton that maps `ı` and `i` together would erase the strongest
//!    name signal in the language in the name of catching homoglyphs. This table
//!    therefore folds INTO the Latin dotted/dotless letters and never BETWEEN
//!    them -- see [`TURKISH_PROTECTED`] and the tests.
//!
//! The cost of curating is honest and stated: this covers Latin, Cyrillic and
//! Greek, which are the scripts that plausibly appear in Turkish clinical text,
//! plus fullwidth Latin and a small set of letterlike and ligature forms. A
//! homoglyph drawn from Armenian, Cherokee or the mathematical alphanumerics
//! outside those ranges is NOT folded and will not be caught. Widening the table
//! is a data change with a test, not a redesign.
//!
//! # This raises suspicion; it never lowers it
//!
//! Folding is a RECALL mechanism. The mirror-image signal -- a token that is
//! Latin with one Cyrillic letter in it is an anomaly regardless of what it
//! matches -- runs the other way, and [`is_mixed_script`] exists for it. The
//! asymmetry L4 must respect: a mixed-script token must never earn allowlist
//! protection, because an attacker who writes `carcinom` + Cyrillic `а` would
//! otherwise buy a `Keep` for a name. Mixed script means ineligible for the
//! allowlist short-circuit and escalate; it never means demote (I2).

/// The four letters this fold must never touch.
///
/// `İ` U+0130, `I` U+0049, `ı` U+0131 and `i` U+0069 are four distinct letters
/// in Turkish, not four renderings of one. Any mapping that relates two of them
/// destroys the dotted/dotless distinction, which is exactly what I6 forbids
/// when it bans `*-uncased` backbones. Cyrillic and Greek lookalikes fold INTO
/// these; these fold into nothing.
pub const TURKISH_PROTECTED: [char; 4] = ['\u{0130}', '\u{0049}', '\u{0131}', '\u{0069}'];

/// The Latin skeleton of a confusable character, if it has one.
///
/// Returns a `&'static str` rather than a `char` because a few confusables are
/// one-to-many: the `ﬁ` ligature skeletons to `fi`, `№` to `No`. The caller's
/// offset index handles the cardinality; a `char` return would have silently
/// forced these entries out of the table.
#[must_use]
pub fn skeleton(character: char) -> Option<&'static str> {
    // Nothing in the protected set is ever rewritten, checked FIRST so no
    // later arm can reach one of them by accident as the table grows.
    if is_turkish_protected(character) {
        return None;
    }
    if let Some(folded) = fullwidth_latin(character) {
        return Some(folded);
    }
    Some(match character {
        // ---- Cyrillic -> Latin -------------------------------------------
        // The lowercase set an attacker actually reaches for: these render
        // identically to their Latin counterparts in every common font.
        '\u{0430}' => "a", // CYRILLIC SMALL LETTER A
        '\u{0435}' => "e", // CYRILLIC SMALL LETTER IE
        '\u{043E}' => "o", // CYRILLIC SMALL LETTER O
        '\u{0440}' => "p", // CYRILLIC SMALL LETTER ER
        '\u{0441}' => "c", // CYRILLIC SMALL LETTER ES
        '\u{0443}' => "y", // CYRILLIC SMALL LETTER U
        '\u{0445}' => "x", // CYRILLIC SMALL LETTER HA
        '\u{0455}' => "s", // CYRILLIC SMALL LETTER DZE
        '\u{0456}' => "i", // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
        '\u{0458}' => "j", // CYRILLIC SMALL LETTER JE
        '\u{04BB}' => "h", // CYRILLIC SMALL LETTER SHHA
        '\u{04CF}' => "l", // CYRILLIC SMALL LETTER PALOCHKA
        '\u{0501}' => "d", // CYRILLIC SMALL LETTER KOMI DE
        '\u{051B}' => "q", // CYRILLIC SMALL LETTER QA
        '\u{051D}' => "w", // CYRILLIC SMALL LETTER WE
        // Capitals. `İ` and `I` are the pair the brief singles out: Cyrillic
        // `І` U+0406 sits in exactly the visual space Turkish `I` occupies,
        // which makes a substitution in a Turkish name unusually plausible.
        '\u{0410}' => "A",
        '\u{0412}' => "B",
        '\u{0415}' => "E",
        '\u{041A}' => "K",
        '\u{041C}' => "M",
        '\u{041D}' => "H",
        '\u{041E}' => "O",
        '\u{0420}' => "P",
        '\u{0421}' => "C",
        '\u{0422}' => "T",
        '\u{0423}' => "Y",
        '\u{0425}' => "X",
        '\u{0405}' => "S",
        '\u{0406}' => "I",
        '\u{0408}' => "J",
        '\u{04C0}' => "I",
        '\u{050C}' => "G",

        // ---- Greek -> Latin -----------------------------------------------
        // Greek reaches Turkish clinical text legitimately through units and
        // notation (`μ`, `α`), so this direction is folded for MATCHING only
        // and never applied to the emitted document.
        '\u{03B1}' => "a", // GREEK SMALL LETTER ALPHA
        '\u{03BF}' => "o", // GREEK SMALL LETTER OMICRON
        '\u{03C1}' => "p", // GREEK SMALL LETTER RHO
        '\u{03C5}' => "u", // GREEK SMALL LETTER UPSILON
        '\u{03BD}' => "v", // GREEK SMALL LETTER NU
        '\u{03C7}' => "x", // GREEK SMALL LETTER CHI
        '\u{03BA}' => "k", // GREEK SMALL LETTER KAPPA
        '\u{03C4}' => "t", // GREEK SMALL LETTER TAU
        '\u{03B9}' => "i", // GREEK SMALL LETTER IOTA
        '\u{0391}' => "A",
        '\u{0392}' => "B",
        '\u{0395}' => "E",
        '\u{0396}' => "Z",
        '\u{0397}' => "H",
        '\u{0399}' => "I",
        '\u{039A}' => "K",
        '\u{039C}' => "M",
        '\u{039D}' => "N",
        '\u{039F}' => "O",
        '\u{03A1}' => "P",
        '\u{03A4}' => "T",
        '\u{03A5}' => "Y",
        '\u{03A7}' => "X",
        '\u{03A9}' => "O", // GREEK CAPITAL OMEGA, confusable with O in many faces

        // ---- Letterlike symbols and ligatures ------------------------------
        // These do carry a compatibility decomposition, so NFKC would also fold
        // them. They are listed rather than reached through NFKC because NFKC
        // as a blanket transform is irreversible and would fold far more than
        // this pass is willing to.
        '\u{2113}' => "l", // SCRIPT SMALL L
        '\u{212F}' => "e", // SCRIPT SMALL E
        '\u{2126}' => "O", // OHM SIGN
        '\u{212A}' => "K", // KELVIN SIGN
        '\u{212B}' => "A", // ANGSTROM SIGN
        '\u{2117}' => "P",
        '\u{FB00}' => "ff",
        '\u{FB01}' => "fi",
        '\u{FB02}' => "fl",
        '\u{FB03}' => "ffi",
        '\u{FB04}' => "ffl",
        '\u{2116}' => "No", // NUMERO SIGN, which is how `No` reaches an address line
        _ => return None,
    })
}

/// True for one of the four Turkish `i` letters this fold refuses to touch.
#[must_use]
pub fn is_turkish_protected(character: char) -> bool {
    TURKISH_PROTECTED.contains(&character)
}

/// Fullwidth Latin letters, folded arithmetically rather than by table.
///
/// U+FF21..U+FF3A and U+FF41..U+FF5A are the ASCII letters shifted by a fixed
/// offset, so 52 table entries would be 52 chances to mistype one.
fn fullwidth_latin(character: char) -> Option<&'static str> {
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    let (source, index) = match character {
        '\u{FF21}'..='\u{FF3A}' => (UPPER, character as usize - 0xFF21),
        '\u{FF41}'..='\u{FF5A}' => (LOWER, character as usize - 0xFF41),
        _ => return None,
    };
    source.get(index..=index)
}

/// The script family a character belongs to, coarsely.
///
/// COARSE ON PURPOSE. Real script resolution is a Unicode data table this crate
/// does not carry; what mixed-script detection needs is only whether two letters
/// in one token come from different families, and that question is answerable
/// from block ranges. A character outside every listed block is `None` and is
/// ignored by [`is_mixed_script`], so the predicate under-reports rather than
/// crying wolf on a script it cannot classify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Latin, including the Turkish letters and Latin-1/Extended-A supplements.
    Latin,
    /// Cyrillic, including its supplement blocks.
    Cyrillic,
    /// Greek and Coptic.
    Greek,
}

/// The script of a letter, or `None` for a non-letter or an unclassified one.
#[must_use]
pub const fn script_of(character: char) -> Option<Script> {
    match character {
        'A'..='Z' | 'a'..='z' | '\u{00C0}'..='\u{024F}' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{0400}'..='\u{052F}' | '\u{2DE0}'..='\u{2DFF}' | '\u{A640}'..='\u{A69F}' => {
            Some(Script::Cyrillic)
        }
        _ => None,
    }
}

/// True when one token draws its letters from more than one script.
///
/// A SIGNAL FOR L4, and the direction is fixed by I2. A mixed-script token is an
/// anomaly in a Turkish clinical note whatever it matches, so it escalates and
/// is never eligible for the medical-allowlist short-circuit. It is never a
/// reason to drop a span.
#[must_use]
pub fn is_mixed_script(token: &str) -> bool {
    let mut seen: Option<Script> = None;
    for script in token.chars().filter_map(script_of) {
        match seen {
            None => seen = Some(script),
            Some(first) if first != script => return true,
            Some(_) => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fold a whole string, for the tests that care about the composite result.
    fn fold(text: &str) -> String {
        text.chars()
            .map(|c| skeleton(c).map_or_else(|| c.to_string(), ToOwned::to_owned))
            .collect()
    }

    #[test]
    fn the_four_turkish_i_letters_are_never_folded_into_each_other() {
        // THE test this whole module is constrained by. If it ever fails, the
        // dotted/dotless distinction -- the strongest name signal in Turkish,
        // and the reason I6 bans uncased backbones -- has been destroyed in the
        // name of catching homoglyphs.
        for character in TURKISH_PROTECTED {
            assert_eq!(
                skeleton(character),
                None,
                "U+{:04X} was folded and must not be",
                character as u32
            );
        }
        let folded = fold("İIıi");
        assert_eq!(folded, "İIıi");
        assert_eq!(
            folded.chars().count(),
            4,
            "the four letters must survive as four characters"
        );
        let mut distinct: Vec<char> = folded.chars().collect();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            4,
            "the four letters must stay distinguishable"
        );
    }

    #[test]
    fn a_turkish_name_with_a_cyrillic_homoglyph_folds_onto_the_plain_form() {
        // Cyrillic `А` U+0410 and `е` U+0435 for the Latin letters they render
        // identically to. The `ş` is left alone: it is a Turkish letter, not a
        // confusable, and folding it to `s` would be a diacritic stripper.
        assert_eq!(fold("\u{0410}yş\u{0435}"), "Ayşe");
        assert_ne!(
            "\u{0410}yş\u{0435}", "Ayşe",
            "the fixture must actually differ"
        );
    }

    #[test]
    fn cyrillic_and_greek_lookalikes_fold_into_latin_but_not_across_the_i_family() {
        // Folding INTO `I`/`i` is right -- Cyrillic `І` really is a Latin `I`
        // to a reader. Folding BETWEEN the Turkish four is what must not happen,
        // and the previous test pins that.
        assert_eq!(skeleton('\u{0406}'), Some("I"));
        assert_eq!(skeleton('\u{0456}'), Some("i"));
        assert_eq!(skeleton('\u{0399}'), Some("I"));
        assert_eq!(skeleton('\u{03B9}'), Some("i"));
        // A drug name is as good a target as a person name.
        assert_eq!(fold("\u{0410}dalat"), "Adalat");
    }

    #[test]
    fn fullwidth_latin_folds_arithmetically_across_the_whole_range() {
        for (offset, expected) in ('A'..='Z').enumerate() {
            let wide = char::from_u32(0xFF21 + offset as u32).expect("fullwidth capital");
            assert_eq!(skeleton(wide), Some(&expected.to_string()[..]));
        }
        for (offset, expected) in ('a'..='z').enumerate() {
            let wide = char::from_u32(0xFF41 + offset as u32).expect("fullwidth small");
            assert_eq!(skeleton(wide), Some(&expected.to_string()[..]));
        }
    }

    #[test]
    fn a_one_to_many_fold_is_representable() {
        // The reason the return type is a string and not a char.
        assert_eq!(skeleton('\u{FB01}'), Some("fi"));
        assert_eq!(skeleton('\u{2116}'), Some("No"));
    }

    #[test]
    fn turkish_letters_and_medical_register_pass_through_untouched() {
        // A fold that quietly stripped diacritics would turn `Gökçe` into
        // `Gokce` and `carcinoma` matching would still work -- but the emitted
        // skeleton would no longer be the text any Turkish gazetteer holds.
        assert_eq!(fold("Şükrü Gökçe İnci Yılmaz"), "Şükrü Gökçe İnci Yılmaz");
        assert_eq!(
            fold("carcinoma metformin PET-CT"),
            "carcinoma metformin PET-CT"
        );
    }

    #[test]
    fn mixed_script_is_detected_on_the_token_that_carries_it() {
        assert!(
            is_mixed_script("\u{0410}yse"),
            "Cyrillic A among Latin letters"
        );
        assert!(is_mixed_script("carcinom\u{0430}"));
        assert!(!is_mixed_script("Ayşe"));
        assert!(!is_mixed_script("Şükrü"));
        assert!(!is_mixed_script("carcinoma"));
        // Digits and punctuation carry no script and must not create a mix.
        assert!(!is_mixed_script("PET-CT'de"));
        assert!(!is_mixed_script("12345678901"));
        // An all-Cyrillic token is not mixed. It is a different question,
        // answered by `script_of`, and conflating them would flag every Greek
        // unit symbol in the note.
        assert!(!is_mixed_script("\u{0410}\u{0412}\u{0415}"));
    }

    #[test]
    fn script_classification_places_the_turkish_letters_in_latin() {
        for character in ['İ', 'ı', 'ş', 'ğ', 'ü', 'ö', 'ç', 'A', 'z'] {
            assert_eq!(script_of(character), Some(Script::Latin), "{character:?}");
        }
        assert_eq!(script_of('\u{0430}'), Some(Script::Cyrillic));
        assert_eq!(script_of('\u{03B1}'), Some(Script::Greek));
        assert_eq!(script_of('5'), None);
        assert_eq!(script_of('-'), None);
    }
}
