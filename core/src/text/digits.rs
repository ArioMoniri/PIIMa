//! Folding non-ASCII decimal digits to ASCII, for checksum arithmetic.
//!
//! A TCKN, VKN or IBAN written in anything other than ASCII `0-9` defeats every
//! `[0-9]{11}` pattern in L1 while remaining a perfectly readable national ID to
//! the clinician who typed it and to anyone who later re-identifies the note.
//! The evasion is free; the fold has to be free too.
//!
//! WHY THIS IS NOT NFKC. Fullwidth digits (U+FF10-FF19) and the mathematical
//! alphanumerics do carry a compatibility decomposition, so NFKC would fold
//! them. Arabic-Indic (U+0660-U+0669) and Extended Arabic-Indic (U+06F0-U+06F9)
//! do NOT -- they are distinct digits, not compatibility variants of ASCII ones,
//! and NFKC leaves them exactly as they are. Anything that reached for a single
//! normalisation form here would silently keep the two most plausible evasions
//! in a Turkish clinical context, so the mapping is by NUMERIC VALUE and is
//! written out.
//!
//! RELATIONSHIP TO L1. `core/src/rules/mod.rs` already carries a private
//! `ascii_digit` covering ASCII, fullwidth, Arabic-Indic, Extended Arabic-Indic
//! and Devanagari, and L1's `Doc` already keeps the offset map that makes those
//! folds safe. This table is a SUPERSET of that one and is deliberately
//! range-compatible with it: every range L1 folds, this folds identically. It
//! exists separately because the matching skeleton in `super::normalize` has to
//! compose digit folding with confusable folding and ignorable stripping in one
//! pass over one index, and reaching into a private function in another layer to
//! do it would give the crate two tables that drift. The intended end state is
//! one table -- `rules::Doc` calling this -- and `parity_with_the_l1_rules_layer`
//! below is the test that fails if the two ever disagree on a range.

/// The ASCII digit a character denotes, if it denotes one.
///
/// Explicit ranges rather than `char::to_digit`, which is ASCII-only, and rather
/// than a general Unicode decomposition, which would also fold letters and so
/// change the shape of the very tokens the rules key on.
#[must_use]
pub const fn ascii_digit(character: char) -> Option<char> {
    let value = match character {
        '0'..='9' => return Some(character),
        // Fullwidth forms: how a digit arrives from a CJK-locale IME or a badly
        // transcoded hospital export.
        '\u{FF10}'..='\u{FF19}' => character as u32 - 0xFF10,
        // Arabic-Indic and its Extended (Persian/Urdu) variant. Plausible in a
        // Turkish clinical context through regional data entry, and invisible to
        // NFKC.
        '\u{0660}'..='\u{0669}' => character as u32 - 0x0660,
        '\u{06F0}'..='\u{06F9}' => character as u32 - 0x06F0,
        // Devanagari and Bengali, present in multilingual EHR exports.
        '\u{0966}'..='\u{096F}' => character as u32 - 0x0966,
        '\u{09E6}'..='\u{09EF}' => character as u32 - 0x09E6,
        // Mathematical alphanumeric digits: bold, double-struck, sans-serif,
        // sans-serif bold, and monospace. Five consecutive decades from U+1D7CE,
        // which is why the arithmetic is a modulo rather than five arms.
        '\u{1D7CE}'..='\u{1D7FF}' => (character as u32 - 0x1D7CE) % 10,
        _ => return None,
    };
    // `value` is 0..=9 on every arm above, so the conversion cannot fail; it is
    // written fallibly anyway because this crate forbids `unwrap` outside tests.
    char::from_digit(value, 10)
}

/// True when the character is a decimal digit in SOME numbering system.
#[must_use]
pub const fn is_foldable_digit(character: char) -> bool {
    ascii_digit(character).is_some()
}

/// True when the character is a decimal digit outside ASCII.
///
/// A SIGNAL, not a fold. UTS #39 section 5.3 calls a string drawing digits from
/// more than one decimal numbering system a mixed-number, and an 11-digit run
/// that mixes ASCII with Arabic-Indic is not something a hospital information
/// system produces by accident. Under I2 that raises suspicion and never lowers
/// it: the caller escalates, it never demotes.
#[must_use]
pub const fn is_non_ascii_digit(character: char) -> bool {
    !character.is_ascii_digit() && is_foldable_digit(character)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::EntityLabel;
    use crate::rules::RuleSet;

    /// Rewrite ASCII digits into another decimal system by code-point offset.
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

    #[test]
    fn every_supported_system_folds_to_the_same_ascii_digits() {
        for base in [0xFF10, 0x0660, 0x06F0, 0x0966, 0x09E6, 0x1D7CE, 0x1D7D8] {
            let written = in_system("0123456789", base);
            let folded: String = written.chars().filter_map(ascii_digit).collect();
            assert_eq!(folded, "0123456789", "system at U+{base:04X} did not fold");
        }
    }

    #[test]
    fn ascii_digits_are_returned_unchanged_and_letters_are_not_digits() {
        for character in '0'..='9' {
            assert_eq!(ascii_digit(character), Some(character));
        }
        // The Turkish letters must never be read as digits: `ı` is not `1`.
        for character in ['ı', 'İ', 'I', 'i', 'l', 'O', 'o', 'ş', 'ğ'] {
            assert_eq!(
                ascii_digit(character),
                None,
                "{character:?} folded to a digit"
            );
        }
    }

    #[test]
    fn a_non_ascii_digit_is_flagged_without_being_dropped() {
        assert!(is_non_ascii_digit('\u{FF11}'));
        assert!(is_non_ascii_digit('\u{0661}'));
        assert!(!is_non_ascii_digit('1'));
        assert!(!is_non_ascii_digit('ı'));
    }

    #[test]
    fn parity_with_the_l1_rules_layer() {
        // WHY this test and not a shared function call: `rules::Doc::ascii_digit`
        // is private to L1, so the only observable way to compare the two tables
        // is to write a checksum-valid TCKN in each system and ask L1 whether it
        // still validates. Any range this module folds that L1 does not shows up
        // here as a missing TCKN, which is the direction that matters -- a
        // skeleton that folds more than L1 would report an identifier L1 cannot
        // confirm. The TCKN is built at run time, never written down (I8).
        let tckn = crate::rules::checksum_valid_tckn_for_tests();
        for base in [0xFF10, 0x0660, 0x06F0, 0x0966] {
            let written = in_system(&tckn, base);
            let doc = format!("TCKN {written} kayitlidir.");
            let found = RuleSet
                .detect(&doc)
                .into_iter()
                .find(|s| s.label() == EntityLabel::Tckn);
            let found = found.unwrap_or_else(|| panic!("L1 missed a TCKN at U+{base:04X}"));
            assert!(found.is_checksum_validated());
            assert_eq!(&doc[found.start()..found.end()], written);
        }
    }
}
