//! Fixture builders shared by this crate's tests.
//!
//! I8: no checksum-VALID Turkish identity number is ever written into a
//! committed file. `core/`'s equivalent helper is `pub(crate)` and
//! `#[cfg(test)]`, so it cannot be reached from here; the algorithm is
//! recomputed instead of the number being copied.

/// A checksum-valid TCKN, built at runtime from a caller-chosen prefix.
///
/// The prefix is nine digits; the last two are the check digits from the
/// published algorithm (`d1 != 0`).
pub fn checksum_valid_tckn(prefix: [u8; 9]) -> String {
    let digit = |i: usize| u32::from(prefix[i]);
    let odd = digit(0) + digit(2) + digit(4) + digit(6) + digit(8);
    let even = digit(1) + digit(3) + digit(5) + digit(7);
    // `+ 100` keeps the subtraction positive without changing the residue.
    let tenth = ((odd * 7 + 100 * 10) - even) % 10;
    let eleventh = (odd + even + tenth) % 10;
    let mut out = String::with_capacity(11);
    for value in prefix {
        out.push(char::from(b'0' + value));
    }
    out.push(char::from(b'0' + u8::try_from(tenth).unwrap_or(0)));
    out.push(char::from(b'0' + u8::try_from(eleventh).unwrap_or(0)));
    out
}

/// The TCKN every test in this crate uses, so an expected output written in one
/// module matches the fixture built in another.
pub fn tckn() -> String {
    checksum_valid_tckn([1, 2, 3, 4, 5, 6, 7, 8, 9])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_number_passes_the_rules_layer() {
        // The point of the helper: if it produced a checksum-INVALID number the
        // rules layer would find nothing and every downstream test would pass
        // vacuously.
        let value = tckn();
        assert_eq!(value.len(), 11);
        let pipeline = deid_tr_core::Pipeline::new(deid_tr_core::Tier::SafeHarbor);
        let result = pipeline
            .deidentify(&format!("TCKN {value}"))
            .expect("pipeline");
        assert!(
            !result.text.contains(&value),
            "the fixture is not detectable"
        );
    }
}
