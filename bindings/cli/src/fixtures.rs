//! Synthetic identifiers, built at run time.
//!
//! Invariant I8 forbids a checksum-valid national ID from appearing in any
//! committed file, and the pre-commit hook enforces it. Every test in this crate
//! that needs one calls in here rather than writing digits down, so there is one
//! implementation to keep correct instead of one per test file that drifts.
//!
//! `#[cfg(test)]` at the module declaration in `main.rs`: none of this is
//! compiled into the shipped binary.

/// A TCKN that passes the real checksum.
///
/// Rules, from the brief: 11 digits, `d1 != 0`,
/// `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`,
/// `d11 = (d1+..+d10) mod 10`.
pub fn checksum_valid_tckn(seed: [u8; 9]) -> String {
    let mut digits = [0u8; 11];
    digits[..9].copy_from_slice(&seed);
    // A leading zero is not a TCKN, so it is nudged rather than trusted.
    if digits[0] == 0 {
        digits[0] = 1;
    }
    let odd: i32 = [0, 2, 4, 6, 8].iter().map(|i| i32::from(digits[*i])).sum();
    let even: i32 = [1, 3, 5, 7].iter().map(|i| i32::from(digits[*i])).sum();
    digits[9] = u8::try_from((odd * 7 - even).rem_euclid(10)).unwrap_or(0);
    let total: i32 = digits[..10].iter().map(|d| i32::from(*d)).sum();
    digits[10] = u8::try_from(total.rem_euclid(10)).unwrap_or(0);
    digits.iter().map(|d| char::from(b'0' + d)).collect()
}

/// The default synthetic TCKN.
pub fn tckn() -> String {
    checksum_valid_tckn([1, 2, 3, 4, 5, 6, 7, 8, 9])
}

/// A synthetic Turkish clinical note carrying rule-detectable identifiers.
///
/// Deliberately also carries a name and two code-switched medical terms, so a
/// test can assert both what IS masked and what is NOT.
pub fn note() -> String {
    format!(
        "Hasta Ayşe Yılmaz, TCKN {}, tel 0(532) 000 00 00. carcinoma'lı, MRI'da lezyon yok.",
        tckn()
    )
}
