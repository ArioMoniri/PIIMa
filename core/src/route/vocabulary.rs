//! The class C vocabulary that SHIPS, as opposed to the one that is scored.
//!
//! # Why this module is not `#[cfg(test)]`
//!
//! It used to be. `route::tests_support::bundled_allowlist` compiled the term
//! files in for the collision tests and nothing else, so every binding
//! constructed `Pipeline::new` with an EMPTY allowlist and the entire
//! context-sensitive resolution of D-010/D-023 -- `Costa` the surname against
//! `costa` the rib, `Adalat` the drug against `Adalet` the name -- was
//! unreachable from any shipped binary. The tests passed on a vocabulary the
//! product did not have. A capability reachable only from the test harness is
//! not a capability, and the argument that once justified the gate ("a shipped
//! binary must take its vocabulary from the caller, otherwise the crate pins
//! one snapshot of an append-only artifact") had the trade backwards: pinning
//! the snapshot that was BUILT is the auditable outcome, and requiring every
//! caller to supply the vocabulary means the caller who forgets ships without
//! it. Callers who genuinely have their own vocabulary still pass it to
//! [`Pipeline::with_allowlist`]; callers who do nothing now get the audited
//! one.
//!
//! [`Pipeline::with_allowlist`]: crate::pipeline::Pipeline::with_allowlist
//!
//! # Why `include_str!` and not a file read
//!
//! `core/` performs no I/O (I1) and compiles to `wasm32`, where there is no
//! filesystem to read from. `include_str!` bakes the bytes into the artifact at
//! compile time, so the Safe Harbor tier stays fully on-device, a missing or
//! renamed term file is a BUILD failure rather than a silent runtime
//! degradation to an empty vocabulary, and the browser build carries the same
//! words as the CLI.
//!
//! # Why there is no generated copy of the term files
//!
//! `include_str!` reads `eval/allowlist/*.txt` directly. There is no second
//! copy of the vocabulary in `core/src/`, so the class of drift a generator
//! plus a checked-in artifact would introduce -- the scored vocabulary and the
//! runtime vocabulary diverging -- cannot occur for the CONTENTS of a file that
//! is listed here.
//!
//! One drift vector survives that, and it is the one this project has already
//! been bitten by: [`SOURCES`] enumerates the files by name, so a term file
//! added to the append-only `eval/allowlist/` directory and not added here is
//! scored by `eval/allowlist.py` and invisible to the runtime. `tests::` below
//! reads the directory and fails on exactly that.

use std::sync::OnceLock;

use super::allowlist::{AllowlistCategory, MedicalAllowlist};

/// Every class C term file, with the category it declares in `eval/schema.yaml`.
///
/// PUBLIC because two consumers need the same list and a second hand-written
/// copy of it is a drift vector: L4 builds its lookup index from it, and
/// `crate::surrogate` builds the folded set it uses to refuse minting a
/// surrogate that collides with real vocabulary.
pub const SOURCES: [(AllowlistCategory, &str); 9] = [
    (
        AllowlistCategory::Diagnosis,
        include_str!("../../../eval/allowlist/diagnosis.txt"),
    ),
    (
        AllowlistCategory::Anatomy,
        include_str!("../../../eval/allowlist/anatomy.txt"),
    ),
    (
        AllowlistCategory::Drug,
        include_str!("../../../eval/allowlist/drug.txt"),
    ),
    (
        AllowlistCategory::Abbreviation,
        include_str!("../../../eval/allowlist/abbreviation.txt"),
    ),
    (
        AllowlistCategory::Procedure,
        include_str!("../../../eval/allowlist/procedure.txt"),
    ),
    (
        AllowlistCategory::LabAnalyte,
        include_str!("../../../eval/allowlist/lab_analyte.txt"),
    ),
    (
        AllowlistCategory::Microorganism,
        include_str!("../../../eval/allowlist/microorganism.txt"),
    ),
    (
        AllowlistCategory::Device,
        include_str!("../../../eval/allowlist/device.txt"),
    ),
    (
        AllowlistCategory::CodeSwitched,
        include_str!("../../../eval/allowlist/code_switched.txt"),
    ),
];

/// The file name each entry of [`SOURCES`] was compiled from, in the same order.
///
/// Kept beside `SOURCES` rather than derived from it because `include_str!`
/// consumes the path at compile time and leaves nothing to inspect. Its only
/// consumer is the drift test, which is the point: the test can only compare
/// the embedded set against the directory if it knows which names were claimed.
pub const SOURCE_FILES: [&str; 9] = [
    "diagnosis.txt",
    "anatomy.txt",
    "drug.txt",
    "abbreviation.txt",
    "procedure.txt",
    "lab_analyte.txt",
    "microorganism.txt",
    "device.txt",
    "code_switched.txt",
];

/// The audited class C vocabulary, indexed once per process.
///
/// Indexing expands every term into its dotted/dotless key variants, so it is
/// the expensive part of building an allowlist and is done exactly once behind
/// a `OnceLock`. Callers that need an owned value (`Pipeline` does) clone it.
#[must_use]
pub fn bundled() -> &'static MedicalAllowlist {
    static CELL: OnceLock<MedicalAllowlist> = OnceLock::new();
    CELL.get_or_init(|| MedicalAllowlist::from_sources(&SOURCES))
}

/// Every term in [`SOURCES`], unindexed, in file order.
///
/// The raw words rather than the lookup index: `crate::surrogate` needs to fold
/// them its own way, and the drift test counts them.
pub(crate) fn terms() -> impl Iterator<Item = &'static str> {
    SOURCES.iter().flat_map(|(_, contents)| {
        contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `std::fs` HERE AND NOWHERE ELSE IN `core/`.
    ///
    /// The shipped code reads no files -- that is I1 and the wasm32 target --
    /// but the question this test asks cannot be answered without looking at
    /// the directory: "is every term file that exists compiled in?" is a
    /// question about the filesystem, and a compile-time construct can only
    /// see the paths someone already wrote down. A `#[cfg(test)]` read is not
    /// linked into the library, so the invariant is untouched and the drift is
    /// caught. `just check` runs this; the alternative is discovering a term
    /// file that the eval harness scores and the product ignores at the point
    /// where a hospital reports a masked diagnosis.
    fn allowlist_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("eval")
            .join("allowlist")
    }

    #[test]
    fn every_term_file_on_disk_is_compiled_into_the_binary() {
        let mut on_disk: BTreeSet<String> = BTreeSet::new();
        for entry in std::fs::read_dir(allowlist_dir()).expect("eval/allowlist must be readable") {
            let path = entry.expect("directory entry").path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("txt") {
                on_disk.insert(
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .expect("utf-8 file name")
                        .to_string(),
                );
            }
        }
        let embedded: BTreeSet<String> = SOURCE_FILES.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(
            on_disk, embedded,
            "eval/allowlist/*.txt and route::vocabulary::SOURCES have diverged: a file scored by \
             the eval harness is not in the shipped vocabulary, or vice versa"
        );
    }

    #[test]
    fn the_embedded_contents_are_byte_identical_to_the_term_files() {
        for (index, name) in SOURCE_FILES.iter().enumerate() {
            let on_disk = std::fs::read_to_string(allowlist_dir().join(name))
                .unwrap_or_else(|_| panic!("{name} must be readable"));
            let (_, embedded) = SOURCES[index];
            assert_eq!(
                on_disk, embedded,
                "the embedded copy of {name} is not the file the eval harness scores"
            );
        }
    }

    #[test]
    fn the_bundled_vocabulary_resolves_the_collisions_d_010_names() {
        let allowlist = bundled();
        // Both halves of the D-010 pair, as surface forms. Whether a given
        // OCCURRENCE is kept is L4's context-sensitive decision; what this
        // asserts is that the words reached the index at all.
        assert!(allowlist.contains("costa"));
        assert!(allowlist.contains("Adalat"));
        assert!(allowlist.contains("carcinoma"));
        // The suffixed, code-switched form, which is the boundary the whole
        // project turns on.
        assert!(allowlist.contains("carcinoma'lı"));
    }

    #[test]
    fn the_vocabulary_is_not_empty_in_any_category() {
        for (category, contents) in SOURCES {
            let count = contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .count();
            assert!(count > 0, "{} contributed no terms", category.as_str());
        }
        assert!(terms().count() > 1000, "the vocabulary shrank unexpectedly");
    }
}
