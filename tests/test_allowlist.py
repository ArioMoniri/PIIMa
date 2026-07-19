"""Tests for the class C medical-term allowlist loader.

The hazard these tests document is not hypothetical. `str.lower()` is the
default reflex in Python and it is WRONG for Turkish: it maps `I` to `i` and
`İ` to `i` + U+0307, collapsing four distinct letters into two. Several tests
below assert the wrong answer `str.lower()` gives alongside the right one, so
that anyone who "simplifies" `turkish_casefold` back to `.lower()` gets a red
build that explains itself rather than a silent matching failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.allowlist import (
    DRIFT_EXCEPTIONS,
    AllowlistError,
    DriftReport,
    build_drift,
    fold,
    key_variants,
    load_allowlist,
    normalise,
    strip_turkish_suffix,
    turkish_casefold,
)
from eval.schema import REPO_ROOT, load_schema, validate_schema

# ---------------------------------------------------------------------------
# Turkish-correct casefolding
# ---------------------------------------------------------------------------


def test_dotless_capital_i_folds_to_dotless_i_not_to_dotted_i() -> None:
    """`I` is the capital of `ı`, never of `i`."""
    assert turkish_casefold("ISIL") == "ısıl"
    # The hazard, asserted so it cannot be reintroduced by "simplification":
    assert "ISIL".lower() == "isil"
    assert "ISIL".lower() != turkish_casefold("ISIL")


def test_dotted_capital_i_folds_to_plain_dotted_i_with_no_combining_mark() -> None:
    """`İ` is the capital of `i`, and folding it must not leave U+0307 behind."""
    assert turkish_casefold("İREM") == "irem"
    # str.lower() produces i + COMBINING DOT ABOVE, which compares unequal to a
    # plain "i" and silently fails every lookup made against it.
    assert "İREM".lower() == "i̇rem"
    assert "İREM".lower() != turkish_casefold("İREM")
    assert "̇" not in turkish_casefold("İREM")


def test_the_four_turkish_i_letters_stay_two_distinct_pairs() -> None:
    assert turkish_casefold("Irmak") == "ırmak"
    assert turkish_casefold("İrmak") == "irmak"
    assert turkish_casefold("Irmak") != turkish_casefold("İrmak")
    # str.lower() merges them, which is exactly how a name detector loses the
    # casing signal invariant I6 exists to protect.
    assert "Irmak".lower() == "İrmak".lower().replace("̇", "")


def test_code_switched_term_folds_without_mangling_the_latin_root() -> None:
    """A Latin/English root carrying Turkish morphology must survive folding."""
    assert turkish_casefold("Carcinoma'LI") == "carcinoma'lı"
    assert normalise("carcinoma'lı") == "carcinoma"
    assert normalise("Carcinoma'LI") == "carcinoma"
    assert normalise("MRI'da") == normalise("MRI")


# ---------------------------------------------------------------------------
# Vowel-harmony suffix stripping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "surface",
    [
        "carcinoma'lı",
        "carcinoma'li",
        "carcinoma'lu",
        "carcinoma'lü",
        "carcinoma'da",
        "carcinoma'de",
        "carcinoma'ta",
        "carcinoma'te",
        "carcinoma'dan",
        "carcinoma'den",
        "carcinoma'ya",
        "carcinoma'ye",
        "carcinoma'nın",
        "carcinoma'nin",
        "carcinoma'sı",
        "carcinoma'si",
    ],
)
def test_every_vowel_harmony_variant_strips_to_the_same_root(surface: str) -> None:
    """One suffix, several surface forms. Hardcoding one variant misses the rest."""
    assert normalise(surface) == "carcinoma"


def test_typographic_apostrophe_is_treated_as_an_apostrophe() -> None:
    assert normalise("metformin’e") == "metformin"


def test_possessive_plus_case_buffer_n_strips() -> None:
    assert normalise("Cushing sendromu'nu") == "cushing sendromu"


def test_unrecognised_tail_after_an_apostrophe_is_left_alone() -> None:
    """`d'Amico` is a proper noun, not a suffixed root."""
    assert strip_turkish_suffix("d'amico") == "d'amico"


def test_word_final_suffix_without_an_apostrophe_is_not_stripped() -> None:
    """`costa` ends in `-ta`; stripping bare endings would destroy the term."""
    assert normalise("costa") == "costa"
    assert normalise("data") == "data"


# ---------------------------------------------------------------------------
# Dotted/dotless index expansion, and the Turkish words it must NOT merge
# ---------------------------------------------------------------------------


def test_dotless_expansion_does_not_merge_two_distinct_turkish_words() -> None:
    """`dış` ("outer") is not `diş` ("tooth").

    An unconditional `ı`<->`i` expansion made every occurrence of a common
    Turkish adjective count as an ANATOMY term. That inflates the vocabulary FP
    denominator with terms no clinician wrote, and allowlists a function word at
    L4 - which under open issue D-010 is how an allowlist entry suppresses a
    real span.
    """
    assert key_variants("dış") == ("dış",)
    assert key_variants("diş") == ("diş",)
    assert not set(key_variants("dış")) & set(key_variants("diş"))

    allowlist = load_allowlist()
    assert "diş" in allowlist
    assert "dış" not in allowlist


def test_turkish_words_are_not_expanded_into_a_dotted_reading() -> None:
    """Two independent guards, one per way a Turkish word reaches the index.

    `yarık` carries a Turkish-only letter, so the term is not ASCII-origin at
    all. `sıvı` survives the ASCII test but its `ı` was WRITTEN, not produced by
    folding a capital `I`, so there is no English reading to recover.
    """
    for turkish in ("yarık", "kırık", "ışık", "sıvı", "ılık"):
        assert key_variants(turkish) == (normalise(turkish),), turkish


def test_ascii_origin_vocabulary_still_resolves_in_both_readings() -> None:
    """The English `I`/`i` collapse still has to be indexed, or the fix regresses."""
    assert key_variants("MRI'da") == ("mrı", "mri")
    assert set(key_variants("ISIL")) == {"ısıl", "isil"}
    assert "infective endocarditis" in key_variants("Infective endocarditis")

    allowlist = load_allowlist()
    for term in ("MRI'da", "MRI", "mri", "ICU", "PET-CT'de"):
        assert term in allowlist, term


def test_dis_is_not_scanned_as_a_medical_term_in_running_text() -> None:
    """The corpus scanner is what feeds the vocabulary FP denominator."""
    from eval.allowlist import find_occurrences

    allowlist = load_allowlist()
    text = "Dış merkezde çekilen MRI'da dış kulak yolu doğal izlendi."
    keys = {occurrence.key for occurrence in find_occurrences("d1", text, allowlist)}
    assert "diş" not in keys
    assert "dış" not in keys
    assert "mrı" in keys


# ---------------------------------------------------------------------------
# The loaded corpus vocabulary
# ---------------------------------------------------------------------------


def test_real_allowlist_loads_clean() -> None:
    allowlist = load_allowlist()
    assert allowlist.total_terms > 1800
    assert set(allowlist.counts_by_category) == set(load_schema().allowlist_ids)
    assert all(count > 0 for count in allowlist.counts_by_category.values())


def test_multiword_terms_are_supported() -> None:
    allowlist = load_allowlist()
    assert allowlist.max_words >= 2
    for term in (
        "arteria mesenterica superior",
        "Ductus cysticus",
        "Kerley B",
        "diabetes mellitus",
    ):
        assert term in allowlist, term
    assert "Arteria Mesenterica Superior'da" in allowlist


def test_reconciled_terms_from_the_finding_are_present() -> None:
    allowlist = load_allowlist()
    for term in (
        "ECG",
        "Doppler",
        "Holter",
        "HER2",
        "KRAS",
        "Gleason",
        "FOLFIRINOX",
        "carboplatin",
        "docetaxel",
        "gemcitabine",
        "Cheyne-Stokes",
        "Janeway",
        "ISUP",
        "ECOG",
        "BI-RADS",
        "Apgar",
        "Adalat Crono",
    ):
        assert term in allowlist, term


def test_categories_are_reported_per_term() -> None:
    allowlist = load_allowlist()
    assert "DRUG" in allowlist.categories_of("metformin'e")
    assert "ANATOMY" in allowlist.categories_of("costa")


# ---------------------------------------------------------------------------
# Load-time validation
# ---------------------------------------------------------------------------


def _schema_with_source_file(path: str) -> dict[str, object]:
    return {
        "meta": {
            "schema_version": "1.0.0",
            "language": ["tr"],
            "medical_register": ["la", "en"],
        },
        "direct_identifiers": [],
        "quasi_identifiers": [],
        "allowlist_categories": [
            {
                "id": "DIAGNOSIS",
                "identifier_class": "allowlist",
                "must_never_mask": True,
                "source_file": path,
                "code_switch_suffixed": True,
                "description": "test category",
            }
        ],
    }


def test_missing_source_file_is_a_hard_error_not_a_warning() -> None:
    schema = validate_schema(_schema_with_source_file("eval/allowlist/nope.txt"))
    with pytest.raises(AllowlistError, match="do not exist"):
        load_allowlist(schema)


def test_undeclared_file_on_disk_is_a_hard_error() -> None:
    """A term file no category declares is unreachable data - the original bug."""
    directory = REPO_ROOT / "eval" / "allowlist"
    schema = validate_schema(_schema_with_source_file("eval/allowlist/diagnosis.txt"))
    with pytest.raises(AllowlistError, match="declared by no"):
        load_allowlist(schema, allowlist_dir=directory)


def test_duplicate_term_across_files_is_a_hard_error(tmp_path: Path) -> None:
    directory = tmp_path
    (directory / "a.txt").write_text("# c\naspirin\n", encoding="utf-8")
    (directory / "b.txt").write_text("# c\nAspirin\n", encoding="utf-8")
    raw = _schema_with_source_file(str(directory / "a.txt"))
    categories = raw["allowlist_categories"]
    assert isinstance(categories, list)
    categories.append(
        {
            "id": "DRUG",
            "identifier_class": "allowlist",
            "must_never_mask": True,
            "source_file": str(directory / "b.txt"),
            "code_switch_suffixed": True,
            "description": "test category",
        }
    )
    with pytest.raises(AllowlistError, match="duplicate allowlist term"):
        load_allowlist(validate_schema(raw), allowlist_dir=directory)


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def test_drift_catches_a_term_annotated_but_absent_from_the_vocabulary() -> None:
    allowlist = load_allowlist()
    report = build_drift({normalise("Bogusoma"): "Bogusoma"}, allowlist)
    assert report.annotated_only == ("bogusoma",)


def test_drift_catches_a_vocabulary_term_no_fixture_annotates() -> None:
    allowlist = load_allowlist()
    report = build_drift({normalise("carcinoma"): "carcinoma"}, allowlist)
    assert report.annotated_only == ()
    assert "gleason" in report.vocabulary_only
    counts = report.as_dict()["vocabulary_not_in_fixtures"]
    assert isinstance(counts, int) and counts > 100


def test_drift_matches_a_suffixed_annotation_to_its_root() -> None:
    allowlist = load_allowlist()
    report = build_drift({normalise("carcinoma'lı"): "carcinoma'lı"}, allowlist)
    assert report.annotated_only == ()


def _real_drift() -> DriftReport:
    from eval.allowlist import annotated_terms_from_files
    from eval.build_gold import DEFAULT_CORPUS_ROOTS, iter_corpus_files

    return build_drift(
        annotated_terms_from_files(iter_corpus_files(DEFAULT_CORPUS_ROOTS)),
        load_allowlist(),
    )


def test_real_corpus_drift_is_limited_to_the_documented_exceptions() -> None:
    """Everything left is a PHRASE over vocabulary that is already present.

    Kept as an assertion rather than a comment so that a NEW unmatched fixture
    term fails the suite instead of quietly joining the backlog.
    """
    report = _real_drift()
    assert set(report.annotated_only) == set(DRIFT_EXCEPTIONS)


def test_residual_drift_is_zero_once_exceptions_are_applied() -> None:
    """The number `--strict` reads, and the number `just check` now fails on."""
    assert _real_drift().unjustified == ()


def test_the_seven_reconciled_terms_are_now_in_the_vocabulary() -> None:
    """Each was annotated in a fixture with no runtime reference for L4."""
    allowlist = load_allowlist()
    for term, category in (
        ("costa", "ANATOMY"),
        ("lead", "DEVICE"),
        ("monitör", "DEVICE"),
        ("sensör", "DEVICE"),
        ("walker", "DEVICE"),
        ("rebound", "DIAGNOSIS"),
        # The suffixed form belongs to the morphology file, not to a second
        # DEVICE entry: `Monitörde` is `monitör` inflected, not another term.
        ("Monitörde", "CODE_SWITCHED"),
    ):
        assert term in allowlist, term
        assert category in allowlist.categories_of(term), term


def test_a_drift_exception_cannot_hide_a_genuinely_missing_term(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exception map must not become somewhere to bury vocabulary rot."""
    from eval.allowlist import validate_drift_exceptions

    allowlist = load_allowlist()
    validate_drift_exceptions(allowlist)

    monkeypatch.setitem(
        DRIFT_EXCEPTIONS, "bogusoma marka", "claims to be a phrase but is not"
    )
    with pytest.raises(AllowlistError, match="MISSING TERM"):
        validate_drift_exceptions(allowlist)


def test_strict_mode_exits_non_zero_on_unjustified_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from eval.allowlist import main

    assert main(["--strict"]) == 0

    monkeypatch.delitem(DRIFT_EXCEPTIONS, "costa 6")
    assert main(["--strict"]) == 1


# ---------------------------------------------------------------------------
# Corpus occurrence scanning (the second FP denominator)
# ---------------------------------------------------------------------------


def test_occurrences_are_found_at_utf8_byte_offsets() -> None:
    from eval.allowlist import find_occurrences

    allowlist = load_allowlist()
    text = "Hastada şüpheli carcinoma'lı lezyon; Doppler yapıldı."
    found = find_occurrences("d1", text, allowlist)
    keys = {occurrence.key for occurrence in found}
    assert "carcinoma" in keys
    assert "doppler" in keys
    encoded = text.encode("utf-8")
    for occurrence in found:
        assert encoded[occurrence.start : occurrence.end].decode("utf-8")


def test_longest_multiword_match_wins_and_occurrences_do_not_overlap() -> None:
    from eval.allowlist import find_occurrences

    allowlist = load_allowlist()
    found = find_occurrences("d1", "Tani: diabetes mellitus.", allowlist)
    assert [occurrence.key for occurrence in found] == ["diabetes mellitus"]


def test_fold_keeps_surface_forms_distinct_for_duplicate_detection() -> None:
    assert fold("Adalat'a") != fold("Adalat")
    assert normalise("Adalat'a") == normalise("Adalat")
