"""Tests that the label-map validator REJECTS malformed maps.

Same shape as `tests/test_schema.py` and for the same reason: a validator that
accepts a broken map converts a mapping mistake into a benchmark that scores a
third-party checkpoint against a translation nobody checked. The rejection tests
come first; the tests over the real file come after.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from eval.label_map import (
    DEFAULT_LABEL_MAP_DIR,
    LabelMapError,
    MatchPolicy,
    available_label_maps,
    load_label_map,
    strip_bio_prefix,
    validate_label_map,
)
from eval.schema import Schema, load_schema

MODERNBERT_MAP: Path = DEFAULT_LABEL_MAP_DIR / "modernbert-tr-pii-ner.yaml"


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


def minimal_map() -> dict[str, Any]:
    """A map that validates clean, used as the base for each mutation."""
    return {
        "meta": {
            "map_version": "1.0.0",
            "source_model": "test/model",
            "source_scheme": "BIO",
            "source_label_count": 3,
            "schema_file": "eval/schema.yaml",
            "status": "unmeasured",
        },
        "labels": [
            {
                "source": "TCKN",
                "targets": ["TCKN"],
                "match_policy": "exact",
                "scored": True,
                "rationale": "Same entity.",
            },
            {
                "source": "KISI",
                "targets": ["PATIENT_NAME", "CLINICIAN_NAME"],
                "match_policy": "any_of",
                "scored": True,
                "rationale": "One label, two of ours.",
            },
            {
                "source": "SWIFT",
                "targets": [],
                "match_policy": "unmapped",
                "scored": False,
                "rationale": "Names a bank, not a patient.",
            },
        ],
    }


def test_minimal_map_validates(schema: Schema) -> None:
    label_map = validate_label_map(minimal_map(), schema)
    assert label_map.source_labels == {"TCKN", "KISI", "SWIFT"}
    assert label_map.unmapped_labels == {"SWIFT"}


# ---------------------------------------------------------------------------
# Rejections.
# ---------------------------------------------------------------------------


def test_missing_targets_key_is_rejected(schema: Schema) -> None:
    """ "We forgot" must not be spellable the same way as "we declined"."""
    document = minimal_map()
    del document["labels"][2]["targets"]
    with pytest.raises(LabelMapError, match="targets"):
        validate_label_map(document, schema)


def test_target_absent_from_schema_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0]["targets"] = ["PERSON_NAME"]
    with pytest.raises(LabelMapError, match="does not exist in eval/schema.yaml"):
        validate_label_map(document, schema)


def test_unknown_source_label_lookup_is_a_hard_error(schema: Schema) -> None:
    label_map = validate_label_map(minimal_map(), schema)
    with pytest.raises(LabelMapError, match="unknown source label"):
        label_map.lookup("MERSIS_NO")


def test_declined_label_returns_empty_targets_not_an_error(schema: Schema) -> None:
    """The difference between "declined" and "unknown" is the whole point."""
    label_map = validate_label_map(minimal_map(), schema)
    assert label_map.targets_for("SWIFT") == ()
    assert label_map.lookup("SWIFT").match_policy is MatchPolicy.UNMAPPED


def test_unexplained_shared_target_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"].append(
        {
            "source": "TCKN_ALT",
            "targets": ["TCKN"],
            "match_policy": "exact",
            "scored": True,
            "rationale": "Also a national id.",
        }
    )
    document["meta"]["source_label_count"] = 4
    with pytest.raises(LabelMapError, match="shared_target_reason"):
        validate_label_map(document, schema)


def test_shared_target_with_stated_reason_is_accepted(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0]["shared_target_reason"] = "Our schema is coarser here."
    document["labels"].append(
        {
            "source": "TCKN_ALT",
            "targets": ["TCKN"],
            "match_policy": "exact",
            "scored": True,
            "rationale": "Also a national id.",
            "shared_target_reason": "Our schema is coarser here.",
        }
    )
    document["meta"]["source_label_count"] = 4
    assert len(validate_label_map(document, schema).mappings) == 4


def test_quasi_target_cannot_be_scored(schema: Schema) -> None:
    """D-008 must not be reversible by a YAML edit."""
    document = minimal_map()
    document["labels"][0] = {
        "source": "MESLEK",
        "targets": ["EMPLOYER_ROLE"],
        "match_policy": "exact",
        "scored": True,
        "rationale": "Occupation.",
    }
    with pytest.raises(LabelMapError, match="quasi-identifier"):
        validate_label_map(document, schema)


def test_quasi_target_unscored_is_accepted(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0] = {
        "source": "MESLEK",
        "targets": ["EMPLOYER_ROLE"],
        "match_policy": "exact",
        "scored": False,
        "rationale": "Occupation.",
    }
    assert validate_label_map(document, schema).scored_labels == {"KISI"}


def test_allowlist_target_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0]["targets"] = ["DIAGNOSIS"]
    with pytest.raises(LabelMapError, match="allowlist"):
        validate_label_map(document, schema)


def test_unmapped_with_targets_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][2]["targets"] = ["TCKN"]
    with pytest.raises(LabelMapError, match="must carry no targets"):
        validate_label_map(document, schema)


def test_exact_with_two_targets_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][1]["match_policy"] = "exact"
    with pytest.raises(LabelMapError, match="exactly one target"):
        validate_label_map(document, schema)


def test_any_of_with_one_target_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0]["match_policy"] = "any_of"
    with pytest.raises(LabelMapError, match="at least two targets"):
        validate_label_map(document, schema)


def test_unknown_match_policy_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0]["match_policy"] = "best_effort"
    with pytest.raises(LabelMapError, match="unknown match_policy"):
        validate_label_map(document, schema)


def test_scored_unmapped_label_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][2]["scored"] = True
    with pytest.raises(LabelMapError, match="cannot be scored"):
        validate_label_map(document, schema)


def test_duplicate_source_label_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"].append(copy.deepcopy(document["labels"][0]))
    document["meta"]["source_label_count"] = 4
    with pytest.raises(LabelMapError, match="duplicate source label"):
        validate_label_map(document, schema)


def test_label_count_mismatch_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["meta"]["source_label_count"] = 25
    with pytest.raises(LabelMapError, match="source_label_count"):
        validate_label_map(document, schema)


def test_bio_prefixed_source_declaration_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["labels"][0]["source"] = "B-TCKN"
    with pytest.raises(LabelMapError, match="WITHOUT a BIO prefix"):
        validate_label_map(document, schema)


def test_missing_rationale_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    del document["labels"][0]["rationale"]
    with pytest.raises(LabelMapError, match="rationale"):
        validate_label_map(document, schema)


def test_unknown_status_is_rejected(schema: Schema) -> None:
    document = minimal_map()
    document["meta"]["status"] = "working"
    with pytest.raises(LabelMapError, match="unknown status"):
        validate_label_map(document, schema)


def test_missing_file_is_rejected(schema: Schema, tmp_path: Path) -> None:
    with pytest.raises(LabelMapError, match="not found"):
        load_label_map(tmp_path / "absent.yaml", schema)


# ---------------------------------------------------------------------------
# BIO handling.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("B-TCKN", "TCKN"),
        ("I-TCKN", "TCKN"),
        ("TCKN", "TCKN"),
        ("  b-tckn  ", "TCKN"),
        ("O", "O"),
    ],
)
def test_strip_bio_prefix(raw: str, expected: str) -> None:
    assert strip_bio_prefix(raw) == expected


def test_lookup_accepts_both_bio_halves(schema: Schema) -> None:
    label_map = validate_label_map(minimal_map(), schema)
    assert label_map.lookup("B-TCKN").targets == ("TCKN",)
    assert label_map.lookup("I-TCKN").targets == ("TCKN",)


# ---------------------------------------------------------------------------
# The committed map for ytu-ce-cosmos/modernbert-tr-pii-ner.
# ---------------------------------------------------------------------------

# The published checkpoint's 25 entity types, transcribed from its config
# `id2label` (51 BIO labels = 25 x 2 + O). Written out here so that a future
# edit to the YAML that DROPS a label fails a test rather than shrinking the
# benchmark quietly.
MODERNBERT_SOURCE_LABELS: frozenset[str] = frozenset(
    {
        "KISI_AD_SOYAD",
        "TCKN",
        "TELEFON",
        "EMAIL",
        "ADRES",
        "POSTA_KODU",
        "DOGUM_TARIHI",
        "PLAKA",
        "IP_ADRES",
        "KIMLIK_BELGE_NO",
        "PASAPORT_NO",
        "SURUCU_BELGESI_NO",
        "IBAN_TR",
        "KART_NO",
        "KART_CVV",
        "KART_SON_KULLANMA",
        "HESAP_NO",
        "SWIFT_BIC",
        "VKN",
        "MERSIS_NO",
        "ETTN_EFATURA_ID",
        "MESLEK_UNVAN",
        "TUZEL_KISI",
        "SAGLIK_BILGISI",
        "DIN_ETNIK_SIYASI_TERIM",
    }
)


@pytest.fixture(scope="module")
def modernbert(schema: Schema) -> Any:
    return load_label_map(MODERNBERT_MAP, schema)


def test_every_published_label_is_declared(modernbert: Any) -> None:
    assert modernbert.source_labels == MODERNBERT_SOURCE_LABELS
    assert modernbert.meta["source_bio_label_count"] == 51


def test_every_label_resolves_to_a_target_or_an_explicit_null(modernbert: Any) -> None:
    for label in MODERNBERT_SOURCE_LABELS:
        mapping = modernbert.lookup(label)
        if mapping.match_policy is MatchPolicy.UNMAPPED:
            assert mapping.targets == ()
        else:
            assert mapping.targets


def test_unpublished_label_is_a_hard_error(modernbert: Any) -> None:
    with pytest.raises(LabelMapError, match="unknown source label"):
        modernbert.lookup("B-KREDI_NOTU")


def test_person_name_maps_to_all_three_name_labels(modernbert: Any) -> None:
    """The model makes no role distinction, so neither does the mapping."""
    mapping = modernbert.lookup("KISI_AD_SOYAD")
    assert mapping.match_policy is MatchPolicy.ANY_OF
    assert set(mapping.targets) == {"PATIENT_NAME", "CLINICIAN_NAME", "RELATIVE_NAME"}


def test_occupation_is_mapped_but_not_scored(modernbert: Any) -> None:
    mapping = modernbert.lookup("MESLEK_UNVAN")
    assert mapping.targets == ("EMPLOYER_ROLE",)
    assert mapping.scored is False
    assert mapping.scoring_note is not None


def test_health_information_is_unmapped_and_flagged(modernbert: Any) -> None:
    mapping = modernbert.lookup("SAGLIK_BILGISI")
    assert mapping.targets == ()
    assert mapping.needs_human_decision is True
    assert modernbert.needs_human_decision == {"SAGLIK_BILGISI"}


@pytest.mark.parametrize(
    "label",
    ["DIN_ETNIK_SIYASI_TERIM", "KART_CVV", "MERSIS_NO", "ETTN_EFATURA_ID", "SWIFT_BIC"],
)
def test_labels_without_a_clinical_analogue_are_unmapped(
    modernbert: Any, label: str
) -> None:
    assert modernbert.lookup(label).targets == ()


def test_map_does_not_claim_to_have_been_measured(modernbert: Any) -> None:
    """No weights have been fetched and no inference has been run."""
    assert modernbert.status == "unmeasured"


def test_every_committed_map_validates(schema: Schema) -> None:
    """Coverage stays total as maps are added: no map is exempt from the loader."""
    paths = available_label_maps()
    assert paths, "eval/label_maps/ has no maps"
    for path in paths:
        load_label_map(path, schema)
