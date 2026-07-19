"""Tests that the schema validator REJECTS malformed schemas.

The brief is explicit that the rejection tests come before the schema is
trusted. A validator that accepts a broken schema is worse than no validator:
it converts a structural mistake into a silently under-scoped benchmark, and an
entity type that is missing from the vocabulary is an entity type nobody ever
measures recall on.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from eval.build_gold import GoldError, load_corpus
from eval.schema import (
    DEFAULT_SCHEMA_PATH,
    REPO_ROOT,
    SchemaError,
    load_schema,
    validate_schema,
)

GOLD_DIR = REPO_ROOT / "eval" / "gold"
ADVERSARIAL_DIR = REPO_ROOT / "eval" / "adversarial"


def minimal_schema() -> dict[str, Any]:
    """A schema that validates clean, used as the base for each mutation."""
    return {
        "meta": {
            "schema_version": "1.0.0",
            "language": ["tr"],
            "medical_register": ["la", "en"],
        },
        "direct_identifiers": [
            {
                "id": "PATIENT_NAME",
                "hipaa_category": "Names",
                "identifier_class": "direct",
                "detector": "ner",
                "tr_specific": False,
                "checksum_validatable": False,
                "recall_threshold": 0.98,
                "description": "Patient name.",
            },
            {
                "id": "TCKN",
                "hipaa_category": "Social Security numbers",
                "identifier_class": "direct",
                "detector": "rules",
                "tr_specific": True,
                "checksum_validatable": True,
                "recall_threshold": 0.98,
                "precision_threshold": 1.000,
                "description": "Turkish national identification number.",
            },
        ],
        "quasi_identifiers": [
            {
                "id": "EMPLOYER_ROLE",
                "identifier_class": "quasi",
                "detector": "llm",
                "validated_by": "reid_red_team",
                "scored_by_f1": False,
                "description": "Employer or institutional role.",
            }
        ],
        "allowlist_categories": [
            {
                "id": "DIAGNOSIS",
                "identifier_class": "allowlist",
                "must_never_mask": True,
                "source_file": "eval/allowlist/diagnosis.txt",
                "code_switch_suffixed": True,
                "description": "Latin/English diagnosis terms.",
            }
        ],
    }


def test_minimal_schema_is_valid() -> None:
    schema = validate_schema(minimal_schema())
    assert schema.direct_ids == {"PATIENT_NAME", "TCKN"}
    assert schema.quasi_ids == {"EMPLOYER_ROLE"}
    assert schema.checksum_validatable_ids == {"TCKN"}


def test_direct_entry_missing_required_key_is_rejected() -> None:
    raw = minimal_schema()
    del raw["direct_identifiers"][0]["recall_threshold"]

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    message = str(excinfo.value)
    assert "PATIENT_NAME" in message, "the error must name the offending entry"
    assert "recall_threshold" in message


def test_checksum_validatable_without_precision_threshold_is_rejected() -> None:
    raw = minimal_schema()
    del raw["direct_identifiers"][1]["precision_threshold"]

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    message = str(excinfo.value)
    assert "TCKN" in message
    assert "precision_threshold" in message


def test_quasi_entry_with_recall_threshold_is_rejected() -> None:
    """A recall_threshold on a quasi entry is a category error, not a typo.

    Quasi-identifiers are validated by the red team. Letting one carry a recall
    floor would let an unvalidated contextual number be published as if it were
    an F1 gate.
    """
    raw = minimal_schema()
    raw["quasi_identifiers"][0]["recall_threshold"] = 0.90

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    message = str(excinfo.value)
    assert "EMPLOYER_ROLE" in message
    assert "recall_threshold" in message


def test_quasi_entry_with_precision_threshold_is_rejected() -> None:
    raw = minimal_schema()
    raw["quasi_identifiers"][0]["precision_threshold"] = 1.0

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "precision_threshold" in str(excinfo.value)


def test_unknown_detector_is_rejected() -> None:
    raw = minimal_schema()
    raw["direct_identifiers"][0]["detector"] = "vibes"

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    message = str(excinfo.value)
    assert "PATIENT_NAME" in message
    assert "vibes" in message


def test_duplicate_entity_id_is_rejected() -> None:
    raw = minimal_schema()
    duplicate = copy.deepcopy(raw["direct_identifiers"][0])
    raw["direct_identifiers"].append(duplicate)

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "duplicate entity id" in str(excinfo.value)
    assert "PATIENT_NAME" in str(excinfo.value)


def test_duplicate_id_across_classes_is_rejected() -> None:
    raw = minimal_schema()
    raw["quasi_identifiers"][0]["id"] = "PATIENT_NAME"

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "duplicate entity id" in str(excinfo.value)


def test_direct_entry_with_wrong_identifier_class_is_rejected() -> None:
    raw = minimal_schema()
    raw["direct_identifiers"][0]["identifier_class"] = "quasi"

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "identifier_class" in str(excinfo.value)


def test_quasi_entry_scored_by_f1_is_rejected() -> None:
    raw = minimal_schema()
    raw["quasi_identifiers"][0]["scored_by_f1"] = True

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "scored_by_f1" in str(excinfo.value)


def test_precision_threshold_on_non_checksum_entry_is_rejected() -> None:
    raw = minimal_schema()
    raw["direct_identifiers"][0]["precision_threshold"] = 0.95

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "PATIENT_NAME" in str(excinfo.value)


def test_missing_section_is_rejected() -> None:
    raw = minimal_schema()
    del raw["quasi_identifiers"]

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(raw)

    assert "quasi_identifiers" in str(excinfo.value)


def test_real_schema_loads_and_validates_clean() -> None:
    schema = load_schema(DEFAULT_SCHEMA_PATH)

    assert schema.meta["language"] == ["tr"]
    assert "PATIENT_NAME" in schema.direct_ids
    assert "TCKN" in schema.checksum_validatable_ids
    assert "EMPLOYER_ROLE" in schema.quasi_ids
    assert "DIAGNOSIS" in schema.allowlist_ids
    # No label may straddle two classes; the three scoring mechanisms depend on
    # the partition being clean.
    assert not schema.direct_ids & schema.quasi_ids
    assert not schema.direct_ids & schema.allowlist_ids


def test_real_schema_checksum_entries_all_carry_precision_floor() -> None:
    schema = load_schema(DEFAULT_SCHEMA_PATH)
    checksum_entities = [e for e in schema.direct if e.checksum_validatable]

    assert checksum_entities, "expected at least one checksum-validatable entity"
    for entity in checksum_entities:
        assert entity.precision_threshold == 1.0, entity.id


def _corpus_files() -> list[Path]:
    files: list[Path] = []
    for root in (GOLD_DIR, ADVERSARIAL_DIR):
        if root.is_dir():
            files.extend(
                path
                for path in root.rglob("*.jsonl")
                if not any(part.startswith(".") for part in path.parts)
            )
    return files


def test_every_label_in_the_corpus_exists_in_the_schema() -> None:
    if not _corpus_files():
        pytest.skip("no gold or adversarial fixtures present yet")

    schema = load_schema(DEFAULT_SCHEMA_PATH)
    try:
        documents = load_corpus(schema=schema)
    except GoldError as exc:  # pragma: no cover - surfaces a fixture defect
        pytest.fail(f"corpus failed to resolve: {exc}")

    unknown: set[str] = set()
    for document in documents:
        for span in document.spans:
            if span.label not in schema.all_ids:
                unknown.add(span.label)

    assert not unknown, f"labels used in fixtures but absent from schema: {unknown}"
