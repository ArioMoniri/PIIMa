"""Tests for quote-to-byte-offset resolution.

Two failure modes are being guarded here, and both of them inflate recall,
which is the direction of error a de-identification benchmark must never drift
in:

  1. A silently dropped gold span shrinks the denominator, so a system that
     misses an identifier scores as if the identifier was never there.
  2. A character index used where a byte offset is expected lands the span in
     the wrong place on any line containing Turkish characters, so the span
     appears to be a miss (or a false positive) for reasons that have nothing to
     do with detection.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from eval.build_gold import (
    ATTACK_CLASSES,
    L6_ATTACK_CLASSES,
    GoldError,
    attack_class_coverage,
    build_resolved,
    load_corpus,
    resolve_quote,
    summarise,
)
from eval.schema import REPO_ROOT, Schema, load_schema

GOLD_DIR = REPO_ROOT / "eval" / "gold"
ADVERSARIAL_DIR = REPO_ROOT / "eval" / "adversarial"


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


def write_corpus(directory: Path, records: list[dict[str, Any]]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "fixtures.jsonl"
    path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )
    return path


def test_missing_quote_raises_naming_the_doc_id(tmp_path: Path, schema: Schema) -> None:
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0001",
                "split": "dev",
                "text": "Hasta Ayşe Yılmaz muayene edildi.",
                "spans": [
                    {"quote": "Mehmet Öztürk", "label": "PATIENT_NAME"},
                ],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    message = str(excinfo.value)
    assert "tr-test-0001" in message, "the error must name the document"
    assert "Mehmet Öztürk" in message, "the error must name the quote"


def test_occurrence_beyond_available_occurrences_raises(
    tmp_path: Path, schema: Schema
) -> None:
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0002",
                "split": "dev",
                "text": "Ayşe geldi. Ayşe gitti.",
                "spans": [
                    {"quote": "Ayşe", "label": "PATIENT_NAME", "occurrence": 3},
                ],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    message = str(excinfo.value)
    assert "tr-test-0002" in message
    assert "occurrence 3" in message
    assert "2 occurrence" in message


def test_offsets_are_byte_offsets_not_character_indices(
    tmp_path: Path, schema: Schema
) -> None:
    """Multi-byte Turkish characters before a span push its BYTE offset higher."""
    text = "Şişli'de Ayşe Yılmaz muayene edildi."
    quote = "Ayşe Yılmaz"
    character_index = text.index(quote)

    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0003",
                "split": "dev",
                "text": text,
                "spans": [{"quote": quote, "label": "PATIENT_NAME"}],
            }
        ],
    )

    documents = load_corpus([tmp_path], schema)
    span = documents[0].spans[0]

    assert span.start > character_index, (
        "Ş, i-dotless and ş before the span are two bytes each, so the byte "
        "offset must exceed the character index"
    )
    encoded = text.encode("utf-8")
    assert encoded[span.start : span.end].decode("utf-8") == quote
    assert span.end - span.start == len(quote.encode("utf-8"))
    assert span.end - span.start > len(quote), "the quote itself is multi-byte"


def test_resolved_offsets_land_on_utf8_character_boundaries(
    tmp_path: Path, schema: Schema
) -> None:
    text = (
        "Hasta Ayşe Yılmaz'ın carcinoma tanısı; Op. Dr. Şükrü Gökçe "
        "değerlendirdi. MRI'da lezyon görüldü."
    )
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0004",
                "split": "dev",
                "text": text,
                "spans": [
                    {"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"},
                    {"quote": "Şükrü Gökçe", "label": "CLINICIAN_NAME"},
                ],
                "allowlist_terms": [
                    {"quote": "carcinoma", "category": "DIAGNOSIS"},
                    {"quote": "MRI", "category": "ABBREVIATION"},
                ],
            }
        ],
    )

    documents = load_corpus([tmp_path], schema)
    encoded = text.encode("utf-8")

    spans = list(documents[0].spans) + list(documents[0].allowlist_terms)
    assert spans
    for span in spans:
        for offset in (span.start, span.end):
            assert 0 <= offset <= len(encoded)
            if offset < len(encoded):
                # 0b10xxxxxx is a UTF-8 continuation byte; an offset pointing at
                # one has landed inside a character.
                assert encoded[offset] & 0b1100_0000 != 0b1000_0000, (
                    f"offset {offset} lands inside a UTF-8 character"
                )
        assert encoded[: span.start].decode("utf-8", errors="strict") is not None


def test_occurrence_selects_the_nth_match(tmp_path: Path, schema: Schema) -> None:
    text = "Ayşe geldi. Ayşe gitti. Ayşe döndü."
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0005",
                "split": "dev",
                "text": text,
                "spans": [
                    {"quote": "Ayşe", "label": "PATIENT_NAME", "occurrence": 2},
                ],
            }
        ],
    )

    span = load_corpus([tmp_path], schema)[0].spans[0]
    encoded = text.encode("utf-8")
    first = len(text[: text.index("Ayşe")].encode("utf-8"))

    assert span.start > first
    assert encoded[span.start : span.end].decode("utf-8") == "Ayşe"


def test_unknown_label_is_a_hard_error(tmp_path: Path, schema: Schema) -> None:
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0006",
                "split": "dev",
                "text": "Hasta Ayşe Yılmaz.",
                "spans": [{"quote": "Ayşe Yılmaz", "label": "NOT_A_REAL_LABEL"}],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    assert "NOT_A_REAL_LABEL" in str(excinfo.value)
    assert "tr-test-0006" in str(excinfo.value)


def test_duplicate_doc_id_is_a_hard_error(tmp_path: Path, schema: Schema) -> None:
    write_corpus(
        tmp_path,
        [
            {"doc_id": "tr-test-0007", "split": "dev", "text": "Bir.", "spans": []},
            {"doc_id": "tr-test-0007", "split": "dev", "text": "Iki.", "spans": []},
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    assert "duplicate doc_id" in str(excinfo.value)


def test_resolve_quote_rejects_empty_and_zero_occurrence() -> None:
    with pytest.raises(GoldError):
        resolve_quote("metin", "", 1, "where")
    with pytest.raises(GoldError):
        resolve_quote("metin", "met", 0, "where")


def test_build_resolved_writes_byte_offsets(tmp_path: Path, schema: Schema) -> None:
    write_corpus(
        tmp_path / "corpus",
        [
            {
                "doc_id": "tr-test-0008",
                "split": "dev",
                "text": "Şişli'de Ayşe Yılmaz.",
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
            }
        ],
    )
    documents = load_corpus([tmp_path / "corpus"], schema)
    out_path = build_resolved(documents, tmp_path / "build" / "resolved.json")

    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["offset_unit"] == "utf8_bytes"
    assert payload["documents"][0]["spans"][0]["start"] == 11


def test_summarise_separates_direct_quasi_and_allowlist(
    tmp_path: Path, schema: Schema
) -> None:
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0009",
                "split": "dev",
                "text": (
                    "Hasta Ayşe Yılmaz, Merkez Bankası'nda çalışıyor; "
                    "carcinoma tanısı mevcut."
                ),
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
                "quasi_spans": [
                    {
                        "quote": "Merkez Bankası'nda çalışıyor",
                        "label": "EMPLOYER_ROLE",
                    }
                ],
                "allowlist_terms": ["carcinoma"],
            }
        ],
    )

    counts = summarise(load_corpus([tmp_path], schema), schema)

    assert counts["documents"] == 1
    assert counts["direct_spans"] == 1
    assert counts["quasi_spans"] == 1
    assert counts["allowlist_terms"] == 1


def test_quasi_spans_key_is_resolved_not_ignored(
    tmp_path: Path, schema: Schema
) -> None:
    """Regression: `quasi_spans` was once read by nobody.

    Contextual gold spans live under their own key. A loader that reads only
    `spans` drops the entire contextual class silently, which makes the
    contextual coverage figure look undefined when it is in fact unmeasured.
    """
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0010",
                "split": "dev",
                "text": (
                    "Hasta Ayşe Yılmaz, Merkez Bankası'nda çalışıyor ve "
                    "eşi tanınmış bir hâkim."
                ),
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
                "quasi_spans": [
                    {
                        "quote": "Merkez Bankası'nda çalışıyor",
                        "label": "EMPLOYER_ROLE",
                        "reason": "named employer narrows the population",
                    },
                    {"quote": "eşi tanınmış bir hâkim", "label": "RELATIONSHIP_REF"},
                ],
            }
        ],
    )

    document = load_corpus([tmp_path], schema)[0]

    assert len(document.direct_spans(schema)) == 1
    assert len(document.quasi_spans(schema)) == 2
    employer = next(
        span for span in document.quasi_spans(schema) if span.label == "EMPLOYER_ROLE"
    )
    assert employer.reason == "named employer narrows the population"

    encoded = document.text.encode("utf-8")
    for span in document.quasi_spans(schema):
        assert encoded[span.start : span.end].decode("utf-8") == span.quote


def test_quasi_label_in_spans_is_rejected(tmp_path: Path, schema: Schema) -> None:
    """Scoring a quasi-identifier by F1 is the category error the schema forbids."""
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0011",
                "split": "dev",
                "text": "Merkez Bankası'nda çalışıyor.",
                "spans": [
                    {
                        "quote": "Merkez Bankası'nda çalışıyor",
                        "label": "EMPLOYER_ROLE",
                    }
                ],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    message = str(excinfo.value)
    assert "EMPLOYER_ROLE" in message
    assert "quasi_spans" in message


def test_direct_label_in_quasi_spans_is_rejected(
    tmp_path: Path, schema: Schema
) -> None:
    """A direct identifier hidden in quasi_spans escapes the recall gates."""
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0012",
                "split": "dev",
                "text": "Hasta Ayşe Yılmaz.",
                "spans": [],
                "quasi_spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    message = str(excinfo.value)
    assert "PATIENT_NAME" in message
    assert "recall" in message


def test_unrecognised_fixture_key_is_rejected(tmp_path: Path, schema: Schema) -> None:
    """An ignored key is how a whole scoring class goes unmeasured."""
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0013",
                "split": "dev",
                "text": "Hasta Ayşe Yılmaz.",
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
                "contextual_spans": [{"quote": "Ayşe", "label": "EMPLOYER_ROLE"}],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    assert "contextual_spans" in str(excinfo.value)


def test_unknown_attack_class_is_a_hard_error(tmp_path: Path, schema: Schema) -> None:
    """The enum is closed: a typo must not invent a class."""
    write_corpus(
        tmp_path,
        [
            {
                "doc_id": "tr-test-0014",
                "split": "adversarial",
                "text": "Hasta Ayşe Yılmaz.",
                "attack_class": "narrative_survivel",
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([tmp_path], schema)

    message = str(excinfo.value)
    assert "narrative_survivel" in message
    assert "narrative_survival" in message, "the error must list the legal values"


def test_adversarial_fixture_without_attack_class_is_rejected(
    tmp_path: Path, schema: Schema
) -> None:
    """Free prose is not groupable; a fixture with no class is invisible."""
    adversarial = tmp_path / "adversarial"
    write_corpus(
        adversarial,
        [
            {
                "doc_id": "tr-test-0015",
                "split": "adversarial",
                "text": "Hasta Ayşe Yılmaz.",
                "attack": "A paragraph of prose, unique to this fixture.",
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
            }
        ],
    )

    with pytest.raises(GoldError) as excinfo:
        load_corpus([adversarial], schema)

    assert "attack_class" in str(excinfo.value)
    assert "tr-test-0015" in str(excinfo.value)


def test_attack_class_coverage_reports_classes_with_zero_fixtures(
    tmp_path: Path, schema: Schema
) -> None:
    """A gap must appear as a zero row, not as a missing row."""
    adversarial = tmp_path / "adversarial"
    write_corpus(
        adversarial,
        [
            {
                "doc_id": "tr-test-0016",
                "split": "adversarial",
                "text": "Hasta Ayşe Yılmaz.",
                "attack_class": "narrative_survival",
                "spans": [{"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"}],
            }
        ],
    )

    documents = load_corpus([adversarial], schema)
    coverage = attack_class_coverage(documents)

    assert set(coverage) == set(ATTACK_CLASSES), "every class must have a row"
    assert coverage["narrative_survival"] == 1
    assert coverage["format_tells"] == 0

    counts = summarise(documents, schema)
    assert counts["adversarial_documents"] == 1
    assert "format_tells" in counts["l6_attack_classes_with_no_fixture"]
    assert "narrative_survival" not in counts["l6_attack_classes_with_no_fixture"]


def _corpus_roots() -> list[Path]:
    return [root for root in (GOLD_DIR, ADVERSARIAL_DIR) if root.is_dir()]


def test_real_corpus_resolves_with_zero_errors(schema: Schema) -> None:
    roots = _corpus_roots()
    if not roots or not any(root.rglob("*.jsonl") for root in roots):
        pytest.skip("no gold or adversarial fixtures present yet")

    documents = load_corpus(roots, schema)

    assert documents, "corpus files exist but resolved to zero documents"
    for document in documents:
        encoded = document.text.encode("utf-8")
        for span in document.spans:
            assert encoded[span.start : span.end].decode("utf-8") == span.quote
        for term in document.allowlist_terms:
            assert encoded[term.start : term.end].decode("utf-8") == term.term

    schema_obj = load_schema()
    assert any(document.direct_spans(schema_obj) for document in documents)
    # Every committed adversarial fixture carries a machine-readable class, so
    # L6 coverage is countable rather than buried in 38 unique paragraphs.
    adversarial = [document for document in documents if document.is_adversarial]
    if adversarial:
        assert all(document.attack_class in ATTACK_CLASSES for document in adversarial)
        coverage = attack_class_coverage(documents)
        assert sum(coverage.values()) == len(adversarial)
        assert any(coverage[name] > 0 for name in L6_ATTACK_CLASSES), (
            "the adversarial corpus must exercise at least one L6 attack class"
        )
    # The contextual track is the differentiator; a corpus that resolved zero
    # quasi spans would mean the loader is dropping them again.
    assert any(document.quasi_spans(schema_obj) for document in documents)
