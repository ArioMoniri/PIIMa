"""Tests for gate reporting.

The assertion this file exists for: AN UNENFORCEABLE GATE IS NOT A PASSING GATE.

Two of the ten non-negotiable release gates - `micro_f1_direct` and
`checksum_id_precision` - are precision-derived, and precision over an empty
prediction set is undefined. So against a detector that predicts nothing, those
two gates cannot fail. That is mathematically correct and it is exactly the
situation in which a report must be loudest, because the failure looks like
silence. These tests pin the three properties that make the silence readable:
`passed` is None rather than True, the rendered verdict is never PASS, and the
artifact carries an explicit list of what was not evaluated and why.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from eval.build_gold import Document, load_corpus
from eval.harness import NullDetector, PredictedSpan, evaluate
from eval.report import (
    Gate,
    build_gates,
    gates_as_dict,
    gates_summary,
    render,
    unenforceable_gates,
)
from eval.schema import Schema, load_schema, load_thresholds

DOC = {
    "doc_id": "tr-report-0001",
    "split": "dev",
    "note_type": "outpatient_note",
    # The TCKN is deliberately checksum-INVALID (I8).
    "text": "Hasta Ayşe Yılmaz, TCKN 12345678951 ile kaydedildi.",
    "spans": [
        {"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"},
        {"quote": "12345678951", "label": "TCKN"},
    ],
}


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


@pytest.fixture(scope="module")
def thresholds() -> dict[str, Any]:
    return load_thresholds()


@pytest.fixture
def corpus(tmp_path: Path, schema: Schema) -> list[Document]:
    path = tmp_path / "fixtures.jsonl"
    path.write_text(json.dumps(DOC, ensure_ascii=False) + "\n", encoding="utf-8")
    return load_corpus([tmp_path], schema)


@pytest.fixture
def null_gates(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any], tmp_path: Path
) -> list[Gate]:
    metrics = evaluate(corpus, NullDetector(), schema, tmp_path / "absent.json")
    return build_gates(metrics, schema, thresholds)


def test_undefined_gate_does_not_report_passed(null_gates: list[Gate]) -> None:
    by_name = {gate.name: gate for gate in null_gates}

    for name in ("micro_f1_direct", "checksum_id_precision"):
        gate = by_name[name]
        assert gate.observed is None, f"{name} must be undefined under a null detector"
        assert gate.passed is None, f"{name} must not report passed=True"
        assert gate.passed is not True
        assert gate.enforceable is False


def test_unenforceable_verdict_is_never_rendered_as_pass(
    null_gates: list[Gate],
) -> None:
    for gate in null_gates:
        if gate.enforceable:
            continue
        assert gate.verdict == "UNENFORCEABLE"
        assert "PASS" not in gate.verdict


def test_unenforceable_gates_list_names_the_gate_and_the_reason(
    null_gates: list[Gate],
) -> None:
    blocked = unenforceable_gates(null_gates)
    named = {entry["gate"] for entry in blocked}

    assert "micro_f1_direct" in named
    assert "checksum_id_precision" in named
    for entry in blocked:
        assert entry["why"], f"{entry['gate']} must say why it could not be evaluated"

    micro_f1_reason = next(
        entry["why"] for entry in blocked if entry["gate"] == "micro_f1_direct"
    )
    assert "EMPTY PREDICTION SET" in micro_f1_reason

    # checksum_id_precision has a DIFFERENT empty set, and the difference is
    # load-bearing (D-030). It is not "the detector predicted nothing" - it is
    # "nothing was checksum-validated", which stays true even for a detector
    # that predicts every TCKN in the corpus, because I8 guarantees none of them
    # passes its check digits.
    checksum_reason = next(
        entry["why"] for entry in blocked if entry["gate"] == "checksum_id_precision"
    )
    assert "checksum-validated" in checksum_reason
    assert "I8" in checksum_reason


def test_gates_summary_counts_three_buckets(null_gates: list[Gate]) -> None:
    summary = gates_summary(null_gates)

    assert summary["total"] == len(null_gates)
    assert (
        summary["passed"] + summary["failed"] + summary["unenforceable"]
        == (summary["total"])
    )
    assert summary["unenforceable"] >= 2
    assert summary["all_gates_passed"] is False, (
        "a run with unenforceable gates has not met the release gates"
    )


def test_all_gates_passed_is_false_when_only_unenforceable_remain() -> None:
    """No failures is not all passed. This is the whole point."""
    gates = [
        Gate(name="a", threshold=0.5, observed=0.9, direction="floor"),
        Gate(name="b", threshold=0.5, observed=None, direction="floor"),
    ]

    summary = gates_summary(gates)

    assert summary["failed"] == 0
    assert summary["passed"] == 1
    assert summary["unenforceable"] == 1
    assert summary["all_gates_passed"] is False


def test_artifact_gate_entry_is_structurally_distinct(null_gates: list[Gate]) -> None:
    payload = gates_as_dict(null_gates)

    blocked = payload["checksum_id_precision"]
    assert blocked["pass"] is None
    assert blocked["enforceable"] is False
    assert blocked["verdict"] == "UNENFORCEABLE"
    assert isinstance(blocked["unenforceable_because"], str)

    passing_or_failing = [entry for entry in payload.values() if entry["enforceable"]]
    assert passing_or_failing, "the fixture must produce at least one real verdict"
    for entry in passing_or_failing:
        assert entry["pass"] in (True, False)
        assert entry["unenforceable_because"] is None


def test_render_names_the_unenforceable_gates(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any], tmp_path: Path
) -> None:
    metrics = evaluate(corpus, NullDetector(), schema, tmp_path / "absent.json")
    gates = build_gates(metrics, schema, thresholds)

    text = render(metrics, gates, enforcing=False)

    assert "UNENFORCEABLE" in text
    assert "NOT EVALUATED, THEREFORE NOT PASSED" in text
    assert "micro_f1_direct" in text
    # The gate table must not print PASS on the same line as an undefined value.
    for line in text.splitlines():
        if "micro_f1_direct" in line and "PASS" in line:
            pytest.fail(f"undefined gate rendered as a pass: {line!r}")


def test_leak_rate_gate_reads_the_leakable_denominator(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any], tmp_path: Path
) -> None:
    metrics = evaluate(corpus, NullDetector(), schema, tmp_path / "absent.json")
    gates = build_gates(metrics, schema, thresholds)

    gate = next(gate for gate in gates if gate.name == "document_leak_rate_max")

    assert gate.observed == metrics.document_leak_rate_over_leakable
    # Same numerator over a smaller denominator: never a weaker gate (I2).
    assert metrics.document_leak_rate is not None
    assert gate.observed is not None
    assert gate.observed >= metrics.document_leak_rate


# ---------------------------------------------------------------------------
# The medical-term gate must see BOTH denominators
# ---------------------------------------------------------------------------


class _VocabularyProbeDetector:
    """Masks every occurrence of one word that no fixture annotates.

    `ameliyat` is present in eval/allowlist/*.txt and annotated in ZERO
    fixtures. A detector that destroys it wrecks the clinical meaning of every
    note it appears in while leaving `fp_rate_annotated` at exactly 0.0, so it
    is the minimal reproduction of a gate reading the wrong denominator.
    """

    probe: str = "ameliyat"

    @property
    def name(self) -> str:
        return "vocabulary-probe"

    def predict(self, text: str) -> list[PredictedSpan]:
        import re

        spans: list[PredictedSpan] = []
        # Suffixed forms count: `ameliyattan` is the same destroyed term, and a
        # probe that only caught the bare root would understate the damage.
        for match in re.finditer(rf"{self.probe}\w*", text, flags=re.IGNORECASE):
            start = len(text[: match.start()].encode("utf-8"))
            end = start + len(match.group(0).encode("utf-8"))
            spans.append(PredictedSpan(start=start, end=end, label="PATIENT_NAME"))
        return spans


@pytest.fixture(scope="module")
def real_corpus(schema: Schema) -> list[Document]:
    from eval.build_gold import DEFAULT_CORPUS_ROOTS

    return load_corpus(DEFAULT_CORPUS_ROOTS, schema)


def test_medical_term_gate_fails_on_a_vocabulary_only_breach(
    real_corpus: list[Document],
    schema: Schema,
    thresholds: dict[str, Any],
    tmp_path: Path,
) -> None:
    """The failure the gate exists to catch, which it previously scored PASS."""
    metrics = evaluate(
        real_corpus, _VocabularyProbeDetector(), schema, tmp_path / "absent.json"
    )
    ceiling = thresholds["medical_terms"]["fp_rate_max"]

    # The premise: annotated is clean, vocabulary is breached.
    assert metrics.medical_term_fp_rate == 0.0
    assert metrics.vocabulary_terms_masked > 0
    assert metrics.medical_term_fp_rate_vocabulary is not None
    assert metrics.medical_term_fp_rate_vocabulary > ceiling

    gate = next(
        gate
        for gate in build_gates(metrics, schema, thresholds)
        if gate.name == "medical_term_fp_rate_max"
    )
    assert gate.observed == metrics.medical_term_fp_rate_vocabulary
    assert gate.passed is False, "a destroyed medical term must fail the gate"
    assert gate.verdict == "FAIL"


def test_medical_term_gate_reads_the_worse_of_the_two_denominators(
    real_corpus: list[Document],
    schema: Schema,
    thresholds: dict[str, Any],
    tmp_path: Path,
) -> None:
    metrics = evaluate(real_corpus, NullDetector(), schema, tmp_path / "absent.json")
    gate = next(
        gate
        for gate in build_gates(metrics, schema, thresholds)
        if gate.name == "medical_term_fp_rate_max"
    )
    assert gate.observed == max(
        metrics.medical_term_fp_rate or 0.0,
        metrics.medical_term_fp_rate_vocabulary or 0.0,
    )
    # A null detector masks nothing, so both denominators report a clean 0.0.
    assert gate.observed == 0.0
