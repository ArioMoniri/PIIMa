"""Tests for the scoring engine.

The central assertion in this file is an ASYMMETRY. Against a detector that
finds nothing, per-entity recall is 0.0 and the document leak rate is 1.0, but
the medical-term false-positive rate is 0.0 - masking nothing cannot destroy a
clinical term. Any refactor that "simplifies" the three headline numbers into
one blended score breaks that asymmetry, and a blended score is exactly how a
system that leaks names ends up looking respectable on a leaderboard.

The second assertion is that an unvalidated contextual tier reports None, never
0.0. A red-team run that never happened is not a red-team run that found
nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from eval.build_gold import Document, load_corpus
from eval.harness import (
    NullDetector,
    PredictedSpan,
    evaluate,
    load_redteam_report,
    match_spans,
)
from eval.report import Gate, build_gates
from eval.schema import Schema, load_schema, load_thresholds

# Every identifier-shaped value below is synthetic. The TCKN is deliberately
# checksum-INVALID (its final check digit is wrong), so the I8 pre-commit hook
# never has to reject this file.
PATIENT_DOC = {
    "doc_id": "tr-harness-0001",
    "split": "dev",
    "note_type": "outpatient_note",
    "text": (
        "Hasta Ayşe Yılmaz'ın carcinoma tanısı ile takip edilmektedir. "
        "TCKN 12345678951 olarak kaydedildi. "
        "Merkez Bankası'nda çalışıyor."
    ),
    "spans": [
        {"quote": "Ayşe Yılmaz", "label": "PATIENT_NAME"},
        {"quote": "12345678951", "label": "TCKN"},
    ],
    "quasi_spans": [
        {
            "quote": "Merkez Bankası'nda çalışıyor",
            "label": "EMPLOYER_ROLE",
            "reason": "named employer narrows the candidate population",
        }
    ],
    "allowlist_terms": [{"quote": "carcinoma", "category": "DIAGNOSIS"}],
}

CLINICIAN_DOC = {
    "doc_id": "tr-harness-0002",
    "split": "sight_unseen",
    "note_type": "radiology_report",
    "text": (
        "Op. Dr. Şükrü Gökçe değerlendirdi. MRI'da lezyon saptandı. "
        "Protokol No: 2026-0004312"
    ),
    "spans": [
        {"quote": "Şükrü Gökçe", "label": "CLINICIAN_NAME"},
        {"quote": "2026-0004312", "label": "MRN"},
    ],
    "allowlist_terms": [{"quote": "MRI", "category": "ABBREVIATION"}],
}


def _contextual_gate(metrics: Any, schema: Schema) -> Gate:
    """The contextual_reid_rate_max gate as the release report would render it."""
    gates = build_gates(metrics, schema, load_thresholds())
    for gate in gates:
        if gate.name == "contextual_reid_rate_max":
            return gate
    raise AssertionError("contextual_reid_rate_max gate is missing")


class ChecksumClaimingDetector:
    """Emits ONE span and says whether a checksum validated it.

    Exists to separate the two claims the checksum gate used to conflate: a span
    LABELLED TCKN, and a span a checksum VOUCHED FOR.
    """

    def __init__(self, quote: str, label: str, *, checksum_validated: bool) -> None:
        self._quote = quote
        self._label = label
        self._validated = checksum_validated

    @property
    def name(self) -> str:
        return "checksum-claiming"

    def predict(self, text: str) -> list[PredictedSpan]:
        index = text.encode("utf-8").find(self._quote.encode("utf-8"))
        if index < 0:
            return []
        return [
            PredictedSpan(
                start=index,
                end=index + len(self._quote.encode("utf-8")),
                label=self._label,
                confidence=1.0,
                checksum_validated=self._validated,
            )
        ]


class PerfectDetector:
    """An oracle built from the gold spans.

    It lives in the test suite and is deliberately unreachable from eval/run.py:
    a benchmark runner that can be pointed at an oracle is a benchmark runner
    that can manufacture a model card.
    """

    def __init__(self, documents: list[Document]) -> None:
        self._by_text: dict[str, list[PredictedSpan]] = {
            document.text: [
                PredictedSpan(
                    start=span.start, end=span.end, label=span.label, confidence=1.0
                )
                for span in document.spans
            ]
            for document in documents
        }

    @property
    def name(self) -> str:
        return "perfect"

    def predict(self, text: str) -> list[PredictedSpan]:
        return list(self._by_text.get(text, []))


class FixedSpanDetector:
    """Emits a caller-supplied span set, keyed by the quote it should cover."""

    def __init__(self, targets: list[tuple[str, str]]) -> None:
        self._targets = targets

    @property
    def name(self) -> str:
        return "fixed"

    def predict(self, text: str) -> list[PredictedSpan]:
        encoded = text.encode("utf-8")
        spans: list[PredictedSpan] = []
        for quote, label in self._targets:
            index = text.find(quote)
            if index == -1:
                continue
            start = len(text[:index].encode("utf-8"))
            end = start + len(quote.encode("utf-8"))
            assert encoded[start:end].decode("utf-8") == quote
            spans.append(PredictedSpan(start=start, end=end, label=label))
        return spans


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


@pytest.fixture
def corpus(tmp_path: Path, schema: Schema) -> list[Document]:
    path = tmp_path / "fixtures.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(record, ensure_ascii=False)
            for record in (PATIENT_DOC, CLINICIAN_DOC)
        )
        + "\n",
        encoding="utf-8",
    )
    return load_corpus([tmp_path], schema)


@pytest.fixture
def no_redteam(tmp_path: Path) -> Path:
    return tmp_path / "no-such-redteam-report.json"


def test_null_detector_recall_is_zero_for_every_direct_type(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    metrics = evaluate(corpus, NullDetector(), schema, no_redteam)

    assert set(metrics.per_entity_relaxed) == {
        "PATIENT_NAME",
        "TCKN",
        "CLINICIAN_NAME",
        "MRN",
    }
    for label, counts in metrics.per_entity_relaxed.items():
        assert counts.gold > 0, label
        assert counts.recall == 0.0, f"{label} recall must be exactly 0.0"
    assert metrics.micro_direct_relaxed.recall == 0.0


def test_null_detector_medical_term_fp_rate_is_exactly_zero(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    """Masking nothing cannot mask a medical term.

    This asymmetry against the 0.0 recall above is the whole reason the three
    numbers are reported separately rather than blended.
    """
    metrics = evaluate(corpus, NullDetector(), schema, no_redteam)

    assert metrics.medical_terms_total == 2
    assert metrics.medical_terms_masked == 0
    assert metrics.medical_term_fp_rate == 0.0
    assert metrics.micro_direct_relaxed.recall == 0.0


def test_null_detector_contextual_coverage_zero_but_reid_rate_is_none(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    """Absence of a red-team run is not a passing score."""
    metrics = evaluate(corpus, NullDetector(), schema, no_redteam)

    assert metrics.contextual.gold_quasi_spans == 1
    assert metrics.contextual.coverage == 0.0
    assert metrics.contextual.reid_rate is None
    assert metrics.contextual.reid_rate is not metrics.contextual.coverage
    assert metrics.contextual.validated_by is None


def test_perfect_detector_scores_recall_one_on_every_direct_type(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    metrics = evaluate(corpus, PerfectDetector(corpus), schema, no_redteam)

    for label, counts in metrics.per_entity_relaxed.items():
        assert counts.recall == 1.0, label
    assert metrics.micro_direct_relaxed.recall == 1.0
    assert metrics.micro_direct_strict.recall == 1.0
    assert metrics.document_leak_rate == 0.0
    # NOT 1.0, and the difference is the point. The perfect detector reproduces
    # the gold LABELS; it validates no checksum, and I8 guarantees there is no
    # checksum-valid Turkish ID in this repository for it to validate. Checksum
    # precision therefore has an empty denominator and reports n/a. It used to
    # report 0.9902 by counting spans selected by label, which was a number
    # about annotation.
    assert metrics.checksum_id_precision is None
    assert metrics.checksum_id_counts.predicted == 0


def test_masking_an_allowlist_term_is_penalised(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    detector = FixedSpanDetector([("carcinoma", "PATIENT_NAME")])

    metrics = evaluate(corpus, detector, schema, no_redteam)

    assert metrics.medical_terms_masked == 1
    assert metrics.medical_terms_total == 2
    assert metrics.medical_term_fp_rate == pytest.approx(0.5)


def test_document_leak_rate_is_one_with_null_detector(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    for document in corpus:
        assert document.direct_spans(schema), document.doc_id

    metrics = evaluate(corpus, NullDetector(), schema, no_redteam)

    assert metrics.documents_leaking == len(corpus)
    assert metrics.document_leak_rate == 1.0


QUASI_ONLY_DOC = {
    "doc_id": "tr-harness-0003",
    "split": "dev",
    "note_type": "outpatient_note",
    # No direct identifier anywhere: this document cannot leak one.
    "text": "Merkez Bankası'nda çalışıyor. carcinoma takibi sürüyor.",
    "spans": [],
    "quasi_spans": [
        {"quote": "Merkez Bankası'nda çalışıyor", "label": "EMPLOYER_ROLE"}
    ],
    "allowlist_terms": [{"quote": "carcinoma", "category": "DIAGNOSIS"}],
}


def test_leak_rate_reports_both_denominators_explicitly(
    tmp_path: Path, schema: Schema, no_redteam: Path
) -> None:
    """A document with no direct identifier cannot leak one.

    Including it in the denominator drags the reported leak rate DOWN under a
    detector that found nothing, which reads to an auditor as if those
    documents were handled correctly. Both denominators are therefore carried.
    """
    path = tmp_path / "fixtures.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(record, ensure_ascii=False)
            for record in (PATIENT_DOC, CLINICIAN_DOC, QUASI_ONLY_DOC)
        )
        + "\n",
        encoding="utf-8",
    )
    corpus = load_corpus([tmp_path], schema)

    metrics = evaluate(corpus, NullDetector(), schema, no_redteam)

    assert metrics.documents == 3
    assert metrics.documents_with_direct_spans == 2
    assert metrics.documents_without_direct_spans == 1
    assert metrics.documents_leaking == 2
    # The misleading number: 2/3, as if one document had been de-identified.
    assert metrics.document_leak_rate == pytest.approx(2 / 3)
    # The honest one: every document that could leak, did.
    assert metrics.document_leak_rate_over_leakable == 1.0

    direct = metrics.as_dict()["direct"]
    assert direct["documents_with_direct_spans"] == 2
    assert direct["documents_excluded_no_direct_identifier"] == 1
    assert direct["documents_leaked"] == 2
    assert direct["document_leak_rate_over_documents_with_direct_spans"] == 1.0
    assert direct["document_leak_rate_over_all_documents"] == pytest.approx(2 / 3)


def test_relaxed_credits_the_turkish_case_suffix_but_strict_does_not(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    """A span swallowing `'in` caught the name; it has not leaked anything.

    Letting a boundary convention count that as a miss would inflate the miss
    rate and push effort toward tuning boundaries instead of catching
    identifiers.
    """
    detector = FixedSpanDetector([("Ayşe Yılmaz'ın", "PATIENT_NAME")])

    metrics = evaluate(corpus, detector, schema, no_redteam)

    relaxed = metrics.per_entity_relaxed["PATIENT_NAME"]
    strict = metrics.per_entity_strict["PATIENT_NAME"]

    assert relaxed.recall == 1.0, "relaxed matching must credit the suffixed span"
    assert strict.recall == 0.0, "strict matching must not credit it"


def test_matching_is_one_to_one(schema: Schema, corpus: list[Document]) -> None:
    """One span covering the whole note must not match every gold span in it."""
    document = corpus[0]
    whole_note = PredictedSpan(
        start=0,
        end=len(document.text.encode("utf-8")),
        label="PATIENT_NAME",
    )
    gold = [span for span in document.spans if span.label == "PATIENT_NAME"]

    outcome = match_spans(gold, [whole_note, whole_note], strict=False)

    assert outcome.counts["PATIENT_NAME"].true_positives == 1


def test_label_disagreement_is_not_a_match(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    detector = FixedSpanDetector([("Ayşe Yılmaz", "CLINICIAN_NAME")])

    metrics = evaluate(corpus, detector, schema, no_redteam)

    assert metrics.per_entity_relaxed["PATIENT_NAME"].recall == 0.0


def test_checksum_precision_ignores_spans_no_checksum_validated(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    """A TCKN label is not a checksum result.

    The detector below finds the gold TCKN exactly, and claims no checksum. The
    metric must stay n/a: on this corpus I8 guarantees no eleven-digit run
    passes its check digits, so a 0.9902 here would be a number about labelling
    dressed up as a number about validation.
    """
    detector = ChecksumClaimingDetector("12345678951", "TCKN", checksum_validated=False)

    metrics = evaluate(corpus, detector, schema, no_redteam)

    assert metrics.per_entity_relaxed["TCKN"].recall == 1.0
    assert metrics.checksum_id_precision is None
    assert metrics.checksum_id_counts.predicted == 0


def test_checksum_precision_counts_only_actually_validated_spans(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    validated = ChecksumClaimingDetector("12345678951", "TCKN", checksum_validated=True)
    metrics = evaluate(corpus, validated, schema, no_redteam)
    assert metrics.checksum_id_counts.predicted == 1
    assert metrics.checksum_id_precision == 1.0

    # A checksum-validated span that is NOT a gold identifier is the failure the
    # 1.000 gate exists to catch, and it must be able to fail.
    wrong = ChecksumClaimingDetector("carcinoma", "TCKN", checksum_validated=True)
    metrics = evaluate(corpus, wrong, schema, no_redteam)
    assert metrics.checksum_id_counts.predicted == 1
    assert metrics.checksum_id_precision == 0.0


def _redteam_report(
    tmp_path: Path,
    *,
    masker: str,
    detector: str | None,
    eval_sha: str | None,
    rate: float = 0.04,
) -> Path:
    """Write a red-team report with caller-chosen provenance."""
    report_path = tmp_path / f"redteam-{masker}.json"
    report_path.write_text(
        json.dumps(
            {
                "masker": masker,
                "masker_kind": "pipeline" if masker == "pipeline" else "reference",
                "contextual_reid_rate": rate,
                "reid_rate_measured": rate,
                "validated_by": f"l6_reid_red_team (masker={masker})",
                "provenance": {"detector": detector, "eval_sha": eval_sha},
            }
        ),
        encoding="utf-8",
    )
    return report_path


def test_redteam_report_supplies_the_authoritative_reid_rate(
    corpus: list[Document], schema: Schema, tmp_path: Path
) -> None:
    report_path = _redteam_report(
        tmp_path, masker="pipeline", detector="null", eval_sha="deadbeef"
    )

    metrics = evaluate(corpus, NullDetector(), schema, report_path, eval_sha="deadbeef")

    assert metrics.contextual.reid_rate == pytest.approx(0.04)
    assert metrics.contextual.validated_by == "l6_reid_red_team (masker=pipeline)"
    assert metrics.contextual.provenance.accepted is True


def test_a_report_from_a_reference_masker_leaves_the_gate_unenforceable(
    corpus: list[Document], schema: Schema, tmp_path: Path
) -> None:
    """THE REGRESSION. A gate a null detector can pass is not a gate.

    `contextual_reid_rate = 0.0303 PASS` was byte-identical for the null
    detector, the L1-only pipeline and the full pipeline, because the committed
    report had been produced against OracleMasker and the harness read it
    whatever it was scoring. The rate must now be VISIBLE and UNGATED.
    """
    report_path = _redteam_report(
        tmp_path, masker="oracle", detector="null", eval_sha="deadbeef", rate=0.0303
    )

    metrics = evaluate(corpus, NullDetector(), schema, report_path, eval_sha="deadbeef")

    assert metrics.contextual.reid_rate is None, (
        "an oracle-derived rate must never populate the gate"
    )
    assert metrics.contextual.validated_by is None
    provenance = metrics.contextual.provenance
    assert provenance.accepted is False
    assert provenance.measured_reid_rate == pytest.approx(0.0303)
    assert provenance.rejected_because is not None
    assert "oracle" in provenance.rejected_because

    gate = _contextual_gate(metrics, schema)
    assert gate.passed is None, "UNENFORCEABLE, not PASS"
    assert gate.verdict == "UNENFORCEABLE"


def test_a_report_from_a_different_detector_leaves_the_gate_unenforceable(
    corpus: list[Document], schema: Schema, tmp_path: Path
) -> None:
    report_path = _redteam_report(
        tmp_path,
        masker="pipeline",
        detector="pipeline:safe_harbor",
        eval_sha="deadbeef",
    )

    metrics = evaluate(corpus, NullDetector(), schema, report_path, eval_sha="deadbeef")

    assert metrics.contextual.reid_rate is None
    assert _contextual_gate(metrics, schema).passed is None


def test_a_report_from_a_different_eval_sha_leaves_the_gate_unenforceable(
    corpus: list[Document], schema: Schema, tmp_path: Path
) -> None:
    report_path = _redteam_report(
        tmp_path, masker="pipeline", detector="null", eval_sha="0000000"
    )

    metrics = evaluate(corpus, NullDetector(), schema, report_path, eval_sha="deadbeef")

    assert metrics.contextual.reid_rate is None
    assert _contextual_gate(metrics, schema).passed is None


def test_load_redteam_report_returns_none_when_absent(tmp_path: Path) -> None:
    provenance = load_redteam_report(tmp_path / "absent.json")

    assert provenance.gated_rate is None
    assert provenance.measured_reid_rate is None
    assert provenance.accepted is False


def test_sight_unseen_recall_drop_is_reported(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    detector = FixedSpanDetector(
        [("Ayşe Yılmaz", "PATIENT_NAME"), ("12345678951", "TCKN")]
    )

    metrics = evaluate(corpus, detector, schema, no_redteam)

    assert metrics.recall_by_split["dev"] == 1.0
    assert metrics.recall_by_split["sight_unseen"] == 0.0
    assert metrics.sight_unseen_recall_drop == pytest.approx(1.0)


def test_artifact_shape_keeps_coverage_and_reid_rate_distinct(
    corpus: list[Document], schema: Schema, no_redteam: Path
) -> None:
    metrics = evaluate(corpus, NullDetector(), schema, no_redteam)

    payload: dict[str, Any] = metrics.as_dict()
    contextual = payload["contextual"]

    assert contextual["coverage_is_diagnostic_only"] is True
    assert contextual["reid_rate_is_authoritative"] is True
    assert contextual["reid_rate"] is None
    assert contextual["coverage"] == 0.0
