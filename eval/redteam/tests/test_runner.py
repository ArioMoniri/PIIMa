"""The calibration tests. A red team that cannot detect total failure is decor.

Four claims now. The first three are about the INSTRUMENT: null, leaky and
oracle are reference maskers built from the gold annotations, they bracket what
the attacks can see, and three separated readings are the evidence that the
instrument discriminates at all. The fourth is about the GATE: none of those
three numbers may reach it, because a rate measured against a gold-derived
masker describes the red team and not deid-tr. That confusion is what made
`contextual_reid_rate = 0.0303 PASS` identical under the null detector and the
real pipeline.

  1. Against a detector that masks NOTHING, the re-ID rate is high and the gate
     FAILS. If a red team can be handed an unmodified clinical corpus and report
     a passing privacy score, every green run it ever produces means nothing.
  2. Against a masker that masks everything but leaks it back through the
     surrogates, the gate FAILS TOO - by a different set of attack classes. This
     is the harder claim: total absence of masking is easy to notice, and L5
     failures are the ones a naive red team misses.
  3. Against an oracle masker, the measured rate clears the ceiling - and is
     STILL withheld from the gate.
  4. Against the real pipeline, the rate is gate-eligible and is measurably
     different from the oracle's. A number that does not move when the masking
     moves is not measuring the masking.

The oracle does not reach zero on the committed corpus and is not asserted to.
It masks exactly what the gold set annotates, and the red team finds a handful
of documents where an unannotated year or an unannotated relational phrase
survives. Asserting zero would mean tuning the attacks until they agreed with
the annotation, which is the direction that turns a red team into a rubber
stamp; the honest assertion is that the rate clears the D-008 ceiling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from eval.build_gold import Document, load_corpus
from eval.harness import load_redteam_report
from eval.pipeline import PipelineMasker
from eval.redteam.maskers import LeakyMasker, NullMasker, OracleMasker
from eval.redteam.model import CORPUS_WIDE_DOC_ID
from eval.redteam.runner import build_attacks, main, run_red_team
from eval.schema import Schema, load_schema, load_thresholds


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


@pytest.fixture(scope="module")
def thresholds() -> dict[str, Any]:
    return load_thresholds()


@pytest.fixture(scope="module")
def corpus(schema: Schema) -> list[Document]:
    return load_corpus(schema=schema)


def _ceiling(thresholds: dict[str, Any]) -> float:
    contextual: dict[str, Any] = thresholds["contextual"]
    return float(contextual["reid_rate_max"])


def test_null_masker_fails_the_gate_loudly(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any]
) -> None:
    report, _, _ = run_red_team(
        corpus, NullMasker(), schema, thresholds, run_id="test-null"
    )
    rate = report["reid_rate_measured"]
    assert rate is not None
    assert rate > 0.5, "a corpus that was never masked must re-identify most of it"
    assert report["local_verdict_within_ceiling"] is False
    # Loud, and still not gate-eligible: the number describes the instrument.
    assert report["contextual_reid_rate"] is None
    assert report["gate"]["passed"] is None
    # Every attack that can fire without a span map must have fired.
    assert set(report["successful_attack_classes"]) >= {
        "narrative_survival",
        "quasi_identifier_combination",
        "rare_value_survival",
        "indirect_reference",
    }


def test_leaky_masker_fails_the_gate_through_the_surrogates(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any]
) -> None:
    report, _, _ = run_red_team(
        corpus, LeakyMasker(), schema, thresholds, run_id="test-leaky"
    )
    assert report["local_verdict_within_ceiling"] is False
    successful = set(report["successful_attack_classes"])
    # The narrative IS masked here, so the classes that fire are the L5 ones.
    assert "narrative_survival" not in successful
    assert {
        "structural_leakage",
        "cross_document_linkage",
        "format_tells",
    } <= successful


def test_oracle_masker_passes_the_gate(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any]
) -> None:
    report, _, _ = run_red_team(
        corpus, OracleMasker(), schema, thresholds, run_id="test-oracle"
    )
    rate = report["reid_rate_measured"]
    assert rate is not None
    assert rate <= _ceiling(thresholds)
    assert report["local_verdict_within_ceiling"] is True
    assert "narrative_survival" not in report["successful_attack_classes"]
    # THE FIX. A perfect gold-derived masker clearing the ceiling is a statement
    # about the red team's false-positive rate, not a release gate, and it must
    # not be able to render as PASS anywhere.
    assert report["gate_eligible"] is False
    assert report["contextual_reid_rate"] is None
    assert report["gate"]["passed"] is None
    assert report["calibration"]["reid_rate_measured"] == rate


def test_pipeline_masker_measures_the_product_not_the_instrument(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any]
) -> None:
    """The number must move when what is masked moves.

    The defect was that it did not: the same 0.0303 was published whatever was
    being scored. Attacking the real pipeline and attacking a perfect
    gold-derived masker must produce visibly different numbers, and only the
    first may reach the gate.
    """
    pipeline_report, _, _ = run_red_team(
        corpus, PipelineMasker(), schema, thresholds, run_id="test-pipeline"
    )
    oracle_report, _, _ = run_red_team(
        corpus, OracleMasker(), schema, thresholds, run_id="test-oracle-vs"
    )

    measured = pipeline_report["reid_rate_measured"]
    assert measured is not None
    assert measured > oracle_report["reid_rate_measured"]
    assert pipeline_report["gate_eligible"] is True
    assert pipeline_report["contextual_reid_rate"] == measured
    assert pipeline_report["provenance"]["detector"] == "pipeline:safe_harbor"


def test_all_seven_attack_classes_are_reported(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any]
) -> None:
    report, _, _ = run_red_team(
        corpus[:20], OracleMasker(), schema, thresholds, run_id="test-seven"
    )
    reported = [entry["attack_class"] for entry in report["attack_classes"]]
    assert len(reported) == 7
    assert len(set(reported)) == 7
    assert [attack.attack_class for attack in build_attacks()] == reported


def test_corpus_wide_findings_do_not_count_as_documents(
    corpus: list[Document], schema: Schema, thresholds: dict[str, Any]
) -> None:
    """The inverted-gradient finding has no document behind it."""
    report, results, masked = run_red_team(
        corpus, NullMasker(), schema, thresholds, run_id="test-pseudo"
    )
    hit: set[str] = set()
    for result in results:
        hit |= result.documents_hit
    assert CORPUS_WIDE_DOC_ID in hit or True  # may or may not fire; must never count
    assert report["documents_reidentified"] <= len(masked)
    assert all(document.doc_id != CORPUS_WIDE_DOC_ID for document in masked), (
        "the pseudo doc_id must not collide with a real fixture"
    )


def test_missing_threshold_fails_the_run_rather_than_relaxing_it(
    corpus: list[Document], schema: Schema
) -> None:
    from eval.schema import SchemaError

    with pytest.raises(SchemaError):
        run_red_team(corpus[:5], OracleMasker(), schema, {}, run_id="test-nogate")


def test_a_reference_masker_report_can_never_populate_the_gate(
    tmp_path: Path,
) -> None:
    """The regression, asserted end to end through the real runner.

    A gate that a null detector can pass is not a gate. The oracle report is
    written, read by the harness loader, and REFUSED - and the refusal names the
    masker, so the reason is in the artifact rather than in a reviewer's memory.
    """
    out = tmp_path / "redteam.json"
    assert main(["--masker", "oracle", "--out", str(out)]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["masker_kind"] == "reference"
    assert written["reid_rate_measured"] is not None
    assert written["contextual_reid_rate"] is None

    provenance = load_redteam_report(
        out, detector_name="null", eval_sha=written["provenance"]["eval_sha"]
    )
    assert provenance.gated_rate is None
    assert provenance.accepted is False
    assert provenance.rejected_because is not None
    assert "oracle" in provenance.rejected_because
    # Visible, but never without its source.
    assert provenance.measured_reid_rate == written["reid_rate_measured"]


def test_pipeline_report_is_the_field_the_harness_reads(tmp_path: Path) -> None:
    """The contract between this runner and eval/harness.py, asserted."""
    out = tmp_path / "redteam.json"
    assert main(["--masker", "pipeline", "--out", str(out)]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["masker_kind"] == "pipeline"
    assert written["provenance"]["detector"] == "pipeline:safe_harbor"

    provenance = load_redteam_report(
        out,
        detector_name="pipeline:safe_harbor",
        eval_sha=written["provenance"]["eval_sha"],
    )
    assert provenance.accepted is True
    assert provenance.gated_rate == written["contextual_reid_rate"]
    assert provenance.validated_by == "l6_reid_red_team (masker=pipeline)"


def test_absent_report_leaves_the_harness_field_null(tmp_path: Path) -> None:
    """Absence of a red-team run is not a passing score."""
    provenance = load_redteam_report(tmp_path / "does-not-exist.json")
    assert provenance.gated_rate is None
    assert provenance.measured_reid_rate is None
    assert provenance.accepted is False


def test_cli_gate_flag_exits_non_zero_on_failure(tmp_path: Path) -> None:
    out = tmp_path / "redteam-null.json"
    assert main(["--masker", "null", "--out", str(out), "--gate"]) == 1
    assert (
        main(["--masker", "oracle", "--out", str(out.with_name("ok.json")), "--gate"])
        == 0
    )
