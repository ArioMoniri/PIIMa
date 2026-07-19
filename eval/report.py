"""Render an evaluation run and enforce the gates in eval/thresholds.yaml.

TWO MODES, AND THE DIFFERENCE IS THE POINT.

  --baseline (default)  Compute every metric, print every gate with its
                        PASS/FAIL/n-a verdict, and exit 0 regardless.
  --gates               Same report, but exit non-zero if any APPLICABLE gate
                        fails.

M0's exit criterion is that the harness RUNS and honestly reports total
failure. With a null detector every direct-recall gate is trivially unmet, so an
enforcing default would make `just eval` red before a single model exists and
would create pressure to weaken the harness to get a green build - the precise
inversion this project is built to avoid. The default `just eval` path is
therefore the REPORTING path. `--gates` is what a release runs, and what CI runs
once a detector exists.

A gate is ENFORCEABLE only when its metric has a real denominator. Recall on an
entity type with zero gold spans is undefined, not 0.0; checksum precision with
zero predictions is undefined, not 1.000; and the contextual re-ID rate is
undefined until the L6 red team has actually run. Undefined gates never fail a
build, because failing on absence and failing on a breach are different events
and must not share an exit code.

AN UNENFORCEABLE GATE IS NOT A PASSING GATE, and this module is built so that
the two cannot be confused. `Gate.passed` is `None` - not `True` - when the
metric is undefined; the rendered verdict is the word `UNENFORCEABLE`, never
`PASS` and never a green state; the summary line counts three buckets rather
than two; and the results artifact carries an explicit `unenforceable_gates`
list naming each one and why. This matters most in exactly the case that looks
best: a detector emitting zero predictions makes `micro_f1_direct` and
`checksum_id_precision` undefined, because precision over an empty prediction
set is undefined - so two of the ten non-negotiable release gates cannot fail
against a system that predicts nothing. "No failures" and "all gates passed"
are different sentences, and an auditor must be able to see which one they are
reading.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

# Support `python3 eval/report.py` as well as `python3 -m eval.report`: a bare
# script invocation puts eval/ on sys.path instead of the repo root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.harness import RunMetrics
from eval.schema import Schema

Direction = Literal["floor", "ceiling"]

_UNDEFINED: Final[str] = "n/a"
_UNENFORCEABLE: Final[str] = "UNENFORCEABLE"

# The default explanation for an undefined metric. Every gate that can go
# undefined for a more specific reason supplies its own.
_NO_DENOMINATOR: Final[str] = (
    "the metric is undefined: it has no denominator in this run"
)


@dataclass(frozen=True)
class Gate:
    """One numeric release gate evaluated against one observed metric.

    `passed` is deliberately three-valued. A two-valued `passed` forces an
    undefined metric to be encoded as either True or False, and both are lies:
    True says a gate was met that was never evaluated, False says a breach that
    never happened. `None` is the only honest third answer, and making callers
    handle it is the mechanism that stops an unenforceable gate rendering green.
    """

    name: str
    threshold: float
    observed: float | None
    direction: Direction
    reason: str = ""
    # Why this gate could not be evaluated. Only read when `observed is None`.
    unenforceable_because: str = _NO_DENOMINATOR

    @property
    def enforceable(self) -> bool:
        return self.observed is not None

    @property
    def applicable(self) -> bool:
        """Deprecated alias for `enforceable`, kept for existing readers."""
        return self.enforceable

    @property
    def passed(self) -> bool | None:
        """True, False, or None when the gate could not be evaluated at all."""
        if self.observed is None:
            return None
        if self.direction == "floor":
            return self.observed >= self.threshold
        return self.observed <= self.threshold

    @property
    def verdict(self) -> str:
        if self.passed is None:
            return _UNENFORCEABLE
        return "PASS" if self.passed else "FAIL"

    def as_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "observed": self.observed,
            "direction": self.direction,
            "enforceable": self.enforceable,
            "applicable": self.enforceable,
            "pass": self.passed,
            "verdict": self.verdict,
            "reason": self.reason,
            "unenforceable_because": (
                None if self.enforceable else self.unenforceable_because
            ),
        }


def unenforceable_gates(gates: Sequence[Gate]) -> list[dict[str, Any]]:
    """The gates that could not be evaluated, each with its reason.

    Emitted into the results artifact as a first-class list rather than left to
    be derived by whoever reads it, because a consumer that filters on
    `pass is not False` will conclude the run was clean.
    """
    return [
        {
            "gate": gate.name,
            "threshold": gate.threshold,
            "direction": gate.direction,
            "why": gate.unenforceable_because,
        }
        for gate in gates
        if not gate.enforceable
    ]


def gates_summary(gates: Sequence[Gate]) -> dict[str, Any]:
    """Counts an auditor can read at a glance: passed / failed / unenforceable."""
    passed = sum(1 for gate in gates if gate.passed is True)
    failed = sum(1 for gate in gates if gate.passed is False)
    unenforceable = sum(1 for gate in gates if gate.passed is None)
    return {
        "total": len(gates),
        "passed": passed,
        "failed": failed,
        "unenforceable": unenforceable,
        "all_gates_passed": failed == 0 and unenforceable == 0,
        "note": (
            "all_gates_passed is false whenever any gate is unenforceable. "
            "Zero failures is not the same as full coverage: an unenforceable "
            "gate was not evaluated, so it cannot have been met."
        ),
    }


def _fmt(value: float | None, places: int = 4) -> str:
    if value is None:
        return _UNDEFINED
    return f"{value:.{places}f}"


def _require(thresholds: dict[str, Any], section: str, key: str) -> float:
    """Read a threshold, refusing to invent a default.

    A missing key must fail the run rather than silently relax a gate, which is
    what thresholds.yaml's own header promises.
    """
    block = thresholds.get(section)
    if not isinstance(block, dict) or key not in block:
        raise KeyError(
            f"eval/thresholds.yaml: missing required gate '{section}.{key}'; "
            "the harness has no defaults, a missing gate fails the run"
        )
    value = block[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"eval/thresholds.yaml: '{section}.{key}' must be numeric, got {value!r}"
        )
    return float(value)


def build_gates(
    metrics: RunMetrics, schema: Schema, thresholds: dict[str, Any]
) -> list[Gate]:
    """Assemble every gate for this run, in report order."""
    gates: list[Gate] = []

    critical_floor = _require(
        thresholds, "direct_identifiers", "recall_direct_critical"
    )

    # The critical set is DERIVED from the schema rather than hardcoded: any
    # entity whose own recall floor is at or above the critical floor is by
    # definition one of the HIPAA-critical NAME/ID/CONTACT classes. A hardcoded
    # list would drift from schema.yaml the first time an entity is added.
    critical_labels = {
        entity.id
        for entity in schema.direct
        if entity.recall_threshold >= critical_floor
    }
    critical_gold = sum(
        counts.gold
        for label, counts in metrics.per_entity_relaxed.items()
        if label in critical_labels
    )
    critical_tp = sum(
        counts.true_positives
        for label, counts in metrics.per_entity_relaxed.items()
        if label in critical_labels
    )
    gates.append(
        Gate(
            name="recall_direct_critical",
            threshold=critical_floor,
            observed=(critical_tp / critical_gold) if critical_gold else None,
            direction="floor",
            reason="HIPAA-critical direct identifiers (NAME, ID, CONTACT)",
            unenforceable_because=(
                "the corpus contains no gold spans for any HIPAA-critical "
                "entity type, so critical recall has no denominator"
            ),
        )
    )

    gates.append(
        Gate(
            name="micro_f1_direct",
            threshold=_require(thresholds, "direct_identifiers", "micro_f1_direct"),
            observed=metrics.micro_direct_relaxed.f1,
            direction="floor",
            reason="Stubbs et al. 2015 accepted bar",
            unenforceable_because=(
                "F1 requires precision, and precision over an EMPTY PREDICTION "
                "SET is undefined. A detector that predicts no direct "
                "identifier at all therefore cannot fail this gate. Read the "
                "per-entity recall table instead: it has a gold-span "
                "denominator and does report 0.0."
            ),
        )
    )
    # The gate reads the leakable denominator, not the all-documents one. Same
    # numerator, smaller denominator, so the observed rate is never lower: this
    # is a strictly stricter gate, which is the only direction I2 permits.
    gates.append(
        Gate(
            name="document_leak_rate_max",
            threshold=_require(
                thresholds, "direct_identifiers", "document_leak_rate_max"
            ),
            observed=metrics.document_leak_rate_over_leakable,
            direction="ceiling",
            reason=(
                "documents with >= 1 missed direct identifier, over documents "
                "that hold a direct identifier at all"
            ),
            unenforceable_because=(
                "no document in the corpus holds a direct gold span, so no "
                "document is capable of leaking one"
            ),
        )
    )
    gates.append(
        Gate(
            name="checksum_id_precision",
            threshold=_require(
                thresholds, "direct_identifiers", "checksum_id_precision"
            ),
            observed=metrics.checksum_id_precision,
            direction="floor",
            reason=(
                "a checksum-valid ID is never a false positive; the denominator "
                "is spans a checksum ACTUALLY VALIDATED, not spans carrying a "
                "checksum-validatable label"
            ),
            unenforceable_because=(
                "no span in this run was checksum-validated, so precision over "
                "them is undefined. This is UNMEASURABLE BY CONSTRUCTION on "
                "this corpus, not a detector result: I8 forbids a "
                "checksum-valid Turkish ID from existing in the repository, so "
                "all 128 eleven-digit runs in the gold set fail their check "
                "digits and every TCKN escalates at confidence 0.50 with "
                "Merged::is_protected() unarmed. The protection path is "
                "exercised instead by core/tests/checksum_protection_armed.rs, "
                "which generates checksum-valid identifiers AT RUNTIME and "
                "never writes them to disk. See ADR D-030."
            ),
        )
    )
    # WHY the WORSE of the two rates: the annotated denominator is whatever a
    # human thought to mark, the vocabulary denominator is every term the
    # project claims to protect. Gating on the annotated one alone let a probe
    # detector that masks every occurrence of `ameliyat` - a term present in
    # eval/allowlist/*.txt and annotated in ZERO fixtures - destroy 25 real
    # medical terms and still score PASS. A gate that cannot see the breach it
    # exists to catch is not a gate.
    medical_fp_rates = [
        rate
        for rate in (
            metrics.medical_term_fp_rate,
            metrics.medical_term_fp_rate_vocabulary,
        )
        if rate is not None
    ]
    gates.append(
        Gate(
            name="medical_term_fp_rate_max",
            threshold=_require(thresholds, "medical_terms", "fp_rate_max"),
            observed=max(medical_fp_rates) if medical_fp_rates else None,
            direction="ceiling",
            reason=(
                "masking a medical term destroys the note; the gate reads the "
                "WORSE of fp_rate_annotated and fp_rate_vocabulary, and fails "
                "if EITHER denominator breaches the threshold"
            ),
            unenforceable_because=(
                "neither denominator exists: no allowlist term is annotated "
                "anywhere in the corpus AND the vocabulary scanner found no "
                "eval/allowlist/*.txt term in any document, so the negative "
                "set is empty"
            ),
        )
    )
    gates.append(
        Gate(
            name="contextual_reid_rate_max",
            threshold=_require(thresholds, "contextual", "reid_rate_max"),
            observed=metrics.contextual.reid_rate,
            direction="ceiling",
            reason=(
                "L6 red team, PIPELINE masker only; unenforceable means "
                "UNVALIDATED, not passing"
            ),
            unenforceable_because=(
                "no L6 red-team report with matching provenance exists, so the "
                "contextual tier is UNVALIDATED for this run. Either no report "
                "exists, or the report was produced against a REFERENCE masker "
                "(null/leaky/oracle) or against a different detector or "
                "eval_sha. Absence of an attack is not a survived attack, and "
                "somebody else's attack is not this run's result - see "
                "contextual.reid_rate_provenance in the artifact for which of "
                "those applies. ADR D-029."
            ),
        )
    )
    # A drop measured from a dev recall of zero is vacuous: 0.0 - 0.0 = 0.0
    # would PASS a robustness gate for a system that detects nothing at all.
    # The value is still reported; only the gate is withheld.
    dev_recall = metrics.recall_by_split.get("dev")
    drop_is_meaningful = (
        metrics.sight_unseen_recall_drop is not None
        and dev_recall is not None
        and dev_recall > 0.0
    )
    gates.append(
        Gate(
            name="sight_unseen_recall_drop_max",
            threshold=_require(
                thresholds, "robustness", "sight_unseen_recall_drop_max"
            ),
            observed=(metrics.sight_unseen_recall_drop if drop_is_meaningful else None),
            direction="ceiling",
            reason="generalisation loss on a held-out note type",
            unenforceable_because=(
                "dev recall is zero or absent, so a drop measured from it is "
                "vacuous: 0.0 - 0.0 = 0.0 would PASS a robustness gate for a "
                "system that detects nothing"
            ),
        )
    )

    per_entity = thresholds.get("per_entity_recall")
    if not isinstance(per_entity, dict):
        raise KeyError("eval/thresholds.yaml: missing section 'per_entity_recall'")
    for label in sorted(per_entity):
        floor = _require(thresholds, "per_entity_recall", label)
        counts = metrics.per_entity_relaxed.get(label)
        gates.append(
            Gate(
                name=f"recall.{label}",
                threshold=floor,
                observed=counts.recall if counts is not None else None,
                direction="floor",
                reason="per-entity recall floor",
                unenforceable_because=(
                    f"the corpus holds no gold span labelled {label}, so recall "
                    "for it has no denominator. This is a CORPUS GAP, not a "
                    "detector result."
                ),
            )
        )

    return gates


def render(metrics: RunMetrics, gates: Sequence[Gate], enforcing: bool) -> str:
    """Render the full human-readable report."""
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("deid-tr evaluation report")
    lines.append("=" * 78)
    lines.append(f"detector          : {metrics.detector_name}")
    lines.append(f"documents         : {metrics.documents}")
    lines.append(
        f"mode              : {'GATES (enforcing)' if enforcing else 'BASELINE (reporting only)'}"
    )
    lines.append("")

    lines.append("-" * 78)
    lines.append("PER-ENTITY RECALL (direct identifiers, relaxed matching)")
    lines.append("-" * 78)
    header = f"{'entity':<20} {'gold':>6} {'pred':>6} {'tp':>6} {'recall':>9} {'prec':>9} {'f1':>9}"
    lines.append(header)
    if not metrics.per_entity_relaxed:
        lines.append("  (no direct gold spans in corpus)")
    for label, counts in sorted(metrics.per_entity_relaxed.items()):
        lines.append(
            f"{label:<20} {counts.gold:>6} {counts.predicted:>6} "
            f"{counts.true_positives:>6} {_fmt(counts.recall):>9} "
            f"{_fmt(counts.precision):>9} {_fmt(counts.f1):>9}"
        )
    lines.append("")

    lines.append("-" * 78)
    lines.append("STRICT vs RELAXED (boundary policy)")
    lines.append("-" * 78)
    lines.append(
        f"  micro relaxed     : recall {_fmt(metrics.micro_direct_relaxed.recall)}  "
        f"precision {_fmt(metrics.micro_direct_relaxed.precision)}  "
        f"f1 {_fmt(metrics.micro_direct_relaxed.f1)}"
    )
    lines.append(
        f"  micro strict      : recall {_fmt(metrics.micro_direct_strict.recall)}  "
        f"precision {_fmt(metrics.micro_direct_strict.precision)}  "
        f"f1 {_fmt(metrics.micro_direct_strict.f1)}"
    )
    lines.append("  gates are evaluated against RELAXED matching.")
    lines.append("")

    lines.append("=" * 78)
    lines.append("THE THREE HEADLINE NUMBERS (reported separately, never blended)")
    lines.append("=" * 78)
    lines.append("")
    lines.append("  [1] DIRECT IDENTIFIERS")
    lines.append(
        f"        micro F1            : {_fmt(metrics.micro_direct_relaxed.f1)}"
    )
    lines.append(
        f"        micro recall        : {_fmt(metrics.micro_direct_relaxed.recall)}"
    )
    lines.append(
        f"        document leak rate  : "
        f"{_fmt(metrics.document_leak_rate_over_leakable)} "
        f"({metrics.documents_leaking}/{metrics.documents_with_direct_spans} "
        f"documents that hold a direct identifier)   <- GATED"
    )
    lines.append(
        f"          same, over ALL docs : {_fmt(metrics.document_leak_rate)} "
        f"({metrics.documents_leaking}/{metrics.documents} documents)"
    )
    lines.append(
        f"          excluded as unleakable (zero direct gold spans) : "
        f"{metrics.documents_without_direct_spans} documents"
    )
    if metrics.documents_without_direct_spans:
        lines.append(
            "          a document with no direct identifier cannot leak one; it "
            "dilutes the"
        )
        lines.append(
            "          all-documents rate downward without any detection having "
            "happened."
        )
    lines.append(f"        checksum precision  : {_fmt(metrics.checksum_id_precision)}")
    lines.append(
        f"        sight-unseen drop   : {_fmt(metrics.sight_unseen_recall_drop)}"
    )
    lines.append("")
    lines.append("  [2] MEDICAL-TERM FALSE-POSITIVE RATE")
    lines.append(
        f"        fp rate (annotated) : {_fmt(metrics.medical_term_fp_rate)} "
        f"({metrics.medical_terms_masked}/{metrics.medical_terms_total} terms masked)"
    )
    lines.append(
        f"        fp rate (vocabulary): "
        f"{_fmt(metrics.medical_term_fp_rate_vocabulary)} "
        f"({metrics.vocabulary_terms_masked}/{metrics.vocabulary_terms_total} "
        "terms masked)"
    )
    lines.append(
        "        the gate reads the WORSE of the two: a term destroyed under "
        "either denominator is a destroyed term."
    )
    lines.append("")
    lines.append("  [3] CONTEXTUAL")
    lines.append(
        f"        coverage (DIAGNOSTIC ONLY, not a score) : "
        f"{_fmt(metrics.contextual.coverage)} "
        f"({metrics.contextual.covered_quasi_spans}/"
        f"{metrics.contextual.gold_quasi_spans} quasi spans)"
    )
    lines.append(
        f"        re-ID rate (AUTHORITATIVE, red team)    : "
        f"{_fmt(metrics.contextual.reid_rate)}"
    )
    if metrics.contextual.reid_rate is None:
        provenance = metrics.contextual.provenance
        lines.append(
            "        the contextual tier is UNVALIDATED for this run: "
            f"{provenance.rejected_because}"
        )
        if provenance.measured_reid_rate is not None:
            lines.append(
                "        a red-team report DOES exist and measured "
                f"{_fmt(provenance.measured_reid_rate)} against "
                f"masker={provenance.masker}. That number is reported here and "
                "gated nowhere:"
            )
            if provenance.masker != "pipeline":
                lines.append(
                    "        a rate measured against anything but the real "
                    "pipeline describes the red team, not deid-tr."
                )
            else:
                lines.append(
                    "        that run attacked different code or a different "
                    "detector, so it is not this run's result."
                )
        lines.append(
            "        Coverage above is NOT a substitute. Absence of an attack is "
            "not a survived attack."
        )
    else:
        lines.append(
            f"        validated_by                            : "
            f"{metrics.contextual.validated_by}"
        )
    lines.append("")

    lines.append("-" * 78)
    lines.append("GATES")
    lines.append("-" * 78)
    lines.append(f"{'gate':<34} {'threshold':>10} {'observed':>10}  verdict")
    for gate in gates:
        lines.append(
            f"{gate.name:<34} {gate.threshold:>10.4f} "
            f"{_fmt(gate.observed):>10}  {gate.verdict}"
        )
    lines.append("")

    summary = gates_summary(gates)
    blocked = unenforceable_gates(gates)
    lines.append(
        f"summary: {summary['passed']} passed, {summary['failed']} failed, "
        f"{summary['unenforceable']} UNENFORCEABLE"
    )
    if blocked:
        lines.append("")
        lines.append("-" * 78)
        lines.append(
            f"UNENFORCEABLE GATES ({len(blocked)}) - NOT EVALUATED, THEREFORE NOT PASSED"
        )
        lines.append("-" * 78)
        lines.append(
            "  These gates could not be evaluated at all. They are not failures "
            "and they are"
        )
        lines.append(
            "  not passes. A run with zero failures and a non-empty list below "
            "has NOT met"
        )
        lines.append("  the release gates - it has declined to test them.")
        for entry in blocked:
            lines.append(f"    {entry['gate']}")
            lines.append(f"        {entry['why']}")
        lines.append("")
    if enforcing:
        if summary["failed"]:
            lines.append("  mode GATES: a failing enforceable gate exits non-zero.")
        elif summary["unenforceable"]:
            lines.append(
                f"  mode GATES: no gate FAILED, but {summary['unenforceable']} "
                "could not be evaluated."
            )
            lines.append(
                "  This exits 0 and it is NOT a green release. Release readiness "
                "requires"
            )
            lines.append("  every gate enforceable and passing.")
        else:
            lines.append("  mode GATES: every gate was enforceable and passed.")
    else:
        lines.append(
            "  mode BASELINE: exiting 0 regardless. Run with --gates to enforce."
        )
    return "\n".join(lines)


def report(
    metrics: RunMetrics,
    schema: Schema,
    thresholds: dict[str, Any],
    *,
    enforcing: bool,
    stream: Any = None,
) -> int:
    """Print the report and return the process exit code."""
    gates = build_gates(metrics, schema, thresholds)
    text = render(metrics, gates, enforcing)
    print(text, file=stream if stream is not None else sys.stdout)
    if not enforcing:
        return 0
    return 1 if any(gate.passed is False for gate in gates) else 0


def gates_as_dict(gates: Sequence[Gate]) -> dict[str, Any]:
    """Shape the gates for the results artifact (the card contract, I5)."""
    return {gate.name: gate.as_dict() for gate in gates}


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="eval/report.py",
        description="Render a deid-tr evaluation run and check release gates.",
    )
    parser.add_argument(
        "results",
        type=Path,
        help="path to an eval/results/<run_id>.json artifact",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--baseline",
        action="store_true",
        help="report only; always exit 0 (default)",
    )
    mode.add_argument(
        "--gates",
        action="store_true",
        help="enforce: exit non-zero when an applicable gate fails",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    payload = json.loads(args.results.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print(f"{args.results}: expected a JSON object", file=sys.stderr)
        return 2

    stored_gates = payload.get("gates", {})
    if not isinstance(stored_gates, dict):
        print(f"{args.results}: 'gates' must be an object", file=sys.stderr)
        return 2

    enforcing = bool(args.gates)
    print(f"deid-tr gates from {args.results}")
    print(f"mode: {'GATES (enforcing)' if enforcing else 'BASELINE (reporting only)'}")
    failing = 0
    passing = 0
    blocked: list[tuple[str, str]] = []
    for name in sorted(stored_gates):
        entry = stored_gates[name]
        if not isinstance(entry, dict):
            continue
        observed = entry.get("observed")
        threshold = entry.get("threshold")
        passed = entry.get("pass")
        if passed is None:
            verdict = _UNENFORCEABLE
            why = entry.get("unenforceable_because")
            blocked.append((name, why if isinstance(why, str) else _NO_DENOMINATOR))
        elif passed:
            verdict = "PASS"
            passing += 1
        else:
            verdict = "FAIL"
            failing += 1
        obs_text = _UNDEFINED if observed is None else f"{float(observed):.4f}"
        thr_text = _UNDEFINED if threshold is None else f"{float(threshold):.4f}"
        print(f"{name:<34} {thr_text:>10} {obs_text:>10}  {verdict}")
    print(f"summary: {passing} passed, {failing} failed, {len(blocked)} UNENFORCEABLE")
    if blocked:
        print(
            f"UNENFORCEABLE GATES ({len(blocked)}) - NOT EVALUATED, THEREFORE "
            "NOT PASSED:"
        )
        for name, why in blocked:
            print(f"  {name}")
            print(f"      {why}")
        print(
            "Zero failures above is NOT the same as all gates passed: an "
            "unenforceable gate was never evaluated."
        )
    if not enforcing:
        print("mode BASELINE: exiting 0 regardless. Run with --gates to enforce.")
        return 0
    return 1 if failing else 0


if __name__ == "__main__":
    raise SystemExit(main())
