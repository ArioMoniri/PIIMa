"""L6 runner: execute all seven attacks and publish the contextual re-ID rate.

    python3 -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json

The number this writes is the one gate class B quasi-identifiers have. Per D-008
at most 5% of documents may fall to any attack class; `eval/thresholds.yaml`
holds the ceiling and this module never carries a default for it, so deleting
the key fails the run instead of relaxing the gate.

WHAT WAS ATTACKED IS PART OF THE NUMBER. This runner used to accept only three
REFERENCE maskers, all derived from the gold annotations, and the committed
report was produced against `oracle` - a perfect masker. `eval/harness.py` read
that file whatever it was scoring, so `contextual_reid_rate = 0.0303 PASS` came
out byte-identical for the null detector and for the real pipeline, and it was
one of only two gates the null detector passed. `--masker pipeline` runs the
actual `core::Pipeline`, and only its rate is gate-eligible; every other masker
now reports under `calibration` with the gate explicitly WITHHELD.

WHAT THE RATE IS. A document is re-identified when ANY of the seven attacks
lands on it. Not a weighted blend, not an average severity: the attacker only
needs one route, and averaging seven attacks would let six defences hide the one
that failed. This mirrors the union rule the detection layers use for recall.

DENOMINATOR. Both are computed. `over_all_documents` divides by the whole
corpus, including fixtures with no gold span at all, which cannot be
re-identified by a masking failure and therefore dilute the rate downward
without any privacy having been achieved - the same trap eval/harness.py
documents for the document leak rate. `over_attackable_documents` divides by the
documents that hold at least one gold span. The gated, headline
`contextual_reid_rate` is the attackable one, because it is the larger of the
two and a privacy gate should be asserted against the less flattering number.

ABSENCE IS NOT A PASS. eval/harness.py reads `contextual_reid_rate` from the
report this writes and leaves the field null when no report exists. That
asymmetry is deliberate and is preserved here: this module writes a report only
when it has actually run every attack, and an attack that could not run at all
is marked `inapplicable` rather than being counted as survived.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Final

# Support `python3 eval/redteam/runner.py` as well as `python3 -m
# eval.redteam.runner`: a bare script invocation puts eval/redteam/ on sys.path
# instead of the repo root.
if __package__ in (None, ""):  # pragma: no cover - import-path plumbing
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from eval.build_gold import (
    DEFAULT_CORPUS_ROOTS,
    L6_ATTACK_CLASSES,
    GoldError,
    load_corpus,
)
from eval.redteam.cross_doc_linkage import CrossDocLinkageAttack
from eval.redteam.fixtures import emit_fixtures
from eval.redteam.format_tells import FormatTellsAttack
from eval.redteam.indirect_reference import IndirectReferenceAttack
from eval.redteam.maskers import (
    LeakyMasker,
    Masker,
    NullMasker,
    OracleMasker,
    mask_corpus,
)
from eval.redteam.model import (
    CORPUS_WIDE_DOC_ID,
    Attack,
    AttackResult,
    DeidDocument,
)
from eval.pipeline import PipelineMasker
from eval.provenance import file_sha256, git_eval_sha
from eval.redteam.narrative_survival import NarrativeSurvivalAttack
from eval.redteam.quasi_combination import QuasiCombinationAttack
from eval.redteam.rare_value_survival import RareValueSurvivalAttack
from eval.redteam.structural_leakage import StructuralLeakageAttack
from eval.schema import REPO_ROOT, Schema, SchemaError, load_schema, load_thresholds

DEFAULT_REPORT_PATH: Final[Path] = REPO_ROOT / "eval" / "results" / "redteam.json"

VALIDATED_BY: Final[str] = "l6_reid_red_team"


def validated_by(masker_name: str) -> str:
    """The provenance string eval/harness.py surfaces beside the rate.

    It names the MASKER, because the rate is a property of what was attacked. A
    report produced against the oracle says nothing about the detector an eval
    run happens to be scoring, and a bare "l6_reid_red_team" beside a 0.03 in
    the results artifact reads as though it did.
    """
    return f"{VALIDATED_BY} (masker={masker_name})"


# THE GATE-ELIGIBLE MASKER, and there is exactly one.
#
# `pipeline` runs the real core::Pipeline over the corpus and hands its ACTUAL
# masked output to the seven attacks. Every other masker here is a REFERENCE
# instrument built from the gold annotations: null / leaky / oracle exist to
# prove the red team discriminates (they measure 1.0000 / high / ~0.03 across
# three known points, which is real evidence the instrument works), and a number
# measured against any of them describes the red team rather than deid-tr.
PIPELINE_MASKER: Final[str] = "pipeline"

REFERENCE_MASKERS: Final[dict[str, Callable[[], Masker]]] = {
    "null": NullMasker,
    "leaky": LeakyMasker,
    "oracle": OracleMasker,
}

MASKERS: Final[dict[str, Callable[[], Masker]]] = {
    **REFERENCE_MASKERS,
    PIPELINE_MASKER: PipelineMasker,
}


def masker_kind(masker_name: str) -> str:
    """ "pipeline" (gate-eligible) or "reference" (calibration only)."""
    return "pipeline" if masker_name == PIPELINE_MASKER else "reference"


def build_attacks() -> tuple[Attack, ...]:
    """The seven attack classes, in the brief's order.

    Constructed as a tuple rather than discovered, so that a module deleted or
    renamed breaks the import instead of quietly shrinking the red team to six
    attacks that all pass.
    """
    attacks: tuple[Attack, ...] = (
        QuasiCombinationAttack(),
        NarrativeSurvivalAttack(),
        StructuralLeakageAttack(),
        CrossDocLinkageAttack(),
        RareValueSurvivalAttack(),
        FormatTellsAttack(),
        IndirectReferenceAttack(),
    )
    covered = {attack.attack_class for attack in attacks}
    missing = sorted(set(L6_ATTACK_CLASSES) - covered)
    if missing:
        raise RuntimeError(
            f"the red team is missing an attack class: {', '.join(missing)}. "
            "The seven classes are a closed set from the brief; running six of "
            "them and reporting a rate would understate risk."
        )
    return attacks


def run_attacks(corpus: Sequence[DeidDocument], schema: Schema) -> list[AttackResult]:
    return [attack.run(corpus, schema) for attack in build_attacks()]


def build_report(
    results: Sequence[AttackResult],
    corpus: Sequence[DeidDocument],
    thresholds: dict[str, Any],
    *,
    masker_name: str,
    run_id: str,
    detector: str | None = None,
) -> dict[str, Any]:
    """Assemble the report eval/harness.py reads `contextual_reid_rate` from.

    TWO NUMBERS, STRUCTURALLY SEPARATED.

      `reid_rate_measured`  - what the attacks measured. Always present.
      `contextual_reid_rate`- the GATE-ELIGIBLE copy. Equal to the measured rate
                              only when the masker was the real pipeline; null
                              for every reference masker, with the reason
                              recorded beside it.

    A reference run additionally emits a `calibration` block, because the
    null/leaky/oracle numbers are genuinely valuable - they are the evidence
    that the instrument discriminates - and burying them would be as dishonest
    in the other direction as gating on them was.
    """
    contextual = thresholds.get("contextual")
    if not isinstance(contextual, dict) or "reid_rate_max" not in contextual:
        raise SchemaError(
            "eval/thresholds.yaml: contextual.reid_rate_max is missing. The red "
            "team carries no default ceiling; a missing gate fails the run "
            "rather than passing it."
        )
    ceiling = float(contextual["reid_rate_max"])

    documents = len(corpus)
    attackable = sum(1 for document in corpus if document.is_attackable)
    reidentified: set[str] = set()
    for result in results:
        reidentified |= result.documents_hit
    reidentified.discard(CORPUS_WIDE_DOC_ID)

    over_all = (len(reidentified) / documents) if documents else None
    over_attackable = (len(reidentified) / attackable) if attackable else None
    rate = over_attackable

    successful = sorted(result.attack_class for result in results if result.succeeded)
    inapplicable = sorted(
        result.attack_class for result in results if result.inapplicable
    )
    # The local verdict: measured against the ceiling, whatever the masker. This
    # is what `--gate` reads, because a calibration run must still be able to
    # assert "the null masker fails". It is NOT the release gate.
    local_verdict = None if rate is None else rate <= ceiling

    kind = masker_kind(masker_name)
    gate_eligible = kind == "pipeline"
    withheld: str | None = None
    if not gate_eligible:
        withheld = (
            f"masker={masker_name!r} is a REFERENCE instrument derived from the "
            "gold annotations. Its rate calibrates the red team and says "
            "nothing about what deid-tr masks, so it may not populate "
            "contextual.reid_rate_max."
        )
    gated_rate = rate if gate_eligible else None
    passed = None if gated_rate is None else gated_rate <= ceiling

    report: dict[str, Any] = {
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "masker": masker_name,
        "masker_kind": kind,
        "gate_eligible": gate_eligible,
        "validated_by": validated_by(masker_name),
        "provenance": {
            # The identity eval/harness.py matches against the detector being
            # scored. None for a reference masker: there is no detector behind
            # a gold-derived instrument, and inventing one would be the whole
            # defect in a different coat.
            "detector": detector,
            "eval_sha": git_eval_sha(),
            "schema_sha": file_sha256(REPO_ROOT / "eval" / "schema.yaml"),
            "thresholds_sha": file_sha256(REPO_ROOT / "eval" / "thresholds.yaml"),
            "note": (
                "eval/harness.py populates contextual.reid_rate ONLY from a "
                "report whose masker is 'pipeline' and whose detector and "
                "eval_sha match the run being scored."
            ),
        },
        # What the attacks measured, always.
        "reid_rate_measured": rate,
        "local_verdict_within_ceiling": local_verdict,
        # The field eval/harness.py reads. Null unless the pipeline was attacked.
        "contextual_reid_rate": gated_rate,
        "contextual_reid_rate_withheld_because": withheld,
        "contextual_reid_rate_denominator": "documents_attackable",
        "contextual_reid_rate_over_all_documents": over_all,
        "contextual_reid_rate_over_attackable_documents": over_attackable,
        "denominator_note": (
            "A fixture with no gold span cannot be re-identified by a masking "
            "failure, so it dilutes the over-all-documents rate without any "
            "privacy having been achieved. The gated rate is the attackable one."
        ),
        "documents_evaluated": documents,
        "documents_attackable": attackable,
        "documents_reidentified": len(reidentified),
        "gate": {
            "name": "contextual.reid_rate_max",
            "ceiling": ceiling,
            "value": gated_rate,
            "passed": passed,
            "eligible": gate_eligible,
            "withheld_because": withheld,
            "note": (
                "D-008. The only gate class B quasi-identifiers have; they carry "
                "no recall or precision threshold because they are meanings, not "
                "enumerable entities. `passed` is null - UNENFORCEABLE, which is "
                "not a pass - whenever the attacked output did not come from the "
                "real pipeline."
            ),
        },
        "successful_attack_classes": successful,
        "inapplicable_attack_classes": inapplicable,
        "attack_classes": [result.as_dict() for result in results],
    }

    if not gate_eligible:
        report["calibration"] = {
            "masker": masker_name,
            "reid_rate_measured": rate,
            "ceiling": ceiling,
            "within_ceiling": local_verdict,
            "role": (
                "REFERENCE POINT, not a score. null / leaky / oracle bracket the "
                "instrument: total failure, L5-shaped failure, and near-perfect "
                "masking. Three separated readings are the evidence that the red "
                "team discriminates at all, which is what makes a pipeline "
                "number worth reading."
            ),
        }
    return report


def run_red_team(
    documents: Sequence[Any],
    masker: Masker,
    schema: Schema,
    thresholds: dict[str, Any],
    *,
    run_id: str,
) -> tuple[dict[str, Any], list[AttackResult], list[DeidDocument]]:
    """Mask a corpus, run all seven attacks, and build the report."""
    corpus = mask_corpus(documents, masker, schema)
    results = run_attacks(corpus, schema)
    # Only a masker that ran a real detector has a detector identity to declare.
    detector = getattr(masker, "detector", None)
    report = build_report(
        results,
        corpus,
        thresholds,
        masker_name=masker.name,
        run_id=run_id,
        detector=detector if isinstance(detector, str) else None,
    )
    return report, results, corpus


def render(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("L6 RE-IDENTIFICATION RED TEAM")
    lines.append("=" * 78)
    lines.append(
        f"  masker                 : {report['masker']}  "
        f"({report['masker_kind']}, "
        f"{'GATE-ELIGIBLE' if report['gate_eligible'] else 'CALIBRATION ONLY'})"
    )
    detector = report["provenance"]["detector"]
    lines.append(f"  detector attacked      : {detector if detector else 'n/a'}")
    lines.append(f"  documents evaluated    : {report['documents_evaluated']}")
    lines.append(f"  documents attackable   : {report['documents_attackable']}")
    lines.append(f"  documents re-identified: {report['documents_reidentified']}")
    lines.append("")
    lines.append("-" * 78)
    lines.append("ATTACK CLASSES")
    lines.append("-" * 78)
    for entry in report["attack_classes"]:
        if entry["inapplicable"] and not entry["succeeded"]:
            verdict = "NOT RUN"
        elif entry["succeeded"]:
            verdict = "BREACHED"
        else:
            verdict = "held"
        lines.append(
            f"  {entry['attack_class']:<30} {verdict:<9} "
            f"{entry['documents_hit']:>4} doc(s), {entry['findings']:>4} finding(s)"
        )
    lines.append("")
    gate = report["gate"]
    measured = report["reid_rate_measured"]
    measured_shown = "undefined" if measured is None else f"{measured:.4f}"
    ceiling = gate["ceiling"]
    lines.append("-" * 78)
    lines.append(
        f"MEASURED RE-ID RATE    {measured_shown}  (ceiling {ceiling:.4f})  "
        f"{'within' if report['local_verdict_within_ceiling'] else 'ABOVE'}"
    )
    lines.append("-" * 78)
    if report["gate_eligible"]:
        verdict = (
            "n/a" if gate["passed"] is None else ("PASS" if gate["passed"] else "FAIL")
        )
        lines.append(f"  RELEASE GATE contextual.reid_rate_max : {verdict}")
        lines.append(
            "  This masker IS the product, so this number is the gate. "
            "Denominator is documents"
        )
        lines.append("  holding at least one gold span.")
    else:
        lines.append("  RELEASE GATE contextual.reid_rate_max : WITHHELD")
        lines.append(f"  {gate['withheld_because']}")
        lines.append(
            "  The number above is a CALIBRATION reading. It says the red team "
            "discriminates;"
        )
        lines.append(
            "  it does not say what deid-tr masks. Run --masker pipeline for a "
            "number about"
        )
        lines.append("  the product.")
    lines.append(
        "  eval/harness.py leaves contextual.reid_rate null - UNENFORCEABLE, not "
        "passing -"
    )
    lines.append(
        "  unless this report's masker, detector and eval_sha match the run being "
        "scored."
    )
    return "\n".join(lines)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="eval/redteam/runner.py",
        description="Run the L6 re-identification red team over a masked corpus.",
    )
    parser.add_argument(
        "--masker",
        default=PIPELINE_MASKER,
        choices=sorted(MASKERS),
        help=(
            "what to attack (default: pipeline). `pipeline` runs the REAL "
            "core::Pipeline and is the only masker whose rate may populate the "
            "release gate. `null` masks nothing, `leaky` masks badly and "
            "`oracle` masks perfectly; all three are calibration instruments."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="report path (default: eval/results/redteam.json)",
    )
    parser.add_argument("--run-id", default=None, help="run identifier")
    parser.add_argument(
        "--corpus-root",
        type=Path,
        action="append",
        default=None,
        help="corpus root (repeatable; defaults to eval/gold and eval/adversarial)",
    )
    parser.add_argument(
        "--emit-fixtures",
        action="store_true",
        help=(
            "write successful attacks back as a NEW adversarial fixture file "
            "(append-only; never touches a committed one)"
        ),
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help=(
            "exit non-zero when the MEASURED re-ID rate exceeds its ceiling. "
            "Reads the measured rate for every masker, so a calibration run can "
            "still assert that the null masker fails; the RELEASE gate is the "
            "provenance-checked one in eval/harness.py."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        schema = load_schema()
        thresholds = load_thresholds()
    except SchemaError as exc:
        print(f"schema/thresholds error: {exc}", file=sys.stderr)
        return 2

    roots = tuple(args.corpus_root) if args.corpus_root else DEFAULT_CORPUS_ROOTS
    try:
        documents = load_corpus(roots, schema)
    except GoldError as exc:
        print(f"FAILED to resolve gold corpus: {exc}", file=sys.stderr)
        return 2

    run_id = args.run_id or datetime.now(timezone.utc).strftime(
        f"%Y%m%dT%H%M%SZ-{args.masker}"
    )
    masker = MASKERS[args.masker]()

    try:
        report, results, corpus = run_red_team(
            documents, masker, schema, thresholds, run_id=run_id
        )
    except SchemaError as exc:
        print(f"threshold error: {exc}", file=sys.stderr)
        return 2

    fixture_path: Path | None = None
    if args.emit_fixtures:
        fixture_path = emit_fixtures(results, corpus, schema, run_id)
    report["emitted_fixture_file"] = str(fixture_path) if fixture_path else None

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(render(report))
    print(f"\nreport            : {args.out}")
    if fixture_path is not None:
        print(f"new fixtures      : {fixture_path}")

    if not args.gate:
        return 0
    return 1 if report["local_verdict_within_ceiling"] is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
