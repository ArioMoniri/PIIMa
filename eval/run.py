"""CLI entry point: run a detector against the gold corpus and write the artifact.

    python3 eval/run.py --detector null --out eval/results/<run_id>.json

The file this writes is the CARD CONTRACT (invariant I5). Model cards are build
artifacts: no human writes one, and `scripts/publish.py` reads THIS file and
nothing else. Every field a card needs is therefore emitted here, including the
provenance fields (`eval_sha`, `schema_sha`, `thresholds_sha`) that let a reader
prove the published numbers came from the evaluation committed in the repo
rather than from a different run.

`eval_sha` is the string "uncommitted" whenever the working tree is dirty or the
repository has no commit yet. A card carrying "uncommitted" must never ship;
emitting the honest marker is what makes that check possible downstream.

The detector registry here deliberately contains only detectors that could
legitimately be published. A gold-derived "perfect" detector exists in the test
suite, where it belongs, and is not reachable from this CLI - a benchmark runner
that can be pointed at an oracle is a benchmark runner that can manufacture a
card.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Final

# Support `python3 eval/run.py` as well as `python3 -m eval.run`: a bare script
# invocation puts eval/ on sys.path instead of the repo root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.build_gold import (
    DEFAULT_CORPUS_ROOTS,
    L6_ATTACK_CLASSES,
    NON_L6_ATTACK_CLASSES,
    GoldError,
    load_corpus,
    summarise,
)
from eval.harness import Detector, NullDetector, RunMetrics, evaluate
from eval.pipeline import PipelineDetector
from eval.provenance import file_sha256, git_eval_sha
from eval.report import (
    build_gates,
    gates_as_dict,
    gates_summary,
    render,
    unenforceable_gates,
)
from eval.schema import (
    REPO_ROOT,
    Schema,
    SchemaError,
    load_schema,
    load_thresholds,
)

RESULTS_DIR: Final[Path] = REPO_ROOT / "eval" / "results"

DETECTORS: Final[dict[str, Callable[[], Detector]]] = {
    "null": NullDetector,
    # The real thing. Runs core::Pipeline over the corpus through
    # eval/rust-bridge/. Registered under its own identity string
    # ("pipeline:safe_harbor") because eval/harness.py matches that name against
    # the detector a red-team report was produced from before it will let the
    # report's rate reach the contextual gate.
    "pipeline": PipelineDetector,
}

VALID_TIERS: Final[tuple[str, ...]] = ("safe_harbor", "expert_determination")


def _metric_entries(
    metrics: RunMetrics, dataset_type: str, dataset_name: str
) -> list[dict[str, Any]]:
    """Shape metrics the way huggingface_hub's EvalResult expects them."""
    task_type = "token-classification"
    task_name = "PHI/PII de-identification (Turkish clinical text)"
    entries: list[dict[str, Any]] = []

    def add(
        metric_type: str, metric_name: str, value: float | None, note: str = ""
    ) -> None:
        entries.append(
            {
                "task_type": task_type,
                "task_name": task_name,
                "dataset_type": dataset_type,
                "dataset_name": dataset_name,
                "metric_type": metric_type,
                "metric_name": metric_name,
                "metric_value": value,
                "verified": False,
                "note": note,
            }
        )

    add(
        "f1",
        "Micro F1 (direct identifiers, relaxed)",
        metrics.micro_direct_relaxed.f1,
    )
    add(
        "recall",
        "Micro recall (direct identifiers, relaxed)",
        metrics.micro_direct_relaxed.recall,
    )
    add(
        "precision",
        "Micro precision (direct identifiers, relaxed)",
        metrics.micro_direct_relaxed.precision,
    )
    add("f1", "Micro F1 (direct identifiers, strict)", metrics.micro_direct_strict.f1)
    add(
        "leak_rate",
        "Document leak rate (over documents holding a direct identifier)",
        metrics.document_leak_rate_over_leakable,
        note=(
            f"{metrics.documents_leaking} of "
            f"{metrics.documents_with_direct_spans} documents that hold at "
            f"least one direct gold span. "
            f"{metrics.documents_without_direct_spans} of "
            f"{metrics.documents} documents are excluded because they hold no "
            "direct identifier and therefore cannot leak one. This is the "
            "gated number."
        ),
    )
    add(
        "leak_rate",
        "Document leak rate (over all documents)",
        metrics.document_leak_rate,
        note=(
            "Denominator includes documents with no direct identifier, which "
            "cannot leak. Reported for completeness; not the gated number."
        ),
    )
    add("precision", "Checksum-validated ID precision", metrics.checksum_id_precision)
    add(
        "false_positive_rate",
        "Medical-term false-positive rate",
        metrics.medical_term_fp_rate,
    )
    add(
        "recall_drop",
        "Sight-unseen recall drop",
        metrics.sight_unseen_recall_drop,
    )
    add(
        "coverage",
        "Contextual coverage (DIAGNOSTIC ONLY)",
        metrics.contextual.coverage,
        note=(
            "Not a validated score. Quasi-identifiers are not scored by F1; the "
            "authoritative contextual number is the red-team re-ID rate."
        ),
    )
    add(
        "reid_rate",
        "Contextual re-ID rate (red-team validated)",
        metrics.contextual.reid_rate,
        note="null means the contextual tier is UNVALIDATED, not that it passed.",
    )
    for label, counts in sorted(metrics.per_entity_relaxed.items()):
        add("recall", f"Recall ({label})", counts.recall)
    return entries


def build_artifact(
    metrics: RunMetrics,
    schema: Schema,
    thresholds: dict[str, Any],
    corpus_counts: dict[str, Any],
    *,
    run_id: str,
    tier: str,
    detector_name: str,
    base_model: str | None,
    model_name: str | None,
    dataset_type: str,
    dataset_name: str,
) -> dict[str, Any]:
    """Assemble the results artifact - the sole input to scripts/publish.py."""
    gates = build_gates(metrics, schema, thresholds)
    meta = schema.meta
    language = meta.get("language", ["tr"])
    medical_register = meta.get("medical_register", ["la", "en"])

    return {
        "run_id": run_id,
        "eval_sha": git_eval_sha(),
        "schema_sha": file_sha256(REPO_ROOT / "eval" / "schema.yaml"),
        "thresholds_sha": file_sha256(REPO_ROOT / "eval" / "thresholds.yaml"),
        "schema_version": meta.get("schema_version"),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "language": language,
        "medical_register": medical_register,
        "base_model": base_model,
        "model_name": model_name,
        "dataset_type": dataset_type,
        "dataset_name": dataset_name,
        "tier": tier,
        "detector_name": detector_name,
        "corpus": corpus_counts,
        "metrics": _metric_entries(metrics, dataset_type, dataset_name),
        "per_entity_recall": metrics.per_entity_recall,
        "per_entity_detail": {
            label: counts.as_dict()
            for label, counts in sorted(metrics.per_entity_relaxed.items())
        },
        "medical_term_fp_rate": metrics.medical_term_fp_rate,
        "medical_term_fp_rate_annotated": metrics.medical_term_fp_rate,
        "medical_term_fp_rate_vocabulary": metrics.medical_term_fp_rate_vocabulary,
        "contextual": {
            "coverage": metrics.contextual.coverage,
            "reid_rate": metrics.contextual.reid_rate,
            "validated_by": metrics.contextual.validated_by,
            # The number can never be read without its source. A rate produced
            # against a reference masker, or against a different detector or
            # eval_sha, arrives here rejected and leaves `reid_rate` null.
            "reid_rate_provenance": metrics.contextual.provenance.as_dict(),
        },
        "gates": gates_as_dict(gates),
        # Top-level and first-class, not derivable-if-you-remember-to. A
        # consumer that filters the `gates` map on `pass is not False` finds a
        # clean run; these two fields make that mistake impossible to make
        # silently.
        "gates_summary": gates_summary(gates),
        "unenforceable_gates": unenforceable_gates(gates),
        "detail": metrics.as_dict(),
    }


def render_attack_class_coverage(corpus_counts: dict[str, Any]) -> str:
    """Render adversarial fixture counts per attack class.

    Printed on every eval run rather than only by `just build-gold`, because
    the question "which attack class has no fixture" is asked while reading the
    scores, not while rebuilding the corpus. Classes with zero fixtures are
    listed explicitly: an absent row reads as nothing to report, and the whole
    point is that there is something to report.
    """
    per_class: dict[str, int] = corpus_counts.get("per_attack_class", {})
    gaps: list[str] = corpus_counts.get("l6_attack_classes_with_no_fixture", [])
    lines: list[str] = []
    lines.append("-" * 78)
    lines.append("L6 RED-TEAM COVERAGE (adversarial fixtures per attack class)")
    lines.append("-" * 78)
    for name in L6_ATTACK_CLASSES:
        count = per_class.get(name, 0)
        flag = "   <- NO FIXTURE" if count == 0 else ""
        lines.append(f"  {name:<32} {count:>4}{flag}")
    lines.append("  (not L6 attacks, scored elsewhere)")
    for name in NON_L6_ATTACK_CLASSES:
        lines.append(f"  {name:<32} {per_class.get(name, 0):>4}")
    if gaps:
        lines.append(
            f"  {len(gaps)} of {len(L6_ATTACK_CLASSES)} L6 attack classes have "
            "no fixture. The red team"
        )
        lines.append(
            "  cannot report a result for a class it has nothing to run, and an "
            "unattacked"
        )
        lines.append("  class is not a defended one.")
    return "\n".join(lines)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="eval/run.py",
        description="Run a detector against the deid-tr gold corpus.",
    )
    parser.add_argument(
        "--detector",
        default="null",
        choices=sorted(DETECTORS),
        help="detector to evaluate (default: null)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="results artifact path (default: eval/results/<run_id>.json)",
    )
    parser.add_argument("--run-id", default=None, help="run identifier")
    parser.add_argument(
        "--tier",
        default="safe_harbor",
        choices=VALID_TIERS,
        help="assurance tier this run evaluates (default: safe_harbor)",
    )
    parser.add_argument("--base-model", default=None, help="backbone repo id, if any")
    parser.add_argument("--model-name", default=None, help="model repo id, if any")
    parser.add_argument(
        "--dataset-type", default="deid-tr/TurkDeID-Bench", help="HF dataset id"
    )
    parser.add_argument(
        "--dataset-name", default="TurkDeID-Bench", help="human-readable dataset name"
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        action="append",
        default=None,
        help="corpus root (repeatable; defaults to eval/gold and eval/adversarial)",
    )
    parser.add_argument(
        "--redteam-report",
        type=Path,
        default=None,
        help="L6 red-team report supplying the authoritative re-ID rate",
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

    detector = DETECTORS[args.detector]()
    # A detector that runs a subprocess wants the corpus in one call. Declared
    # through a method rather than special-cased on the class name so a future
    # detector can opt in without editing this function.
    warm = getattr(detector, "warm", None)
    if callable(warm):
        warm(documents)

    # One eval_sha for the whole run, handed to the harness so it can refuse a
    # red-team report produced from different code.
    eval_sha = git_eval_sha()
    metrics = evaluate(
        documents, detector, schema, args.redteam_report, eval_sha=eval_sha
    )

    run_id = args.run_id or datetime.now(timezone.utc).strftime(
        f"%Y%m%dT%H%M%SZ-{args.detector}"
    )
    out_path = args.out if args.out is not None else RESULTS_DIR / f"{run_id}.json"

    artifact = build_artifact(
        metrics,
        schema,
        thresholds,
        summarise(documents, schema),
        run_id=run_id,
        tier=args.tier,
        detector_name=detector.name,
        base_model=args.base_model,
        model_name=args.model_name,
        dataset_type=args.dataset_type,
        dataset_name=args.dataset_name,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    enforcing = bool(args.gates)
    gates = build_gates(metrics, schema, thresholds)
    print(render(metrics, gates, enforcing))
    print(render_attack_class_coverage(artifact["corpus"]))
    print(f"\nresults artifact  : {out_path}")
    print(f"eval_sha          : {artifact['eval_sha']}")

    if not documents:
        print(
            "\nWARNING: the gold corpus is empty. Every metric above is undefined "
            "and no gate is applicable.",
            file=sys.stderr,
        )

    if not enforcing:
        return 0
    return 1 if any(gate.passed is False for gate in gates) else 0


if __name__ == "__main__":
    raise SystemExit(main())
