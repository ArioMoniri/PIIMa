"""I5: model cards are build artifacts, generated from a committed eval run.

    python3 scripts/publish.py 20260719T101500Z-berturk

No human writes a card. The only source of numbers is
`eval/results/<run_id>.json`, and this script reads nothing else - not a second
results file, not a CLI flag carrying a metric, not a value a maintainer
remembers. A number that cannot be traced to that file cannot appear on a card.

THIS FILE CANNOT PUSH. There is no upload code path in it: no `HfApi`, no
`push_to_hub`, no `create_commit`, and no flag that would enable one. It writes
the rendered card into a build directory, prints the diff against whatever is
already there, and stops. The refusal is structural rather than a default,
because a `--push` flag guarded by a check is a flag that gets passed at 2am.

PREFLIGHT, in order, every step blocking:

  1. The results JSON is committed, and the working-tree copy is byte-identical
     to the committed one. A dirty results file means the numbers on the card
     are not the numbers in the repository.
  2. `eval_sha` in the JSON matches HEAD and is not "uncommitted".
  3. `scripts/gate_tokenizer.py` exits 0 for the backbone the JSON names (I6).
  4. Every gate declared in `eval/thresholds.yaml` is present in the JSON's
     gates block, carries the same threshold value, and passes. A gate reported
     as not-applicable blocks publication: an unmeasured gate is not a passed
     gate.
  5. Card language equals eval language. This is checked with an explicit
     assertion because it is the exact failure mode of the incumbent, which
     shipped Turkish PII model cards carrying `language: ar` next to Arabic
     widget examples and Arabic evaluation numbers. The published Turkish
     accuracy figures were Arabic figures. That is a process failure worth
     naming and worth making structurally impossible here.
  6. The widget example is synthetic and in the evaluated language.

The module imports `huggingface_hub` lazily inside the build function, so it
can be imported and unit-tested with the dependency absent.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib
import json
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.schema import SchemaError, load_thresholds  # noqa: E402

RESULTS_DIR: Final[Path] = REPO_ROOT / "eval" / "results"
THRESHOLDS_PATH: Final[Path] = REPO_ROOT / "eval" / "thresholds.yaml"
TEMPLATE_PATH: Final[Path] = REPO_ROOT / "scripts" / "card_template.md"
GATE_SCRIPT: Final[Path] = REPO_ROOT / "scripts" / "gate_tokenizer.py"
DEFAULT_BUILD_DIR: Final[Path] = REPO_ROOT / "build" / "cards"

EXIT_OK: Final[int] = 0
EXIT_PREFLIGHT_FAILED: Final[int] = 1
EXIT_USAGE: Final[int] = 2

LANGUAGE_MISMATCH_MESSAGE: Final[str] = (
    "CARD LANGUAGE != EVAL LANGUAGE. This is the incumbent's exact failure "
    "mode: Turkish PII cards published with `language: ar`, an Arabic widget "
    "example, and Arabic evaluation numbers presented as Turkish accuracy. A "
    "card whose language tag disagrees with the language the numbers were "
    "measured in is a card that misreports its own subject, and no amount of "
    "correct arithmetic upstream repairs it."
)

# Synthetic, in-language widget examples. These live in the source, not behind a
# CLI flag, which is what makes "synthetic" structurally true rather than a
# promise: there is no way to hand this script a real clinical note. Every name,
# date and number is fabricated, and the national-ID-shaped number is
# deliberately checksum-invalid (I8).
WIDGET_EXAMPLES: Final[dict[str, str]] = {
    "tr": (
        "Hasta Ayşe Yılmaz, 12345678900 numaralı kayıt ile 14.03.2024 tarihinde "
        "Kadıköy'deki polikliniğe başvurdu. PET-CT'de saptanan lezyon "
        "carcinoma'lı olarak raporlandı; Op. Dr. İlhan Işık tarafından "
        "metformin'e ek tedavi planlandı. İletişim: 0(532) 000 00 00."
    ),
}

# Letters that only a Turkish-orthography string carries. Used to check that the
# widget example is actually in the language the card claims.
_TURKISH_MARKERS: Final[frozenset[str]] = frozenset("çğıöşüÇĞİÖŞÜ")


class PreflightError(Exception):
    """Raised when a blocking preflight step fails."""


@dataclass(frozen=True)
class PreflightResult:
    """What preflight established, for the card to consume."""

    results_path: Path
    payload: dict[str, Any]
    head_sha: str
    language: tuple[str, ...]
    widget_example: str


def _run(command: Sequence[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        list(command),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _as_mapping(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PreflightError(f"{where}: expected a JSON object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise PreflightError(f"{where}: non-string key {key!r}")
        result[key] = item
    return result


def load_results(
    run_id: str, results_dir: Path = RESULTS_DIR
) -> tuple[Path, dict[str, Any]]:
    """Read `eval/results/<run_id>.json`, the sole source of numbers."""
    path = results_dir / f"{run_id}.json"
    if not path.is_file():
        raise PreflightError(
            f"no results artifact at {path}. A card is generated from a "
            "committed eval run; run eval/run.py first and commit its output."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PreflightError(f"{path}: not valid JSON: {exc}") from exc
    return path, _as_mapping(raw, str(path))


def check_committed(path: Path) -> None:
    """Step 1. The results file is committed and the working copy matches HEAD."""
    relative = path.resolve().relative_to(REPO_ROOT).as_posix()
    code, stdout, stderr = _run(["git", "log", "--oneline", "-1", "--", relative])
    if code != 0:
        raise PreflightError(
            f"git log failed for {relative}: {stderr.strip() or 'unknown error'}"
        )
    if not stdout.strip():
        raise PreflightError(
            f"{relative} has no commit history. I5: no card ships whose eval run "
            "is not committed. Commit the results artifact first."
        )
    code, committed, stderr = _run(["git", "show", f"HEAD:{relative}"])
    if code != 0:
        raise PreflightError(
            f"{relative} is not present at HEAD: {stderr.strip() or 'unknown error'}"
        )
    if committed != path.read_text(encoding="utf-8"):
        raise PreflightError(
            f"{relative} differs from its committed copy at HEAD. The numbers "
            "on the card would not be the numbers in the repository."
        )


def check_eval_sha(payload: dict[str, Any]) -> str:
    """Step 2. `eval_sha` names the current commit, and is not 'uncommitted'."""
    eval_sha = payload.get("eval_sha")
    if not isinstance(eval_sha, str) or not eval_sha:
        raise PreflightError("results artifact has no 'eval_sha'")
    if eval_sha == "uncommitted":
        raise PreflightError(
            "eval_sha is 'uncommitted': the run was produced against a dirty "
            "tree, so its numbers cannot be reproduced from any commit."
        )
    code, stdout, stderr = _run(["git", "rev-parse", "HEAD"])
    if code != 0:
        raise PreflightError(
            f"cannot resolve HEAD: {stderr.strip() or 'unknown error'}"
        )
    head = stdout.strip()
    if head != eval_sha:
        raise PreflightError(
            f"eval_sha {eval_sha} does not match HEAD {head}. The gate is "
            "`exact`, not `prefix` and not `nearest run`: publishing from a "
            "different tree than the one evaluated is how a card acquires "
            "numbers no one can reproduce."
        )
    return head


def check_tokenizer_gate(
    payload: dict[str, Any], *, local_tokenizer: str | None
) -> str:
    """Step 3. I6 - the backbone's tokenizer must round-trip the language."""
    base_model = payload.get("base_model")
    if not isinstance(base_model, str) or not base_model:
        raise PreflightError(
            "results artifact has no 'base_model'. I6 gates the backbone, so a "
            "run that does not name one cannot be published."
        )
    languages = _language_tuple(payload)
    target = local_tokenizer if local_tokenizer is not None else base_model
    command = [
        sys.executable,
        str(GATE_SCRIPT),
        target,
        "--languages",
        ",".join(languages),
    ]
    if local_tokenizer is not None:
        command.append("--local-only")
    code, stdout, stderr = _run(command)
    if code != 0:
        raise PreflightError(
            f"gate_tokenizer.py exited {code} for backbone {base_model}:\n"
            f"{stdout.strip()}\n{stderr.strip()}"
        )
    return base_model


def _language_tuple(payload: dict[str, Any]) -> tuple[str, ...]:
    raw = payload.get("language")
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, list) and raw and all(isinstance(item, str) for item in raw):
        return tuple(str(item) for item in raw)
    raise PreflightError(
        "results artifact has no usable 'language'; the card cannot be tagged "
        "with a language the evaluation did not declare."
    )


def required_gate_names(thresholds: dict[str, Any]) -> dict[str, float]:
    """Map every gate declared in thresholds.yaml onto its name in the JSON."""
    mapping: dict[str, tuple[str, str]] = {
        "recall_direct_critical": ("direct_identifiers", "recall_direct_critical"),
        "micro_f1_direct": ("direct_identifiers", "micro_f1_direct"),
        "document_leak_rate_max": ("direct_identifiers", "document_leak_rate_max"),
        "checksum_id_precision": ("direct_identifiers", "checksum_id_precision"),
        "medical_term_fp_rate_max": ("medical_terms", "fp_rate_max"),
        "contextual_reid_rate_max": ("contextual", "reid_rate_max"),
        "sight_unseen_recall_drop_max": (
            "robustness",
            "sight_unseen_recall_drop_max",
        ),
    }
    required: dict[str, float] = {}
    for gate_name, (section, key) in mapping.items():
        block = thresholds.get(section)
        if not isinstance(block, dict) or key not in block:
            raise PreflightError(
                f"eval/thresholds.yaml: missing '{section}.{key}'. A missing "
                "gate fails the run; it never relaxes one."
            )
        required[gate_name] = float(block[key])

    per_entity = thresholds.get("per_entity_recall")
    if not isinstance(per_entity, dict):
        raise PreflightError("eval/thresholds.yaml: missing 'per_entity_recall'")
    for label in sorted(per_entity):
        required[f"recall.{label}"] = float(per_entity[label])
    return required


def check_gates(payload: dict[str, Any], thresholds: dict[str, Any]) -> None:
    """Step 4. Every declared gate is present, unweakened, applicable, passing."""
    stored_sha = payload.get("thresholds_sha")
    current_sha = hashlib.sha256(THRESHOLDS_PATH.read_bytes()).hexdigest()
    if isinstance(stored_sha, str) and stored_sha not in {"missing", current_sha}:
        raise PreflightError(
            "the run was scored against a different eval/thresholds.yaml "
            f"(run: {stored_sha[:12]}, current: {current_sha[:12]}). Re-run the "
            "evaluation against the committed thresholds."
        )

    gates = payload.get("gates")
    if not isinstance(gates, dict):
        raise PreflightError("results artifact has no 'gates' block")

    tier = str(payload.get("tier", ""))
    problems: list[str] = []
    for name, threshold in sorted(required_gate_names(thresholds).items()):
        entry = gates.get(name)
        if not isinstance(entry, dict):
            problems.append(f"{name}: absent from the run's gates block")
            continue
        stored_threshold = entry.get("threshold")
        if (
            not isinstance(stored_threshold, (int, float))
            or float(stored_threshold) != threshold
        ):
            problems.append(
                f"{name}: run was scored against threshold {stored_threshold}, "
                f"eval/thresholds.yaml declares {threshold}"
            )
            continue
        passed = entry.get("pass")
        if passed is None:
            # The contextual gate has no denominator until the L6 red team has
            # run, which is expected on a Safe Harbor card. Every other gate
            # being not-applicable means the card would advertise a number
            # nobody measured.
            if name == "contextual_reid_rate_max" and tier != "expert_determination":
                continue
            problems.append(
                f"{name}: not applicable in this run - unmeasured is not passed"
            )
            continue
        if passed is not True:
            problems.append(
                f"{name}: FAILED (observed {entry.get('observed')}, "
                f"threshold {threshold})"
            )
    if problems:
        raise PreflightError(
            "release gates block publication:\n  " + "\n  ".join(problems)
        )


def check_language(
    payload: dict[str, Any], card_language: Sequence[str] | None
) -> tuple[str, ...]:
    """Step 5. Card language must equal eval language."""
    eval_language = _language_tuple(payload)
    if card_language is None:
        return eval_language
    requested = tuple(card_language)
    if requested != eval_language:
        raise PreflightError(
            f"{LANGUAGE_MISMATCH_MESSAGE}\n"
            f"  requested card language: {list(requested)}\n"
            f"  evaluated language     : {list(eval_language)}"
        )
    return eval_language


def tckn_is_checksum_valid(digits: str) -> bool:
    """The Turkish national ID checksum, used only to prove our example fails it."""
    if len(digits) != 11 or not digits.isdigit() or digits[0] == "0":
        return False
    values = [int(character) for character in digits]
    odd = values[0] + values[2] + values[4] + values[6] + values[8]
    even = values[1] + values[3] + values[5] + values[7]
    if values[9] != (odd * 7 - even) % 10:
        return False
    return values[10] == sum(values[:10]) % 10


def check_widget_example(language: Sequence[str]) -> str:
    """Step 6. The widget example is synthetic and in the evaluated language."""
    primary = language[0]
    example = WIDGET_EXAMPLES.get(primary)
    if example is None:
        raise PreflightError(
            f"no synthetic widget example exists for language {primary!r}. A "
            "card ships an example in the language it was evaluated in, or it "
            "does not ship."
        )
    if primary == "tr" and not any(
        character in _TURKISH_MARKERS for character in example
    ):
        raise PreflightError(
            "the widget example carries no Turkish orthography, so it cannot "
            "be an in-language example."
        )
    for run_start in range(len(example)):
        candidate = example[run_start : run_start + 11]
        if tckn_is_checksum_valid(candidate):
            raise PreflightError(
                "the widget example contains a checksum-VALID national ID. "
                "Every example in this repository is synthetic and every "
                "ID-shaped number in it must fail its checksum (I8)."
            )
    return example


def preflight(
    run_id: str,
    *,
    card_language: Sequence[str] | None = None,
    local_tokenizer: str | None = None,
    results_dir: Path = RESULTS_DIR,
) -> PreflightResult:
    """Run every blocking step, in order."""
    results_path, payload = load_results(run_id, results_dir)
    check_committed(results_path)
    head_sha = check_eval_sha(payload)
    check_tokenizer_gate(payload, local_tokenizer=local_tokenizer)
    try:
        thresholds = load_thresholds(THRESHOLDS_PATH)
    except SchemaError as exc:
        raise PreflightError(str(exc)) from exc
    check_gates(payload, thresholds)
    language = check_language(payload, card_language)
    widget_example = check_widget_example(language)
    return PreflightResult(
        results_path=results_path,
        payload=payload,
        head_sha=head_sha,
        language=language,
        widget_example=widget_example,
    )


def _fmt(value: object, places: int = 4) -> str:
    """Render a metric, never inventing one. Absent stays visibly absent."""
    if value is None:
        return "not measured"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return str(value)
    return f"{float(value):.{places}f}"


def _percent(value: object, places: int = 2) -> str:
    if value is None or isinstance(value, bool) or not isinstance(value, (int, float)):
        return "not measured"
    return f"{float(value) * 100:.{places}f}%"


def template_context(result: PreflightResult) -> dict[str, Any]:
    """Every value the template may print, all of it read from the run JSON."""
    payload = result.payload
    detail = _as_mapping(payload.get("detail", {}), "detail")
    direct = _as_mapping(detail.get("direct", {}), "detail.direct")
    micro_relaxed = _as_mapping(
        direct.get("micro_relaxed", {}), "detail.direct.micro_relaxed"
    )
    micro_strict = _as_mapping(
        direct.get("micro_strict", {}), "detail.direct.micro_strict"
    )
    medical = _as_mapping(detail.get("medical_terms", {}), "detail.medical_terms")
    contextual = _as_mapping(detail.get("contextual", {}), "detail.contextual")
    corpus = _as_mapping(payload.get("corpus", {}), "corpus")
    per_entity = _as_mapping(payload.get("per_entity_detail", {}), "per_entity_detail")
    gates = _as_mapping(payload.get("gates", {}), "gates")

    entity_rows: list[dict[str, str]] = []
    for label in sorted(per_entity):
        counts = _as_mapping(per_entity[label], f"per_entity_detail.{label}")
        entity_rows.append(
            {
                "label": label,
                "gold": str(counts.get("gold", "")),
                "predicted": str(counts.get("predicted", "")),
                "true_positives": str(counts.get("true_positives", "")),
                "recall": _fmt(counts.get("recall")),
                "precision": _fmt(counts.get("precision")),
                "f1": _fmt(counts.get("f1")),
            }
        )

    gate_rows: list[dict[str, str]] = []
    for name in sorted(gates):
        entry = _as_mapping(gates[name], f"gates.{name}")
        passed = entry.get("pass")
        gate_rows.append(
            {
                "name": name,
                "threshold": _fmt(entry.get("threshold")),
                "observed": _fmt(entry.get("observed")),
                "direction": str(entry.get("direction", "")),
                "verdict": (
                    "not applicable"
                    if passed is None
                    else ("PASS" if passed else "FAIL")
                ),
            }
        )

    tier = str(payload.get("tier", ""))
    return {
        "run_id": str(payload.get("run_id", "")),
        "eval_sha": str(payload.get("eval_sha", "")),
        "schema_sha": str(payload.get("schema_sha", "")),
        "thresholds_sha": str(payload.get("thresholds_sha", "")),
        "schema_version": str(payload.get("schema_version", "")),
        "timestamp_utc": str(payload.get("timestamp_utc", "")),
        "eval_run_path": (
            result.results_path.resolve().relative_to(REPO_ROOT).as_posix()
        ),
        "language": list(result.language),
        "language_primary": result.language[0],
        "medical_register": list(payload.get("medical_register", [])),
        "model_name": str(payload.get("model_name") or ""),
        "base_model": str(payload.get("base_model") or ""),
        "detector_name": str(payload.get("detector_name", "")),
        "dataset_type": str(payload.get("dataset_type", "")),
        "dataset_name": str(payload.get("dataset_name", "")),
        "tier": tier,
        "tier_label": (
            "Expert Determination (L1+L2+L3+L4+L5, contextual sweep enabled)"
            if tier == "expert_determination"
            else "Safe Harbor (L1+L2+L4+L5, direct identifiers only)"
        ),
        "documents": str(corpus.get("documents", "")),
        "direct_spans": str(corpus.get("direct_spans", "")),
        "quasi_spans": str(corpus.get("quasi_spans", "")),
        "allowlist_terms": str(corpus.get("allowlist_terms", "")),
        "micro_f1_relaxed": _fmt(micro_relaxed.get("f1")),
        "micro_recall_relaxed": _fmt(micro_relaxed.get("recall")),
        "micro_precision_relaxed": _fmt(micro_relaxed.get("precision")),
        "micro_f1_strict": _fmt(micro_strict.get("f1")),
        "document_leak_rate": _fmt(direct.get("document_leak_rate")),
        "documents_leaking": str(direct.get("documents_leaking", "")),
        "checksum_id_precision": _fmt(direct.get("checksum_id_precision")),
        "sight_unseen_recall_drop": _fmt(direct.get("sight_unseen_recall_drop")),
        "medical_term_fp_rate": _fmt(medical.get("fp_rate")),
        "medical_term_fp_percent": _percent(medical.get("fp_rate")),
        "medical_terms_masked": str(medical.get("masked", "")),
        "medical_terms_total": str(medical.get("total", "")),
        "contextual_reid_rate": _fmt(contextual.get("reid_rate")),
        "contextual_reid_percent": _percent(contextual.get("reid_rate")),
        "contextual_validated_by": str(contextual.get("validated_by") or ""),
        "contextual_coverage": _fmt(contextual.get("coverage")),
        "contextual_gold_quasi_spans": str(contextual.get("gold_quasi_spans", "")),
        "per_entity_rows": entity_rows,
        "gate_rows": gate_rows,
        "widget_example": result.widget_example,
    }


def _eval_results(payload: dict[str, Any], eval_result_cls: Any) -> list[Any]:
    """Shape the JSON's metric entries as EvalResult objects, dropping absent ones."""
    entries = payload.get("metrics")
    if not isinstance(entries, list):
        return []
    results: list[Any] = []
    for raw in entries:
        entry = _as_mapping(raw, "metrics[]")
        value = entry.get("metric_value")
        if (
            value is None
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            continue
        results.append(
            eval_result_cls(
                task_type=str(entry.get("task_type", "")),
                task_name=str(entry.get("task_name", "")),
                dataset_type=str(entry.get("dataset_type", "")),
                dataset_name=str(entry.get("dataset_name", "")),
                metric_type=str(entry.get("metric_type", "")),
                metric_name=str(entry.get("metric_name", "")),
                metric_value=float(value),
                verified=bool(entry.get("verified", False)),
            )
        )
    return results


def build_card(result: PreflightResult) -> str:
    """Render the card. `huggingface_hub` is imported here, not at module scope."""
    try:
        hub = importlib.import_module("huggingface_hub")
    except ImportError as exc:
        raise PreflightError(
            "huggingface_hub is not importable, so no card can be rendered.\n"
            "  Install it in the publishing environment:\n"
            "      uv pip install huggingface_hub\n"
            "  This script never installs anything on your behalf."
        ) from exc

    payload = result.payload
    context = template_context(result)

    card_data: Any = hub.ModelCardData(
        language=list(result.language),
        license="apache-2.0",
        base_model=payload.get("base_model") or None,
        model_name=payload.get("model_name") or None,
        library_name="transformers",
        pipeline_tag="token-classification",
        tags=[
            "de-identification",
            "phi",
            "pii",
            "turkish",
            "clinical",
            "kvkk",
            "hipaa-safe-harbor",
            "token-classification",
        ],
        eval_results=_eval_results(payload, hub.EvalResult),
        widget=[{"text": result.widget_example}],
    )

    # Step 5 again, and deliberately at the point the card object actually
    # exists. Preflight validated the JSON; this validates the artifact being
    # published, so a future refactor that reorders preflight still cannot ship
    # a card whose language tag disagrees with its numbers.
    assert tuple(card_data.language) == result.language, LANGUAGE_MISMATCH_MESSAGE

    card: Any = hub.ModelCard.from_template(
        card_data, template_path=str(TEMPLATE_PATH), **context
    )
    return str(card)


def write_and_diff(content: str, out_path: Path) -> None:
    """Write the card into the build directory and print the diff. No upload."""
    previous = out_path.read_text(encoding="utf-8") if out_path.is_file() else ""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")
    diff = list(
        difflib.unified_diff(
            previous.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f"{out_path} (previous)",
            tofile=f"{out_path} (rendered)",
        )
    )
    if diff:
        print("".join(diff))
    else:
        print("card is byte-identical to the previous build.")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scripts/publish.py",
        description=(
            "Generate a model card from a committed eval run. Writes to a "
            "build directory and prints the diff. It cannot upload."
        ),
    )
    parser.add_argument("run_id", help="run id of eval/results/<run_id>.json")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help=f"build directory for the rendered card (default: {DEFAULT_BUILD_DIR})",
    )
    parser.add_argument(
        "--card-language",
        default=None,
        help=(
            "comma-separated language tag a maintainer believes the card "
            "should carry; blocked unless it equals the evaluated language"
        ),
    )
    parser.add_argument(
        "--local-tokenizer",
        default=None,
        help="local tokenizer directory, so the I6 gate runs air-gapped",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    card_language: tuple[str, ...] | None = None
    if args.card_language is not None:
        card_language = tuple(
            item.strip() for item in str(args.card_language).split(",") if item.strip()
        )

    try:
        result = preflight(
            str(args.run_id),
            card_language=card_language,
            local_tokenizer=args.local_tokenizer,
        )
        content = build_card(result)
    except PreflightError as exc:
        print(f"PREFLIGHT FAILED: {exc}", file=sys.stderr)
        return EXIT_PREFLIGHT_FAILED

    slug = str(result.payload.get("model_name") or result.payload.get("run_id") or "")
    slug = slug.replace("/", "__") or "card"
    out_path = Path(args.out_dir) / slug / "README.md"
    write_and_diff(content, out_path)

    print()
    print(f"card written : {out_path}")
    print(f"eval run     : {result.results_path}")
    print(f"eval_sha     : {result.head_sha}")
    print(
        "NOT PUBLISHED. This script has no upload code path. Review the card, "
        "then publish it by hand with explicit approval."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
