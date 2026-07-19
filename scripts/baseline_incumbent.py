"""Measure a third-party Turkish PII model on OUR benchmark, so the comparison
is measured rather than asserted.

    python3 scripts/baseline_incumbent.py <hf-model-id> --i-have-approval

DO NOT RUN THIS CASUALLY. It downloads a model and its tokenizer from the
Hugging Face Hub and therefore requires network access and explicit human
approval in the session. It refuses to start without `--i-have-approval`, and
with the flag it still prints what it is about to fetch before fetching it. No
patient text is involved: the corpus it scores against is the synthetic gold set
in this repository. This script is never imported by `core/` or by the eval
harness, so invariant I1 - PHI never leaves the device - is untouched by it.

WHAT IT PRODUCES. A results artifact in `eval/results/` in exactly the schema
`eval/run.py` writes, so a baseline run and one of our own runs can be diffed
field by field. It reports the same three separate numbers our own report does:
direct-identifier recall (per entity type as well as micro), medical-term
false-positive rate, and the contextual figure.

WHAT IT IS BUILT TO SURFACE RATHER THAN PRESUME. Two hypotheses motivated this
script, and the script is arranged so that either can come out false:

  - Near-zero contextual quasi-identifier coverage. A token classifier has no
    label for "works at the Central Bank", so its coverage of narrative
    quasi-identifiers may be zero BY CONSTRUCTION rather than by failure. The
    report says which, and the artifact records the model's own label
    inventory so a reader can check.
  - Mishandling of code-switched medical terms. A Latin or English root
    carrying a Turkish suffix is where the boundary between a suffixed name and
    a suffixed diagnosis lives. That shows up as the medical-term
    false-positive rate, measured on the same allowlist our own runs use.

The label map is deliberately GENEROUS. Where a third-party label plausibly
corresponds to one of ours, it is mapped, and where it maps to several the
mapping picks the one that earns the baseline the most credit. Every unmapped
label the model emitted is printed and stored in the artifact. A baseline that
looks weak because we scored it against a label space it never claimed would be
a rigged comparison, and rigged comparisons are worthless to us: the point is a
number a skeptical reader can reproduce.

REPORTING ETHICS. These are conditions on how any result from this script is
written up, not decoration.

  - Prior art gets cited, not attacked. The models this measures are real work
    by real researchers, and the citation goes in the write-up alongside the
    number.
  - Findings are reported as benchmark results: model id, revision, corpus,
    commit, thresholds file, and the three numbers, with the method reproducible
    from this repository. Not as a claim about anyone's competence.
  - The criticism is of a PROCESS that published faster than it evaluated -
    cards carrying numbers from a different language than the model, backbones
    that cannot represent the target language - never of a person, a team, or an
    institution.
  - A baseline that beats us is reported with the same prominence as one that
    does not. The benchmark is the product; a benchmark that only publishes
    flattering comparisons is not a benchmark.
  - Numbers are reported with their denominators and their corpus. "Near-zero
    contextual coverage" is meaningless without saying how many quasi spans
    were in the corpus.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.build_gold import (  # noqa: E402
    DEFAULT_CORPUS_ROOTS,
    GoldError,
    load_corpus,
    summarise,
)
from eval.harness import PredictedSpan, evaluate  # noqa: E402
from eval.report import build_gates, render  # noqa: E402
from eval.run import RESULTS_DIR, build_artifact  # noqa: E402
from eval.schema import SchemaError, load_schema, load_thresholds  # noqa: E402

EXIT_OK: Final[int] = 0
EXIT_USAGE: Final[int] = 2

# Generous by design: where a third-party label could map to several of ours,
# this picks the one that credits the baseline most. Keys are compared after
# upper-casing and stripping BIO prefixes.
DEFAULT_LABEL_MAP: Final[dict[str, str]] = {
    "PER": "PATIENT_NAME",
    "PERSON": "PATIENT_NAME",
    "NAME": "PATIENT_NAME",
    "PATIENT": "PATIENT_NAME",
    "FIRSTNAME": "PATIENT_NAME",
    "LASTNAME": "PATIENT_NAME",
    "SURNAME": "PATIENT_NAME",
    "DOCTOR": "CLINICIAN_NAME",
    "STAFF": "CLINICIAN_NAME",
    "USERNAME": "PATIENT_NAME",
    "LOC": "ADDRESS_CITY",
    "LOCATION": "ADDRESS_CITY",
    "GPE": "ADDRESS_CITY",
    "CITY": "ADDRESS_CITY",
    "DISTRICT": "ADDRESS_DISTRICT",
    "STATE": "ADDRESS_CITY",
    "STREET": "ADDRESS_STREET",
    "ADDRESS": "ADDRESS_STREET",
    "BUILDINGNUMBER": "ADDRESS_STREET",
    "ZIPCODE": "POSTAL_CODE",
    "POSTCODE": "POSTAL_CODE",
    "POSTALCODE": "POSTAL_CODE",
    "ORG": "FACILITY_NAME",
    "ORGANIZATION": "FACILITY_NAME",
    "HOSPITAL": "FACILITY_NAME",
    "COMPANY": "FACILITY_NAME",
    "DATE": "DATE_ADMISSION",
    "TIME": "DATE_ADMISSION",
    "DOB": "DATE_BIRTH",
    "DATEOFBIRTH": "DATE_BIRTH",
    "BIRTHDATE": "DATE_BIRTH",
    "AGE": "AGE_OVER_89",
    "PHONE": "PHONE",
    "PHONENUMBER": "PHONE",
    "TEL": "PHONE",
    "FAX": "PHONE",
    "EMAIL": "EMAIL",
    "URL": "URL",
    "IP": "IP_ADDRESS",
    "IPADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    "ID": "OTHER_UNIQUE_ID",
    "IDNUM": "OTHER_UNIQUE_ID",
    "SSN": "TCKN",
    "NATIONALID": "TCKN",
    "TCKN": "TCKN",
    "TCKIMLIKNO": "TCKN",
    "VKN": "VKN",
    "TAXNUMBER": "VKN",
    "SGK": "SGK_NO",
    "MRN": "MRN",
    "MEDICALRECORD": "MRN",
    "MEDICALRECORDNUMBER": "MRN",
    "HEALTHPLAN": "HEALTH_PLAN_ID",
    "INSURANCE": "HEALTH_PLAN_ID",
    "IBAN": "IBAN",
    "BANKACCOUNT": "ACCOUNT_NO",
    "ACCOUNT": "ACCOUNT_NO",
    "ACCOUNTNUMBER": "ACCOUNT_NO",
    "CREDITCARD": "ACCOUNT_NO",
    "PASSPORT": "PASSPORT_NO",
    "PASSPORTNUMBER": "PASSPORT_NO",
    "LICENSE": "LICENSE_PLATE",
    "LICENSEPLATE": "LICENSE_PLATE",
    "PLATE": "LICENSE_PLATE",
    "VEHICLE": "VEHICLE_ID",
    "VIN": "VEHICLE_ID",
    "DEVICE": "DEVICE_ID",
    "BIOMETRIC": "BIOMETRIC_ID",
    "CERTIFICATE": "CERTIFICATE_NO",
    "PHOTO": "PHOTO_REF",
    # Mapped on purpose. A profession label is the closest a token classifier
    # gets to a narrative employment quasi-identifier, and refusing the mapping
    # would manufacture the contextual result this script exists to test.
    "PROFESSION": "EMPLOYER_ROLE",
    "JOB": "EMPLOYER_ROLE",
    "JOBTITLE": "EMPLOYER_ROLE",
    "OCCUPATION": "EMPLOYER_ROLE",
    "EMPLOYER": "EMPLOYER_ROLE",
}

NETWORK_NOTICE: Final[str] = (
    "NETWORK NOTICE. This script downloads a third-party model and tokenizer "
    "from the Hugging Face Hub.\n"
    "  It is a benchmarking tool, not part of the de-identification pipeline: "
    "core/ and the eval harness never import it, and invariant I1 (PHI never "
    "leaves the device) is unaffected.\n"
    "  The corpus it scores against is the synthetic gold set in this "
    "repository. No patient text is involved.\n"
    "  Running it requires explicit human approval in the session."
)


class BaselineError(Exception):
    """Raised when the baseline cannot be run or scored."""


def normalise_label(raw: str) -> str:
    """Strip BIO prefixes and separators so label maps stay readable."""
    text = raw.strip().upper()
    for prefix in ("B-", "I-", "E-", "S-", "L-", "U-"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    return text.replace("_", "").replace("-", "").replace(" ", "")


def load_label_map(path: Path | None, valid_ids: frozenset[str]) -> dict[str, str]:
    """Load and validate the third-party -> deid-tr label mapping."""
    mapping = dict(DEFAULT_LABEL_MAP)
    if path is not None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"{path}: cannot read label map: {exc}") from exc
        if not isinstance(raw, dict):
            raise BaselineError(f"{path}: label map must be a JSON object")
        for key, value in raw.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise BaselineError(
                    f"{path}: label map keys and values must be strings"
                )
            mapping[normalise_label(key)] = value
    unknown = sorted({target for target in mapping.values() if target not in valid_ids})
    if unknown:
        raise BaselineError(
            "label map targets labels that do not exist in eval/schema.yaml: "
            + ", ".join(unknown)
        )
    return mapping


class IncumbentDetector:
    """A third-party token classifier wrapped in the harness `Detector` protocol.

    Character offsets from the pipeline are converted to UTF-8 BYTE offsets
    here, because that is what every span in this project speaks and because
    Turkish letters are multi-byte: scoring character offsets against byte gold
    spans would misreport the baseline in whichever direction the arithmetic
    happened to land.
    """

    def __init__(
        self,
        model_id: str,
        pipeline: Any,
        label_map: dict[str, str],
        min_score: float,
    ) -> None:
        self._model_id = model_id
        self._pipeline: Any = pipeline
        self._label_map = label_map
        self._min_score = min_score
        self.unmapped_labels: dict[str, int] = {}
        self.emitted_labels: dict[str, int] = {}
        self.below_threshold = 0

    @property
    def name(self) -> str:
        return f"incumbent:{self._model_id}"

    def predict(self, text: str) -> list[PredictedSpan]:
        raw_results: Any = self._pipeline(text)
        spans: list[PredictedSpan] = []
        for item in raw_results:
            entity = item.get("entity_group") or item.get("entity") or ""
            label = normalise_label(str(entity))
            self.emitted_labels[label] = self.emitted_labels.get(label, 0) + 1

            score = float(item.get("score", 1.0))
            if score < self._min_score:
                self.below_threshold += 1
                continue

            mapped = self._label_map.get(label)
            if mapped is None:
                self.unmapped_labels[label] = self.unmapped_labels.get(label, 0) + 1
                continue

            char_start = int(item.get("start", -1))
            char_end = int(item.get("end", -1))
            if not 0 <= char_start < char_end <= len(text):
                # A prediction we cannot anchor is dropped rather than guessed
                # at, and the drop is visible in the counts below.
                self.unmapped_labels["<unanchorable>"] = (
                    self.unmapped_labels.get("<unanchorable>", 0) + 1
                )
                continue
            byte_start = len(text[:char_start].encode("utf-8"))
            byte_end = len(text[:char_end].encode("utf-8"))
            spans.append(
                PredictedSpan(
                    start=byte_start, end=byte_end, label=mapped, confidence=score
                )
            )
        return spans


def build_pipeline(model_id: str, revision: str | None) -> Any:
    """Import `transformers` lazily and construct the token-classification pipeline."""
    try:
        transformers = importlib.import_module("transformers")
    except ImportError as exc:
        raise BaselineError(
            "transformers is not importable, so no baseline can be run.\n"
            "  Install it in the benchmarking environment:\n"
            "      uv pip install transformers torch\n"
            "  This script never installs anything on your behalf."
        ) from exc
    kwargs: dict[str, Any] = {
        "task": "token-classification",
        "model": model_id,
        "aggregation_strategy": "simple",
    }
    if revision is not None:
        kwargs["revision"] = revision
    return transformers.pipeline(**kwargs)


def _render_inventory(detector: IncumbentDetector, quasi_span_total: int) -> str:
    lines = ["-" * 78, "BASELINE LABEL INVENTORY", "-" * 78]
    if detector.emitted_labels:
        for label, count in sorted(detector.emitted_labels.items()):
            was_dropped = label in detector.unmapped_labels
            note = "UNMAPPED (not scored)" if was_dropped else "mapped"
            lines.append(f"  {label:<24} {count:>6}  {note}")
    else:
        lines.append("  the model emitted no spans at all on this corpus")
    lines.append(f"  predictions below the score threshold: {detector.below_threshold}")
    lines.append("")
    lines.append(
        "Read the contextual number against this inventory. If no emitted label "
        "corresponds to a narrative quasi-identifier, contextual coverage is "
        f"zero BY CONSTRUCTION over the corpus's {quasi_span_total} quasi "
        "span(s), which is a statement about the model's task definition rather "
        "than about its quality at the task it does claim."
    )
    return "\n".join(lines)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scripts/baseline_incumbent.py",
        description=(
            "Run a third-party Turkish PII model through the deid-tr harness "
            "and write a results artifact in the same schema as our own runs."
        ),
    )
    parser.add_argument("model_id", help="Hugging Face model id of the baseline")
    parser.add_argument(
        "--i-have-approval",
        action="store_true",
        help="confirm explicit human approval to download and run this model",
    )
    parser.add_argument("--revision", default=None, help="pin the model revision")
    parser.add_argument(
        "--label-map",
        type=Path,
        default=None,
        help="JSON file overriding or extending the third-party label mapping",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="drop predictions below this score (default 0.0, i.e. keep all)",
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
    parser.add_argument("--run-id", default=None, help="run identifier")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="results artifact path (default: eval/results/<run_id>.json)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    print(NETWORK_NOTICE, file=sys.stderr)
    if not args.i_have_approval:
        print(
            "\nrefusing to run: pass --i-have-approval once a human has "
            f"approved downloading and running {args.model_id}.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    print(
        f"\napproval flag present; about to fetch {args.model_id}"
        + (f" at revision {args.revision}" if args.revision else "")
        + "\n",
        file=sys.stderr,
    )

    try:
        schema = load_schema()
        thresholds = load_thresholds()
    except SchemaError as exc:
        print(f"schema/thresholds error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    roots = tuple(args.corpus_root) if args.corpus_root else DEFAULT_CORPUS_ROOTS
    try:
        documents = load_corpus(roots, schema)
    except GoldError as exc:
        print(f"FAILED to resolve gold corpus: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        label_map = load_label_map(args.label_map, schema.all_ids)
        pipeline = build_pipeline(str(args.model_id), args.revision)
    except BaselineError as exc:
        print(f"cannot run baseline: {exc}", file=sys.stderr)
        return EXIT_USAGE

    detector = IncumbentDetector(
        model_id=str(args.model_id),
        pipeline=pipeline,
        label_map=label_map,
        min_score=float(args.min_score),
    )
    metrics = evaluate(documents, detector, schema, args.redteam_report)

    slug = str(args.model_id).replace("/", "__")
    run_id = args.run_id or datetime.now(timezone.utc).strftime(
        f"%Y%m%dT%H%M%SZ-baseline-{slug}"
    )
    out_path = args.out if args.out is not None else RESULTS_DIR / f"{run_id}.json"

    artifact = build_artifact(
        metrics,
        schema,
        thresholds,
        summarise(documents, schema),
        run_id=run_id,
        # A third-party token classifier covers direct identifiers only, so
        # scoring it as Safe Harbor is the comparison that makes sense.
        tier="safe_harbor",
        detector_name=detector.name,
        base_model=str(args.model_id),
        model_name=str(args.model_id),
        dataset_type="deid-tr/TurkDeID-Bench",
        dataset_name="TurkDeID-Bench",
    )
    artifact["baseline"] = {
        "third_party_model": str(args.model_id),
        "revision": args.revision,
        "min_score": float(args.min_score),
        "emitted_labels": dict(sorted(detector.emitted_labels.items())),
        "unmapped_labels": dict(sorted(detector.unmapped_labels.items())),
        "predictions_below_threshold": detector.below_threshold,
        "label_map": dict(sorted(label_map.items())),
        "label_map_note": (
            "Generous by design: where a third-party label could map to several "
            "of ours, the mapping picks the one that credits the baseline most."
        ),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    gates = build_gates(metrics, schema, thresholds)
    print(render(metrics, gates, enforcing=False))
    print()
    print(_render_inventory(detector, metrics.contextual.gold_quasi_spans))
    print()
    print(f"baseline artifact : {out_path}")
    print(f"third-party model : {args.model_id}")
    print(
        "Report this as a benchmark result with its corpus and denominators, "
        "cite the model's own publication, and criticise the publishing process "
        "rather than any person."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
