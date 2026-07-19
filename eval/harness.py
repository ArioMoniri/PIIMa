"""The deid-tr scoring engine.

This harness produces THREE SEPARATE NUMBERS and refuses to blend them:

  1. direct-identifier metrics - per-entity recall/precision/F1 plus a micro F1
     over all direct entities. Per-entity recall is always reported and is never
     collapsed into the aggregate, because a 0.88 micro F1 sitting on top of a
     0.85 NAME recall is a breach machine that looks fine on a leaderboard.
  2. medical-term false-positive rate - of the allowlist terms present in the
     corpus, the fraction the system masked. Masking `carcinoma` destroys the
     note, so this is the gate that protects clinical meaning.
  3. contextual coverage plus a HOOK for the red-team-validated contextual
     re-ID rate.

On point 3, the distinction is load-bearing and is preserved in the code and in
the emitted JSON. `contextual_coverage` is DIAGNOSTIC ONLY: narrative
re-identification has no clean ground truth, two annotators legitimately
disagree about whether a phrase re-identifies, and any F1 computed over quasi
spans would be a number about our annotation habits rather than about privacy.
The authoritative figure is `contextual_reid_rate`, produced by the L6
adversarial red team and read from its report. When no red-team run exists the
rate is None, never 0.0 - the absence of an attack is not a survived attack, and
conflating the two would let an unvalidated system look validated.

AND THE REPORT MUST BE ABOUT THIS RUN. Reading the rate out of whatever report
happened to be committed is how `contextual_reid_rate = 0.0303 PASS` came to be
byte-identical for the null detector and the real pipeline: the file had been
generated against a gold-derived oracle masker. `RedteamProvenance` now gates
the read - pipeline masker, matching detector, matching eval_sha, or the field
stays null and the gate stays UNENFORCEABLE.

`checksum_id_precision` is likewise computed over spans a CHECKSUM ACTUALLY
VALIDATED, not over spans carrying a checksum-validatable LABEL. On this corpus
that set is empty by construction (I8 forbids a checksum-valid Turkish ID from
existing here), so the metric reports n/a. It used to report 0.9902 against a
1.000 threshold, which was a number about labelling.

Matching policy. A predicted span matches a gold span when the labels agree and
the spans overlap. Both policies are computed and both are reported:

  strict  - exact byte boundaries on both ends.
  relaxed - any overlap at all.

Relaxed drives the recall gates. A span that catches `Ayse Yilmaz` but also
swallows the Turkish case suffix in `Ayse Yilmaz'in` has leaked nothing, and
letting a boundary convention inflate the miss rate would push the project
toward tuning boundaries instead of toward catching identifiers.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from eval.allowlist import MedicalAllowlist, find_occurrences, load_allowlist
from eval.build_gold import Document, GoldSpan
from eval.schema import REPO_ROOT, Schema

DEFAULT_REDTEAM_REPORT: Final[Path] = REPO_ROOT / "eval" / "results" / "redteam.json"


@dataclass(frozen=True)
class PredictedSpan:
    """A span a detector proposes masking, in original-text UTF-8 byte offsets."""

    start: int
    end: int
    label: str
    confidence: float = 1.0
    # Did a CHECKSUM actually validate this span, or is it merely labelled as a
    # checksum-validatable type? The two are different claims and only the first
    # one carries the 1.000 precision gate. Defaults to False so a detector that
    # does not know the answer cannot accidentally assert it.
    checksum_validated: bool = False


class Detector(Protocol):
    """Anything that proposes spans to mask.

    Deliberately minimal: the harness must be exercisable with no model at all,
    so that M0 can prove the benchmark reports total failure honestly before any
    model exists to make it report success.
    """

    @property
    def name(self) -> str: ...

    def predict(self, text: str) -> list[PredictedSpan]: ...


class NullDetector:
    """A detector that finds nothing.

    The floor of the benchmark. Its scores are the shape of total failure:
    every recall 0.0, document leak rate 1.0 - and, importantly, a medical-term
    false-positive rate of 0.0, because masking nothing cannot mask a medical
    term. That asymmetry is the point of scoring the three numbers separately.
    """

    @property
    def name(self) -> str:
        return "null"

    def predict(self, text: str) -> list[PredictedSpan]:
        del text
        return []


@dataclass(frozen=True)
class LabelCounts:
    """Raw match counts for one entity label under one matching policy."""

    gold: int = 0
    predicted: int = 0
    true_positives: int = 0

    def merged(self, other: LabelCounts) -> LabelCounts:
        return LabelCounts(
            gold=self.gold + other.gold,
            predicted=self.predicted + other.predicted,
            true_positives=self.true_positives + other.true_positives,
        )

    @property
    def recall(self) -> float | None:
        if self.gold == 0:
            return None
        return self.true_positives / self.gold

    @property
    def precision(self) -> float | None:
        if self.predicted == 0:
            return None
        return self.true_positives / self.predicted

    @property
    def f1(self) -> float | None:
        recall = self.recall
        precision = self.precision
        if recall is None or precision is None:
            return None
        if recall + precision == 0.0:
            return 0.0
        return 2 * recall * precision / (recall + precision)

    def as_dict(self) -> dict[str, Any]:
        return {
            "gold": self.gold,
            "predicted": self.predicted,
            "true_positives": self.true_positives,
            "recall": self.recall,
            "precision": self.precision,
            "f1": self.f1,
        }


@dataclass(frozen=True)
class MatchOutcome:
    """Per-label counts plus which gold spans went unmatched in one document."""

    counts: dict[str, LabelCounts]
    missed_gold: tuple[GoldSpan, ...]


def _overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    return max(0, min(a_end, b_end) - max(a_start, b_start))


def match_spans(
    gold: Sequence[GoldSpan], predicted: Sequence[PredictedSpan], *, strict: bool
) -> MatchOutcome:
    """Match predictions to gold spans one-to-one within a single document.

    One-to-one is deliberate: without it, one huge predicted span covering the
    whole note would "match" every gold span in it and score perfect recall
    while masking the entire document.
    """
    candidates: list[tuple[int, int, int]] = []
    for gold_index, gold_span in enumerate(gold):
        for pred_index, pred_span in enumerate(predicted):
            if gold_span.label != pred_span.label:
                continue
            if strict:
                if gold_span.start != pred_span.start or gold_span.end != pred_span.end:
                    continue
                score = gold_span.end - gold_span.start
            else:
                score = _overlap(
                    gold_span.start, gold_span.end, pred_span.start, pred_span.end
                )
                if score <= 0:
                    continue
            candidates.append((score, gold_index, pred_index))

    # Best overlap first so a tight prediction is not consumed by a sloppy one.
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))

    matched_gold: set[int] = set()
    matched_pred: set[int] = set()
    for _, gold_index, pred_index in candidates:
        if gold_index in matched_gold or pred_index in matched_pred:
            continue
        matched_gold.add(gold_index)
        matched_pred.add(pred_index)

    counts: dict[str, LabelCounts] = {}

    def bump(label: str, delta: LabelCounts) -> None:
        counts[label] = counts.get(label, LabelCounts()).merged(delta)

    for gold_index, gold_span in enumerate(gold):
        bump(
            gold_span.label,
            LabelCounts(gold=1, true_positives=1 if gold_index in matched_gold else 0),
        )
    for pred_span in predicted:
        bump(pred_span.label, LabelCounts(predicted=1))

    missed = tuple(span for index, span in enumerate(gold) if index not in matched_gold)
    return MatchOutcome(counts=counts, missed_gold=missed)


@dataclass(frozen=True)
class RedteamProvenance:
    """Where a contextual re-ID rate came from, and whether it may be gated.

    THE DEFECT THIS TYPE EXISTS TO PREVENT. `contextual_reid_rate` used to be
    read out of a committed `eval/results/redteam.json` and dropped into the
    gate whatever produced it. That file had been generated against
    `OracleMasker` - a gold-derived PERFECT masker - so the same 0.0303 PASS
    appeared under the null detector, an L1-only pipeline and a full pipeline
    alike. The report did say `masker=oracle`, honestly, and the gate table
    still counted it as PASS.

    A rate is therefore admissible only when it was measured against the REAL
    pipeline (`masker == "pipeline"`) AND against the same run being scored
    (same detector identity, same eval_sha). Anything else leaves the gate
    UNENFORCEABLE, which is not a pass. The rejected number is still carried
    here, next to the reason it was rejected, so it can be read but never read
    without its source.
    """

    # The masker that produced the number, e.g. "pipeline" or "oracle".
    masker: str | None
    # "pipeline" (gate-eligible) or "reference" (calibration only).
    masker_kind: str | None
    # The detector identity the masked output came from.
    report_detector: str | None
    report_eval_sha: str | None
    report_run_id: str | None
    report_path: str | None
    # What the red team actually measured, admissible or not.
    measured_reid_rate: float | None
    validated_by: str | None
    accepted: bool
    rejected_because: str | None

    @property
    def gated_rate(self) -> float | None:
        """The number the gate may read. None whenever provenance fails."""
        return self.measured_reid_rate if self.accepted else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_path": self.report_path,
            "masker": self.masker,
            "masker_kind": self.masker_kind,
            "detector": self.report_detector,
            "eval_sha": self.report_eval_sha,
            "run_id": self.report_run_id,
            "measured_reid_rate": self.measured_reid_rate,
            "validated_by": self.validated_by,
            "accepted_for_gate": self.accepted,
            "rejected_because": self.rejected_because,
            "rule": (
                "contextual.reid_rate is populated ONLY from a red-team report "
                "whose masker is the real pipeline and whose detector and "
                "eval_sha match the run being scored. A rate from any other "
                "masker is calibration: it measures the red team, not deid-tr."
            ),
        }


NO_REPORT = RedteamProvenance(
    masker=None,
    masker_kind=None,
    report_detector=None,
    report_eval_sha=None,
    report_run_id=None,
    report_path=None,
    measured_reid_rate=None,
    validated_by=None,
    accepted=False,
    rejected_because="no L6 red-team report exists",
)


@dataclass(frozen=True)
class ContextualResult:
    """Contextual findings, kept structurally separate from the F1 metrics.

    `coverage` is diagnostic. `reid_rate` is the gate. They are different kinds
    of number and this type exists so nobody can accidentally read one as the
    other.
    """

    coverage: float | None
    gold_quasi_spans: int
    covered_quasi_spans: int
    provenance: RedteamProvenance = NO_REPORT

    @property
    def reid_rate(self) -> float | None:
        """The gate-eligible rate. None unless provenance was accepted."""
        return self.provenance.gated_rate

    @property
    def validated_by(self) -> str | None:
        return self.provenance.validated_by if self.provenance.accepted else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "coverage": self.coverage,
            "coverage_is_diagnostic_only": True,
            "coverage_note": (
                "Fraction of gold quasi spans overlapped by some predicted span. "
                "NOT a validated score: contextual quasi-identifiers are not "
                "scored by F1. The authoritative number is reid_rate, which comes "
                "from the L6 red team."
            ),
            "gold_quasi_spans": self.gold_quasi_spans,
            "covered_quasi_spans": self.covered_quasi_spans,
            "reid_rate": self.reid_rate,
            "reid_rate_is_authoritative": True,
            "validated_by": self.validated_by,
            # The number and its source, always together. Emitting the rate
            # without this block is what let a published PASS come from a run
            # nobody was scoring.
            "reid_rate_provenance": self.provenance.as_dict(),
        }


@dataclass(frozen=True)
class RunMetrics:
    """Everything one evaluation run produced."""

    detector_name: str
    documents: int
    per_entity_relaxed: dict[str, LabelCounts]
    per_entity_strict: dict[str, LabelCounts]
    micro_direct_relaxed: LabelCounts
    micro_direct_strict: LabelCounts
    medical_term_fp_rate: float | None
    medical_terms_total: int
    medical_terms_masked: int
    medical_term_fp_rate_vocabulary: float | None
    vocabulary_terms_total: int
    vocabulary_terms_masked: int
    contextual: ContextualResult
    document_leak_rate: float | None
    documents_leaking: int
    # THE DENOMINATOR PROBLEM, made explicit.
    #
    # `document_leak_rate` divides by every document in the corpus, including
    # documents that hold no direct gold span at all and therefore CANNOT leak
    # a direct identifier. Against the null detector that produces a headline
    # like "0.9565 (132/138)", and an auditor reading a 95.7% leak rate under a
    # detector that finds nothing may reasonably conclude the remaining 4.3% of
    # documents were handled correctly. They were not; they were unleakable.
    # Both denominators are therefore carried and both are reported.
    documents_with_direct_spans: int
    documents_without_direct_spans: int
    document_leak_rate_over_leakable: float | None
    checksum_id_precision: float | None
    checksum_id_counts: LabelCounts
    recall_by_split: dict[str, float | None]
    sight_unseen_recall_drop: float | None

    @property
    def per_entity_recall(self) -> dict[str, float | None]:
        return {
            label: counts.recall
            for label, counts in sorted(self.per_entity_relaxed.items())
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "detector_name": self.detector_name,
            "documents": self.documents,
            "direct": {
                "per_entity_relaxed": {
                    label: counts.as_dict()
                    for label, counts in sorted(self.per_entity_relaxed.items())
                },
                "per_entity_strict": {
                    label: counts.as_dict()
                    for label, counts in sorted(self.per_entity_strict.items())
                },
                "micro_relaxed": self.micro_direct_relaxed.as_dict(),
                "micro_strict": self.micro_direct_strict.as_dict(),
                # Field names spell out their own denominators. A bare
                # "leak_rate" is the field an auditor misreads.
                "documents_evaluated": self.documents,
                "documents_with_direct_spans": self.documents_with_direct_spans,
                "documents_excluded_no_direct_identifier": (
                    self.documents_without_direct_spans
                ),
                "documents_leaked": self.documents_leaking,
                "document_leak_rate_over_all_documents": self.document_leak_rate,
                "document_leak_rate_over_documents_with_direct_spans": (
                    self.document_leak_rate_over_leakable
                ),
                "document_leak_rate_denominator_note": (
                    "A document with zero direct gold spans cannot leak a "
                    "direct identifier, so it dilutes the over-all-documents "
                    "rate downward without any detection having occurred. The "
                    "gate reads the over-documents-with-direct-spans rate, "
                    "which is the honest one."
                ),
                # Retained under its original name so existing readers of the
                # artifact do not silently start reading a different number.
                "document_leak_rate": self.document_leak_rate,
                "documents_leaking": self.documents_leaking,
                "checksum_id_precision": self.checksum_id_precision,
                "checksum_id_counts": self.checksum_id_counts.as_dict(),
                "checksum_id_precision_denominator": (
                    "spans a checksum ACTUALLY VALIDATED, not spans carrying a "
                    "checksum-validatable label. I8 forbids a checksum-valid "
                    "Turkish ID from existing in this repository, so on this "
                    "corpus the denominator is zero and the metric is n/a. The "
                    "protection path is exercised instead by the synthetic "
                    "runtime suite core/tests/checksum_protection_armed.rs."
                ),
                "recall_by_split": self.recall_by_split,
                "sight_unseen_recall_drop": self.sight_unseen_recall_drop,
            },
            "medical_terms": {
                # Two denominators, reported separately and never blended - the
                # same discipline the brief demands of the three headline
                # numbers. `annotated` is what a human marked in a fixture;
                # `vocabulary` is every eval/allowlist/*.txt term the scanner
                # found anywhere in the corpus. A system can look clean on the
                # first and terrible on the second, and averaging them would
                # hide exactly that.
                "fp_rate": self.medical_term_fp_rate,
                "fp_rate_annotated": self.medical_term_fp_rate,
                "total": self.medical_terms_total,
                "masked": self.medical_terms_masked,
                "annotated": {
                    "fp_rate": self.medical_term_fp_rate,
                    "total": self.medical_terms_total,
                    "masked": self.medical_terms_masked,
                    "denominator": "per-document allowlist_terms annotations",
                },
                "fp_rate_vocabulary": self.medical_term_fp_rate_vocabulary,
                "vocabulary": {
                    "fp_rate": self.medical_term_fp_rate_vocabulary,
                    "total": self.vocabulary_terms_total,
                    "masked": self.vocabulary_terms_masked,
                    "denominator": (
                        "every eval/allowlist/*.txt term occurring in the corpus"
                    ),
                },
                # Which number the release gate asserts against. The gate is
                # unchanged by this addition on purpose: silently re-pointing a
                # committed gate at a different denominator would change what
                # a published card means without anyone deciding to.
                "gate_reads": "fp_rate_annotated",
            },
            "contextual": self.contextual.as_dict(),
        }


def _optional_str(raw: dict[str, Any], key: str, path: Path) -> str | None:
    value = raw.get(key)
    if value is None or isinstance(value, str):
        return value
    raise ValueError(f"{path}: '{key}' must be a string or null")


def _optional_rate(raw: dict[str, Any], key: str, path: Path) -> float | None:
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{path}: '{key}' must be a number, got {value!r}")
    return float(value)


def load_redteam_report(
    path: Path | None = None,
    *,
    detector_name: str | None = None,
    eval_sha: str | None = None,
) -> RedteamProvenance:
    """Read an L6 red-team report and decide whether its rate may be gated.

    Absence returns a rejected provenance carrying no rate. That is not a
    passing score - it means the contextual tier is UNVALIDATED, and every
    consumer must treat it as such.

    Presence is not enough either. The rate is admissible only when the report
    was produced by the PIPELINE masker against the same detector and the same
    eval_sha as the run being scored. See `RedteamProvenance`.
    """
    report_path = path if path is not None else DEFAULT_REDTEAM_REPORT
    if not report_path.is_file():
        return NO_REPORT
    raw = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{report_path}: expected a JSON object")

    masker = _optional_str(raw, "masker", report_path)
    masker_kind = _optional_str(raw, "masker_kind", report_path)
    provenance = raw.get("provenance")
    if provenance is None:
        provenance = {}
    if not isinstance(provenance, dict):
        raise ValueError(f"{report_path}: 'provenance' must be an object or null")

    report_detector = _optional_str(provenance, "detector", report_path)
    report_eval_sha = _optional_str(provenance, "eval_sha", report_path)
    run_id = _optional_str(raw, "run_id", report_path)
    validated_by = _optional_str(raw, "validated_by", report_path)

    # The measured number is read from either field. `reid_rate_measured` is
    # what the runner now writes for every masker; `contextual_reid_rate` is the
    # gate-eligible copy, and older reports carry only the latter. Reading both
    # means a legacy oracle report is still SEEN - and still refused.
    measured = _optional_rate(raw, "reid_rate_measured", report_path)
    if measured is None:
        measured = _optional_rate(raw, "contextual_reid_rate", report_path)

    def reject(reason: str) -> RedteamProvenance:
        return RedteamProvenance(
            masker=masker,
            masker_kind=masker_kind,
            report_detector=report_detector,
            report_eval_sha=report_eval_sha,
            report_run_id=run_id,
            report_path=str(report_path),
            measured_reid_rate=measured,
            validated_by=validated_by,
            accepted=False,
            rejected_because=reason,
        )

    if measured is None:
        return reject("the report carries no re-ID rate")
    if masker != "pipeline" or masker_kind != "pipeline":
        return reject(
            f"the report was produced against masker={masker!r}, which is a "
            "REFERENCE instrument. Its rate calibrates the red team and says "
            "nothing about what deid-tr masks."
        )
    if detector_name is None:
        return reject(
            "the scoring run named no detector, so the report cannot be shown "
            "to describe it"
        )
    if report_detector != detector_name:
        return reject(
            f"the report was produced against detector={report_detector!r} but "
            f"this run scores {detector_name!r}"
        )
    if eval_sha is None or report_eval_sha is None:
        return reject("the report or the scoring run carries no eval_sha")
    if report_eval_sha != eval_sha:
        return reject(
            "the report's eval_sha does not match the run being scored, so the "
            "attacked output was produced by different code"
        )

    return RedteamProvenance(
        masker=masker,
        masker_kind=masker_kind,
        report_detector=report_detector,
        report_eval_sha=report_eval_sha,
        report_run_id=run_id,
        report_path=str(report_path),
        measured_reid_rate=measured,
        validated_by=validated_by,
        accepted=True,
        rejected_because=None,
    )


def _micro(counts: Iterable[LabelCounts]) -> LabelCounts:
    total = LabelCounts()
    for item in counts:
        total = total.merged(item)
    return total


def evaluate(
    documents: Sequence[Document],
    detector: Detector,
    schema: Schema,
    redteam_report: Path | None = None,
    allowlist: MedicalAllowlist | None = None,
    *,
    eval_sha: str | None = None,
) -> RunMetrics:
    """Score `detector` against `documents`.

    `eval_sha` identifies the code this run scores. It is passed through to the
    red-team provenance check, which refuses a re-ID rate produced by a
    different run.
    """
    vocabulary = allowlist if allowlist is not None else load_allowlist(schema)
    relaxed: dict[str, LabelCounts] = {}
    strict: dict[str, LabelCounts] = {}
    split_counts: dict[str, LabelCounts] = {}

    checksum_counts = LabelCounts()
    documents_leaking = 0
    documents_with_direct_spans = 0
    medical_terms_total = 0
    medical_terms_masked = 0
    vocabulary_terms_total = 0
    vocabulary_terms_masked = 0
    gold_quasi_total = 0
    quasi_covered = 0

    def accumulate(
        target: dict[str, LabelCounts], outcome_counts: dict[str, LabelCounts]
    ) -> None:
        for label, counts in outcome_counts.items():
            target[label] = target.get(label, LabelCounts()).merged(counts)

    for document in documents:
        predictions = detector.predict(document.text)

        direct_gold = document.direct_spans(schema)
        if direct_gold:
            documents_with_direct_spans += 1
        direct_predictions = [
            span for span in predictions if schema.is_direct(span.label)
        ]

        relaxed_outcome = match_spans(direct_gold, direct_predictions, strict=False)
        strict_outcome = match_spans(direct_gold, direct_predictions, strict=True)
        accumulate(relaxed, relaxed_outcome.counts)
        accumulate(strict, strict_outcome.counts)

        # Relaxed drives the leak rate: a span that includes the case suffix has
        # not leaked, and counting it as a leak would misreport the breach risk.
        if relaxed_outcome.missed_gold:
            documents_leaking += 1

        # CHECKSUM PRECISION, over spans a checksum ACTUALLY VALIDATED.
        #
        # It used to be computed over predictions selected BY LABEL, which made
        # it a statement about spans labelled TCKN/VKN/IBAN rather than about
        # spans the checksum vouched for. Those are different sets, and on this
        # corpus the second one is EMPTY: I8 forbids a checksum-valid Turkish ID
        # from existing in the repository, so every eleven-digit run here fails
        # its check digits by construction. The honest report is therefore n/a,
        # and the guardrail is exercised instead by the synthetic runtime suite
        # in core/tests/checksum_protection_armed.rs (see ADR D-030).
        validated_predictions = [
            span for span in direct_predictions if span.checksum_validated
        ]
        if validated_predictions:
            checksum_gold = [
                span
                for span in direct_gold
                if span.label in schema.checksum_validatable_ids
            ]
            checksum_outcome = match_spans(
                checksum_gold, validated_predictions, strict=False
            )
            checksum_counts = checksum_counts.merged(
                LabelCounts(
                    predicted=len(validated_predictions),
                    gold=len(checksum_gold),
                    true_positives=sum(
                        counts.true_positives
                        for counts in checksum_outcome.counts.values()
                    ),
                )
            )

        split_micro = _micro(
            counts
            for label, counts in relaxed_outcome.counts.items()
            if schema.is_direct(label)
        )
        split_counts[document.split] = split_counts.get(
            document.split, LabelCounts()
        ).merged(split_micro)

        # Any predicted span overlapping an allowlist term masks it, regardless
        # of the label the detector assigned; the harm is the destroyed term.
        for term in document.allowlist_terms:
            medical_terms_total += 1
            if any(
                _overlap(term.start, term.end, span.start, span.end) > 0
                for span in predictions
            ):
                medical_terms_masked += 1

        # The second denominator. The annotated set is whatever a human thought
        # to mark; the vocabulary set is every term the project actually claims
        # to protect. Scoring only the first is how 1813 curated terms became
        # data nothing read.
        for occurrence in find_occurrences(document.doc_id, document.text, vocabulary):
            vocabulary_terms_total += 1
            if any(
                _overlap(occurrence.start, occurrence.end, span.start, span.end) > 0
                for span in predictions
            ):
                vocabulary_terms_masked += 1

        # Coverage is label-agnostic: quasi category boundaries are a judgement
        # call, so requiring the exact quasi label would understate coverage on
        # a number that is diagnostic anyway.
        for quasi_span in document.quasi_spans(schema):
            gold_quasi_total += 1
            if any(
                _overlap(quasi_span.start, quasi_span.end, span.start, span.end) > 0
                for span in predictions
            ):
                quasi_covered += 1

    direct_relaxed = {
        label: counts for label, counts in relaxed.items() if schema.is_direct(label)
    }
    direct_strict = {
        label: counts for label, counts in strict.items() if schema.is_direct(label)
    }

    recall_by_split: dict[str, float | None] = {
        split: counts.recall for split, counts in sorted(split_counts.items())
    }
    dev_recall = recall_by_split.get("dev")
    unseen_recall = recall_by_split.get("sight_unseen")
    drop: float | None = None
    if dev_recall is not None and unseen_recall is not None:
        drop = dev_recall - unseen_recall

    provenance = load_redteam_report(
        redteam_report, detector_name=detector.name, eval_sha=eval_sha
    )

    contextual = ContextualResult(
        coverage=(quasi_covered / gold_quasi_total) if gold_quasi_total else None,
        gold_quasi_spans=gold_quasi_total,
        covered_quasi_spans=quasi_covered,
        provenance=provenance,
    )

    return RunMetrics(
        detector_name=detector.name,
        documents=len(documents),
        per_entity_relaxed=direct_relaxed,
        per_entity_strict=direct_strict,
        micro_direct_relaxed=_micro(direct_relaxed.values()),
        micro_direct_strict=_micro(direct_strict.values()),
        medical_term_fp_rate=(
            medical_terms_masked / medical_terms_total if medical_terms_total else None
        ),
        medical_terms_total=medical_terms_total,
        medical_terms_masked=medical_terms_masked,
        medical_term_fp_rate_vocabulary=(
            vocabulary_terms_masked / vocabulary_terms_total
            if vocabulary_terms_total
            else None
        ),
        vocabulary_terms_total=vocabulary_terms_total,
        vocabulary_terms_masked=vocabulary_terms_masked,
        contextual=contextual,
        document_leak_rate=(documents_leaking / len(documents) if documents else None),
        documents_leaking=documents_leaking,
        documents_with_direct_spans=documents_with_direct_spans,
        documents_without_direct_spans=len(documents) - documents_with_direct_spans,
        document_leak_rate_over_leakable=(
            documents_leaking / documents_with_direct_spans
            if documents_with_direct_spans
            else None
        ),
        checksum_id_precision=checksum_counts.precision,
        checksum_id_counts=checksum_counts,
        recall_by_split=recall_by_split,
        sight_unseen_recall_drop=drop,
    )
