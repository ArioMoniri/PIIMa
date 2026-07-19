"""Attack 3 - structural leakage. The test L5 must pass.

A surrogate that is the same length as the value it replaced tells an attacker
the length of the original. Over a corpus that is enough to shortlist: Turkish
given-name plus surname lengths are far from uniform, and combined with one more
attribute a length constraint cuts the candidate set hard. Casing does the same
job - a surrogate that is ALL CAPS exactly when the original was tells you the
header convention, and a title-cased surrogate confirms a proper noun.

L5's own specification says it: "break structural tells - do NOT preserve length
or casing patterns". This attack is the assertion of that clause.

The measurement is corpus-level and statistical, because a single equal-length
pair is a coincidence and a systematic relationship is a channel:

  length - Pearson r between original and surrogate character length, with the
           standard t test. Flagged when the sample is large enough, the
           correlation is at least moderate, and t clears the threshold.
  casing - the fraction of pairs whose casing signature is identical, MINUS the
           fraction obtained when the same surrogates are paired with the wrong
           originals. The permutation baseline is not optional. A surrogate
           scheme emitting `[PATIENT_NAME-ab]` for everything matches the casing
           signature of every Turkish proper noun in the corpus while carrying
           no information about any of them, and an absolute agreement threshold
           calls that a leak. What identifies is agreement in EXCESS of what the
           scheme would score against a stranger's name.

Per-document findings are only emitted when the corpus-level test fires. One
equal-length surrogate in an otherwise decorrelated scheme leaks nothing, and
reporting it would make this attack fire on every masker forever.

r is None, not 0.0, when either side has no variance. A constant-length
surrogate scheme genuinely carries no length channel, and collapsing "no signal
possible" into "measured and found none" would let a degenerate corpus read as
a passing measurement.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from eval.redteam.model import AttackFinding, AttackResult, DeidDocument
from eval.redteam.textutil import casing_signature, pearson, pearson_t
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "structural_leakage"

# Below this many pairs no correlation is credible and the t test is meaningless.
_MIN_PAIRS: Final[int] = 8

# |r| >= 0.5 is a moderate association; below it the length channel carries too
# little to shortlist with. Paired with the t test so a strong r on four points
# does not fire.
_MIN_ABS_R: Final[float] = 0.5

# ~p < 0.05 two-tailed for the sample sizes a fixture corpus produces. An
# approximation on purpose: eval/ carries no scipy dependency, and the decision
# this number drives is "investigate", not "publish".
_MIN_ABS_T: Final[float] = 2.0

# Agreement must exceed the mismatched-pairing baseline by this much before it
# is evidence of preservation rather than of a corpus where everything happens
# to be title-cased.
_MIN_CASING_EXCESS: Final[float] = 0.25

# Cyclic shifts sampled to estimate the baseline. Every shift would be O(n^2)
# over a span map with thousands of entries; a fixed sample is enough to
# separate "matches everything" from "matches its own original".
_BASELINE_SHIFTS: Final[int] = 32


def _mismatched_agreement(
    originals: Sequence[tuple[bool, bool, bool, bool]],
    surrogates: Sequence[tuple[bool, bool, bool, bool]],
) -> float | None:
    """Casing agreement when each surrogate is paired with the WRONG original.

    Estimated over cyclic shifts. This is the agreement a scheme achieves purely
    by emitting a shape that happens to look like Turkish proper nouns, and it
    is the number the observed agreement has to beat.
    """
    count = len(originals)
    if count < 2:
        return None
    shifts = [
        1 + (index * max(1, (count - 1) // _BASELINE_SHIFTS))
        for index in range(min(_BASELINE_SHIFTS, count - 1))
    ]
    total = 0
    compared = 0
    for shift in shifts:
        if shift >= count:
            break
        for index in range(count):
            compared += 1
            if originals[index] == surrogates[(index + shift) % count]:
                total += 1
    if compared == 0:
        return None
    return total / compared


class StructuralLeakageAttack:
    """Correlates surrogate shape against original shape over the span map."""

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        del schema
        original_lengths: list[float] = []
        surrogate_lengths: list[float] = []
        original_casing: list[tuple[bool, bool, bool, bool]] = []
        surrogate_casing: list[tuple[bool, bool, bool, bool]] = []
        casing_matches = 0
        pairs = 0
        exact_length_pairs: list[tuple[str, int, int, str]] = []
        casing_pairs: list[tuple[str, int, int, str]] = []

        for document in corpus:
            for span in document.span_map:
                pairs += 1
                original_lengths.append(float(len(span.original)))
                surrogate_lengths.append(float(len(span.surrogate)))
                if len(span.original) == len(span.surrogate):
                    exact_length_pairs.append(
                        (document.doc_id, span.start, span.end, span.label)
                    )
                left = casing_signature(span.original)
                right = casing_signature(span.surrogate)
                original_casing.append(left)
                surrogate_casing.append(right)
                if left == right:
                    casing_matches += 1
                    casing_pairs.append(
                        (document.doc_id, span.start, span.end, span.label)
                    )

        correlation = pearson(original_lengths, surrogate_lengths)
        t_statistic = pearson_t(correlation, pairs) if correlation is not None else None
        casing_agreement = (casing_matches / pairs) if pairs else None
        casing_baseline = _mismatched_agreement(original_casing, surrogate_casing)
        casing_excess = (
            casing_agreement - casing_baseline
            if casing_agreement is not None and casing_baseline is not None
            else None
        )

        length_leaks = (
            pairs >= _MIN_PAIRS
            and correlation is not None
            and abs(correlation) >= _MIN_ABS_R
            and t_statistic is not None
            and abs(t_statistic) >= _MIN_ABS_T
        )
        casing_leaks = (
            pairs >= _MIN_PAIRS
            and casing_excess is not None
            and casing_excess >= _MIN_CASING_EXCESS
        )

        findings: list[AttackFinding] = []
        if length_leaks:
            for doc_id, start, end, label in exact_length_pairs:
                findings.append(
                    AttackFinding(
                        doc_id=doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            f"surrogate for a {label} span reproduces the "
                            "original's length exactly, and over the corpus "
                            f"surrogate length correlates with original length "
                            f"(r={correlation:.3f}, t={t_statistic:.2f}, "
                            f"n={pairs}). The released text discloses how long "
                            "the masked value was"
                        ),
                        start=start,
                        end=end,
                        label=label,
                        severity=0.6,
                    )
                )
        if casing_leaks:
            for doc_id, start, end, label in casing_pairs:
                findings.append(
                    AttackFinding(
                        doc_id=doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            f"surrogate for a {label} span reproduces the "
                            "original's casing signature, and corpus-wide "
                            f"casing agreement exceeds the mismatched-pairing "
                            f"baseline by {casing_excess:.2f} over {pairs} "
                            "pairs. Casing is the strongest name signal in "
                            "Turkish (I6) and it was preserved"
                        ),
                        start=start,
                        end=end,
                        label=label,
                        severity=0.5,
                    )
                )

        stats: dict[str, Any] = {
            "span_map_pairs": pairs,
            "length_correlation_r": correlation,
            "length_correlation_t": t_statistic,
            "length_leaks": length_leaks,
            "exact_length_pairs": len(exact_length_pairs),
            "casing_agreement": casing_agreement,
            "casing_agreement_mismatched_baseline": casing_baseline,
            "casing_agreement_excess": casing_excess,
            "casing_leaks": casing_leaks,
            "thresholds": {
                "min_pairs": _MIN_PAIRS,
                "min_abs_r": _MIN_ABS_R,
                "min_abs_t": _MIN_ABS_T,
                "min_casing_excess": _MIN_CASING_EXCESS,
            },
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "L5 must break length and casing tells. r is null when a series "
                "has no variance, which means no channel exists rather than that "
                "a channel was measured at zero."
            ),
            # No span map at all: nothing was masked, so nothing can leak
            # structurally. That is a total failure of a different attack, not a
            # pass of this one.
            inapplicable=pairs < _MIN_PAIRS,
        )
