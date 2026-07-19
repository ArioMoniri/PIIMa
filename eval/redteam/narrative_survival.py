"""Attack 2 - narrative survival. The attack that validates L3.

Every other attack asks whether the masking was done well. This one asks whether
it was done at all, on the only content L3 exists to catch: employment and role,
relationships, assets and geography, distinctive events, and rare attribute
combinations. These are the quasi-identifiers the brief calls meanings rather
than entities - no NER model tags "works at the Central Bank", because it is not
an entity.

The measurement is against the gold `quasi_spans`, and that is the whole point:
the gold set is where a human wrote down, per document, exactly which phrase
re-identifies and why. A quasi span that the span map did not cover survived,
and a survived quasi span IS a contextual re-identification. This attack
therefore produces most of the contextual re-ID rate, and D-008's <= 5% gate is
in practice a statement about this number.

Label-agnostic coverage is the right test here, matching eval/harness.py's
diagnostic coverage: whether the masker called a phrase EMPLOYER_ROLE or
RARE_ATTRIBUTE_COMBO changes nothing about whether the patient can be found.
What matters is that the bytes were covered.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from eval.redteam.model import AttackFinding, AttackResult, DeidDocument, FixtureAnchor
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "narrative_survival"

# A span map entry that covers only a sliver of a long narrative phrase has not
# neutralised it: "the patient's daughter, [NAME], a nurse in this same
# department" still re-identifies. Coverage below this fraction is treated as
# survival, which is the recall-first reading (I2).
_MIN_COVERED_FRACTION: Final[float] = 0.5


def _covered_bytes(document: DeidDocument, start: int, end: int) -> int:
    """Bytes of [start, end) covered by the span map, without double counting."""
    ranges = sorted(
        (max(start, span.start), min(end, span.end))
        for span in document.span_map
        if min(end, span.end) > max(start, span.start)
    )
    covered = 0
    cursor = start
    for low, high in ranges:
        if high <= cursor:
            continue
        covered += high - max(low, cursor)
        cursor = max(cursor, high)
    return covered


class NarrativeSurvivalAttack:
    """Flags gold quasi-identifier spans that masking left legible."""

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        findings: list[AttackFinding] = []
        total = 0
        survived = 0
        per_label_total: dict[str, int] = {}
        per_label_survived: dict[str, int] = {}

        for document in corpus:
            for span in document.gold_quasi(schema):
                total += 1
                per_label_total[span.label] = per_label_total.get(span.label, 0) + 1
                length = span.end - span.start
                covered = _covered_bytes(document, span.start, span.end)
                fraction = covered / length if length else 0.0
                if fraction >= _MIN_COVERED_FRACTION:
                    continue
                survived += 1
                per_label_survived[span.label] = (
                    per_label_survived.get(span.label, 0) + 1
                )
                findings.append(
                    AttackFinding(
                        doc_id=document.doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            f"a gold {span.label} quasi-identifier of {length} "
                            f"bytes survived masking ({covered} bytes covered, "
                            f"{fraction:.2f} of the span). The annotator recorded "
                            "a re-identification rationale for this phrase; it is "
                            "still in the released text"
                        ),
                        start=span.start,
                        end=span.end,
                        label=span.label,
                        severity=1.0,
                        anchor=FixtureAnchor(
                            quote=span.quote,
                            label=span.label,
                            occurrence=span.occurrence,
                        ),
                    )
                )

        stats: dict[str, Any] = {
            "gold_quasi_spans": total,
            "quasi_spans_survived": survived,
            "quasi_span_survival_rate": (survived / total) if total else None,
            "min_covered_fraction_to_count_as_masked": _MIN_COVERED_FRACTION,
            "per_label": {
                label: {
                    "total": count,
                    "survived": per_label_survived.get(label, 0),
                    "survival_rate": per_label_survived.get(label, 0) / count,
                }
                for label, count in sorted(per_label_total.items())
            },
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "This is L3's validation. A surviving quasi span is a contextual "
                "re-identification by the definition the gold set was annotated "
                "under. Survival rate here is not the gate: the gate is over "
                "DOCUMENTS, computed by the runner."
            ),
            # No quasi spans anywhere means this attack had nothing to run, which
            # is a corpus gap, not a defence.
            inapplicable=total == 0,
        )
