"""Attack 5 - rare-value survival. The worst failure mode there is.

A detector trained on names learns the names it saw. Common ones - Mehmet,
Ayse, Yilmaz - are masked reliably because they were everywhere in training.
Unusual ones are missed, because an unusual surname looks to a token classifier
like an unseen token, which is to say like anything else.

That gradient is exactly inverted from what privacy requires. A common name
narrows the population barely at all; a surname held by four families in Turkey
identifies on its own. A system with 0.99 recall on common names and 0.70 on
rare ones scores well and leaks precisely the identifiers that matter, and the
aggregate recall number will not show it - which is why this attack exists
separately from the harness's per-entity recall.

Two things are measured and they answer different questions.

  findings - every RARE name span that survived masking. Each one is a
             re-identification on its own merits, regardless of what the corpus
             gradient looks like. This is what fires against a detector that
             masks nothing.
  gradient - recall as a function of name frequency. Reported always; flagged
             when recall FALLS as rarity RISES. This is what fires against a
             detector that looks good on aggregate.

Frequency is document frequency of the folded name token across the corpus,
Turkish-lowered and stripped of apostrophe suffixes so `Yilmaz'in` counts as
`yilmaz`. Corpus frequency is a proxy for population frequency and a weak one on
178 documents; it is used anyway because the alternative is a name-frequency
table the project does not have, and a weak rarity signal that flags too much is
the error direction I2 asks for.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from eval.redteam.model import (
    CORPUS_WIDE_DOC_ID,
    NAME_LABELS,
    AttackFinding,
    AttackResult,
    DeidDocument,
)
from eval.redteam.textutil import name_tokens, turkish_lower
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "rare_value_survival"

# Document-frequency bucket edges. `rare` means the token appears in at most one
# document in the whole corpus, which is the strongest rarity signal available
# without an external name-frequency table.
_RARE_MAX: Final[int] = 1
_UNCOMMON_MAX: Final[int] = 3

# Recall must not fall as rarity rises. A small tolerance keeps sampling noise on
# a fixture-sized corpus from flagging a system that is actually flat.
_INVERSION_TOLERANCE: Final[float] = 0.05

_BUCKETS: Final[tuple[str, ...]] = ("rare", "uncommon", "common")


def _bucket(frequency: int) -> str:
    if frequency <= _RARE_MAX:
        return "rare"
    if frequency <= _UNCOMMON_MAX:
        return "uncommon"
    return "common"


class RareValueSurvivalAttack:
    """Measures recall against name rarity and flags surviving rare names."""

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        del schema
        # Document frequency over the ORIGINAL text: rarity is a property of the
        # population, not of what survived masking.
        folded_texts = {
            document.doc_id: turkish_lower(document.text) for document in corpus
        }
        frequency_cache: dict[str, int] = {}

        def document_frequency(token: str) -> int:
            if token not in frequency_cache:
                frequency_cache[token] = sum(
                    1 for folded in folded_texts.values() if token in folded
                )
            return frequency_cache[token]

        totals = {name: 0 for name in _BUCKETS}
        masked = {name: 0 for name in _BUCKETS}
        findings: list[AttackFinding] = []

        for document in corpus:
            for span in document.gold.spans:
                if span.label not in NAME_LABELS:
                    continue
                tokens = name_tokens(span.quote)
                if not tokens:
                    continue
                # The rarest token in a name decides the bucket: a common given
                # name attached to a rare surname is a rare name.
                rarity = min(document_frequency(token) for token in tokens)
                bucket = _bucket(rarity)
                totals[bucket] += 1
                was_masked = not document.survived(span.start, span.end)
                if was_masked:
                    masked[bucket] += 1
                    continue
                if bucket != "rare":
                    continue
                findings.append(
                    AttackFinding(
                        doc_id=document.doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            f"a {span.label} whose rarest token occurs in "
                            f"{rarity} document(s) of {len(corpus)} survived "
                            "masking. A rare name identifies on its own, so "
                            "this is the class of miss that matters most"
                        ),
                        start=span.start,
                        end=span.end,
                        label=span.label,
                        severity=1.0,
                        # Deliberately no anchor: emitting a fixture quoting the
                        # rare name would put that exact surface form in a
                        # committed file, and a rare name is the most
                        # identifying thing in the document. The pattern is
                        # exportable, the instance is not (I4).
                    )
                )

        recall = {
            bucket: (masked[bucket] / totals[bucket]) if totals[bucket] else None
            for bucket in _BUCKETS
        }
        rare_recall = recall["rare"]
        common_recall = recall["common"]
        inverted = (
            rare_recall is not None
            and common_recall is not None
            and rare_recall < common_recall - _INVERSION_TOLERANCE
        )
        if inverted and rare_recall is not None and common_recall is not None:
            findings.append(
                AttackFinding(
                    doc_id=CORPUS_WIDE_DOC_ID,
                    attack_class=ATTACK_CLASS,
                    detail=(
                        f"recall falls as rarity rises: {rare_recall:.3f} on rare "
                        f"names against {common_recall:.3f} on common ones. The "
                        "gradient is inverted from the one privacy requires, and "
                        "an aggregate recall figure hides it"
                    ),
                    severity=1.0,
                )
            )

        stats: dict[str, Any] = {
            "name_spans": sum(totals.values()),
            "buckets": {
                bucket: {
                    "document_frequency": (
                        f"<= {_RARE_MAX}"
                        if bucket == "rare"
                        else f"<= {_UNCOMMON_MAX}"
                        if bucket == "uncommon"
                        else f"> {_UNCOMMON_MAX}"
                    ),
                    "total": totals[bucket],
                    "masked": masked[bucket],
                    "recall": recall[bucket],
                }
                for bucket in _BUCKETS
            },
            "recall_gradient_inverted": inverted,
            "inversion_tolerance": _INVERSION_TOLERANCE,
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "Recall must not fall as rarity rises. Findings are surviving "
                "rare names; the gradient is reported separately because a "
                "system can fail either one without failing the other."
            ),
            inapplicable=sum(totals.values()) == 0,
        )
