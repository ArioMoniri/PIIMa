"""L6 - the re-identification red team.

This package is an EVAL step and never runs in the masking path. It consumes a
de-identified document plus its span map and tries to put the patient back
together. What it produces is the contextual re-ID rate, which per D-008 is the
only gate class B quasi-identifiers have: they are meanings, not enumerable
entities, so no F1 can score them and only a survived attack can.

Two disciplines are enforced throughout and are worth stating once here.

I4 - nothing this package REPORTS may carry document text. The attacks
necessarily read the original text (an attacker with oracle access is the
strongest attacker, and a red team that cannot see the original cannot measure
what leaked), so the in-memory types do hold it. The boundary is the emitted
JSON: `AttackFinding.as_dict` serialises offsets, labels, and prose about the
mechanism, and structurally cannot serialise the anchor quote it also carries.
`tests/test_report_carries_no_text.py` asserts that boundary rather than
trusting it.

Denominators - the same discipline eval/harness.py applies to the document leak
rate. A document holding no gold span at all cannot be re-identified by masking
it, so it dilutes the rate downward without any privacy having been achieved.
Both denominators are computed and both are reported; the gated number is the
one over attackable documents, because it is the higher and therefore the
stricter of the two.
"""

from __future__ import annotations

from eval.redteam.model import (
    Attack,
    AttackFinding,
    AttackResult,
    DeidDocument,
    FixtureAnchor,
    MappedSpan,
)

__all__ = [
    "Attack",
    "AttackFinding",
    "AttackResult",
    "DeidDocument",
    "FixtureAnchor",
    "MappedSpan",
]
