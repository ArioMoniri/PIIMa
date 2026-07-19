"""The types every L6 attack speaks.

Offsets are UTF-8 BYTE offsets into the ORIGINAL document text, matching every
other layer of the project. Attacks locate their evidence in the original and
then ask whether the span map covered it, rather than searching the masked text
for what is missing: the original is where a quote can be anchored for a fixture,
and "was this region masked" is a question the span map answers exactly, whereas
"is this string absent from the output" is answered wrongly the moment a
surrogate happens to contain the same substring.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from eval.build_gold import Document, GoldSpan
from eval.schema import Schema

# Direct identifiers whose surrogate, if reused verbatim across documents, joins
# two records that were meant to be unlinkable. Restricted to identifiers that
# are unique to a person: a masked city name recurring across documents links
# nothing, and counting it would drown the real signal.
LINKABLE_LABELS: frozenset[str] = frozenset(
    {
        "PATIENT_NAME",
        "RELATIVE_NAME",
        "TCKN",
        "VKN",
        "SGK_NO",
        "MRN",
        "PASSPORT_NO",
        "IBAN",
        "PHONE",
        "EMAIL",
        "ACCOUNT_NO",
        "HEALTH_PLAN_ID",
        "DEVICE_ID",
        "LICENSE_PLATE",
        "BIOMETRIC_ID",
        "CERTIFICATE_NO",
        "OTHER_UNIQUE_ID",
    }
)

NAME_LABELS: frozenset[str] = frozenset(
    {"PATIENT_NAME", "CLINICIAN_NAME", "RELATIVE_NAME"}
)

# The doc_id a finding carries when it is a property of the CORPUS rather than of
# any one document - an inverted recall gradient, for instance. Such a finding
# must never be counted as a re-identified document: the re-ID rate is a fraction
# of documents, and a pseudo-document in the numerator would push it above the
# gate for a reason that has no document behind it.
CORPUS_WIDE_DOC_ID: str = "__corpus__"


def stable_key(value: str) -> str:
    """A short, stable, non-reversible key for a text value.

    Used wherever the red team needs to know that two documents concern the same
    person without ever holding or emitting the person's name. Truncated sha256
    rather than the u64 `text_hash` the pipeline uses, because this key exists to
    be printed in a report and a 64-bit non-crypto hash of a short Turkish name
    is enumerable (see the brief's known open issue 3).
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class MappedSpan:
    """One entry of L5's span map: what was masked, and what replaced it.

    `original` is present because the red team is an oracle attacker - measuring
    whether a surrogate leaks the length, casing, digits or weekday of the value
    it replaced is impossible without both sides. It is never serialised.
    """

    start: int
    end: int
    label: str
    surrogate: str
    original: str
    # The salt L5 keyed this surrogate on. A salt shared across documents makes
    # the surrogate mapping global, which is what cross_doc_linkage attacks.
    salt: str


@dataclass(frozen=True)
class DeidDocument:
    """A de-identified document plus everything needed to attack it."""

    gold: Document
    deid_text: str
    span_map: tuple[MappedSpan, ...]
    # Identifies the person across documents without naming them. None when the
    # fixture carries no patient name to key on.
    patient_key: str | None

    @property
    def doc_id(self) -> str:
        return self.gold.doc_id

    @property
    def split(self) -> str:
        return self.gold.split

    @property
    def text(self) -> str:
        """The ORIGINAL text. Attacks anchor to this; reports never carry it."""
        return self.gold.text

    def survived(self, start: int, end: int) -> bool:
        """True when no span-map entry overlaps [start, end) - nothing masked it."""
        return not any(
            min(end, span.end) > max(start, span.start) for span in self.span_map
        )

    def quote(self, start: int, end: int) -> str:
        """The original text covered by a byte range, for fixture anchoring."""
        return self.text.encode("utf-8")[start:end].decode("utf-8")

    def gold_direct(self, schema: Schema) -> tuple[GoldSpan, ...]:
        return self.gold.direct_spans(schema)

    def gold_quasi(self, schema: Schema) -> tuple[GoldSpan, ...]:
        return self.gold.quasi_spans(schema)

    @property
    def is_attackable(self) -> bool:
        """True when this document holds something a masker could have leaked.

        A fixture with no gold span at all cannot be re-identified by a failure
        to mask, so including it in the denominator lowers the rate without any
        privacy having been achieved - the same denominator trap eval/harness.py
        documents for the document leak rate.
        """
        return bool(self.gold.spans)


@dataclass(frozen=True)
class FixtureAnchor:
    """A verbatim quote from the SYNTHETIC corpus, for emitting a fixture.

    Deliberately a separate type from the finding's reportable fields. Fixture
    emission needs the quote (the fixture format is quote-anchored); the report
    must not have it (I4). Keeping the two in one flat dataclass would make the
    correct behaviour a matter of remembering which keys to skip.
    """

    quote: str
    label: str | None
    occurrence: int = 1


@dataclass(frozen=True)
class AttackFinding:
    """One successful re-identification against one document.

    `detail` explains the MECHANISM and must never quote the document. "a
    RELATIONSHIP_REF of 74 bytes survived masking" is a finding; the phrase
    itself is PHI (I4).
    """

    doc_id: str
    attack_class: str
    detail: str
    start: int | None = None
    end: int | None = None
    label: str | None = None
    severity: float = 1.0
    anchor: FixtureAnchor | None = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        """Report projection. Structurally cannot emit `anchor`."""
        return {
            "doc_id": self.doc_id,
            "attack_class": self.attack_class,
            "detail": self.detail,
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class AttackResult:
    """What one attack class concluded over the whole corpus."""

    attack_class: str
    findings: tuple[AttackFinding, ...]
    # Corpus-level measurements: correlation coefficients, cell sizes, recall by
    # frequency bucket. Numbers and labels only, never text.
    stats: dict[str, Any]
    note: str
    # True when the attack could not run at all - no span map to correlate over,
    # no allowlist to draw rare diagnoses from. Distinct from "ran and found
    # nothing", because an attack that never ran is not an attack survived.
    inapplicable: bool = False

    @property
    def succeeded(self) -> bool:
        return bool(self.findings)

    @property
    def documents_hit(self) -> frozenset[str]:
        return frozenset(finding.doc_id for finding in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attack_class": self.attack_class,
            "succeeded": self.succeeded,
            "inapplicable": self.inapplicable,
            "findings": len(self.findings),
            "documents_hit": len(self.documents_hit),
            "note": self.note,
            "stats": self.stats,
            "detail": [finding.as_dict() for finding in self.findings],
        }


class Attack(Protocol):
    """An attack class. Reads a masked corpus, returns what it re-identified."""

    @property
    def attack_class(self) -> str: ...

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult: ...
