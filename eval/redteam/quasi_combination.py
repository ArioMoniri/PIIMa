"""Attack 1 - quasi-identifier combination.

No single surviving attribute identifies anybody. A residual year, plus a rare
diagnosis, plus a named facility, together describe a cell of the population,
and when that cell holds one person the document is re-identified even though
every enumerated HIPAA identifier was removed.

This is k-anonymity applied to what SURVIVED masking rather than to a released
table. The cell key is built from three components:

  year      - a four-digit year still legible in the output. Dates are the
              classic quasi-identifier and a surrogate that preserves the year
              hands one back.
  rare_dx   - a diagnosis or procedure term from the medical allowlist that
              occurs in few documents. The allowlist term itself must never be
              masked (masking `carcinoma` destroys the note), so this component
              is a permanent, unavoidable quasi-identifier and the reason the
              other two must go.
  facility  - a FACILITY_NAME that was not masked. In a small population, the
              hospital is most of the answer.

A cell is only scored when at least TWO components survive. One attribute is not
a combination, and counting it as one would collapse this attack into "a rare
diagnosis exists", which is true of every oncology corpus ever assembled.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final

from eval.allowlist import MedicalAllowlist, find_occurrences, load_allowlist
from eval.redteam.model import AttackFinding, AttackResult, DeidDocument, FixtureAnchor
from eval.redteam.textutil import byte_offsets, turkish_lower
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "quasi_identifier_combination"

_YEAR: Final[re.Pattern[str]] = re.compile(r"\b(?:19|20)\d{2}\b")

# Allowlist categories whose terms carry clinical rarity. An anatomy term or a
# lab analyte narrows nothing - every note mentions a kidney.
_RARITY_CATEGORIES: Final[frozenset[str]] = frozenset({"DIAGNOSIS", "PROCEDURE"})

# A term occurring in at most this many documents is rare enough that, combined
# with one more attribute, it isolates. Deliberately generous: recall beats
# precision (I2), and a red team that under-reports rarity under-reports risk.
_RARE_DOCUMENT_FREQUENCY: Final[int] = 3

_MIN_COMPONENTS: Final[int] = 2


def _surviving_years(document: DeidDocument) -> list[tuple[int, int, str]]:
    table = byte_offsets(document.text)
    found: list[tuple[int, int, str]] = []
    for match in _YEAR.finditer(document.text):
        start, end = table[match.start()], table[match.end()]
        if document.survived(start, end):
            found.append((start, end, match.group()))
    return found


def _surviving_facilities(document: DeidDocument) -> list[tuple[int, int, str]]:
    return [
        (span.start, span.end, turkish_lower(span.quote))
        for span in document.gold.spans
        if span.label == "FACILITY_NAME" and document.survived(span.start, span.end)
    ]


def _diagnosis_occurrences(
    document: DeidDocument, allowlist: MedicalAllowlist
) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for occurrence in find_occurrences(document.doc_id, document.text, allowlist):
        categories = allowlist.categories_of(occurrence.key)
        if not any(category in _RARITY_CATEGORIES for category in categories):
            continue
        found.append((occurrence.start, occurrence.end, occurrence.key))
    return found


class QuasiCombinationAttack:
    """Flags documents whose surviving quasi-identifier cell holds one person."""

    def __init__(self, allowlist: MedicalAllowlist | None = None) -> None:
        self._allowlist = allowlist

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        allowlist = (
            self._allowlist if self._allowlist is not None else load_allowlist(schema)
        )

        # Document frequency is computed over every occurrence, masked or not:
        # rarity is a property of the clinical vocabulary in this population, not
        # of what the masker happened to leave behind.
        per_document_terms: dict[str, list[tuple[int, int, str]]] = {}
        document_frequency: dict[str, int] = {}
        for document in corpus:
            occurrences = _diagnosis_occurrences(document, allowlist)
            per_document_terms[document.doc_id] = occurrences
            for term_key in {term for _, _, term in occurrences}:
                document_frequency[term_key] = document_frequency.get(term_key, 0) + 1

        cells: dict[tuple[str | None, str | None, str | None], list[str]] = {}
        components: dict[str, dict[str, Any]] = {}

        for document in corpus:
            years = _surviving_years(document)
            facilities = _surviving_facilities(document)
            rare = [
                (start, end, key)
                for start, end, key in per_document_terms[document.doc_id]
                if document_frequency.get(key, 0) <= _RARE_DOCUMENT_FREQUENCY
                and document.survived(start, end)
            ]

            year_value = years[0][2] if years else None
            dx_value = min(key for _, _, key in rare) if rare else None
            facility_value = (
                min(name for _, _, name in facilities) if facilities else None
            )

            present = sum(
                1
                for value in (year_value, dx_value, facility_value)
                if value is not None
            )
            components[document.doc_id] = {
                "year": year_value is not None,
                "rare_diagnosis": dx_value is not None,
                "facility": facility_value is not None,
                "surviving_components": present,
            }
            if present < _MIN_COMPONENTS:
                continue
            cell = (year_value, dx_value, facility_value)
            cells.setdefault(cell, []).append(document.doc_id)

        by_doc = {document.doc_id: document for document in corpus}
        findings: list[AttackFinding] = []
        singleton_cells = 0
        for cell, doc_ids in sorted(cells.items(), key=lambda item: item[1]):
            if len(doc_ids) != 1:
                continue
            singleton_cells += 1
            doc_id = doc_ids[0]
            document = by_doc[doc_id]
            shape = components[doc_id]
            present_names = [
                name for name in ("year", "rare_diagnosis", "facility") if shape[name]
            ]
            anchor = _anchor_for(document, cell)
            findings.append(
                AttackFinding(
                    doc_id=doc_id,
                    attack_class=ATTACK_CLASS,
                    detail=(
                        "k-anonymity cell of size 1 over the surviving "
                        f"quasi-identifiers {'+'.join(present_names)}: this "
                        "document is the only one in the corpus with this "
                        "combination, so removing the direct identifiers left "
                        "the patient uniquely described"
                    ),
                    severity=1.0,
                    anchor=anchor,
                )
            )

        sized = [len(doc_ids) for doc_ids in cells.values()]
        stats: dict[str, Any] = {
            "documents_with_a_cell": sum(len(doc_ids) for doc_ids in cells.values()),
            "cells": len(cells),
            "cells_of_size_1": singleton_cells,
            "min_cell_size": min(sized) if sized else None,
            "rare_term_document_frequency_max": _RARE_DOCUMENT_FREQUENCY,
            "min_components_for_a_cell": _MIN_COMPONENTS,
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "A cell of size 1 means the surviving attributes describe "
                "exactly one patient in the corpus. The rare diagnosis cannot "
                "be masked, so the fix is always to mask one of the other two."
            ),
            inapplicable=not cells and not corpus,
        )


def _anchor_for(
    document: DeidDocument, key: tuple[str | None, str | None, str | None]
) -> FixtureAnchor | None:
    """Anchor the fixture to the facility, else the year - never the diagnosis.

    The diagnosis is allowlist vocabulary that must never be masked, so a
    fixture anchored to it would assert the opposite of what the project wants.
    """
    _, _, facility = key
    if facility is not None:
        for span in document.gold.spans:
            if span.label == "FACILITY_NAME":
                return FixtureAnchor(
                    quote=span.quote, label=span.label, occurrence=span.occurrence
                )
    return None
