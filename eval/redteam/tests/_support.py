"""Builders for tiny synthetic corpora, so each attack can be tested alone.

The real gold corpus exercises the attacks end to end in test_runner.py. These
builders exist for the opposite job: constructing the single condition an attack
is supposed to fire on, with nothing else in the document that could fire it,
so that a passing test means the attack detected THAT and not something nearby.

Every string here is invented. No TCKN written into this file is
checksum-valid (I8); `valid_tckn` builds one at call time for the one test that
needs the checksum path to fire.
"""

from __future__ import annotations

from typing import Any

from eval.build_gold import AllowlistTerm, Document, GoldSpan, resolve_quote
from eval.redteam.model import DeidDocument, MappedSpan
from eval.schema import Schema


def valid_tckn(prefix: str = "123456789") -> str:
    """Build a checksum-valid TCKN at runtime from a nine-digit prefix.

    Never committed as a literal: a checksum-valid TCKN in a source file is
    exactly what the pre-commit hook blocks (I8), and the red team's own
    checksum path is the one place a test genuinely needs one.
    """
    digits = [int(char) for char in prefix]
    odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even = digits[1] + digits[3] + digits[5] + digits[7]
    tenth = (odd * 7 - even) % 10
    digits.append(tenth)
    digits.append(sum(digits) % 10)
    return "".join(str(digit) for digit in digits)


def gold_document(
    doc_id: str,
    text: str,
    spans: list[tuple[str, str]] | None = None,
    quasi: list[tuple[str, str]] | None = None,
    allowlist: list[str] | None = None,
    split: str = "dev",
) -> Document:
    """A Document with every span resolved from its quote, as build_gold does."""
    resolved: list[GoldSpan] = []
    for quote, label in (spans or []) + (quasi or []):
        start, end = resolve_quote(text, quote, 1, f"{doc_id} {label}")
        resolved.append(
            GoldSpan(
                doc_id=doc_id,
                label=label,
                quote=quote,
                occurrence=1,
                start=start,
                end=end,
                reason=None,
            )
        )
    terms: list[AllowlistTerm] = []
    for quote in allowlist or []:
        start, end = resolve_quote(text, quote, 1, f"{doc_id} allowlist")
        terms.append(
            AllowlistTerm(
                doc_id=doc_id,
                term=quote,
                category=None,
                occurrence=1,
                start=start,
                end=end,
            )
        )
    return Document(
        doc_id=doc_id,
        split=split,
        note_type="test_note",
        text=text,
        spans=tuple(resolved),
        allowlist_terms=tuple(terms),
        source_path=f"synthetic:{doc_id}",
    )


def deid(
    document: Document,
    mapped: list[tuple[str, str, str]] | None = None,
    salt: str = "per-doc-salt",
    patient_key: str | None = None,
) -> DeidDocument:
    """Attach a hand-written span map: (quote, label, surrogate) triples."""
    spans: list[MappedSpan] = []
    for quote, label, surrogate in mapped or []:
        start, end = resolve_quote(document.text, quote, 1, f"{document.doc_id} map")
        spans.append(
            MappedSpan(
                start=start,
                end=end,
                label=label,
                surrogate=surrogate,
                original=quote,
                salt=salt,
            )
        )
    deid_text = document.text
    for span in sorted(spans, key=lambda item: -item.start):
        encoded = deid_text.encode("utf-8")
        deid_text = (
            encoded[: span.start].decode("utf-8")
            + span.surrogate
            + encoded[span.end :].decode("utf-8")
        )
    return DeidDocument(
        gold=document,
        deid_text=deid_text,
        span_map=tuple(spans),
        patient_key=patient_key,
    )


def stats_of(result: Any) -> dict[str, Any]:
    """Narrow `AttackResult.stats` for mypy --strict at a call site."""
    stats: dict[str, Any] = result.stats
    return stats


__all__ = ["Schema", "deid", "gold_document", "stats_of", "valid_tckn"]
