"""Reference maskers the red team is calibrated against.

NONE OF THESE MAY POPULATE THE RELEASE GATE. They are gold-derived, so a rate
measured against one describes the red team and not deid-tr; `eval/pipeline.py`
holds the masker that runs the real `core::Pipeline`, and `eval/harness.py`
refuses a rate whose report names any masker but that one. Calibration lives
here, the product lives there, and the separation is structural because the two
were once read as the same number.

These are EVAL instruments, not the product. They exist because a red team is
only trustworthy if it is known to report total failure as total failure and
perfect masking as passing; a red team validated only against the real pipeline
tells you about the pipeline and nothing about itself.

  NullMasker   - masks nothing. The floor. Every attack that can fire should.
  LeakyMasker  - masks everything, then leaks it back through the surrogates:
                 identical length, identical casing, retained digit prefixes,
                 date shifts that are multiples of seven days, preserved IBAN
                 bank codes and one global salt. This is L5 implemented by
                 someone optimising for readability, and it is the masker L5
                 must not resemble.
  OracleMasker - masks everything with opaque, structure-free, per-document
                 surrogates. The ceiling.

OracleMasker deliberately does NOT preserve format. Format preservation is a
utility feature of L5 (a downstream parser still sees something date-shaped); it
buys no privacy, and an oracle defined as "maximum privacy" is the right upper
bound for a privacy measurement. Anything the red team flags against this masker
is a false positive in the red team.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import date, timedelta
from typing import Final, Protocol, runtime_checkable

from eval.build_gold import Document, GoldSpan
from eval.redteam.model import DeidDocument, MappedSpan, stable_key
from eval.schema import Schema

_UPPER: Final[str] = "BCDFGHJKLMNPRSTVYZ"
_LOWER: Final[str] = "bcdfghjklmnprstvyz"
_DIGITS: Final[str] = "0123456789"

# Digits the LeakyMasker keeps verbatim at the head of a numeric identifier -
# "so the clinician can still tell two records apart at a glance", which is
# exactly how a prefix survives masking.
_LEAKY_DIGIT_PREFIX: Final[int] = 3

# A shift that is a whole number of weeks preserves the weekday of every date it
# touches. Seven is the value a naive implementation picks precisely because it
# keeps the note reading naturally.
_LEAKY_DATE_SHIFT_DAYS: Final[int] = 7


class Masker(Protocol):
    """Turns a gold document into a de-identified one plus its span map."""

    @property
    def name(self) -> str: ...

    def mask(self, document: Document, schema: Schema) -> DeidDocument: ...


def _digest(*parts: str) -> str:
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def patient_key(document: Document) -> str | None:
    """A stable, non-reversible key for the patient a document concerns."""
    for span in document.spans:
        if span.label == "PATIENT_NAME":
            return stable_key(span.quote)
    return None


def _non_overlapping(spans: Sequence[GoldSpan]) -> list[GoldSpan]:
    """Longest-first, dropping any span overlapping one already taken.

    Direct and quasi annotations legitimately overlap (a name inside an
    employment phrase). Substituting both would corrupt the offsets of the
    second, so the wider one wins - which is also the more conservative masking
    decision.
    """
    ordered = sorted(spans, key=lambda span: (-(span.end - span.start), span.start))
    taken: list[GoldSpan] = []
    for span in ordered:
        if any(
            min(span.end, other.end) > max(span.start, other.start) for other in taken
        ):
            continue
        taken.append(span)
    return sorted(taken, key=lambda span: span.start)


def _splice(text: str, replacements: Sequence[tuple[int, int, str]]) -> str:
    """Apply byte-range replacements to `text`, left to right."""
    encoded = text.encode("utf-8")
    pieces: list[str] = []
    cursor = 0
    for start, end, surrogate in sorted(replacements):
        pieces.append(encoded[cursor:start].decode("utf-8"))
        pieces.append(surrogate)
        cursor = end
    pieces.append(encoded[cursor:].decode("utf-8"))
    return "".join(pieces)


class NullMasker:
    """Masks nothing. The shape of total failure."""

    @property
    def name(self) -> str:
        return "null"

    def mask(self, document: Document, schema: Schema) -> DeidDocument:
        del schema
        return DeidDocument(
            gold=document,
            deid_text=document.text,
            span_map=(),
            patient_key=patient_key(document),
        )


class LeakyMasker:
    """Masks every gold span, then leaks it back through the surrogate."""

    def __init__(self, salt: str = "global-fixed-salt") -> None:
        # One salt for the whole corpus: the surrogate for a given value is then
        # the same in every document, which relinks the records.
        self._salt = salt

    @property
    def name(self) -> str:
        return "leaky"

    def _char_map(self, char: str, seed: str) -> str:
        if char.isdigit():
            index = int(_digest(seed, char, "d")[:8], 16) % len(_DIGITS)
            return _DIGITS[index]
        if char.isalpha():
            pool = _UPPER if char.isupper() else _LOWER
            index = int(_digest(seed, char, "a")[:8], 16) % len(pool)
            return pool[index]
        return char

    def _surrogate(self, span: GoldSpan) -> str:
        original = span.quote
        seed = _digest(self._salt, original)

        shifted = _shift_turkish_date(original, _LEAKY_DATE_SHIFT_DAYS)
        if shifted is not None:
            return shifted

        compact = original.replace(" ", "")
        if compact.upper().startswith("TR") and len(compact) >= 10:
            # Keep "TR" + check digits + the five-digit bank code, exactly the
            # part that says which bank - and therefore which branch, and
            # therefore which town.
            head = original[: _iban_head_length(original)]
            tail = "".join(self._char_map(char, seed) for char in original[len(head) :])
            return head + tail

        digits = [char for char in original if char.isdigit()]
        if len(digits) >= 6 and all(
            char.isdigit() or char in " -" for char in original
        ):
            kept = 0
            out: list[str] = []
            for char in original:
                if char.isdigit() and kept < _LEAKY_DIGIT_PREFIX:
                    kept += 1
                    out.append(char)
                else:
                    out.append(self._char_map(char, seed))
            return "".join(out)

        return "".join(self._char_map(char, seed) for char in original)

    def mask(self, document: Document, schema: Schema) -> DeidDocument:
        del schema
        spans = _non_overlapping(document.spans)
        mapped = tuple(
            MappedSpan(
                start=span.start,
                end=span.end,
                label=span.label,
                surrogate=self._surrogate(span),
                original=span.quote,
                salt=self._salt,
            )
            for span in spans
        )
        deid = _splice(
            document.text,
            [(span.start, span.end, span.surrogate) for span in mapped],
        )
        return DeidDocument(
            gold=document,
            deid_text=deid,
            span_map=mapped,
            patient_key=patient_key(document),
        )


class OracleMasker:
    """Masks every gold span with an opaque, per-document surrogate."""

    def __init__(self, seed: str = "oracle") -> None:
        self._seed = seed

    @property
    def name(self) -> str:
        return "oracle"

    def _salt(self, document: Document) -> str:
        # Per-document salt: the same name in two notes gets two surrogates, so
        # the span map cannot be used to join the notes.
        return _digest(self._seed, document.doc_id)[:32]

    def _surrogate(self, span: GoldSpan, salt: str) -> str:
        digest = _digest(salt, span.label, span.quote)
        # Suffix length varies with the digest, not with the original, so the
        # surrogate length carries no information about what it replaced.
        width = 3 + int(digest[:2], 16) % 4
        return f"[{span.label}-{digest[2 : 2 + width]}]"

    def mask(self, document: Document, schema: Schema) -> DeidDocument:
        del schema
        salt = self._salt(document)
        spans = _non_overlapping(document.spans)
        mapped = tuple(
            MappedSpan(
                start=span.start,
                end=span.end,
                label=span.label,
                surrogate=self._surrogate(span, salt),
                original=span.quote,
                salt=salt,
            )
            for span in spans
        )
        deid = _splice(
            document.text,
            [(span.start, span.end, span.surrogate) for span in mapped],
        )
        return DeidDocument(
            gold=document,
            deid_text=deid,
            span_map=mapped,
            patient_key=patient_key(document),
        )


def _iban_head_length(value: str) -> int:
    """Characters covering `TR` + two check digits + the five-digit bank code."""
    seen = 0
    for index, char in enumerate(value):
        if char != " ":
            seen += 1
        if seen == 9:
            return index + 1
    return len(value)


def parse_turkish_date(value: str) -> date | None:
    """Parse `dd.mm.yyyy` / `dd/mm/yyyy` / `dd-mm-yyyy`, else None."""
    text = value.strip()
    for separator in (".", "/", "-"):
        parts = text.split(separator)
        if len(parts) != 3:
            continue
        if not all(part.isdigit() for part in parts):
            continue
        day, month, year = (int(part) for part in parts)
        if len(parts[2]) != 4:
            continue
        try:
            return date(year, month, day)
        except ValueError:
            return None
    return None


def _shift_turkish_date(value: str, days: int) -> str | None:
    parsed = parse_turkish_date(value)
    if parsed is None:
        return None
    separator = next((char for char in value if char in "./-"), ".")
    shifted = parsed + timedelta(days=days)
    return separator.join(
        (f"{shifted.day:02d}", f"{shifted.month:02d}", f"{shifted.year:04d}")
    )


@runtime_checkable
class BatchMasker(Protocol):
    """A masker that would rather see the whole corpus at once.

    Exists for the pipeline masker, which spawns a subprocess: 178 spawns and
    one spawn produce identical output, and only one of them is usable in a
    test suite. Declared as a Protocol so the capability is a property of the
    masker rather than a name `mask_corpus` special-cases.
    """

    def mask_all(
        self, documents: Sequence[Document], schema: Schema
    ) -> list[DeidDocument]: ...


def mask_corpus(
    documents: Sequence[Document], masker: Masker, schema: Schema
) -> list[DeidDocument]:
    """Run `masker` over a whole corpus."""
    if isinstance(masker, BatchMasker):
        return list(masker.mask_all(documents, schema))
    return [masker.mask(document, schema) for document in documents]
