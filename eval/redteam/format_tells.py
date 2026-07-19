"""Attack 6 - format tells.

L5 preserves format on purpose: a TCKN becomes a checksum-valid fake TCKN so
that a downstream parser still works. Format preservation is a utility feature
and it is not the leak. The leak is what leaks THROUGH the preserved format.

Four tells, each a real implementation shortcut:

  identity        - the surrogate equals the original. Either nothing was
                    substituted or the substitution was a no-op. The strongest
                    possible tell.
  digit retention - the surrogate keeps the original's leading or trailing
                    digits, usually so a clinician can still eyeball two
                    records apart. Three retained digits of a TCKN cut the
                    candidate space by three orders of magnitude, and combined
                    with a birth year they finish the job.
  weekday         - a date shifted by a whole number of weeks reads naturally
                    and preserves the weekday. Clinic days are weekly, so the
                    weekday plus a department is an appointment schedule. The
                    day-of-month and year are checked the same way.
  bank code       - a TR IBAN is 26 characters and characters 5-9 are the bank
                    code. A surrogate that keeps them names the patient's bank,
                    which in Turkey often names the town and sometimes the
                    employer.

On the checksum. The brief asks whether a masked TCKN still passes the checksum,
and there are two readings. A SURROGATE passing the checksum is intended by L5,
so it is reported as a statistic and is not a finding. A checksum-valid TCKN
still present in the released text and NOT covered by the span map is a real
identifier that was never masked, and that is a finding - the strongest one this
attack can raise. It cannot fire against the committed corpus, because I8
forbids a checksum-valid TCKN in any fixture; the check exists for runs against
real text and is exercised by a TCKN constructed at test time.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final

from eval.redteam.maskers import parse_turkish_date
from eval.redteam.model import AttackFinding, AttackResult, DeidDocument, MappedSpan
from eval.redteam.textutil import byte_offsets
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "format_tells"

# Retaining this many digits at either end of an identifier is a shortlist, not
# a coincidence.
_MIN_SHARED_DIGITS: Final[int] = 3

_ELEVEN_DIGITS: Final[re.Pattern[str]] = re.compile(r"(?<!\d)\d{11}(?!\d)")

_DATE_LABELS: Final[frozenset[str]] = frozenset(
    {"DATE_BIRTH", "DATE_ADMISSION", "DATE_DISCHARGE", "DATE_DEATH"}
)

_TR_IBAN_BANK_CODE: Final[slice] = slice(4, 9)


def tckn_checksum_valid(value: str) -> bool:
    """The TCKN check per the brief: 11 digits, d1 != 0, two check digits."""
    if len(value) != 11 or not value.isdigit():
        return False
    digits = [int(char) for char in value]
    if digits[0] == 0:
        return False
    odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even = digits[1] + digits[3] + digits[5] + digits[7]
    if (odd * 7 - even) % 10 != digits[9]:
        return False
    return sum(digits[:10]) % 10 == digits[10]


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _shared_prefix(left: str, right: str) -> int:
    count = 0
    for a, b in zip(left, right):
        if a != b:
            break
        count += 1
    return count


def _compact(value: str) -> str:
    return "".join(value.split()).upper()


def _tells_for(span: MappedSpan) -> list[tuple[str, str, float]]:
    """Return (tell, detail, severity) for one span-map entry."""
    tells: list[tuple[str, str, float]] = []

    if span.surrogate == span.original:
        tells.append(
            (
                "identity",
                f"the surrogate for this {span.label} is byte-identical to the "
                "value it replaced, so nothing was masked at all",
                1.0,
            )
        )
        return tells

    original_digits = _digits(span.original)
    surrogate_digits = _digits(span.surrogate)
    if len(original_digits) >= _MIN_SHARED_DIGITS:
        prefix = _shared_prefix(original_digits, surrogate_digits)
        suffix = _shared_prefix(original_digits[::-1], surrogate_digits[::-1])
        if prefix >= _MIN_SHARED_DIGITS or suffix >= _MIN_SHARED_DIGITS:
            tells.append(
                (
                    "digit_retention",
                    f"the surrogate for this {span.label} retains {prefix} "
                    f"leading and {suffix} trailing digits of the original, "
                    "which shortlists the true value",
                    0.9,
                )
            )

    if span.label in _DATE_LABELS:
        original_date = parse_turkish_date(span.original)
        surrogate_date = parse_turkish_date(span.surrogate)
        if original_date is not None and surrogate_date is not None:
            if original_date.weekday() == surrogate_date.weekday():
                tells.append(
                    (
                        "weekday_preserved",
                        f"the surrogate for this {span.label} falls on the same "
                        "weekday as the original, so the shift is a whole "
                        "number of weeks and the clinic day survived",
                        0.7,
                    )
                )
            if original_date.year == surrogate_date.year:
                tells.append(
                    (
                        "year_preserved",
                        f"the surrogate for this {span.label} keeps the "
                        "original's year",
                        0.6,
                    )
                )
            if original_date.day == surrogate_date.day:
                tells.append(
                    (
                        "day_of_month_preserved",
                        f"the surrogate for this {span.label} keeps the "
                        "original's day of month",
                        0.6,
                    )
                )

    original_iban = _compact(span.original)
    surrogate_iban = _compact(span.surrogate)
    if (
        original_iban.startswith("TR")
        and surrogate_iban.startswith("TR")
        and len(original_iban) >= 9
        and len(surrogate_iban) >= 9
        and original_iban[_TR_IBAN_BANK_CODE] == surrogate_iban[_TR_IBAN_BANK_CODE]
    ):
        tells.append(
            (
                "bank_code_preserved",
                "the surrogate IBAN keeps the original's five-digit bank code, "
                "which names the patient's bank and often their town",
                0.8,
            )
        )

    return tells


class FormatTellsAttack:
    """Reads the original through the shape of its surrogate."""

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        del schema
        findings: list[AttackFinding] = []
        counts: dict[str, int] = {}
        pairs = 0
        surrogate_tckns = 0
        surrogate_tckns_checksum_valid = 0
        unmasked_valid_tckns = 0

        for document in corpus:
            for span in document.span_map:
                pairs += 1
                if (
                    len(_digits(span.surrogate)) == 11
                    and _digits(span.surrogate) == span.surrogate.strip()
                ):
                    surrogate_tckns += 1
                    if tckn_checksum_valid(span.surrogate.strip()):
                        surrogate_tckns_checksum_valid += 1
                for tell, detail, severity in _tells_for(span):
                    counts[tell] = counts.get(tell, 0) + 1
                    findings.append(
                        AttackFinding(
                            doc_id=document.doc_id,
                            attack_class=ATTACK_CLASS,
                            detail=detail,
                            start=span.start,
                            end=span.end,
                            label=span.label,
                            severity=severity,
                        )
                    )

            table = byte_offsets(document.text)
            for match in _ELEVEN_DIGITS.finditer(document.text):
                if not tckn_checksum_valid(match.group()):
                    continue
                start, end = table[match.start()], table[match.end()]
                if not document.survived(start, end):
                    continue
                unmasked_valid_tckns += 1
                counts["unmasked_checksum_valid_tckn"] = (
                    counts.get("unmasked_checksum_valid_tckn", 0) + 1
                )
                findings.append(
                    AttackFinding(
                        doc_id=document.doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            "an eleven-digit number that passes the TCKN "
                            "checksum is still present in the released text and "
                            "is not covered by the span map. A checksum-valid "
                            "TCKN cannot be a coincidence; this is a national "
                            "identity number that was never masked"
                        ),
                        start=start,
                        end=end,
                        label="TCKN",
                        severity=1.0,
                    )
                )

        stats: dict[str, Any] = {
            "span_map_pairs": pairs,
            "tells": dict(sorted(counts.items())),
            "surrogate_tckns": surrogate_tckns,
            "surrogate_tckns_checksum_valid": surrogate_tckns_checksum_valid,
            "surrogate_checksum_validity_note": (
                "A checksum-valid TCKN surrogate is L5 working as specified and "
                "is NOT a finding. The finding is a checksum-valid TCKN that was "
                "never masked."
            ),
            "unmasked_checksum_valid_tckns": unmasked_valid_tckns,
            "min_shared_digits": _MIN_SHARED_DIGITS,
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "Format preservation is intended; leaking the original through "
                "the preserved format is not. Retained digits, preserved "
                "weekdays and preserved bank codes are the three shortcuts that "
                "do it."
            ),
            inapplicable=pairs == 0 and unmasked_valid_tckns == 0,
        )
