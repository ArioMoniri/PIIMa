"""Attack 7 - indirect reference.

"the patient's daughter, a nurse in this same department" contains no name, no
number, no date and no address. It is still PHI, and in a department of forty
people it is a better identifier than most names, because the set of nurses in
one department who have a parent admitted to it has one member.

Nothing in L1 or L2 can see this. There is no entity to tag - the identifying
content is a relation composed with a role or a co-location, and each half is
unremarkable on its own. "kizi" appears in every second note. "hemsire" appears
in every note. The pair, inside one clause, is a person.

Detection is therefore a co-occurrence test inside a window, not a lexicon
lookup: a kinship term within `_WINDOW_CHARS` characters of a role term or of a
co-location marker, where the region was not covered by the span map. The window
is characters rather than bytes because it approximates a clause and Turkish is
multi-byte; the offsets it reports are converted to bytes like everything else.

Matching runs on the ORIGINAL text and then asks the span map whether the region
was masked, rather than searching the masked text. Searching the output would
report a hit whenever a surrogate happened to contain a kinship substring, and
would miss the case where masking replaced the name inside the phrase but left
the phrase itself standing - which is the exact failure this attack is for.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final

from eval.redteam.model import AttackFinding, AttackResult, DeidDocument, FixtureAnchor
from eval.redteam.textutil import byte_offsets, turkish_lower
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "indirect_reference"

# Turkish kinship terms with their possessive and case suffixes. Written as
# stems plus an optional suffix tail rather than as a fixed list of surface
# forms, because vowel harmony makes the same suffix surface four ways and
# hardcoding one variant misses the other three.
_KINSHIP_STEMS: Final[tuple[str, ...]] = (
    "gelin",
    "damat",
    "damad",
    "kız",
    "oğl",
    "oğul",
    "eş",
    "kayınvalide",
    "kayınpeder",
    "torun",
    "kardeş",
    "abla",
    "abi",
    "ağabey",
    "yeğen",
    "hala",
    "teyze",
    "amca",
    "dayı",
    "anne",
    "baba",
    "dede",
    "nine",
    "refakatçi",
    "vasi",
)

# Roles distinctive enough that one of them plus a relation isolates a person.
# Deliberately excludes "hasta" and other terms that describe the patient rather
# than a third party.
_ROLE_STEMS: Final[tuple[str, ...]] = (
    "hemşire",
    "başhemşire",
    "doktor",
    "hekim",
    "cerrah",
    "eczacı",
    "öğretmen",
    "öğretim üyesi",
    "akademisyen",
    "hakim",
    "hâkim",
    "savcı",
    "avukat",
    "müdür",
    "başkan",
    "müfettiş",
    "polis",
    "komiser",
    "asker",
    "subay",
    "imam",
    "muhtar",
    "milletvekili",
    "belediye",
    "mühendis",
    "pilot",
    "gazeteci",
    "noter",
    "kaymakam",
    "vali",
)

# Co-location: "in this same department" is identifying without any role at all,
# because it says the third party works where the note was written.
_COLOCATION_PHRASES: Final[tuple[str, ...]] = (
    "aynı serviste",
    "aynı servisde",
    "aynı hastanede",
    "aynı hastanenin",
    "aynı bölümde",
    "aynı klinikte",
    "aynı poliklinikte",
    "bu serviste",
    "bu bölümde",
    "bu hastanede",
    "burada çalış",
    "kendi servisimizde",
    "servisimizde çalış",
)

# Roughly one clause. Wide enough for a Turkish relative construction, narrow
# enough that two unrelated sentences do not pair up.
_WINDOW_CHARS: Final[int] = 70


def _compile(stems: Sequence[str]) -> re.Pattern[str]:
    # `\w*` absorbs the agglutinated suffix (`gelini`, `kizinin`, `hemsireler`)
    # without enumerating the vowel-harmony variants.
    alternatives = "|".join(re.escape(stem) for stem in stems)
    return re.compile(rf"(?<!\w)(?:{alternatives})\w*", re.UNICODE)


_KINSHIP: Final[re.Pattern[str]] = _compile(_KINSHIP_STEMS)
_ROLE: Final[re.Pattern[str]] = _compile(_ROLE_STEMS)
_COLOCATION: Final[re.Pattern[str]] = re.compile(
    "|".join(re.escape(phrase) for phrase in _COLOCATION_PHRASES), re.UNICODE
)


class IndirectReferenceAttack:
    """Flags surviving relational references that carry no name."""

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        del schema
        findings: list[AttackFinding] = []
        detected = 0
        by_trigger: dict[str, int] = {}

        for document in corpus:
            folded = turkish_lower(document.text)
            table = byte_offsets(document.text)
            kinship = [
                (match.start(), match.end()) for match in _KINSHIP.finditer(folded)
            ]
            if not kinship:
                continue
            partners = [
                (match.start(), match.end(), "role") for match in _ROLE.finditer(folded)
            ] + [
                (match.start(), match.end(), "colocation")
                for match in _COLOCATION.finditer(folded)
            ]
            if not partners:
                continue

            # One finding per document at most. A note that mentions the same
            # relative four times has one indirect reference, not four, and
            # counting them separately would let verbosity inflate the score.
            best: tuple[int, int, str] | None = None
            for k_start, k_end in kinship:
                for p_start, p_end, kind in partners:
                    gap = max(k_start, p_start) - min(k_end, p_end)
                    if gap > _WINDOW_CHARS:
                        continue
                    span = (min(k_start, p_start), max(k_end, p_end), kind)
                    if best is None or (span[1] - span[0]) < (best[1] - best[0]):
                        best = span
            if best is None:
                continue

            detected += 1
            char_start, char_end, kind = best
            start, end = table[char_start], table[char_end]
            by_trigger[kind] = by_trigger.get(kind, 0) + 1
            if not document.survived(start, end):
                continue
            findings.append(
                AttackFinding(
                    doc_id=document.doc_id,
                    attack_class=ATTACK_CLASS,
                    detail=(
                        f"a kinship term co-occurs with a {kind} marker inside "
                        f"{end - start} bytes and the region was not masked. "
                        "The phrase names nobody and still identifies: the set "
                        "of people standing in that relation with that "
                        "attribute is very small"
                    ),
                    start=start,
                    end=end,
                    label="RELATIONSHIP_REF",
                    severity=0.9,
                    anchor=FixtureAnchor(
                        quote=document.quote(start, end),
                        label="RELATIONSHIP_REF",
                    ),
                )
            )

        stats: dict[str, Any] = {
            "documents_with_an_indirect_reference": detected,
            "documents_where_it_survived": len(findings),
            "trigger_kinds": dict(sorted(by_trigger.items())),
            "window_chars": _WINDOW_CHARS,
            "kinship_stems": len(_KINSHIP_STEMS),
            "role_stems": len(_ROLE_STEMS),
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "PHI with no name in it. Neither half of the pattern is "
                "identifying alone, which is why no token classifier tags it and "
                "why L3 has to."
            ),
            inapplicable=detected == 0,
        )
