"""Byte/character offset plumbing and Turkish-safe casing for the red team.

Two small things that are wrong everywhere they are not written down once.

Python regexes index characters; every offset in this project is a UTF-8 byte
offset. Converting per match with `len(text[:i].encode())` is O(n) per match and
quietly quadratic over a corpus, so a per-document prefix table is built once.

`str.lower()` maps `I` to `i`, which is wrong for Turkish: `I` lowercases to `ı`
and `İ` lowercases to `i`. Folding a Turkish name with the wrong rule turns a
lexicon lookup into a silent miss, and a missed lexicon lookup in a red team
reads as a defence that held.
"""

from __future__ import annotations

import re
from typing import Final

_UPPER_DOTTED: Final[str] = "İ"  # I with dot above
_LOWER_DOTLESS: Final[str] = "ı"  # dotless i


def turkish_lower(text: str) -> str:
    """Lowercase using Turkish casing rules for the four i-letters."""
    return text.replace(_UPPER_DOTTED, "i").replace("I", _LOWER_DOTLESS).lower()


def byte_offsets(text: str) -> list[int]:
    """Prefix table: byte offset of every character index, plus the end.

    `table[i]` is the byte offset of character `i`, and `table[len(text)]` is the
    length of the encoded text, so a character slice `[a, b)` maps to bytes
    `[table[a], table[b])` with no re-encoding.
    """
    table = [0] * (len(text) + 1)
    offset = 0
    for index, char in enumerate(text):
        table[index] = offset
        offset += len(char.encode("utf-8"))
    table[len(text)] = offset
    return table


# Turkish agglutination attaches suffixes with an apostrophe on proper nouns
# (`Ayse'nin`) and without one elsewhere. Only the apostrophe form is stripped
# here: cutting at a bare vowel boundary would mangle names whose stem genuinely
# ends that way, and this function feeds a frequency count where a wrong stem is
# worse than an unstemmed one.
_APOSTROPHE_SUFFIX: Final[re.Pattern[str]] = re.compile(r"[’'](?:[a-zıçğöşü]+)$")

# Turkish clinical titles. A title is not part of the name and counting `Dr.`
# as a name token would make every clinician name look common.
TITLE_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "dr",
        "dr.",
        "op",
        "op.",
        "prof",
        "prof.",
        "doç",
        "doç.",
        "uz",
        "uz.",
        "hemş",
        "hemş.",
        "yrd",
        "yrd.",
        "sn",
        "sn.",
        "bay",
        "bayan",
        "bey",
        "hanım",
        "hasta",
        "adı",
    }
)


def strip_apostrophe_suffix(token: str) -> str:
    """Drop a Turkish case suffix attached with an apostrophe."""
    return _APOSTROPHE_SUFFIX.sub("", token)


def name_tokens(quote: str) -> list[str]:
    """The folded name tokens of a name span, titles and suffixes removed."""
    tokens: list[str] = []
    for raw in quote.split():
        folded = strip_apostrophe_suffix(turkish_lower(raw.strip(",;:()[]")))
        if not folded or folded in TITLE_TOKENS:
            continue
        tokens.append(folded)
    return tokens


def casing_signature(value: str) -> tuple[bool, bool, bool, bool]:
    """A compact, length-independent description of how a string is cased.

    Length is measured separately; mixing the two into one signature would make
    a length correlation masquerade as a casing correlation and vice versa.
    """
    letters = [char for char in value if char.isalpha()]
    return (
        bool(letters) and letters[0].isupper(),
        bool(letters) and all(char.isupper() for char in letters),
        bool(letters) and all(char.islower() for char in letters),
        any(char.isdigit() for char in value),
    )


def pearson(xs: list[float], ys: list[float]) -> float | None:
    """Pearson correlation, or None when either series has zero variance.

    None is not zero. A surrogate scheme that emits a constant length carries no
    length signal at all, and reporting that as `r = 0.0` would put it in the
    same bucket as a scheme measured and found uncorrelated.
    """
    count = len(xs)
    if count != len(ys) or count < 2:
        return None
    mean_x = sum(xs) / count
    mean_y = sum(ys) / count
    dx = [value - mean_x for value in xs]
    dy = [value - mean_y for value in ys]
    var_x = sum(value * value for value in dx)
    var_y = sum(value * value for value in dy)
    if var_x <= 0.0 or var_y <= 0.0:
        return None
    covariance = sum(a * b for a, b in zip(dx, dy))
    return float(covariance / ((var_x**0.5) * (var_y**0.5)))


def pearson_t(correlation: float, count: int) -> float | None:
    """The t statistic for a Pearson r on `count` pairs.

    t = r * sqrt((n - 2) / (1 - r^2)), the standard test. Computed here rather
    than pulled from scipy because eval/ carries no numeric dependency and one
    closed-form expression is not worth acquiring one.
    """
    if count < 3:
        return None
    if abs(correlation) >= 1.0:
        # Perfect correlation: the t statistic diverges. Return a large finite
        # value so callers compare rather than special-case infinity.
        return 1.0e9 if correlation > 0 else -1.0e9
    scale = ((count - 2) / (1.0 - correlation * correlation)) ** 0.5
    return float(correlation * scale)
