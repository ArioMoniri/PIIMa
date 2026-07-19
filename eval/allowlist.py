"""Loader for the class C medical-term allowlist (eval/allowlist/*.txt).

WHY this module exists: the term files were dead data. The medical-term
false-positive rate - a hard release gate at <= 0.5% - was computed exclusively
from the per-document `allowlist_terms` annotations, so nineteen hundred lines of
curated vocabulary neither gated anything nor was checked against the schema
that claims to declare it. Two artifacts nobody compares always drift, and they
had: hundreds of terms annotated in fixtures had no counterpart in the files.

Normalisation is Turkish-correct, and that is the load-bearing detail. Python's
`str.lower()` maps `I` to `i` and `İ` to `i` + U+0307, which silently merges four
distinct Turkish letters (`İ i I ı`) into two. Doing that inside a
de-identification pipeline is not cosmetic: it corrupts the surface form the
matcher compares, and casing is the strongest name signal we have (invariant I6
forbids an `*-uncased` backbone for exactly this reason). So `turkish_casefold`
pre-maps the dotted/dotless pairs before folding the rest.

Suffix handling is generated from vowel-harmony templates rather than a hardcoded
list. One Turkish suffix surfaces in several forms (`-de/-da/-te/-ta`,
`-li/-lı/-lu/-lü`); hardcoding one variant misses the others, which is precisely
the failure mode the brief calls out. Only apostrophe-separated suffixes are
stripped - stripping a bare word-final `-ta` would turn the anatomical term
`costa` into `cos`.
"""

from __future__ import annotations

import sys
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from eval.schema import REPO_ROOT, Schema, load_schema

DEFAULT_ALLOWLIST_DIR: Final[Path] = REPO_ROOT / "eval" / "allowlist"

# Every apostrophe a Turkish writer might type between a Latin/English root and
# its suffix. The typographic ones arrive from word processors and PDF exports.
APOSTROPHES: Final[str] = "'’ʼ´‘`"

# Vowel-harmony expansion classes. `A` is the two-way low vowel, `I` the
# four-way high vowel, `D` the voicing alternation of the consonant.
_HARMONY: Final[dict[str, tuple[str, ...]]] = {
    "A": ("a", "e"),
    "I": ("ı", "i", "u", "ü"),
    "D": ("d", "t"),
    "C": ("c", "ç"),
}

# Suffix templates in the archiphoneme notation above. These cover the case,
# possessive, relational and derivational endings that actually attach to a
# code-switched medical root in clinical prose.
_SUFFIX_TEMPLATES: Final[tuple[str, ...]] = (
    "A",
    "yA",
    "I",
    "yI",
    "In",
    "nIn",
    "sI",
    "sInA",
    "sInI",
    "sInDA",
    "sInDAn",
    "DA",
    "DAn",
    "nDA",
    "nDAn",
    # The buffer -n- appears when a case ending follows a possessive:
    # `Cushing sendromu'nu`, `Hashimoto tiroiditi'ne`.
    "nI",
    "nA",
    "lI",
    "lIk",
    "lIğI",
    "lArI",
    "lAr",
    "lArDA",
    "lArDAn",
    "lArIn",
    "lA",
    "ylA",
    "DIr",
    "ydI",
    "yDI",
    "ken",
    "sIz",
    "CI",
    "CIsI",
    "e",
    "a",
    "i",
    "ı",
    "u",
    "ü",
    "n",
    "m",
    "t",
)


class AllowlistError(Exception):
    """Raised when the allowlist files and the schema disagree.

    Every condition this reports is fatal on purpose. A missing or misnamed
    source file used to be invisible; making it a warning would restore exactly
    the silence that let the vocabulary rot.
    """


def _expand(template: str) -> Iterator[str]:
    for index, char in enumerate(template):
        if char in _HARMONY:
            head, tail = template[:index], template[index + 1 :]
            for variant in _HARMONY[char]:
                yield from _expand(head + variant + tail)
            return
    yield template


def _build_suffixes() -> frozenset[str]:
    forms: set[str] = set()
    for template in _SUFFIX_TEMPLATES:
        for form in _expand(template):
            forms.add(turkish_casefold(form))
    return frozenset(forms)


def turkish_casefold(text: str) -> str:
    """Casefold `text` without destroying the Turkish dotted/dotless distinction.

    `İ i I ı` are four letters, not two. `str.lower()` and `str.casefold()` both
    treat `I` as the uppercase of `i`, which is an English assumption:
    `"ISIL".lower()` yields `"isil"` where Turkish requires `"ısıl"`, and
    `"İREM".lower()` yields `"i̇rem"` with a stray combining dot. Both
    outputs then fail to match the vocabulary they were supposed to match.
    """
    normalised = unicodedata.normalize("NFC", text)
    mapped = normalised.replace("İ", "i").replace("I", "ı")
    folded = mapped.casefold()
    # casefold() decomposes any İ that survived NFC as i + U+0307; drop the
    # orphan combining mark so the result is a plain lowercase i.
    return folded.replace("̇", "")


_SUFFIXES: Final[frozenset[str]] = _build_suffixes()


def strip_turkish_suffix(token: str) -> str:
    """Remove an apostrophe-separated Turkish suffix from one casefolded token.

    `carcinoma'lı` -> `carcinoma`, `MRI'da` -> `mrı`... only when what follows the
    apostrophe is a recognised vowel-harmony variant. An unrecognised tail is
    left alone: `d'Amico` is a proper noun, not a suffixed root.
    """
    for index, char in enumerate(token):
        if char in APOSTROPHES:
            root, tail = token[:index], token[index + 1 :]
            if root and tail in _SUFFIXES:
                return root
    return token


def fold(term: str) -> str:
    """Casefold and whitespace-normalise a term WITHOUT stripping suffixes.

    This is the surface identity used for duplicate detection: `Adalat'a` and
    `Adalat` are two legitimately distinct lines in two different files, and
    collapsing them would report a duplicate that is not one.
    """
    return " ".join(turkish_casefold(term).split())


def normalise(term: str) -> str:
    """The lookup key: casefolded, whitespace-collapsed, suffix-stripped."""
    return " ".join(strip_turkish_suffix(token) for token in fold(term).split())


def _is_ascii_origin(key: str) -> bool:
    """True when `key` is Latin/English vocabulary rather than a Turkish word.

    The test is: unify the dotted/dotless pair and see whether anything
    non-ASCII survives. `mrı` -> `mri` (ASCII, so `MRI` is English), `dış` ->
    `diş` (still carries `ş`, so it is Turkish and must not be expanded).
    """
    return key.replace("ı", "i").isascii()


def key_variants(term: str) -> tuple[str, ...]:
    """Every dotted/dotless reading of `term`'s lookup key.

    WHY this exists and why it does NOT weaken `turkish_casefold`: the class C
    vocabulary is Latin and English, languages in which `I` and `i` are one
    letter. A Turkish writer typing `Infective endocarditis` produces a capital
    `I` that a Turkish-correct fold reads as `ı` - correctly, because in Turkish
    it is a different letter. Both readings therefore have to be indexed, or a
    correct fold would make the English vocabulary unmatchable.

    WHY the expansion is gated on `_is_ascii_origin`: applied unconditionally it
    merges Turkish words that are not the same word. `dış` ("outer") and `diş`
    ("tooth") differ only in that pair, so an unconditional expansion made every
    occurrence of a common function word count as an ANATOMY term - inflating
    the vocabulary FP denominator with phantom terms, and at L4 runtime handing
    `dış` an allowlist `Keep` that open issue D-010 turns into a suppressed
    real span. Turkish orthography distinguishes the two letters; only
    ASCII-origin vocabulary, which does not, gets both readings.

    The expansion is confined to the allowlist index. The fold itself stays
    lossless, because span offsets and NAME detection depend on it: Turkish
    person names are never class C, so nothing here can merge `Irmak` with
    `İrmak` anywhere that a name decision is made.
    """
    key = normalise(term)
    if not _is_ascii_origin(key):
        return (key,)
    variants = [key]
    # The `ı`->`i` reading only makes sense for an `ı` the fold PRODUCED from an
    # ASCII capital `I`. A written lowercase `ı` is a Turkish letter the author
    # chose, so `sıvı` must not also index `sivi`.
    if "I" in unicodedata.normalize("NFC", term):
        variants.append(key.replace("ı", "i"))
    # The `i`->`ı` reading covers the reverse: an ASCII-origin term written in
    # lower case, met in a document that upper-cased it (`INFECTIVE`).
    variants.append(key.replace("i", "ı"))
    return tuple(dict.fromkeys(variants))


@dataclass(frozen=True)
class AllowlistEntry:
    """One vocabulary line, with the category and file it came from."""

    term: str
    category: str
    source_file: str

    @property
    def folded(self) -> str:
        return fold(self.term)

    @property
    def key(self) -> str:
        return normalise(self.term)

    @property
    def word_count(self) -> int:
        return len(self.key.split())


@dataclass(frozen=True)
class MedicalAllowlist:
    """The loaded class C vocabulary: L4's runtime reference and a DoD gate."""

    entries: tuple[AllowlistEntry, ...]
    by_key: dict[str, tuple[AllowlistEntry, ...]]
    counts_by_category: dict[str, int]
    max_words: int
    source_dir: Path

    def __contains__(self, term: object) -> bool:
        return isinstance(term, str) and bool(self.lookup(term))

    def lookup(self, term: str) -> tuple[AllowlistEntry, ...]:
        """Every entry whose normalised form equals `term`'s."""
        for variant in key_variants(term):
            hit = self.by_key.get(variant)
            if hit:
                return hit
        return ()

    def categories_of(self, term: str) -> tuple[str, ...]:
        seen: list[str] = []
        for entry in self.lookup(term):
            if entry.category not in seen:
                seen.append(entry.category)
        return tuple(seen)

    @property
    def keys(self) -> frozenset[str]:
        """Every indexed key, including dotted/dotless variants."""
        return frozenset(self.by_key)

    @property
    def canonical_keys(self) -> frozenset[str]:
        """One key per distinct term, without the dotted/dotless expansion."""
        return frozenset(entry.key for entry in self.entries)

    @property
    def total_terms(self) -> int:
        return len(self.entries)

    def summary(self) -> dict[str, object]:
        return {
            "source_dir": str(self.source_dir),
            "files": len(self.counts_by_category),
            "terms": self.total_terms,
            "distinct_keys": len(self.by_key),
            "max_words": self.max_words,
            "counts_by_category": dict(sorted(self.counts_by_category.items())),
        }


def read_terms(path: Path) -> list[str]:
    """Read one term file: one term per line, `#` comments, blank lines ignored."""
    if not path.is_file():
        raise AllowlistError(f"allowlist source file not found: {path}")
    terms: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        terms.append(stripped)
    return terms


def _declared_files(schema: Schema) -> dict[str, Path]:
    declared: dict[str, Path] = {}
    for category in schema.allowlist:
        path = REPO_ROOT / category.source_file
        for other_id, other_path in declared.items():
            if other_path == path:
                raise AllowlistError(
                    f"allowlist categories {other_id!r} and {category.id!r} both "
                    f"declare source_file {category.source_file!r}; one file "
                    "cannot be two categories"
                )
        declared[category.id] = path
    return declared


def load_allowlist(
    schema: Schema | None = None, allowlist_dir: Path | None = None
) -> MedicalAllowlist:
    """Load every file named by schema.yaml's class C entries.

    Fatal conditions, all of them:
      * a declared `source_file` that does not exist;
      * a `.txt` file in the allowlist directory that no category declares;
      * the same surface form appearing in two different files.
    """
    active = schema if schema is not None else load_schema()
    if not active.allowlist:
        raise AllowlistError(
            "schema declares no allowlist_categories; class C is the negative "
            "set behind the medical-term FP gate and cannot be empty"
        )

    directory = allowlist_dir if allowlist_dir is not None else DEFAULT_ALLOWLIST_DIR
    declared = _declared_files(active)

    missing = sorted(
        f"{cid} -> {path}" for cid, path in declared.items() if not path.is_file()
    )
    if missing:
        raise AllowlistError(
            "allowlist source file(s) declared in eval/schema.yaml do not exist: "
            + "; ".join(missing)
        )

    if directory.is_dir():
        present = {path.resolve() for path in sorted(directory.glob("*.txt"))}
        undeclared = sorted(
            str(path) for path in present - {p.resolve() for p in declared.values()}
        )
        if undeclared:
            raise AllowlistError(
                "allowlist file(s) present on disk but declared by no "
                "allowlist_categories entry in eval/schema.yaml: "
                + "; ".join(undeclared)
            )

    entries: list[AllowlistEntry] = []
    counts: dict[str, int] = {}
    seen_surface: dict[str, tuple[str, str]] = {}
    for category_id, path in declared.items():
        try:
            relative = str(path.relative_to(REPO_ROOT))
        except ValueError:
            # A test fixture may live outside the repo; the message still has to
            # name the file it is complaining about.
            relative = str(path)
        terms = read_terms(path)
        counts[category_id] = len(terms)
        for term in terms:
            surface = fold(term)
            previous = seen_surface.get(surface)
            if previous is not None:
                raise AllowlistError(
                    f"duplicate allowlist term {term!r}: already declared as "
                    f"{previous[0]!r} in {previous[1]} (category "
                    f"{category_id}, file {relative})"
                )
            seen_surface[surface] = (term, relative)
            entries.append(
                AllowlistEntry(term=term, category=category_id, source_file=relative)
            )

    by_key: dict[str, list[AllowlistEntry]] = {}
    for entry in entries:
        for variant in key_variants(entry.term):
            bucket = by_key.setdefault(variant, [])
            if entry not in bucket:
                bucket.append(entry)

    return MedicalAllowlist(
        entries=tuple(entries),
        by_key={key: tuple(value) for key, value in by_key.items()},
        counts_by_category=counts,
        max_words=max((entry.word_count for entry in entries), default=1),
        source_dir=directory,
    )


# ---------------------------------------------------------------------------
# Corpus occurrence scanning
# ---------------------------------------------------------------------------

_WORD_CHARS_EXTRA: Final[str] = APOSTROPHES + "-+/"


def _tokenise(text: str) -> list[tuple[int, int, str]]:
    """Split `text` into word tokens as (byte_start, byte_end, surface).

    Hyphens and slashes stay inside a token because `PET-CT`, `BI-RADS` and
    `Cheyne-Stokes` are single medical terms; splitting them would make the
    vocabulary unmatchable.
    """
    tokens: list[tuple[int, int, str]] = []
    byte_offset = 0
    start_byte = -1
    buffer: list[str] = []
    for char in text:
        width = len(char.encode("utf-8"))
        if char.isalnum() or char in _WORD_CHARS_EXTRA:
            if start_byte < 0:
                start_byte = byte_offset
            buffer.append(char)
        elif buffer:
            tokens.append((start_byte, byte_offset, "".join(buffer)))
            buffer = []
            start_byte = -1
        byte_offset += width
    if buffer:
        tokens.append((start_byte, byte_offset, "".join(buffer)))
    return tokens


@dataclass(frozen=True)
class TermOccurrence:
    """One vocabulary term found in document text, in UTF-8 byte offsets."""

    doc_id: str
    key: str
    surface: str
    start: int
    end: int


def find_occurrences(
    doc_id: str, text: str, allowlist: MedicalAllowlist
) -> list[TermOccurrence]:
    """Find every allowlist term occurring in `text`, longest match wins.

    Matches do not overlap: `diabetes mellitus` is one occurrence, not three
    (`diabetes`, `mellitus` and the pair), because the harm the FP rate measures
    is one destroyed term, counted once.
    """
    tokens = _tokenise(text)
    found: list[TermOccurrence] = []
    index = 0
    while index < len(tokens):
        matched = False
        upper = min(allowlist.max_words, len(tokens) - index)
        for width in range(upper, 0, -1):
            window = tokens[index : index + width]
            key = " ".join(
                strip_turkish_suffix(turkish_casefold(token[2])) for token in window
            )
            if key in allowlist.by_key:
                found.append(
                    TermOccurrence(
                        doc_id=doc_id,
                        key=key,
                        surface=text.encode("utf-8")[
                            window[0][0] : window[-1][1]
                        ].decode("utf-8"),
                        start=window[0][0],
                        end=window[-1][1],
                    )
                )
                index += width
                matched = True
                break
        if not matched:
            index += 1
    return found


# ---------------------------------------------------------------------------
# Drift between the fixtures and the vocabulary
# ---------------------------------------------------------------------------


# Fixture annotations that are deliberately NOT vocabulary entries, each with
# the reason. WHY an explicit map rather than silence: `just allowlist-drift`
# reported eight missing terms and exited 0, so seven genuinely medical terms
# sat unreconciled indefinitely. Strict mode now fails on anything not listed
# here, which makes every remaining gap a decision somebody wrote down.
#
# Both survivors are PHRASES - an allowlist term plus a modifier that is not
# itself vocabulary - not missing terms. `validate_drift_exceptions` proves that
# by requiring each one's head token to be in the vocabulary already, so this
# map cannot be used to bury a term that really is absent.
DRIFT_EXCEPTIONS: Final[dict[str, str]] = {
    "costa 6": (
        "phrase, not a term: `costa` is in anatomy.txt and the rib number is an "
        "unbounded index. Enumerating costa 1..12 would add nothing L4 can use."
    ),
    "deva marka parasetamol": (
        "phrase, not a term: `deva` and `parasetamol` are both in drug.txt; "
        "`marka` ('brand') is an ordinary Turkish noun and not class C."
    ),
}


def validate_drift_exceptions(allowlist: MedicalAllowlist) -> None:
    """Fail if any documented exception is really a missing vocabulary term.

    The head token of a phrase exception must already be class C. Without this
    check the exception map degenerates into a place to hide drift, which is the
    silence the strict mode was added to end.
    """
    for key, reason in DRIFT_EXCEPTIONS.items():
        if not reason.strip():
            raise AllowlistError(
                f"drift exception {key!r} carries no justification; an "
                "undocumented exception is indistinguishable from drift"
            )
        head = key.split()[0]
        if not allowlist.lookup(head):
            raise AllowlistError(
                f"drift exception {key!r} is not a phrase over known "
                f"vocabulary: its head token {head!r} is absent from "
                "eval/allowlist/*.txt, so this is a MISSING TERM, not an "
                "exception"
            )


@dataclass(frozen=True)
class DriftReport:
    """What the fixtures annotate versus what the vocabulary files contain.

    The check that would have caught the 313-term drift on day one. Both
    directions are reported: a term annotated in a fixture but absent from the
    files means L4 has no runtime reference for it, and a file term that never
    occurs in the corpus means the gate never exercises it.
    """

    annotated_keys: frozenset[str]
    vocabulary_keys: frozenset[str]
    annotated_only: tuple[str, ...]
    vocabulary_only: tuple[str, ...]
    annotated_examples: dict[str, str]

    @property
    def shared(self) -> tuple[str, ...]:
        return tuple(
            sorted(key for key in self.annotated_keys if key not in self.annotated_only)
        )

    @property
    def unjustified(self) -> tuple[str, ...]:
        """Missing terms that no documented exception accounts for.

        This, not `annotated_only`, is what fails a build: a reviewed and
        recorded gap is a decision, an unreviewed one is rot.
        """
        return tuple(key for key in self.annotated_only if key not in DRIFT_EXCEPTIONS)

    def as_dict(self, examples: int = 20) -> dict[str, object]:
        return {
            "annotated_terms": len(self.annotated_keys),
            "vocabulary_terms": len(self.vocabulary_keys),
            "shared_terms": len(self.shared),
            "annotated_not_in_vocabulary": len(self.annotated_only),
            "annotated_not_in_vocabulary_unjustified": len(self.unjustified),
            "documented_exceptions": {
                key: DRIFT_EXCEPTIONS[key]
                for key in self.annotated_only
                if key in DRIFT_EXCEPTIONS
            },
            "vocabulary_not_in_fixtures": len(self.vocabulary_only),
            "annotated_not_in_vocabulary_examples": [
                self.annotated_examples.get(key, key)
                for key in self.annotated_only[:examples]
            ],
            "vocabulary_not_in_fixtures_examples": list(
                self.vocabulary_only[:examples]
            ),
        }


def build_drift(
    annotated_examples: dict[str, str], allowlist: MedicalAllowlist
) -> DriftReport:
    """Diff a `{normalised key -> example surface}` map against the vocabulary."""
    annotated_only = tuple(
        sorted(
            key
            for key, surface in annotated_examples.items()
            if not allowlist.lookup(surface)
        )
    )
    annotated_variants = {
        variant
        for surface in annotated_examples.values()
        for variant in key_variants(surface)
    }
    vocabulary_only = tuple(
        sorted(
            key
            for key in allowlist.canonical_keys
            if not annotated_variants & set(key_variants(key))
        )
    )
    return DriftReport(
        annotated_keys=frozenset(annotated_examples),
        vocabulary_keys=allowlist.canonical_keys,
        annotated_only=annotated_only,
        vocabulary_only=vocabulary_only,
        annotated_examples=dict(annotated_examples),
    )


def annotated_terms(documents: Sequence[object]) -> dict[str, str]:
    """Collect `{normalised key -> first surface form}` from fixture documents."""
    examples: dict[str, str] = {}
    for document in documents:
        for term in getattr(document, "allowlist_terms", ()):
            surface = getattr(term, "term", None)
            if not isinstance(surface, str):
                continue
            examples.setdefault(normalise(surface), surface)
    return examples


def annotated_terms_from_files(paths: Sequence[Path]) -> dict[str, str]:
    """Collect annotated terms straight from the .jsonl fixtures.

    WHY it does not go through `build_gold.load_corpus`: the drift check is
    about vocabulary, not byte offsets. An unrelated defect in one fixture's
    span metadata must not be able to silence the check that catches vocabulary
    rot - that coupling is how a gate quietly stops running.
    """
    import json

    examples: dict[str, str] = {}
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            if not isinstance(record, dict):
                continue
            for raw in record.get("allowlist_terms", []):
                surface = raw.get("term") if isinstance(raw, dict) else raw
                if isinstance(surface, str) and surface:
                    examples.setdefault(normalise(surface), surface)
    return examples


def compute_drift(
    documents: Sequence[object], allowlist: MedicalAllowlist
) -> DriftReport:
    """Compare fixture `allowlist_terms` annotations against the vocabulary."""
    return build_drift(annotated_terms(documents), allowlist)


def render_drift(report: DriftReport, examples: int = 20) -> str:
    """Human-readable drift report for `just allowlist-drift`."""
    lines = [
        "allowlist drift report",
        "======================",
        f"  fixture-annotated distinct terms : {len(report.annotated_keys)}",
        f"  vocabulary distinct terms        : {len(report.vocabulary_keys)}",
        f"  present in both                  : {len(report.shared)}",
        "",
        f"annotated in fixtures, ABSENT from eval/allowlist/*.txt: "
        f"{len(report.annotated_only)}",
    ]
    for key in report.annotated_only[:examples]:
        marker = "documented exception" if key in DRIFT_EXCEPTIONS else "UNJUSTIFIED"
        lines.append(f"    - {report.annotated_examples.get(key, key)}  [{marker}]")
    if len(report.annotated_only) > examples:
        lines.append(f"    ... and {len(report.annotated_only) - examples} more")
    lines.append("")
    lines.append(f"unjustified (fails --strict): {len(report.unjustified)}")
    for key in report.unjustified[:examples]:
        lines.append(f"    - {report.annotated_examples.get(key, key)}")
    for key in report.annotated_only:
        if key in DRIFT_EXCEPTIONS:
            lines.append(f"exception  {key}: {DRIFT_EXCEPTIONS[key]}")
    lines.append("")
    lines.append(
        "in eval/allowlist/*.txt, never annotated in a fixture: "
        f"{len(report.vocabulary_only)}"
    )
    for key in report.vocabulary_only[:examples]:
        lines.append(f"    - {key}")
    if len(report.vocabulary_only) > examples:
        lines.append(f"    ... and {len(report.vocabulary_only) - examples} more")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """`just allowlist-drift` entry point."""
    import argparse

    from eval.build_gold import DEFAULT_CORPUS_ROOTS, iter_corpus_files

    parser = argparse.ArgumentParser(description="Medical-term allowlist drift report")
    parser.add_argument(
        "--examples",
        type=int,
        default=20,
        help="how many example terms to print per direction",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "exit non-zero when a fixture term is missing from the vocabulary "
            "and no DRIFT_EXCEPTIONS entry justifies it"
        ),
    )
    args = parser.parse_args(argv)

    schema = load_schema()
    allowlist = load_allowlist(schema)
    validate_drift_exceptions(allowlist)
    summary = allowlist.summary()
    print(
        f"loaded {summary['terms']} terms "
        f"({summary['distinct_keys']} distinct keys) "
        f"from {summary['files']} files in {summary['source_dir']}"
    )
    counts = allowlist.counts_by_category
    for category in sorted(counts):
        print(f"    {category:<16} {counts[category]}")
    print()

    fixtures = iter_corpus_files(DEFAULT_CORPUS_ROOTS)
    report = build_drift(annotated_terms_from_files(fixtures), allowlist)
    print(render_drift(report, args.examples))
    if args.strict and report.unjustified:
        print(
            f"\nallowlist-drift: FAIL - {len(report.unjustified)} fixture term(s) "
            "missing from eval/allowlist/*.txt with no documented exception. "
            "Add the term to the right category file, or record why it is not "
            "class C in eval.allowlist.DRIFT_EXCEPTIONS.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
