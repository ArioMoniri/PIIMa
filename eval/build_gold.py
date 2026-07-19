"""Resolve quote-anchored gold fixtures into concrete UTF-8 byte offsets.

The fixture format anchors every span to a verbatim quote plus an occurrence
index rather than to integer offsets, for two reasons. Offsets written by hand
drift the moment a fixture is edited, and an LLM asked for offsets hallucinates
them - the whole pipeline re-anchors quotes to the original text instead
(brief, L3). This module performs that resolution once, up front, so the
harness never has to.

Offsets are BYTE offsets into the UTF-8 encoding of the original text, not
character indices. Turkish is multi-byte (`s`-cedilla, `g`-breve, dotted-I are
two bytes each) and every layer of the project speaks byte offsets; mixing the
two is the project's stated number one correctness trap.

Resolution failures are fatal, never skipped. A gold span that is silently
dropped because its quote no longer matches shrinks the recall denominator,
which inflates recall - the exact direction of error that makes a
de-identification benchmark lie about a system that is leaking.

Fixture format, one JSON object per line under eval/gold/ and eval/adversarial/:

    {
      "doc_id": "tr-dev-0001",
      "split": "dev",
      "note_type": "discharge_summary",
      "text": "...",
      "spans": [
        {"quote": "Ayse Yilmaz", "label": "PATIENT_NAME", "occurrence": 1}
      ],
      "quasi_spans": [
        {"quote": "Merkez Bankasi'nda calisiyor", "label": "EMPLOYER_ROLE",
         "occurrence": 1, "reason": "named employer narrows the population"}
      ],
      "allowlist_terms": [
        {"quote": "carcinoma", "occurrence": 1, "category": "DIAGNOSIS"}
      ]
    }

`occurrence` is 1-based and defaults to 1. `allowlist_terms` entries may also be
bare strings, which are read as occurrence 1 with no category.

An ADVERSARIAL fixture carries two attack fields and needs both:

    "attack_class": "cross_document_linkage",
    "attack":       "Indirect reference through a second record: ..."

`attack_class` is a CLOSED ENUM (`ATTACK_CLASSES`) and `attack` is free prose.
The enum exists because the prose did not scale: 38 adversarial fixtures held 38
distinct paragraphs and no two of them shared a value, so nothing downstream
could group by attack class, and the L6 red team could not see which of the
brief's seven attack classes had no fixture at all. Prose explains one fixture
to one human; the enum is what makes red-team coverage countable. An
`attack_class` outside the enum is a hard error rather than a new class, because
a typo that silently invents a class is indistinguishable from coverage.

The two span keys are separate because the two classes are scored by different
mechanisms, and the separation is ENFORCED: a quasi label in `spans` or a direct
label in `quasi_spans` is a hard error. Unrecognised top-level keys are a hard
error too - an ignored key is how an entire scoring class goes unmeasured.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

# Support `python3 eval/build_gold.py` as well as `python3 -m eval.build_gold`:
# a bare script invocation puts eval/ on sys.path instead of the repo root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.schema import REPO_ROOT, Schema, load_schema

GOLD_DIR: Final[Path] = REPO_ROOT / "eval" / "gold"
ADVERSARIAL_DIR: Final[Path] = REPO_ROOT / "eval" / "adversarial"
DEFAULT_CORPUS_ROOTS: Final[tuple[Path, ...]] = (GOLD_DIR, ADVERSARIAL_DIR)
RESOLVED_PATH: Final[Path] = GOLD_DIR / ".build" / "resolved.json"

# The seven L6 attack classes from the brief, in the brief's order. These are
# the classes the re-ID red team runs, and coverage is reported per class so a
# class with zero fixtures is visible as a gap rather than absent from a table.
L6_ATTACK_CLASSES: Final[tuple[str, ...]] = (
    "quasi_identifier_combination",
    "narrative_survival",
    "structural_leakage",
    "cross_document_linkage",
    "rare_value_survival",
    "format_tells",
    "indirect_reference",
)

# The two adversarial kinds that are not L6 re-identification attacks at all.
# They are adversarial in the ordinary sense - they are the cases the detector
# gets wrong - but they attack L1/L2/L4, not the masked output, so folding them
# into an L6 class would inflate red-team coverage with fixtures the red team
# never runs.
NON_L6_ATTACK_CLASSES: Final[tuple[str, ...]] = (
    "direct_identifier_edge_case",
    "medical_term_false_positive",
)

ATTACK_CLASSES: Final[tuple[str, ...]] = L6_ATTACK_CLASSES + NON_L6_ATTACK_CLASSES

# A UTF-8 continuation byte is 0b10xxxxxx; an offset pointing at one is an
# offset that fell inside a character.
_CONTINUATION_MASK: Final[int] = 0b1100_0000
_CONTINUATION_VALUE: Final[int] = 0b1000_0000


class GoldError(Exception):
    """Raised when a gold fixture cannot be resolved to byte offsets."""


@dataclass(frozen=True)
class GoldSpan:
    """A gold span resolved to byte offsets into the original document text."""

    doc_id: str
    label: str
    quote: str
    occurrence: int
    start: int
    end: int
    # Quasi-identifier fixtures carry the annotator's re-identification
    # rationale; direct identifiers need none, because a TCKN identifies on its
    # own and there is nothing to argue about.
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "label": self.label,
            "quote": self.quote,
            "occurrence": self.occurrence,
            "start": self.start,
            "end": self.end,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AllowlistTerm:
    """An occurrence of a medical-term allowlist entry inside a document.

    These form the NEGATIVE set: the denominator of the medical-term
    false-positive rate.
    """

    doc_id: str
    term: str
    category: str | None
    occurrence: int
    start: int
    end: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "term": self.term,
            "category": self.category,
            "occurrence": self.occurrence,
            "start": self.start,
            "end": self.end,
        }


@dataclass(frozen=True)
class Document:
    """A resolved gold document."""

    doc_id: str
    split: str
    note_type: str | None
    text: str
    spans: tuple[GoldSpan, ...]
    allowlist_terms: tuple[AllowlistTerm, ...]
    source_path: str
    tags: tuple[str, ...] = field(default=())
    specialty: str | None = None
    # Free prose describing, for a human, exactly what this fixture attacks.
    # Never grouped on: every fixture's value is unique by construction.
    attack: str | None = None
    # The machine-readable class, drawn from `ATTACK_CLASSES`. Required on every
    # adversarial fixture; None on ordinary gold notes.
    attack_class: str | None = None

    @property
    def is_adversarial(self) -> bool:
        """True for a fixture that exercises a named attack class.

        Derived from `attack_class` rather than from the file path, because the
        path is where the fixture happens to live and the class is what it
        actually is.
        """
        return self.attack_class is not None

    def direct_spans(self, schema: Schema) -> tuple[GoldSpan, ...]:
        return tuple(span for span in self.spans if schema.is_direct(span.label))

    def quasi_spans(self, schema: Schema) -> tuple[GoldSpan, ...]:
        return tuple(span for span in self.spans if schema.is_quasi(span.label))

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "split": self.split,
            "note_type": self.note_type,
            "specialty": self.specialty,
            "attack": self.attack,
            "attack_class": self.attack_class,
            "is_adversarial": self.is_adversarial,
            "text": self.text,
            "tags": list(self.tags),
            "spans": [span.as_dict() for span in self.spans],
            "allowlist_terms": [term.as_dict() for term in self.allowlist_terms],
            "source_path": self.source_path,
        }


def _assert_char_boundary(encoded: bytes, offset: int, where: str) -> None:
    if offset < 0 or offset > len(encoded):
        raise GoldError(f"{where}: byte offset {offset} outside text")
    if offset == len(encoded):
        return
    if encoded[offset] & _CONTINUATION_MASK == _CONTINUATION_VALUE:
        raise GoldError(f"{where}: byte offset {offset} lands inside a UTF-8 character")


def resolve_quote(
    text: str, quote: str, occurrence: int, where: str
) -> tuple[int, int]:
    """Return the (start, end) BYTE offsets of the Nth occurrence of `quote`.

    Search runs over characters and the result is converted to bytes, which
    makes it structurally impossible to land mid-character; the boundary
    assertion afterwards guards against a future change to that strategy.
    Occurrences are counted from every start position, so overlapping matches
    each count once.
    """
    if occurrence < 1:
        raise GoldError(f"{where}: occurrence must be >= 1, got {occurrence}")
    if not quote:
        raise GoldError(f"{where}: empty quote")

    char_index = -1
    found = 0
    cursor = 0
    while True:
        hit = text.find(quote, cursor)
        if hit == -1:
            break
        found += 1
        if found == occurrence:
            char_index = hit
            break
        cursor = hit + 1

    if char_index == -1:
        if found == 0:
            raise GoldError(
                f"{where}: quote {quote!r} does not occur in the document text"
            )
        raise GoldError(
            f"{where}: requested occurrence {occurrence} of quote {quote!r} "
            f"but only {found} occurrence(s) are present"
        )

    encoded = text.encode("utf-8")
    start = len(text[:char_index].encode("utf-8"))
    end = start + len(quote.encode("utf-8"))
    _assert_char_boundary(encoded, start, where)
    _assert_char_boundary(encoded, end, where)

    if encoded[start:end].decode("utf-8") != quote:
        raise GoldError(
            f"{where}: resolved bytes [{start}, {end}) do not round-trip to "
            f"quote {quote!r}"
        )
    return start, end


def _as_mapping(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GoldError(f"{where}: expected an object, got {type(value).__name__}")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise GoldError(f"{where}: non-string key {key!r}")
        result[key] = item
    return result


def _require_str(record: dict[str, Any], key: str, where: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise GoldError(f"{where}: '{key}' must be a non-empty string, got {value!r}")
    return value


def _occurrence(record: dict[str, Any], where: str) -> int:
    raw = record.get("occurrence", 1)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise GoldError(f"{where}: 'occurrence' must be an integer, got {raw!r}")
    return int(raw)


def _parse_span_list(
    raw_spans: object,
    *,
    key: str,
    expected_class: str,
    doc_id: str,
    text: str,
    schema: Schema,
    where_doc: str,
) -> list[GoldSpan]:
    """Resolve one span list, enforcing that its labels are of `expected_class`.

    The class partition is enforced rather than assumed. A quasi label sitting
    in `spans` would be scored by F1, and a direct label sitting in
    `quasi_spans` would escape the recall gates entirely - both are the category
    error the schema's own comments forbid, and both are silent if unchecked.
    """
    if not isinstance(raw_spans, list):
        raise GoldError(f"{where_doc}: {key!r} must be a list")

    resolved: list[GoldSpan] = []
    for index, raw_span in enumerate(raw_spans):
        where_span = f"{where_doc} {key}[{index}]"
        span = _as_mapping(raw_span, where_span)
        quote = _require_str(span, "quote", where_span)
        label = _require_str(span, "label", where_span)
        if label not in schema.all_ids:
            raise GoldError(
                f"{where_span}: unknown label {label!r}; it is not declared in "
                "eval/schema.yaml"
            )
        if expected_class == "direct" and not schema.is_direct(label):
            raise GoldError(
                f"{where_span}: {label!r} is not a direct identifier; contextual "
                "quasi-identifiers belong in 'quasi_spans', which is scored by "
                "the red team rather than by F1"
            )
        if expected_class == "quasi" and not schema.is_quasi(label):
            raise GoldError(
                f"{where_span}: {label!r} is not a quasi-identifier; direct "
                "identifiers belong in 'spans' so they are covered by the "
                "per-entity recall gates"
            )

        reason = span.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise GoldError(f"{where_span}: 'reason' must be a string or absent")

        occurrence = _occurrence(span, where_span)
        start, end = resolve_quote(text, quote, occurrence, where_span)
        resolved.append(
            GoldSpan(
                doc_id=doc_id,
                label=label,
                quote=quote,
                occurrence=occurrence,
                start=start,
                end=end,
                reason=reason,
            )
        )
    return resolved


# Every key a fixture may carry. An unrecognised key is a hard error: the whole
# reason this list exists is that `quasi_spans` was once read by nobody and 88
# gold spans went silently unscored.
KNOWN_DOCUMENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "doc_id",
        "split",
        "note_type",
        "specialty",
        "attack",
        "attack_class",
        "tags",
        "text",
        "spans",
        "quasi_spans",
        "allowlist_terms",
    }
)


def _is_adversarial_source(source_path: Path) -> bool:
    """True when a fixture file lives under eval/adversarial/.

    Path-based rather than content-based on purpose: the requirement is that
    every fixture FILED as adversarial declares its class, and a check that
    reads the record cannot notice a record that omitted the field.
    """
    return "adversarial" in source_path.parts


def _parse_document(
    record: dict[str, Any], schema: Schema, source_path: Path, line_no: int
) -> Document:
    location = f"{source_path}:{line_no}"
    doc_id = _require_str(record, "doc_id", location)
    where_doc = f"{location} doc_id={doc_id}"

    unknown = sorted(set(record) - KNOWN_DOCUMENT_KEYS)
    if unknown:
        raise GoldError(
            f"{where_doc}: unrecognised fixture key(s): {', '.join(unknown)}. "
            "Unknown keys are rejected rather than ignored, because an ignored "
            "key can silently drop gold spans and inflate recall."
        )

    text = record.get("text")
    if not isinstance(text, str) or not text:
        raise GoldError(f"{where_doc}: 'text' must be a non-empty string")

    split = record.get("split", "dev")
    if not isinstance(split, str) or not split:
        raise GoldError(f"{where_doc}: 'split' must be a non-empty string")

    note_type = record.get("note_type")
    if note_type is not None and not isinstance(note_type, str):
        raise GoldError(f"{where_doc}: 'note_type' must be a string or absent")

    specialty = record.get("specialty")
    if specialty is not None and not isinstance(specialty, str):
        raise GoldError(f"{where_doc}: 'specialty' must be a string or absent")

    attack = record.get("attack")
    if attack is not None and not isinstance(attack, str):
        raise GoldError(f"{where_doc}: 'attack' must be a string or absent")

    attack_class = record.get("attack_class")
    if attack_class is not None and not isinstance(attack_class, str):
        raise GoldError(f"{where_doc}: 'attack_class' must be a string or absent")
    if attack_class is not None and attack_class not in ATTACK_CLASSES:
        raise GoldError(
            f"{where_doc}: unknown attack_class {attack_class!r}. Permitted "
            f"values: {', '.join(ATTACK_CLASSES)}. The enum is closed on "
            "purpose - a value outside it would be counted as coverage of an "
            "attack class that the red team does not run."
        )
    # An adversarial fixture without a class is invisible to the coverage
    # report, and an invisible fixture is indistinguishable from a gap that
    # nobody has filled. `attack` prose alone does not satisfy this: prose is
    # unique per fixture and therefore ungroupable.
    if _is_adversarial_source(source_path) and attack_class is None:
        raise GoldError(
            f"{where_doc}: adversarial fixtures require 'attack_class', one of "
            f"{', '.join(ATTACK_CLASSES)}. The free-prose 'attack' field "
            "explains a fixture to a human; 'attack_class' is what lets the L6 "
            "red team count coverage and see which classes have no fixture."
        )

    raw_tags = record.get("tags", [])
    if not isinstance(raw_tags, list) or any(
        not isinstance(tag, str) for tag in raw_tags
    ):
        raise GoldError(f"{where_doc}: 'tags' must be a list of strings")
    tags = tuple(str(tag) for tag in raw_tags)

    # Direct identifiers live in `spans`, contextual quasi-identifiers in
    # `quasi_spans`. Both are resolved here and merged into one span list; the
    # harness re-splits them by class. Reading only one of the two keys would
    # silently drop an entire scoring class, which is the failure this module
    # exists to prevent.
    spans: list[GoldSpan] = []
    spans.extend(
        _parse_span_list(
            record.get("spans", []),
            key="spans",
            expected_class="direct",
            doc_id=doc_id,
            text=text,
            schema=schema,
            where_doc=where_doc,
        )
    )
    spans.extend(
        _parse_span_list(
            record.get("quasi_spans", []),
            key="quasi_spans",
            expected_class="quasi",
            doc_id=doc_id,
            text=text,
            schema=schema,
            where_doc=where_doc,
        )
    )

    raw_terms = record.get("allowlist_terms", [])
    if not isinstance(raw_terms, list):
        raise GoldError(f"{where_doc}: 'allowlist_terms' must be a list")

    terms: list[AllowlistTerm] = []
    for index, raw_term in enumerate(raw_terms):
        where_term = f"{where_doc} allowlist_terms[{index}]"
        if isinstance(raw_term, str):
            term_entry: dict[str, Any] = {"quote": raw_term}
        else:
            term_entry = _as_mapping(raw_term, where_term)
        quote = _require_str(term_entry, "quote", where_term)
        category = term_entry.get("category")
        if category is not None and not isinstance(category, str):
            raise GoldError(f"{where_term}: 'category' must be a string or absent")
        if isinstance(category, str) and category not in schema.allowlist_ids:
            raise GoldError(
                f"{where_term}: unknown allowlist category {category!r}; it is not "
                "declared in eval/schema.yaml"
            )
        occurrence = _occurrence(term_entry, where_term)
        start, end = resolve_quote(text, quote, occurrence, where_term)
        terms.append(
            AllowlistTerm(
                doc_id=doc_id,
                term=quote,
                category=category,
                occurrence=occurrence,
                start=start,
                end=end,
            )
        )

    return Document(
        doc_id=doc_id,
        split=split,
        note_type=note_type,
        text=text,
        spans=tuple(spans),
        allowlist_terms=tuple(terms),
        source_path=str(source_path),
        tags=tags,
        specialty=specialty,
        attack=attack,
        attack_class=attack_class,
    )


def iter_corpus_files(roots: Iterable[Path]) -> list[Path]:
    """Return every .jsonl fixture under `roots`, excluding build output."""
    files: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.jsonl")):
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            files.append(path)
    return files


def load_corpus(
    roots: Sequence[Path] | None = None, schema: Schema | None = None
) -> list[Document]:
    """Load and resolve every fixture under `roots`.

    Raises `GoldError` on the first unresolvable span. Duplicate doc_ids are
    fatal too: two documents sharing an id would double-count in the
    document-level leak rate.
    """
    corpus_roots = tuple(roots) if roots is not None else DEFAULT_CORPUS_ROOTS
    active_schema = schema if schema is not None else load_schema()

    documents: list[Document] = []
    seen: dict[str, str] = {}
    for path in iter_corpus_files(corpus_roots):
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise GoldError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
                record = _as_mapping(raw, f"{path}:{line_no}")
                document = _parse_document(record, active_schema, path, line_no)
                if document.doc_id in seen:
                    raise GoldError(
                        f"{path}:{line_no}: duplicate doc_id "
                        f"{document.doc_id!r}, already defined in "
                        f"{seen[document.doc_id]}"
                    )
                seen[document.doc_id] = f"{path}:{line_no}"
                documents.append(document)
    return documents


def build_resolved(
    documents: Sequence[Document], out_path: Path = RESOLVED_PATH
) -> Path:
    """Write the resolved corpus to `out_path` (gitignored build output)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "documents": [document.as_dict() for document in documents],
        "offset_unit": "utf8_bytes",
    }
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out_path


def attack_class_coverage(documents: Sequence[Document]) -> dict[str, int]:
    """Fixture count per attack class, INCLUDING classes with zero fixtures.

    Every enum member is present in the result even at zero. A table that only
    lists the classes somebody remembered to write a fixture for reports full
    coverage of whatever it happens to contain; the gap is the point.
    """
    counts: dict[str, int] = {name: 0 for name in ATTACK_CLASSES}
    for document in documents:
        if document.attack_class is not None:
            counts[document.attack_class] += 1
    return counts


def summarise(documents: Sequence[Document], schema: Schema) -> dict[str, Any]:
    """Return corpus counts for the CLI summary and the results artifact."""
    per_split: dict[str, int] = {}
    per_label: dict[str, int] = {}
    direct_spans = 0
    quasi_spans = 0
    allowlist_terms = 0
    for document in documents:
        per_split[document.split] = per_split.get(document.split, 0) + 1
        allowlist_terms += len(document.allowlist_terms)
        for span in document.spans:
            per_label[span.label] = per_label.get(span.label, 0) + 1
            if schema.is_direct(span.label):
                direct_spans += 1
            elif schema.is_quasi(span.label):
                quasi_spans += 1
    per_attack_class = attack_class_coverage(documents)
    return {
        "documents": len(documents),
        "adversarial_documents": sum(
            1 for document in documents if document.is_adversarial
        ),
        "direct_spans": direct_spans,
        "quasi_spans": quasi_spans,
        "allowlist_terms": allowlist_terms,
        "per_split": dict(sorted(per_split.items())),
        "per_label": dict(sorted(per_label.items())),
        "per_attack_class": per_attack_class,
        "l6_attack_classes_with_no_fixture": [
            name for name in L6_ATTACK_CLASSES if per_attack_class[name] == 0
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        roots = tuple(Path(arg) for arg in args)
    else:
        roots = DEFAULT_CORPUS_ROOTS

    schema = load_schema()
    try:
        documents = load_corpus(roots, schema)
    except GoldError as exc:
        print(f"FAILED to resolve gold corpus: {exc}", file=sys.stderr)
        return 1

    counts = summarise(documents, schema)
    out_path = build_resolved(documents)

    print("deid-tr gold corpus")
    print(f"  roots            : {', '.join(str(root) for root in roots)}")
    print(f"  documents        : {counts['documents']}")
    print(f"  direct spans     : {counts['direct_spans']}")
    print(f"  quasi spans      : {counts['quasi_spans']}")
    print(f"  allowlist terms  : {counts['allowlist_terms']}")
    print("  per split        :")
    per_split: dict[str, int] = counts["per_split"]
    for split, count in per_split.items():
        print(f"    {split:<20} {count}")
    print("  per label        :")
    per_label: dict[str, int] = counts["per_label"]
    for label, count in per_label.items():
        print(f"    {label:<20} {count}")
    print(f"  adversarial docs : {counts['adversarial_documents']}")
    print("  per attack class (L6 red-team coverage):")
    per_attack_class: dict[str, int] = counts["per_attack_class"]
    for name in L6_ATTACK_CLASSES:
        flag = "   <- NO FIXTURE" if per_attack_class[name] == 0 else ""
        print(f"    {name:<32} {per_attack_class[name]}{flag}")
    print("  per attack class (not an L6 attack):")
    for name in NON_L6_ATTACK_CLASSES:
        print(f"    {name:<32} {per_attack_class[name]}")
    gaps: list[str] = counts["l6_attack_classes_with_no_fixture"]
    if gaps:
        print(
            f"  NOTE: {len(gaps)} of {len(L6_ATTACK_CLASSES)} L6 attack classes "
            "have no fixture; the red team cannot report on a class it has "
            "nothing to run."
        )
    print(f"  resolved written : {out_path}")
    if counts["documents"] == 0:
        print("  NOTE: corpus is empty; every recall figure below is undefined.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
