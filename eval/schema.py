"""Loader and validator for eval/schema.yaml.

The schema is the single source of truth for the label vocabulary, so a
malformed schema must fail loudly at load time rather than degrade into a
harness that silently scores fewer entity types than the project claims to
cover. Validation is therefore structural and total: every entry is checked,
and the first violation raises `SchemaError` naming the offending entry.

The three identifier classes are validated by three different rule sets on
purpose. A `recall_threshold` on a quasi-identifier is not a typo to be
tolerated - it is a category error that would let an unvalidated contextual
number reach a model card as if it were an F1 gate, which is exactly the
failure mode the schema's own comments forbid.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA_PATH: Final[Path] = REPO_ROOT / "eval" / "schema.yaml"

VALID_DETECTORS: Final[frozenset[str]] = frozenset({"rules", "ner", "llm"})
VALID_IDENTIFIER_CLASSES: Final[frozenset[str]] = frozenset(
    {"direct", "quasi", "allowlist"}
)

DIRECT_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "id",
    "hipaa_category",
    "identifier_class",
    "detector",
    "tr_specific",
    "checksum_validatable",
    "recall_threshold",
    "description",
)
QUASI_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "id",
    "identifier_class",
    "detector",
    "validated_by",
    "scored_by_f1",
    "description",
)
ALLOWLIST_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "id",
    "identifier_class",
    "must_never_mask",
    "source_file",
    "code_switch_suffixed",
    "description",
)

# Quasi-identifiers are validated by the L6 red team, never by F1. Carrying
# either of these keys would make one look like a scored entity type.
QUASI_FORBIDDEN_KEYS: Final[tuple[str, ...]] = (
    "recall_threshold",
    "precision_threshold",
)


class SchemaError(Exception):
    """Raised when the entity schema violates a structural invariant."""


@dataclass(frozen=True)
class DirectEntity:
    """A class A direct identifier, scored by a per-entity recall floor."""

    id: str
    hipaa_category: str
    detector: str
    tr_specific: bool
    checksum_validatable: bool
    recall_threshold: float
    description: str
    precision_threshold: float | None


@dataclass(frozen=True)
class QuasiEntity:
    """A class B contextual quasi-identifier, validated by the red team."""

    id: str
    detector: str
    validated_by: str
    scored_by_f1: bool
    description: str


@dataclass(frozen=True)
class AllowlistCategory:
    """A class C medical-term category, scored as a false-positive rate."""

    id: str
    must_never_mask: bool
    source_file: str
    code_switch_suffixed: bool
    description: str


@dataclass(frozen=True)
class Schema:
    """The validated label vocabulary."""

    meta: dict[str, Any]
    direct: tuple[DirectEntity, ...]
    quasi: tuple[QuasiEntity, ...]
    allowlist: tuple[AllowlistCategory, ...]

    @property
    def direct_ids(self) -> frozenset[str]:
        return frozenset(entity.id for entity in self.direct)

    @property
    def quasi_ids(self) -> frozenset[str]:
        return frozenset(entity.id for entity in self.quasi)

    @property
    def allowlist_ids(self) -> frozenset[str]:
        return frozenset(entity.id for entity in self.allowlist)

    @property
    def all_ids(self) -> frozenset[str]:
        return self.direct_ids | self.quasi_ids | self.allowlist_ids

    @property
    def checksum_validatable_ids(self) -> frozenset[str]:
        return frozenset(e.id for e in self.direct if e.checksum_validatable)

    def direct_by_id(self, label: str) -> DirectEntity | None:
        for entity in self.direct:
            if entity.id == label:
                return entity
        return None

    def is_direct(self, label: str) -> bool:
        return label in self.direct_ids

    def is_quasi(self, label: str) -> bool:
        return label in self.quasi_ids


def _as_mapping(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SchemaError(f"{where}: expected a mapping, got {type(value).__name__}")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise SchemaError(f"{where}: non-string key {key!r}")
        result[key] = item
    return result


def _as_sequence(value: object, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise SchemaError(f"{where}: expected a list, got {type(value).__name__}")
    return list(value)


def _entry_name(entry: dict[str, Any], section: str, index: int) -> str:
    raw_id = entry.get("id")
    if isinstance(raw_id, str) and raw_id:
        return f"{section}[{index}] (id={raw_id})"
    return f"{section}[{index}] (id missing)"


def _require_keys(entry: dict[str, Any], keys: Sequence[str], name: str) -> None:
    missing = [key for key in keys if key not in entry]
    if missing:
        raise SchemaError(f"{name}: missing required key(s): {', '.join(missing)}")


def _require_str(entry: dict[str, Any], key: str, name: str) -> str:
    value = entry[key]
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{name}: '{key}' must be a non-empty string, got {value!r}")
    return value


def _require_bool(entry: dict[str, Any], key: str, name: str) -> bool:
    value = entry[key]
    if not isinstance(value, bool):
        raise SchemaError(f"{name}: '{key}' must be a boolean, got {value!r}")
    return value


def _require_rate(entry: dict[str, Any], key: str, name: str) -> float:
    value = entry[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchemaError(f"{name}: '{key}' must be a number, got {value!r}")
    rate = float(value)
    if not 0.0 < rate <= 1.0:
        raise SchemaError(f"{name}: '{key}' must be in (0.0, 1.0], got {rate}")
    return rate


def _require_identifier_class(entry: dict[str, Any], expected: str, name: str) -> None:
    value = _require_str(entry, "identifier_class", name)
    if value not in VALID_IDENTIFIER_CLASSES:
        raise SchemaError(f"{name}: unknown identifier_class {value!r}")
    if value != expected:
        raise SchemaError(
            f"{name}: identifier_class must be {expected!r} in this section, "
            f"got {value!r}"
        )


def _require_detector(entry: dict[str, Any], name: str) -> str:
    value = _require_str(entry, "detector", name)
    if value not in VALID_DETECTORS:
        raise SchemaError(
            f"{name}: unknown detector {value!r}; "
            f"expected one of {sorted(VALID_DETECTORS)}"
        )
    return value


def _parse_direct(entries: list[Any]) -> tuple[DirectEntity, ...]:
    parsed: list[DirectEntity] = []
    for index, raw in enumerate(entries):
        entry = _as_mapping(raw, f"direct_identifiers[{index}]")
        name = _entry_name(entry, "direct_identifiers", index)
        _require_keys(entry, DIRECT_REQUIRED_KEYS, name)
        _require_identifier_class(entry, "direct", name)
        detector = _require_detector(entry, name)
        checksum_validatable = _require_bool(entry, "checksum_validatable", name)

        precision_threshold: float | None = None
        if checksum_validatable:
            if "precision_threshold" not in entry:
                raise SchemaError(
                    f"{name}: checksum_validatable entries must carry "
                    "'precision_threshold' (a checksum-valid match is never a "
                    "false positive)"
                )
            precision_threshold = _require_rate(entry, "precision_threshold", name)
            if precision_threshold != 1.0:
                raise SchemaError(
                    f"{name}: checksum_validatable entries require "
                    f"precision_threshold 1.000, got {precision_threshold}"
                )
        elif "precision_threshold" in entry:
            raise SchemaError(
                f"{name}: 'precision_threshold' is only meaningful on a "
                "checksum_validatable entry; a precision floor on an "
                "NER-detected label creates pressure to drop borderline spans"
            )

        parsed.append(
            DirectEntity(
                id=_require_str(entry, "id", name),
                hipaa_category=_require_str(entry, "hipaa_category", name),
                detector=detector,
                tr_specific=_require_bool(entry, "tr_specific", name),
                checksum_validatable=checksum_validatable,
                recall_threshold=_require_rate(entry, "recall_threshold", name),
                description=_require_str(entry, "description", name),
                precision_threshold=precision_threshold,
            )
        )
    return tuple(parsed)


def _parse_quasi(entries: list[Any]) -> tuple[QuasiEntity, ...]:
    parsed: list[QuasiEntity] = []
    for index, raw in enumerate(entries):
        entry = _as_mapping(raw, f"quasi_identifiers[{index}]")
        name = _entry_name(entry, "quasi_identifiers", index)
        _require_keys(entry, QUASI_REQUIRED_KEYS, name)
        _require_identifier_class(entry, "quasi", name)

        present_forbidden = [key for key in QUASI_FORBIDDEN_KEYS if key in entry]
        if present_forbidden:
            raise SchemaError(
                f"{name}: quasi-identifiers are validated by the re-ID red team, "
                f"not scored by F1; remove {', '.join(present_forbidden)}"
            )

        detector = _require_detector(entry, name)
        scored_by_f1 = _require_bool(entry, "scored_by_f1", name)
        if scored_by_f1:
            raise SchemaError(
                f"{name}: 'scored_by_f1' must be false for a quasi-identifier"
            )

        parsed.append(
            QuasiEntity(
                id=_require_str(entry, "id", name),
                detector=detector,
                validated_by=_require_str(entry, "validated_by", name),
                scored_by_f1=scored_by_f1,
                description=_require_str(entry, "description", name),
            )
        )
    return tuple(parsed)


def _parse_allowlist(entries: list[Any]) -> tuple[AllowlistCategory, ...]:
    parsed: list[AllowlistCategory] = []
    for index, raw in enumerate(entries):
        entry = _as_mapping(raw, f"allowlist_categories[{index}]")
        name = _entry_name(entry, "allowlist_categories", index)
        _require_keys(entry, ALLOWLIST_REQUIRED_KEYS, name)
        _require_identifier_class(entry, "allowlist", name)
        must_never_mask = _require_bool(entry, "must_never_mask", name)
        if not must_never_mask:
            raise SchemaError(
                f"{name}: 'must_never_mask' must be true; an allowlist entry that "
                "may be masked is not an allowlist entry"
            )
        parsed.append(
            AllowlistCategory(
                id=_require_str(entry, "id", name),
                must_never_mask=must_never_mask,
                source_file=_require_str(entry, "source_file", name),
                code_switch_suffixed=_require_bool(entry, "code_switch_suffixed", name),
                description=_require_str(entry, "description", name),
            )
        )
    return tuple(parsed)


def _iter_ids(schema: Schema) -> Iterator[tuple[str, str]]:
    for direct in schema.direct:
        yield direct.id, "direct_identifiers"
    for quasi in schema.quasi:
        yield quasi.id, "quasi_identifiers"
    for allow in schema.allowlist:
        yield allow.id, "allowlist_categories"


def validate_schema(raw: object) -> Schema:
    """Validate an already-parsed schema document, returning a typed `Schema`."""
    document = _as_mapping(raw, "schema")

    for section in ("meta", "direct_identifiers", "quasi_identifiers"):
        if section not in document:
            raise SchemaError(f"schema: missing required section {section!r}")

    meta = _as_mapping(document["meta"], "meta")
    for key in ("schema_version", "language", "medical_register"):
        if key not in meta:
            raise SchemaError(f"meta: missing required key {key!r}")

    schema = Schema(
        meta=meta,
        direct=_parse_direct(
            _as_sequence(document["direct_identifiers"], "direct_identifiers")
        ),
        quasi=_parse_quasi(
            _as_sequence(document["quasi_identifiers"], "quasi_identifiers")
        ),
        allowlist=_parse_allowlist(
            _as_sequence(
                document.get("allowlist_categories", []), "allowlist_categories"
            )
        ),
    )

    seen: dict[str, str] = {}
    for entity_id, section in _iter_ids(schema):
        if entity_id in seen:
            raise SchemaError(
                f"duplicate entity id {entity_id!r}: declared in {seen[entity_id]} "
                f"and again in {section}"
            )
        seen[entity_id] = section

    return schema


def load_schema(path: Path | str = DEFAULT_SCHEMA_PATH) -> Schema:
    """Load and validate the entity schema from `path`."""
    schema_path = Path(path)
    if not schema_path.is_file():
        raise SchemaError(f"schema file not found: {schema_path}")
    try:
        raw = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SchemaError(f"{schema_path}: not valid YAML: {exc}") from exc
    return validate_schema(raw)


def load_thresholds(path: Path | str | None = None) -> dict[str, Any]:
    """Load eval/thresholds.yaml.

    No defaults are supplied here on purpose: the harness must fail a run when a
    gate key is missing rather than silently relax the gate.
    """
    thresholds_path = (
        Path(path) if path is not None else REPO_ROOT / "eval" / "thresholds.yaml"
    )
    if not thresholds_path.is_file():
        raise SchemaError(f"thresholds file not found: {thresholds_path}")
    try:
        raw = yaml.safe_load(thresholds_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SchemaError(f"{thresholds_path}: not valid YAML: {exc}") from exc
    return _as_mapping(raw, "thresholds")
