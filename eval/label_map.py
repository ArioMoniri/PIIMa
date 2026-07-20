"""Loader and validator for `eval/label_maps/*.yaml`.

A third-party checkpoint emits its own label set, and scoring it against
`eval/schema.yaml` needs a translation. That translation is a set of judgement
calls that change the reported numbers, so it lives in YAML with its reasoning
attached and this module is the only thing that reads it. A second checkpoint
with a different label set is a new file in `eval/label_maps/` and no code
change here.

WHAT THIS MODULE REFUSES, and why each refusal is worth a hard error:

*   A source label with no `targets` key. "We forgot this label" and "we decided
    this label maps to nothing" must not look the same on disk, so declining is
    spelled `targets: []` and silence is a `LabelMapError`.
*   A lookup of a label the map does not declare. The alternative -- returning
    `None` for an unknown label the way it is returned for a deliberately
    unmapped one -- turns a checkpoint that grew a new entity type into a
    silently under-scored benchmark, which is the same failure the schema
    validator exists to prevent.
*   Two source labels claiming one schema id with no stated reason. Many-to-one
    is legitimate (our schema is coarser than theirs in places) but it is a
    decision, so it is written down or it is rejected.
*   A quasi-identifier target marked `scored: true`. Class B labels are
    validated by the L6 re-ID red team and never by F1 (schema class B comment,
    D-008). A YAML edit must not be able to promote one into the F1-scored set;
    doing that requires changing this rule, which requires arguing for it.

WHAT THIS MODULE DOES NOT DO. It does not score anything. `MatchPolicy.ANY_OF`
is a specification the eval harness does not implement yet -- `match_spans`
compares labels with `==`. Loading a map therefore gives a scorer no way to use
an `any_of` label today, and that is stated rather than papered over with a
runtime fallback, because the obvious fallback (collapse to the first target) is
the exact scoring error the map's own rationale rejects.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

import yaml

from eval.schema import REPO_ROOT, Schema

DEFAULT_LABEL_MAP_DIR: Final[Path] = REPO_ROOT / "eval" / "label_maps"

# The BIO/BIOES prefixes a token classifier may put in front of an entity type.
# Stripped rather than enumerated in the YAML: a map that listed `B-TCKN` and
# `I-TCKN` as separate entries would happily accept a checkpoint that had
# dropped one of them.
_BIO_PREFIXES: Final[tuple[str, ...]] = ("B-", "I-", "E-", "S-", "L-", "U-")

# The outside-any-entity tag. Not an entity type, so it is not declared in the
# map and looking it up is not an error.
OUTSIDE_TAG: Final[str] = "O"

LABEL_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "source",
    "targets",
    "match_policy",
    "scored",
    "rationale",
)

META_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "map_version",
    "source_model",
    "source_scheme",
    "source_label_count",
    "schema_file",
    "status",
)

# `unmeasured` is the honest state of any map whose checkpoint has not been run
# against the corpus. `measured` may only be set by a run that produced an eval
# artifact; nothing in this repository sets it today.
VALID_STATUSES: Final[frozenset[str]] = frozenset({"unmeasured", "measured"})


class LabelMapError(Exception):
    """Raised when a label map violates a structural invariant."""


class MatchPolicy(Enum):
    """How a source label's prediction is matched against gold spans."""

    # One source label, one schema id. Ordinary label equality.
    EXACT = "exact"
    # One source label, several schema ids our schema distinguishes and the
    # model does not. A prediction is eligible to match a gold span carrying any
    # of the targets, is consumed by the first match (one-to-one, so one
    # prediction is never counted several times), and credits the true positive
    # to the GOLD span's own label so every per-entity floor stays intact.
    ANY_OF = "any_of"
    # No schema id. An explicit decision, not an omission.
    UNMAPPED = "unmapped"


@dataclass(frozen=True)
class LabelMapping:
    """One source label's disposition, with the reasoning that produced it."""

    source: str
    targets: tuple[str, ...]
    match_policy: MatchPolicy
    scored: bool
    rationale: str
    shared_target_reason: str | None
    scoring_note: str | None
    needs_human_decision: bool

    @property
    def is_mapped(self) -> bool:
        return self.match_policy is not MatchPolicy.UNMAPPED


@dataclass(frozen=True)
class LabelMap:
    """A validated third-party label set translated onto `eval/schema.yaml`."""

    meta: dict[str, Any]
    mappings: tuple[LabelMapping, ...]

    @property
    def source_model(self) -> str:
        return str(self.meta["source_model"])

    @property
    def status(self) -> str:
        return str(self.meta["status"])

    @property
    def source_labels(self) -> frozenset[str]:
        return frozenset(mapping.source for mapping in self.mappings)

    @property
    def mapped_labels(self) -> frozenset[str]:
        return frozenset(m.source for m in self.mappings if m.is_mapped)

    @property
    def unmapped_labels(self) -> frozenset[str]:
        return frozenset(m.source for m in self.mappings if not m.is_mapped)

    @property
    def needs_human_decision(self) -> frozenset[str]:
        return frozenset(m.source for m in self.mappings if m.needs_human_decision)

    @property
    def scored_labels(self) -> frozenset[str]:
        return frozenset(m.source for m in self.mappings if m.scored)

    def lookup(self, source_label: str) -> LabelMapping:
        """Resolve a source label, stripping any BIO prefix.

        An undeclared label is a hard error and not `None`: `None` is what a
        DELIBERATELY unmapped label returns from `targets_for`, and conflating
        the two lets a checkpoint that grew an entity type score as if it had
        not.
        """
        entity = strip_bio_prefix(source_label)
        for mapping in self.mappings:
            if mapping.source == entity:
                return mapping
        raise LabelMapError(
            f"{self.source_model}: unknown source label {source_label!r} "
            f"(normalised to {entity!r}); this map declares "
            f"{len(self.mappings)} labels and every prediction must resolve to "
            "one of them or be an explicit null"
        )

    def targets_for(self, source_label: str) -> tuple[str, ...]:
        """Schema ids a source label may match; empty for a declined label."""
        return self.lookup(source_label).targets


def strip_bio_prefix(raw: str) -> str:
    """Strip one BIO/BIOES prefix. Case and surrounding space are normalised."""
    text = raw.strip().upper()
    for prefix in _BIO_PREFIXES:
        if text.startswith(prefix):
            return text[len(prefix) :]
    return text


def _as_mapping(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LabelMapError(f"{where}: expected a mapping, got {type(value).__name__}")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise LabelMapError(f"{where}: non-string key {key!r}")
        result[key] = item
    return result


def _require_str(entry: dict[str, Any], key: str, name: str) -> str:
    value = entry[key]
    if not isinstance(value, str) or not value.strip():
        raise LabelMapError(
            f"{name}: '{key}' must be a non-empty string, got {value!r}"
        )
    return value


def _require_bool(entry: dict[str, Any], key: str, name: str) -> bool:
    value = entry[key]
    if not isinstance(value, bool):
        raise LabelMapError(f"{name}: '{key}' must be a boolean, got {value!r}")
    return value


def _optional_str(entry: dict[str, Any], key: str, name: str) -> str | None:
    if key not in entry:
        return None
    return _require_str(entry, key, name)


def _parse_targets(entry: dict[str, Any], name: str, schema: Schema) -> tuple[str, ...]:
    raw = entry["targets"]
    if not isinstance(raw, list):
        raise LabelMapError(
            f"{name}: 'targets' must be a list (use [] to decline a label "
            f"explicitly), got {type(raw).__name__}"
        )
    targets: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise LabelMapError(f"{name}: target ids must be non-empty strings")
        if item not in schema.all_ids:
            raise LabelMapError(
                f"{name}: target {item!r} does not exist in eval/schema.yaml"
            )
        if item in targets:
            raise LabelMapError(f"{name}: target {item!r} listed twice")
        targets.append(item)
    return tuple(targets)


def _parse_policy(
    entry: dict[str, Any], name: str, targets: Sequence[str]
) -> MatchPolicy:
    raw = _require_str(entry, "match_policy", name)
    try:
        policy = MatchPolicy(raw)
    except ValueError as exc:
        valid = ", ".join(sorted(p.value for p in MatchPolicy))
        raise LabelMapError(
            f"{name}: unknown match_policy {raw!r}; expected one of {valid}"
        ) from exc

    if policy is MatchPolicy.UNMAPPED and targets:
        raise LabelMapError(
            f"{name}: match_policy 'unmapped' must carry no targets, got "
            f"{list(targets)}"
        )
    if policy is not MatchPolicy.UNMAPPED and not targets:
        raise LabelMapError(
            f"{name}: no targets, so the only honest policy is 'unmapped'; "
            f"got {policy.value}"
        )
    if policy is MatchPolicy.EXACT and len(targets) != 1:
        raise LabelMapError(
            f"{name}: match_policy 'exact' needs exactly one target, got {len(targets)}"
        )
    if policy is MatchPolicy.ANY_OF and len(targets) < 2:
        raise LabelMapError(
            f"{name}: match_policy 'any_of' needs at least two targets; with "
            "one target it is 'exact' and saying otherwise hides the fact that "
            "no distinction is being collapsed"
        )
    return policy


def _check_scored(
    entry: dict[str, Any], name: str, targets: Sequence[str], schema: Schema
) -> bool:
    scored = _require_bool(entry, "scored", name)
    if scored and not targets:
        raise LabelMapError(f"{name}: an unmapped label cannot be scored")

    quasi_targets = [target for target in targets if schema.is_quasi(target)]
    if scored and quasi_targets:
        raise LabelMapError(
            f"{name}: {', '.join(quasi_targets)} is a class B quasi-identifier, "
            "validated by the L6 re-ID red team and never by F1 (D-008). "
            "'scored: true' here would promote it into the F1-scored set as a "
            "side effect of a YAML edit; that reversal needs an ADR, not a flag"
        )

    allowlist_targets = [target for target in targets if target in schema.allowlist_ids]
    if allowlist_targets:
        raise LabelMapError(
            f"{name}: {', '.join(allowlist_targets)} is a class C allowlist "
            "category. Those are a NEGATIVE set scored as a false-positive "
            "rate, not a prediction target"
        )
    return scored


def _parse_label(raw: object, index: int, schema: Schema) -> LabelMapping:
    entry = _as_mapping(raw, f"labels[{index}]")
    raw_source = entry.get("source")
    name = (
        f"labels[{index}] (source={raw_source})"
        if isinstance(raw_source, str) and raw_source
        else f"labels[{index}] (source missing)"
    )

    missing = [key for key in LABEL_REQUIRED_KEYS if key not in entry]
    if missing:
        raise LabelMapError(f"{name}: missing required key(s): {', '.join(missing)}")

    source = _require_str(entry, "source", name)
    if source != strip_bio_prefix(source):
        raise LabelMapError(
            f"{name}: source labels are declared WITHOUT a BIO prefix; the "
            "loader strips B-/I- at lookup, and declaring both halves would "
            "let a checkpoint drop one of them unnoticed"
        )

    targets = _parse_targets(entry, name, schema)
    policy = _parse_policy(entry, name, targets)
    scored = _check_scored(entry, name, targets, schema)

    return LabelMapping(
        source=source,
        targets=targets,
        match_policy=policy,
        scored=scored,
        rationale=_require_str(entry, "rationale", name),
        shared_target_reason=_optional_str(entry, "shared_target_reason", name),
        scoring_note=_optional_str(entry, "scoring_note", name),
        needs_human_decision=(
            _require_bool(entry, "needs_human_decision", name)
            if "needs_human_decision" in entry
            else False
        ),
    )


def _check_collisions(mappings: Sequence[LabelMapping]) -> None:
    """Reject an unexplained many-to-one mapping.

    Many-to-one is legitimate where our schema is coarser than theirs -- two
    source labels produce spans over different text, so nothing is double
    counted -- but it costs the eval report a distinction it can no longer make.
    That is a decision, so it is written down or it is a hard error.
    """
    claimants: dict[str, list[LabelMapping]] = {}
    for mapping in mappings:
        for target in mapping.targets:
            claimants.setdefault(target, []).append(mapping)

    for target, holders in sorted(claimants.items()):
        if len(holders) < 2:
            continue
        unexplained = [m.source for m in holders if not m.shared_target_reason]
        if unexplained:
            raise LabelMapError(
                f"schema id {target!r} is claimed by "
                f"{', '.join(m.source for m in holders)}, but "
                f"{', '.join(unexplained)} state(s) no 'shared_target_reason'. "
                "A shared target is a decision; write it down"
            )


def validate_label_map(raw: object, schema: Schema) -> LabelMap:
    """Validate an already-parsed label-map document against the schema."""
    document = _as_mapping(raw, "label map")

    for section in ("meta", "labels"):
        if section not in document:
            raise LabelMapError(f"label map: missing required section {section!r}")

    meta = _as_mapping(document["meta"], "meta")
    missing_meta = [key for key in META_REQUIRED_KEYS if key not in meta]
    if missing_meta:
        raise LabelMapError(f"meta: missing required key(s): {', '.join(missing_meta)}")

    status = _require_str(meta, "status", "meta")
    if status not in VALID_STATUSES:
        raise LabelMapError(
            f"meta: unknown status {status!r}; expected one of "
            f"{', '.join(sorted(VALID_STATUSES))}"
        )

    raw_labels = document["labels"]
    if not isinstance(raw_labels, list) or not raw_labels:
        raise LabelMapError("labels: expected a non-empty list")

    mappings = tuple(
        _parse_label(entry, index, schema) for index, entry in enumerate(raw_labels)
    )

    seen: set[str] = set()
    for mapping in mappings:
        if mapping.source in seen:
            raise LabelMapError(f"duplicate source label {mapping.source!r}")
        seen.add(mapping.source)

    declared = meta["source_label_count"]
    if isinstance(declared, bool) or not isinstance(declared, int):
        raise LabelMapError(
            f"meta: 'source_label_count' must be an integer, got {declared!r}"
        )
    if declared != len(mappings):
        raise LabelMapError(
            f"meta: 'source_label_count' says {declared} but {len(mappings)} "
            "labels are declared. The count is a checksum against a checkpoint "
            "whose label set changed under us"
        )

    _check_collisions(mappings)
    return LabelMap(meta=meta, mappings=mappings)


def load_label_map(path: Path | str, schema: Schema) -> LabelMap:
    """Load and validate a label map from `path`."""
    map_path = Path(path)
    if not map_path.is_file():
        raise LabelMapError(f"label map file not found: {map_path}")
    try:
        raw = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise LabelMapError(f"{map_path}: not valid YAML: {exc}") from exc
    return validate_label_map(raw, schema)


def available_label_maps(
    directory: Path | str = DEFAULT_LABEL_MAP_DIR,
) -> tuple[Path, ...]:
    """Every label map on disk, sorted. Used by tests to keep coverage total."""
    map_dir = Path(directory)
    if not map_dir.is_dir():
        return ()
    return tuple(sorted(map_dir.glob("*.yaml")))
