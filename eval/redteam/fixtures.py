"""Turn successful attacks into new adversarial fixtures.

An attack that succeeded once and was then fixed will regress silently unless
the case is in the corpus. So every red-team run that lands a hit writes the
case back as a fixture, in the ordinary quote-anchored format, and the next run
of the harness scores against it.

I7 - the golden set is append-only - is respected structurally rather than by
care: fixtures are written to a NEW file per run, named for the run id, and the
writer refuses to overwrite an existing path. No committed fixture file is ever
opened for writing, so no fixture can be weakened or deleted by this code.

Volume is capped per attack class. A masker that fails one attack fails it on
every document, and 178 near-identical fixtures would bury the corpus while
adding one bit of information. The cap keeps what the class is; the count of
what it hit lives in the report.

Fixture text is copied verbatim from the source fixture, which is synthetic by
I8. Nothing here can introduce real PHI that was not already committed, and
nothing here writes a document the red team was pointed at from outside the
corpus - `emit_fixtures` refuses a source document that did not come from a
fixture file.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from eval.build_gold import ADVERSARIAL_DIR, DEFAULT_CORPUS_ROOTS, load_corpus
from eval.redteam.model import AttackFinding, AttackResult, DeidDocument
from eval.schema import Schema

# Enough to describe the class from more than one angle, few enough that a
# systematically failing masker cannot flood the corpus.
MAX_FIXTURES_PER_CLASS: Final[int] = 3


def build_fixture_record(
    document: DeidDocument,
    finding: AttackFinding,
    schema: Schema,
    doc_id: str,
) -> dict[str, Any] | None:
    """Build one fixture record, or None when the finding carries no anchor.

    A finding without an anchor is deliberate in some attacks - rare_value_
    survival refuses to quote a rare name into a committed file (I4) - and those
    classes simply do not emit fixtures.
    """
    if finding.anchor is None:
        return None

    gold = document.gold
    direct: list[dict[str, Any]] = []
    quasi: list[dict[str, Any]] = []
    for span in gold.spans:
        entry: dict[str, Any] = {
            "quote": span.quote,
            "label": span.label,
            "occurrence": span.occurrence,
        }
        if schema.is_direct(span.label):
            direct.append(entry)
        else:
            if span.reason is not None:
                entry["reason"] = span.reason
            quasi.append(entry)

    anchor = finding.anchor
    if anchor.label is not None and schema.is_quasi(anchor.label):
        already = any(
            entry["quote"] == anchor.quote and entry["label"] == anchor.label
            for entry in quasi
        )
        if not already:
            quasi.append(
                {
                    "quote": anchor.quote,
                    "label": anchor.label,
                    "occurrence": anchor.occurrence,
                    "reason": finding.detail,
                }
            )

    record: dict[str, Any] = {
        "doc_id": doc_id,
        "split": "adversarial",
        "attack_class": finding.attack_class,
        "attack": (f"Emitted by the L6 red team from {gold.doc_id}: {finding.detail}."),
        "text": gold.text,
        "spans": direct,
        "quasi_spans": quasi,
        "allowlist_terms": [
            {
                "quote": term.term,
                "occurrence": term.occurrence,
                **({"category": term.category} if term.category is not None else {}),
            }
            for term in gold.allowlist_terms
        ],
    }
    if gold.note_type is not None:
        record["note_type"] = gold.note_type
    if gold.specialty is not None:
        record["specialty"] = gold.specialty
    return record


def select_findings(
    results: Sequence[AttackResult],
    corpus: Sequence[DeidDocument],
) -> list[tuple[DeidDocument, AttackFinding]]:
    """Pick at most `MAX_FIXTURES_PER_CLASS` anchored findings per attack class.

    One per source document, so a class does not spend its whole budget on the
    same note attacked from three angles.
    """
    by_doc = {document.doc_id: document for document in corpus}
    chosen: list[tuple[DeidDocument, AttackFinding]] = []
    for result in results:
        taken = 0
        seen_docs: set[str] = set()
        for finding in result.findings:
            if taken >= MAX_FIXTURES_PER_CLASS:
                break
            if finding.anchor is None:
                continue
            document = by_doc.get(finding.doc_id)
            if document is None or finding.doc_id in seen_docs:
                continue
            seen_docs.add(finding.doc_id)
            chosen.append((document, finding))
            taken += 1
    return chosen


def emit_fixtures(
    results: Sequence[AttackResult],
    corpus: Sequence[DeidDocument],
    schema: Schema,
    run_id: str,
    directory: Path = ADVERSARIAL_DIR,
    validate_roots: Sequence[Path] = DEFAULT_CORPUS_ROOTS,
) -> Path | None:
    """Write a new adversarial fixture file for this run, or None if empty.

    The written file is loaded back through `load_corpus` before this function
    returns. An emitted fixture that does not resolve would break every
    subsequent harness run, and discovering that at the next `just eval` rather
    than here is how a red team becomes the thing that broke the build.
    """
    selected = select_findings(results, corpus)
    if not selected:
        return None

    path = directory / f"adv_redteam_{run_id}.jsonl"
    if path.exists():
        raise FileExistsError(
            f"{path} already exists; red-team fixtures are append-only and are "
            "never rewritten (I7)"
        )

    lines: list[str] = []
    for index, (document, finding) in enumerate(selected, start=1):
        doc_id = f"adv-rt-{run_id}-{index:04d}"
        record = build_fixture_record(document, finding, schema, doc_id)
        if record is None:
            continue
        lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))

    if not lines:
        return None

    directory.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        load_corpus(tuple(validate_roots), schema)
    except Exception:
        path.unlink()
        raise
    return path
