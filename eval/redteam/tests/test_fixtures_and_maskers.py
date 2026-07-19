"""Fixture emission (I7) and the reference maskers themselves.

The maskers are test instruments, so their own correctness is load-bearing: an
oracle that silently failed to substitute anything would make the red team look
like it passes, and the calibration tests in test_runner.py would assert
nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from eval.build_gold import Document, load_corpus
from eval.redteam.fixtures import MAX_FIXTURES_PER_CLASS, emit_fixtures, select_findings
from eval.redteam.maskers import LeakyMasker, NullMasker, OracleMasker, mask_corpus
from eval.redteam.runner import run_attacks
from eval.schema import Schema, load_schema, load_thresholds


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


@pytest.fixture(scope="module")
def corpus(schema: Schema) -> list[Document]:
    return load_corpus(schema=schema)


# ---------------------------------------------------------------------------
# maskers
# ---------------------------------------------------------------------------


def test_null_masker_changes_nothing(corpus: list[Document], schema: Schema) -> None:
    masked = mask_corpus(corpus[:10], NullMasker(), schema)
    assert all(document.deid_text == document.gold.text for document in masked)
    assert all(document.span_map == () for document in masked)


def test_oracle_masker_removes_every_gold_span(
    corpus: list[Document], schema: Schema
) -> None:
    checked = 0
    for document in mask_corpus(corpus, OracleMasker(), schema):
        for span in document.gold.spans:
            # Checked by OFFSET, not by substring. A substring test is wrong in
            # both directions on this corpus: a two-digit AGE_OVER_89 reappears
            # by coincidence inside the hex suffix of an unrelated surrogate,
            # and adv-direct-0005 deliberately embeds its TCKN a second time
            # inside a device log line that is not annotated. Both would read as
            # masking failures, and a test that cries wolf is a test somebody
            # eventually weakens.
            assert not document.survived(span.start, span.end), document.doc_id
            checked += 1
    assert checked > 0


def test_oracle_masker_uses_a_different_salt_per_document(
    corpus: list[Document], schema: Schema
) -> None:
    salts = {
        span.salt
        for document in mask_corpus(corpus[:20], OracleMasker(), schema)
        for span in document.span_map
    }
    assert len(salts) > 1


def test_leaky_masker_preserves_length(corpus: list[Document], schema: Schema) -> None:
    checked = 0
    for document in mask_corpus(corpus[:20], LeakyMasker(), schema):
        for span in document.span_map:
            assert len(span.surrogate) == len(span.original)
            checked += 1
    assert checked > 0


def test_leaky_masker_still_replaces_the_text(
    corpus: list[Document], schema: Schema
) -> None:
    """Leaky means leaky, not absent: it really does substitute."""
    for document in mask_corpus(corpus[:20], LeakyMasker(), schema):
        for span in document.span_map:
            if span.original.strip().isalpha():
                assert span.surrogate != span.original


# ---------------------------------------------------------------------------
# fixture emission
# ---------------------------------------------------------------------------


def test_emitted_fixtures_resolve_and_land_in_a_new_file(
    corpus: list[Document], schema: Schema, tmp_path: Path
) -> None:
    masked = mask_corpus(corpus, NullMasker(), schema)
    results = run_attacks(masked, schema)

    out_dir = tmp_path / "adversarial"
    path = emit_fixtures(
        results,
        masked,
        schema,
        run_id="unit-test",
        directory=out_dir,
        validate_roots=(out_dir,),
    )
    assert path is not None
    assert path.parent == out_dir

    # The written file must load through the ordinary gold loader; a fixture the
    # harness cannot resolve would break every subsequent eval run.
    emitted = load_corpus((out_dir,), schema)
    assert emitted
    assert all(document.attack_class is not None for document in emitted)
    assert all(document.split == "adversarial" for document in emitted)


def test_emission_refuses_to_overwrite(
    corpus: list[Document], schema: Schema, tmp_path: Path
) -> None:
    """I7 made structural: no committed fixture file is ever opened for writing."""
    masked = mask_corpus(corpus, NullMasker(), schema)
    results = run_attacks(masked, schema)
    out_dir = tmp_path / "adversarial"
    emit_fixtures(
        results, masked, schema, "same-id", directory=out_dir, validate_roots=(out_dir,)
    )
    with pytest.raises(FileExistsError):
        emit_fixtures(
            results,
            masked,
            schema,
            "same-id",
            directory=out_dir,
            validate_roots=(out_dir,),
        )


def test_emission_is_capped_per_attack_class(
    corpus: list[Document], schema: Schema
) -> None:
    masked = mask_corpus(corpus, NullMasker(), schema)
    results = run_attacks(masked, schema)
    selected = select_findings(results, masked)
    per_class: dict[str, int] = {}
    for _, finding in selected:
        per_class[finding.attack_class] = per_class.get(finding.attack_class, 0) + 1
    assert per_class
    assert max(per_class.values()) <= MAX_FIXTURES_PER_CLASS


def test_emission_returns_none_when_nothing_was_breached(
    schema: Schema, tmp_path: Path
) -> None:
    thresholds: dict[str, Any] = load_thresholds()
    del thresholds
    assert (
        emit_fixtures(
            [],
            [],
            schema,
            "empty",
            directory=tmp_path,
            validate_roots=(tmp_path,),
        )
        is None
    )
