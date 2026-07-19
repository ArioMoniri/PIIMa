"""I4, asserted rather than trusted.

"Feedback on a miss is PHI." A red-team report is nothing but a list of misses,
so it is the single most likely place in this repository for document text to
end up in a file that gets copied into a ticket, a commit message or a model
card. The attacks all hold the original text in memory - they have to, an oracle
attacker is the strongest one - and the only thing standing between that and the
artifact is `AttackFinding.as_dict` refusing to serialise the anchor.

This test reads the serialised report back and looks for the corpus in it. It
is deliberately crude: every reasonably long word of every document, checked
against the whole JSON blob. A cleverer test would be easier to satisfy.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from eval.build_gold import Document, load_corpus
from eval.redteam.maskers import LeakyMasker, NullMasker
from eval.redteam.runner import run_red_team
from eval.schema import Schema, load_schema, load_thresholds

# Words this short are ordinary Turkish and English and appear in the report's
# own prose. The identifying content of a clinical note is not five characters
# long.
_MIN_WORD = 6

# Vocabulary the report legitimately contains: label names, attack-class names
# and the fixed prose of the findings. Anything here is a word the red team
# wrote, not a word it copied out of a document.
_REPORT_VOCABULARY = frozenset(
    {
        "adversarial",
        "attackable",
        "contextual",
        "identifier",
        "quasi",
        "redteam",
        "surrogate",
    }
)


def _document_words(documents: list[Document]) -> set[str]:
    words: set[str] = set()
    for document in documents:
        for span in document.spans:
            for token in re.findall(r"\w+", span.quote, flags=re.UNICODE):
                lowered = token.lower()
                if len(lowered) >= _MIN_WORD and lowered not in _REPORT_VOCABULARY:
                    words.add(lowered)
    return words


@pytest.mark.parametrize("masker_factory", [NullMasker, LeakyMasker])
def test_report_json_contains_no_span_text(masker_factory: Any) -> None:
    schema: Schema = load_schema()
    thresholds: dict[str, Any] = load_thresholds()
    documents = load_corpus(schema=schema)
    report, _, _ = run_red_team(
        documents, masker_factory(), schema, thresholds, run_id="i4-check"
    )
    blob = json.dumps(report, ensure_ascii=False).lower()

    leaked = sorted(word for word in _document_words(documents) if word in blob)
    assert not leaked, (
        f"{len(leaked)} gold span token(s) reached the red-team report. A "
        "finding may describe the mechanism and the offsets; it may never carry "
        "the text (I4)."
    )


def test_finding_as_dict_cannot_emit_the_anchor() -> None:
    from eval.redteam.model import AttackFinding, FixtureAnchor

    finding = AttackFinding(
        doc_id="d1",
        attack_class="narrative_survival",
        detail="a gold EMPLOYER_ROLE quasi-identifier survived masking",
        anchor=FixtureAnchor(
            quote="Merkez Bankasi'nda calisiyor", label="EMPLOYER_ROLE"
        ),
    )
    payload = json.dumps(finding.as_dict(), ensure_ascii=False)
    assert "anchor" not in payload
    assert "Bankasi" not in payload
    # repr is the other way text escapes, via a traceback or a debug print.
    assert "Bankasi" not in repr(finding)
