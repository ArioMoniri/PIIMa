"""The REAL pipeline, wired into the eval harness and the L6 red team.

WHY THIS FILE EXISTS. Before it, `eval/redteam/runner.py` could only be pointed
at three REFERENCE maskers - null, leaky, oracle - all of them derived from the
gold annotations. The number it published therefore described the INSTRUMENT and
not the product, and because `eval/harness.py` read that number out of a
committed file regardless of what was being scored, `contextual_reid_rate` came
out byte-identical for the null detector, an L1-only pipeline and a full
pipeline. A gate that a detector finding nothing can pass is not a gate.

The fix is to attack the actual masked output. `core::Pipeline` is Rust, so this
module speaks to `eval/rust-bridge/` (binary `deid-eval-bridge`) over stdin and
stdout, and exposes two things built from its output:

  PipelineDetector - a `eval.harness.Detector`. Its predictions are the spans the
                     pipeline decided to MASK, carrying the pipeline's own
                     confidence and, crucially, whether the span was actually
                     CHECKSUM-VALIDATED rather than merely labelled as a
                     checksum-validatable type.
  PipelineMasker   - a `eval.redteam.maskers.Masker`. The only masker whose
                     re-ID rate may ever populate the release gate.

Both report the same `detector` identity string, which is what lets
`eval.harness` refuse a red-team report produced against a different run.

OFFLINE. The bridge is built with `cargo build --offline`; nothing here reaches
the network, so `just test-airgapped` is unaffected.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from eval.build_gold import Document
from eval.harness import PredictedSpan
from eval.redteam.model import DeidDocument, MappedSpan
from eval.schema import REPO_ROOT, Schema

BRIDGE_CRATE: Final[str] = "deid-tr-eval-bridge"
BRIDGE_BINARY: Final[str] = "deid-eval-bridge"

# The one tier the bridge will run. Expert Determination needs an L3 local model
# the eval host does not install, and scoring a Safe Harbor run as though the
# contextual sweep had happened would be the same substitution this whole module
# exists to remove.
TIER: Final[str] = "safe_harbor"

# The identity recorded in the red-team report and matched by eval/harness.py.
DETECTOR_IDENTITY: Final[str] = f"pipeline:{TIER}"


class BridgeError(RuntimeError):
    """The bridge could not be built or did not answer.

    Carries no document text: the bridge's own errors are shaped as codes and
    offsets (I4), and this type must not undo that by quoting stderr blindly -
    it quotes only the bridge's diagnostic line, which is text-free by
    construction.
    """


@dataclass(frozen=True)
class BridgeSpan:
    """One span the pipeline produced, as the bridge reports it."""

    start: int
    end: int
    label: str
    decision: str
    replacement: str | None
    confidence: float
    # What the CHECKSUM said, not what a label claims. The distinction is the
    # whole of the checksum-precision gate: I8 forbids a checksum-valid Turkish
    # ID from existing in this repository, so on this corpus every TCKN span is
    # labelled TCKN and validated by nothing.
    checksum_validated: bool
    rationale: str

    @property
    def masked(self) -> bool:
        return self.decision == "mask"


@dataclass(frozen=True)
class BridgeDocument:
    """The pipeline's output for one document."""

    doc_id: str
    deid_text: str
    spans: tuple[BridgeSpan, ...]

    @property
    def masked_spans(self) -> tuple[BridgeSpan, ...]:
        return tuple(span for span in self.spans if span.masked)


def bridge_binary(repo_root: Path = REPO_ROOT) -> Path:
    """Locate the bridge, building it offline if necessary."""
    override = os.environ.get("DEID_EVAL_BRIDGE")
    if override:
        path = Path(override)
        if not path.is_file():
            raise BridgeError(f"DEID_EVAL_BRIDGE does not point at a file: {path}")
        return path

    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / BRIDGE_BINARY
        if candidate.is_file():
            return candidate

    if shutil.which("cargo") is None:
        raise BridgeError(
            "cargo is not installed, so the pipeline bridge cannot be built. "
            "The pipeline masker is the ONLY masker whose number may populate "
            "the contextual gate, so this fails rather than falling back to a "
            "reference masker."
        )
    build = subprocess.run(
        ["cargo", "build", "--offline", "-p", BRIDGE_CRATE],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        raise BridgeError(f"cargo build -p {BRIDGE_CRATE} failed (offline)")
    built = repo_root / "target" / "debug" / BRIDGE_BINARY
    if not built.is_file():
        raise BridgeError(f"{BRIDGE_CRATE} built but {built} is absent")
    return built


def _parse_span(raw: Any) -> BridgeSpan:
    if not isinstance(raw, dict):
        raise BridgeError("bridge span was not a JSON object")
    replacement = raw.get("replacement")
    return BridgeSpan(
        start=int(raw["start"]),
        end=int(raw["end"]),
        label=str(raw["label"]),
        decision=str(raw["decision"]),
        replacement=None if replacement is None else str(replacement),
        confidence=float(raw["confidence"]),
        checksum_validated=bool(raw["checksum_validated"]),
        rationale=str(raw["rationale"]),
    )


def run_pipeline(
    documents: Sequence[Document], repo_root: Path = REPO_ROOT
) -> dict[str, BridgeDocument]:
    """Run the real pipeline over `documents`, keyed by doc_id.

    One process for the whole corpus: the pipeline is stateless per document, so
    batching changes no number and turns 178 process spawns into one.
    """
    binary = bridge_binary(repo_root)
    request = {
        "tier": TIER,
        "documents": [
            {"doc_id": document.doc_id, "text": document.text} for document in documents
        ],
    }
    completed = subprocess.run(
        [str(binary)],
        input=json.dumps(request, ensure_ascii=False),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BridgeError(f"{BRIDGE_BINARY} exited {completed.returncode}")
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise BridgeError("bridge output was not a JSON object")
    if payload.get("detector") != DETECTOR_IDENTITY:
        raise BridgeError(
            "bridge reported a different detector identity than this module "
            "claims; provenance matching would silently compare the wrong names"
        )
    raw_documents = payload.get("documents")
    if not isinstance(raw_documents, list):
        raise BridgeError("bridge output carried no documents array")

    out: dict[str, BridgeDocument] = {}
    for entry in raw_documents:
        if not isinstance(entry, dict):
            raise BridgeError("bridge document was not a JSON object")
        doc_id = str(entry["doc_id"])
        out[doc_id] = BridgeDocument(
            doc_id=doc_id,
            deid_text=str(entry["deid_text"]),
            spans=tuple(_parse_span(span) for span in entry["spans"]),
        )
    missing = [document.doc_id for document in documents if document.doc_id not in out]
    if missing:
        raise BridgeError(f"bridge returned no output for {len(missing)} document(s)")
    return out


class PipelineDetector:
    """The real pipeline, scored by eval/harness.py.

    Predictions are the spans the pipeline MASKED. A span L4 demoted to `Keep`
    is not a prediction: the document went out with that text intact, so
    counting it would credit the system for a decision it reversed.
    """

    def __init__(self, repo_root: Path = REPO_ROOT) -> None:
        self._repo_root = repo_root
        # Keyed by text because the Detector protocol is handed text and nothing
        # else; the doc_id is not in scope inside `predict`.
        self._by_text: dict[str, BridgeDocument] = {}

    @property
    def name(self) -> str:
        return DETECTOR_IDENTITY

    def warm(self, documents: Sequence[Document]) -> None:
        """Pre-run the whole corpus in one bridge process."""
        produced = run_pipeline(documents, self._repo_root)
        for document in documents:
            self._by_text[document.text] = produced[document.doc_id]

    def predict(self, text: str) -> list[PredictedSpan]:
        found = self._by_text.get(text)
        if found is None:
            raise BridgeError(
                "PipelineDetector.predict was called for a document that was "
                "not warmed. Call warm(documents) with the corpus first; a "
                "per-call bridge spawn would make the eval unreadably slow and "
                "a silent empty prediction list would score as a miss."
            )
        return [
            PredictedSpan(
                start=span.start,
                end=span.end,
                label=span.label,
                confidence=span.confidence,
                checksum_validated=span.checksum_validated,
            )
            for span in found.masked_spans
        ]


class PipelineMasker:
    """The real pipeline, attacked by the L6 red team.

    THE ONLY MASKER WHOSE NUMBER MAY POPULATE THE GATE. null, leaky and oracle
    remain as calibration instruments (they prove the red team discriminates
    across three known reference points), but a rate measured against any of
    them is a statement about the red team, not about deid-tr.
    """

    def __init__(self, repo_root: Path = REPO_ROOT) -> None:
        self._repo_root = repo_root

    @property
    def name(self) -> str:
        return "pipeline"

    @property
    def detector(self) -> str:
        return DETECTOR_IDENTITY

    def mask_all(
        self, documents: Sequence[Document], schema: Schema
    ) -> list[DeidDocument]:
        del schema
        produced = run_pipeline(documents, self._repo_root)
        return [
            self._build(document, produced[document.doc_id]) for document in documents
        ]

    def mask(self, document: Document, schema: Schema) -> DeidDocument:
        return self.mask_all([document], schema)[0]

    @staticmethod
    def _build(document: Document, produced: BridgeDocument) -> DeidDocument:
        from eval.redteam.maskers import patient_key

        encoded = document.text.encode("utf-8")
        mapped = tuple(
            MappedSpan(
                start=span.start,
                end=span.end,
                label=span.label,
                surrogate=span.replacement if span.replacement is not None else "",
                # Sliced from the corpus this process already holds rather than
                # returned by the bridge: the bridge has no reason to send a
                # document's PHI back, and the red team needs both sides to
                # measure whether a surrogate leaks what it replaced.
                original=encoded[span.start : span.end].decode("utf-8"),
                # L5 salts per document (SaltScope::Document, the product
                # default), and the bridge derives that salt from the doc_id.
                salt=f"pipeline/document/{document.doc_id}",
            )
            for span in produced.masked_spans
        )
        return DeidDocument(
            gold=document,
            deid_text=produced.deid_text,
            span_map=mapped,
            patient_key=patient_key(document),
        )
