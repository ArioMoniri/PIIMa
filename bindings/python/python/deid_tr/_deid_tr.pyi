"""Type stubs for the compiled extension.

Hand-written rather than generated, because the stub is where the API's safety
properties are stated in a form a caller's type checker enforces:

- `Pipeline.__init__` takes `tier` as a REQUIRED positional argument with no
  default, so `mypy` rejects `Pipeline()` before anyone runs it;
- every offset is documented as a BYTE offset, which is the difference between
  a correct slice and a corrupted Turkish name;
- no class exposes the covered text of a span, because none of them holds it.
"""

from collections.abc import Callable
from typing import final

__version__: str

@final
class Tier:
    """The assurance tier, which is a legal standard made into a product setting."""

    SAFE_HARBOR: Tier
    """L1 + L2 + L4 + L5: the 18 enumerated direct identifiers. Needs no model."""

    EXPERT_DETERMINATION: Tier
    """Adds L3, the full-document contextual sweep. Needs a LOCAL model."""

    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Span:
    """A candidate identifier located in the original document.

    There is deliberately no accessor for the covered text. The pipeline never
    stores it -- only a hash, so L5 can give one entity one surrogate -- and a
    caller who holds the document can slice it themselves.
    """

    @property
    def start(self) -> int:
        """Inclusive BYTE offset into the original document.

        Bytes, not characters. `len("Ayşe")` is 4 in Python and 5 here, so
        `doc[span.start : span.end]` on a `str` is wrong for any Turkish note;
        slice `doc.encode("utf-8")` and decode the result.
        """

    @property
    def end(self) -> int:
        """Exclusive BYTE offset into the original document."""

    @property
    def label(self) -> str:
        """The schema label, e.g. `TCKN`, `PATIENT_NAME`, `EMPLOYER_ROLE`."""

    @property
    def layer(self) -> str:
        """Which layer proposed it: `rules`, `ner` or `context`."""

    @property
    def detector(self) -> str:
        """Which detector instance proposed it, e.g. `rules`, `ner[0]`."""

    @property
    def confidence(self) -> float:
        """1.0 for checksum-valid, softmax for NER, model-reported for L3."""

    @property
    def checksum_validated(self) -> bool:
        """True when an arithmetic check actually passed on the covered bytes.

        The strongest statement available about a masked identifier: this one
        was not a model's opinion, and L4 is forbidden to demote it.
        """

    @property
    def byte_len(self) -> int:
        """Length of the covered range in BYTES."""

@final
class MappedSpan:
    """One span as it appears in both the original and the de-identified text."""

    @property
    def span(self) -> Span: ...
    @property
    def decision(self) -> str:
        """`"mask"` or `"keep"`."""

    @property
    def replacement(self) -> str | None:
        """The synthetic text substituted, when the decision was to mask."""

    @property
    def output_start(self) -> int:
        """Inclusive BYTE offset in the OUTPUT text.

        Masking changes byte lengths, so this cannot be derived from
        `span.start`. It is what makes the span map a round-trip table.
        """

    @property
    def output_end(self) -> int:
        """Exclusive BYTE offset in the OUTPUT text."""

@final
class AuditEntry:
    """One decision about one span.

    Carries no rationale. An L3 rationale is written by quoting the
    quasi-identifier it describes, so it is stripped before it reaches Python.
    """

    @property
    def layer(self) -> str: ...
    @property
    def label(self) -> str: ...
    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def confidence(self) -> float: ...
    @property
    def decision(self) -> str: ...

@final
class DeidResult:
    """The output of one de-identification run."""

    @property
    def text(self) -> str:
        """The de-identified document."""

    @property
    def span_map(self) -> list[MappedSpan]:
        """The round-trip table. Local, never logged, never transmitted."""

    @property
    def audit(self) -> list[AuditEntry]:
        """What was decided about each span, with no model free text attached."""

    @property
    def audit_is_redacted(self) -> bool:
        """Check this before persisting or transmitting an audit log."""

    @property
    def masked_count(self) -> int:
        """How many spans were masked rather than kept."""

    def reidentify(self) -> str:
        """Restore the original document from the de-identified one.

        The exact inverse, computed from the span map's OUTPUT offsets. It stays
        unambiguous when several spans share one replacement, which they all do
        until L5 lands and every `[TCKN]` in a note is the same string.
        """

@final
class Pipeline:
    """The de-identification pipeline.

    The tier is a required argument. There is no default, because both defaults
    are wrong in opposite directions: Safe Harbor by default hands an un-swept
    document to someone who wanted quasi-identifiers gone, and Expert
    Determination by default masks prose someone wanted readable.
    """

    def __init__(
        self,
        tier: Tier,
        *,
        local_model: Callable[[str], str] | None = ...,
        model_id: str = ...,
        backend: str = ...,
        quantization: str = ...,
        seed: int = ...,
        salt_key_material: bytes | None = ...,
        label_placeholders: bool = ...,
    ) -> None:
        """Build a pipeline at an explicitly chosen tier.

        `local_model` is required for `Tier.EXPERT_DETERMINATION` and rejected
        for `Tier.SAFE_HARBOR`. It receives the L3 prompt and must return the
        completion; it MUST run a local model, because the prompt contains the
        whole clinical note.

        The audited medical vocabulary (class C) and L5 surrogates are on by
        default; neither has to be asked for. The two optional arguments are
        the ways to change that, and both are explicit:

        `salt_key_material` supplies the L5 key instead of drawing a fresh one
        per document. Passing it makes surrogates consistent ACROSS documents,
        which preserves longitudinal linkage for a researcher and for an
        attacker alike -- take that decision deliberately.

        `label_placeholders=True` turns L5 off. Each identifier is then
        replaced by its label, so every patient in a note collapses onto
        `[PATIENT_NAME]` and the document stops reading as clinical prose.

        Raises:
            ContextualLayerMissingError: Expert Determination with no model.
            ValueError: a model was passed to Safe Harbor, where it would be
                ignored -- and a silently ignored model is an un-swept document;
                or `salt_key_material` was too short to be a key.
        """

    @classmethod
    def safe_harbor(cls) -> Pipeline:
        """The Safe Harbor tier, spelled out at the call site."""

    @classmethod
    def expert_determination(
        cls,
        local_model: Callable[[str], str],
        *,
        model_id: str = ...,
        backend: str = ...,
        quantization: str = ...,
        seed: int = ...,
    ) -> Pipeline:
        """The Expert Determination tier, spelled out at the call site."""

    @property
    def tier(self) -> Tier: ...
    def deidentify(self, doc: str) -> DeidResult:
        """De-identify a document, entirely on this device."""

def contextual_prompt(doc: str) -> str:
    """The exact prompt L3 sends, for a caller wiring their own local runtime.

    THE PROMPT CONTAINS THE WHOLE DOCUMENT. Anything that posts this string has
    uploaded the clinical note.
    """

def contextual_prompt_version() -> int:
    """The prompt format version, so a cached completion can be pinned to it."""

def all_spans_masked(result: DeidResult) -> bool:
    """True when every candidate span was masked rather than kept."""

class DeidError(Exception):
    """Base class for every error this library raises."""

class SpanError(DeidError):
    """A span was not a valid range over the document it was built against."""

class OffsetError(SpanError):
    """A byte offset was out of bounds or split a multi-byte character."""

class GuardrailError(DeidError):
    """L4 attempted something it is forbidden to do."""

class ProtectedSpanDemotionError(GuardrailError):
    """L4 tried to demote a checksum-validated or multi-detector span."""

class ConfigurationError(DeidError):
    """The pipeline was assembled in a way that cannot produce a correct result."""

class ContextualLayerMissingError(ConfigurationError):
    """Expert Determination was requested without a local model to sweep with."""

class ContextualModelError(DeidError):
    """The local L3 model failed or answered with something unusable."""

class MalformedContextualResponseError(ContextualModelError):
    """The local model's completion was not the requested JSON."""

class LocalModelFailedError(ContextualModelError):
    """The local model could not be run at all."""

class SchemaError(DeidError):
    """A label id did not match the committed entity schema."""
