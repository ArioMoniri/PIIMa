"""deid-tr -- on-device de-identification of Turkish clinical text.

The tier is a required argument::

    from deid_tr import Pipeline, Tier

    result = Pipeline(Tier.SAFE_HARBOR).deidentify(note)
    assert result.reidentify() == note

There is no default tier and there will not be one. Defaulting to Safe Harbor
hands an un-swept document to a caller who wanted quasi-identifiers gone, and
the output is indistinguishable from one that was swept. Defaulting to Expert
Determination masks narrative prose for a caller who wanted a readable note.
Both failures are silent, so the choice is made a required argument instead.

Importing this package opens no socket, contacts no registry and downloads no
weights, now or at first inference (I1). The L3 contextual model is a callable
the caller supplies, and it must be local: the prompt contains the entire
clinical note, so handing it to a hosted API is a disclosure with extra steps.
"""

from ._deid_tr import (
    AuditEntry,
    ConfigurationError,
    ContextualLayerMissingError,
    ContextualModelError,
    DeidError,
    DeidResult,
    GuardrailError,
    LocalModelFailedError,
    MalformedContextualResponseError,
    MappedSpan,
    OffsetError,
    Pipeline,
    ProtectedSpanDemotionError,
    SchemaError,
    Span,
    SpanError,
    Tier,
    __version__,
    all_spans_masked,
    contextual_prompt,
    contextual_prompt_version,
)

# Listed explicitly so the re-export is one `mypy --strict` accepts, and so the
# public surface is a decision recorded in a file rather than whatever happens
# to be importable from the extension.
__all__ = [
    "AuditEntry",
    "ConfigurationError",
    "ContextualLayerMissingError",
    "ContextualModelError",
    "DeidError",
    "DeidResult",
    "GuardrailError",
    "LocalModelFailedError",
    "MalformedContextualResponseError",
    "MappedSpan",
    "OffsetError",
    "Pipeline",
    "ProtectedSpanDemotionError",
    "SchemaError",
    "Span",
    "SpanError",
    "Tier",
    "__version__",
    "all_spans_masked",
    "contextual_prompt",
    "contextual_prompt_version",
]
