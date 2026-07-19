"""Mask and re-identify, end to end, through the compiled binding.

Every fixture here is synthetic. No TCKN is written into this file: I8 forbids a
checksum-valid national id anywhere in the repository and the pre-commit hook
scans for exactly that, so the valid one is COMPUTED at run time by
`valid_tckn()` below and exists only in the test process.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from deid_tr import (
    ContextualLayerMissingError,
    DeidError,
    DeidResult,
    Pipeline,
    Tier,
    all_spans_masked,
    contextual_prompt,
    contextual_prompt_version,
)

# The employer phrase is a quasi-identifier: no NER model tags "works at the
# Central Bank" as PHI, because it is not an entity, it is a meaning. Catching
# it is the whole reason the Expert Determination tier exists.
EMPLOYER = "Merkez Bankası"
QUASI_NOTE = f"Hasta {EMPLOYER}'nda çalışıyor."


def valid_tckn() -> str:
    """A checksum-valid TCKN, derived rather than written down.

    ``d10 = ((d1+d3+d5+d7+d9) * 7 - (d2+d4+d6+d8)) mod 10`` and
    ``d11 = sum(d1..d10) mod 10``, over a fixed nine-digit stem.
    """
    stem = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    odd = sum(stem[0::2])
    even = sum(stem[1::2])
    tenth = (odd * 7 + 100 - even) % 10
    eleventh = (sum(stem) + tenth) % 10
    return "".join(str(digit) for digit in [*stem, tenth, eleventh])


def direct_note() -> str:
    return f"Hasta Ayşe Yılmaz, TCKN {valid_tckn()}, tel 0(532) 000 00 00."


def canned_model(response: str) -> Callable[[str], str]:
    """A stand-in for the caller's LOCAL model.

    Local in the strictest possible sense: it is a closure, so the test suite
    proves the L3 path without a weights file and without a socket.
    """

    def generate(prompt: str) -> str:
        assert QUASI_NOTE in prompt, "L3 must see the whole document"
        return response

    return generate


# --- the tier is a decision, not a default ----------------------------------


def test_the_pipeline_cannot_be_built_without_naming_a_tier() -> None:
    """The API's central safety property, asserted rather than documented."""
    with pytest.raises(TypeError):
        Pipeline()  # type: ignore[call-arg]


def test_expert_determination_without_a_model_is_refused_at_construction() -> None:
    """It must fail LOUDLY. Degrading to Safe Harbor here would hand back an
    un-swept document that is indistinguishable from a swept one."""
    with pytest.raises(ContextualLayerMissingError):
        Pipeline(Tier.EXPERT_DETERMINATION)


def test_a_local_model_passed_to_safe_harbor_is_refused_rather_than_ignored() -> None:
    """A caller who passes a model believes their quasi-identifiers are being
    swept. Accepting and ignoring the argument lets them keep believing it."""
    with pytest.raises(ValueError, match="EXPERT_DETERMINATION"):
        Pipeline(Tier.SAFE_HARBOR, local_model=canned_model("[]"))


def test_the_named_constructors_agree_with_the_explicit_ones() -> None:
    assert Pipeline.safe_harbor().tier == Tier.SAFE_HARBOR
    expert = Pipeline.expert_determination(
        canned_model("[]"),
        model_id="test",
        backend="cpu",
        quantization="q4_0",
        seed=7,
    )
    assert expert.tier == Tier.EXPERT_DETERMINATION


# --- mask, then re-identify --------------------------------------------------


def test_safe_harbor_masks_a_checksum_valid_identifier() -> None:
    tckn = valid_tckn()
    # `label_placeholders=True` is asked for here because this test is about
    # WHICH spans were masked, and a label is the readable way to see that.
    # It is not the default: see
    # test_the_default_pipeline_produces_surrogates_and_not_labels.
    result = Pipeline(Tier.SAFE_HARBOR, label_placeholders=True).deidentify(
        direct_note()
    )
    assert tckn not in result.text
    assert "[TCKN]" in result.text
    assert "[PHONE]" in result.text
    masked = [entry for entry in result.span_map if entry.span.label == "TCKN"]
    assert len(masked) == 1
    assert masked[0].span.checksum_validated
    assert masked[0].span.layer == "rules"
    assert masked[0].decision == "mask"


def test_the_round_trip_restores_the_original_document_exactly() -> None:
    note = direct_note()
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(note)
    assert result.text != note, "nothing was masked, so nothing is proven"
    assert result.reidentify() == note


def test_the_round_trip_survives_multi_byte_turkish_offsets() -> None:
    """The failure this test exists to catch: a round trip built on character
    indices truncates at every `ş`, `ı` and `ğ` and lands inside a letter."""
    note = f"Ayşe Yılmaz'ın TCKN'si {valid_tckn()}, Şişli'de."
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(note)
    assert result.reidentify() == note
    raw = note.encode("utf-8")
    for entry in result.span_map:
        # Offsets are BYTE offsets, so they index the encoded form and must
        # decode cleanly -- a span that split a letter would raise here.
        raw[entry.span.start : entry.span.end].decode("utf-8")


def test_output_offsets_address_the_replacement_in_the_output_text() -> None:
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(direct_note())
    encoded = result.text.encode("utf-8")
    for entry in result.span_map:
        assert entry.replacement is not None
        window = encoded[entry.output_start : entry.output_end].decode("utf-8")
        assert window == entry.replacement


def test_a_document_with_nothing_to_mask_round_trips_unchanged() -> None:
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(QUASI_NOTE)
    assert result.text == QUASI_NOTE
    assert result.span_map == []
    assert result.reidentify() == QUASI_NOTE


# --- the contextual tier -----------------------------------------------------


def test_expert_determination_masks_a_quasi_identifier_and_round_trips() -> None:
    response = (
        '[{"quote": "Merkez Bankası", "category": "EMPLOYER_ROLE",'
        ' "reason": "employer"}]'
    )
    pipeline = Pipeline.expert_determination(
        canned_model(response),
        model_id="test-model",
        backend="cpu",
        quantization="q4_0",
        seed=7,
    )
    result = pipeline.deidentify(QUASI_NOTE)
    assert "[EMPLOYER_ROLE]" in result.text
    assert EMPLOYER not in result.text
    assert result.reidentify() == QUASI_NOTE
    assert all_spans_masked(result)


def test_a_hallucinated_quote_is_dropped_rather_than_masking_the_wrong_bytes() -> None:
    """A model that invents a quote costs recall. It must never be able to make
    the pipeline mask bytes the quote does not cover."""
    response = (
        '[{"quote": "Ziraat Bankası", "category": "EMPLOYER_ROLE",'
        ' "reason": "hallucinated"}]'
    )
    result = Pipeline.expert_determination(
        canned_model(response),
    ).deidentify(QUASI_NOTE)
    assert result.text == QUASI_NOTE
    assert result.span_map == []


def test_a_malformed_completion_raises_a_typed_error_without_quoting_itself() -> None:
    """I4 at the Python boundary. The model's completion quotes the document by
    design, so it must not reach a traceback a caller pastes into a bug report.
    """
    response = f'[{{"quote": "{EMPLOYER}", "category": "NOT_A_CATEGORY"}}]'
    pipeline = Pipeline.expert_determination(canned_model(response))
    with pytest.raises(DeidError) as caught:
        pipeline.deidentify(QUASI_NOTE)
    assert EMPLOYER not in str(caught.value)
    assert QUASI_NOTE not in str(caught.value)


def test_an_exception_from_the_callers_model_reaches_the_caller_unchanged() -> None:
    """Flattening it into a generic model failure would destroy the one piece of
    information the caller needs to fix their own runtime."""

    def broken(_prompt: str) -> str:
        raise TimeoutError("the local runtime did not answer")

    pipeline = Pipeline.expert_determination(broken)
    with pytest.raises(TimeoutError, match="did not answer"):
        pipeline.deidentify(QUASI_NOTE)


def test_the_contextual_prompt_is_available_for_a_caller_wiring_its_own_runtime() -> (
    None
):
    prompt = contextual_prompt(QUASI_NOTE)
    assert QUASI_NOTE in prompt
    assert contextual_prompt_version() >= 1


# --- what must never leave ---------------------------------------------------


def test_the_audit_log_handed_to_python_carries_no_rationale() -> None:
    response = (
        '[{"quote": "Merkez Bankası", "category": "EMPLOYER_ROLE",'
        f' "reason": "the patient works at {EMPLOYER}"}}]'
    )
    result = Pipeline.expert_determination(
        canned_model(response),
    ).deidentify(QUASI_NOTE)
    assert result.audit_is_redacted
    assert len(result.audit) == 1
    entry = result.audit[0]
    assert entry.layer == "context"
    assert entry.decision == "mask"
    # The rationale quoted the employer verbatim. Nothing on the Python object
    # may expose it, including through the repr of any part of the log.
    assert EMPLOYER not in repr(result.audit)


def test_repr_never_renders_the_document_or_the_masked_text() -> None:
    """`repr` reaches REPL transcripts, notebook checkpoints and `!r` inside
    somebody's log call. The object holds the original document, so rendering
    any text at all is how a checkpoint becomes a disclosure."""
    note = direct_note()
    result: DeidResult = Pipeline(Tier.SAFE_HARBOR).deidentify(note)
    rendered = repr(result)
    assert valid_tckn() not in rendered
    assert "Ayşe Yılmaz" not in rendered
    assert result.text not in rendered
    assert "DeidResult(" in rendered
    for entry in result.span_map:
        assert valid_tckn() not in repr(entry.span)


def test_a_span_offers_no_way_to_read_the_text_it_covers() -> None:
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(direct_note())
    span = result.span_map[0].span
    assert not any(
        name in dir(span) for name in ("text", "covered", "value", "surface")
    )
    assert span.byte_len == span.end - span.start


def test_importing_the_package_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """I1, checked rather than asserted.

    Every way of obtaining a connection is replaced by something that fails
    loudly, the package is re-imported from scratch, and a full
    de-identification is run. A licence check, a telemetry ping or a lazy weight
    download raises here instead of succeeding quietly on a hospital network.
    """
    import importlib
    import socket
    import sys

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the binding reached for the network")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in [module for module in sys.modules if module.startswith("deid_tr")]:
        monkeypatch.delitem(sys.modules, name)

    module = importlib.import_module("deid_tr")
    result = module.Pipeline(
        module.Tier.SAFE_HARBOR, label_placeholders=True
    ).deidentify(direct_note())
    assert "[TCKN]" in result.text
    assert result.reidentify() == direct_note()
