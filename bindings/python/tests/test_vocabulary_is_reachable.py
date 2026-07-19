"""Does the SHIPPED wheel carry the audited medical vocabulary and L5?

The binding used to build ``core``'s ``Pipeline::new(tier)`` and nothing else,
so L4 consulted an EMPTY class C vocabulary and L5 was never installed. Every
collision test in ``core/`` passed against a vocabulary the wheel did not have,
which is why these tests go through ``deid_tr.Pipeline`` -- the only surface a
Python caller has -- and never touch an internal.

The candidate spans come from the L3 seam. That is not a convenience: it is the
only span source this binding actually has for a NAME. L1 has no name rule and
L2 ships with no weights, so a surname is never a candidate in the Safe Harbor
tier no matter what the allowlist contains. The local model here is a closure,
so the whole path runs with no weights file and no socket (I1).

Every fixture is synthetic (I8).
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from deid_tr import Pipeline, Tier

# The brief's canonical medical-register document. `Costa` appears once as a
# surname under a title and once, lower case and suffixed, as the Latin word
# for a rib. A rule that masks both passes half the test; a rule that keeps
# both passes the other half; only the context-sensitive resolution passes at
# once, on one document.
COSTA_NOTE = (
    "GÖĞÜS CERRAHİSİ KONSÜLTASYON NOTU\n"
    "Konsültan: Prof. Dr. Marco Costa\n"
    "\n"
    "Tetkikler: Toraks BT'de sol 5. costa'da deplase olmayan fraktür izlendi.\n"
    "Hasta carcinoma'lı değil; MRI'da ek patoloji yok.\n"
)

# What a LOCAL model returns for the L3 prompt: verbatim quotes, a category and
# a reason. `core` re-locates each quote in the document to derive byte offsets
# and drops anything it cannot find, so a fabricated quote costs recall and can
# never mask the wrong bytes.
BOTH_COSTAS = (
    '[{"quote": "Costa", "category": "RELATIONSHIP_REF", "reason": "named person"},'
    ' {"quote": "costa\'da", "category": "RELATIONSHIP_REF", "reason": "unclear"}]'
)


def canned_model(response: str) -> Callable[[str], str]:
    """A stand-in for the caller's LOCAL model: a closure, not a weights file."""

    def generate(prompt: str) -> str:
        assert COSTA_NOTE in prompt, "L3 must see the whole document"
        return response

    return generate


def valid_tckn() -> str:
    """A checksum-valid TCKN, computed rather than written down (I8)."""
    stem = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    odd = sum(stem[0::2])
    even = sum(stem[1::2])
    tenth = (odd * 7 + 100 - even) % 10
    eleventh = (sum(stem) + tenth) % 10
    return "".join(str(digit) for digit in [*stem, tenth, eleventh])


def expert(response: str) -> Pipeline:
    return Pipeline.expert_determination(
        canned_model(response),
        model_id="test-model",
        backend="cpu",
        quantization="q4_0",
        seed=7,
    )


def test_the_wheel_resolves_the_costa_collision_in_both_directions() -> None:
    result = expert(BOTH_COSTAS).deidentify(COSTA_NOTE)

    # The surname: masked. `costa` IS vocabulary, so the only thing that can
    # mask it is the surrounding evidence -- a title two tokens back and a
    # capitalised given name directly before.
    assert "Marco Costa" not in result.text
    # The rib: kept. Same surface form, no person evidence. With the empty
    # allowlist every previous release shipped, this line fails.
    assert "costa'da deplase" in result.text
    # And the rest of the clinical register is untouched, including the
    # code-switched forms that are the hardest boundary in the product.
    assert "carcinoma'lı" in result.text
    assert "MRI'da" in result.text
    assert result.reidentify() == COSTA_NOTE


def test_the_masked_output_is_a_surrogate_and_not_a_label_placeholder() -> None:
    tckn = valid_tckn()
    note = f"Hasta TCKN {tckn} ile kayıtlıdır."
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(note)

    assert "[TCKN]" not in result.text, "L5 is not installed by default"
    assert tckn not in result.text
    # Format-preserving: an 11-digit replacement, which is what keeps the
    # de-identified note parseable by a hospital system.
    replacement = re.search(r"(?<!\d)\d{11}(?!\d)", result.text)
    assert replacement is not None, result.text
    assert replacement.group() != tckn
    assert result.reidentify() == note


def test_the_same_identifier_twice_gets_one_consistent_surrogate() -> None:
    tckn = valid_tckn()
    note = f"TCKN {tckn} kayit acildi. Kontrolde TCKN {tckn} dogrulandi."
    result = Pipeline(Tier.SAFE_HARBOR).deidentify(note)

    surrogates = re.findall(r"(?<!\d)\d{11}(?!\d)", result.text)
    assert len(surrogates) == 2, result.text
    assert surrogates[0] == surrogates[1], "one patient became two"


def test_label_placeholders_is_an_opt_out_and_says_what_it_costs() -> None:
    tckn = valid_tckn()
    note = f"Hasta TCKN {tckn} ile kayıtlıdır."
    result = Pipeline(Tier.SAFE_HARBOR, label_placeholders=True).deidentify(note)
    assert "[TCKN]" in result.text


def test_supplied_key_material_makes_surrogates_consistent_across_documents() -> None:
    # The longitudinal-research case, taken as a decision rather than by
    # default: the same key across two calls links a patient's notes -- for a
    # researcher and for an attacker alike.
    tckn = valid_tckn()
    key = bytes(range(32))
    first = Pipeline(Tier.SAFE_HARBOR, salt_key_material=key).deidentify(
        f"Ilk not: TCKN {tckn}."
    )
    second = Pipeline(Tier.SAFE_HARBOR, salt_key_material=key).deidentify(
        f"Ikinci not: TCKN {tckn}."
    )
    assert re.findall(r"(?<!\d)\d{11}(?!\d)", first.text) == re.findall(
        r"(?<!\d)\d{11}(?!\d)", second.text
    )

    # And the default really is per-document: no shared key, no linkage.
    third = Pipeline(Tier.SAFE_HARBOR).deidentify(f"Ilk not: TCKN {tckn}.")
    assert re.findall(r"(?<!\d)\d{11}(?!\d)", third.text) != re.findall(
        r"(?<!\d)\d{11}(?!\d)", first.text
    )


def test_key_material_too_short_to_be_a_key_is_refused_at_construction() -> None:
    # A short salt is not a weak salt, it is a guessable one. Refusing at
    # construction means a mis-sized key is found when the pipeline is
    # configured, not halfway through a corpus.
    with pytest.raises(ValueError):
        Pipeline(Tier.SAFE_HARBOR, salt_key_material=b"tooshort")
