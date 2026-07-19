"""One focused test per attack class: it fires on its condition, and only on it.

Every attack gets both directions. Firing on the failure is half a red team;
the other half is not firing on the defence, because an attack that always fires
carries no information and an attack that never fires is worse.
"""

from __future__ import annotations

import pytest

from eval.redteam.cross_doc_linkage import CrossDocLinkageAttack
from eval.redteam.format_tells import FormatTellsAttack, tckn_checksum_valid
from eval.redteam.indirect_reference import IndirectReferenceAttack
from eval.redteam.narrative_survival import NarrativeSurvivalAttack
from eval.redteam.quasi_combination import QuasiCombinationAttack
from eval.redteam.rare_value_survival import RareValueSurvivalAttack
from eval.redteam.structural_leakage import StructuralLeakageAttack
from eval.redteam.model import DeidDocument
from eval.redteam.tests._support import deid, gold_document, valid_tckn
from eval.schema import Schema, load_schema


@pytest.fixture(scope="module")
def schema() -> Schema:
    return load_schema()


# ---------------------------------------------------------------------------
# 1. quasi-identifier combination
# ---------------------------------------------------------------------------


def test_quasi_combination_flags_a_cell_of_size_one(schema: Schema) -> None:
    from eval.allowlist import load_allowlist

    allowlist = load_allowlist(schema)
    shared = (
        "Hasta 2019 yılında başvurdu. Kontrol planlandı ve taburcu edildi. "
        "Genel durum stabil seyretti."
    )
    unique = (
        "Hasta 2019 yılında Ankara Şehir Hastanesi kliniğine başvurdu. "
        "Mesothelioma tanısı kondu ve tedavi planlandı."
    )
    corpus = [
        deid(
            gold_document(
                "d1", unique, spans=[("Ankara Şehir Hastanesi", "FACILITY_NAME")]
            )
        ),
        deid(gold_document("d2", shared)),
        deid(gold_document("d3", shared.replace("2019", "2021"))),
    ]
    result = QuasiCombinationAttack(allowlist).run(corpus, schema)
    assert result.succeeded
    assert result.documents_hit == {"d1"}
    assert result.stats["cells_of_size_1"] == 1


def test_quasi_combination_holds_when_the_facility_is_masked(schema: Schema) -> None:
    from eval.allowlist import load_allowlist

    text = (
        "Hasta 2019 yılında Ankara Şehir Hastanesi kliniğine başvurdu. "
        "Mesothelioma tanısı kondu ve tedavi planlandı."
    )
    document = gold_document(
        "d1",
        text,
        spans=[("Ankara Şehir Hastanesi", "FACILITY_NAME"), ("2019", "DATE_ADMISSION")],
    )
    masked = deid(
        document,
        mapped=[
            ("Ankara Şehir Hastanesi", "FACILITY_NAME", "[FACILITY-9ac]"),
            ("2019", "DATE_ADMISSION", "[DATE-41f]"),
        ],
    )
    result = QuasiCombinationAttack(load_allowlist(schema)).run([masked], schema)
    # Only the un-maskable rare diagnosis survives, and one component is not a
    # combination.
    assert not result.succeeded


# ---------------------------------------------------------------------------
# 2. narrative survival
# ---------------------------------------------------------------------------


_EMPLOYMENT = "Merkez Bankası'nda kıdemli ekonomist olarak çalışıyor"


def test_narrative_survival_flags_an_unmasked_quasi_span(schema: Schema) -> None:
    text = f"Anamnez: {_EMPLOYMENT}. Şikayeti iki aydır sürüyor."
    corpus = [deid(gold_document("d1", text, quasi=[(_EMPLOYMENT, "EMPLOYER_ROLE")]))]
    result = NarrativeSurvivalAttack().run(corpus, schema)
    assert result.succeeded
    assert result.stats["quasi_span_survival_rate"] == 1.0
    assert result.findings[0].label == "EMPLOYER_ROLE"


def test_narrative_survival_holds_when_the_quasi_span_is_masked(
    schema: Schema,
) -> None:
    text = f"Anamnez: {_EMPLOYMENT}. Şikayeti iki aydır sürüyor."
    document = gold_document("d1", text, quasi=[(_EMPLOYMENT, "EMPLOYER_ROLE")])
    corpus = [deid(document, mapped=[(_EMPLOYMENT, "EMPLOYER_ROLE", "[EMPLOYER-3b1]")])]
    result = NarrativeSurvivalAttack().run(corpus, schema)
    assert not result.succeeded
    assert result.stats["quasi_span_survival_rate"] == 0.0


def test_narrative_survival_counts_a_sliver_of_coverage_as_survival(
    schema: Schema,
) -> None:
    """Masking the name inside the phrase does not neutralise the phrase."""
    text = f"Anamnez: {_EMPLOYMENT}. Şikayeti iki aydır sürüyor."
    document = gold_document("d1", text, quasi=[(_EMPLOYMENT, "EMPLOYER_ROLE")])
    corpus = [deid(document, mapped=[("ekonomist", "PATIENT_NAME", "[NAME-77]")])]
    assert NarrativeSurvivalAttack().run(corpus, schema).succeeded


# ---------------------------------------------------------------------------
# 3. structural leakage
# ---------------------------------------------------------------------------


def _shape_corpus(
    surrogate_for: dict[str, str],
) -> list[DeidDocument]:
    names = [
        "Ali Kaya",
        "Zeynep Aydınlıoğlu",
        "Mehmet Can",
        "Elif Şahinkaya",
        "Burak Ozan",
        "Nur Yıldırımlar",
        "Cem Ak",
        "Deniz Karaosmanoğlu",
        "Ece Tan",
        "Ferit Gülbahar",
    ]
    corpus: list[DeidDocument] = []
    for index, name in enumerate(names):
        text = f"Hasta Adı: {name}\nKontrol planlandı."
        document = gold_document(f"d{index}", text, spans=[(name, "PATIENT_NAME")])
        corpus.append(
            deid(
                document,
                mapped=[(name, "PATIENT_NAME", surrogate_for[name])],
                salt=f"salt-{index}",
            )
        )
    return corpus


def test_structural_leakage_flags_length_preserving_surrogates(
    schema: Schema,
) -> None:
    corpus = _shape_corpus({name: "X" * len(name) for name in _NAMES})
    result = StructuralLeakageAttack().run(corpus, schema)
    assert result.succeeded
    assert result.stats["length_leaks"] is True
    assert result.stats["length_correlation_r"] == pytest.approx(1.0)


def test_structural_leakage_holds_on_decorrelated_surrogates(schema: Schema) -> None:
    # Lengths chosen from the index, not from the original, so no channel exists.
    surrogates = {
        name: "[NAME-" + "z" * (index % 4 + 2) + "]"
        for index, name in enumerate(_NAMES)
    }
    result = StructuralLeakageAttack().run(_shape_corpus(surrogates), schema)
    assert not result.succeeded
    assert result.stats["length_leaks"] is False


_NAMES = [
    "Ali Kaya",
    "Zeynep Aydınlıoğlu",
    "Mehmet Can",
    "Elif Şahinkaya",
    "Burak Ozan",
    "Nur Yıldırımlar",
    "Cem Ak",
    "Deniz Karaosmanoğlu",
    "Ece Tan",
    "Ferit Gülbahar",
]


# ---------------------------------------------------------------------------
# 4. cross-document linkage
# ---------------------------------------------------------------------------


def test_cross_doc_linkage_flags_a_surrogate_reused_for_one_patient(
    schema: Schema,
) -> None:
    corpus = []
    for index in (1, 2):
        text = f"Hasta Adı: Selin Bora\nVizit {index}."
        document = gold_document(
            f"d{index}", text, spans=[("Selin Bora", "PATIENT_NAME")]
        )
        corpus.append(
            deid(
                document,
                mapped=[("Selin Bora", "PATIENT_NAME", "[NAME-fixed]")],
                salt="one-global-salt",
                patient_key="patient-a",
            )
        )
    result = CrossDocLinkageAttack().run(corpus, schema)
    assert result.succeeded
    assert result.documents_hit == {"d1", "d2"}
    assert result.stats["surrogates_reused_across_documents"] == 1


def test_cross_doc_linkage_does_not_count_a_collision_as_a_link(
    schema: Schema,
) -> None:
    """The same surrogate for two DIFFERENT patients identifies nobody."""
    corpus = []
    for index, patient in ((1, "patient-a"), (2, "patient-b")):
        text = f"Hasta Adı: Selin Bora\nVizit {index}."
        document = gold_document(
            f"d{index}", text, spans=[("Selin Bora", "PATIENT_NAME")]
        )
        corpus.append(
            deid(
                document,
                mapped=[("Selin Bora", "PATIENT_NAME", "[NAME-fixed]")],
                salt=f"salt-{index}",
                patient_key=patient,
            )
        )
    result = CrossDocLinkageAttack().run(corpus, schema)
    assert not result.succeeded
    assert result.stats["collisions_not_counted_as_findings"] == 1


def test_cross_doc_linkage_flags_a_salt_shared_between_patients(
    schema: Schema,
) -> None:
    corpus = []
    for index, patient in ((1, "patient-a"), (2, "patient-b")):
        text = f"Hasta Adı: Selin Bora\nVizit {index}."
        document = gold_document(
            f"d{index}", text, spans=[("Selin Bora", "PATIENT_NAME")]
        )
        corpus.append(
            deid(
                document,
                mapped=[("Selin Bora", "PATIENT_NAME", f"[NAME-{index}]")],
                salt="one-global-salt",
                patient_key=patient,
            )
        )
    result = CrossDocLinkageAttack().run(corpus, schema)
    assert result.succeeded
    assert result.stats["salts_covering_multiple_patients"] == 1


# ---------------------------------------------------------------------------
# 5. rare-value survival
# ---------------------------------------------------------------------------


def _name_corpus(mask_rare: bool, mask_common: bool) -> list[DeidDocument]:
    corpus = []
    # `Yılmaz` recurs, so it is common; each `Kuzucuoğlu`-style surname is unique.
    for index in range(6):
        text = f"Hasta Adı: Ayşe Yılmaz\nProtokol {index}."
        document = gold_document(
            f"c{index}", text, spans=[("Ayşe Yılmaz", "PATIENT_NAME")]
        )
        mapped = [("Ayşe Yılmaz", "PATIENT_NAME", "[NAME-a]")] if mask_common else None
        corpus.append(deid(document, mapped=mapped))
    for index, surname in enumerate(("Zorbeyoğulları", "Kuzucuoğlu", "Hepgüler")):
        name = f"Bora {surname}"
        text = f"Hasta Adı: {name}\nProtokol r{index}."
        document = gold_document(f"r{index}", text, spans=[(name, "PATIENT_NAME")])
        mapped = [(name, "PATIENT_NAME", "[NAME-b]")] if mask_rare else None
        corpus.append(deid(document, mapped=mapped))
    return corpus


def test_rare_value_survival_flags_a_surviving_rare_name(schema: Schema) -> None:
    result = RareValueSurvivalAttack().run(
        _name_corpus(mask_rare=False, mask_common=True), schema
    )
    assert result.succeeded
    assert result.stats["recall_gradient_inverted"] is True
    assert result.stats["buckets"]["rare"]["recall"] == 0.0
    assert result.stats["buckets"]["common"]["recall"] == 1.0


def test_rare_value_survival_holds_when_rare_names_are_masked(
    schema: Schema,
) -> None:
    result = RareValueSurvivalAttack().run(
        _name_corpus(mask_rare=True, mask_common=True), schema
    )
    assert not result.succeeded
    assert result.stats["recall_gradient_inverted"] is False


def test_rare_value_survival_never_quotes_the_rare_name(schema: Schema) -> None:
    """I4: the pattern is exportable, the instance never is."""
    result = RareValueSurvivalAttack().run(
        _name_corpus(mask_rare=False, mask_common=True), schema
    )
    assert all(finding.anchor is None for finding in result.findings)


# ---------------------------------------------------------------------------
# 6. format tells
# ---------------------------------------------------------------------------


def test_tckn_checksum_matches_the_specified_algorithm() -> None:
    built = valid_tckn("102030405")
    assert tckn_checksum_valid(built)
    # Perturbing one digit must break it, or the checksum is not doing any work.
    broken = built[:5] + str((int(built[5]) + 1) % 10) + built[6:]
    assert not tckn_checksum_valid(broken)
    assert not tckn_checksum_valid("0" + built[1:])


def test_format_tells_flags_an_unmasked_checksum_valid_tckn(schema: Schema) -> None:
    tckn = valid_tckn("246813579")
    text = f"TC Kimlik No: {tckn}\nKontrol planlandı."
    corpus = [deid(gold_document("d1", text))]
    result = FormatTellsAttack().run(corpus, schema)
    assert result.succeeded
    assert result.stats["unmasked_checksum_valid_tckns"] == 1


def test_format_tells_flags_digit_retention(schema: Schema) -> None:
    # Built at runtime, never written as a literal. The previous revision hardcoded a
    # checksum-VALID TCKN here and the pre-commit hook (I8) rejected the commit, which
    # is the hook doing its job: a checksum-valid national ID in a source file could
    # belong to a real person, and "it is obviously synthetic" is a judgement the repo
    # must not rely on a reader to make.
    original = valid_tckn("111111111")
    # The surrogate deliberately retains the original's leading digits -- that shared
    # prefix is the structural tell this attack exists to catch.
    surrogate = original[:3] + "22334455"
    text = f"TC Kimlik No: {original}\nKontrol planlandı."
    document = gold_document("d1", text, spans=[(original, "TCKN")])
    corpus = [deid(document, mapped=[(original, "TCKN", surrogate)])]
    result = FormatTellsAttack().run(corpus, schema)
    assert result.succeeded
    assert result.stats["tells"]["digit_retention"] == 1


def test_format_tells_flags_a_weekday_preserving_date_shift(schema: Schema) -> None:
    text = "Yatış tarihi 04.05.2026 olarak kaydedildi."
    document = gold_document("d1", text, spans=[("04.05.2026", "DATE_ADMISSION")])
    corpus = [deid(document, mapped=[("04.05.2026", "DATE_ADMISSION", "18.05.2026")])]
    result = FormatTellsAttack().run(corpus, schema)
    assert result.succeeded
    assert result.stats["tells"]["weekday_preserved"] == 1


def test_format_tells_flags_a_preserved_iban_bank_code(schema: Schema) -> None:
    original = "TR330006100519786457841326"
    surrogate = "TR330006100519786457841777"
    text = f"IBAN {original} kaydedildi."
    document = gold_document("d1", text, spans=[(original, "IBAN")])
    corpus = [deid(document, mapped=[(original, "IBAN", surrogate)])]
    result = FormatTellsAttack().run(corpus, schema)
    assert result.stats["tells"]["bank_code_preserved"] == 1


def test_format_tells_holds_on_an_opaque_surrogate(schema: Schema) -> None:
    text = "Yatış tarihi 04.05.2026 olarak kaydedildi."
    document = gold_document("d1", text, spans=[("04.05.2026", "DATE_ADMISSION")])
    corpus = [deid(document, mapped=[("04.05.2026", "DATE_ADMISSION", "[DATE-9f2]")])]
    assert not FormatTellsAttack().run(corpus, schema).succeeded


# ---------------------------------------------------------------------------
# 7. indirect reference
# ---------------------------------------------------------------------------


_INDIRECT = "aynı hastanenin başhemşiresi olan gelini"


def test_indirect_reference_flags_a_surviving_relational_phrase(
    schema: Schema,
) -> None:
    text = f"Plan: bakımın büyük kısmını {_INDIRECT} üstlenecek."
    corpus = [deid(gold_document("d1", text))]
    result = IndirectReferenceAttack().run(corpus, schema)
    assert result.succeeded
    assert result.findings[0].label == "RELATIONSHIP_REF"


def test_indirect_reference_holds_when_the_phrase_is_masked(schema: Schema) -> None:
    text = f"Plan: bakımın büyük kısmını {_INDIRECT} üstlenecek."
    document = gold_document("d1", text, quasi=[(_INDIRECT, "RELATIONSHIP_REF")])
    corpus = [deid(document, mapped=[(_INDIRECT, "RELATIONSHIP_REF", "[REL-1a]")])]
    result = IndirectReferenceAttack().run(corpus, schema)
    assert not result.succeeded
    assert result.stats["documents_with_an_indirect_reference"] == 1


def test_indirect_reference_needs_both_halves(schema: Schema) -> None:
    """A kinship term alone is not identifying; neither is a role alone."""
    kinship_only = deid(gold_document("d1", "Hastanın kızı refakat etti."))
    role_only = deid(gold_document("d2", "Serviste bir hemşire görev yaptı."))
    assert (
        not IndirectReferenceAttack().run([kinship_only, role_only], schema).succeeded
    )
