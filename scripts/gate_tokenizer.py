"""I6, the backbone/language gate: a tokenizer that cannot carry the language
does not ship a model for that language.

    python3 scripts/gate_tokenizer.py dbmdz/bert-base-turkish-cased
    python3 scripts/gate_tokenizer.py --local-only ./vendor/berturk
    python3 scripts/gate_tokenizer.py --self-test

Two independent conditions must hold before a backbone may be published for a
language set, and either one alone rejects it.

  1. CASING. No `*-uncased` backbone ships for Turkish, ever. Casing is the
     strongest single signal a name detector has, and Turkish lowercasing is
     not a case fold but a corruption: `I` -> `i` merges the dotless and dotted
     letters, `Istanbul` -> `i-dot-above + stanbul` invents a combining mark.
     This rule has no override and is checked before anything is loaded, so a
     rejected backbone is never even downloaded.

  2. ROUND-TRIP. The tokenizer must reproduce the probe corpus below, and its
     reported offsets must re-anchor onto correct UTF-8 BYTE offsets in the
     original string. Offsets are the project's number one correctness trap:
     every layer speaks byte offsets, Turkish letters are multi-byte, and a
     tokenizer whose offsets are off by a byte produces spans that leak a
     suffix or clip a name.

DECODE COMPARISON, and the one narrowing in it. `decode(encode(s)) == s` is the
literal statement of losslessness, but a WordPiece decoder is a pretty-printer:
it re-inserts spaces around punctuation, so `Ayse'ye` decodes to `Ayse ' ye` on
a backbone that has not lost a single character. Rejecting on that would reject
every WordPiece backbone including the Turkish-native ones, which would make
the gate something people route around instead of something they pass. The
default comparison therefore ignores WHITESPACE ONLY, and is paired with an
exact ordered comparison of every non-whitespace character. A dropped diacritic,
a corrupted dotted-i, a normalisation form change or a substituted character all
still fail. `--strict-decode` demands byte-exact decode output for backbones
whose decoder is expected to be exact.

NETWORK EXCEPTION, and why it does not weaken I1. I1 says PHI never leaves the
device: `core/` has no network dependency, no lazy model download exists at
inference, and the test suite passes with networking disabled. This script is
not on that path. It is a PUBLISH-TIME gate run by a maintainer against a
public backbone id with no patient text anywhere in the process, and resolving
a hub id necessarily downloads a tokenizer. The exception is bounded by three
structural rules:

  - Nothing under `core/` or `eval/harness.py` may import this module. The
    network-touching loader additionally refuses to run unless `main()` armed
    it, so an accidental import cannot reach the network even by calling in.
  - `--local-only` reads a tokenizer directory from disk and touches nothing,
    which is the air-gapped and CI path.
  - The script announces the exception loudly on stderr before it fetches.

When the tokenizer libraries are absent the script exits 2 with an actionable
message. It never installs anything.
"""

from __future__ import annotations

import argparse
import importlib
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Final

EXIT_OK: Final[int] = 0
EXIT_GATE_FAILED: Final[int] = 1
EXIT_USAGE: Final[int] = 2


class GateError(Exception):
    """Raised when the gate cannot run at all, as opposed to failing a check."""


@dataclass(frozen=True)
class ProbeGroup:
    """One family of probe strings plus the failure it exists to catch."""

    name: str
    why: str
    probes: tuple[str, ...]


# The probe corpus. Every group here corresponds to a documented way a
# tokenizer silently destroys Turkish clinical text; a backbone that survives
# all of them can carry the language, and one that does not, cannot.
PROBE_CORPUS: Final[tuple[ProbeGroup, ...]] = (
    ProbeGroup(
        name="name_morphology",
        # Turkish is agglutinative and attaches case suffixes to proper names
        # across an apostrophe. English subword vocabularies fragment these,
        # the span boundary lands inside the suffix, and `'nin` leaks next to a
        # masked name. Transliterated spellings appear because Turkish records
        # contain both `Sukru` and the diacritic form.
        why="case suffixes attached to proper names across an apostrophe",
        probes=(
            "Ayşe'ye",
            "Ayşe'nin",
            "Yılmaz'ın",
            "Gökçe'den",
            "Şükrü Bey'in",
            "Ayse'ye",
            "Ayse'nin",
            "Yilmaz'in",
            "Gokce'den",
            "Sukru Bey'in",
        ),
    ),
    ProbeGroup(
        name="dotted_dotless_i",
        # I, i, İ and ı are four distinct letters. A naive lowercase maps İ to
        # `i` plus a combining dot above and I to `i`, merging two letters and
        # changing the byte length of the string. Names and place names are
        # where this does the damage.
        why="dotted and dotless i are four distinct letters, not two cases",
        probes=(
            "İREM",
            "Irmak",
            "İlhan",
            "IŞIL",
            "İsmail",
            "İSTANBUL",
            "Işık",
            "IREM",
            "Ilhan",
            "ISIL",
            "Ismail",
            "ISTANBUL",
            "Isik",
        ),
    ),
    ProbeGroup(
        name="code_switched_medical",
        # A Latin or English medical root carrying a Turkish suffix is exactly
        # where a token classifier confuses a drug or diagnosis with a person.
        # If the tokenizer cannot even reproduce the surface form, the layer
        # that must tell `Adalat` from `Adalet` never gets a fair chance.
        why="Latin/English medical roots carrying Turkish suffixes",
        probes=(
            "carcinoma'lı",
            "carcinoma'li",
            "MRI'da",
            "PET-CT'de",
            "metformin'e",
            "sepsis'ten",
            "pneumonia'nın",
            "pneumonia'nin",
            "EKG'si",
            "Hodgkin'li",
            "hipertansiyon'u",
            "stent'in",
        ),
    ),
    ProbeGroup(
        name="vowel_harmony",
        # The same suffix surfaces four ways depending on the preceding vowel.
        # Anything that hardcodes one variant misses the other three, so all
        # four surfaces of the locative and of -lI are probed on real clinical
        # roots.
        why="one suffix, four surface forms driven by vowel harmony",
        probes=(
            "böbrekte",
            "kolda",
            "ciltte",
            "ayakta",
            "gözde",
            "idrarda",
            "serviste",
            "yüzde",
            "belirtili",
            "ağrılı",
            "huzurlu",
            "öksürüklü",
            "MR'de",
            "MRI'da",
            "EKG'de",
            "PET-CT'de",
        ),
    ),
    ProbeGroup(
        name="mixed_script_clinical",
        # Whole sentences, because a tokenizer can pass on isolated words and
        # still break where Turkish grammar meets Latin/English terminology in
        # running text. Every name, date and number here is fabricated, and the
        # national-ID-shaped number is deliberately checksum-invalid so the I8
        # pre-commit hook never has to reject the gate's own fixtures.
        why="Turkish grammar and Latin/English terminology in running prose",
        probes=(
            "Hasta Ayşe Yılmaz'ın PET-CT'de saptanan pulmoner nodülü için "
            "toraks BT planlandı.",
            "Şükrü Bey'in hipertansiyon'u nedeniyle metformin'e ek olarak "
            "ACE inhibitörü başlandı.",
            "Gökçe Hanım'ın MRI'da izlenen lezyonu carcinoma'lı olarak "
            "raporlandı, Op. Dr. İlhan Işık değerlendirdi.",
            "Hastanın 12345678900'in kayıtlı olduğu dosyada sepsis'ten "
            "taburculuk notu bulunmaktadır.",
            "Uz. Dr. İrem Öztürk, EKG'si normal sınırlarda olan hastayı "
            "Kadıköy'deki polikliniğe yönlendirdi.",
        ),
    ),
    ProbeGroup(
        name="turkish_characters",
        # The six Turkish-specific letters and their capitals, each in every
        # position the orthography allows, plus the bare letters for the two
        # that cannot start a word. A vocabulary missing one of these does not
        # fail loudly; it emits an unknown token and the offsets around it move.
        why="Turkish-specific letters in initial, medial and final position",
        probes=(
            "çocuk",
            "içerik",
            "amaç",
            "ÇOCUK",
            "SAÇAK",
            "AMAÇ",
            "sağlık",
            "dağ",
            "ğ",
            "Ğ",
            "ılık",
            "kırık",
            "sarı",
            "ILIK",
            "KIRIK",
            "SARI",
            "ödem",
            "böbrek",
            "bordö",
            "ÖDEM",
            "BÖBREK",
            "BORDÖ",
            "şeker",
            "başak",
            "gümüş",
            "ŞEKER",
            "BAŞAK",
            "GÜMÜŞ",
            "üre",
            "gübre",
            "ütü",
            "ÜRE",
            "GÜBRE",
            "ÜTÜ",
            "İdrar",
            "İSTANBUL",
            "Iğdır",
        ),
    ),
)


@dataclass(frozen=True)
class Encoding:
    """What the gate needs from a tokenizer: ids plus reported offsets.

    Offsets are CHARACTER offsets into the input string, which is what both the
    `tokenizers` Python binding and `transformers` fast tokenizers report. The
    gate's whole job on them is to prove they convert to correct byte offsets.
    """

    ids: tuple[int, ...]
    offsets: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class ProbeFailure:
    """One probe failing one check."""

    group: str
    probe: str
    kind: str
    detail: str


@dataclass(frozen=True)
class GateReport:
    """The verdict for one backbone."""

    model_id: str
    languages: tuple[str, ...]
    probes_checked: int
    failures: tuple[ProbeFailure, ...]

    @property
    def passed(self) -> bool:
        return not self.failures


class _StubTokenizer:
    """Base for the self-test tokenizers. Not used against real backbones."""

    def encode(self, text: str) -> Encoding:
        raise NotImplementedError

    def decode(self, ids: Sequence[int]) -> str:
        raise NotImplementedError


def casing_violation(model_id: str, languages: Sequence[str]) -> str | None:
    """Return the rejection message when an uncased backbone meets Turkish.

    Checked on the identifier alone, before any load, because the point is to
    refuse the backbone rather than to evaluate it.
    """
    if "tr" not in {language.lower() for language in languages}:
        return None
    haystack = model_id.replace("\\", "/").lower()
    if "-uncased" not in haystack:
        return None
    return (
        f"{model_id}: uncased backbone rejected for Turkish. Casing is the "
        "strongest name signal a detector has, and Turkish lowercasing is not a "
        "case fold: I and dotted-I collapse onto i, dotted-I gains a combining "
        "mark, and the dotless i disappears. An uncased vocabulary cannot "
        "represent Turkish names. This rule has no override."
    )


def _significant(text: str) -> str:
    """The text with whitespace removed - the part decode may never alter."""
    return "".join(character for character in text if not character.isspace())


def _normalisation_hint(expected: str, actual: str) -> str:
    """Name the Unicode normalisation form when that is the whole difference."""
    for form in ("NFC", "NFD", "NFKC", "NFKD"):
        if unicodedata.normalize(form, expected) == actual:
            return (
                f" The decoded text is the {form} normalisation of the input; "
                "the tokenizer changed the normalisation form, which changes "
                "the byte length and therefore every downstream offset."
            )
    return ""


def check_decode(
    tokenizer: Any, probe: str, group: str, *, strict_decode: bool
) -> list[ProbeFailure]:
    """Assert decode(encode(probe)) reproduces the probe."""
    encoding = tokenizer.encode(probe)
    decoded = tokenizer.decode(encoding.ids)
    if not isinstance(decoded, str):
        return [
            ProbeFailure(
                group=group,
                probe=probe,
                kind="decode_type",
                detail=f"decode returned {type(decoded).__name__}, expected str",
            )
        ]

    if strict_decode:
        if decoded == probe:
            return []
        return [
            ProbeFailure(
                group=group,
                probe=probe,
                kind="roundtrip_strict",
                detail=(
                    f"decode(encode(s)) != s under --strict-decode: "
                    f"got {decoded!r}" + _normalisation_hint(probe, decoded)
                ),
            )
        ]

    expected = _significant(probe)
    observed = _significant(decoded)
    if observed == expected:
        return []
    return [
        ProbeFailure(
            group=group,
            probe=probe,
            kind="roundtrip",
            detail=(
                "decode(encode(s)) lost or altered a non-whitespace character: "
                f"expected {expected!r}, got {observed!r} (full decode: "
                f"{decoded!r})" + _normalisation_hint(probe, decoded)
            ),
        )
    ]


def check_offsets(tokenizer: Any, probe: str, group: str) -> list[ProbeFailure]:
    """Assert reported offsets re-anchor onto correct UTF-8 byte offsets.

    Every layer of the pipeline consumes byte offsets into the original text,
    so a character offset that converts to a byte offset landing mid-character,
    running past the end, or skipping content is a span bug waiting to leak a
    suffix.
    """
    encoding = tokenizer.encode(probe)
    encoded_bytes = probe.encode("utf-8")
    failures: list[ProbeFailure] = []
    covered: list[str] = []
    previous_end = 0

    for index, (char_start, char_end) in enumerate(encoding.offsets):
        # (0, 0) is how both libraries mark a special token that covers no
        # source text; it is not a drift, so it is skipped rather than failed.
        if char_start == 0 and char_end == 0:
            continue
        if not 0 <= char_start <= char_end <= len(probe):
            failures.append(
                ProbeFailure(
                    group=group,
                    probe=probe,
                    kind="offset_range",
                    detail=(
                        f"token {index} reports offsets ({char_start}, "
                        f"{char_end}) outside the input, which is "
                        f"{len(probe)} characters and "
                        f"{len(encoded_bytes)} bytes; a tokenizer reporting "
                        "byte offsets where character offsets are expected "
                        "fails exactly this way on multi-byte Turkish letters"
                    ),
                )
            )
            continue
        if char_start < previous_end:
            failures.append(
                ProbeFailure(
                    group=group,
                    probe=probe,
                    kind="offset_order",
                    detail=(
                        f"token {index} starts at {char_start}, before the "
                        f"previous token ended at {previous_end}; overlapping "
                        "offsets cannot be merged into a span map"
                    ),
                )
            )
        previous_end = max(previous_end, char_end)

        byte_start = len(probe[:char_start].encode("utf-8"))
        byte_end = len(probe[:char_end].encode("utf-8"))
        slice_text = encoded_bytes[byte_start:byte_end]
        try:
            decoded_slice = slice_text.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(
                ProbeFailure(
                    group=group,
                    probe=probe,
                    kind="offset_boundary",
                    detail=(
                        f"token {index} maps to bytes [{byte_start}, "
                        f"{byte_end}) which do not decode as UTF-8; the offset "
                        "lands inside a character"
                    ),
                )
            )
            continue
        if decoded_slice != probe[char_start:char_end]:
            failures.append(
                ProbeFailure(
                    group=group,
                    probe=probe,
                    kind="offset_anchor",
                    detail=(
                        f"token {index} re-anchored to bytes [{byte_start}, "
                        f"{byte_end}) yielding {decoded_slice!r}, expected "
                        f"{probe[char_start:char_end]!r}"
                    ),
                )
            )
            continue
        covered.append(decoded_slice)

    reconstructed = _significant("".join(covered))
    if reconstructed != _significant(probe):
        failures.append(
            ProbeFailure(
                group=group,
                probe=probe,
                kind="offset_coverage",
                detail=(
                    "the offset map does not cover the input: reconstructing "
                    f"from offsets gives {reconstructed!r}, expected "
                    f"{_significant(probe)!r}. Characters the offset map drops "
                    "are characters no span can ever be anchored to"
                ),
            )
        )
    return failures


def run_probes(
    tokenizer: Any,
    *,
    strict_decode: bool = False,
    corpus: Sequence[ProbeGroup] = PROBE_CORPUS,
) -> tuple[int, list[ProbeFailure]]:
    """Run every probe, returning (probes checked, failures)."""
    failures: list[ProbeFailure] = []
    checked = 0
    for group in corpus:
        for probe in group.probes:
            checked += 1
            failures.extend(
                check_decode(tokenizer, probe, group.name, strict_decode=strict_decode)
            )
            failures.extend(check_offsets(tokenizer, probe, group.name))
    return checked, failures


def gate(
    model_id: str,
    tokenizer: Any,
    languages: Sequence[str],
    *,
    strict_decode: bool = False,
) -> GateReport:
    """Apply both conditions. A lossless tokenizer never rescues an uncased id."""
    language_tuple = tuple(languages)
    violation = casing_violation(model_id, language_tuple)
    if violation is not None:
        return GateReport(
            model_id=model_id,
            languages=language_tuple,
            probes_checked=0,
            failures=(
                ProbeFailure(
                    group="casing",
                    probe=model_id,
                    kind="uncased_backbone",
                    detail=violation,
                ),
            ),
        )
    checked, failures = run_probes(tokenizer, strict_decode=strict_decode)
    return GateReport(
        model_id=model_id,
        languages=language_tuple,
        probes_checked=checked,
        failures=tuple(failures),
    )


_NETWORK_ARMED = False


def _import_optional(name: str) -> ModuleType | None:
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


class _LibraryTokenizer:
    """Adapter over `tokenizers.Tokenizer` or a `transformers` fast tokenizer."""

    def __init__(self, backend: Any, kind: str) -> None:
        self._backend: Any = backend
        self._kind = kind

    def encode(self, text: str) -> Encoding:
        if self._kind == "tokenizers":
            raw: Any = self._backend.encode(text)
            return Encoding(
                ids=tuple(int(value) for value in raw.ids),
                offsets=tuple((int(start), int(end)) for start, end in raw.offsets),
            )
        raw = self._backend(text, return_offsets_mapping=True)
        return Encoding(
            ids=tuple(int(value) for value in raw["input_ids"]),
            offsets=tuple(
                (int(start), int(end)) for start, end in raw["offset_mapping"]
            ),
        )

    def decode(self, ids: Sequence[int]) -> str:
        return str(self._backend.decode(list(ids), skip_special_tokens=True))


def _missing_dependency_error() -> GateError:
    return GateError(
        "neither `tokenizers` nor `transformers` is importable, so no "
        "tokenizer can be loaded.\n"
        "  Install one into the environment you run this gate from, for "
        "example:\n"
        "      uv pip install tokenizers\n"
        "  or run the gate against a local tokenizer directory that a "
        "colleague has already fetched:\n"
        "      python3 scripts/gate_tokenizer.py --local-only ./vendor/berturk\n"
        "  This script never installs anything on your behalf."
    )


def load_local_tokenizer(source: str) -> _LibraryTokenizer:
    """Load a tokenizer from a directory or a tokenizer.json. No network."""
    path = Path(source)
    candidate = path / "tokenizer.json" if path.is_dir() else path
    tokenizers_module = _import_optional("tokenizers")
    if tokenizers_module is not None and candidate.is_file():
        backend: Any = tokenizers_module.Tokenizer.from_file(str(candidate))
        return _LibraryTokenizer(backend, "tokenizers")
    transformers_module = _import_optional("transformers")
    if transformers_module is not None and path.is_dir():
        backend = transformers_module.AutoTokenizer.from_pretrained(
            str(path), local_files_only=True, use_fast=True
        )
        return _LibraryTokenizer(backend, "transformers")
    if tokenizers_module is None and transformers_module is None:
        raise _missing_dependency_error()
    raise GateError(
        f"--local-only: {source} is neither a tokenizer.json nor a directory "
        "containing one"
    )


def load_hub_tokenizer(model_id: str) -> _LibraryTokenizer:
    """Resolve a hub id, which downloads. Only `main()` may arm this path.

    The arming flag is what keeps the I1 exception structural: importing this
    module from somewhere it does not belong cannot reach the network, because
    the caller would have to reach into a private module global to do it.
    """
    if not _NETWORK_ARMED:
        raise GateError(
            "load_hub_tokenizer() reached without main() arming it. This "
            "module is a publish-time gate and must never be imported by "
            "core/ or by eval/harness.py; use --local-only for in-process or "
            "air-gapped checks."
        )
    tokenizers_module = _import_optional("tokenizers")
    if tokenizers_module is not None:
        backend: Any = tokenizers_module.Tokenizer.from_pretrained(model_id)
        return _LibraryTokenizer(backend, "tokenizers")
    transformers_module = _import_optional("transformers")
    if transformers_module is not None:
        backend = transformers_module.AutoTokenizer.from_pretrained(
            model_id, use_fast=True
        )
        return _LibraryTokenizer(backend, "transformers")
    raise _missing_dependency_error()


class _IdentityTokenizer(_StubTokenizer):
    """A perfect tokenizer: one token per character, exact offsets."""

    def encode(self, text: str) -> Encoding:
        return Encoding(
            ids=tuple(ord(character) for character in text),
            offsets=tuple((index, index + 1) for index in range(len(text))),
        )

    def decode(self, ids: Sequence[int]) -> str:
        return "".join(chr(value) for value in ids)


class _NaiveLowercaseTokenizer(_IdentityTokenizer):
    """What an uncased vocabulary does to Turkish: `str.lower()`."""

    def decode(self, ids: Sequence[int]) -> str:
        return super().decode(ids).lower()


class _ByteOffsetTokenizer(_IdentityTokenizer):
    """Reports byte offsets where character offsets are expected.

    The classic drift, and the reason the gate checks offsets at all: on ASCII
    it is invisible, and on Turkish every span after the first multi-byte
    letter is wrong.
    """

    def encode(self, text: str) -> Encoding:
        offsets: list[tuple[int, int]] = []
        cursor = 0
        for character in text:
            width = len(character.encode("utf-8"))
            offsets.append((cursor, cursor + width))
            cursor += width
        return Encoding(
            ids=tuple(ord(character) for character in text),
            offsets=tuple(offsets),
        )


def _self_test() -> int:
    """Prove the gate has teeth: it must reject as well as accept.

    Runs entirely offline against stub tokenizers, so it is safe in CI and on
    an air-gapped machine.
    """
    checks: list[tuple[str, bool]] = []

    checks.append(
        (
            "rejects distilbert-base-uncased for Turkish",
            casing_violation("distilbert-base-uncased", ("tr",)) is not None,
        )
    )
    checks.append(
        (
            "rejects OpenMed-style uncased id for Turkish",
            casing_violation("some-org/model-distilbert-base-uncased-pii", ("tr",))
            is not None,
        )
    )
    checks.append(
        (
            "accepts dbmdz/bert-base-turkish-cased casing rule",
            casing_violation("dbmdz/bert-base-turkish-cased", ("tr",)) is None,
        )
    )
    checks.append(
        (
            "casing rule is scoped to Turkish, not global",
            casing_violation("distilbert-base-uncased", ("en",)) is None,
        )
    )

    lossless = gate("dbmdz/bert-base-turkish-cased", _IdentityTokenizer(), ("tr",))
    checks.append(
        (
            "accepts a Turkish-native cased backbone with a lossless tokenizer",
            lossless.passed and lossless.probes_checked > 0,
        )
    )

    uncased_but_lossless = gate(
        "distilbert-base-uncased", _IdentityTokenizer(), ("tr",)
    )
    checks.append(
        (
            "a lossless tokenizer does not rescue an uncased backbone",
            not uncased_but_lossless.passed,
        )
    )

    _, lowercase_failures = run_probes(_NaiveLowercaseTokenizer())
    dotted_i_caught = any(
        failure.group == "dotted_dotless_i" and failure.kind == "roundtrip"
        for failure in lowercase_failures
    )
    checks.append(
        (
            "rejects a lowercasing tokenizer on dotted/dotless i",
            dotted_i_caught,
        )
    )

    _, drift_failures = run_probes(_ByteOffsetTokenizer())
    drift_caught = any(
        failure.kind in {"offset_range", "offset_anchor", "offset_coverage"}
        for failure in drift_failures
    )
    checks.append(
        (
            "rejects a tokenizer reporting byte offsets as character offsets",
            drift_caught,
        )
    )

    checks.append(
        (
            "the probe corpus covers every required group",
            {group.name for group in PROBE_CORPUS}
            == {
                "name_morphology",
                "dotted_dotless_i",
                "code_switched_medical",
                "vowel_harmony",
                "mixed_script_clinical",
                "turkish_characters",
            },
        )
    )

    print("gate_tokenizer self-test (offline)")
    failed = 0
    for description, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {description}")
        if not ok:
            failed += 1
    print(f"summary: {len(checks) - failed} passed, {failed} failed")
    return EXIT_OK if failed == 0 else EXIT_GATE_FAILED


def _render(report: GateReport) -> str:
    lines = [
        "-" * 78,
        f"backbone : {report.model_id}",
        f"languages: {', '.join(report.languages)}",
        f"probes   : {report.probes_checked}",
    ]
    if report.passed:
        lines.append("verdict  : PASS - tokenizer round-trips the language losslessly")
        return "\n".join(lines)
    lines.append(f"verdict  : FAIL - {len(report.failures)} failing check(s)")
    for failure in report.failures:
        lines.append(f"  [{failure.group}/{failure.kind}] {failure.probe!r}")
        lines.append(f"      {failure.detail}")
    return "\n".join(lines)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scripts/gate_tokenizer.py",
        description=(
            "I6 backbone/language gate. Exits non-zero unless every named "
            "backbone round-trips the probe corpus losslessly."
        ),
    )
    parser.add_argument(
        "models",
        nargs="*",
        help="hub model ids, or local tokenizer paths with --local-only",
    )
    parser.add_argument(
        "--languages",
        default="tr",
        help="comma-separated language set this backbone would publish for",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="read tokenizers from disk; touches no network",
    )
    parser.add_argument(
        "--strict-decode",
        action="store_true",
        help="require byte-exact decode output, not whitespace-tolerant",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove offline that the gate rejects what it must reject",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    global _NETWORK_ARMED
    args = _parse_args(argv)

    if args.self_test:
        return _self_test()

    if not args.models:
        print(
            "no backbone given. Pass one or more model ids, or --self-test.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    languages = tuple(
        item.strip() for item in str(args.languages).split(",") if item.strip()
    )
    if not languages:
        print("--languages resolved to an empty set", file=sys.stderr)
        return EXIT_USAGE

    if not args.local_only:
        print(
            "NETWORK NOTICE: this is a PUBLISH-TIME gate and it will reach the "
            "Hugging Face Hub to resolve each tokenizer.\n"
            "  No patient text is involved and this path is never reachable "
            "from core/ or from the eval harness (invariant I1).\n"
            "  Use --local-only <dir> for an air-gapped or CI run.",
            file=sys.stderr,
        )
        _NETWORK_ARMED = True

    reports: list[GateReport] = []
    for model_id in args.models:
        violation = casing_violation(model_id, languages)
        if violation is not None:
            reports.append(
                GateReport(
                    model_id=model_id,
                    languages=languages,
                    probes_checked=0,
                    failures=(
                        ProbeFailure(
                            group="casing",
                            probe=model_id,
                            kind="uncased_backbone",
                            detail=violation,
                        ),
                    ),
                )
            )
            continue
        try:
            tokenizer = (
                load_local_tokenizer(model_id)
                if args.local_only
                else load_hub_tokenizer(model_id)
            )
        except GateError as exc:
            print(f"cannot run gate for {model_id}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        except OSError as exc:
            print(f"cannot load tokenizer for {model_id}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        reports.append(
            gate(
                model_id,
                tokenizer,
                languages,
                strict_decode=bool(args.strict_decode),
            )
        )

    for report in reports:
        print(_render(report))
    failing = [report for report in reports if not report.passed]
    print("-" * 78)
    print(
        f"summary: {len(reports) - len(failing)} backbone(s) passed, "
        f"{len(failing)} failed"
    )
    return EXIT_GATE_FAILED if failing else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
