# deid-tr — standing brief

Project `deid-tr`. Apache-2.0. Default branch `main`. Repo root is the only writable tree.

## START HERE — session protocol

Do these three reads before any other tool call:

1. `docs/PLAN.md` — goal, milestones M0-M7, architecture, scope boundaries.
2. `docs/PROGRESS.md` — the **last three entries only**. This is the recovery point after compaction.
3. `docs/TASKS.md` — checkboxes for the current milestone only.

Then, before editing anything, state in plain text:

- **Current milestone** and its exit criterion.
- **Next unchecked task** verbatim from `docs/TASKS.md`.
- **Blockers**, or the word `none`.

Then do **exactly one task**. Delegate verbose work (bulk fixture generation, corpus scans, wide refactors) to subagents. TDD. Run `just check`. Tick the box, append `docs/PROGRESS.md`, append `docs/DECISIONS.md` if a tradeoff was made. Stop.

**Loop invariant:** if `git status` is dirty and `docs/PROGRESS.md` has no entry describing it, the loop is broken. Reconstruct the entry from the diff before starting new work.

**Compaction survival:** write PROGRESS entries naming files and line numbers. Never "the thing we discussed".

## Goal

Build the highest-assurance open-source PHI/PII de-identification pipeline for **Turkish clinical text**, and the benchmark that proves it. North star: a compliance officer at a Turkish hospital reads our eval report and signs off on sending clinical text to a cloud LLM.

## Two properties of clinical text that drive every design decision

**1. Medicine is multilingual by nature.** Turkish clinical notes are Turkish prose saturated with Latin and English medical register: diagnoses (`carcinoma`, `pneumonia`), anatomy (`hepaticus`, `sinistra`), drugs (`Adalat`, `metformin`), abbreviations (`MRI`, `PET-CT`, `ECG`). Two consequences, both first-class requirements:

- These terms must **never be masked**. Masking `carcinoma` destroys the note. `Adalat` reads like a person's name to a naive detector.
- They **code-switch morphologically**: a Latin/English root takes a Turkish suffix — `carcinoma'lı hasta`, `MRI'da`, `PET-CT'de`, `metformin'e`. The boundary between a Turkish name with a case suffix and a Latin term with a case suffix is exactly where token classifiers fail.

This drives: the class-C medical allowlist, the L4 adjudication layer, the I6 tokenizer gate, and the medical-term false-positive release gate.

**2. The most dangerous PHI has no token-level signature.** The 18 HIPAA identifiers are *direct* identifiers a token classifier can learn. Clinical narrative re-identifies patients through **quasi-identifiers embedded in prose**:

- "he works at the Central Bank" — employment/role; lethal in a small population.
- "his wife is a well-known judge" — relationship plus incidental detail.
- "they have a beach house in Dubai" — asset plus geography.
- "the patient's daughter, a nurse in this same department" — PHI containing no name.

No NER model tags "works at the Central Bank", because it is not an entity — it is a *meaning*. Catching it requires an LLM reasoning about re-identification risk across the whole document. This drives: L3, the Expert Determination tier, the class-B schema, and the red-team-validated re-ID rate instead of an F1.

Legal standards, made into product tiers:

- **Safe Harbor** — remove the 18 enumerated direct identifiers. Mechanical, fast, on-device.
- **Expert Determination** — qualified analysis concludes re-identification risk is very small, accounting for quasi-identifiers.

## Invariants I1-I8

A change violating one is reverted, not debated. Enforced with hooks, not good intentions.

**I1 — PHI never leaves the device.** `core/` has no network dependency. No telemetry, no analytics, no crash reporting containing text, no lazy model download at inference. The test suite passes with networking disabled. **Corollary: L3's LLM is LOCAL, never cloud.** Sending PHI to a cloud LLM to detect its PHI defeats the product's reason to exist. A cloud SDK import or an `https://api.` literal under `core/context/` is blocked by `guard_invariants.sh`.

**I2 — Recall is the product; precision is a feature.** A missed identifier is a breach. An over-masked term is a papercut. When they trade off, recall wins. Never lower a recall threshold to make a build green. The one bounded exception is the medical-term allowlist, handled by precision in L4 — never by weakening recall on actual PHI.

**I3 — Never bind `0.0.0.0`.** Default `127.0.0.1`. Exposure requires all three of: an explicit `--expose` flag, a bearer token, and a startup warning. `"::"` is blocked identically.

**I4 — Feedback on a miss is PHI.** A correction saying "you missed `Ayşe Yılmaz`" contains a patient name. It never leaves the machine, never enters a log, a commit, or a syncing training set.
- False **positives** (a masked non-PHI span) are exportable — bare span only, no surrounding context.
- False **negatives** (missed real PHI) stay local forever. Export the *pattern*, never the *instance*.

**I5 — Model cards are build artifacts.** Generated from `eval/results/<run_id>.json` by `scripts/publish.py`. No human writes a card. No card ships whose `eval_sha` is not a committed eval run.

**I6 — Backbone/language gate.** No model is published for language set L on backbone B unless B's tokenizer round-trips L losslessly, **including code-switched Latin/English medical terms carrying Turkish morphology** (`carcinoma'lı`, `MRI'da`). No `*-uncased` backbone ships for Turkish, ever: casing is the strongest name signal, and Turkish lowercasing corrupts İ/I/ı/i.

**I7 — The golden set is append-only.** Fixtures are never deleted or weakened to make a test pass. Adding a failing adversarial case is an encouraged commit.

**I8 — No real PHI in the repo.** Every fixture is synthetic, or licensed (n2c2/MIMIC under DUA, never committed). A pre-commit hook blocks TCKN-checksum-valid numbers. Every TCKN written into a fixture or doc must be checksum-INVALID.

## Architecture

```
        Clinical note  (Turkish + Latin/English medical register)
                          |
 [L1] Deterministic rules — regex + checksum     direct identifiers, fixed format   always  ~1ms
                          |
 [L2] NER ensemble — UNION                       direct identifiers, token-level    always  ~10ms
                          |
 [L3] Contextual sweep — LOCAL LLM, full-doc     quasi-identifiers in narrative     tier-gated
      employment · relationships · assets/geography · distinctive events            UNION w/ L1+L2
                          |
 [L4] Router + adjudication — CONSENSUS          argue down false positives         flagged spans only
      incl. "is this a person, or a Latin/English medical term / drug / anatomy?"
                          |
 [L5] Consistent surrogates — format-preserving
                          |
 [L6] Re-ID red team — adversarial risk score    validates L3
                          |
       De-identified text + span map + audit log
```

### Two aggregation rules, one per error type

- **UNION across L1 + L2 + L3, for recall.** Anything flagged by any layer is masked. Union sits *before* adjudication because the cost of the two error types is asymmetric. Never majority-vote a span away: a converging council drops exactly the spans only one detector flagged, which is a breach machine.
- **CONSENSUS at L4, for precision.** L4 is the only place agents debate, and it debates only spans that are already flagged. Being wrong here costs clinical utility, not privacy — that is why consensus is confined to this position. L4 is where multilingual medical knowledge lives.

### Two assurance tiers

- **Safe Harbor** = L1 + L2 + L4 + L5 (+L6 in eval). The 18 direct identifiers. Fast, cheap, on-device, runs everywhere including the browser. Default.
- **Expert Determination** = adds L3, the full-document local-LLM contextual sweep. Requires a host able to run a local LLM. Opt-in, because aggressive contextual masking trades clinical readability for privacy.

**Cost economics.** L1/L2 run on every note at ~10ms. In Safe Harbor, L4's adjudicator sees the spans the ensemble is unsure about — originally assumed to be 2-5%, **measured at 40.0% (268 of 670 routed candidates)** on the committed corpus. Corrected in D-027, which states the qualifications (I8 forbids checksum-valid TCKNs in fixtures, so every committed TCKN escalates; L2 is a stub, so nothing is multi-detector yet; `escalated` is an upper bound on `adjudicator_calls`). L3 is a full-document read — the expensive tier, gated behind Expert Determination.

**Two escalation denominators, never interchangeable.** *Routed candidates* — spans that reached `route()`: 268/670 = 40.0%. *Vocabulary occurrences* — every mention of a class C medical term in the corpus text: 74/1910 = 3.87% (D-023). The second answers "how often does allowlisting turn a term into a question" and does not bound the first. Always quote the denominator.

### Core and bindings

```
core/          Rust. Rules, checksums, span algebra, BIOES decode, surrogates, audit.
               Pure. No I/O, no network. Compiles native AND wasm32.
bindings/cli/     native binary
bindings/python/  PyO3
bindings/mcp/     stdio JSON-RPC gateway
bindings/tauri/   desktop + iOS/Android (Tauri v2)
bindings/wasm/    wasm-bindgen -> PWA + local panel
```

Inference is abstracted behind two traits:

```rust
pub trait Detector   { fn infer(&self, ids: &[u32]) -> Result<Vec<Vec<f32>>>; }  // L2
pub trait Contextual { fn sweep(&self, doc: &str)   -> Result<Vec<Span>>; }      // L3, LOCAL LLM
```

Native: `ort` for L2, a local quantized LLM via `candle`/`ort` for L3. Browser: `onnxruntime-web` or `candle` for L2; L3 only where WebGPU can host a small local LLM. Abstracted because `ort` dropped `wasm32-unknown-unknown` support — rules, checksums, span merge and surrogates stay single-sourced in Rust/WASM and only the forward pass swaps. `tokenizers` (HF, Rust) builds for both targets, so tokenisation is shared.

**Product surface constraint:** a hosted upload panel would break the value proposition. The panel and PWA are fully client-side — model in the browser, weights in the service worker, zero uploads.

## Entity schema — three classes

**A. Direct identifiers** — Safe Harbor 18, mapped to Turkish. `detector: rules | ner`. Numeric recall gates. Includes TCKN, VKN, SGK, Turkish address parts (`Mah.`/`Sok.`/`No`/`Daire`), Turkish phone formats (`+90 5XX`, `0(5XX)`, `05XX`), plus names, dates, MRN, email.

**B. Contextual quasi-identifiers** — Expert Determination. `detector: llm`. Categories `EMPLOYER_ROLE`, `RELATIONSHIP_REF`, `ASSET_LOCATION`, `DISTINCTIVE_EVENT`, `RARE_ATTRIBUTE_COMBO`. **Not scored by a fixed F1** — validated by the L6 re-ID red team.

**C. Medical-term allowlist** — the negative set. Latin/English medical vocabulary that must **never** be masked: diagnoses, anatomy, drugs, standard abbreviations, including code-switched Turkish-suffixed forms (`carcinoma'lı`). Scored as a false-positive rate. Serves as L4's runtime reference and as a hard Definition-of-Done gate.

Every direct entry carries: `id`, `hipaa_category`, `identifier_class` (direct|quasi), `detector` (rules|ner|llm), `tr_specific` (bool), `checksum_validatable` (bool), `recall_threshold`, and `precision_threshold: 1.000` when checksum-validatable.

## Layer specifications

Span type — every layer speaks this:

```rust
pub struct Span {
    pub start: usize,        // BYTE offset into ORIGINAL text (UTF-8, must land on char boundary)
    pub end:   usize,        // exclusive byte offset
    pub label: EntityLabel,  // from eval/schema.yaml
    pub source: Layer,       // Rules | Ner | Context
    pub confidence: f32,     // 1.0 for checksum-valid; softmax for NER; model-reported for L3
    pub text_hash: u64,      // hash of covered text for surrogate consistency — NEVER store the text
}
pub enum Layer { Rules, Ner, Context }
pub enum Decision { Mask, Keep }
```

Orchestrator:

```rust
pub enum Tier { SafeHarbor, ExpertDetermination }
pub struct Pipeline {
    rules: RuleSet,                       // L1
    detectors: Vec<Box<dyn Detector>>,    // L2 ensemble
    context: Option<Box<dyn Contextual>>, // L3, ExpertDetermination only
    allowlist: MedicalAllowlist,          // class C
    surrogate: SurrogateEngine,           // L5
    tier: Tier,
}
pub fn deidentify(&self, doc: &str) -> DeidResult;
pub struct DeidResult { pub text: String, pub span_map: Vec<MappedSpan>, pub audit: AuditLog }
```

### Byte-offset discipline — the number-one correctness trap

Offsets are **byte** offsets into the original text, never char indices. Turkish is multi-byte UTF-8 (`ş`, `ğ`, `İ` are two bytes each), so a char index silently shifts every span to the right of the first non-ASCII character. Never trust an offset reported by a tokenizer or an LLM: always re-anchor to the original text and assert the offset lands on a char boundary. İ/ı normalisation must be reversible, and any normalised-space offset must be mapped back before a span escapes the layer that produced it.

### L1 — Deterministic rules · M1 · `core/src/rules/`
Contract: `fn detect(&self, text: &str) -> Vec<Span>`, `source: Rules`.
Approach: **over-match at regex, reject at checksum.** A checksum-valid match gets `confidence: 1.0` and is never demoted downstream.
Modules, each with known-valid and known-invalid vectors: `tckn.rs`, `vkn.rs`, `sgk.rs`, `phone.rs`, `iban.rs`, `mrn.rs`, `date.rs`, `email.rs`.
TCKN checksum (11 digits, `d1 != 0`): `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`; `d11 = (d1+..+d10) mod 10`. VKN has its own 10-digit algorithm. TR IBAN is 26 chars, mod-97 == 1.
Failure modes: suffixed IDs (`12345678901'in`), full-width or non-ASCII digits, IDs glued inside a word, right-length numbers that are a different type.

### L2 — NER ensemble · M3 · `core/src/detect/`
Tokenize -> each fine-tuned encoder emits per-token label logits -> **BIOES decode with a Viterbi transition constraint** -> map subword spans back to original byte offsets -> **UNION across models** (widest wins on overlap, noisy-OR confidence). Never majority-vote a span away.
Backbones, each gated through `scripts/gate_tokenizer.py`: BERTurk, BioBERTurk, ConvBERTurk, mDeBERTa-v3, XLM-R.
Failure modes: subword fragmentation of suffixed names, offset drift after İ/ı normalisation, model disagreement (union absorbs it).

### L3 — Contextual sweep · M4 · LOCAL LLM · `core/src/context/`
Contract: `trait Contextual { fn sweep(&self, doc: &str) -> Result<Vec<Span>>; }`, `source: Context`, every span carrying a short rationale.
A structured prompt to a **local** quantized LLM returns JSON: for each quasi-identifier, the **exact verbatim quote**, the category, and a one-line reason. **Ask for the quote string, never for integer offsets.** Re-locate each quote verbatim to derive byte offsets; **if a quote is not found verbatim, drop it** — that is the hallucination filter. Temperature 0, fixed seed, log the prompt and response hashes only.
Hard constraint: the model is local. A cloud SDK or `https://api.` reference here is blocked by `guard_invariants.sh`.
Failure modes: hallucinated quotes (dropped), paraphrased quotes that fail to anchor (dropped, logged as a recall risk), backend-dependent near-tie flips (see the open issue in D-010).

### L4 — Router + adjudication · M4 · CONSENSUS · `core/src/route/`
Input: the union of L1+L2+L3 spans, the text, and the allowlist. Output: `Vec<(Span, Decision)>`.
1. **Confidence router.** High-confidence spans auto-`Mask` and skip adjudication. Only low-confidence single-source spans escalate — assumed 2-5% in Safe Harbor, **measured 40.0% of routed candidates** (D-027). Not to be confused with the 3.87% of *vocabulary occurrences* in D-023, which is a different denominator.
2. **Adjudication (consensus).** Is this real PHI, or a Latin/English medical term, drug, or anatomy? Check the allowlist first. If ambiguous (`Adalat` the drug versus `Adalet` the name), the local LLM adjudicator votes.
**Guardrail:** L4 may only DEMOTE (`Mask` -> `Keep`). It may never invent a span, and may only demote if the span is on the allowlist OR is a single low-confidence source AND the adjudicator agrees. Checksum-valid and multi-model-agreed spans are **never** demoted.
Failure modes: the allowlist-versus-recall precedence gap — see D-010, OPEN, blocking L4 design.

### L5 — Consistent surrogates · M5 · `core/src/surrogate/`
Per masked entity: (a) **preserve type and format** — name -> Turkish fake name, TCKN -> checksum-valid fake TCKN; (b) **consistent within a document**, keyed by `text_hash + salt`; (c) **break structural tells** — do NOT preserve length or casing patterns, **except the date format**, which is preserved on purpose so downstream parsers keep working. That exception costs a measurable length tell within the DATE family (r = 0.85 `DATE_BIRTH`, 0.89 `DATE_ADMISSION`, 1.0000 `DATE_DEATH`, against -0.06 for `PATIENT_NAME`): the leak is of the author's date TEMPLATE, which the surrounding unmasked prose already shows, not of the value, which the shift destroys. Recorded with the measurement in D-028.
**Date shifting:** one per-patient offset, so intervals survive while absolute dates are fake.
The `span_map` is the round-trip table M2's gateway uses. It is local, never leaves the machine, and is never logged.

### L6 — Re-ID red team · M5 · `eval/`, not the live path
Input: de-identified output. Output: a risk score, the successful attack classes, and new adversarial fixtures. Runs as an **eval step, never in the masking path**.
Seven attack classes: quasi-identifier combination, narrative survival, structural leakage, cross-doc linkage, rare-value survival, format tells, indirect reference. Produces the **contextual re-ID rate** — the <=5% gate that is L3's real success metric (D-008).

**Milestone -> layer map:** M1 = L1. M2 = L1+L2 in the MCP gateway with a round-trip span map. M3 = L2 ensemble. M4 = L3 + L4. M5 = L5 + L6.

## TDD — split by what is being tested

**Layer A — deterministic code** (rules, checksums, span algebra, surrogates). Strict red-green-refactor. Every ID format ships known-valid and known-invalid vectors.

**Layer B — model behaviour.** The **eval harness is the test suite**, the **golden set is the corpus**, and thresholds live in `eval/thresholds.yaml`. Add a fixture the pipeline gets wrong -> RED. Fix it -> GREEN. Three fixture kinds are covered: direct-identifier misses, medical-term false positives, contextual quasi-identifier misses.

**Raise-only rule:** a threshold in `eval/thresholds.yaml` may only ever be **raised**. Lowering one requires a `docs/DECISIONS.md` entry and explicit human approval, and is never done to make a build green (I2).

## Definition of Done

- `just check` green: `fmt`, `clippy -D warnings`, `test`, `eval`
- New behaviour has a test that failed before the change
- No new `unwrap()`/`expect()` in `core/` reachable from the public API
- `just test-airgapped` green (networking disabled)
- `docs/PROGRESS.md` appended; the `docs/TASKS.md` box ticked
- Non-obvious tradeoffs recorded in `docs/DECISIONS.md`

Any task touching detection or masking, additionally:

- Recall did not decrease for **any** direct entity type
- Medical-term false-positive rate did not increase
- `reid-red-team` ran, with no new successful re-identification
- `privacy-reviewer` ran, with no PHI in logs, errors, fixtures, or the commit

**Release gates — numeric, non-negotiable:**

| Gate | Threshold | Why |
|---|---|---|
| Recall, HIPAA-critical direct (NAME, ID, CONTACT) | >= 0.98 | The breach vectors |
| Micro F1, all direct entities | >= 0.95 | Stubbs et al. 2015 accepted bar |
| Document leak rate (>=1 missed direct identifier) | <= 2% | What a hospital asks for |
| Medical-term false-positive rate (allowlist) | <= 0.5% | Masking `carcinoma` destroys the note |
| Contextual re-ID rate (Expert Det. tier, red-team) | <= 5% | The real test of L3 |
| Sight-unseen recall drop (new note type) | <= 5 points | RoBERTa on i2b2 drops to 0.887 F1 on unseen nursing notes |
| Checksum-validated ID precision | 1.000 | A checksum-valid TCKN is never a false positive |
| Multilingual tokenizer round-trip (published backbone) | lossless | Code-switched TR/EN/Latin must survive tokenization |
| Core network syscalls during test | 0 | I1 |
| Card `eval_sha` matches committed run | exact | I5 |

Report **recall per entity type**, never aggregate F1 alone. Report direct-identifier recall, medical-term FP rate, and contextual re-ID rate as **three separate numbers**.

## The loop — four state files

| File | Contains | Rewritten? |
|---|---|---|
| `docs/PLAN.md` | Milestones, architecture, the why, scope boundaries | Rarely |
| `docs/TASKS.md` | Checkboxes for the **current milestone only** | Each milestone |
| `docs/PROGRESS.md` | Append-only log: changed / broke / next | Never — append |
| `docs/DECISIONS.md` | Append-only ADRs | Never — append |

## Milestones

M0 golden set + eval harness -> M1 rules layer -> M2 MCP gateway (round-trip re-identification; first shippable) -> M3 detector ensemble -> **M4 verifier + contextual sweep + router** -> M5 red team + surrogates -> M6 surfaces (CLI -> Tauri -> PWA) -> M7 publish.

M0 first, always. A model without a metric is not progress.

## Hugging Face strategy

Copy the incumbent's mechanics; reject their epistemics.

Legitimate: **naming is SEO** (`deid-tr/DeidTR-PII-Turkish-BERTurk-Base-110M-v1`); **base-model backlinks** — fine-tuning from BERTurk places us in its model tree; tag saturation; collections; translated READMEs; a weekly cadence; paper -> HF Daily Papers. Runtime variants (fp32/int8/ONNX-WebGPU) are real coverage, not padding.

Honest ceiling: about 6 defensible backbones x 3 runtimes, so about 18 Turkish repos, each with its own real eval.

**Forbidden:** publishing an unevaluated checkpoint; shipping a card whose numbers came from a different run; publishing on any backbone that fails the I6 tokenizer gate; **any mechanical download inflation**.

**The distribution vehicle is the benchmark, not the models.** `deid-tr/TurkDeID-Bench` — gold test set plus leaderboard, with a **contextual quasi-identifier track no other benchmark has**. Models are the commodity; the scoreboard is the moat.

Prior art gets cited, not attacked. OpenMed NER (arXiv 2508.01630) is real work; the failure being designed against is a *process* failure. Attack the pipeline, never the person.

## Standing rules

- Never `git push`, publish to Hugging Face, or send anything over the network without explicit approval.
- L3 uses a **local** LLM only. Never wire it to a cloud API.
- Never guess in a masking pipeline. State expected, actual, and ruled-out; propose two options with tradeoffs; ask.
- Comments explain **why**, never what.
- `#![forbid(unsafe_code)]` in `core/`. `thiserror` for errors. No `unwrap()` in library paths. `ruff` + `mypy --strict` + `uv` for Python. Conventional commits. No emoji in code or docs (the top-level `README.md` is an explicit user-approved exception).
- One task at a time.

## Turkish linguistic domain knowledge

- **Agglutination:** `Ayşe'ye`, `Ayşe'nin`, `Yılmaz'ın`. English subword tokenizers fragment these; the span boundary lands wrong and `'nin` leaks.
- **Dotted/dotless i:** İ/i and I/ı are four distinct letters. A naive `.lower()` maps `İ` -> `i̇` and `I` -> `i`, corrupting the text.
- **Vowel harmony:** the same suffix surfaces as `-de/-da/-te/-ta`. Hardcoding one variant misses the others.
- **Code-switch morphology:** Latin/English roots take Turkish suffixes — `carcinoma'lı`, `MRI'da`, `PET-CT'de`, `metformin'e`.
- **Medical allowlist surface:** diagnoses (`carcinoma`, `pneumonia`), anatomy (`sinistra`, `hepaticus`), drugs (`Adalat`, `metformin`), abbreviations (`MRI`, `ECG`) — including suffixed forms.
- **Turkish IDs:** TCKN (11 digits, checksummed), VKN (10 digits), SGK.
- **Titles:** `Dr.`, `Op. Dr.`, `Prof. Dr.`, `Uz. Dr.`, `Hemş.`, `Bey`, `Hanım`. Title plus a capitalized token is the highest-yield name pattern.
- **Transliteration drift:** `Şükrü`/`Sukru`, `Gökçe`/`Gokce`. Both must be caught.
