# deid-tr and OpenMed — an honest comparison

**Date of the evidence in this document:** 2026-07-20.
**Status of deid-tr at that date:** M0/M1. L1 rules and span algebra exist. **L2 has no trained
model, so deid-tr masks ZERO names.** Every deid-tr number below is scoped to rule-detectable
identifiers.

> **Provenance of every number in this document.** Each deid-tr figure below comes from ONE
> evaluation run and no other:
>
> | | |
> |---|---|
> | run id | `20260719T234410Z-pipeline` |
> | artifact | `eval/results/20260719T234410Z-pipeline.json` |
> | `eval_sha` | `uncommitted` |
> | `schema_sha` | `092169a60dd1…` |
> | `thresholds_sha` | `1d107ec99990…` |
> | red-team report | `eval/results/redteam.json`, run id `20260719T234404Z-pipeline`, masker `pipeline` |
> | command | `python3 -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json` then `python3 eval/run.py --detector pipeline --redteam-report eval/results/redteam.json` |
>
> The tables in section 6 are printed from that artifact rather than transcribed, because an
> earlier revision of this document published numbers from a different, older run than the command
> it told you to type — 178 documents against the corpus's 190, a TCKN recall of 1.0000 that the
> then-current tree did not produce, and a gate tally off by three. Publishing figures that came
> from a run other than the named one is the exact failure section 1.1 criticises next door, and it
> was ours. If any figure below cannot be found in that JSON, it is a bug in this document; report
> it.
>
> **`eval_sha` is `uncommitted`, and that is a real limitation, not a formality.** The working tree
> was dirty when this ran, so the run cannot be pinned to a commit, and the D-029 provenance check
> that matches the red-team report to the scored run passed by comparing `uncommitted` to
> `uncommitted` — a match that proves the two artifacts were both produced from unrecorded code, not
> that they were produced from the *same* code. Under I5 no model card may ship carrying this run.
> These numbers are honest about a moving tree; they are not yet reproducible from a checkout.

If you are deciding what to run over patient data this week, read section 1 and section 5 and stop.
Sections 2 to 4 and 6 are about where this project is going and what it currently fails.

---

## 1. What OpenMed is, and what it does better than us today

OpenMed (Maziyar Panahi and contributors; NER paper arXiv 2508.01630) is real, substantial and
widely adopted work: a large published model family, 17 model-backed PII languages including
Turkish, and genuine on-device execution across more platforms than we support or plan to support.
It is Apache-licensed and the code is readable.

(An earlier draft of this document put a checkpoint count and a cumulative-download figure here.
Neither was checked against anything, so both are gone. Every remaining claim about OpenMed in this
document traces to their live model cards, their docs site or their repository, recorded in the
research notes this document was written from.)

**On any head-to-head PHI detection benchmark for Turkish clinical text, OpenMed wins today.** Not
narrowly, and not on a technicality. Theirs runs and ours does not: their Turkish checkpoints emit
name, address, date and identifier spans; ours emit nothing for any name class. A benchmark that
scored the two systems on the same Turkish notes today would show OpenMed detecting names,
organisations, locations and job titles at whatever their true Turkish accuracy is, and deid-tr
detecting none of them. If names must be masked — and in clinical text they must — OpenMed is the
answer and deid-tr is not.

Concretely, things OpenMed does that we do not:

- **Trained models that actually run.** A published checkpoint family with a 54-label space, BIOES
  decoding, and a 1.4B-parameter multilingual privacy filter (`OpenMed/privacy-filter-multilingual`,
  54 labels expanded to 217 BIOES classes). We have zero trained checkpoints.
- **Breadth of language.** 17 model-backed PII languages against our one.
- **Breadth of runtime.** Python (CPU/CUDA), MLX on Apple Silicon with INT4 export certification,
  Swift/OpenMedKit for macOS/iOS/iPadOS, Android/Kotlin via ORT Mobile, browser via
  onnxruntime-web with WebGPU, React Native, FastAPI REST, gRPC, Docker, SageMaker. We ship a
  native CLI, a stdio MCP gateway and a loopback-only REST service.
- **Document and format handling we have not attempted at all.** OCR through Tesseract, PaddleOCR,
  EasyOCR and docTR; DOCX with offset extraction; EPUB, Markdown, AsciiDoc; PDF redaction with a
  text-layer leakage verifier; DICOM header de-identification plus burned-in pixel OCR redaction;
  vCard/iCalendar; JSONL chat logs with speaker pseudonymisation; CSV/TSV PHI column
  classification; FHIR R4, SMART-on-FHIR bulk ingestion, HL7 v2, CDA/C-CDA, OMOP CDM.
- **Six redaction methods** — `mask`, `remove`, `replace`, `hash`, `shift_dates`, `format_preserve`
  — with locale-aware Faker surrogates and checksum-valid synthetic national IDs for the providers
  their docs list (CPF, CNPJ, BSN, NIR, Codice Fiscale, NIE, Aadhaar, Steuer-ID, NPI, MRN). We have
  one surrogate engine and no user-selectable method.
- **A keyed surrogate vault.** `SurrogateVault` stores `(canonical_label, lang, HMAC text_hash) ->
  surrogate` with a caller-supplied secret and no raw surfaces. That design is strictly better than
  our current `text_hash`, which is an unkeyed 64-bit FNV-1a and is brute-forceable by anyone
  holding a span map. We have this filed as an open issue; they have it shipped.
- **HMAC-derived per-patient date shifting** bounded by `date_shift_max_days`, with the raw patient
  key never logged, persisted or returned.
- **Correct Turkish TCKN validation, shipped.** `openmed/core/pii_i18n.py::validate_turkish_tckn`
  implements exactly the same check-digit algorithm as our `core/src/rules/tckn.rs`. Their repo
  README carries a worked Turkish example calling `extract_pii(...)` on a note holding a patient
  name, a `+90` mobile number and a checksum-valid TCKN, with `lang="tr"` — which selects Turkish
  regex patterns and a Turkish default model. (Their literal example TCKN is not reproduced here:
  it is checksum-valid, and I8 forbids a checksum-valid Turkish ID from existing anywhere in this
  repository, including in prose about someone else's documentation.)
- **Presidio-style context scoring** — per-pattern `base_score`, locale-specific `context_words`, a
  `context_boost` inside a 100-character window, and `priority` for overlap resolution. We have no
  equivalent.
- **A large evaluation and release apparatus**: `openmed/eval/` (leakage heatmaps, scorecards,
  threshold sweeps, fairness, robustness, calibration reliability, over-redaction, paired
  significance), `openmed/risk/` (re-identification risk, membership and linkage probes,
  k-anonymity, l-diversity, t-closeness, risk budgets), `release_gates.py`, `evidence_bundle.py`,
  SBOMs, signed images, SLSA provenance. **The gap we describe in section 2 is not a tooling gap.**
- **Sensible security defaults on the REST surface.** Loopback bind in every documented example,
  trusted-host checking always on, CORS off unless exact origins are listed, wildcards rejected,
  `/metrics` opt-in and 404 by default, metrics and traces carrying no PHI. (The shipped
  `docker-compose.yml` does publish on all host interfaces, and their docs tell you to change it to
  `127.0.0.1:8080:8080`.)
- **A cloud-LLM story that fails closed.** `POST /privacy-gateway/complete` redacts locally, runs an
  independent outbound tripwire scan, sends only redacted text to an operator-configured transport
  that the request body cannot override, and refuses unknown or mangled placeholders on the way
  back.

### 1.1 The one thing we criticise, stated exactly, with the stale half removed

Our project brief carried a criticism of OpenMed's Turkish model cards. Before repeating it we
re-checked it against the live cards, because repeating a stale criticism of another project is the
same epistemic failure we are accusing anyone of. **Part of the brief's claim is still true and part
of it is now wrong. Both halves are stated here.**

Verified against `raw/main/README.md` on the live repos, 2026-07-20:

- **Still true, on the v1 PyTorch checkpoints.** Every `OpenMed-PII-Turkish-*` v1 card (all created
  17 May 2026, unchanged since) is a copy of the corresponding Arabic card: YAML `language: ar`,
  an `arabic` tag, an H1 and body naming the Arabic model, an Arabic-script widget example, a
  training-data description of Saudi-locale synthetic data (`+966` phones, SAR currency), a
  "Limitations" line reading "Optimized for Arabic text", and code samples that load a *different
  repo*. The published F1/precision/recall on the Turkish repos are the Arabic numbers:
  `Turkish-SuperClinical-Small-44M-v1` reports micro-F1 0.8855 / P 0.8761 / R 0.8951, which is the
  exact row for `Arabic-SuperClinical-Small-44M-v1` in the Arabic leaderboard.
  **Consequence: there is no published Turkish evaluation number for any OpenMed Turkish PII
  checkpoint.**
- **Now wrong, and we will not repeat it.** The brief said the Turkish cards use English-only
  uncased backbones that cannot tokenize Turkish. That is true of most of the family but not all of
  it: roughly 7 of ~32 use a genuinely multilingual backbone — `xlm-roberta-base` and
  `-large` (`BigMed`), `mdeberta-v3-base` (`mSuperClinical`), `distilbert-base-multilingual-cased`
  (`mLiteClinical`), `bge-m3` (`ClinicalBGE-Large-568M`), `snowflake-arctic-embed-l-v2.0`
  (`SnowflakeMed`), `Qwen3-Embedding-0.6B` (`QwenMed`). Saying "all" would be false.
- **Also now wrong.** `OpenMed-PII-Turkish-SuperMedical-Large-355M-v1-onnx-android` (created
  12 July 2026) carries `language: tr`, describes itself as detecting identifiers in **Turkish**
  clinical text, has no Arabic widget, and publishes the full 54-label list. The language tag has
  been corrected on that derivative. It publishes **no Turkish metrics at all** — the metrics
  section is absent, replaced by advice to evaluate recall on your own governed data. So the
  language tag was fixed; the evaluation gap was not filled, it was removed.

**What we do not claim.** We do not claim the Turkish weights are Arabic weights — the weights were
not downloaded and that is not verifiable from a card. We do not claim OpenMed lacks Turkish
support; it ships a correct TCKN validator, `lang="tr"` routing and Turkish regex patterns. We do
not claim their models detect nothing; they detect a great deal.

**And the criticism is of a process, not of a person.** The failure is that a card shipped carrying
another language's `model-index` block, and that on the v1 repos it has not been corrected in the
two months since. Our invariant I5 — "model cards are build artifacts, generated from
`eval/results/<run_id>.json`; no card ships whose `eval_sha` is not a committed eval run" — exists
precisely to make that class of mistake unrepresentable rather than unlikely. We have that
invariant and no models. They have the models. Neither state is the good one.

---

## 2. What deid-tr does differently, and can defend

None of the following is a claim to better detection. Every item is a claim about *knowing what the
detection does*.

**A Turkish clinical gold benchmark that did not previously exist.** `eval/gold/` and
`eval/adversarial/` are 190 synthetic documents, 1,538 annotated direct-identifier spans, 229
quasi-identifier spans, and 1,293 allowlist-term annotations, split dev / sight-unseen /
adversarial. Gold spans are anchored as verbatim quotes plus an occurrence index and resolved to
byte offsets at load time (D-009); a quote that will not resolve is a hard error, never a skip,
because a silently dropped gold span shrinks the recall denominator and inflates recall. The set is
append-only (I7): fixtures are never deleted or weakened to make a test pass. We searched and found
no published Turkish clinical de-identification benchmark predating this one; we cannot prove a
negative, and if one exists we want to be told, because it would be a better yardstick than a
benchmark whose authors also wrote the system under test.

**Three separately reported numbers instead of a blended F1.** Direct-identifier recall, the
medical-term false-positive rate and the contextual re-ID rate are reported as three numbers and
never averaged. The reason is visible in our own null-detector baseline: masking nothing scores
0.0000 recall and a *perfect* 0.0000 medical-term false-positive rate. A blended score rewards the
detector that does nothing. `eval/thresholds.yaml` carries per-entity recall floors for 32 labels,
and a release is blocked by the worst of them, not by their mean.

**Gates a null detector cannot pass.** The M0 exit criterion was that the harness report total
failure on an empty detector, with a real denominator behind every zero. The medical-term FP rate is
measured against two denominators and gated on the worse of the two (D-014, D-018), so a detector
cannot look clean by being evaluated only on terms it happened to see. `checksum_id_precision` is
measured over spans a checksum *actually validated*, not spans carrying a checksum-validatable
label (D-030) — which is why it currently reports UNENFORCEABLE rather than 1.000, see section 6.

**Provenance-checked metrics — including a check that caught us.** The contextual re-ID gate is
populated only from an L6 red-team report whose masker is the real pipeline and whose `detector` and
`eval_sha` match the run being scored (D-029). That rule exists because our own contextual gate was
found reading a red-team report produced against an **oracle masker** — a reference masker built
from the gold annotations, which by construction masks perfectly. The gate was therefore measuring
the red team, not deid-tr, and it read as a healthy number. It was fixed by refusing any report
whose masker is not the pipeline, and the honest number that replaced it is 0.8983 against a 0.05
ceiling. A metric that flatters the system is worse than no metric, because it is trusted.

**Invariants enforced by hooks, not by convention.** `scripts/hooks/pre_commit_phi.sh` rejects a
commit containing a checksum-valid TCKN (I8). `scripts/hooks/guard_invariants.sh` rejects a
`0.0.0.0` bind (I3), a cloud-LLM reference in the L3 path (I1), and a decrease of any number in
`eval/thresholds.yaml` (I2). `just test-airgapped` runs the suite with networking disabled.
`bindings/python` is deliberately excluded from the cargo workspace so that no build in this
repository can be made to resolve the registry over the network. The point is not that we are more
careful; it is that being less careful should fail the build.

**A contextual quasi-identifier layer that token classification cannot reach by construction.** The
highest-risk content in a clinical narrative is not an entity. "He works at the Central Bank",
"his wife is a well-known judge", "the patient's daughter, a nurse in this same department" — none
of these is a span a token classifier can be trained to tag, because the re-identifying content is
a *meaning*, not a name. OpenMed's 54-label space has `OCCUPATION`, `JOBTITLE` and `ORGANIZATION`,
which are token-level entities; it has no class corresponding to re-identification-risk reasoning
over a whole document. Our L3 is a local LLM performing exactly that, gated behind the Expert
Determination tier and validated by a red team rather than by F1 (D-008). **It is designed, its
schema classes exist, and it currently detects nothing: contextual coverage is 0.0000.**

For completeness, three places where a design difference is real but modest: byte offsets validated
onto UTF-8 character boundaries at construction rather than character positions (which diverge in
almost every Turkish note); `union_widest`, which never votes a lone proposal away, against
OpenMed's dominant-label vote over fragments, whose own troubleshooting docs list "wrong label
selected" as a known outcome; and a `checksum_validated` flag that is recorded by the code that ran
the arithmetic and can never be inferred, so L4 cannot demote a checksum-valid identifier.

---

## 3. Feature matrix

**Rule for this table: nothing is marked `yes` for deid-tr unless it has been demonstrated end to
end through a shipped binary** — today that means the `deid` CLI (`bindings/cli`) or the stdio MCP
gateway (`bindings/mcp`). Designed, specified and tested-in-isolation are all `no` or `partial`.

### 3.1 Detection

| Capability (from the OpenMed inventory) | OpenMed | deid-tr |
|---|---|---|
| Trained token-classification models | yes, a large published family (~32 base repos for Turkish PII alone, plus `-mlx` and ONNX variants) | **no** — L2 has no trained model |
| Names masked in Turkish clinical text | yes | **no — zero names masked** |
| Model-backed PII languages | 17 | 0 |
| Model label space | 54 labels (AI4Privacy `pii-masking-200k`), 217 BIOES classes | 32 gated direct labels + 5 quasi classes, clinical/HIPAA-shaped |
| Dedicated TCKN / VKN / SGK model labels | no — TCKN surfaces as generic `SSN`/`ID_NUM` | by-design-different — dedicated `EntityLabel` variants; today rule-detected only |
| Dedicated MRN label | no — post-processed into `ID_NUM` | yes (rule-detected; recall 1.0000 on our corpus) |
| Turkish TCKN checksum validator | yes | yes |
| Turkish VKN validator | no | yes (rule layer) |
| Turkish IBAN mod-97 | no | yes (rule layer) |
| Turkish SGK validator | no | yes (rule layer) |
| Non-Turkish national-ID validators (NIR, CPF/CNPJ, Steuer-ID, Codice Fiscale, DNI/NIE, BSN, Aadhaar, RRN, CNP, Luhn/NPI) | yes | no — out of scope by design |
| BIOES decode with Viterbi constraint | yes (privacy-filter family) | partial — implemented in `core/src/detect/`, no model to run it on |
| Fragment aggregation | dominant-label vote, can select the wrong type | by-design-different — `union_widest`, never votes a span away |
| Multi-detector agreement as a first-class signal | not documented in their API or docs | by-design-different — `support` counts distinct detector ids; used only to *forbid* demotion |
| Checksum-valid span protected from demotion | no — not a first-class concept | yes (`checksum_validated`, undemotable) |
| Presidio-style context scoring (`base_score`/`context_words`/`context_boost`) | yes, 100-char window | no |
| Contextual quasi-identifier detection (narrative re-ID) | no capability | **no — designed (L3), unbuilt, coverage 0.0000** |
| Cloud LLM in the detection path | yes, `POST /privacy-gateway/complete`, operator-configured, fails closed | by-design-different — forbidden by I1; L3 must be a local model |
| Offsets | character positions | by-design-different — byte offsets, char-boundary-validated at construction |

### 3.2 Redaction and surrogates

| Capability | OpenMed | deid-tr |
|---|---|---|
| Redaction methods | six: `mask`, `remove`, `replace`, `hash`, `shift_dates`, `format_preserve` | partial — surrogates by default, `--placeholder-labels` to opt out; no user-selectable method set (see D-032) |
| Locale-aware surrogates | yes, Faker; **no `tr -> tr_TR` row is published**, so Turkish `replace` has no documented locale mapping | yes, Turkish-first |
| Checksum-valid synthetic IDs | yes, for the providers their docs list (CPF, CNPJ, BSN, NIR, Codice Fiscale, NIE, Aadhaar, Steuer-ID, NPI, MRN); **no Turkish TCKN/VKN/IBAN surrogate provider is listed** | yes for Turkish IDs |
| Deterministic / consistent surrogates | yes (`consistent`, `seed`, blake2b keying) | yes (keyed BLAKE2s, D-024) |
| Keyed surrogate vault with HMAC | yes (`SurrogateVault`) | partial — L5 keys on a keyed digest (D-024), but `Span::text_hash` is still an unkeyed 64-bit FNV-1a and is brute-forceable from a span map. Their design is better. |
| Per-patient HMAC date shifting | yes, bounded, key never persisted | no |
| Format-preserving dates | yes | yes — and we measured the cost: surrogate length correlates with the original at r = 0.8867 for `DATE_ADMISSION` (n=155), 0.8516 for `DATE_BIRTH` (n=90) and 1.0000 for `DATE_DEATH` — the last over **n=6**, which is too few to headline, so the two large-n figures are the ones to read (D-028) |
| Round-trip re-identification | yes, `keep_mapping=True` + `reidentify()` | yes, through the MCP gateway span map (D-025) |
| Custom deny/allow recognizers | yes, allow-list wins unconditionally over deny-list *and* model | by-design-different — context-sensitive allowlisting with graded escalation, precisely because an unconditional allow-list can drop a real name whose surface collides (D-023, resolving D-010). OpenMed's allow-list has the same shape and the same hazard; we cite it as prior art, not as an attack. |

### 3.3 Surfaces, formats, operations

| Capability | OpenMed | deid-tr |
|---|---|---|
| Python API | yes, large | no — `bindings/python` exists but is excluded from the cargo workspace and is not built here |
| Native CLI | yes (`openmed redact-dataset`, …) | yes (`deid mask`, `deid update`, `deid version`) |
| MCP / stdio gateway | not documented | yes (`bindings/mcp`, stdio only, no socket — D-026) |
| REST service | yes, FastAPI, loopback-documented | yes — `deid-serve` (`bindings/service`), binds `127.0.0.1` with no flags; a non-loopback bind needs `--expose` AND a bearer token AND a startup warning, and an all-interfaces address is refused unconditionally (D-035). Routes: `/health`, `/entities`, `/analyze`, `/pii/extract`, `/deidentify`, `/reidentify`, `/batch` |
| gRPC | yes | no |
| Browser / WebGPU | yes | partial — `bindings/wasm` compiles and `bindings/wasm/panel` is a fully client-side panel served over loopback by `just serve-panel`, loading nothing from a network origin; no WebGPU path, no installable PWA, and no model to run |
| Apple MLX / Swift / iOS | yes | no |
| Android / Kotlin | yes | no |
| React Native | yes | no |
| Docker / SageMaker / Kafka / Spark / Dask / DuckDB | yes | no |
| Batch and dataset redaction (CSV/JSONL/Parquet) | yes | partial — `deid mask --batch DIR --out DIR` de-identifies a directory through the shipped CLI, writing a `manifest.jsonl` record for every entry and exiting non-zero if any item failed. It treats each file as UTF-8 **text**: it does not parse CSV or JSONL structure, does not classify PHI columns, and has no Parquet path |
| OCR (Tesseract, PaddleOCR, EasyOCR, docTR) | yes | no |
| DOCX / EPUB / Markdown / AsciiDoc | yes | no — DOCX is implemented in the `deid-tr-files` library, which **no shipped binary links**, so by this table's own rule it is not a capability yet. No EPUB, Markdown or AsciiDoc handler exists |
| PDF redaction with text-layer leakage verification | yes | no — implemented in the `deid-tr-files` library (content-stream removal, full rewrite, re-open-and-verify, refusal on scanned pages, per D-033) and **reachable from no shipped binary**. Nobody can run it, so it does not count |
| DICOM header + burned-in pixel redaction | yes | no |
| FHIR R4 / SMART-on-FHIR / HL7 v2 / CDA / OMOP | yes | no |
| Chat-log and vCard/iCalendar redaction | yes | no |
| Third-party adapters (Presidio, PHILTER, pyDeid, GLiNER-BioMed, LangChain, spaCy) | yes | no |

### 3.4 Evaluation and assurance

| Capability | OpenMed | deid-tr |
|---|---|---|
| Evaluation tooling breadth | very large (`openmed/eval/`, `openmed/risk/`, release gates, evidence bundles) | smaller |
| **Published Turkish evaluation numbers** | **none** — v1 cards carry the Arabic numbers; the ONNX derivative carries none | yes, in full, including every failure — section 6 |
| Public Turkish clinical gold benchmark | none published that we could find | yes, 190 documents / 1,538 direct spans, append-only |
| Three separate headline numbers, never blended | no (blended F1 on cards) | yes |
| Gates a null detector cannot pass | not documented | yes |
| Metric provenance checking (which masker produced the attacked output) | not documented | yes (D-029) |
| Model cards generated from an eval artifact, never hand-written | tooling exists (`model_card.py`); whatever produced the v1 Turkish cards emitted the Arabic `model-index` block onto a Turkish repo | by-design-different — I5 forbids any other path; we have no cards because we have no models |
| Adversarial red team over 7 attack classes | risk probes exist (membership, linkage, k-anonymity) | partial — all 7 classes run and 6 of 7 breached in the run named at the top of this document, but only 5 of 7 have a fixture written to probe them deliberately; `structural_leakage` and `format_tells` have none, and a class that is only attacked incidentally is not a defended one |
| Air-gapped test gate | local-path `local_files_only=True` supported | yes, `just test-airgapped`, zero network syscalls in `core/` |

---

## 4. Where our design is deliberately more conservative, and what it costs

Three of these are choices, not accidents, and each one is paid for.

**Union for recall means we over-mask, on purpose.** L1, L2 and L3 propose independently and
`union_widest` drops nothing, including a span exactly one detector saw. There is no majority vote
anywhere in the flagging path, because a converging council that out-votes the single detector that
saw an identifier is a breach machine. The cost is precision, and it is measurable: our micro
precision in the run named at the top of this document is 0.8863, meaning roughly one in nine masked
spans is not a gold identifier. It also costs money — our own measurement found the L4 adjudicator
escalation rate is **40.0%** of routed candidates (268 of 670), not the 2-5% the project brief
assumed (D-027). We corrected the brief rather than the constant, because moving
`ESCALATION_CONFIDENCE_MAX` to make the number look right would have been tuning the metric.

That 40.0% carries a caveat this document owes the reader, since it is the one figure here that is
**not** from the run named at the top. It comes from
`core/src/route/mod.rs::corpus_measurement::report_the_router_escalation_rate_over_routed_candidates`,
printed on every test run, and that measurement currently walks **178 records** while the eval
corpus is 190 documents. It has not been re-measured over the 12 documents added since. Treat it as
a figure for the smaller corpus, not for the one section 6 scores.

**The medical allowlist is context-sensitive and therefore heuristic.** Masking `carcinoma`
destroys the note, so a negative vocabulary is mandatory. But `Deva` is both a Turkish given name
and a pharmaceutical brand; `Costa` is both a Latin anatomical term and a common surname. An
unconditional allow-list — which is what OpenMed ships and what we originally specified — will
deterministically keep the real name and leak it, and recall silently losing to an allow-list is
exactly what I2 forbids. Our resolution (D-023) escalates colliding surfaces to the adjudicator
using title, casing and position evidence instead of short-circuiting. The cost is honest: **that
evidence is heuristic**. It will be wrong in both directions, it has no checksum behind it, and its
error rate is bounded only by the medical-term FP gate and the per-entity recall floors. We also
measured residual allowlist drift rather than assuming it away, and drift is legal only where
`DRIFT_EXCEPTIONS` records why (D-019).

**The Expert Determination tier trades clinical readability for privacy.** L3 masks meanings, not
entities. Removing "works at the Central Bank" or "his wife is a well-known judge" removes clinical
and social context that a treating clinician or a downstream researcher may actually need. There is
no way to mask a quasi-identifier without removing information, because the information *is* the
identifier. That is why the tier is opt-in and Safe Harbor is the default: opting into that trade
should be an explicit decision by someone who knows their own use case, not a default we chose for
them. It is also the expensive tier — a full-document local-LLM read per note, against ~10ms for
L1/L2 — and it needs a host that can run a local model at all, which rules out most mobile devices
and most browsers.

A fourth cost, less principled and more just a bill: I1 forbids the L3 model from being a cloud API.
That gives up the best available reasoning models and confines us to whatever a quantized local
model can do. We accept it because sending PHI to a cloud LLM in order to detect its PHI defeats the
purpose of the product.

---

## 5. When to use which

**Use OpenMed today for almost everything, and certainly for anything that needs names masked.**
Specifically:

- Any Turkish clinical text where patient or clinician names must be removed. deid-tr will not
  remove them. This is not a close call.
- Any language other than Turkish.
- Any workflow involving PDFs, DOCX, scanned documents, DICOM, FHIR, HL7, CSV/Parquet datasets, or
  chat logs.
- Any deployment needing iOS, Android, browser, MLX, gRPC or SageMaker. (deid-tr does now ship a
  loopback-only REST service, `deid-serve`; it detects exactly what the CLI detects, which is no
  names, so it does not change this recommendation.)
- Any situation where you need something working this week.

If you use OpenMed for Turkish, two things are worth doing on your own data, and their own ONNX card
now says the same: **evaluate recall yourself**, because no Turkish number is published for those
checkpoints; and **check which backbone you are loading**, because most of the family is built on
English-only or uncased backbones, and an uncased backbone destroys the İ/I/ı/i distinction that
carries most of the name signal in Turkish. Prefer the multilingual-backbone variants (`BigMed`,
`mSuperClinical`, `mLiteClinical`, `ClinicalBGE-Large-568M`, `SnowflakeMed`, `QwenMed`) for Turkish.

**Use deid-tr today only for:**

- Turkish structured-identifier redaction where names are not present, or are handled some other
  way: TCKN, VKN, SGK, IBAN, MRN, phone, email. These are the rule-detectable identifiers, and they
  are the only things this pipeline currently masks.
- Benchmarking. `eval/gold` and `eval/adversarial` are usable by anyone, including as a test set for
  OpenMed's Turkish checkpoints. We would rather someone measured them than that nobody did.

**Consider deid-tr later, if and only if it earns it, for:** Turkish clinical text where a
compliance officer needs a per-entity recall number they can sign, and for narrative re-identifica-
tion risk that token classification cannot reach. Neither capability exists today.

---

## 6. Our current measured numbers, in full, including the failures

Run: detector `pipeline`, tier `safe_harbor`, corpus `eval/gold` + `eval/adversarial`
(190 documents, 1,538 direct gold spans, 229 quasi gold spans, 1,293 allowlist-term annotations).

Reproduce exactly this, in this order:

```
python3 -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json
python3 eval/run.py --detector pipeline --redteam-report eval/results/redteam.json
```

Run id `20260719T234410Z-pipeline`, `eval_sha` `uncommitted`. Every figure in 6.1 and 6.2 is
printed from `eval/results/20260719T234410Z-pipeline.json`.

### 6.1 Headline

| Metric | Observed | Gate | Verdict |
|---|---|---|---|
| Micro F1, direct identifiers (relaxed) | **0.5418** | >= 0.95 | **FAIL** |
| Micro F1, direct identifiers (strict) | 0.5400 | — | reported only |
| Micro recall, direct identifiers | **0.3901** | — | reported only |
| Micro precision, direct identifiers | 0.8863 | — | reported only |
| Recall, HIPAA-critical (NAME, ID, CONTACT) | **0.4269** | >= 0.98 | **FAIL** |
| Document leak rate (documents holding >= 1 direct identifier) | **0.9451** (155 of 164) | <= 0.02 | **FAIL** |
| Document leak rate (all 190 documents) | 0.8158 | — | not the gated number |
| Medical-term FP rate, annotated denominator | 0.0000 | — | reported |
| Medical-term FP rate, vocabulary denominator | 0.000488 | <= 0.005 | **PASS** (gated on the worse of the two, D-018) |
| Contextual coverage (diagnostic only) | 0.0000 | — | not a validated score |
| **Contextual re-ID rate, red-team measured** | **0.8983** | <= 0.05 | **FAIL** |
| Sight-unseen recall drop | -0.0213 | <= 0.05 | **PASS** |
| Checksum-validated ID precision | null | 1.000 | **UNENFORCEABLE** |

**Gate tally: 10 PASS, 28 FAIL, 1 UNENFORCEABLE, of 39.** `all_gates_passed` is false whenever any
gate is unenforceable: an unevaluated gate has not been met.

The contextual re-ID gate is enforceable in this run and fails at 0.8983, because the red-team
report scored above was produced by the pipeline masker from this same tree. That is D-029 working
as designed — with the caveat recorded at the top of this document, that the `eval_sha` it matched
on was `uncommitted` on both sides.

One gate is unenforceable, and it does not mean "passed":

- `checksum_id_precision` is **unmeasurable by construction on this corpus**, not a detector result.
  I8 forbids a checksum-valid Turkish ID from existing anywhere in the repository, so all 128
  eleven-digit runs in the gold set fail their check digits; every TCKN therefore escalates at
  confidence 0.50 with `Merged::is_protected()` unarmed. The protection path is exercised instead by
  `core/tests/checksum_protection_armed.rs`, which generates checksum-valid identifiers at runtime
  and never writes them to disk (D-030). A consequence worth stating plainly: **our TCKN recall of
  1.0000 below is achieved by the regex shape, not by the checksum**, because on this corpus no
  checksum passes.

The contextual re-ID rate of 0.8983 means **159 of the 177 attackable documents were re-identified
from the masked output**. The denominator is the attackable documents, not all 190, because a
fixture with no gold span cannot be re-identified by a masking failure and would dilute the rate
without any privacy having been achieved; over all 190 documents the rate is 0.8368. The rate is
this high for the reason every section of this document gives: names are not masked, so most
documents are re-identifiable directly.

Two of the seven L6 attack classes, `structural_leakage` and `format_tells`, have **no adversarial
fixture dedicated to them** — 0 fixtures each, against 3, 2, 2, 3 and 2 for the other five. They are
not unreported: the attacks run over the whole corpus, and in this run both breached
(`structural_leakage` 122 documents, `format_tells` 55). What is missing is a fixture written to
probe each class deliberately, so what those two classes report is whatever the corpus happens to
expose rather than what an author tried to break. An unattacked case is not a defended one.

### 6.2 Per-entity recall, all 32 gated labels

| Label | Recall | Floor | Verdict |
|---|---|---|---|
| TCKN | 1.0000 | 0.98 | PASS |
| VKN | 1.0000 | 0.98 | PASS |
| SGK_NO | 1.0000 | 0.98 | PASS |
| IBAN | 1.0000 | 0.98 | PASS |
| MRN | 1.0000 | 0.98 | PASS |
| PHONE | 1.0000 | 0.98 | PASS |
| EMAIL | 1.0000 | 0.98 | PASS |
| DATE_BIRTH | 1.0000 | 0.98 | PASS |
| DATE_DISCHARGE | 0.7917 | 0.97 | FAIL |
| DATE_DEATH | 0.6667 | 0.97 | FAIL |
| DATE_ADMISSION | 0.5742 | 0.97 | FAIL |
| **PATIENT_NAME** | **0.0000** | 0.98 | **FAIL** |
| **CLINICIAN_NAME** | **0.0000** | 0.98 | **FAIL** |
| **RELATIVE_NAME** | **0.0000** | 0.98 | **FAIL** |
| FACILITY_NAME | 0.0000 | 0.96 | FAIL |
| ADDRESS_STREET | 0.0000 | 0.98 | FAIL |
| ADDRESS_DISTRICT | 0.0000 | 0.96 | FAIL |
| ADDRESS_CITY | 0.0000 | 0.95 | FAIL |
| POSTAL_CODE | 0.0000 | 0.97 | FAIL |
| AGE_OVER_89 | 0.0000 | 0.97 | FAIL |
| ACCOUNT_NO | 0.0000 | 0.98 | FAIL |
| HEALTH_PLAN_ID | 0.0000 | 0.98 | FAIL |
| CERTIFICATE_NO | 0.0000 | 0.98 | FAIL |
| PASSPORT_NO | 0.0000 | 0.98 | FAIL |
| LICENSE_PLATE | 0.0000 | 0.98 | FAIL |
| VEHICLE_ID | 0.0000 | 0.98 | FAIL |
| DEVICE_ID | 0.0000 | 0.98 | FAIL |
| BIOMETRIC_ID | 0.0000 | 0.98 | FAIL |
| PHOTO_REF | 0.0000 | 0.96 | FAIL |
| IP_ADDRESS | 0.0000 | 0.98 | FAIL |
| URL | 0.0000 | 0.98 | FAIL |
| OTHER_UNIQUE_ID | 0.0000 | 0.98 | FAIL |

The shape of that table is most of the state of the project, but not all of it, and an earlier
revision of this document overstated it. It said "everything with a rule behind it is at or near
1.0000". **That is false, and the counter-examples are in the table above.** Three labels are
rule-detected and nowhere near 1.0000: `DATE_DISCHARGE` 0.7917, `DATE_DEATH` 0.6667 and
`DATE_ADMISSION` 0.5742, all three below their floors. The accurate statement is narrower: every
label with a deterministic *format* — TCKN, VKN, SGK_NO, IBAN, MRN, PHONE, EMAIL — is at 1.0000,
and so is `DATE_BIRTH`. Everything requiring a model is at exactly 0.0000, because there is no
model. The three name labels — 531 gold spans between them — are the reason this document says, in
every section, that deid-tr masks zero names.

The date family is the interesting middle, and it is the counter-example above: `DATE_BIRTH` at
1.0000 and `DATE_ADMISSION` at 0.5742 share the same rule, because L1 emits a role-less `DATE` and
never guesses which of the four roles a date is (D-021). A rule can find a date; it cannot tell you
whether the date is an admission or a discharge, and the recall floors are per role. So the gap is a
scoring artifact of role assignment rather than four different detectors — which explains the number
without excusing it, because the gold set asks for the role and the pipeline does not supply it.

---

## 7. What would change this comparison

One thing: a trained, evaluated L2 for Turkish, published with per-entity recall against this gold
set. Until then, section 5's recommendation stands unchanged — for masking names in Turkish clinical
text today, use OpenMed.
