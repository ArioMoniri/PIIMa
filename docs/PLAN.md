# PLAN — deid-tr

Rewritten rarely. Holds the goal, the reason this is winnable, the milestones, the architecture, the
assurance tiers, the runtime matrix, and the scope boundaries. Operational detail lives in
`CLAUDE.md`; current work lives in `docs/TASKS.md`.

## Goal

Build the highest-assurance open-source PHI/PII de-identification pipeline for **Turkish clinical
text**, and the benchmark that proves it.

North star: a compliance officer at a Turkish hospital reads our eval report and signs off on
sending clinical text to a cloud LLM.

## Why this is winnable (findings verified 2026-07)

- **No public Turkish clinical de-identification gold benchmark exists.** There is nothing to
  compare against, so the first credible benchmark defines the field's vocabulary.
- **No validated Turkish clinical de-id model exists.** Checkpoints exist; validated ones do not.
- **Nearest prior art — TEHR, *Applied Sciences*, February 2026** — reports base models scoring
  single-digit to mid-teens F1 on Turkish clinical NER *before* fine-tuning, and explicitly flags
  non-English de-identification as underrepresented. The floor is very low and publicly documented.
- **The incumbent's process is the opening.** OpenMed publishes roughly 3,500 Hugging Face
  checkpoints, including Turkish PII models. Their Turkish cards carry `language: ar`, Arabic widget
  examples, and Arabic evaluation metrics, on English-only uncased backbones (`deberta-v3-small`,
  `distilbert-base-uncased`) that cannot tokenize Turkish. The published Turkish accuracy numbers
  are Arabic numbers. All of it is pure token classification with zero contextual capability. This
  is a process failure in card generation, cited as prior art, never as an attack on the authors.
- **Real Turkish backbones exist and are free:** BERTurk (`dbmdz/bert-base-turkish-cased`, 35GB
  corpus, 128K vocab), BioBERTurk, ConvBERTurk, mDeBERTa-v3, XLM-R.
- **KVKK — Turkey's Personal Data Protection Law No. 6698**, under which health data is a special
  category, is the regulatory hook that turns this from a research artifact into a procurement item.

**Strategy statement: we win on validation, and on catching what NER cannot. Not on volume.**
The incumbent has more checkpoints than we will ever publish. We have a gold benchmark they cannot
retrofit, a card pipeline whose numbers are traceable to a committed eval run, and a contextual
quasi-identifier layer that token classification is structurally unable to reach.

## Milestones M0-M7

| Milestone | Delivers | Layers |
|---|---|---|
| **M0** | Golden set v0, entity schema, thresholds, eval harness, air-gap proof, tokenizer gate, incumbent baseline | none — the metric comes first |
| **M1** | Deterministic rules: regex plus checksum for Turkish ID formats | L1 |
| **M2** | MCP gateway with a round-trip span map — **first shippable** | L1 + L2 |
| **M3** | NER ensemble across gated Turkish backbones, BIOES/Viterbi decode, union merge | L2 |
| **M4** | Local-LLM contextual sweep and the consensus router/adjudicator | L3 + L4 |
| **M5** | Consistent format-preserving surrogates and the re-ID red team | L5 + L6 |
| **M6** | Surfaces: CLI, then Tauri desktop/mobile, then the fully client-side PWA panel | all |
| **M7** | Publish: evaluated checkpoints plus `deid-tr/TurkDeID-Bench` | all |

M0 first, always. A model without a metric is not progress.

## Architecture

```
        Clinical note  (Turkish + Latin/English medical register)
                          |
 [L1] Deterministic rules — regex + checksum     direct identifiers, fixed format   always  ~1ms
                          |
 [L2] NER ensemble — UNION                       direct identifiers, token-level    always  ~10ms
                          |
 [L3] Contextual sweep — LOCAL LLM, full-doc     quasi-identifiers in narrative     tier-gated
                          |
 [L4] Router + adjudication — CONSENSUS          argue down false positives         flagged spans only
                          |
 [L5] Consistent surrogates — format-preserving
                          |
 [L6] Re-ID red team — adversarial risk score    validates L3
                          |
       De-identified text + span map + audit log
```

Two aggregation rules, one per error type: **UNION over L1+L2+L3 for recall** (never majority-vote a
span away), **CONSENSUS at L4 for precision** (only over spans already flagged, and L4 may only
demote, never invent). Rationale in `docs/DECISIONS.md` D-002.

Code layout: a pure Rust `core/` (rules, checksums, span algebra, BIOES decode, surrogates, audit;
no I/O, no network; compiles native and `wasm32`), with `bindings/{cli,python,mcp,tauri,wasm}`.
Inference sits behind `trait Detector` (L2) and `trait Contextual` (L3) so only the forward pass
swaps between targets — see D-006.

## Assurance tiers mapped to the HIPAA legal standards

| Tier | Legal standard | Layers | Cost | Default |
|---|---|---|---|---|
| **Safe Harbor** | Remove the 18 enumerated direct identifiers | L1 + L2 + L4 + L5 (+L6 in eval) | ~10ms/note; adjudicator sees a measured **40.0% of routed candidates** (268/670), not the 2-5% originally assumed — D-027 | yes |
| **Expert Determination** | A qualified analysis concludes re-identification risk is very small, accounting for quasi-identifiers | adds L3, a full-document local-LLM sweep | one full-document LLM read per note | opt-in |

The Safe Harbor cost figure carries two denominators that must never be swapped: **routed
candidates** (spans that reached the router — 268/670 = 40.0%) and **vocabulary occurrences**
(every mention of a class C medical term in the corpus text — 74/1910 = 3.87%, D-023). Both are
measured on every test run and neither bounds the other.

Expert Determination is opt-in because aggressive contextual masking trades clinical readability for
privacy, and because L3 requires a host that can run a local LLM. Its success metric is the red-team
contextual re-ID rate, not a token-level F1 (D-008).

## Runtime backends

| Surface | L1/L2 (detector) | L3 (contextual LLM) |
|---|---|---|
| CLI · MCP · Python | native `ort`: CPU default, CUDA/CoreML/DirectML if present | local LLM (`candle`/`ort`), same execution provider |
| Tauri desktop | native `ort`, same EP selection | local LLM, native |
| Tauri mobile | native `ort` (CoreML / NNAPI) | small local LLM if the device allows, else Safe Harbor only |
| Browser PWA / panel | `onnxruntime-web`: WebGPU if available, WASM/CPU fallback | WebGPU plus a small model only; otherwise Safe Harbor only |

Backend detection is automatic and logged once at startup — offsets and types only, never text.

## Weights download policy

Weights are **never** fetched lazily at inference (I1) and **never** live inside `core/`. Exactly two
supported paths:

1. **Bundled** in the release artifact, or
2. **One explicit fetch**: `deid pull`, with a progress bar and a printed checksum.

**Air-gapped path:** `deid pull --from ./bundle` installs from local media with the same checksum
verification, so a hospital network that permits no egress reaches the same verified state as a
connected one. In the browser, weights are fetched once from our own static origin into the service
worker cache; the panel never uploads text.

## OUT OF SCOPE

Recorded so that a future session does not silently expand the surface.

- **Languages beyond Turkish plus the Latin/English medical register.** Our defensible claim is a
  validated Turkish benchmark; adding a second clinical language multiplies the gold-set and red-team
  cost before the first one is proven.
- **Federated learning of model weights.** Gradient inversion reconstructs training inputs and models
  memorise rare strings, so shipping weights off-site is a privacy risk wearing a privacy-sounding
  name. We federate the *eval* instead — see D-004.
- **Any hosted service that touches PHI.** An upload endpoint contradicts I1 and destroys the reason
  a compliance officer would trust the tool at all; every surface is client-side or on-premises.
