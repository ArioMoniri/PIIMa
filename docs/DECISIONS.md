# DECISIONS — architecture decision record log

**Append-only.** Entries are never edited and never deleted. A decision that turns out to be wrong is
**superseded** by a later entry that names the id it replaces; the original stays in place so that a
future session can see what was believed and why it changed. Correcting a typo in a shipped entry is
still an edit — do not.

Each entry carries: id, title, date, status, Decision, Alternatives considered, Rationale, and
Consequences. **Consequences must include the negative ones.** An ADR with no downside listed is not
an ADR; it is advocacy, and it teaches a future session nothing about what it is paying.

Status values: `ACCEPTED`, `OPEN` (decision not yet made; the entry records the conflict),
`SUPERSEDED by D-NNN`.

---

## D-001 — Benchmark before model

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** M0 builds the entity schema, the golden set, the thresholds and the eval harness. No
detection code is written until `just eval` can report total failure on an empty detector.

**Alternatives considered.**
1. Fine-tune a Turkish backbone first and build evaluation around whatever it produces. Fastest path
   to a visible artifact.
2. Adopt an existing de-identification benchmark and translate it. Cheaper than authoring a gold set.
3. Ship rules first (L1) since they are deterministic and need no corpus.

**Rationale.** A model without a metric is not progress; it is an unfalsifiable claim. Building the
harness after the model guarantees the harness is shaped to flatter the model, which is exactly the
process failure visible in the incumbent's Turkish cards. Translating an English benchmark imports
none of what makes Turkish clinical text hard — agglutinated names, İ/ı casing, code-switched Latin
roots with Turkish suffixes — so it would certify the wrong thing. Building rules first is defensible
but leaves no way to prove they helped. The benchmark is also the **distribution vehicle and the
moat**: datasets outlive the models trained on them, and a public scoreboard cannot be faked the way
a model card can.

**Consequences.**
- Nothing is demonstrable for the whole of M0. There is no demo, no checkpoint, no number that goes
  up. This is the single hardest milestone to stay honest through.
- 100 gold-annotated synthetic notes plus 30 adversarial fixtures is expensive hand work with no
  intermediate reward.
- Hosting a public benchmark creates a maintenance obligation and a submissions surface we will have
  to police, indefinitely.
- If the schema is wrong, every fixture annotated against it must be revisited, and I7 forbids
  deleting them.

---

## D-002 — Union for recall (L1+L2+L3), consensus for precision (L4)

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** Spans from L1, L2 and L3 are combined by **UNION**: anything flagged by any layer is
masked. Debate happens only at **L4**, only over spans that are already flagged, and L4 may only
demote `Mask` -> `Keep`, never invent a span.

**Alternatives considered.**
1. Majority vote across all detectors, a standard ensemble aggregation.
2. Confidence-weighted averaging with a single global threshold.
3. A single strong model, no ensemble, and no aggregation problem at all.

**Rationale.** The two error types are asymmetric: **a missed identifier is a breach; an over-mask is
a papercut.** Aggregation therefore cannot be symmetric either. Majority voting drops exactly the
spans that only one detector flagged — which is the definition of the marginal catch, the span the
other models missed. A converging council is a breach machine. Consensus is safe only where being
wrong costs clinical utility rather than privacy, and that is precisely the L4 position: the span is
already flagged, and the question has narrowed to "is this a person, or a Latin/English medical term,
drug or anatomy?"

**Consequences.**
- Precision at the union point is poor by construction. Every downstream component must be designed
  to absorb a noisy input rather than assume a clean one.
- L4 becomes load-bearing for usability. If L4 is weak, output is over-masked to the point of being
  clinically unreadable, and the product fails for a reason that is not a privacy failure.
- L4 needs guardrails that are themselves a source of bugs: never demote a checksum-valid span, never
  demote a multi-model-agreed span, only demote on allowlist or single low-confidence source.
- Adding a noisy detector to the ensemble can only increase the over-masking load; there is no
  automatic mechanism that suppresses a bad member.
- The allowlist short-circuit inside L4 creates a recall hole. See D-010, which is OPEN.

---

## D-003 — Model cards are generated from eval artifacts, never hand-written

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** Every model card is produced by `scripts/publish.py` from a committed
`eval/results/<run_id>.json`. No human writes or edits a card. No card ships whose `eval_sha` does not
match a committed eval run. Invariant I5.

**Alternatives considered.**
1. Hand-written cards with a review checklist.
2. A template with human-filled metric fields.
3. Generated cards plus permitted manual edits for prose sections.

**Rationale.** The incumbent's Turkish PII checkpoints carry cards declaring `language: ar`, with
Arabic widget examples and Arabic evaluation metrics, on English-only uncased backbones that cannot
tokenize Turkish — their published Turkish accuracy numbers are Arabic numbers. That is not
dishonesty and is not being alleged as such; it is what happens when card generation is a templating
step decoupled from the run that produced the numbers, at a scale of roughly 3,500 checkpoints. The
failure is in the **process**, and a process failure is fixed by removing the human write path, not by
adding a review step that scales worse than the publishing does. Option 3 fails because any manual
edit path re-opens exactly the decoupling being closed.

**Consequences.**
- Cards read mechanically. We give up persuasive prose in the highest-visibility surface we have.
- Any change to card presentation is a code change with a review cycle, not a text edit.
- Publishing is blocked whenever the eval pipeline is broken, even for an unrelated fix.
- The generator becomes a single point of failure: a bug in it corrupts every card at once.

---

## D-004 — No federated learning of weights; federate the eval instead

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** We do not federate model training. Participating sites run the evaluation locally and
report **DP-noised aggregate metrics under secure aggregation**. Weights and gradients never leave a
site. Raw text never leaves a site.

**Alternatives considered.**
1. Standard federated learning: sites train locally, a coordinator averages weight updates.
2. Federated learning with differential privacy applied to the gradients.
3. Centralised training on data pooled under DUAs.

**Rationale.** Naive federated learning is a privacy risk wearing a privacy-sounding name: gradient
inversion reconstructs training inputs, and models memorise rare strings — and a rare string in this
domain is a patient's name. Adding DP noise to fix that degrades recall, which is the exact property
that prevents breaches (I2), so option 2 spends the product's core metric to defend against a leak
that **local-only training prevents for free**. Option 3 concentrates PHI, which contradicts I1.
Federating the eval keeps every trade on the right side: each site learns how the pipeline performs
on its own distribution, and the network learns only noised aggregates.

Secure aggregation is also the **participation incentive**, not just a privacy control. No hospital
volunteers for a benchmark where it might be publicly identified as the worst performer. SecAgg makes
that outcome cryptographically impossible: the coordinator can compute the aggregate without learning
any individual site's contribution, so joining carries no reputational downside.

**Consequences.**
- We forgo any accuracy gain from multi-site training data. A well-executed FL system would likely
  produce a better model than ours.
- Site-level diagnostics are limited by design: when the aggregate looks bad we cannot ask which site
  is dragging it down.
- DP noise on the aggregates makes small-sample results genuinely noisy; sites with few notes get
  metrics of limited use to them.
- Secure aggregation adds cryptographic machinery, key management and a minimum-cohort requirement
  before any result can be published at all.

---

## D-005 — Feedback asymmetry: false positives are exportable, false negatives are not

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** Invariant I4. A false **positive** correction (we masked something that was not PHI) is
exportable as a **bare span with no surrounding context**. A false **negative** correction (we missed
real PHI) stays local **forever**; only the abstracted *pattern* may ever be exported, never the
instance.

**Alternatives considered.**
1. Symmetric feedback: collect both error types, review before upload.
2. Collect both, but hash or pseudonymise the false negatives.
3. Collect nothing at all.

**Rationale.** The two corrections are not the same kind of object. "You masked `carcinoma`" contains
a medical term. "You missed `Ayşe Yılmaz`" **is a patient name** — the feedback channel becomes a PHI
exfiltration channel, and the miss report is strictly more sensitive than the original note because it
is pre-extracted. Human review (option 1) does not scale and fails exactly when the reviewer is tired.
Hashing (option 2) does not help: a short name against a known salt is enumerable, which is the same
weakness recorded against `text_hash: u64` in D-010. Option 3 forgoes the false-positive signal, which
is safe to collect and is the main lever on the medical-term FP gate.

**Consequences.**
- Our most valuable training signal — real misses — is the one signal we can never centralise. Recall
  improvements must come from synthetic adversarial fixtures and red-teaming instead.
- "Export the pattern, not the instance" needs a definition and a reviewer, and pattern abstraction is
  itself a leak surface if done carelessly.
- Two separate feedback code paths with different guarantees, and a permanent risk that a future
  contributor unifies them for tidiness.

---

## D-006 — Rust core with inference behind a trait

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** All deterministic logic — rules, checksums, span merge, BIOES decode, surrogates, audit
— lives once in Rust in `core/`, compiling to native and `wasm32`. Inference sits behind
`trait Detector` (L2) and `trait Contextual` (L3). Only the forward pass has per-target
implementations.

**Alternatives considered.**
1. A Python core with the browser served by a separate JavaScript/TypeScript reimplementation.
2. Rust native only, no browser target, with the panel calling a local server.
3. A single Rust inference stack, accepting whichever targets it supports.

**Rationale.** Option 3 was ruled out by a hard external fact: `ort` dropped
`wasm32-unknown-unknown` support, so one inference stack cannot cover both native and browser.
Options 1 and 2 both mean the detection logic exists twice, or the client-side promise is dropped.
The split is drawn where correctness risk lives: **a matmul is a matmul.** Two inference backends
produce numerically different logits but carry no independent correctness risk in the *rules*; two
regex implementations, two TCKN checksums or two span-merge routines absolutely do, and they diverge
silently and asymmetrically in the direction of missed PHI. So rules, checksums, span merge and
surrogates stay single-sourced, and only the backend swaps. `tokenizers` (HF, Rust) builds for both
targets, so tokenisation — where offset bugs are born — is also shared.

**Consequences.**
- Two inference backends to maintain, test and keep behind a stable trait boundary.
- Numeric results are not bitwise identical across backends. This collides directly with the
  `eval_sha` reproducibility gate for any L3-dependent metric — tracked as an open issue in D-010.
- Rust plus WASM plus PyO3 plus Tauri is a steep contributor on-ramp, which will limit outside
  contributions.
- Everything in `core/` must be written to the constraints of the most restrictive target: no I/O, no
  threads assumed, no network.

---

## D-007 — Two assurance tiers; contextual detection runs on a LOCAL LLM

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** **Safe Harbor** (L1 + L2 + L4 + L5) is the default: the 18 direct identifiers, fast and
fully on-device, runnable everywhere including the browser. **Expert Determination** adds **L3**, a
full-document contextual sweep by a **local** quantized LLM, and is opt-in.

**Alternatives considered.**
1. One tier that always runs the contextual sweep. Simpler product, strictly safer output.
2. One tier, direct identifiers only. Simplest, and matches what every competitor offers.
3. Contextual sweep via a cloud LLM API, for quality and for hosts that cannot run a local model.

**Rationale.** The two tiers are not an arbitrary product split; they mirror the two HIPAA
de-identification standards, which is what a compliance officer is actually reading against. Option 2
gives up the capability that separates us from token-classification incumbents. Option 1 forces every
user to pay both the compute cost of a full-document LLM read and the readability cost of aggressive
contextual masking — masking "works at the Central Bank" and "his wife is a judge" removes clinical
context a downstream reader may need, so the tradeoff must be the user's to make, explicitly.

Option 3 is rejected outright: **sending PHI to a cloud model to detect PHI defeats the product's
reason to exist** and violates I1's corollary directly. A cloud SDK import or an `https://api.`
literal under `core/context/` is blocked by `guard_invariants.sh`, not left to review.

**Consequences.**
- Expert Determination is unavailable on hosts that cannot run a local LLM — some mobile devices, and
  browsers without WebGPU. Those surfaces get Safe Harbor only, and must say so clearly.
- Our contextual quality is capped by what a small quantized local model can do, which is meaningfully
  below a frontier cloud model.
- Two tiers means two eval configurations, two sets of published numbers, and a permanent risk of a
  user reading a number from one tier and assuming it applies to the other.
- The tier a given output was produced under must be recorded in the audit log, or the numbers are
  uninterpretable after the fact.

---

## D-008 — Contextual quasi-identifiers are validated by the red team, not by a fixed F1

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** Class B (contextual quasi-identifiers) is **not** scored with a token-level F1. L3's
success metric is the **contextual re-identification rate** measured by the L6 red team, gated at
<= 5%. Class B spans in the golden set exist to make failures inspectable, not to compute a score.

**Alternatives considered.**
1. Annotate exact quasi-identifier spans and score F1 like any other entity class.
2. Score class B by document-level binary classification: does this note contain a quasi-identifier?
3. Skip evaluation of L3 and rely on human spot-checking.

**Rationale.** Narrative re-identification has no clean ground truth. Is the PHI "works at the Central
Bank", "the Central Bank", or the whole sentence including the tenure that narrows it? Two competent
annotators disagree, so any F1 computed over those spans is measuring annotation convention, not
privacy — and it would be a **false number**, precisely the failure mode D-003 exists to prevent.
What is measurable is the outcome that matters: after masking, can an adversary re-identify the
patient? That ties **detection (L3) directly to validation (L6)** and scores the thing the compliance
officer is asking about.

**Consequences.**
- L3 cannot be evaluated at all until L6 exists in M5. A whole layer sits unmeasured across M4.
- The re-ID rate depends on how good our red team is. A weak red team reports a flattering number,
  and the metric silently degrades as attackers get better while our attack suite does not.
- The metric is coarse: it says the pipeline failed, not which span it failed on. Debugging L3 needs
  separate tooling.
- Class B numbers are not comparable to any published NER benchmark, so we cannot claim a
  state-of-the-art result on them.

---

## D-009 — Gold spans are verbatim quotes plus an occurrence index, not integer byte offsets

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** Gold annotations record the **exact quoted substring** plus an **occurrence index**
(which appearance of that string, 0-based). `eval/build_gold.py` resolves quotes to byte offsets at
build time and **fails loudly** on any quote it cannot resolve — never silently skipping one.

**Alternatives considered.**
1. Hand-computed integer byte offsets in the fixture files.
2. Character offsets, converted to byte offsets at load time.
3. Inline markup in the note text (`[NAME]Ayşe[/NAME]`), stripped at load.

**Rationale.** Hand-computed byte offsets over multi-byte Turkish text are an error class that fails
in the worst possible direction: `ş`, `ğ` and `İ` are two bytes each, so a miscounted offset either
lands mid-character or points at the wrong span, and a gold span that fails to resolve gets dropped
from the denominator — **silently inflating recall**. An eval harness that quietly reports a better
number when its own fixtures are broken is worse than no harness. Option 2 has the same defect one
conversion later. Option 3 corrupts the note text itself, which is the artifact we most need to keep
pristine. Quotes also **mirror the L3 contract exactly**: we ask the model for a verbatim quote and
never for offsets, and re-anchor it ourselves (dropping anything that does not resolve). The eval
format and the runtime format then fail the same way, which means the same bug shows up in both.

**Consequences.**
- A build step is now required before eval. `just eval` depends on `build_gold.py`, and a stale build
  is a new failure mode that must be detected rather than tolerated.
- Duplicate quote strings within a note need an explicit occurrence index, which annotators will get
  wrong; the builder must validate the index range and refuse an out-of-range one.
- A fixture whose text is edited invalidates its quotes, and I7 forbids deleting the fixture to make
  the problem go away — the quote must be repaired.
- Resolution is O(occurrences) per span at build time, negligible now but linear in golden-set growth.

---

## D-010 — OPEN: allowlist versus recall precedence

- **Date:** 2026-07-19
- **Status:** **OPEN — blocking L4 design in M4**

**Decision.** None yet. This entry records the conflict so it is not rediscovered late.

**The conflict.** L4 checks the medical allowlist **first**, as a deterministic `Keep`. The L4
guardrail protects a span from demotion only when it is checksum-valid or multi-model-agreed. A NAME
span is **neither**: names have no checksum, and a single-model NAME span is common and legitimate. So
a single-model name span whose surface form collides with an allowlist entry is deterministically kept
and **LEAKED**. Real collisions:

- `Deva` — a Turkish given name and a Turkish pharmaceutical brand.
- `Costa` — Latin for rib and a common surname.

**Recall silently loses to the allowlist, which invariant I2 forbids.** Worse, it loses silently: the
span never reaches the adjudicator, so nothing logs a decision that could be reviewed.

**Alternatives considered.**
1. Remove the allowlist short-circuit; send every collision to the adjudicator. Correct on recall,
   but moves adjudication cost into the common path and risks over-masking common medical terms.
2. Strip colliding surface forms from the allowlist entirely. Trivially safe on recall; guarantees
   `carcinoma`-class false positives on any term that is also a name somewhere.
3. Rank by span source: a NER-sourced NAME always beats the allowlist. Simple, but hands full
   precedence to the noisiest detector.
4. Context-sensitive allowlisting (proposed direction).

**Proposed direction.** An allowlist entry may only demote a span when the surrounding evidence does
**not** independently mark it as a name. Evidence signals: an adjacent title (`Dr.`, `Op. Dr.`,
`Prof. Dr.`, `Uz. Dr.`, `Hemş.`, `Bey`, `Hanım`), casing, sentence position, and adjacent name tokens.
Collisions **escalate to the consensus adjudicator** instead of short-circuiting, so every collision
produces a logged decision.

**Consequences (of leaving it open, and of the proposed direction).**
- L4 cannot be designed until this is resolved, and **it must be resolved before any Safe Harbor tier
  release** — Safe Harbor is precisely the tier where NAME recall is the headline number.
- The proposed direction makes L4 stateful with respect to context, so its unit tests need whole
  sentences rather than isolated spans.
- Escalating collisions raises adjudicator traffic above the 2-5% budget assumed in the Safe Harbor
  cost model, by an amount nobody has measured.
- Every evidence signal is a Turkish-specific heuristic and therefore a source of locale bugs.

**Two further open issues, tracked here until they earn their own ADRs.**

1. **L3 determinism is not achievable bitwise** across the mandated multi-backend matrix. CUDA,
   CoreML, CPU and WebGPU produce different logits, and near-ties flip under floating-point
   nondeterminism. This collides with the `eval_sha` reproducibility gate for every L3-dependent
   metric, and no tolerance band has been defined.
2. **`text_hash: u64` is brute-forceable.** A 64-bit non-cryptographic hash of a short name lets an
   attacker holding the span map enumerate Turkish names against a known salt and confirm a patient's
   presence — partially defeating "never store the text". Wants a keyed HMAC with a secret salt, plus
   an explicit collision-handling policy for surrogate consistency.

---

## D-011 — Spans carry a detector identity, not only a layer

- **Date:** 2026-07-19
- **Status:** ACCEPTED
- **Implementation status:** decided, NOT yet implemented. `core/src/span.rs` is unchanged.

**Decision.** `Span` gains a detector-identity field alongside `source: Layer`. The dedup and
support-counting in `union_widest` (`core/src/span.rs:291`, dedup at `core/src/span.rs:308`) key on
that identity. The rules layer built in M1 must set it, and every future ensemble member must set a
distinct one.

**Alternatives considered.**
1. Keep `Layer` as the only provenance and accept that two L2 models agreeing on identical bounds
   count as one proposal.
2. Infer identity from `confidence`, on the theory that two models rarely produce the same float.
3. Track support outside `Span`, in a side table owned by the orchestrator.
4. Count support by insertion order, treating every input element as independent.

**Rationale.** `Layer` answers "which architectural layer proposed this", which is a different
question from "which detector instance proposed this", and the merge needs the second one. Without
it, two ensemble members agreeing on identical byte bounds are indistinguishable from one model
proposing the same span twice: the dedup at `core/src/span.rs:308` collapses both to
`support == 1`, and `Merged::is_protected()` (`core/src/span.rs:275`) reads `support > 1`. So the L4
no-demotion guarantee fails **exactly where agreement is strongest** — on exact boundary agreement,
which is the strongest evidence the pipeline can produce, and the case most likely to be a real
identifier. Option 4 is the inverse bug and is worse: it lets one model manufacture protection by
repeating itself, and D-002's whole point is that agreement must be earned. Option 2 is a heuristic
standing in for a fact. Option 3 puts the invariant somewhere other than the type that carries the
invariant, so a caller that forgets the side table silently loses the guarantee.

**Consequences.**
- `Span` grows a field. Every construction site must supply it correctly, and a caller that reuses
  one id across two detectors re-creates the defect invisibly — the type cannot catch that.
- `Span` gets larger, and it is the hot type in the merge path.
- The existing test `duplicate_proposals_do_not_manufacture_agreement` (`core/src/span.rs:636`)
  needs a companion asserting the opposite case, and the two together are easy for a future reader
  to see as contradictory.
- Detector ids become part of the audit surface: they say which model saw what, which is useful for
  debugging and is one more thing that must not leak text.
- The rules layer in M1 now carries a requirement it would not otherwise have had.

---

## D-012 — `checksum_validated` is an explicit flag, never inferred

- **Date:** 2026-07-19
- **Status:** ACCEPTED
- **Implementation status:** decided, NOT yet implemented. `core/src/span.rs` is unchanged.

**Decision.** `Span` gains an explicit `checksum_validated: bool`, set by the rule that ran the
checksum. `Merged::is_protected()` (`core/src/span.rs:275`) reads that flag instead of reconstructing
it from `source == Layer::Rules && confidence >= CHECKSUM_CONFIDENCE`. The flag is OR-ed across
merges: if any parent was checksum-validated, the merged span is.

**Alternatives considered.**
1. Keep the inference from `(source, confidence)` and document the coupling.
2. Encode it in `EntityLabel`, since only TCKN, VKN and IBAN are checksum-validatable.
3. A separate `Provenance` enum replacing `Layer` entirely.

**Rationale.** The inference reconstructs a fact that was known exactly once — at the moment the
checksum was computed — from two values that are both derived and both mutable by the merge.
`confidence` is the output of `noisy_or` (`core/src/span.rs:132`), which combines parents; `source`
is `min()` over parents (`core/src/span.rs:243`). So the most safety-critical predicate in the
codebase, "may L4 demote this span", is rebuilt from two numbers that the merge itself rewrites.
Any future change to either — a rules span emitted at 0.99 for a soft match, a fourth `Layer`
variant sorting below `Rules` — silently changes which spans are protected, with no test naming the
coupling. Option 2 conflates "this label CAN be checksum-validated" with "this instance WAS", which
is precisely the distinction that matters for a TCKN-shaped number that failed its check digits
(the case `eval/adversarial/adv_direct.jsonl` adv-direct-0006 exists to test). Record the fact where
it is known; do not derive it later.

**Consequences.**
- Another field to set correctly, and the failure mode is silent in the dangerous direction: a rule
  that forgets to set it produces a checksum-valid span that L4 is allowed to demote.
- Two sources of truth now exist during the transition — the flag and the old `(source, confidence)`
  pair — and they can disagree. The inference must be deleted, not merely bypassed.
- OR-ing across merges means a wide, weak NER span that overlaps a checksum-valid TCKN becomes
  protected over its whole extent, so a bad boundary is now unarguable-with as well as wrong.
- `Span` grows again; see D-011's size note.

---

## D-013 — Hand-written `Debug` impls that redact L3 rationales

- **Date:** 2026-07-19
- **Status:** ACCEPTED
- **Implementation status:** decided, NOT yet implemented. `core/src/audit.rs` is unchanged.

**Decision.** Any type that can reach a model-generated rationale gets a hand-written `Debug` impl
that prints a redaction marker in place of the text. This covers `AuditEntry`
(`core/src/audit.rs:14`, currently `#[derive(Debug, Clone, PartialEq)]`) and `AuditLog`
(`core/src/audit.rs:97`), and applies to every future type carrying L3 output.

**Alternatives considered.**
1. Keep the derive and rely on `AuditLog::redacted()` (`core/src/audit.rs:134`) at every export
   point, enforced by review.
2. Feature-gate the derive so rationales print in debug builds only.
3. Keep the derive and make the rationale a newtype with its own redacting `Debug`.
4. Do not store rationales at all.

**Rationale.** An L3 rationale explains why a phrase re-identifies a patient, and the most natural
way for a model to write that sentence is to QUOTE THE PHRASE — "flagged because the patient is
described as the spouse of a well-known judge in <district>". The rationale therefore *is* the
quasi-identifier. A derived `Debug` on such a type is a PHI egress path through `{:?}` in a log
line, through a panic message, through `unwrap`/`expect` on a `Result` containing the value, and
through any binding's error path (PyO3, WASM, Tauri, MCP) that stringifies an error. Option 1
defends the deliberate export paths and not the accidental ones, and the accidental ones are the
ones that leak. Option 2 is worse than useless: developers debug on machines holding real notes, and
a guarantee that holds only in release is not a guarantee. Option 3 is the right shape and is
compatible with this decision, but it does not by itself stop a future field being added to
`AuditEntry` that carries text — the redaction belongs on every type that can reach one. Option 4
loses the interactive review path that makes L3 auditable at all.

**Consequences.**
- Debug output is lossy by design. When an L3 span is wrong, `{:?}` will not show why, and the
  developer must go through the in-memory accessor deliberately. This is mildly annoying exactly
  when debugging is hardest, and it is the correct trade.
- Hand-written `Debug` impls drift: a field added to `AuditEntry` will not appear in its `Debug`
  output until someone remembers, so debug output can silently become stale and misleading.
- `#[derive(Debug)]` becomes forbidden on a growing set of types, which is a rule enforced by
  reviewers and hooks rather than by the compiler.
- Snapshot-style tests that compare `Debug` output cannot be used on these types.

---

## D-014 — The medical-term FP rate is reported against two denominators

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** The medical-term false-positive rate is reported as TWO numbers, never one: against
the allowlist terms ANNOTATED in fixture text, and against the occurrences of the LOADED ALLOWLIST
VOCABULARY (`eval/allowlist/`) found in that same text. The gate names which one it reads.

**Alternatives considered.**
1. Report only against fixture annotations. The annotator said what mattered.
2. Report only against the loaded vocabulary. It is bigger and needs no hand annotation.
3. Report a single blended rate over the union of both.
4. Force the two sets to be identical and report one number.

**Rationale.** The two sets had silently drifted apart by 313 terms — terms annotated in fixtures
that the loaded vocabulary did not contain — and a single blended number hid the drift completely,
because either denominator alone produces a plausible-looking rate. The two measure genuinely
different things and both matter: fixture annotations measure "did we destroy the terms an annotator
judged clinically load-bearing", vocabulary occurrences measure "did we destroy anything in the
negative set we actually ship to L4 at runtime". A term in the fixtures but not the vocabulary is a
runtime gap in L4's reference data; a term in the vocabulary but not the fixtures is untested. One
number cannot say which of those is happening. Option 4 is the tidy answer and is wrong: it forces
the vocabulary to be exactly as large as our annotation effort, when the vocabulary should grow
faster than the fixtures do.

**Consequences.**
- Two numbers to track and two ways to regress, and a reader who quotes "the FP rate" without
  saying which one has said nothing.
- The gate must name its denominator explicitly, and changing which one it reads is a change of
  gate semantics that needs an ADR of its own.
- Divergence between the two is now visible, which means someone has to reconcile it. That work did
  not exist while the number was blended.
- Model cards carry two figures where competitors carry none, which is harder to compare against
  published work.

---

## D-015 — `attack_class` is a closed enum on adversarial fixtures

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** Every fixture under `eval/adversarial/` carries a REQUIRED `attack_class` drawn from a
closed enum (`ATTACK_CLASSES` in `eval/build_gold.py`): the brief's seven L6 classes
(`quasi_identifier_combination`, `narrative_survival`, `structural_leakage`,
`cross_document_linkage`, `rare_value_survival`, `format_tells`, `indirect_reference`) plus
`direct_identifier_edge_case` and `medical_term_false_positive` for the two adversarial kinds that
are not L6 attacks. A value outside the enum is a hard `GoldError`. The free-prose `attack` field
stays alongside it. Coverage is reported per class on every eval run, including classes at zero.

**Alternatives considered.**
1. Keep free prose only, and grep it when the red team needs to group.
2. An open-ended string with a naming convention.
3. Tags on the existing `tags` field rather than a dedicated key.
4. Infer the class from the fixture's filename (`adv_direct.jsonl`, `adv_contextual.jsonl`).

**Rationale.** The prose field was already documented as "which of the L6 attack classes an
adversarial fixture exercises", but it held 38 distinct paragraphs across 38 fixtures with no two
values alike, and validation only checked that it was a string. So nothing downstream could group,
count, or report by class, and M5's red team had no way to see that `structural_leakage` and
`format_tells` had zero fixtures — which is exactly what the enum surfaced on its first run. A gap
you cannot count is a gap you will not fill. Option 2 fails on the first typo: `narrative_survivel`
would be silently counted as coverage of a class the red team does not run, which is worse than an
uncounted gap because it reads as safety. Option 4 ties classification to file organisation, and
`eval/adversarial/adv_direct.jsonl` already contains a fixture (adv-direct-0011) whose actual attack
is a medical-term false positive. Prose explains one fixture to one human; the enum is what makes
coverage machine-readable.

**Consequences.**
- Adding a fixture now requires choosing a class, which is a judgement call the author may get
  wrong, and a mis-filed fixture reports as coverage of a class it does not exercise.
- Some fixtures genuinely straddle two classes and the schema forces one. `adv-codeswitch-0011`
  tests both a suffixed-NAME boundary and a code-switched medical root and is filed under the
  former; that choice is arguable and is now invisible in the counts.
- The enum will need extending when a genuinely new attack class is found, and extending it is a
  code change plus a re-review of every existing fixture that might belong to the new class.
- Because the enum is closed, a red teamer who discovers a novel attack cannot record it until the
  enum is changed, which is friction at exactly the moment we most want the fixture committed.
- Backfilling the existing fixtures required classifying 50 paragraphs of prose after the fact, and
  those classifications carry the backfiller's judgement, not the original author's.

---

## D-016 — `Span` and `Merged` fields are private; `support` is a set of detector ids

- **Date:** 2026-07-19
- **Status:** ACCEPTED
- **Implementation status:** IMPLEMENTED. `core/src/span.rs`, `core/src/pipeline.rs`,
  `core/src/audit.rs`, `core/tests/public_surface.rs`.

**Decision.** Four coupled changes, all in the span algebra.

1. Every field of `Span` becomes private, with `#[must_use]` accessors (`start`, `end`, `label`,
   `source`, `detector_id`, `confidence`, `text_hash`, `is_checksum_validated`). `Span::new` and
   `Span::checksum_validated` are the only construction paths.
2. Every field of `Merged` becomes private. `Merged::single` (support 1) and `union_widest` are the
   only construction paths; `span()`, `contributors()` and `support()` read.
3. `Merged` stores the SET of distinct `DetectorId`s that contributed. `support()` is its
   cardinality, not a count of merge events.
4. `Span::union_with` takes `detector_id` from the DOMINANT parent, the same parent that supplies
   the surviving label and bounds, instead of `min()` over the parents.

**Alternatives considered.**
1. `#[non_exhaustive]` on `Span` instead of private fields.
2. Keep the fields public and document the constructor as the intended path (the status quo).
3. Define `support` as "detectors sharing a commonly-agreed byte range", so a transitive
   A-B, B-C chain with no common byte reports 2, or 1, rather than 3.
4. Keep `detector_id` as `min()` and add a separate `dominant_detector` field.

**Rationale.** The previous round added `checksum_validated` and `DetectorId` and then documented
`Span::checksum_validated` as "the only way to set" the flag. From another crate that was simply
false: `Span { checksum_validated: true, ..ner_span }` made an `Ner(3)` span at confidence 0.01
protected, and a struct literal equally bypassed all three invariants `Span::new` enforces — an
offset inside a `ş`, `confidence: 42.0`, and `source: Rules` on an `Ner(0)` detection. The BREACH
direction is worse than the forgery and is the one that decides this ADR: a binding author writing
a literal for a genuinely checksum-valid TCKN and omitting the flag hands L4 a demotable
identifier, which is exactly the failure the flag exists to prevent. Option 1 blocks the external
literal only; in-crate literals remain, and the crate's own tests were writing
`Merged { span, support: 2 }` — which is how defect 3 stayed invisible through a full review round.
Option 2 is what was already tried.

On `support`: the doc comment claimed distinct detector ids while the code incremented once per
merge event after a byte-identical dedup. With a SINGLE `Ner(0)`, two overlapping-but-not-identical
proposals reported `support: 2` and became undemotable, as did the same bounds under two labels.
"Independent agreement" was a claim the code could not back and no test covered.

On option 3, the transitive-chain semantics, which had to be decided rather than left implicit:
support is now defined as the number of distinct detectors that contributed to the merged region,
and it explicitly does NOT assert a byte range all of them agreed on. A three-detector chain
reports 3. This over-approximates agreement. It is chosen because `support`'s only consumer is
`is_protected()`, where a higher number FORBIDS demotion — so the stricter reading makes chained
spans demotable, and demoting a real identifier is a breach while over-protecting is a precision
papercut. I2 settles that trade in one direction.

On option 4: provenance that names a detector which produced neither the surviving label nor the
surviving bounds is a false claim about who found what. Merging `Ner(0)@"Ayşe"` with the wider
`Ner(1)@"Ayşe Yılmaz"` reported `Ner(0)` over `Ner(1)`'s label and hull. Nothing egresses that
today only because `AuditEntry` records `layer` and not `detector_id`, and recording the detector
is the obvious next entry. A second field keeps the wrong value reachable under a name that reads
authoritative; the contributing set already carries the parents that lost.

**Consequences.**
- `Merged` is no longer `Copy` in spirit and now allocates a `Vec<DetectorId>` per merged region.
  `Span` itself stays `Copy` and allocation-free, so the browser build's hot structure is unchanged,
  but the merge output is not free any more. A `SmallVec` or a bitset over ensemble slots is the
  optimisation if it ever shows up in a profile.
- Every call site now reads through accessors, so a future field rename is a compile error at one
  definition instead of a silent edit across the crate — but the diff to get here touched every
  reader in `pipeline.rs` and `audit.rs`.
- `support()` is no longer `const`, because `Vec::len` is not; `is_protected()` follows it.
- The over-approximating chain semantics mean a long chain of weak single-detector proposals that
  happen to overlap pairwise becomes unarguable-with by L4. That is deliberate and it is a precision
  cost the medical-term FP rate will have to absorb at M4.
- A residual gap this ADR does NOT close: two overlapping-but-not-identical proposals from ONE
  detector still noisy-OR their confidences together, so a single model can still raise its own
  confidence past `ESCALATION_CONFIDENCE_MAX` by proposing two ranges. The byte-identical dedup in
  `union_widest` catches only the exact-duplicate case. Support is now immune to it; confidence is
  not.
- The compile-fail property — "this struct literal does not compile" — is asserted only indirectly.
  `core/tests/public_surface.rs` runs from outside the crate and can therefore exercise only what
  compiles; a `trybuild` suite asserts on rustc's diagnostics and is strictly stronger. It is not
  added here because the dependency would have to be fetched over the network. The test file says
  so at the top, so the gap is recorded where the next reader will find it.

## D-017 — The dotted/dotless index expansion is gated on ASCII origin and on capital-`I` provenance

**Context.** D-014 added `key_variants`, which indexed `key`, `key.replace("ı","i")` and
`key.replace("i","ı")` for every class C term, so that English vocabulary written with a capital `I`
(`Infective endocarditis`) stayed matchable under a Turkish-correct fold. The expansion was
unconditional. Turkish distinguishes `ı` from `i`, so unconditional expansion merges words that are
not the same word: measured over the 174-document corpus, 14 tokens of the common adjective `dış`
("outer") matched the ANATOMY entry `diş` ("tooth"). Every one of the 14 inflated the
`fp_rate_vocabulary` denominator with a medical term nobody wrote, and at L4 runtime the same
expansion hands a function word an allowlist `Keep` — which under the open allowlist-vs-recall
precedence gap is the mechanism by which an allowlist entry suppresses a real span.

**Decision.** Keep `turkish_casefold` exactly as it is; the fold was never the defect. Gate the
expansion on two independent conditions, both in `eval/allowlist.py:key_variants`:

1. The key must be ASCII-origin: `key.replace("ı","i").isascii()`. `mrı` -> `mri` is ASCII, so
   `MRI` is English vocabulary. `dış` -> `diş` still carries `ş`, so the term is Turkish and gets no
   second reading.
2. The `ı`->`i` direction additionally requires an ASCII capital `I` in the source spelling. A
   written lowercase `ı` is a letter the author chose, so `sıvı` must not also index `sivi`; an `ı`
   that the fold produced from `I` is genuinely ambiguous and must.

**Alternatives rejected.** An explicit exception set listing `dış`: it fixes one collision and leaves
the mechanism, so the next collision is silent again. Dropping the expansion entirely: it makes the
English half of the vocabulary unmatchable, which is the defect D-014 fixed.

**Consequences.** Distinct index keys fall from 2818 to 2805 while the term count rises, because the
phantom variants are gone. A residual class remains: an ASCII-only Turkish word whose `i`/`ı` twin is
also a real word could still merge (`ısı`/`isi`). Nothing in the current vocabulary is in that class,
and condition 2 removes the write-direction half of it. Recorded here rather than guarded, because a
guard for a collision that does not exist is untested code.

## D-018 — The medical-term gate reads the WORSE of both denominators

**Context.** D-014 established two denominators — annotated (what a human marked in a fixture) and
vocabulary (every `eval/allowlist/*.txt` term the scanner finds in a document) — and reported both.
`eval/report.py` then built the `medical_term_fp_rate_max` release gate from the annotated one alone.
The consequence, proven with a probe detector: masking every occurrence of `ameliyat` — a term in the
vocabulary files and annotated in ZERO fixtures — destroys 25 real medical terms, wrecks the clinical
meaning of every note it appears in, and scores `medical_term_fp_rate_max 0.0000 PASS`. The gate's
own reason string said which denominator it read, so the defect was documented rather than hidden,
but a documented gate that cannot fail is still a gate that cannot fail.

**Decision.** The gate observes `max(fp_rate_annotated, fp_rate_vocabulary)` over whichever
denominators exist, and is UNENFORCEABLE only when neither exists. Both numbers stay printed
separately; only the gated one changes.

**Alternatives rejected.** A second gate name for the vocabulary rate: two gates over the same harm
means a release checklist can be read as passing while one of them is red, and the thresholds file
would need a second entry that I2 then has to defend separately. Gating on the vocabulary rate alone:
the annotated set contains multi-word phrases and context the scanner does not reproduce, so it can
catch harms the scanner misses.

**Consequences.** The gate is strictly stricter, which is the only direction I2 permits. Under a real
detector the vocabulary denominator will usually dominate, so `medical_terms.fp_rate_max` will bite
earlier than it used to; that is the intended cost of the gate being able to fail.

## D-019 — Residual allowlist drift is legal only when `DRIFT_EXCEPTIONS` says why

**Context.** `just allowlist-drift` reported eight fixture-annotated terms missing from the
vocabulary and exited 0. Seven were genuinely medical (`costa`, `rebound`, `lead`, `monitör`,
`Monitörde`, `sensör`, `walker`) and had no runtime reference for L4 at all. A report nobody can fail
is a report nobody reads.

**Decision.** Reconcile the seven, then make the residue explicit and enforced.
- `lead`, `monitör`, `sensör`, `walker` go to a new class C category `DEVICE`
  (`eval/allowlist/device.txt`), declared in `eval/schema.yaml`. Bedside equipment had no home, and
  it is a collision class second only to brand names: `Lead`, `Monitor` and `Walker` are surnames.
- `rebound` goes to DIAGNOSIS as a clinical finding.
- `Monitörde` goes to `code_switched.txt`, not to DEVICE. It is `monitör` inflected, not a second
  term, and `code_switched.txt` is where inflected surface forms already live. The bare-suffix case
  cannot be stripped algorithmically without turning `costa` into `cos`.
- `costa 6` and `Deva marka parasetamol` are PHRASES over vocabulary that is already present, and are
  listed in `eval.allowlist.DRIFT_EXCEPTIONS` with a written reason each.
- `--strict` now fails on `report.unjustified` (drift minus documented exceptions) rather than on all
  drift, and `just check` depends on a new `drift-check` recipe that runs it.

**Alternatives rejected.** Enumerating `costa 1` through `costa 12`: the rib index is unbounded data,
not vocabulary, and adds nothing L4 can use. Leaving `--strict` opt-in: that is the state that let the
eight sit unreconciled.

**Consequences.** `DRIFT_EXCEPTIONS` is the obvious place to bury a term that really is missing, so
`validate_drift_exceptions` requires each exception's head token to already be class C — `costa` is in
anatomy.txt, `deva` in drug.txt — and raises `AllowlistError` naming the entry as a MISSING TERM
otherwise. The map cannot silence a term whose root is absent. A new fixture annotating a term absent
from the vocabulary now fails `just check` instead of joining a backlog.

## D-020 — Auto-update is opt-out and auto-installing

**Numbering note.** This entry was requested as D-016. That identifier was taken in an earlier
session (`Span` and `Merged` fields are private), and DECISIONS.md is append-only, so the ADR is
recorded at the next free number rather than by overwriting one.

**Context.** `deid-tr` is a de-identifier. Its defects are not inconveniences: a recall regression in
a released binary is a stream of clinical notes leaving hospitals with patient identifiers still in
them, and nobody downstream can tell. An install that never updates keeps that defect forever. Set
against this, I1 says PHI never leaves the device and the product's strongest claim is that you can
open devtools, run the tool, and watch the network tab stay empty. An updater is in tension with that
claim, and the tension is real rather than rhetorical.

**Decision.** Automatic update checking is ENABLED BY DEFAULT and, once a release signing key is
pinned, AUTO-INSTALLS verified releases. The project owner made this choice explicitly after being
shown the conflict with I1 and after the recommended alternative was declined. This is a DELIBERATE
RELAXATION of I1's spirit — not a reinterpretation of it. I1's letter still holds: `core/` has no
network dependency, the mask path opens no socket, and no document-derived byte is ever transmitted.
What is relaxed is the broader claim that this tool never talks to the network at all.

**Alternatives rejected.**
- *Opt-in, notify-only* — checks off until the operator turns them on, and a new version reported but
  never installed. THIS WAS THE RECOMMENDED OPTION AND IT WAS DECLINED. It preserves the empty
  network tab and imposes no phone-home on anyone who did not ask for one. It was rejected because
  the population that most needs a security patch is exactly the population that never opts in.
- *Defer to M6* — ship the CLI now, decide later. Rejected because "later" for an updater means after
  binaries are in the field, and an install base with no update channel cannot be given one remotely;
  every one of those machines becomes a manual upgrade.
- *Auto-install without signature verification* — never seriously on the table. See mitigation 6.

**Rationale.** Security-patch reach. A de-identifier with a known recall defect that nobody updates
is itself a hazard, and it is a hazard whose victims are patients who were never told the tool
existed. Weighed against a static-file fetch that reveals an IP address, the owner judged reach to be
worth more than the fetch costs. That judgement is theirs to make; recorded here so it is auditable
rather than assumed.

**Consequences, stated plainly.**
1. **Every check is a phone-home.** The release host learns that a given IP address runs this tool,
   and — because checks happen at process start — roughly on what schedule, which for a clinical site
   correlates with working hours. Fetching a static manifest and comparing versions locally means the
   host is not told which version is running, but it is still a beacon and it is still a log line on
   somebody else's server. There is no version of this feature in which that is not true.
2. **It weakens the "open devtools, watch the network tab stay empty" argument.** That argument was
   the single most persuasive thing we could say to a compliance officer, and it now needs a caveat.
   The caveat is defensible — a static release manifest is not patient data — but a claim requiring a
   caveat is a materially weaker claim than one that does not.
3. **It creates an auto-install path that must be signature-verified forever.** A binary that
   replaces itself from the network is remote code execution on a machine holding PHI unless every
   byte is verified. That requirement is now permanent: it cannot be relaxed for a hotfix, for a
   mirror, for a CI convenience, or because a key rotation is inconvenient.
4. **It puts a permanent burden on reviewers.** `bindings/cli/src/update.rs` and
   `bindings/cli/src/transport.rs` are the only components in the product whose job is to talk to the
   network, which makes them the only plausible home for a telemetry regression. Every future change
   to them is a privacy review, indefinitely. Telemetry regressions do not arrive as "add analytics";
   they arrive as "we should know which platforms to build for" (an install id) and "we should know
   if updates are failing" (an error beacon). Both are refused by name in that module's header.

**Mitigations, binding on any future change.** These are load-bearing for the product to function at
all, and none of them is overridden by the owner's choice. A change that breaks one is reverted.
1. The updater lives in `bindings/cli/` and never in `core/`. `core/Cargo.toml` carries no network
   dependency and `scripts/hooks/pre_commit_phi.sh` enforces that on the staged manifest.
2. It never runs during `deidentify()` or any inference path — only at explicit process start for
   commands that open no document, or on an explicit `deid update`. `bindings/cli/src/mask.rs` cannot
   name the networking modules and `bindings/cli/tests/mask_path_is_offline.rs` fails if it ever
   does. The defence is structural because statement ordering is not.
3. It is disableable three independent ways, each sufficient alone: `--offline`, `DEID_NO_UPDATE=1`,
   and `auto_update = false`. Precedence is CLI flag > env var > config file > default, and the
   switch is one-way — no layer can re-enable what a lower one disabled. This is a FUNCTIONAL
   requirement: without it the air-gapped hospital install, the product's core user, is impossible.
4. It auto-detects a restricted environment and disables itself quietly: one bounded TCP probe,
   two-second ceiling, fully asynchronous on a detached thread that is never joined, failure silent
   and non-fatal. A detected air gap suppresses further probing for 24 hours, so a hospital with no
   egress sees one connection attempt a day rather than one per invocation.
5. It sends NO telemetry. Two GETs of static paths; no query string, no request body, no header
   derived from this machine, no install id, no counts, no document bytes. The complete inventory of
   what is and is not sent is in the module header of `bindings/cli/src/update.rs`, written out
   rather than summarised precisely because that file is where a regression would land.
6. Downloads are verified before they are applied: an Ed25519 signature over the manifest, checked
   against a pinned public key with the legacy-algorithm downgrade refused, PLUS a SHA-256 over the
   artifact named in that signed manifest. Both, or nothing installs. Until the project owner
   generates and pins a release key, `update_public_key` is unset and the updater is NOTIFY-ONLY by
   construction; unverifiable bytes are never written to an executable path. Downgrades are refused
   even when correctly signed, because a replayed old signed manifest is a valid signature over a
   known defect.
7. It prints a one-line notice on first run stating that auto-update is ON and naming all three ways
   to turn it off, on stderr, before any check is spawned. Silent network activity in a PHI tool is
   not acceptable even when the owner opted in.

**One thing a reviewer should look at twice.** `bindings/cli/src/transport.rs` builds its request URL
from a `SCHEME` constant and an operator-configured host rather than from a single string literal.
There is no release host compiled into this binary and no default endpoint, so an unconfigured
install cannot reach anything — but that assembly also means the URL does not appear as a literal to
`scripts/hooks/guard_invariants.sh`, whose repo-wide remote-`https` block exists to keep the L3
contextual layer local. The guard is not widened and no exception is added to it; the shape is
recorded here instead, per that guard's own escape-hatch instruction.

---

## D-021 — L1 emits a role-less `DATE`, and never guesses which of the four a date is

`core/src/rules/date.rs` labelled every date it found `DATE_BIRTH`, on the argument that
over-assigning the label with the strictest recall floor (0.98 against 0.97) is the recall-safe
direction. That argument is wrong, and it is wrong in a way the eval makes exact: `match_spans`
pairs a prediction with a gold span only when the LABELS AGREE as well as the offsets, so one
correctly-located date under the wrong role scores as a MISS on its true role AND a FALSE POSITIVE
on the guessed one. On the 178-document corpus 179 found dates were counted twice as errors —
`DATE_BIRTH` read recall 1.0000 at precision 0.3285 while `DATE_ADMISSION` (155 gold) and
`DATE_DISCHARGE` (24 gold) read 0.0000, which described nothing the detector actually did.

**Decision.** A generic `DATE` entry is added to `eval/schema.yaml` (`detector: rules`,
`recall_threshold: 0.97`, the general date floor rather than the birth-date floor, because this
label is the residue after role assignment and holding it to the re-identification-triple floor
would assert a role it declines to claim). L1 assigns one of the four roles when a cue is in reach
and `DATE` otherwise. L2/L4 refine it.

**Not a masking change.** `DATE` is a direct identifier like the other four; nothing is masked less
because a date arrived without a cue.

**Follow-up a human has to make.** `eval/thresholds.yaml` has no `per_entity_recall: DATE` entry,
so the new label is currently ungated. That file is write-protected by
`scripts/hooks/guard_invariants.sh` and edits to it need explicit human approval, so it is reported
here rather than made. Adding `DATE: 0.97` would mirror the schema; the guard's rule is raise-only,
and adding an entry is not a lowering.

---

## D-022 — The `checksum_id_precision` gate measures a different set than its name

Fixing the VKN interior-window defect took `checksum_id_precision` from 0.6871 to 0.9806. It cannot
reach the 1.000 gate, and the residue is not a rule defect.

`eval/harness.py` computes the number over EVERY prediction carrying a checksum-VALIDATABLE LABEL
(`TCKN`, `VKN`, `IBAN`), not over the predictions that were checksum-VALIDATED. The brief's gate is
named "Checksum-validated ID precision" and justified by "a checksum-valid TCKN is never a false
positive"; those are two different sets, and L1 deliberately populates the difference. `tckn.rs`,
`vkn.rs` and `iban.rs` each emit a right-length candidate that FAILED its arithmetic, at
`CHECKSUM_FAILED` (0.50) and demotable, because a failed check digit in hand-typed clinical text is
at least as likely to be a transcription slip on a real identifier as a coincidence — an I2 recall
decision recorded in each module and covered by a test.

Exactly two such spans are false on the corpus: an eleven-digit protocol number (`PROT20260011907B`,
gold `MRN`) emitted as a checksum-failed `TCKN`, and an adversarial fixture's mod-97-failing TR IBAN.
Both are the recall decision working as designed.

**Decision: nothing is changed in L1 to chase the number.** Deleting the checksum-failed emissions
would buy 1.000 by giving up recall on typo'd identifiers, which I2 forbids in that direction. The
two honest options both need a human: (a) restrict the metric to spans whose `checksum_validated`
flag is set — which requires `PredictedSpan` to carry the flag and makes the number match its own
name and the brief's wording; or (b) leave the metric and accept that the gate is unreachable while
any module emits a checksum-failed candidate. This ADR exists so the 0.9806 is read as a measured
disagreement between the gate and the layer, not as a leftover bug.

---

## D-023 — RESOLVES D-010: context-sensitive allowlisting, with a graded escalation

- **Date:** 2026-07-19
- **Status:** ACCEPTED. Supersedes the OPEN status of D-010.
- **Implementation status:** IMPLEMENTED. `core/src/route/` — `allowlist.rs`, `evidence.rs`,
  `router.rs`, `adjudicate.rs`, `mod.rs`.

**Decision.** An allowlist entry may demote a span **only when the surrounding evidence does not
independently mark it as a person**. The deterministic `Keep` on an allowlist hit is removed. L4 now
decides in this order, and the order is the ADR:

1. **Protected?** Checksum-validated, or agreed by more than one distinct detector. Mask, and never
   reach any demotion path. `crate::pipeline::demote_to_keep` remains the only demotion primitive
   and still returns `Err(ProtectedSpanDemotion)` for these.
2. **On the allowlist?** If not, Mask. Allowlist membership is a *precondition* for demotion; the
   adjudicator cannot demote a span no term file vouches for.
3. **Weigh person evidence** over the original text at byte offsets. Six signals in two grades.
   *Decisive*: an adjacent Turkish title (`Dr.`, `Op. Dr.`, `Prof. Dr.`, `Uz. Dr.`, `Hemş.`, …,
   found across up to two intervening capitalised tokens so `Op. Dr. Andrea Costa` is caught from
   `Costa`); a trailing honorific (`Bey`, `Hanım`, inflected forms included); position in a
   name-bearing field (`Hasta Adı:`, `Konsültan:`, `Refakatçi:`). *Suggestive*: an adjacent
   capitalised token forming a plausible given-name plus surname pair; casing inconsistent with the
   entry's normal register; a genitive suffix typical of a person reference.
4. **Decisive evidence → Mask.** The allowlist loses. This is the leak D-010 describes, closed.
5. **No evidence → demote to Keep.** The cheap, common, deterministic path.
6. **Conflicting/suggestive evidence → escalate to the adjudicator**, never short-circuit. Only
   `Verdict::MedicalTerm` demotes. `Person`, `Undecided`, an adjudicator that errors, and an
   adjudicator that is not installed at all **all keep masking** — I2 settles a tie in one direction.

**Alternatives considered.**
1. *Deterministic keep* (the status quo D-010 records). Cheapest and it leaks: `Deva Ergüven`,
   `Deva Hanım` and `Op. Dr. Andrea Costa` are all suppressed by a vocabulary hit. Rejected under I2.
2. *Always escalate every collision.* Correct on recall, and it puts a local-model call on the
   common path: measured at 1910 vocabulary occurrences over the 178-document corpus, that is 1910
   adjudications where 74 are actually needed. It also makes recall on a collision depend on a small
   local model's judgment rather than on an audited artifact.
3. *Strip colliding surfaces from the term files.* Forbidden outright — the files are append-only
   (I7), and it guarantees `carcinoma`-class false positives on every term that is a surname
   somewhere.
4. *Rank by source: a NER `NAME` always beats the allowlist.* Hands full precedence to the noisiest
   detector and re-creates the medical-term FP problem the 0.5% gate exists to bound.
5. *Let the adjudicator demote spans that are NOT on the allowlist.* Rejected: the allowlist is the
   audited, append-only artifact the medical-term FP gate is scored against. Making recall a
   function of model judgment puts it out of the reach of the eval, which I2 does not permit.

**Rationale.** The two error directions are not symmetric and the grading is what keeps them apart.
A decisive signal — a title, an honorific, a name field — is produced by a person and by nothing
else in a Turkish clinical note, so acting on it costs no precision. A suggestive signal is produced
by persons *and* by ordinary prose, so acting on it in either direction would be a guess; escalating
converts the guess into a logged decision, which D-010 explicitly asks for. Every branch that cannot
reach a confident answer ends in `Mask`.

Three of the guards are there because the corpus measured them, not because they were predicted:
a preceding capitalised token only counts when it is capitalised *by choice* and not by sentence or
line position (`Bilinen hipertansiyon'u`, `Pretibial ödem` — 176 occurrences); a line-opening
capitalised token followed by another is a section heading and not a name pair (`Triyaj Notu`,
`Ameliyat Notu`); and an all-caps neighbour is a formulation code, not a surname (`Adalat CR`).
The Turkish-correct casefold and the ASCII-origin gate on the dotted/dotless expansion are ported
from `eval/allowlist.py` rather than re-derived, so the runtime matcher and the artifact the FP gate
is scored with cannot drift; the `dış`/`diş` lesson recorded as D-017 is carried over with its test.

**Consequences.**
- **The three named collisions now resolve in both directions inside one document.** `Costa` the
  surgeon is masked and `costa` the rib is kept; `Deva` the patient is masked and `Deva` the brand
  is kept; `Adalet` the given name is masked and `Adalat` the drug is kept.
  `core/src/route/mod.rs::collision_tests`.
- **THE REAL DOWNSIDE: this is heuristic, and it will sometimes escalate a plain medical term.**
  It is not a classifier with a measured error rate; it is six hand-written Turkish signals. Every
  one of them is a locale bug waiting to happen, and a term that merely stands next to a capitalised
  word pays for an adjudication it did not need.
- **The escalation rate therefore rises above the 2-5% target for documents dense in eponyms.**
  Measured over the committed corpus (`core/src/route/mod.rs::corpus_measurement`, printed on every
  run): 178 documents, 1910 vocabulary occurrences, 1819 kept deterministically, 17 masked on
  decisive evidence, **74 escalated — 3.87%**, inside the band. But that is an average over a mixed
  corpus. `adv_medical_term` and `adv_eponym` documents are built out of eponymous diagnoses and
  name/term collisions, and on those the rate is several times higher; a real oncology or trauma
  service with eponym-heavy dictation will sit above 5%. The cost model for the Safe Harbor tier has
  to carry that as a per-specialty variance, not as one number.
- `RoutingStats` separates `escalated` (entered adjudication) from `adjudicator_calls` (invoked the
  model). Only the second costs anything, and it is strictly the smaller.
- **A known residual, recorded rather than hidden.** A person whose given name is itself class C
  vocabulary, standing at the start of a line with no title, no honorific and no field label — a
  bare signature line — loses the capitalised-neighbour signal. It does not become demotable on that
  account: it still has to be on the allowlist and produce no other signal. No such configuration
  occurs in the corpus, and an adversarial fixture for it is a welcome commit under I7.
- L4's unit tests now need whole sentences rather than isolated spans, exactly as D-010 predicted.

---

## D-024 — L5 keys surrogates on a keyed BLAKE2s digest, not on `Span::text_hash`

**Numbering note.** This entry was requested as D-018. That identifier was taken in an earlier
session by "The medical-term gate reads the WORSE of both denominators", so it was filed as the
next free number. The precedent is D-020's own numbering note.

**Numbering note, second correction (2026-07-19).** It was filed as **D-023**, which by then was
ALSO taken — by "RESOLVES D-010: context-sensitive allowlisting", immediately above. Two ADRs
therefore carried the identifier D-023 for one session, and every citation of "D-023" in the code
was ambiguous between an L4 decision and an L5 one. This entry is renumbered to **D-024**, the
next free identifier, and the collision is recorded here rather than erased: the file is
append-only, so the honest fix is a renumber plus a note saying it happened, not a quiet edit.
The earlier entry keeps D-023 because it was written first and because `core/src/pipeline.rs`
and `core/src/route/vocabulary.rs` already cite it under that number. Citations of the L5 entry
(`core/src/surrogate/mod.rs`, `core/src/surrogate/keyed_hash.rs`, D-025 below) are updated to
D-024 in the same change. No other identifier in this file is duplicated; the check is
`grep -oE '^## D-[0-9]{3}' docs/DECISIONS.md | sort | uniq -d`, which must print nothing.

**Context.** The brief specifies `text_hash: u64` on `Span`, and `core/src/span.rs` implements it as
FNV-1a over the covered text with the comment "NEVER store the text". The field does not deliver
that property. 64 bits of an unkeyed, published, non-cryptographic hash over a SHORT, LOW-ENTROPY
string is not a one-way function in any operational sense: the space of Turkish given names is on
the order of 10^4 and of given-plus-surname pairs on the order of 10^8, so an attacker holding a span
map — or any artifact carrying spans — enumerates the space and confirms by equality whether a named
patient is present. That is a membership disclosure, and membership in a clinical corpus is itself
the special-category fact KVKK protects. It was recorded as an open issue in the brief and in D-010,
and L5 is the first layer whose correctness depends on the answer.

**Decision.**

1. **L5 does not read `Span::text_hash`.** Surrogate identity is derived in
   `core/src/surrogate/mod.rs` as `BLAKE2s-256(key = per-document salt, domain-separated,
   length-prefixed fields: scope tag, format-family tag, Turkish-folded covered text)`. The primitive
   is implemented in `core/src/surrogate/keyed_hash.rs` and checked against the RFC 7693 keyed test
   vectors in that module's tests.
2. **The `u64` stays on `Span`.** Changing its type or removing it is an API break for every binding
   and for the span algebra's merge, and the field is genuinely useful as a merge-consistency aid
   (`union_with` rehashes over merged bounds). Its doc comment must stop claiming a privacy property
   it does not have; that edit belongs to whoever next owns `span.rs`.
3. **Key material is the caller's.** `core/` performs no I/O (I1) and therefore has no CSPRNG. A
   `Salt` is constructed from caller-supplied bytes, with a 16-byte floor on derived material. A core
   that invented its own randomness would invent it from a counter, and a guessable salt is not a
   salt.
4. **Collisions are handled, not assumed away.** Two kinds, two answers. A derivation collision (two
   originals, one 256-bit key) is DETECTED by keeping the folded original next to the key in the
   assignment table, and resolved onto a disjoint derivation. A surrogate collision (two entities,
   one replacement drawn from a finite pool — likely, not improbable) is detected against a
   surrogate-to-key table and resolved by re-deriving at the next attempt number, deterministically.
   Exhaustion after 64 attempts is a loud `SurrogateError::Exhausted`, because handing two entities
   one surrogate would make `SpanMap::reidentify` restore the wrong one.

**Why BLAKE2s keyed mode rather than HMAC-SHA-256.** Keying is a native primitive in BLAKE2 (RFC
7693, 2.5) rather than a two-pass outer/inner-pad construction, and the algorithm is 32-bit-word
arithmetic throughout, which matters because `core/` compiles to wasm32. It is implemented in-crate
rather than added as a dependency because I1's ban is enforced by a hook that greps `core/Cargo.toml`
by eye, and a published-vector-checkable 200-line primitive is cheaper to audit than a new
dependency graph.

**Residual exposure, stated precisely rather than waved at.** The keyed hash protects the DERIVATION,
not the table. `SpanMap` holds original PHI text in cleartext next to its offsets, because
re-identifying model output is impossible otherwise and that is L5's contract with the M2 gateway.
So:

- An attacker holding SPANS ONLY (offsets, label, `text_hash`) can still run the FNV enumeration
  against the `u64` and confirm membership. Point 2 above does not fix that; it is unchanged by this
  ADR and remains open until `span.rs` changes.
- An attacker holding DERIVED KEYS or surrogates cannot confirm a guessed name without the salt.
- An attacker holding the SPAN MAP has the document. No hash construction changes that. The map is
  therefore treated as document-equivalent: local, never logged, never transmitted, never persisted
  by `core/`, and given a hand-written `Debug` that redacts the originals — the D-013 construction,
  applied to the one structure that must hold text.
- The date shift is not a secret in the way the salt is: whoever knows the offset recovers every
  absolute date, so it travels with the map, never alongside the de-identified text.

**Salt scope is a configuration choice, and it is a real trade.** `SaltScope::Document` (the default)
breaks cross-document linkage, which is the most effective re-identification technique against a
de-identified corpus — and breaks longitudinal research linkage with it. `SaltScope::Patient`
preserves the patient trajectory for cohort studies and preserves the attacker's chain at the same
time. The default is the privacy-preserving one and the other must be selected deliberately, which is
I2's direction applied to L5: an unusable research dataset is a papercut, a linkable corpus is a
breach.

**Rejected: hash the text at 128 bits and keep it unkeyed.** Widening a non-cryptographic hash raises
the cost of a birthday collision and does nothing whatsoever about a dictionary attack, which is the
actual threat — the attacker is not searching for collisions, they are hashing candidate names.

**Rejected: store no identity at all and give every occurrence a fresh surrogate.** That deletes
property (b). `Ayşe Yılmaz` in the history and in the discharge summary would become two people, the
note would stop being clinically readable, and the corpus would stop being usable as research data.

## D-025 — The M2 gateway mints its own bracketed tokens instead of using L5 surrogates

**Context.** M2's whole point is a ROUND TRIP: `bindings/mcp/` masks a note on the way out to a
cloud model and restores the real identifiers in the model's reply on the way back. Restoration
is not offset splicing — the model does not echo the document, it writes prose that mentions the
redactions — so re-identification is a *search* for the surrogate string in arbitrary text
followed by substitution.

**Decision.** `bindings/mcp/src/surrogate.rs` re-renders `DeidResult` with tokens shaped
`[PATIENT_NAME_4f1a2b7c_2]`: schema label, 32-bit CSPRNG nonce fresh per document, and an
ordinal keyed on `Span::text_hash` so one entity reads as one entity. The gateway does NOT call
`Pipeline::with_surrogates`, and `health` reports `L5.live: false` with that reason.

**Rejected: the pipeline's fallback placeholder.** With no L5 engine installed the pipeline
emits the label — every TCKN in a note becomes `[TCKN]`. Not injective, so two patients collapse
onto one token and restoration would write one patient's identifier onto another patient's
finding. That is a disclosure, not a corruption: the clinician reads a correct-looking note
about the wrong person.

**Rejected: core's real L5 surrogates.** They are format-preserving by design (D-024) — a
Turkish name becomes a plausible Turkish name, a TCKN becomes a checksum-valid TCKN. Correct for
producing a de-identified corpus, and actively dangerous as a round-trip key, because a
plausible surrogate cannot be searched for safely in free text. A fake surname colliding with an
ordinary Turkish word, or echoed by the model inside an unrelated sentence, gets rewritten into
a real patient's name on the way back. The property this path needs is not plausibility, it is
being UNMISTAKABLE in arbitrary text. These two requirements are in direct opposition, which is
why the gateway does not reuse L5 rather than L5 being unfinished.

**Why the nonce, which is the part that looks optional.** Two jobs. It stops cross-session
bleed: session A's tokens carry a nonce absent from session B's span map, so restoring A's
document under B's handle substitutes NOTHING rather than substituting wrongly — a client-side
handle mix-up becomes a no-op instead of a disclosure. And it stops collision with document
content: a note that literally contains `[TCKN_1]` would otherwise have that text rewritten into
a real identifier. Collision against the original document is checked rather than assumed, with
a bounded retry (`MINT_ATTEMPTS`) so a pathological input fails loudly instead of looping.

**Consequence, accepted.** Tokens are not stable across calls and must not be cached by a
client. The single-pass restoration in `restore()` never revisits its own output, so a restored
identifier that itself looks like a token is not re-substituted — reachable with
patient-controlled content, and the failure it would otherwise produce is again one patient's
identifier in another's record.

## D-026 — The MCP gateway has no socket, and refuses the flags that would imply one

**Context.** I3 says never bind all interfaces, and the brief names this as the specific defect
in the incumbent. The conventional reading is "default to `127.0.0.1`". For M2 there is a
stronger option available for free.

**Decision.** `bindings/mcp/` is stdio-only. No socket type, no `std::net`, no socket-capable
dependency. A process with no socket library binds no address, so there is no default to get
wrong and no flag that can widen one. The gateway never speaks to the cloud model — the MCP
CLIENT does — and that split is precisely what makes it safe for this process to hold the span
map, which is the literal mapping from surrogate back to real PHI.

**Enforced three ways, because none of them subsumes the others.**
`bindings/mcp/tests/no_listener.rs` scans source files for socket types and the all-interfaces
address in every spelling, and scans the declared dependency table. `just mcp-no-socket` reads
the RESOLVED dependency graph including transitive edges a source scan cannot see. The existing
`guard_invariants.sh` blocks the address literals at edit time. The source scan sees
`use std::net::TcpListener`, which has no dependency edge at all; the graph check sees a crate
pulled in three levels down; neither sees what the other does.

**`--expose`, `--port`, `--listen`, `--host`, `--http`, `--bind` are recognised only to be
refused.** Silently ignoring an unknown flag is the dangerous behaviour here: an operator who
assumes the feature exists passes `--expose`, sees no complaint, and believes the resulting
process is reachable and authenticated when it is neither. The refusal names what the binary
actually is.

**If a socket transport is ever added**, all four hold together: loopback only, explicit
`--expose`, a bearer token, and a startup warning naming what became reachable. Any one alone is
insufficient — the flag alone is an open port, the token alone is an open port with a password
nobody was told about.

---

## D-027 — The Safe Harbor cost model was wrong by an order of magnitude: 40.0%, not 2-5%

- **Date:** 2026-07-19
- **Status:** ACCEPTED. Corrects a claim in the brief, in `docs/PLAN.md`, in `CLAUDE.md` and in
  four `core/` module docs. Supersedes nothing; D-023's 3.87% is not withdrawn, it is
  re-labelled with the denominator it was always about.

**The defect.** The brief and every document downstream of it say L4's adjudicator sees "the 2-5%
of spans the ensemble is unsure about". Measured over the committed corpus, the escalation rate
over routed candidates is **40.0% — 268 of 670** (`core/src/route/mod.rs::corpus_measurement::
report_the_router_escalation_rate_over_routed_candidates`, printed on every test run). The claim
was off by roughly a factor of ten, and it is the claim the Safe Harbor tier's economics rest on:
"fast, cheap, on-device, runs everywhere including the browser" is a statement about how rarely
the expensive path is taken.

**Two denominators, named here so they can never be confused again.**

| Quantity | Denominator | Measured | Where |
|---|---|---|---|
| Vocabulary escalation rate | occurrences of a class C medical term in the corpus text (1910) | 74, **3.87%** | D-023, `report_the_escalation_rate_over_the_committed_corpus` |
| **Router escalation rate** | **candidates that reached `route()` (670)** | **268, 40.0%** | this ADR, `report_the_router_escalation_rate_over_routed_candidates` |

D-023's 3.87% is a correct number answering a different question — how often context-sensitive
allowlisting turns a medical term into a question — and it was quoted as if it settled the 2-5%
claim. It does not: its denominator is roughly three times larger than the number of spans the
pipeline actually produces, and it counts a population (every mention of `carcinoma`) that mostly
never becomes a candidate at all. A rate is a fraction, and a fraction quoted without its
denominator is not a measurement.

**Why the real rate is what it is.** The router auto-masks on three grounds: a passed checksum,
agreement between distinct detectors, or confidence above `ESCALATION_CONFIDENCE_MAX` (0.60).
On the committed corpus, of 670 candidates: 0 checksum-validated, 0 multi-detector, 402 high
confidence, 268 escalated. The escalations are entirely the checksum-bearing and context-cued
identifier types sitting at 0.50 — `MRN` 155, `TCKN` 91, `SGK_NO` 11, `IBAN` 7, `VKN` 4 — which
is L1 doing exactly what D-012 and the rule modules say it does: emit a failed or unverifiable
identifier below the ceiling so L4 can argue about it, rather than dropping it (I2).

**Three qualifications, because a corrected number that is itself misread helps nobody.**

1. **The corpus makes this an upper bound, by construction.** I8 forbids a checksum-valid TCKN in
   the repository, so *every* committed TCKN fails its check digit and lands at 0.50. In real
   clinical text most TCKNs are valid, are protected, and never escalate. The 91 escalated TCKNs
   are an artifact of the fixture rule, not a property of the layer.
2. **L2 is a stub.** Zero candidates were multi-detector because there is only one detector. A
   real ensemble can only move this number down: agreement auto-masks.
3. **`escalated` is not `adjudicator_calls`.** `RoutingStats` separates them, and only the second
   costs a model invocation — an escalated span that is not on the allowlist is settled by the
   lookup alone. The 40.0% is the upper of the two.

**Decision.**

1. **The claim is corrected everywhere it appears**, to "measured 40.0% of routed candidates on
   the committed corpus, with the qualifications above", and every occurrence now names its
   denominator. `CLAUDE.md` (cost economics and the L4 spec), `docs/PLAN.md` (the tier table),
   `core/src/route/router.rs`, `core/src/route/mod.rs` and `core/src/pipeline.rs`.
2. **No constant is touched.** Lowering `ESCALATION_CONFIDENCE_MAX` would move the number toward
   the claim by auto-masking spans L4 currently argues about, and raising the confidence L1 emits
   for a failed checksum would do it by pretending to a certainty the arithmetic denies. Both are
   tuning a metric rather than measuring one, and the second is an I2 violation wearing a cost
   argument.
3. **The measurement is a test, not a gate.** It prints on every run and asserts only that the
   corpus loaded. A threshold here would fail the build for reporting a true number, which is the
   pressure that produces (2).

**What it implies for the Safe Harbor tier.** The tier is still on-device, still ~10ms for L1+L2,
and still the default — none of that changes. What changes is the *adjudicator* budget: at 40% of
candidates, a local adjudicator model on the escalation path is not a rounding error, and the
browser surface in particular cannot assume it is free. Three consequences follow, and they are
work, not conclusions:

- The honest planning number for a browser or mobile Safe Harbor deployment is "a local model call
  on a large minority of candidates", so the tier must remain correct with **no adjudicator
  installed at all** — which it is: an absent adjudicator keeps masking (D-023, step 6). The cost
  is precision on medical-term collisions, never recall.
- The largest single contributor is `MRN` (155 of 268), a type with no checksum to validate. If
  the adjudicator budget needs to come down, the place to look is MRN evidence quality — more
  context signals raising confidence honestly — not the ceiling.
- The eval report should carry the router escalation rate as a first-class number next to recall
  and the medical-term FP rate, so a change in the cost profile is as visible as a change in
  accuracy.

---

## D-028 — L5 preserves the date FORMAT, and therefore a measurable date-length tell

- **Date:** 2026-07-19
- **Status:** ACCEPTED. Narrows brief property L5(c) for one entity family. Related: D-024
  (surrogate derivation), D-025 (the gateway's own tokens).

**The defect.** Brief property L5(c) says surrogates must "break structural tells — do NOT
preserve length or casing patterns", and `core/src/surrogate/mod.rs` repeated it flatly. It is
false for dates. `format.rs::DateStyle` deliberately re-emits the original's written form, so
`14.06.1959` becomes another `dd.mm.yyyy` and `14 Haziran 1959` becomes another `d MMMM yyyy` —
and a format determines a width. The existing test that "measured" the property drew every
original from the name pool, so it could not see this.

**Measured**, over the direct spans of the committed corpus (1516 pairs, character lengths,
`surrogate::tests::length_correlation_by_label_over_the_committed_corpus`, printed on every run):

| Label | n | Pearson r |
|---|---|---|
| `DATE_DEATH` | 6 | **1.0000** |
| `DATE_ADMISSION` | 155 | **0.8867** |
| `DATE_BIRTH` | 90 | **0.8516** |
| `DATE_DISCHARGE` | 24 | n/a — no length variance on either side |
| `PATIENT_NAME` | 240 | -0.0575 |
| `CLINICIAN_NAME` | 226 | 0.1698 |
| `MRN` | 152 | -0.1900 |
| all labels pooled | 1516 | 0.6934 |

The pooled figure is a mix of populations and is reported only so nobody quotes it as a per-label
result — the denominator lesson of D-027 applies to this table too. The finding is the DATE family
and nothing else; `CERTIFICATE_NO` (0.75, n=5) and `HEALTH_PLAN_ID` (0.59, n=11) are below the
20-pair floor at which a correlation here is a measurement rather than noise.

**Decision: keep format preservation, correct the claim, record the residual.** The two options
were to randomise the output format independently of the input, or to keep it and say so.

*Randomising was rejected*, and this is the substantive half of the ADR. A date is the field
downstream systems parse hardest: an EHR importer, a lab-result matcher and every regex in a
hospital's integration layer are written against the local convention. Re-emitting a `dd.mm.yyyy`
note in ISO, or emitting three different conventions inside one document, breaks the de-identified
note as a *clinical artifact* — which is brief property (a), and property (a) is not a lesser
property than (c). It would also break nothing an attacker cares about: what the format leaks is
the AUTHOR'S TEMPLATE, and that template is visible in every unmasked date-shaped string, every
section heading and every form label in the surrounding prose that L5 never touches. Randomising
the surrogate's format hides one instance of a fact the document announces on every other line.

*What is actually protected* is the absolute value, and the per-patient shift destroys that
completely while preserving intervals (the property the tier exists to keep). A length tell of
r = 1.0 within one format family narrows nothing: `14.06.1959` and `03.11.1987` are the same
width, so knowing the width tells an attacker the format, which they already had.

**The residual, stated so it is not rediscovered as a surprise.** Across format families the tell
is real: a surrogate rendered as `d MMMM yyyy` says the original was written as `d MMMM yyyy`,
which is weak evidence about the note's author, template or era. It is narrower than a name-length
tell — it identifies a document convention rather than a value — but it is not zero, and it is why
this ADR exists rather than a comment.

**Consequences.**
- `core/src/surrogate/mod.rs`'s module doc and `CLAUDE.md`'s L5 spec now state property (c) as
  "break structural tells, except the date format", with the reason attached.
- The name family keeps a real, gated guarantee: the new test asserts |r| < 0.35 for every
  `*_NAME` label with at least 20 pairs, so a regression in the name pool still fails the build.
  Dates are excluded from that gate BY NAME rather than by loosening the bound, which is the
  difference between an exception and a weakened test.
- L6's `structural_leakage` attack will keep reporting date pairs whose length matches. That is
  now expected output rather than a finding, and the red team's severity for a DATE-labelled
  length match should be read against this ADR.

---

## D-029 — The contextual re-ID gate is provenance-checked: only the PIPELINE masker may populate it

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**The defect.** `contextual_reid_rate = 0.0303 PASS` was BYTE-IDENTICAL for the null detector, an
L1-only pipeline and a full pipeline. `eval/harness.py:49` read a committed
`eval/results/redteam.json` whatever it was scoring, and that file had been produced by
`eval/redteam/runner.py --masker oracle` — `OracleMasker` being a gold-derived PERFECT masker.
`--masker` accepted only `{leaky, null, oracle}`; there was no pipeline masker, so no number the red
team could produce had ever described the product. A detector that finds nothing scored the same as
the real system, and `contextual_reid_rate_max` was one of only two gates the NULL detector passed.

The report did say `masker=oracle`, honestly. It was still counted PASS in the gate table, and the
gate table is what a compliance officer reads. Publishing it would have been exactly the failure
this project exists to criticise: a number that came from a different run.

**Decision.**
1. `eval/rust-bridge/` (binary `deid-eval-bridge`) runs the real `core::Pipeline` over the corpus and
   returns its actual masked text and span map. `eval/pipeline.py` wraps it as `PipelineMasker`
   (`--masker pipeline`, now the default) and `PipelineDetector` (`eval/run.py --detector pipeline`).
2. `eval/harness.py` populates `contextual.reid_rate` ONLY from a report whose `masker` is
   `pipeline` AND whose `provenance.detector` and `provenance.eval_sha` match the run being scored.
   Anything else leaves the gate `null` and UNENFORCEABLE — never PASS. The rejected number and the
   reason travel with it in `contextual.reid_rate_provenance`, so the number cannot be read without
   its source.
3. The runner writes two fields: `reid_rate_measured` (always) and `contextual_reid_rate` (the
   gate-eligible copy, null for every reference masker, with `contextual_reid_rate_withheld_because`
   beside it). A reference run additionally emits a `calibration` block.
4. `null`, `leaky` and `oracle` are KEPT, as instrument calibration. They are genuinely valuable —
   1.0000 / high / 0.0303 across three known reference points is real evidence that the red team
   discriminates, and without it a pipeline number would mean nothing. `just red-team-calibrate`
   runs all three; none of them writes `eval/results/redteam.json`.

**The number, reported.** Against the real pipeline: **0.9091** (150 of 165 attackable documents),
ceiling 0.05, **FAIL**. Six of seven attack classes land. That is near the null masker's 0.9333 and
nowhere near the 0.0303 that was being published, which is what a 0.0000 NAME recall predicts. It is
reported anyway; reporting it is the point.

**Alternatives considered.**
1. *Delete the oracle/null/leaky maskers.* Rejected: it would remove the only evidence that the red
   team detects failure at all, trading a false number for an unvalidated instrument.
2. *Keep reading whatever report exists, but rename the field.* Rejected: the defect is not a naming
   problem. A gate a null detector can pass is not a gate whatever the field is called.
3. *Let any masker populate the gate and rely on the `masker=` label.* That is what was already
   happening. The label was accurate and it did not help.

**Consequences, including the negative ones.**
- `just eval` (null detector) now shows `contextual_reid_rate_max UNENFORCEABLE` instead of PASS.
  The run's gate summary gets strictly worse and that is the correction, not a regression.
- The eval now depends on a Rust build. `eval/pipeline.py` shells out to `cargo build --offline`,
  so `just test-airgapped` still holds, but a Python-only checkout can no longer produce a pipeline
  number — it fails loudly rather than falling back to a reference masker.
- The red team is slower: attacking 178 documents now includes a real pipeline pass.
- `eval/rust-bridge/` prints a span map, which the product CLI deliberately refuses to do. It is
  admissible only because I8 makes the corpus synthetic. It is `publish = false`, lives outside
  `bindings/`, and must never be pointed at a clinical note.
- Provenance matching uses string equality on `eval_sha`, and a dirty tree resolves to
  `"uncommitted"` on both sides, so two uncommitted runs match. That is deliberate — the I5 check
  that refuses to ship a card built on `"uncommitted"` lives in `scripts/publish.py` — but it means
  the gate can be enforceable in a working tree that is not reproducible.

---

## D-030 — RESOLVES D-022: `checksum_id_precision` is measured over checksum-validated spans, and I8 makes it unmeasurable here

- **Date:** 2026-07-19
- **Status:** ACCEPTED

**Decision.** D-022 left two honest options open and this entry takes option (a).
`eval.harness.PredictedSpan` now carries `checksum_validated`, and `checksum_id_precision` is
computed over the spans a checksum ACTUALLY VALIDATED rather than over every prediction carrying a
checksum-validatable LABEL. The metric now matches its own name and the brief's justification, "a
checksum-valid TCKN is never a false positive".

**The consequence nobody anticipated, stated plainly.** On this corpus the new denominator is ZERO.
Invariant I8 forbids a checksum-VALID Turkish national ID from existing anywhere in the repository —
the pre-commit hook enforces it — so measurement over the committed corpus finds **128
non-overlapping eleven-digit runs and 0 checksum-valid ones**. The gate therefore reports `n/a` /
UNENFORCEABLE, which is the truth: it was 0.9902 against a 1.000 threshold, and that 0.9902 was a
number about labelling.

The same fact has a second, worse consequence. `Merged::is_protected()` — the single most
safety-critical predicate in the crate, the one thing standing between L4 and a demoted
identifier — is armed by exactly two conditions, a checksum result or agreement between detectors.
With no NER ensemble installed there is no agreement, and with no checksum-valid ID in the corpus
there is no checksum. **The guardrail is never armed on any evaluated document.** Every TCKN in the
gold set arrives at L4 at confidence 0.50, demotable. Nothing in the eval could have detected the
guardrail being broken.

**The structural tension.** I8 exists so that a checksum-valid TCKN in a committed file can never
belong to a real person. The checksum-precision gate and the protection predicate exist because a
checksum-valid TCKN is the one identifier the system may never get wrong. Both are right, and
together they guarantee that the safety-critical path is untested by the benchmark. This is a
genuine structural consequence of I8, not an oversight in either.

**The resolution: prove it somewhere else.** `core/tests/checksum_protection_armed.rs` GENERATES
checksum-valid identifiers at runtime and never writes them to disk inside the repository. They
exist for microseconds inside a test process, which satisfies I8's actual concern while exercising
the whole path: L1 sets `checksum_validated` and `CHECKSUM_CONFIDENCE`, `Merged::is_protected()`
returns true on a single detector, `demote_to_keep` REFUSES (and its error names no digits, I4), the
full `Pipeline` masks the value, and the checksum-INVALID twin of the same digits is shown to be
demotable — which is precisely the shape of every TCKN in `eval/gold`.

**Alternatives considered.**
1. *Weaken I8 for a small set of "known fake but checksum-valid" fixtures.* Rejected outright. A
   checksum-valid TCKN in a committed file is indistinguishable from a real person's, and the whole
   invariant is that nobody has to make that judgement call.
2. *Leave the metric as-is and keep reporting 0.9902.* Rejected by D-022's own reasoning: it is a
   measured disagreement between the gate and the layer, published as though it were the gate.
3. *Compute the metric over checksum-INVALID candidates too, with a different threshold.* Rejected:
   that is a second metric wearing the first one's name, which is the family of defect this ADR and
   D-029 are both about.

**Consequences, including the negative ones.**
- One more gate is UNENFORCEABLE on every run, so `gates_summary.all_gates_passed` cannot be true
  until the corpus can carry a checksum-valid identifier — which, under I8, it never can. Release
  readiness for this gate has to be argued from the synthetic suite, in prose, by a human.
- A detector that does not report `checksum_validated` silently gets `False` and contributes
  nothing to this metric. That is the safe default (it cannot assert protection it did not earn),
  but it means a future detector can leave the gate dark by omission.
- The synthetic suite lives in `core/tests/`, so it does not run in the Python eval and does not
  appear in `eval/results/<run_id>.json`. A card reader sees `n/a` for this gate and must read this
  ADR to learn where the guarantee actually is.

## D-031 — The bundled medical vocabulary ships; `Pipeline::new` is safe by default and the degraded configurations are named opt-outs

**Context.** `route::tests_support::bundled_allowlist` was `#[cfg(test)]`, and `Pipeline::new`
installed `MedicalAllowlist::new()` — empty. All four bindings called `Pipeline::new` and nothing
else. So the entire context-sensitive allowlist resolution of D-010/D-023 — the `Costa`/`costa` and
`Adalat`/`Adalet` discrimination this project's hardest tests are about — executed only inside
`cargo test`, and L5 never ran anywhere: shipped output was `[LABEL]` placeholders. Every collision
test passed and the product did not have the behaviour.

**Decision.**
1. The nine term files are compiled into `core` with `include_str!` (`core/src/route/vocabulary.rs`)
   and `Pipeline::new` installs them. No file I/O, so I1 holds and the wasm32 target still builds.
2. Every binding installs L5 by default. `core/` cannot draw a salt — it performs no I/O, so it has
   no CSPRNG, and a salt from a counter is a salt an attacker reconstructs — so each binding draws
   its own: `getrandom` in the CLI, the gateway and the wheel; the HOST in the browser, because
   `js-sys`/`web-sys` are banned there and linking them is exactly what would put `fetch` in the
   module's import table.
3. Degradation is opt-out and the names carry the cost: `without_medical_allowlist`,
   `--placeholder-labels`, `--no-medical-allowlist`, `deidentifyWithLabelPlaceholders`,
   `label_placeholders=True`.

**Alternatives considered.**
1. *Keep the vocabulary caller-supplied and fix the four call sites.* Rejected. It is the shape that
   produced the defect: four independent places that must each remember, and the failure mode of
   forgetting is silent and looks correct. The old comment argued that a compiled-in vocabulary
   "pins one snapshot of an append-only artifact" — true, and pinning the snapshot that was BUILT is
   the auditable outcome; a caller who forgets pins nothing at all.
2. *Generate an embedded Rust module from the term files with a build script.* Rejected: it creates
   a second copy of the vocabulary in `core/src/`, which is a drift vector between the scored
   vocabulary and the runtime one — the exact defect already found once in this project.
   `include_str!` reads `eval/allowlist/*.txt` directly, so no copy exists. The one surviving vector
   is the FILE LIST, and `vocabulary::tests` reads the directory and fails on it.
3. *Have `core` generate the salt.* Rejected by I1.
4. *Leave the browser's `deidentify` signature alone and add an optional salt argument.* Rejected:
   omitting an optional argument would then be the way to ship placeholders, which is this defect
   again with a smaller blast radius.

**Consequences, including the negative ones.**
- `Server::new` in the gateway is now fallible, and the wasm entry points took a breaking signature
  change. Both are pre-1.0 and both make the unsafe configuration harder to reach by accident.
- `Pipeline::new` clones an indexed `MedicalAllowlist` (~2,200 terms with dotted/dotless variants)
  per construction. The index itself is built once behind a `OnceLock`; the clone is per pipeline,
  not per document, and no binding builds a pipeline per document except the wheel, which already
  rebuilds its contextual adapter per call for unrelated reasons.
- The gateway installs L5 even though `surrogate.rs` re-renders every masked span with its own
  reversible token, so L5's output never reaches the wire there. That is deliberate: "the default is
  the safe one" holding in three bindings out of four is how the fourth becomes the one whose wiring
  is forgotten when a tool that returns raw pipeline output is added. The cost is one surrogate
  derivation per masked span.
- The CLI and the gateway still cannot mask a name, because nothing in them proposes a name span.
  This ADR does not change that and their tests say so in their headers rather than pretending
  otherwise.

---

## D-032 — Two redaction methods, not six: surrogates by default, bracketed placeholders as a named opt-out

- **Date:** 2026-07-20
- **Status:** ACCEPTED

**Context.** OpenMed exposes six redaction methods (`mask`, `remove`, `replace`, `hash`,
`shift_dates`, `format_preserve`) and lets the caller pick per call. Reviewing that menu while
writing `docs/COMPARISON.md` forced the question of which of them deid-tr should offer.

**Decision.** deid-tr offers exactly two ways to rewrite a masked span, and the choice is a policy
setting rather than a per-call parameter:

1. **Format-preserving surrogates (L5), the default** on every binding (D-031).
2. **Bracketed type placeholders**, reached only through an opt-out whose name states the cost:
   `--placeholder-labels` / `label_placeholders=True` / `deidentifyWithLabelPlaceholders`.

`remove`, `hash` and a separately selectable `shift_dates` are REJECTED as product surface.
Date shifting is not a method; it is what the L5 date surrogate already does, and it is not
separately selectable because a caller who shifts dates while leaving names to a different method
has produced a document with two different privacy properties in it.

**Alternatives considered.**
1. Match the six-method menu. Maximum flexibility, and the shape a user migrating from OpenMed
   expects.
2. Surrogates only, with no opt-out at all. Simplest, and the strongest default.
3. The chosen two.

**Rationale.** Each rejected method is rejected for a specific reason, not for tidiness.
`remove` deletes bytes, which destroys the positional alignment between the original and the
output — and the span map that makes the M2 gateway's round trip possible (D-025) is exactly that
alignment. `hash` is deterministic across documents by construction, which is a **cross-document
linkage primitive**: the same patient hashes to the same token in every note, so an attacker holding
two de-identified corpora can join them on a column we handed them. That is one of the seven L6
attack classes we grade ourselves against, and shipping a menu item that guarantees it is
indefensible. A per-call method parameter is itself a hazard: the safest configuration must not be
one of six equally-presented options, because the option list is where a caller optimises for
readability under deadline. Option 2 was rejected because placeholder output is genuinely needed —
for human review of what was masked, and for consumers that cannot tolerate plausible-looking fake
data — and forbidding it would push callers to post-process our surrogates back into labels, worse
and unmeasured.

**Consequences.**
- We are less flexible than OpenMed here, and a migrating user loses four methods. `docs/COMPARISON.md`
  section 3.2 marks this `partial` rather than dressing it as a feature.
- Losing `hash` costs a legitimate use case: longitudinal cohort assembly across notes. The
  replacement is the salted, within-document-consistent surrogate plus the span map held locally by
  the data owner — which is more work for the data owner and is the correct place for that work.
- Placeholder output remains reachable, so the failure mode where a caller ships `[PATIENT_NAME]`
  into a downstream parser that expected a name still exists. It is now at least named at the call
  site.
- The two methods must both be evaluated. A surrogate that leaks through its own shape is a
  measured defect, not a hypothetical one — see D-028, where `DATE_DEATH` surrogate length
  correlates r = 1.0000 with the original.

---

## D-033 — True PDF redaction removes the content stream, and REFUSES a scanned page rather than drawing over it

- **Date:** 2026-07-20
- **Status:** ACCEPTED

**Context.** A PDF carries a text layer and a rendered appearance. The overwhelmingly common
"redaction" bug in the wild is to draw an opaque rectangle over a name and save: the glyphs are
still in the content stream, and any text extractor recovers them in full. OpenMed takes this
seriously — `multimodal/verify_pdf.py` checks a redacted PDF's text layer for leakage — and any
file-level surface we ship has to decide its own policy before it has any code in it.

**Decision.**
1. A redacted PDF is produced by **removing the covered glyphs from the content stream** and
   re-emitting it. A drawn rectangle may accompany that for human legibility; it never substitutes
   for it.
2. Document-level metadata (`/Info`, XMP), embedded file attachments, annotations and the
   incremental-update history are stripped, because a name removed from page 3 is still in the
   previous revision if the file is saved incrementally.
3. **The output is verified before it is written**: the text layer of the result is re-extracted and
   re-scanned, and a run that still finds a masked surface fails rather than writing the file.
4. **A page with no extractable text layer is REFUSED, not processed.** The tool exits non-zero and
   names the page. It does not draw boxes on a scanned page, and it does not silently pass the page
   through.

**Alternatives considered.**
1. Draw-and-flatten: rasterise every page after drawing the boxes. Genuinely removes the text layer.
2. Draw boxes only. What most tooling does.
3. OCR the scanned page ourselves, then redact the recognised regions.
4. The chosen policy, with refusal on scanned pages.

**Rationale.** Option 2 is a data breach with a progress bar. Option 1 destroys every downstream
property of the document — selectable text, accessibility, searchability, file size — and it
converts a text PDF into exactly the scanned page we say we cannot handle. Option 3 is the
interesting one and it is rejected **for now on an honesty ground, not a technical one**: OCR
recall on Turkish clinical scans is unknown to us and unmeasured by anything in `eval/`, and a tool
that OCRs a page and redacts what it recognised produces a document whose privacy is bounded by an
OCR error rate the user cannot see and we have not published. Refusal is the only response that does
not make an unmeasured promise. It is also the response that fails LOUDLY, which is the whole
disposition of I2: the user learns that page needs handling some other way.

**Consequences.**
- Mixed documents — a typed discharge summary with one scanned consent form appended — are refused
  as a whole until the user splits them. That is real friction and users will feel it as the tool
  being broken.
- We are strictly less capable than OpenMed on scanned documents, which handle them through four OCR
  engines. `docs/COMPARISON.md` section 3.3 records this as `no`, with the refusal rule named.
- The verify-before-write step means every redacted PDF is parsed twice, and a PDF whose text layer
  cannot be re-extracted at all after rewriting fails the run even if the redaction was correct.
- Rule 4 is only as good as "has an extractable text layer". A page with a thin, near-empty text
  layer over a scanned image — a common output of some scanner software — will pass the check while
  behaving like a scan. That gap is real and is not closed by this ADR.
- None of this masks names, because nothing in this pipeline masks names yet. A PDF surface built
  today removes rule-detectable identifiers from a PDF and nothing else.

---

## D-034 — NFC and nothing else: no NFKC, no NFD, and the compatibility folds we do want are done explicitly and reversibly

- **Date:** 2026-07-20
- **Status:** ACCEPTED

**Context.** Text arriving from a file, a clipboard, a DOCX or an HTTP body is not in a canonical
Unicode form. `Ş` may be one code point (U+015E) or two (`S` + U+0327 COMBINING CEDILLA), and the
two forms compare unequal, hash unequal, and produce different byte offsets. Separately, the L1
failure-mode list in the brief names full-width and non-ASCII digits and invisible characters glued
into identifiers as live evasion vectors, and `core/src/text/digits.rs` and
`core/src/text/invisible.rs` exist to handle them.

**Decision.**
1. **Normalisation form is NFC, applied once at the ingestion boundary in `bindings/`, never inside
   `core/`.** The NFC text is what `core::Pipeline` receives and what every byte offset in a `Span`,
   a span map or an audit entry refers to. Offsets are never reported against the pre-normalisation
   bytes.
2. **NFKC is forbidden.** So is NFD, and so is NFKD.
3. The two compatibility behaviours we actually want — folding non-ASCII decimal digits to ASCII for
   checksum evaluation, and neutralising invisible format characters inside a candidate identifier —
   are performed **explicitly, narrowly and reversibly** by `core/src/text/digits.rs` and
   `core/src/text/invisible.rs`, over the candidate span only, never over the document.
4. `Normalization::TurkishDottedI` (`core/src/detect/align.rs`) is unaffected and remains
   character-for-character with a reversible index. It is a model-input fold, not a document
   rewrite.

**Alternatives considered.**
1. No normalisation at all. Zero offset risk; leaves decomposed `Ş` unmatched by every rule and
   every vocabulary entry.
2. NFKC, which would fold full-width digits and a great deal else for free.
3. NFD, so that combining marks are uniform.
4. NFC plus targeted explicit folds — chosen.

**Rationale.** Option 1 is an evasion vector: an attacker, or merely an unlucky export from a
hospital system, writes the patient name in decomposed form and every allowlist lookup, surrogate
key and rule match misses it. Option 2 is rejected because NFKC's mapping table is large,
open-ended and **clinically destructive**: it rewrites `µ` (U+00B5) to `μ`, `℃` to `°C`, ligatures
to their parts, and superscripts and subscripts to baseline digits — which silently turns a dosage
or a formula into different text, in a document whose whole purpose is to stay clinically readable
after masking. It also changes lengths across an unbounded character set, so every offset in the
system depends on a table we do not control. Getting full-width-digit folding "for free" is not
worth buying the rest of that table, especially when the fold we need is a dozen lines and can be
scoped to the candidate span. Option 3 is rejected because decomposing splits a Turkish letter into
a base plus a combining mark, which multiplies the number of char boundaries inside every name,
breaks the "one letter, one boundary" reasoning the span type depends on, and weakens the casing
signal that I6 says is the strongest name evidence in Turkish.

**Consequences.**
- NFC is not free: it can change byte length (decomposed input is longer than composed), so the
  binding that normalises MUST keep the index that maps output offsets back onto the bytes the user
  actually gave us, or a masked file will be rewritten at the wrong positions. That index is now a
  correctness dependency of every file surface.
- Because normalisation happens in `bindings/` and not `core/`, **each binding can forget to do
  it**, and a binding that forgets has a silent recall hole rather than a compile error. This is the
  same hazard D-031 records for the allowlist and L5, and it wants the same treatment: a default
  that is hard to skip.
- We keep exactly the compatibility problems NFKC would have solved and that we chose not to solve:
  ligatures, enclosed alphanumerics, and non-ASCII digits appearing anywhere other than inside a
  candidate identifier are not folded, and a rule that would have matched after NFKC will not match.
- A document that was already NFKC-normalised upstream reaches us with that damage already done, and
  we cannot detect it.

---

## D-035 — The REST service binds loopback only; exposure requires a flag, a token and a startup warning, and the container image gets no exception

- **Date:** 2026-07-20
- **Status:** ACCEPTED

**Context.** I3 forbids binding `0.0.0.0`. `bindings/service` introduces the first deid-tr surface
that opens a socket at all — the MCP gateway deliberately has none and refuses the flags that would
imply one (D-026) — so I3 stops being a rule about code nobody writes and becomes a rule about a
running process.

**Decision.**
1. The default bind is `127.0.0.1` on an explicit port. `0.0.0.0`, `::`, and any address that is not
   a loopback address are rejected **at parse time**, not at bind time, and rejected by value rather
   than by string comparison, so `0.0.0.000`, `0x0.0.0.0`, `[::ffff:0.0.0.0]` and a hostname that
   resolves off-loopback are all refused.
2. Exposure beyond loopback requires ALL THREE of: an explicit `--expose` flag, a bearer token
   supplied by the operator (never generated for them, never defaulted), and a warning printed to
   stderr at startup naming the address it is listening on.
3. There is no environment variable that can turn (2) on. A misconfigured deployment environment must
   not be able to expose a PHI endpoint without someone having typed the flag.
4. **The container image gets no exception.** Any compose or container file we ship publishes
   `127.0.0.1:PORT:PORT`, never `PORT:PORT`.
5. Request and response bodies never enter a log, a metric label, a trace attribute or an error
   string (I4). Metrics, if enabled at all, are pull-only and labelled by route template and status
   code.

**Alternatives considered.**
1. Bind loopback by default and let a plain `--host` flag take any address. The conventional design,
   and what most services do.
2. Ship no REST surface at all, on the grounds that a network service holding PHI is a category of
   risk we do not need.
3. The chosen three-part gate.

**Rationale.** Option 1 fails in the one direction that matters: `--host 0.0.0.0` is the single most
copy-pasted line in server documentation, it appears in every "it works in Docker now" answer, and
it silently converts a local tool into an unauthenticated PHI endpoint on a hospital LAN. Requiring
three separate deliberate acts means no single copy-paste can do it. Rule 4 exists because it is the
exact gap in an otherwise careful posture next door: OpenMed's documentation is consistently
loopback — uvicorn examples use `--host 127.0.0.1`, trusted-host checking is always on, CORS is off
unless exact origins are listed — and their shipped `docker-compose.yml` publishes on all host
interfaces anyway, with the docs telling you to change it. That is not a criticism of their
judgement; it is evidence that the container file is where this rule gets lost, so we name it in the
ADR rather than trusting ourselves to remember. Option 2 was seriously considered and rejected
because the alternative to a local REST service is not "no network service" — it is the user standing
up their own wrapper around the Python binding, with none of these properties.

**Consequences.**
- Legitimate multi-host deployments are inconvenient by design. A team that wants the service on a
  cluster must set a token and pass a flag on every start, and they will find this annoying.
- Rejecting non-loopback addresses at parse time means we must implement address classification
  ourselves rather than deferring to the OS bind call, and an address family we classify wrongly is
  a bug in the direction of refusing something valid — the safe direction, but a support burden.
- A bearer token in a process argument is visible in `ps`. Reading it from a file or stdin is the
  better shape and this ADR does not settle it.
- Rule 3 means an operator cannot configure exposure through the same mechanism as everything else,
  which is genuinely inconsistent configuration design. We accept the inconsistency because the
  asymmetry is the point.
- None of this makes the service safe to expose. It makes exposing it a decision someone made.

## D-036 — L1's `Doc` IS the Unicode skeleton; and an exotic space between two digits is dropped, not folded

**Status.** Accepted. Supersedes nothing; completes D-034, which specified the fold but left it
without a caller.

**Context.** `core/src/text/` implemented the fold, the offset index, the confusable table and the
invisible-character policy, and its module header presented a four-row table of evasions as
"handled". Nothing outside the module called it. L1 ran its own normaliser — `rules::mod::Doc` —
which folded decimal digit systems and nothing else. Measured against the live pipeline with a
checksum-valid TCKN: fullwidth, Arabic-Indic and bidi-wrapped ids were detected; ids split by
U+200D, U+00AD, U+200B, U+FEFF or U+00A0 produced zero spans. `recall.TCKN` read 0.9792 against a
0.98 floor — a failing gate on a checksum-validatable direct identifier, which is an I2 violation.

**Decision.**

1. `rules::mod::Doc` is a thin wrapper over `text::Skeleton` at `Fold::Skeleton`. It owns no
   normalisation of its own. There is exactly ONE fold and ONE offset index in the crate, because
   two offset maps that stack instead of compose is the bug class the index exists to close.
2. An exotic space (U+00A0 and family) BETWEEN TWO DIGITS is dropped from the matching buffer
   rather than folded to an ASCII space. Everywhere else it is still folded to a space.
3. The ASCII space is never bridged. `0532 123 45 67` is written that way on purpose, and
   tolerating a real space inside an identifier is a rule-module decision, not a normaliser's.
4. `route::allowlist::MedicalAllowlist::lookup` refuses every mixed-script token, wiring
   `text::is_mixed_script` into the one place it was written for.

**Rationale.** (2) is the only part that is not mechanical. The stated reason exotic spaces are
folded rather than deleted is that they SEPARATE TOKENS, and deleting one glues `Ayşe` to `Yılmaz`
into a token no gazetteer has seen. Two digits of one number are not two tokens: a NO-BREAK SPACE
between them is what a word processor inserts precisely to say "do not wrap here", and a PDF text
extractor hands it through mid-identifier. Folding it to a space there splits an eleven-digit run
into four and seven, which is a missed national ID — a breach, against a papercut on the other side.
(4) is I2's precedence rule made executable: `carcinom` + Cyrillic `а` folds onto a real allowlist
term, so without the check the fold would hand an attacker a deterministic `Keep` for anything they
can disguise. Refusing the entry masks nothing by itself; it withdraws the short-circuit so the span
reaches the adjudicator on its own evidence.

**Consequences.**
- `recall.TCKN` 0.9792 -> 1.0000, strict and relaxed. No other entity's recall moved in either
  direction; micro relaxed recall 0.3888 -> 0.3901, micro precision 0.8859 -> 0.8863,
  medical-term FP rate unchanged at 0.0000 annotated / 0.000488 vocabulary.
- Every L1 span now travels through `Skeleton::original_range`, which refuses a mid-character
  offset rather than rounding it. A rule that produced one used to get a truncated span; it now
  gets no span. That is the safe direction but it is a behaviour change.
- The confusable fold is now live in L1, so a homoglyph can make a rule match where it did not
  before. Precision on the committed corpus did not move, but this is a real widening.
- A digit run bridged across an NBSP means a European thousands separator (`10 000 000` written
  with U+00A0) reads as one long run. Only checksum-PASSING windows are emitted from such a run,
  so the exposure is the ~1% of random eleven-digit windows that pass — accepted under I2.
- `Fold::Compose`, `Skeleton::original_slice`, `invisible::contains_invisible` and
  `invisible::contains_bidi_control` remain unconsumed by the pipeline. They are documented in
  `text/mod.rs` as signals offered to bindings, explicitly NOT as controls this crate enforces.

---

## D-037 — Both escalation rates re-measured over the full 190-document corpus: 40.5% and 3.83%

- **Date:** 2026-07-20
- **Status:** ACCEPTED. Supersedes the NUMBERS in D-023 (3.87%) and D-027 (40.0%). Neither ADR is
  withdrawn and neither is edited — `docs/DECISIONS.md` is append-only, and both remain correct
  accounts of what was measured when they were written. Their reasoning stands unchanged; only the
  denominators grew.

**The defect.** `core/src/route/mod.rs::corpus_measurement` embeds its corpus with `include_str!`,
which requires literal paths, so it carries a hardcoded list of fixture files. The eval harness
(`eval/build_gold.py`) discovers fixtures with `rglob("*.jsonl")`. When
`eval/adversarial/adv_unicode.jsonl` added 12 documents, the harness moved to 190 and the Rust
measurement stayed on 178. Nothing failed. Both sides were internally consistent, `cargo test` was
green, and the escalation rate published in `docs/COMPARISON.md` section 4 quietly described a
smaller corpus than the benchmark numbers printed beside it.

This is the same shape as the defects behind D-029 and the `bundled_allowlist` finding: code that
is correct, tested, and wired to something other than the thing it is quoted against. It is the
most dangerous failure mode this project has, because every gate stays green.

**Re-measured, 2026-07-20, over the same 190 documents the harness walks:**

| Quantity | Denominator | Was | Now |
|---|---|---|---|
| Vocabulary escalation rate | class C vocabulary occurrences | 74 of 1910, **3.87%** (D-023) | 74 of 1934, **3.83%** |
| Router escalation rate | candidates reaching `route()` | 268 of 670, **40.0%** (D-027) | 274 of 677, **40.5%** |

**What did not change: the conclusion.** D-027's finding was that the brief's "2–5% of spans"
claim for the Safe Harbor tier is wrong by roughly an order of magnitude. 40.5% is not materially
different from 40.0%, and the correction stands exactly as written. The 12 added documents are
Unicode-evasion fixtures — dense in identifiers, thin in prose — so they add candidates without
shifting the distribution much. **Nobody should read this ADR as the rate having moved. It moved by
half a point; what moved is that the number now describes the corpus it is quoted against.**

The escalated-label breakdown is unchanged in shape: MRN 156, TCKN 96, SGK_NO 11, IBAN 7, VKN 4.
MRN and TCKN dominate for the reason D-027 gives — both are emitted at 0.50, below
`ESCALATION_CONFIDENCE_MAX` (0.60), so every one of them escalates.

**Still zero checksum-validated and zero multi-detector auto-masks**, over all 677 candidates. That
is not a router defect: I8 forbids a checksum-valid Turkish ID from existing in this repository, so
no corpus document can contain one, and L2 is a stub so no second detector exists to agree. The
`is_protected()` guardrail — the single most safety-critical predicate in the crate — is therefore
correct and armed on nothing here. It is exercised instead by
`core/tests/checksum_protection_armed.rs`, which generates valid identifiers at runtime and never
writes one to disk.

**Consequences.**

- Two published figures were stale for a session and are now correct. The cost of the fix was one
  `include_str!` line; the cost of *finding* it was a reader noticing that two numbers on the same
  page described different corpora.
- `tests/test_corpus_manifest.py` now fails when a fixture exists on disk but is not embedded in
  `CORPUS`, in both directions. This is the real remediation — the number was a symptom, the
  hand-maintained list was the defect, and without the guard the next fixture file re-creates it.
  Verified by removing the `adv_unicode` line and confirming the test fails and names the file.
- The guard lives in Python, not Rust, because the check needs to read a directory and `core/`
  performs no runtime I/O (I1). A drift check that cannot look at the filesystem cannot detect
  drift, so it belongs on the side of the boundary where filesystem access is ordinary.
- The rate is still **reported, not gated**. Asserting a ceiling here would either fail the build
  for reporting a true number or invite someone to move `ESCALATION_CONFIDENCE_MAX` until the
  number looked right, which is tuning a metric rather than measuring one. That reasoning is
  D-027's and it is unchanged.
- Both measurements remain averages over a mixed corpus, and D-023's caveat about eponym-dense
  documents still applies unchanged.
