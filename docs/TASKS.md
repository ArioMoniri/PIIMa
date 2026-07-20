# TASKS — milestone M6: surfaces

This file covers the **current milestone only** and is rewritten at each milestone boundary. Boxes
are ticked by the orchestrator after verification, never by the agent that did the work.

> **Rewritten 2026-07-20.** The previous revision still described M0 and had done so for a long
> time, while the tree had reached M6. A task list that describes a milestone the project left is
> worse than no task list: it is a list somebody reads to decide what to do next.

## THE STANDING DISCLOSURE

**This build masks ZERO names.** L2 has no trained model and no weights ship. Every measurement
below is the measurement of a pipeline whose name detector does not exist. No box in this file, and
no string in any surface, may imply otherwise.

## Where the project actually is

| Milestone | Layers | State |
|---|---|---|
| M0 golden set + eval harness | — | **Done**, except two tasks that need a network operation nobody has approved (carried below). |
| M1 deterministic rules | L1 | **Done and measured.** |
| M2 MCP gateway, round-trip span map | L1+L2 | **Done.** `deid-mcp` builds and is registered by `just register-mcp`. |
| M3 NER ensemble | L2 | **NOT STARTED. The seam is built and empty.** `NerEnsemble`, BIOES/Viterbi decode, union merge and the `Detector`/`Tokenizer` traits exist and are tested against synthetic logits. No model is trained, no backbone has been fine-tuned, no weights exist. This is the single largest gap in the product. |
| M4 contextual sweep + router | L3+L4 | **Code done, L3 unvalidated.** L4 runs on every note with the audited allowlist. L3 is wired to a local GGUF runtime (D-038) and refuses loudly without one; nobody has run it against a real model, so its quality is unmeasured. |
| M5 surrogates + re-ID red team | L5+L6 | **Done as machinery.** L5 is installed by default in every surface. L6 runs and reports; its number for the current pipeline is a failing 0.8983, which is the correct answer for a Safe Harbor run with no L3 and no names masked. |
| **M6 surfaces** | all | **In progress. This milestone.** |
| M7 publish | all | **Not started, and blocked on M3.** There is nothing to publish: I5 forbids a card without a committed eval run, and there is no model to card. |

### The current numbers, measured not asserted

`python3 eval/run.py --detector pipeline` over the committed corpus, 2026-07-20. Reported as three
separate numbers, never as an aggregate:

- **Direct-identifier recall, HIPAA-critical (NAME, ID, CONTACT): 0.4269** against a 0.98 gate. The
  shortfall is names: every NAME label scores 0.0000.
- **Medical-term false-positive rate: 0.0005** against a 0.005 ceiling. **PASS** — the one release
  gate this build meets.
- **Contextual re-ID rate: 0.8983** against a 0.05 ceiling, on a run with no L3.

Per-entity, the rules layer does what it claims: `TCKN`, `VKN`, `SGK_NO`, `IBAN`, `PHONE`, `EMAIL`,
`MRN` and `DATE_BIRTH` all score **1.0000**. The other date roles are partial (`DATE_DISCHARGE`
0.7917, `DATE_DEATH` 0.6667, `DATE_ADMISSION` 0.5742). Everything whose schema `detector` is `ner`
scores **0.0000**, as does every direct identifier with no rule written yet (`PASSPORT_NO`,
`ACCOUNT_NO`, `DEVICE_ID`, `IP_ADDRESS`, `URL`, `LICENSE_PLATE`, `POSTAL_CODE`, `ADDRESS_*`,
`FACILITY_NAME`, and the rest). `checksum_id_precision` is **UNENFORCEABLE** by construction: I8
forbids a checksum-valid Turkish ID in the repository, so the corpus cannot exercise it (D-030).
`micro_f1_direct` at 0.5418 is reported and not leaned on, for the reason the harness prints.

## M6 EXIT CRITERION

> Every surface in the runtime matrix either **runs**, or is **named in this file as not built**.
> No surface is listed as delivered unless somebody has executed it and said so here.

A roadmap item marked done that cannot be run is the failure mode this project has hit repeatedly
(D-029, D-037). The exit criterion is written against that, not against a count of directories.

## Tasks

- [x] **CLI — `deid`.** `mask`, `batch`, `doctor`, `verify`, config precedence, the L3 tier gate.
      Verified: builds in release via `just build-all`; the workspace test suite is green across 34
      test binaries.

- [x] **MCP gateway — `deid-mcp`.** stdio JSON-RPC, round-trip span map, no socket (D-026).
      Verified: builds in release; `just mcp-no-socket` is part of `just check`.

- [x] **REST service — `deid-serve`.** Loopback-only bind, refuses all-interfaces unconditionally,
      session store with TTL (D-035, D-040). Verified: builds in release, 88 + 12 tests green.

- [x] **File and document formats.** PDF (true redaction, output re-opened and verified), DOCX, TXT,
      CSV, JSON, JSON Lines; scanned pages refused rather than returned looking processed (D-033,
      D-039). Verified: `bindings/files` tests green, exercised through the CLI and the desktop app.

- [x] **Browser panel + PWA — `bindings/wasm`.** Verified: `just build-wasm` produces both targets,
      `just test-wasm` proves zero uploads with every networking global stubbed.

- [x] **Desktop application — `bindings/tauri`.** Tauri v2, calling the native crates directly
      rather than through wasm; text de-identification, file open/redact/save through OS dialogs,
      a live layer report, and the L3 tier gate with an actionable refusal.
      **Verified by running it:** `just build-tauri` builds offline; the binary launches and holds a
      window; 17 tests pass without a webview; `just tauri-no-network` passes and was proven to FAIL
      when a capability is added; `just build-all` builds it with nothing skipped. The
      names-are-not-masked disclosure is in the main view, not an About box.

- [ ] **Desktop: mobile targets (iOS, Android).** **NOT STARTED.** `tauri.conf.json` carries
      `bundle.iOS.minimumSystemVersion` and `bundle.android.minSdkVersion` and the Rust is portable,
      but `tauri ios init` and `tauri android init` have never been run, no Xcode or Gradle project
      exists, no NDK toolchain has been proven, and nothing has run on a device or a simulator. The
      file-picker flow in particular uses a desktop dialog whose mobile equivalent is a different
      document-provider model nobody here has touched. Configured is not built.

- [ ] **Desktop: installers and app bundles.** **NOT STARTED.** `bundle.active` is `false`, so
      `just build-tauri` produces a bare executable and no `.app`, `.dmg`, `.msi`, `.deb` or
      `.AppImage`. Needs a per-platform icon set and, on macOS and Windows, code-signing identities
      this repository does not have. An unbundled macOS binary also relaunches unreliably within a
      second of being killed, which bundling would fix.

- [ ] **Desktop: verify on Linux and Windows.** **NOT DONE.** Built and run on macOS only. The
      `webkit2gtk-4.1` skip path in `just build-all` is written and its detection command was
      exercised against an unresolvable manifest, but the Linux branch itself has never executed.
      Nothing about the desktop app has been observed on Windows.

- [ ] **React panel — `bindings/panel-app`.** In progress in a parallel line of work; not assessed
      here and deliberately not ticked by this session.

## Carried from M0 — still blocked, still not done

Neither can be completed offline, and the standing rules forbid a network operation without explicit
in-session human approval.

- [ ] **Tokenizer gate against a real tokenizer.** `scripts/gate_tokenizer.py --self-test` is green
      offline (9 passed, 0 failed) and covers the uncased rejection, the dotted/dotless-i rejection
      and the byte-versus-character offset rejection. It has never been run against a published
      tokenizer, because loading `dbmdz/bert-base-turkish-cased` or `distilbert-base-uncased`
      requires a download. The gate is proven against its own stubs, not against the artifacts it
      will gate (I6).

- [ ] **Incumbent baseline.** `scripts/baseline_incumbent.py` exists as the runner and has never
      been executed. Requires downloading a third-party checkpoint. No reference row exists.

## What M6 does not cover, so nobody goes looking

- **Training anything.** M3 is a separate milestone and it is the one that moves the recall numbers.
  No amount of surface work changes 0.4269.
- **Running L3 against a real local model.** The wiring is done and refuses honestly without one;
  measuring its output is M4 work that needs a model on a machine.
- **Publishing.** M7, blocked on M3.
