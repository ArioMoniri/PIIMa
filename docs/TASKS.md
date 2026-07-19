# TASKS — milestone M0: golden set + eval harness

This file covers the **current milestone only** and is rewritten at each milestone boundary.
Boxes are ticked by the orchestrator after verification, never by the agent that did the work.

## M0 EXIT CRITERION

> `just eval` runs green on an **empty detector** and reports **0.0 recall across all direct entity
> types, 0% contextual coverage, and 0% medical-term false positives**.

An eval harness that cannot report total failure cannot report success. A harness that scores above
zero with nothing plugged in is measuring its own fixtures, not the pipeline. M0 is not done until
the floor is demonstrated.

## Tasks

- [x] **Entity schema** — `eval/schema.yaml` covering all three classes: A direct identifiers
      (Safe Harbor 18 mapped to Turkish, incl. TCKN/VKN/SGK, Turkish address parts, Turkish phone
      formats), B contextual quasi-identifiers (`EMPLOYER_ROLE`, `RELATIONSHIP_REF`,
      `ASSET_LOCATION`, `DISTINCTIVE_EVENT`, `RARE_ATTRIBUTE_COMBO`), C the medical-term allowlist.
      Every direct entry carries `id`, `hipaa_category`, `identifier_class`, `detector`,
      `tr_specific`, `checksum_validatable`, `recall_threshold`, and `precision_threshold: 1.000`
      when checksum-validatable.

- [x] **Thresholds** — `eval/thresholds.yaml` holding the release gates (HIPAA-critical direct recall
      >= 0.98; micro F1 all direct >= 0.95; document leak rate <= 2%; medical-term FP rate <= 0.5%;
      contextual re-ID rate <= 5%; sight-unseen recall drop <= 5 points; checksum-validated ID
      precision 1.000). File header and harness both mark it **RAISE-ONLY**: lowering any value
      requires a `docs/DECISIONS.md` entry plus explicit human approval.

- [x] **Golden set v0** — 100 synthetic Turkish clinical notes with gold spans. Mandatory coverage:
      (a) code-switched Latin/English medical terms carrying Turkish suffixes (`carcinoma'lı`,
      `MRI'da`, `PET-CT'de`, `metformin'e`) and (b) contextual quasi-identifiers stated in narrative
      prose, not as fields. All synthetic (I8); every TCKN written must be checksum-INVALID.

- [x] **Adversarial seed** — at least 30 fixtures spanning three kinds: direct-identifier edge cases
      (suffixed IDs, glued digits, non-ASCII digits, transliteration drift); medical-term-as-false-
      name (`Adalat` vs `Adalet`, `Deva`, `Costa`); contextual quasi-identifiers.

- [x] **Negative fixtures** — `eval/allowlist/`: medical vocabulary that must never be masked
      (diagnoses, anatomy, drugs, standard abbreviations), including code-switched Turkish-suffixed
      forms. This is the corpus behind the medical-term false-positive rate.

- [x] **Eval harness** — `eval/harness.py` reporting: per-entity recall / precision / F1 for direct
      identifiers; medical-term false-positive rate; a hook for the red-team-validated contextual
      re-ID rate (populated in M5, present and reporting 0% now); document leak rate (fraction of
      documents with >= 1 missed direct identifier); and a sight-unseen split held out from any
      tuning.

- [x] **Card contract** — the harness emits `eval/results/<run_id>.json` containing at minimum
      `eval_sha`, `language`, and `base_model`. This file is the only permitted source of model-card
      numbers (I5); `scripts/publish.py` reads it and no human writes a card.

- [x] **`justfile`** — recipes `check` (fmt, clippy -D warnings, test, eval), `eval`,
      `test-airgapped`, `publish`.

- [x] **Air-gap proof** — `just test-airgapped` runs the suite with networking disabled and proves
      **zero network syscalls** from `core/` (I1), failing loudly rather than skipping.

- [x] **Pre-commit hook** — blocks any commit containing a TCKN-checksum-valid number (I8). Checksum:
      11 digits, `d1 != 0`, `d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10`,
      `d11 = (d1+..+d10) mod 10`.

- [ ] **Tokenizer gate** — `scripts/gate_tokenizer.py` asserting lossless round-trip of code-switched
      TR/EN/Latin text including Turkish morphology on Latin roots, and asserting that
      `distilbert-base-uncased` **FAILS** for Turkish. A gate with no known failing input is not a
      gate (I6).
      **PARTIAL — left unticked.** The script exists and `python3 scripts/gate_tokenizer.py
      --self-test` is green offline (9 passed, 0 failed), covering the uncased rejection, the
      dotted/dotless-i lowercasing rejection, and the byte-versus-character offset rejection. What
      remains: it has never been run against a REAL published tokenizer. Loading
      `dbmdz/bert-base-turkish-cased` or `distilbert-base-uncased` requires a download, and network
      access needs explicit human approval. Until that has run, the gate is proven against its own
      stubs and not against the artifacts it will gate.

- [ ] **Incumbent baseline** — run the incumbent's published Turkish model through our harness across
      all three fixture kinds (direct identifiers, medical-term false positives, contextual
      quasi-identifiers) and commit the result as the reference row. Reported as a measurement, not
      a polemic.
      **BLOCKED ON APPROVAL — not started.** Requires downloading a third-party checkpoint from
      Hugging Face, which is a network operation, and the standing rules forbid sending or fetching
      anything over the network without explicit human approval in-session. `scripts/
      baseline_incumbent.py` exists as the runner; it has not been executed and no reference row has
      been produced. Nothing about this task can be completed offline.
