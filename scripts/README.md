# scripts/

Publishing and gating tools. Nothing here is on the de-identification path:
`core/` and `eval/harness.py` never import any of it, which is what lets two of
these scripts reach the network without touching invariant I1 (PHI never leaves
the device).

| Script | Does | Network |
|---|---|---|
| `gate_tokenizer.py` | Invariant I6. Refuses a backbone whose tokenizer cannot round-trip the language, including code-switched Latin/English medical terms carrying Turkish morphology, and refuses every `*-uncased` backbone for Turkish outright. Verifies that reported offsets re-anchor onto correct UTF-8 byte offsets. `--self-test` proves offline that the gate rejects what it must reject. | Yes, by default. Resolving a hub id downloads a tokenizer. This is a publish-time gate run by a maintainer against a public backbone with no patient text in the process; it announces the fetch on stderr, and its network path refuses to run unless `main()` armed it. `--local-only <dir>` reads a tokenizer from disk and touches nothing. |
| `publish.py` | Invariant I5. Generates a model card from `eval/results/<run_id>.json` and from no other source of numbers. Six blocking preflight steps: the run is committed and matches HEAD, `eval_sha` equals HEAD, the I6 tokenizer gate passes for the named backbone, every gate in `eval/thresholds.yaml` is present and passing, card language equals eval language, and the widget example is synthetic and in-language. | Indirectly: it shells out to `gate_tokenizer.py`, which fetches unless `--local-tokenizer` is given. `publish.py` itself has no upload code path at all - no `HfApi`, no `push_to_hub`, no flag that would add one. It writes the card to a build directory, prints the diff, and stops. |
| `card_template.md` | The Jinja template `ModelCard.from_template` renders. Every number in it comes from the template context, which comes from the results JSON. There is no hardcoded metric anywhere in the file. | No. |
| `baseline_incumbent.py` | Runs a third-party Turkish PII model through our harness on all three fixture kinds and writes a results artifact in the same schema as our own runs, so the comparison is measured rather than asserted. Reports the same three separate numbers. | Yes. It downloads a third-party model and tokenizer. It refuses to start without `--i-have-approval` and prints what it is about to fetch. The corpus it scores against is the synthetic gold set in this repository; no patient text is involved. |

## Rules that hold across all of them

- Neither `core/` nor `eval/harness.py` may import anything in this directory.
  The I1 exception is bounded to publish-time and benchmarking tooling.
- No script here installs a dependency. A missing library produces an
  actionable message and a non-zero exit, never a traceback and never a silent
  `pip install`.
- No script here pushes, uploads, or commits. Publication is a human action
  taken with explicit approval, against a card that has already been reviewed.
- Every example string committed in this directory is synthetic, and every
  national-ID-shaped number in one deliberately fails its checksum (I8).
