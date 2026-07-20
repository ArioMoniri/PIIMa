# L2 candidates -- Turkish PII checkpoints we could put behind the detector seam

**Status of this document:** a shortlist and a set of expectations, not a result. Nothing here has
been measured against `eval/gold/`. **This build still masks ZERO names** and this document does not
change that. See `README.md` and `docs/COMPARISON.md` for the state of the shipped binary.

L2 is the neural NER ensemble. It is the layer that masks names, and it is the one blocker between
this project and a number a compliance officer could read. The decode, the alignment, the union and
the merge are all built and tested in `core/src/detect/` against `MockDetector`; the forward pass
sits behind `Detector` and lands in `bindings/ort/`. What has never existed is a checkpoint worth
putting there for Turkish.

---

## Candidate 1 -- `ytu-ce-cosmos/modernbert-tr-pii-ner`

### Citation

> Yıldız Technical University Cosmos research group (ytu-ce-cosmos).
> `ytu-ce-cosmos/modernbert-tr-pii-ner`. Hugging Face model repository. Apache-2.0.
> Base model: `ytu-ce-cosmos/modernbert-tr-base`.

Cite the repository and the revision, never this file. Under I5 a number is meaningless without the
checkpoint and revision that produced it, and D-042 makes that binding explicit.

### What it is, stated from the card and config and nothing else

| | |
|---|---|
| Repository | `ytu-ce-cosmos/modernbert-tr-pii-ner` |
| Parameters | 149.4M |
| Licence | Apache-2.0 |
| Artifacts | ONNX and safetensors |
| Tokenizer | cased WordPiece, vocabulary 50,008 |
| Label space | 25 KVKK entity types, 51 BIO labels |
| Base model | `ytu-ce-cosmos/modernbert-tr-base`, ModernBERT architecture, 8,192 context |
| Reported score | 80.85 +/- 0.19 overlap micro-F2 on a 300-document test set |
| Released checkpoint | 81.01 on the same measure |
| Quantized (int8) | 71.90 on the same measure |
| Training data | 8,014 documents: Turkish web PDFs, anonymized high-court decisions, born-labeled synthetic documents, OCR-degraded synthetic documents. The loader retained 7,763. |

### Why this is the first candidate worth the work

Be plain about it: this is a good piece of work and it is exactly the artifact this project has been
blocked on since M0.

- **The base is cased.** I6 rejects every `*-uncased` backbone for Turkish outright, because
  lowercasing corrupts İ/I/ı/i and casing is the strongest name signal there is. A cased Turkish
  WordPiece is the entry requirement, and most of what is published fails it.
- **The licence is permissive.** Apache-2.0 matches this repository's licence, so integration is a
  technical question rather than a legal one.
- **The label set is KVKK-shaped**, not a translated English PII schema. KVKK (Law No. 6698, under
  which health data is a special category) is the regulatory hook this whole project hangs on, and a
  label inventory built against it starts closer to our entity schema than anything else available.
- **ONNX ships alongside safetensors**, which is the artifact `bindings/ort` consumes. No conversion
  step to get wrong.
- **A test set and a variance figure are published.** `+/- 0.19` means somebody ran it more than
  once. Section 1.1 of `docs/COMPARISON.md` exists because a large published family shipped Turkish
  cards carrying another language's numbers. This card does not do that.

### The three reasons it may not clear our gates

The point of integrating it is to find out. All three of the following are expectations, not
findings, and each one is a prediction this project has committed to testing rather than assuming.

#### (a) DOMAIN -- it was not trained on clinical text

The training corpus is Turkish web PDFs, anonymized high-court decisions, born-labeled synthetic
documents and OCR-degraded synthetic documents. None of that is a clinical note. Our benchmark is
190 synthetic Turkish clinical documents in `eval/gold/` and `eval/adversarial/`.

Clinical Turkish is its own register. It is saturated with Latin and English medical vocabulary that
takes Turkish suffixes (`carcinoma'lı`, `MRI'da`, `PET-CT'de`, `metformin'e`), and the boundary
between a suffixed Turkish name and a suffixed Latin term is exactly where a token classifier fails.
A model that has seen court decisions and web PDFs has seen Turkish names in abundance and this
register never.

**We EXPECT a drop, and measuring its size is the entire point of the integration.** The project
brief names the sight-unseen case directly: RoBERTa on i2b2 falls to 0.887 F1 on unseen nursing
notes, from a system trained on clinical text in the first place. Our release gate allows a
sight-unseen recall drop of at most 5 points on a new note type. This candidate is not a new note
type within a trained domain; it is a different domain entirely, so the drop should be expected to
be larger than that gate contemplates, and a result at or below it would be a genuine surprise
worth reporting as such.

There is no dishonourable outcome here. A large measured drop is a real finding about domain
transfer into Turkish clinical text, which is a thing nobody has published. A small one would be a
better finding. Both beat the current state, which is no number at all.

#### (b) METRIC -- 80.85 overlap micro-F2 is not our recall floor, and cannot be compared to it

This is the failure mode most likely to be committed by somebody reading this document quickly, so
it gets stated at length.

- **Different quantity.** Micro-F2 is a single blended score weighting recall above precision. Our
  HIPAA-critical gate is `recall >= 0.98` **per entity type**, reported per type and never averaged,
  and a release is blocked by the worst floor rather than by a mean. There is no arithmetic that
  turns an F2 into a per-entity recall.
- **Different matching rule.** *Overlap* micro-F2 credits a predicted span that overlaps a gold
  span. Our spans are byte offsets validated onto UTF-8 character boundaries, and a name span that
  leaks a Turkish case suffix or clips a syllable is a partial mask, which in a de-identification
  product is a miss. Overlap scoring and exact scoring diverge most on precisely the agglutinative
  boundaries Turkish produces.
- **Different corpus.** 300 documents of theirs against 190 of ours, drawn from different domains,
  annotated to different label definitions by different people under different guidelines.

F2 *does* weight recall above precision, which is the right direction for I2 and is a point in this
model's favour on shape. But shape is not magnitude.

**Anyone quoting 80.85 (or 81.01, or 71.90) as a deid-tr number would be repeating the exact error
`docs/COMPARISON.md` section 1.1 criticises** -- publishing a figure produced by a different
evaluation as though it described the system in front of them. We criticised that in someone else's
model cards. Doing it in our own README would be worse, because we would be doing it after writing
down why it is wrong. I5 exists to make it unrepresentable: a card's numbers come from
`eval/results/<run_id>.json` or the card does not ship.

#### (c) LABEL GRANULARITY -- 25 KVKK types do not map onto our schema one-to-one

Two mismatches are already visible from the label list, before anything is run.

**One name label against our three name roles.** The candidate emits a single `KISI_AD_SOYAD`
(person name). `eval/schema.yaml` carries `PATIENT_NAME`, `CLINICIAN_NAME` and `RELATIVE_NAME` as
separate labels with separate recall floors, because they are separate risks: a clinician name is
a staffing signal, a relative name is a linkage vector into a second person's record, and a patient
name is the breach. A single-label detector can populate all three only through a role assignment
this project would have to write and then defend, and any such assignment is a place where a name
detected correctly can be scored as a miss on the wrong label. The union rule (D-002) protects
recall of the *masking* regardless, since a span flagged by any layer is masked. Scoring is where
the granularity gap bites, and the honest options are to report a collapsed name class beside the
three, or to write the role assignment and measure it as its own component. That decision is not
taken here and does not belong in this document.

**`MESLEK_UNVAN` lands on a quasi-identifier we do not score by F1.** Occupation and title is a
token-level entity in their schema. In ours, employment and role is `EMPLOYER_ROLE`, a class-B
contextual quasi-identifier detected by L3 and validated by the L6 red team rather than by a fixed
F1 (D-008). "He works at the Central Bank" is re-identifying because of what it *means* in a small
population, not because "Central Bank" is an organisation string. A token-level `MESLEK_UNVAN`
overlaps the surface forms and does not do the same job. Feeding it into the quasi-identifier track
would put an F1-shaped signal into a red-team-scored track and quietly change what that track
measures, which is the failure D-029 was written after finding in our own gate.

---

## What has to be true before this produces a number

Named plainly so nobody mistakes a shortlist for an integration. As of this document:

1. `bindings/ort/Cargo.toml` **does not declare `ort`**, deliberately, and the reasons are recorded
   in that file: `ort`'s default features fetch a shared library over the network at build time, and
   declaring it at all forces a registry resolve that breaks `just test-airgapped`. The exact line
   to add, and the `default-features = false` that drops `download-binaries`, are written there.
   Until a human runs that one online `cargo fetch`, the only `Session` in the crate is
   `StubSession`.
2. There is no tokenizer loader and no `LabelSet` built from this checkpoint's 51 BIO labels.
   `core/src/detect/bioes.rs` decodes BIOES under a Viterbi transition constraint; a BIO label
   inventory has to be mapped onto it, and that mapping is a place spans get silently dropped.
3. The tokenizer gate (I6) has never been run against a published tokenizer.
   `scripts/gate_tokenizer.py --self-test` is green against its own stubs and has never seen a real
   vocabulary. **No model publishes for Turkish until its tokenizer round-trips code-switched
   Latin/English medical terms under Turkish morphology.** A cased WordPiece of 50,008 is a
   promising starting point and it is not evidence; the gate decides.
4. No CLI flag, no service route and no eval detector loads an L2 checkpoint today.

Every one of those is work, and none of it is done. Until it is, this repository masks no names.

## What the operator runs to get the first real number

These commands download weights and run inference. They belong on a server, not on a laptop, and
nothing in the normal build or test path invokes them.

```bash
# 1. Admit the runtime. ONE online resolve, reviewed, and it rewrites Cargo.lock.
#    default-features = false is what drops ort's download-binaries fetch.
#    See bindings/ort/Cargo.toml for the exact dependency and feature lines.
cargo fetch

# 2. Fetch the checkpoint and PIN THE REVISION. A number without a revision
#    cannot be reproduced and, under I5 and D-042, cannot ship on a card.
huggingface-cli download ytu-ce-cosmos/modernbert-tr-pii-ner \
  --revision <COMMIT-SHA> --local-dir ./models/modernbert-tr-pii-ner

# 3. Gate the tokenizer BEFORE anything else. I6. If this fails, stop:
#    the checkpoint does not publish for Turkish, whatever it scores.
python3 scripts/gate_tokenizer.py --tokenizer ./models/modernbert-tr-pii-ner

# 4. Score it against our corpus, on our labels, with our floors.
python3 -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json
python3 eval/run.py --detector pipeline --redteam-report eval/results/redteam.json

# 5. Read the per-entity recall table, never the aggregate.
```

Steps 1, 3 and 4 have flags and entry points that do not exist yet; the sequence is the shape of the
work, not a script to paste. The commit that makes each step real is the commit that removes this
sentence for that step.

**Commit the tree first.** `eval_sha` records `uncommitted` on a dirty tree, and a run pinned to
`uncommitted` cannot ship on a card under I5. The provenance note at the top of
`docs/COMPARISON.md` is what that failure looks like when it has already happened.
