# Medical-term allowlist (class C, the negative set)

Latin, English and Turkish medical vocabulary that must **never** be masked.
Masking `carcinoma` is not a papercut: it destroys the clinical meaning of the
note. These files are the concrete term lists behind `allowlist_categories` in
`eval/schema.yaml`; that file declares the category ids and points at each
`source_file` here.

## Files

| File | Schema category | Contents |
|---|---|---|
| `diagnosis.txt` | `DIAGNOSIS` | Disease and diagnosis terms, including eponymous diagnoses that contain person names |
| `anatomy.txt` | `ANATOMY` | Latin anatomy, laterality, directional terms |
| `drug.txt` | `DRUG` | Generic INNs and brand names |
| `abbreviation.txt` | `ABBREVIATION` | Standard clinical abbreviations |
| `procedure.txt` | `PROCEDURE` | Surgical and interventional procedures |
| `lab_analyte.txt` | `LAB_ANALYTE` | Laboratory analytes and their short forms |
| `microorganism.txt` | `MICROORGANISM` | Binomial and genus-only organism names |
| `code_switched.txt` | `CODE_SWITCHED` | Allowlist roots carrying Turkish suffixes (`carcinoma'lı`, `MRI'da`, `Behçet'li`) |

Format: plain text, UTF-8, one term per line, sorted by Unicode code point,
lines beginning with `#` are comments. Matching is case-insensitive.

## How it is scored

Class C is **not** scored by recall. It is scored as a **false-positive rate**:
the fraction of allowlist occurrences the pipeline masked anyway. The release
gate is `medical_terms.fp_rate_max <= 0.005` in `eval/thresholds.yaml`, and it
is a hard gate, not a target.

This is the one place in the project where precision is the metric. It does not
weaken invariant I2 (recall is the product), because it is handled by L4
adjudication over already-flagged spans, never by lowering a recall threshold on
actual PHI.

## Loader and drift check

`eval/allowlist.py` loads every file named by a `source_file` in
`eval/schema.yaml` and returns a typed `MedicalAllowlist`. Loading is validated,
and every failure is hard rather than a warning: a declared file that does not
exist, a `.txt` file here that no category declares, and the same surface form
appearing in two files all raise `AllowlistError`. Normalisation is
Turkish-correct - `turkish_casefold` maps `I` to `ı` and `İ` to `i`, which
`str.lower()` gets wrong in both directions - and apostrophe-separated suffixes
are stripped using generated vowel-harmony variants rather than a hardcoded
list.

`just allowlist-drift` diffs the fixture `allowlist_terms` annotations against
these files in both directions. It exists because the two had already drifted by
several hundred terms while nothing compared them.

The harness reports the medical-term false-positive rate over **two
denominators**, separately and never blended: `fp_rate_annotated` (the
per-document annotations) and `fp_rate_vocabulary` (every term in these files
found anywhere in the corpus). The release gate reads `fp_rate_annotated`.

## Runtime role

These files are L4's runtime reference. The router loads them as
`MedicalAllowlist` and consults them when adjudicating whether a flagged span is
real PHI or a medical term. Because the lists ship as data rather than code, a
term can be added without touching the label vocabulary or recompiling `core/`.

`code_switched.txt` exists because the matcher must accept Turkish morphology
applied to a Latin or English root. Vowel harmony gives one suffix several
surface forms (`-de/-da/-te/-ta`, `-li/-lı/-lu/-lü`), and writers drop the
apostrophe as often as they use it, so variants are enumerated rather than
normalised to a single canonical form.

## Append-only

These lists are append-only in the sense that matters: a term is never deleted
or weakened to make a build green. They are reference vocabulary rather than
fixtures, so invariant I7 does not govern them, and they may be re-sorted and
de-duplicated - twelve analytes that appeared in two files at once were reduced
to one entry each so the loader's cross-file duplicate check can stay fatal. If
a term here is causing a failure, the failure is the finding.

Adding a term that the pipeline currently masks is an encouraged commit: it
turns a silent quality loss into a red build.

## Known issue: allowlist / recall precedence gap (ADR D-010)

An allowlist term can also be a genuine Turkish name. `Deva` is both a pharma
brand and a given name. `Costa` is both Latin for rib and a common surname.
`Down`, `Turner` and `Wilson` are diagnoses and surnames at once.

L4 currently treats an allowlist hit as a deterministic `Keep`. That means a
single-model NAME span whose surface form collides with an allowlist entry is
suppressed, and a real patient name leaks. That is recall losing to precision,
which invariant I2 forbids.

Resolution is context-sensitive allowlisting: title, casing and position
evidence (`Hemş. Deva` is a person, `Deva 500 mg` is a drug) overrides the
allowlist, and collisions escalate to the L4 adjudicator instead of
short-circuiting. Tracked as **ADR D-010**. Until it lands, collisions are
counted and reported rather than silently resolved.

## Provenance

Every term is real medical vocabulary. Nothing here is invented, and nothing
here is patient information, so invariant I8 (no real PHI in the repo) is not
engaged: it governs patient data, and a drug name is not patient data.
