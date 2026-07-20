# deid-tr — React panel

A React + Tailwind + shadcn/ui surface for the browser pipeline, with a document
blackout animation. Built to static assets, served same-origin, no network.

```sh
just build-panel-app     # build to dist/, then verify it against the CSP
just serve-panel-app     # build, stage the wasm module, serve on 127.0.0.1:8723
just test-panel-app      # typecheck + the animation's three rules
```

## This build masks ZERO names

**No L2 model is loaded and no weights ship.** `PATIENT_NAME`, `CLINICIAN_NAME`
and `RELATIVE_NAME` pass through untouched. What gets removed is what the L1 rule
layer can prove: TCKN, VKN, IBAN, phone numbers, e-mail addresses, dates and the
other fixed-format direct identifiers.

Nothing in this app — no banner, no label, no animation frame — is allowed to
imply otherwise. That constraint is the reason most of the design below exists.

## Why this app and the vanilla panel both survive

There are two browser panels in this repository and neither replaces the other.

**`bindings/wasm/panel/` is the minimal auditable proof.** Its pitch is that you
can open the whole panel — eight files, ~171 kB of unminified source — and audit
it with no build step. What you read is what runs. For a tool whose entire
argument is auditability, that claim has real value, and it is a claim a bundled
React app cannot make: what ships here is a hashed 212 kB chunk, and nobody diffs
a bundle.

**`bindings/panel-app/` is the better product surface.** A page-shaped document
view, a blackout animation that shows the operation happening rather than
describing it, a real component library, a span map that sorts and scans. These
are worth having, and building them in vanilla DOM code would have cost the other
panel its readability.

Both load the **same WebAssembly module** from `pkg-web/`. That is what stops
them becoming two products: the pipeline is one artifact and only the surface
differs. A change that deletes one panel to avoid maintaining two has thrown away
the thing the other one was for.

## The blackout animation

A page-shaped view of the extracted text. On redact, black bars sweep in over the
masked spans **in document order, staggered**, so the eye follows a pass down the
page. Each bar then **resolves** to reveal the surrogate underneath. Span map rows
highlight in sync with their own bar.

The resolve is not decoration. A bar that stayed opaque forever would say *this
was painted over* — which is what a flattened PDF does, and in a flattened PDF the
text is still in the file underneath. What actually happened is that the text was
**removed from the string and replaced**. The wipe is the frame that distinguishes
those two operations, and it is the reason the animation is allowed to exist.

### Three rules that are not negotiable

This animation is far more convincing than the vanilla panel's text sweep. A
black bar is the most recognisable visual shorthand for "redacted" that exists,
and a convincing lie is worse than an ugly truth, because an ugly truth gets
checked.

**1. Only genuinely masked spans get a bar.** Names are not masked in this build.
A bar sweeping over a patient name that is still in the output would be the UI
asserting a safety property that is false. This is enforced three ways, in
`src/deid/bars.ts` and `src/components/SpanViews.tsx`:

- **Type.** `RedactionBar` is branded with a module-private symbol. `barsFor` is
  the only exported producer, and it derives every bar from a segment whose
  `passthrough` is null. (Honest limit: `as unknown as RedactionBar` still
  compiles. The brand stops the accident, not the determined edit — which is why
  it is not the only mechanism.)
- **Runtime.** `barsFor` re-checks the invariant and throws `UnmaskedSpanError`
  if it is violated. Types are erased in the shipped bundle; this is not. The
  message carries the span index and label and never the covered text (I4).
- **Structure.** `MaskedSpanView` renders the bar element. `KeptSpanView` is a
  separate component containing no bar element at all. The bar is not a class
  toggled on a shared node — there is no node under a kept span for a bar to
  appear on.

Tested at both layers: `src/deid/bars.test.ts` (no bar object) and
`src/components/SpanViews.test.tsx` (no bar element). Deliberately breaking
either enforcement fails 7 tests.

**2. The animation is never the only signal.** Components render their final
state by default; the animation is added on top. The counts, the span map, the
ARIA live region and the output text are all correct before the first frame and
after the last. A reader who looks away, whose tab is backgrounded, or whose
browser never runs a CSS animation sees the same result. `SpanViews.test.tsx`
asserts the rendered span markup is byte-identical with and without the sweep.

**3. `prefers-reduced-motion: reduce` disables all of it** and jumps to the final
state — not a shorter animation, not a fade. Enforced in JavaScript
(`useBlackout` never starts a sweep) and independently in CSS (a `@media` block),
because the two fail independently. **The exported output is byte-identical
either way**: export reads `composition.output`, which nothing in the animation
path can reach. `src/deid/export.test.ts` pins it.

## The document view is extracted text, not a picture of your file

There is no PDF rasteriser here and the CSP forbids loading one. What the page
lays out is the **extracted text** — the same string the pipeline read, in the
same order, with spans in their real positions. The page shape is a reading aid.
Every page says so in its header.

This matters beyond pedantry: if the extractor mis-ordered a two-column layout or
dropped a header, a facsimile would show you the header you expect while the
pipeline never saw it. Showing the text that was actually processed means what
you audit is what ran.

## CSP

The built app runs under the same policy the vanilla panel enforces:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
connect-src 'self'; img-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none'
```

**Vite's defaults violate this in three places**, and `vite.config.ts` closes
each one: `modulePreload.polyfill` emits an inline `<script>`;
`assetsInlineLimit` emits `data:` URLs; `cssCodeSplit` lets a chunk inject a
`<style>` element at runtime. If a dependency needed `'unsafe-inline'`, that
dependency would not ship.

React's `style={{...}}` prop is unaffected — it writes through
`node.style.setProperty` (CSSOM), which CSP does not govern. Only a style
attribute parsed out of HTML is blocked.

**`scripts/check-csp.mjs` verifies the built bytes**, and `just build-panel-app`
runs it every time rather than leaving it as a step to remember. It checks for
inline scripts and styles, style attributes in markup, `data:` URIs, remote
origins in loadable positions, and that the policy itself is present and strict.

Minified JS is not decidable by regex — React embeds `http://www.w3.org/...` as
an SVG namespace and `https://reactjs.org` in an error string, and neither is
ever fetched. So JS origins are handled by **review**: every distinct origin must
be on `KNOWN_INERT_ORIGINS` with a written reason, and a new one fails. That is a
smaller claim than "we proved nothing is loaded", and it is one the script can
actually keep. The live proof is the network counter in the running app.

## Carried over from the vanilla panel

- The names-are-not-masked banner, visible without scrolling, first in the
  reading order of `<main>`, never inside a scroll container.
- WCAG AA in both themes. Contrast ratios are recorded beside the token values in
  `src/index.css`; the large-text 3:1 allowance is not used anywhere, because the
  text that matters most is not large.
- Full keyboard access with a visible focus ring (2px, 2px offset, both themes).
  Radix primitives supply the roving tabindex and `aria-controls` wiring.
- An ARIA live region announcing detected and masked counts as two numbers, never
  one: "6 detected, 6 masked" and "6 detected, 3 masked" must be distinguishable
  at a glance.
- Colourblind-safe entity coding on three channels, any one sufficient: a
  two-letter sigil (`ID`, `CT`, `DT`, `PL`, `NM`, `OT`), a distinct underline
  treatment (solid/dotted/dashed/double/wavy), and a hue. The exact label is
  always in the span map besides.
- A live network counter with three independent instruments — trapped networking
  globals, the resource timeline, and CSP violation reports — reported
  separately, because they fail differently.

## Bundle size, measured

From `just build-panel-app` on this tree:

| File | Raw | gzip |
|---|---|---|
| `assets/index-*.js` | 211.94 kB | 69.37 kB |
| `assets/style-*.css` | 24.58 kB | 5.46 kB |
| `index.html` | 2.39 kB | 1.31 kB |
| **total** | **~239 kB** | **~76 kB** |

Not included: `pkg-web/deid_tr_wasm_bg.wasm`, **1188 kB**, which both panels load
and neither bundles. The wasm module is five times the weight of this entire app,
which is the honest framing — the React surface is not where the bytes are.

The vanilla panel is ~171 kB of uncompressed, unminified, readable source, and it
is the same six files whether you read them or run them.

## Layout

```
src/deid/       the pipeline-facing layer, no React
  types.ts      span and segment shapes; `passthrough === null` means masked
  wasm.ts       module load + network trap, in that order (the trap kills fetch)
  compose.ts    UTF-8 BYTE offsets, not string indices
  policy.ts     port of the vanilla panel's policy.js, pinned by tests
  bars.ts       RULE 1 lives here
  pages.ts      pagination by line count, not by measuring the viewport
src/components/ the view layer
  SpanViews.tsx RULE 1, structurally: two components, only one has a bar
src/lib/        hooks: reduced motion, blackout timing
scripts/        check-csp.mjs
```
