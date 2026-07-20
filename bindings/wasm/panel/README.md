# deid-tr — vanilla panel

The browser panel, as eight files you can read.

```sh
just build-wasm      # produces ../pkg-web/
just serve-panel     # 127.0.0.1:8722/panel/index.html
```

No build step, no bundler, no dependencies, no `node_modules`. What you read here
is what runs in the tab.

## This build masks ZERO names

**No L2 model is loaded and no weights ship.** `PATIENT_NAME`, `CLINICIAN_NAME`
and `RELATIVE_NAME` pass through untouched. What gets removed is what the L1 rule
layer can prove: TCKN, VKN, IBAN, phone numbers, e-mail addresses, dates and the
other fixed-format direct identifiers. The banner at the top of the page says so
before any output, and nothing on the page is allowed to imply otherwise.

## Why this panel and the React app both survive

There are two browser panels in this repository and neither replaces the other.

**This one is the minimal auditable proof.** Its pitch is that you can open the
whole panel and audit it with no build step — eight files, ~171 kB of
unminified source, listed here in full so the count is checkable rather than
rhetorical:

| File | What it owns |
|---|---|
| `index.html` | the markup, the CSP, the banner |
| `panel.css` | every style; no inline `<style>`, so `style-src 'self'` holds |
| `panel.js` | module load, the network trap, state, the run loop |
| `render.js` | the four views |
| `compose.js` | span map + policy to output text, on UTF-8 byte offsets |
| `policy.js` | the six redaction methods, entity families, sigils |
| `animate.js` | the masking sweep, presentation only |
| `file.js` | file input, size limits, format detection |

There is nothing between the source and the behaviour. For a tool whose entire
argument is auditability, that has real value — and it is a claim a bundled app
cannot make, because what ships there is a hashed chunk and nobody diffs a
bundle.

**`bindings/panel-app/` is the better product surface.** React + Tailwind +
shadcn/ui, a page-shaped document view, and a blackout animation that shows the
redaction happening rather than describing it. Those are worth having, and
building them here would have cost this page the readability that is its whole
point.

Both load the **same WebAssembly module** from `../pkg-web/`. That is what stops
them becoming two products: the pipeline is one artifact and only the surface
differs. A change that deletes one panel to avoid maintaining two has thrown away
the thing the other one was for.

If the two ever disagree about what the pipeline does, this page is the one to
trust — not because it is more correct, but because you can check it.

## What holds this page up

- **CSP without `'unsafe-inline'`.** `default-src 'none'; script-src 'self'
  'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'`. This is why the
  stylesheet is a separate file and every script is an external module: inlining
  any of them turns the panel into an idle-looking form with no error anywhere.
- **The network trap, armed in the right order.** `panel.js` fetches the wasm
  with the real `fetch` first, *then* replaces every networking global with a
  throwing stub, *then* initialises from the bytes already in memory. Arming the
  trap first strangles the module's own load, which an earlier revision did.
- **Byte offsets, not string indices.** `"ş".length` is 1 in JavaScript and 2 in
  the span map. `compose.js` encodes the document once and slices bytes.
- **Colour is never the only channel.** Each entity family carries a two-letter
  sigil, a distinct underline treatment, and a hue.
- **The sweep in `animate.js` is presentation only.** It animates only spans that
  were actually masked, never gates the pipeline, and `prefers-reduced-motion:
  reduce` disables it entirely. The React panel's blackout animation obeys the
  same three rules under more visual pressure; see its README.
