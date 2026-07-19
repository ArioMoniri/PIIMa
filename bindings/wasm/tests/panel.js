// Extracted from index.html. It must be an EXTERNAL file, not an inline
// <script>: the page's CSP is `script-src 'self'`, which blocks inline
// scripts outright. Inlined, this module never executed at all -- the panel
// rendered as an idle form and every button was dead, with no error anywhere,
// because there was no running code to throw one.
//
// The alternative was adding 'unsafe-inline' to script-src. On a page whose
// entire purpose is demonstrating that clinical text cannot leave the tab,
// widening the script policy to fix a layout-level problem is the wrong trade.

// A module script that throws during start-up fails SILENTLY: the buttons
// simply never respond, and nothing appears in the page. That is how this
// panel sat broken -- it looked like an idle form rather than a dead one.
// Surface start-up failures where a person will actually see them.
window.addEventListener("error", (e) => {
  document.getElementById("verdict").textContent =
    `panel failed to start: ${e.message}`;
});
window.addEventListener("unhandledrejection", (e) => {
  document.getElementById("verdict").textContent =
    `panel failed to start: ${e.reason?.message ?? e.reason}`;
});

// ORDER MATTERS, and an earlier revision of this file got it wrong.
//
// The trap below replaces `fetch`. wasm-bindgen's generated `default()`
// initialiser ALSO uses `fetch` -- to load its own `.wasm` from this same
// directory. Arming the trap first therefore strangled the module load
// ("INIT FAILED: Failed to fetch") and the panel never started at all.
//
// So: pull the module in with the real `fetch` first, then arm the trap,
// then initialise from the bytes already in memory. That preserves the
// claim this page exists to make -- the claim is about CLINICAL TEXT never
// leaving the tab, and no note has been typed at this point. From the
// moment the trap is armed, which is before any note is readable, every
// networking global is dead for the rest of the page's life.
const realFetch = globalThis.fetch.bind(globalThis);
const wasmUrl = new URL("../pkg-web/deid_tr_wasm_bg.wasm", import.meta.url);
const wasmBytes = await (await realFetch(wasmUrl)).arrayBuffer();

// Booby-trap every networking global, so a call from anywhere -- our code,
// the glue, a future dependency -- is recorded rather than merely
// forbidden by the CSP. The CSP blocks; this counts.
const fired = [];
for (const name of [
  "fetch",
  "XMLHttpRequest",
  "WebSocket",
  "EventSource",
  "WebTransport",
  "RTCPeerConnection",
]) {
  globalThis[name] = function trapped() {
    fired.push(name);
    throw new Error(`${name} was called`);
  };
}
if (navigator.sendBeacon) {
  navigator.sendBeacon = () => {
    fired.push("navigator.sendBeacon");
    return false;
  };
}

// `../pkg-web/` is the wasm-bindgen `--target web` output. A relative
// path, same origin, no CDN.
//
// The bytes fetched above are handed to the initialiser directly, so it
// never reaches for the (now trapped) global `fetch`. It must be the ASYNC
// initialiser rather than `initSync`: browsers refuse a synchronous
// `WebAssembly.Module` larger than 4KB on the main thread, and this module
// is ~880KB, so `initSync` throws a RangeError here no matter how correct
// its arguments are.
const wasm = await import("../pkg-web/deid_tr_wasm.js");
await wasm.default({ module_or_path: wasmBytes });

// A checksum-valid TCKN, COMPUTED rather than written into this file (I8).
const stem = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const odd = stem.filter((_, i) => i % 2 === 0).reduce((a, b) => a + b, 0);
const even = stem.filter((_, i) => i % 2 === 1).reduce((a, b) => a + b, 0);
const tenth = (odd * 7 + 100 - even) % 10;
const eleventh = [...stem, tenth].reduce((a, b) => a + b, 0) % 10;
const tckn = [...stem, tenth, eleventh].join("");

const note = document.getElementById("note");
note.value = `Hasta Ayşe Yılmaz, TCKN ${tckn}, tel 0(532) 000 00 00.\nOp. Dr. Şükrü Gökçe tarafından görüldü; carcinoma'lı lezyon, MRI'da izlendi.`;

const output = document.getElementById("output");
const spans = document.getElementById("spans");
const verdict = document.getElementById("verdict");
const restore = document.getElementById("restore");
let last = null;

function report() {
  verdict.textContent =
    fired.length === 0
      ? `no network call was made (${wasm.version()}). Check the Network tab: this document, the glue and the .wasm module, nothing else.`
      : `FAILED: ${fired.join(", ")}`;
}

document.getElementById("run").addEventListener("click", () => {
  spans.replaceChildren();
  try {
    // The tier is passed explicitly at every call. There is no default,
    // because both defaults are wrong in a different direction.
    //
    // The salt is the page's job: the wasm module links neither js-sys
    // nor web-sys (that is what keeps `fetch` out of its import table),
    // so it cannot reach crypto.getRandomValues itself. A fresh one per
    // run is SaltScope::Document -- two runs are not linkable.
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    last = wasm.deidentify(note.value, wasm.Tier.SafeHarbor, salt);
  } catch (error) {
    output.textContent = `error: ${error.message}`;
    report();
    return;
  }
  output.textContent = last.text;
  restore.disabled = false;
  for (let i = 0; i < last.spanCount; i += 1) {
    const span = last.span(i);
    const row = document.createElement("tr");
    for (const cell of [
      `${span.start}..${span.end}`,
      span.label,
      span.layer,
      span.decision,
      span.checksumValidated ? "yes" : "-",
      span.replacement ?? "-",
    ]) {
      const td = document.createElement("td");
      td.textContent = cell;
      row.append(td);
    }
    spans.append(row);
  }
  report();
});

restore.addEventListener("click", () => {
  if (!last) return;
  // The round trip: the span map's OUTPUT offsets make this exact even
  // when two identifiers share a replacement.
  output.textContent = last.reidentify();
  report();
});

report();
