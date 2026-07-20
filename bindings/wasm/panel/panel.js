// The panel's entry point: module load, then wiring.
//
// THIS FILE MUST STAY EXTERNAL. The page's CSP is `script-src 'self'`, which
// blocks inline scripts SILENTLY -- no console error, no visible failure, just
// a page whose controls do nothing. That cost hours once already. The
// alternative, adding 'unsafe-inline', widens the script policy of a page whose
// entire purpose is proving clinical text cannot leave the tab, to solve a
// layout-level problem. Not a trade worth making.

import { compose, tally, PASSTHROUGH } from "./compose.js";
import { METHODS, defaultMethod } from "./policy.js";
import {
  download,
  highlightHtml,
  renderHighlight,
  renderInline,
  renderTable,
  renderText,
  spanMapCsv,
  spanMapJson,
} from "./render.js";

const el = (id) => document.getElementById(id);

// A module script that throws during start-up fails SILENTLY: the controls
// simply never respond and nothing appears anywhere. Surface it where a person
// will actually see it, before anything else can throw.
function fatal(message) {
  const box = el("output-error");
  box.hidden = false;
  box.textContent = `The panel failed to start: ${message}`;
  el("network").textContent = "panel did not start";
}
window.addEventListener("error", (event) => fatal(event.message));
window.addEventListener("unhandledrejection", (event) =>
  fatal(event.reason?.message ?? String(event.reason)),
);

// --- module load ---------------------------------------------------------
//
// ORDER MATTERS AND AN EARLIER REVISION GOT IT WRONG.
//
// The trap below replaces `fetch`. wasm-bindgen's generated `default()`
// initialiser ALSO uses `fetch`, to load its own `.wasm` from the sibling
// directory. Arming the trap first therefore strangles the module load
// ("Failed to fetch") and the panel never starts.
//
// So: pull the module in with the real `fetch` first, then arm the trap, then
// initialise from the bytes already in memory. The claim this page makes is
// about CLINICAL TEXT, and no note can have been typed at this point -- the
// editor is not wired up until after. From the moment the trap is armed, every
// networking global is dead for the rest of the page's life.
const realFetch = globalThis.fetch.bind(globalThis);
const wasmUrl = new URL("../pkg-web/deid_tr_wasm_bg.wasm", import.meta.url);
const wasmBytes = await (await realFetch(wasmUrl)).arrayBuffer();

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
    reportNetwork();
    throw new Error(`${name} was called`);
  };
}
if (navigator.sendBeacon) {
  navigator.sendBeacon = () => {
    fired.push("navigator.sendBeacon");
    reportNetwork();
    return false;
  };
}

// It MUST be the async initialiser, not `initSync`: browsers refuse a
// synchronous `WebAssembly.Module` larger than 4KB on the main thread and this
// module is ~880KB, so `initSync` throws a RangeError here regardless of how
// correct its arguments are.
const wasm = await import("../pkg-web/deid_tr_wasm.js");
await wasm.default({ module_or_path: wasmBytes });

// A SECOND, INDEPENDENT counter, and the baseline is taken HERE -- after the
// last legitimate load -- so the number on screen is "requests this page made
// once it was running", which is the number a reader cares about. The traps
// above cover the globals this page can name; the resource timeline counts what
// the browser actually fetched, including anything a future dependency reaches
// through a path nobody thought to stub. Two mechanisms disagreeing is itself
// the signal worth having.
const baselineRequests = performance.getEntriesByType("resource").length;
let observedRequests = 0;
if (globalThis.PerformanceObserver) {
  new PerformanceObserver((list) => {
    observedRequests += list.getEntries().length;
    reportNetwork();
  }).observe({ type: "resource", buffered: false });
}

// The third instrument, and the one that reports the CSP rather than the page.
// A declarative load the CSP refuses never reaches the network and so never
// reaches the resource timeline either -- it is invisible to both mechanisms
// above. That is a control WORKING, not a leak, but it is still the page trying
// something it should not, and a reader deserves to be told which of the two
// happened rather than being left to infer it from a silence.
const blocked = [];
addEventListener("securitypolicyviolation", (event) => {
  blocked.push(event.effectiveDirective || event.violatedDirective);
  reportNetwork();
});

const BUILD = `deid-tr-wasm ${wasm.version()}`;
el("build").textContent = BUILD;

// --- state ---------------------------------------------------------------

const state = {
  doc: "",
  spans: [],
  segments: [],
  output: "",
  error: null,
  threshold: 0,
  disabled: new Set(),
  methods: new Map(),
  // One salt per document, which is `SaltScope::Document`: surrogates stay
  // stable while the note is edited, and two different notes are not linkable
  // through their surrogates. Regenerated whenever a new document is loaded.
  salt: freshSalt(),
  // The date-shift offset. Per session, never displayed: the offset is the key
  // that reverses a shifted date, so showing it in the UI would put the
  // re-identification key on screen next to the de-identified note.
  shiftDays: shiftOffset(),
};

function freshSalt() {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

function shiftOffset() {
  const draw = new Uint32Array(1);
  crypto.getRandomValues(draw);
  return ((draw[0] % 731) - 365) || 1;
}

// --- the run -------------------------------------------------------------

/// Call the wasm module and flatten its span map into plain objects.
///
/// The wasm-bindgen handles are freed immediately. They are pointers into the
/// module's linear memory holding the ORIGINAL document, and a panel that
/// re-runs on every keystroke would otherwise accumulate one copy of the
/// clinical note per character typed for the lifetime of the tab.
function detect(doc) {
  const result = wasm.deidentify(doc, wasm.Tier.SafeHarbor, state.salt);
  try {
    const spans = [];
    for (let index = 0; index < result.spanCount; index += 1) {
      const span = result.span(index);
      spans.push({
        start: span.start,
        end: span.end,
        label: span.label,
        layer: span.layer,
        decision: span.decision,
        confidence: span.confidence,
        checksumValidated: span.checksumValidated,
        replacement: span.replacement ?? null,
      });
      span.free();
    }
    return spans;
  } finally {
    result.free();
  }
}

function run() {
  state.doc = el("note").value;
  state.error = null;
  if (state.doc.length === 0) {
    state.spans = [];
    state.segments = [];
    state.output = "";
    render();
    return;
  }
  try {
    state.spans = detect(state.doc);
  } catch (error) {
    // The wasm error is a `core::Error` rendering: offsets, labels and layers,
    // structurally incapable of carrying document text (I4). Safe to display.
    state.error = error.message ?? String(error);
    state.spans = [];
  }
  const composition = compose(state.doc, state.spans, {
    disabled: state.disabled,
    methods: state.methods,
    threshold: state.threshold,
    shiftDays: state.shiftDays,
  });
  state.segments = composition.segments;
  state.output = composition.output;
  render();
}

let pending = 0;
function scheduleRun() {
  // Debounced, because de-identification runs on every keystroke and a long
  // note re-encodes the whole document each time. 120ms is below the threshold
  // at which typing feels laggy and above the interval between keystrokes.
  clearTimeout(pending);
  pending = setTimeout(run, 120);
}

// --- render --------------------------------------------------------------

function render() {
  renderInputStatus();
  renderEntityControls();
  renderThresholdEffect();

  const hasContent = state.doc.length > 0;
  const box = el("output-error");
  box.hidden = state.error === null;
  if (state.error !== null) box.textContent = `De-identification failed: ${state.error}`;

  el("output-empty").hidden = hasContent;

  renderHighlight(el("highlight"), state.segments, (detail) => {
    el("span-detail").textContent = detail;
  });
  renderText(el("split-original"), state.doc);
  renderText(el("split-output"), state.output);
  renderInline(el("inline-diff"), state.segments);

  const rows = renderTable(el("spans"), state.segments);
  el("spans-empty").hidden = rows > 0;
  renderSummary(rows);
}

function renderInputStatus() {
  const chars = state.doc.length;
  el("input-status").textContent =
    chars === 0
      ? "Empty. Paste a note, drop a file, or load the sample."
      : `${chars} characters, ${state.spans.length} spans detected. Names are not among them: no L2 model is loaded.`;
}

function renderSummary(rows) {
  const masked = state.segments.filter(
    (segment) => segment.kind === "span" && segment.passthrough === null,
  ).length;
  el("span-summary").textContent =
    rows === 0
      ? ""
      : `${masked} of ${rows} spans masked. Offsets are UTF-8 byte offsets, not JavaScript string indices.`;
}

function renderThresholdEffect() {
  const suppressed = state.segments.filter(
    (segment) =>
      segment.kind === "span" &&
      segment.passthrough === PASSTHROUGH.BELOW_THRESHOLD,
  ).length;
  const line = el("threshold-effect");
  line.hidden = suppressed === 0;
  line.textContent =
    suppressed === 0
      ? ""
      : `${suppressed} detected identifier${suppressed === 1 ? " is" : "s are"} left in the output by this threshold.`;
}

/// One row per entity type present in the current note.
///
/// Rebuilt from scratch on every run, but only when the set of labels actually
/// changed -- otherwise a select the user is interacting with is replaced out
/// from under them on the next keystroke.
let renderedLabels = "";
function renderEntityControls() {
  const counts = tally(state.spans);
  const labels = [...counts.keys()].sort();
  const signature = labels.join(",");
  const container = el("entity-controls");
  el("entity-empty").hidden = labels.length > 0;

  if (signature !== renderedLabels) {
    renderedLabels = signature;
    container.replaceChildren();
    for (const label of labels) {
      container.append(entityRow(label));
    }
  }
  for (const label of labels) {
    const count = counts.get(label);
    const node = container.querySelector(`[data-count="${label}"]`);
    if (node) node.textContent = `${count} span${count === 1 ? "" : "s"}`;
  }
}

function entityRow(label) {
  const row = document.createElement("div");
  row.className = "entity-row";
  row.classList.toggle("off", state.disabled.has(label));

  const toggle = document.createElement("input");
  toggle.type = "checkbox";
  toggle.checked = !state.disabled.has(label);
  toggle.id = `toggle-${label}`;
  toggle.addEventListener("change", () => {
    if (toggle.checked) state.disabled.delete(label);
    else state.disabled.add(label);
    row.classList.toggle("off", !toggle.checked);
    run();
  });
  row.append(toggle);

  const name = document.createElement("label");
  name.className = "name";
  name.htmlFor = toggle.id;
  const strong = document.createElement("strong");
  strong.textContent = label;
  name.append(strong);
  const count = document.createElement("span");
  count.className = "count";
  count.dataset.count = label;
  name.append(document.createTextNode(" "), count);
  row.append(name);

  const select = document.createElement("select");
  select.setAttribute("aria-label", `Redaction method for ${label}`);
  for (const [value, text] of METHODS) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = text;
    if ((state.methods.get(label) ?? defaultMethod()) === value) {
      option.selected = true;
    }
    select.append(option);
  }
  select.addEventListener("change", () => {
    state.methods.set(label, select.value);
    run();
  });
  row.append(select);
  return row;
}

// --- network verdict -----------------------------------------------------

// THE VERDICT MUST NOT BE STRONGER THAN THE INSTRUMENT.
//
// The stubs above cover the APIs a script can name: fetch, XHR, WebSocket,
// EventSource, WebTransport, RTCPeerConnection, sendBeacon. They do not and
// cannot cover declarative loads — `new Image().src = ...`, a <video> source, a
// stylesheet — because those are not function calls on a global there is
// anything to replace. Measured: an image assignment threw nothing, added
// nothing to `fired`, and still appeared in the resource timeline. The page said
// "No network call" over it, which on a privacy tool is the worst available bug:
// a reader who checks the claim the way we told them to gets a false negative.
//
// So the resource timeline is now load-bearing rather than decorative. A request
// the timeline saw is a request, whether or not a stub caught it, and the
// verdict says so. The CSP is what BLOCKS those loads (`img-src 'none'`,
// `default-src 'none'`); the counter is what MEASURES them. They are two
// separate controls and the prose below the counter now names them separately,
// because a control that blocks and a control that observes fail in different
// directions and conflating them is how an overstatement gets written.
function reportNetwork() {
  const node = el("network");
  const since = Math.max(
    observedRequests,
    performance.getEntriesByType("resource").length - baselineRequests,
  );
  if (fired.length > 0) {
    node.className = "verdict bad";
    node.textContent = `FAILED: ${fired.join(", ")} was called.`;
    return;
  }
  if (since > 0) {
    node.className = "verdict bad";
    node.textContent = `FAILED: the resource timeline recorded ${since} request${since === 1 ? "" : "s"} after the module finished loading. No networking global was called, so this arrived through a declarative load (an image, a media element, a stylesheet). ${BUILD}.`;
    return;
  }
  node.className = "verdict ok";
  const csp =
    blocked.length > 0
      ? ` The CSP refused ${blocked.length} load${blocked.length === 1 ? "" : "s"} (${[...new Set(blocked)].join(", ")}) before ${blocked.length === 1 ? "it" : "they"} reached the network.`
      : "";
  node.textContent = `No network call. 0 requests since the module finished loading; every networking global is a throwing stub and the resource timeline is empty.${csp} ${BUILD}.`;
}

// --- input ---------------------------------------------------------------

const note = el("note");
note.addEventListener("input", scheduleRun);

/// A checksum-valid TCKN, COMPUTED here rather than written into this file (I8).
function validTckn() {
  const stem = [1, 2, 3, 4, 5, 6, 7, 8, 9];
  const odd = stem.filter((_, i) => i % 2 === 0).reduce((a, b) => a + b, 0);
  const even = stem.filter((_, i) => i % 2 === 1).reduce((a, b) => a + b, 0);
  const tenth = (odd * 7 + 100 - even) % 10;
  const eleventh = [...stem, tenth].reduce((a, b) => a + b, 0) % 10;
  return [...stem, tenth, eleventh].join("");
}

const SAMPLE = () =>
  `KARDIYOLOJI POLIKLINIK NOTU
Hasta: Ayşe Yılmaz, TCKN ${validTckn()}, dogum 14.03.1961
Iletisim: 0(532) 000 00 00, ayse.yilmaz@example.invalid
Adres: Bahçelievler Mah. Gül Sok. No 12, Kadıköy
Kabul: 02.07.2026  Taburcu: 05.07.2026

Op. Dr. Şükrü Gökçe tarafından görüldü. Toraks BT'de sol 5. costa'da
deplase olmayan fraktür izlendi; carcinoma'lı lezyon yok, MRI'da ek
patoloji saptanmadı. Hasta Merkez Bankası'nda çalışıyor.
`;

el("sample").addEventListener("click", () => {
  newDocument(SAMPLE());
});

el("clear").addEventListener("click", () => {
  newDocument("");
});

function newDocument(text) {
  // A new document gets a new salt: two notes de-identified in one session must
  // not share a surrogate mapping, or the surrogates themselves become a
  // cross-document linkage key.
  state.salt = freshSalt();
  note.value = text;
  run();
}

// --- file input ----------------------------------------------------------

const TEXT_EXTENSIONS = [".txt", ".csv", ".json", ".md"];

async function loadFile(file) {
  const name = file.name.toLowerCase();
  if (!TEXT_EXTENSIONS.some((extension) => name.endsWith(extension))) {
    const box = el("output-error");
    box.hidden = false;
    box.textContent =
      name.endsWith(".pdf") || name.endsWith(".docx")
        ? `${file.name}: PDF and DOCX are handled by the deid-tr CLI, not by this page. Extracting their text needs a parser, and a redacted PDF also needs its text layer and metadata scrubbed and then verified.`
        : `${file.name}: only .txt, .csv, .json and .md are read here.`;
    return;
  }
  // `File.text()` reads from the local file object. No network is involved and
  // none is reachable -- `fetch` has been a throwing stub since before this
  // handler was registered.
  newDocument(await file.text());
}

el("file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (file) loadFile(file);
});

const dropzone = el("drop");
for (const type of ["dragenter", "dragover"]) {
  dropzone.addEventListener(type, (event) => {
    event.preventDefault();
    dropzone.classList.add("over");
  });
}
for (const type of ["dragleave", "drop"]) {
  dropzone.addEventListener(type, () => dropzone.classList.remove("over"));
}
dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  const file = event.dataTransfer?.files?.[0];
  if (file) loadFile(file);
});

// --- controls ------------------------------------------------------------

const threshold = el("threshold");
threshold.addEventListener("input", () => {
  state.threshold = Number(threshold.value);
  el("threshold-value").textContent = state.threshold.toFixed(2);
  el("threshold-warning").hidden = state.threshold === 0;
  run();
});

const tier = el("tier");
tier.addEventListener("change", () => {
  const box = el("output-error");
  if (tier.value === "expert-determination") {
    // HONEST REFUSAL rather than a silent no-op. Expert Determination is L3, a
    // full-document sweep by a local LLM. No local model is loaded in this
    // build, so the tier cannot run -- and a panel that accepted the selection
    // and returned a Safe Harbor result would be handing back an unswept
    // document that looks swept. That is the single most dangerous failure this
    // page could have.
    box.hidden = false;
    box.textContent =
      "Expert Determination is unavailable: it needs a local LLM (L3) for the full-document quasi-identifier sweep, and no local model is loaded in this build. Reverting to Safe Harbor rather than returning an unswept document that looks swept.";
    tier.value = "safe-harbor";
    return;
  }
  box.hidden = true;
});

const theme = el("theme");
theme.addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme !== "dark";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  theme.textContent = dark ? "Light theme" : "Dark theme";
  theme.setAttribute("aria-pressed", String(dark));
});

const TABS = [
  ["tab-highlight", "view-highlight"],
  ["tab-split", "view-split"],
  ["tab-inline", "view-inline"],
];
for (const [tabId, viewId] of TABS) {
  el(tabId).addEventListener("click", () => {
    for (const [otherTab, otherView] of TABS) {
      const selected = otherTab === tabId;
      el(otherTab).setAttribute("aria-selected", String(selected));
      el(otherView).hidden = !selected;
    }
    el(viewId).hidden = false;
  });
}

// --- exports -------------------------------------------------------------

function exportMeta() {
  return { build: BUILD, tier: "SafeHarbor", threshold: state.threshold };
}

function announce(message) {
  el("export-status").textContent = message;
}

function guard(action) {
  return () => {
    if (state.doc.length === 0) {
      announce("Nothing to export yet.");
      return;
    }
    action();
  };
}

el("export-text").addEventListener(
  "click",
  guard(() => {
    download("deid-tr-output.txt", "text/plain;charset=utf-8", state.output);
    announce("De-identified text saved. Names were never masked in it.");
  }),
);

el("export-json").addEventListener(
  "click",
  guard(() => {
    download(
      "deid-tr-span-map.json",
      "application/json;charset=utf-8",
      spanMapJson(state.segments, exportMeta()),
    );
    announce("Span map saved. It contains the originals: treat it as PHI.");
  }),
);

el("export-csv").addEventListener(
  "click",
  guard(() => {
    download(
      "deid-tr-span-map.csv",
      "text/csv;charset=utf-8",
      spanMapCsv(state.segments),
    );
    announce("Span map saved. It contains the originals: treat it as PHI.");
  }),
);

el("export-html").addEventListener(
  "click",
  guard(() => {
    download(
      "deid-tr-highlight.html",
      "text/html;charset=utf-8",
      highlightHtml(state.segments, exportMeta()),
    );
    announce("Highlight view saved. It contains the original text.");
  }),
);

// --- start ---------------------------------------------------------------

reportNetwork();
run();
