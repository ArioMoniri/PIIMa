// The panel's entry point: module load, then wiring.
//
// THIS FILE MUST STAY EXTERNAL. The page's CSP is `script-src 'self'`, which
// blocks inline scripts SILENTLY -- no console error, no visible failure, just
// a page whose controls do nothing. That cost hours once already. The
// alternative, adding 'unsafe-inline', widens the script policy of a page whose
// entire purpose is proving clinical text cannot leave the tab, to solve a
// layout-level problem. Not a trade worth making.

import * as sweep from "./animate.js";
import { compose, tally, PASSTHROUGH } from "./compose.js";
import {
  afterPaint,
  formatName,
  formatFromName,
  formatsDisagree,
  humanSize,
  isBinary,
  readBytes,
} from "./file.js";
import { METHODS, defaultMethod } from "./policy.js";
import {
  download,
  downloadBytes,
  highlightHtml,
  renderHighlight,
  renderInline,
  renderMasked,
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

// THE SIZE IS MEASURED, NEVER ASSERTED.
//
// `wasmBytes` is the ArrayBuffer this tab actually fetched, so this figure is
// the real weight of the real module -- including the PDF and DOCX parsers,
// which are the reason it is no longer the ~600KB it was when the page only
// carried the rules layer. A hand-written number in the markup would have been
// correct until the first time the module grew and silently wrong afterwards,
// and on a page whose entire pitch is "check this yourself" a false claim about
// its own weight is the one that costs the most, because it is the easiest of
// all the claims to check.
const WASM_KB = Math.round(wasmBytes.byteLength / 1024);
const BUILD = `deid-tr-wasm ${wasm.version()}, ${WASM_KB}KB wasm`;
el("build").textContent = BUILD;
el("boot").hidden = true;
el("app").setAttribute("aria-busy", "false");

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
  // Span map sort, presentation only: `render.js` sorts a COPY, so the segment
  // order the byte-offset bookkeeping depends on is never touched.
  sort: { column: "offset", direction: "ascending" },
  // Set for exactly one render, by the actions that constitute "a new document
  // was de-identified". Never set by typing: `run()` fires on a 120ms debounce
  // while someone types, and a sweep restarting on every keystroke would be
  // strobing rather than informative. The result is identical either way -- the
  // sweep is decoration over an already-final DOM.
  animateNext: false,
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
  // Any sweep still in flight belongs to a DOM that is about to be discarded.
  // Abandoning it here is what keeps a half-scrambled node from surviving into
  // the next render.
  sweep.cancel();

  renderInputStatus();
  renderEntityControls();
  renderThresholdEffect();

  const hasContent = state.doc.length > 0;
  const box = el("output-error");
  box.hidden = state.error === null;
  if (state.error !== null) box.textContent = `De-identification failed: ${state.error}`;

  el("output-empty").hidden = hasContent;

  // ORDER: every view is painted in its FINAL state first, and the sweep is
  // started last over nodes that are already correct. Nothing below this point
  // can change what the panel reports or what an export writes.
  const showDetail = (detail) => {
    el("span-detail").textContent = detail;
  };
  // The marks the previous provenance line described are about to be replaced,
  // so a stale sentence describing a span that no longer exists is cleared
  // rather than left standing next to a different document.
  showDetail(
    "No span selected. Focus or hover a mark for its label, layer, confidence, byte offsets and outcome.",
  );
  const units = renderMasked(el("masked"), state.segments, showDetail);
  renderHighlight(el("highlight"), state.segments, showDetail);
  renderText(el("split-original"), state.doc);
  renderText(el("split-output"), state.output);
  renderInline(el("inline-diff"), state.segments);

  const { rows, rowsByIndex } = renderTable(
    el("spans"),
    state.segments,
    state.sort,
  );
  el("spans-empty").hidden = rows > 0;
  renderSummary(rows);
  announceResult(rows);

  for (const unit of units) unit.row = rowsByIndex.get(unit.index) ?? null;
  if (state.animateNext) sweep.play(units);
  state.animateNext = false;
}

/// The result, in words, for anyone not watching the pixels.
///
/// THIS IS THE AUTHORITATIVE ANNOUNCEMENT and it is written on every run,
/// animated or not. A screen reader user, or anyone who looked away during the
/// sweep, gets the same three numbers the span map shows. The names sentence is
/// part of the count deliberately: "5 identifiers detected, 5 masked" read on
/// its own would let someone conclude the note is clean, and it is not.
let announced = "";
function announceResult(rows) {
  const masked = maskedCount();
  const message =
    state.doc.length === 0
      ? "No note loaded."
      : rows === 0
        ? "No identifiers detected in this note. Names are not among the things looked for: no L2 model is loaded, so zero names were masked."
        : `${rows} identifier${rows === 1 ? "" : "s"} detected, ${masked} masked. Zero names masked: no L2 model is loaded in this build, so names were never looked for.`;
  // Rewriting a live region with an unchanged string makes some screen readers
  // announce it again. This runs on a 120ms debounce while someone types, so
  // without the guard the same sentence is read out every few keystrokes and
  // the region becomes noise a user turns off.
  if (message === announced) return;
  announced = message;
  el("run-status").textContent = message;
}

function maskedCount() {
  return state.segments.filter(
    (segment) => segment.kind === "span" && segment.passthrough === null,
  ).length;
}

function renderInputStatus() {
  const chars = state.doc.length;
  el("input-status").textContent =
    chars === 0
      ? "Empty. Paste a note, drop a file, or load the sample."
      : `${chars} characters, ${state.spans.length} span${state.spans.length === 1 ? "" : "s"} detected. Names are not among them: no L2 model is loaded.`;
}

function renderSummary(rows) {
  el("span-summary").textContent =
    rows === 0
      ? ""
      : `${maskedCount()} of ${rows} spans masked. Offsets are UTF-8 byte offsets, not JavaScript string indices.`;
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
// cannot cover declarative loads. `new Image().src = ...`, a <video> source and
// a stylesheet are not function calls on a global, so there is nothing on a
// global to replace. Measured: an image assignment threw nothing, added
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

/// Load text into the editor as a fresh document.
///
/// `fromFile` exists because the two callers want opposite things from the file
/// UI. The sample and clear buttons must TEAR IT DOWN -- otherwise a PDF's
/// verification verdict and its download button survive next to a pasted note,
/// and the button still hands back the previous document's bytes. A text file
/// arriving through `present()` has just POPULATED it with the detection
/// verdict for the file being loaded, and must not wipe its own message.
function newDocument(text, { fromFile = false } = {}) {
  if (!fromFile) clearFileUi();
  // A new document gets a new salt: two notes de-identified in one session must
  // not share a surrogate mapping, or the surrogates themselves become a
  // cross-document linkage key.
  state.salt = freshSalt();
  note.value = text;
  // Loading a document is the deliberate act the sweep is a response to. Typing
  // is not: see `state.animateNext`.
  state.animateNext = true;
  run();
}

// --- file input ----------------------------------------------------------
//
// THE WHOLE FLOW, IN ORDER, BECAUSE EACH STEP CAN END IT:
//
//   1. ceiling      -- checked against the File handle, before any read
//   2. read         -- FileReader, with progress, entirely local
//   3. detect       -- from the BYTES; the name is compared, never trusted
//   4. redact       -- wasm; a refusal throws and produces no bytes
//   5. present      -- text formats keep the editor; binary formats get a
//                      read-only view, a per-region breakdown and a download
//
// Steps 4 and 5 diverge by format and that divergence is the point: a `.txt`
// round-trips through a textarea, a PDF cannot, and pretending otherwise would
// mean offering someone an editor whose edits can never be saved.

/// Everything about the currently loaded file, or null for typed/pasted text.
///
/// Held separately from `state.doc` because the document text is only part of
/// it: the redacted BYTES have no representation in the editor at all, and they
/// are what a binary-format user came for.
let currentFile = null;

/// The ceiling, from the module that enforces it.
///
/// Read once at start-up rather than duplicated as a JS literal, so the number
/// shown to the reader and the number `redactFile` refuses on cannot drift
/// apart. The dropzone hint is rewritten from it for the same reason.
const MAX_BYTES = wasm.maxFileBytes();
el("dz-max").textContent = humanSize(MAX_BYTES);

function clearFileUi() {
  currentFile = null;
  el("file-panel").hidden = true;
  el("file-mismatch").hidden = true;
  el("file-progress").hidden = true;
  el("file-refusal").hidden = true;
  el("file-refusal-ocr").hidden = true;
  // The images block is hidden but its checkbox is NOT reset here. Its whole
  // purpose is to survive the drop that follows it being ticked: clearing it
  // with the rest of the UI would put the reader in a loop where the only way
  // to proceed is a setting that un-sets itself on the way.
  el("file-refusal-images").hidden = true;
  el("images-warning").hidden = true;
  el("images-warning-list").replaceChildren();
  el("images-warning-why").textContent = "";
  // Emptied, not just hidden. A hidden element keeps its text, and the next
  // refusal is populated before it is revealed -- but anything that reveals the
  // block without writing to it would show the PREVIOUS file's reason, which is
  // the one kind of stale text that could tell someone their document was
  // refused for something that happened to a different one.
  el("file-refusal-why").textContent = "";
  el("file-mismatch").textContent = "";
  el("binary-card").hidden = true;
  el("binary-readonly-note").hidden = true;
  note.readOnly = false;
  note.removeAttribute("aria-describedby");
}

function showProgress(fraction, label) {
  el("file-panel").hidden = false;
  el("file-progress").hidden = false;
  el("file-bar-fill").style.width = `${Math.round(fraction * 100)}%`;
  el("file-progress-text").textContent = label;
}

/// A refusal. Loud, named, and with NO download anywhere near it.
///
/// The message comes from the wasm module, which renders a `core`/`files` error
/// through its `Display`. Those enums carry page numbers, part names, offsets
/// and counts and are structurally incapable of carrying document text (I4), so
/// this is safe to put on screen.
function refuse(fileName, message) {
  el("file-refusal").hidden = false;
  el("file-refusal-why").textContent = `${fileName}: ${message}`;
  // The OCR explanation is only shown for the refusals it actually explains.
  // Attaching it to an encrypted-PDF refusal would be answering a question
  // nobody asked and burying the one that was.
  el("file-refusal-ocr").hidden = !/scan|OCR/i.test(message);
  // THE HYBRID-PAGE REFUSAL, which is the one a reader can do something about.
  // Matched on the phrase the Rust `Display` actually emits rather than on a
  // loose keyword, so an encrypted-PDF refusal cannot accidentally offer a
  // checkbox that would not have helped.
  el("file-refusal-images").hidden = !/did not read/i.test(message);
  el("binary-card").hidden = true;
  el("download-file").disabled = true;
  currentFile = null;
}

async function loadFile(file) {
  clearFileUi();
  el("output-error").hidden = true;

  // 1. THE CEILING, BEFORE THE READ. `File.size` is known the moment the handle
  //    exists, so this costs nothing and is answered before any waiting starts.
  //    The limit is the wasm module's own, read at start-up: a copy of the
  //    number here could disagree with the one actually enforced, and the way it
  //    would disagree is that someone waits through a read for a file the module
  //    then refuses -- the exact failure this check exists to prevent.
  if (file.size > MAX_BYTES) {
    el("file-panel").hidden = false;
    el("file-what").textContent = "";
    refuse(
      file.name,
      `${humanSize(file.size)} is over this page's ${humanSize(MAX_BYTES)} ceiling, so it was refused before being read rather than after you waited. The parse runs on the main thread and a file this large would freeze the tab; the deid-tr CLI has no such limit.`,
    );
    return;
  }

  try {
    // 2. THE READ. Local: a `File` handle the user dropped, no URL, no request.
    showProgress(0, `Reading ${file.name}`);
    const bytes = await readBytes(file, (fraction) =>
      showProgress(fraction * 0.5, `Reading ${file.name}`),
    );

    // 3. DETECTION FROM CONTENT. `detectFormat` is given the BYTES AND NOTHING
    //    ELSE -- the binding does not accept a file name, by design, so there is
    //    no path by which an extension can override what the content says. The
    //    name is looked at separately, here, only so a disagreement can be
    //    reported to the reader.
    let detected;
    try {
      detected = wasm.detectFormat(bytes);
    } catch (error) {
      refuse(file.name, error.message ?? String(error));
      return;
    }
    const claimed = formatFromName(file.name);
    el("file-panel").hidden = false;
    el("file-what").textContent = `${file.name} - read as ${formatName(detected)}, decided from its contents (${humanSize(file.size)}).`;
    if (formatsDisagree(detected, claimed)) {
      el("file-mismatch").hidden = false;
      el("file-mismatch").textContent =
        `The name says ${formatName(claimed)} but the bytes are ${formatName(detected)}. deid-tr followed the bytes. Treating this as ${formatName(claimed)} would have rewritten it as the wrong format and left every identifier in place while looking like it worked - so this is the safe direction, but a file whose name and contents disagree is worth a second look before you trust either.`;
    }

    // 4. TEXT FORMATS TAKE THE ORIGINAL ROUTE AND STOP HERE.
    //
    //    A `.txt`, `.csv`, `.json` or `.jsonl` goes into the editor as text and
    //    gets the unchanged live-highlight experience: `run()` re-detects on
    //    every keystroke, every view works, and the file was simply a way of
    //    getting text into the box. Sending it through `redactFile` instead
    //    would hand back finished bytes and a read-only view, which would be a
    //    downgrade of a flow that already works.
    if (!isBinary(detected)) {
      el("file-progress").hidden = true;
      newDocument(new TextDecoder().decode(bytes), { fromFile: true });
      return;
    }

    // 5. THE REDACTION, for the two formats that cannot be edited in place.
    //    Synchronous inside wasm, so the status line is painted and composited
    //    first -- otherwise the message a reader sees during the freeze is the
    //    previous one.
    showProgress(0.5, `Redacting ${formatName(detected)}`);
    await afterPaint();

    state.salt = freshSalt();
    let result;
    try {
      result = wasm.redactFile(
        bytes,
        detected,
        wasm.Tier.SafeHarbor,
        state.salt,
        // Unticked by default, which is the module's default too. The panel
        // does not get to be more permissive than the library.
        el("allow-images").checked,
      );
    } catch (error) {
      // A REFUSAL, not a crash. `pdf::redact` fails rather than returning bytes
      // for an encrypted file, a scanned page, a page whose glyphs cannot be
      // decoded, and -- most importantly -- for an output that fails its own
      // verification. Every one of those must end with nothing offered.
      el("file-progress").hidden = true;
      refuse(file.name, error.message ?? String(error));
      return;
    }

    try {
      showProgress(1, "Done");
      present(file, detected, result);
    } finally {
      // The handle points at the document inside the module's linear memory.
      // Freeing it is what stops a session of dropped files from accumulating
      // one copy of each clinical document for the lifetime of the tab.
      result.free();
    }
  } catch (error) {
    el("file-progress").hidden = true;
    refuse(file.name, error.message ?? String(error));
  } finally {
    setTimeout(() => {
      el("file-progress").hidden = true;
    }, 600);
  }
}

/// Put a binary-format result on screen.
///
/// # Why the read-only view shows the REDACTED text, not the original
///
/// The binding's `preview` is the text recovered from the OUTPUT file, read
/// back with the same decoder the redactor scanned with. That is a deliberately
/// stronger thing to show than the input would have been: it is the evidence
/// behind the verification line rather than an illustration of it. A reader can
/// look at it and see the identifiers gone -- and see, in the same breath, that
/// every name is still sitting there, which no summary count would have made as
/// vivid.
///
/// It also means the panel never holds a decoded copy of the UNREDACTED
/// document in JS. The original bytes go into wasm and what comes back out is
/// already de-identified.
function present(file, format, result) {
  const preview = result.previewAvailable ? result.preview : "";
  currentFile = {
    name: file.name,
    format,
    bytes: result.bytes,
  };

  // The editor becomes a read-only window onto the redacted text. `state.doc`
  // is set directly rather than through `run()`, because re-running detection
  // over already-redacted text would produce an empty span map and overwrite
  // the real one with it.
  note.readOnly = true;
  note.value = preview;
  note.setAttribute("aria-describedby", "binary-readonly-note");
  el("binary-readonly-note").hidden = false;

  state.doc = preview;
  state.spans = [];
  state.segments = preview.length > 0 ? [{ kind: "keep", text: preview }] : [];
  state.output = preview;

  renderBinaryCard(file, format, result);
  render();
  renderFileSpans(result);
}

/// The verification verdict, the breakdown, and the download.
function renderBinaryCard(file, format, result) {
  el("binary-card").hidden = false;
  el("part-noun").textContent = format === "pdf" ? "page" : "part";

  const verification = result.verification;
  const checked = verification.identifiersChecked;
  const checks = [];
  for (let index = 0; index < verification.checkCount; index += 1) {
    checks.push(verification.check(index));
  }

  // THE VERDICT, PROMINENT AND IN WORDS. This is the strongest single thing the
  // feature does and the thing a user would never think to ask for, so it is
  // stated rather than made available. `role="status"` means a screen reader
  // gets it without going looking.
  //
  // ZERO IDENTIFIERS IS NOT A PASS AND MUST NOT READ LIKE ONE. If nothing was
  // removed, the output scan had nothing to hunt for and proved nothing. Saying
  // "verified clean" there would be the vacuous pass this whole feature exists
  // to refuse -- especially given deid-tr detects no names, so "nothing found"
  // is the expected result for a document full of them.
  const verdict = el("verification");
  if (checked === 0) {
    verdict.className = "verdict";
    verdict.textContent = `NOTHING WAS REMOVED from this ${formatName(format)}, so there was nothing for the output scan to look for. This is NOT a clean bill of health: deid-tr detects no names, so a document full of them produces exactly this result.`;
  } else {
    verdict.className = "verdict ok";
    verdict.textContent = `VERIFICATION PASSED: deid-tr re-opened the ${formatName(format)} it had just written and confirmed that none of the ${checked} removed identifier${checked === 1 ? "" : "s"} survives anywhere in the output bytes.`;
  }

  // WHAT WAS NOT READ, before the download. `imageWarningCount` is non-zero
  // only when the reader ticked the box, so this is never a surprise -- but it
  // is also the fact the verification verdict above does NOT cover, and the
  // verdict is the sentence most likely to be read as "this file is finished".
  const imageWarnings = [];
  for (let index = 0; index < result.imageWarningCount; index += 1) {
    imageWarnings.push(result.imageWarning(index));
  }
  el("images-warning").hidden = imageWarnings.length === 0;
  if (imageWarnings.length > 0) {
    el("images-warning-why").textContent = result.imagesDisclosure;
    el("images-warning-list").replaceChildren(
      ...imageWarnings.map((line) => {
        const item = document.createElement("li");
        item.textContent = line;
        return item;
      }),
    );
  }

  el("verification-detail").textContent =
    checks.length === 0
      ? ""
      : `Checked by ${verification.method}, on the output bytes rather than on the redactor's own bookkeeping: ${checks.join("; ")}. A file that fails any of these is not returned at all - there is no flag that produces a partially verified result.`;
  verification.free?.();

  // The per-region breakdown. A zero row means "read, nothing found", which is
  // a different and more reassuring fact than a region that was skipped.
  const tbody = el("parts");
  tbody.replaceChildren();
  for (let index = 0; index < result.partCount; index += 1) {
    const part = result.part(index);
    const row = document.createElement("tr");
    const name = document.createElement("th");
    name.scope = "row";
    name.textContent = part.name;
    row.append(name);
    const count = document.createElement("td");
    count.className = "mono num";
    count.textContent = String(part.masked);
    row.append(count);
    tbody.append(row);
    part.free?.();
  }

  const stripped = [];
  for (let index = 0; index < result.strippedCount; index += 1) {
    stripped.push(result.stripped(index));
  }
  el("stripped").textContent =
    stripped.length === 0
      ? "No whole structures were removed from this document."
      : `Removed outright, by name: ${stripped.join(", ")}. These are structures that duplicate page text or carry authorship - metadata, bookmarks, annotations, attachments, previous revisions - and they are deleted rather than swept.`;

  el("download-note").textContent = `${humanSize(result.bytes.length)}, built as a Blob in this tab and saved by your browser.`;
  el("download-file").disabled = false;

  if (result.previewTruncated) {
    el("binary-readonly-note").textContent =
      "Read-only, and TRUNCATED: this is the beginning of the text recovered from the redacted file, shown so you can see what came out. The full document is in the download above.";
  } else if (!result.previewAvailable) {
    // "No text in the output" and "we could not read the output back" must not
    // look the same to someone deciding whether to trust the file.
    el("binary-readonly-note").textContent =
      "The redacted file could not be read back for a preview. The verification above still ran against its bytes, but there is no text to show you here.";
  } else {
    el("binary-readonly-note").textContent =
      "Read-only: this is the text recovered from the REDACTED file - the evidence behind the verification line above, not a copy of your input. It cannot be edited back into the document; the redacted file is the download.";
  }
}

/// The file span map: what came out, without offsets.
///
/// A FILE SPAN CARRIES NO POSITION, and that is the binding's decision rather
/// than an omission. An offset into a PDF content stream is meaningless in the
/// output (the bytes are gone) and an offset into the input would be a pointer
/// into a document this page no longer holds. So the table shows what was
/// removed and what replaced it, which is what a reviewer can actually act on.
function renderFileSpans(result) {
  const tbody = el("spans");
  tbody.replaceChildren();
  for (let index = 0; index < result.spanCount; index += 1) {
    const span = result.span(index);
    const row = document.createElement("tr");
    // The columns are the editor's, reused, so the table keeps one shape. The
    // two offset columns are dashes rather than numbers: a file span has no
    // position (see this function's doc comment), and printing a plausible
    // integer there would be inventing one. `byteLen` goes in the input column
    // as a LENGTH, labelled as such, because that is what it is.
    //
    // The class strings carry column TYPE: `num` right-aligns and sets tabular
    // figures, so the byte lengths and the confidences form scannable columns
    // in the same shape the editor's span map uses.
    for (const [text, classes] of [
      [`${span.byteLen} bytes`, "mono num"],
      ["-", "mono num"],
      [span.label, ""],
      [span.layer, ""],
      ["mask", ""],
      [span.confidence.toFixed(2), "mono num"],
      [span.checksumValidated ? "yes" : "no", ""],
      ["surrogate", ""],
      [span.replacement, "mono"],
    ]) {
      const cell = document.createElement("td");
      if (classes) cell.className = classes;
      cell.textContent = text;
      row.append(cell);
    }
    tbody.append(row);
    span.free();
  }
  el("spans-empty").hidden = result.spanCount > 0;
  el("span-summary").textContent =
    result.spanCount === 0
      ? "Nothing was removed from this file."
      : `${result.spanCount} span${result.spanCount === 1 ? "" : "s"} removed. A file span has no byte offsets: see the note in the panel source for why.`;

  // THE AUTHORITATIVE ANNOUNCEMENT, overriding the one `render()` just wrote.
  // `render()` speaks for the editor, whose span map is empty for a file, so
  // left alone it would announce "no identifiers detected" over a redaction
  // that removed several. The names sentence rides along for the same reason it
  // does in the text flow: a count on its own reads like a clean result.
  announced = `${result.spanCount} identifier${result.spanCount === 1 ? "" : "s"} removed from this ${formatName(currentFile.format)} and the redacted file verified. Zero names masked: no L2 model is loaded in this build, so the downloaded file still contains every name in it.`;
  el("run-status").textContent = announced;
}

const DOWNLOAD_MIME = new Map([
  ["pdf", "application/pdf"],
  [
    "docx",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ],
]);

/// Suffix the output so a redacted file cannot be mistaken for its original.
///
/// Overwriting the source name in a downloads folder is how someone ends up
/// unable to tell which of two identically named files is the one that still
/// has the identifiers in it.
function redactedName(name) {
  const dot = name.lastIndexOf(".");
  return dot < 0
    ? `${name}-redacted`
    : `${name.slice(0, dot)}-redacted${name.slice(dot)}`;
}

el("download-file").addEventListener("click", () => {
  // `currentFile` is only ever set from a result the module RETURNED, and the
  // module returns bytes only after its own verification passed -- every
  // failure path throws instead. So there is no unverified-bytes state to guard
  // against here; the guard that matters is the refusal path never setting it.
  if (currentFile === null) return;
  downloadBytes(
    redactedName(currentFile.name),
    DOWNLOAD_MIME.get(currentFile.format) ?? "application/octet-stream",
    currentFile.bytes,
  );
  announce(
    "Redacted file saved. It still contains every name: no L2 model is loaded.",
  );
});

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

// --- tier selector -------------------------------------------------------

// HONEST REFUSAL, WITH THE WHOLE CHAIN, rather than a silent no-op or a single
// apologetic sentence.
//
// A one-line "unavailable, reverting" tells a reader that something is missing
// but not what, not why, and not whether waiting or reloading would help. Three
// separate facts are being compressed into that sentence and they have three
// different resolutions: the capability needs a local model, this build has no
// model, and a browser tab could not host one on the terms this page is sold
// on. Only the second is a packaging gap; the third is a deliberate refusal,
// and a reader who assumes it is the second will keep waiting for a release
// that is never coming to this surface.
//
// Building this as a list of DOM nodes rather than a string of markup is the
// same rule the rest of the panel follows: no `innerHTML` anywhere in this
// codebase, so no path exists by which page text becomes page structure.
const TIER_REASONS = [
  [
    "What the tier is.",
    "Expert Determination is the legal standard where a qualified analysis concludes re-identification risk is very small. In this pipeline that is layer L3: a full-document sweep for quasi-identifiers - employer and role, relationship references, assets and geography, distinctive events - which are re-identifying by MEANING and carry no token-level signature for a rule or an NER model to catch.",
  ],
  [
    "Why it needs a model at all.",
    "\"He works at the Central Bank\" is not an entity, so no detector tags it. Catching it requires an LLM reasoning about re-identification risk across the whole note. Invariant I1 of this project makes that model LOCAL, never a cloud API: sending PHI to a remote model in order to find its PHI defeats the entire purpose.",
  ],
  [
    "Why this build cannot run it.",
    "No local model is loaded here. The wasm module ships L1 rules, span algebra, L4 routing and L5 surrogates - and nothing that can read a document for meaning.",
  ],
  [
    "Why a browser tab specifically will not get it soon.",
    `In a tab, L3 would need WebGPU plus a multi-gigabyte model living in the page. This panel deliberately does not ship that. Its whole claim is that it loads no extra runtime and fetches nothing but its own ${WASM_KB}KB of WebAssembly - rules, span algebra, routing, surrogates and the PDF and DOCX parsers, all of it auditable - and a page that pulled gigabytes of weights across the network on first use would have traded away the one property that makes it worth trusting.`,
  ],
  [
    "Where it lands first.",
    "The command line. `deid-tr` on a host that can run a local quantized model is where Expert Determination is being built, because that host can hold the weights on disk, offline, without any of this page's constraints. Tauri desktop follows it. This tab may never get it, and saying so is more useful than an \"unavailable\" that reads like \"not yet\".",
  ],
];

const tier = el("tier");
const tierExplain = el("tier-explain");

function showTierExplanation() {
  tierExplain.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent =
    "Expert Determination is unavailable, and staying on Safe Harbor";
  tierExplain.append(heading);

  const lead = document.createElement("p");
  lead.textContent =
    "The selection was reverted rather than accepted. A panel that took the Expert Determination selection and returned a Safe Harbor result would be handing back an unswept document that looks swept, which is the single most dangerous failure this page could have.";
  tierExplain.append(lead);

  const list = document.createElement("dl");
  for (const [term, detail] of TIER_REASONS) {
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = detail;
    list.append(dt, dd);
  }
  tierExplain.append(list);

  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "ghost";
  dismiss.textContent = "Dismiss";
  dismiss.addEventListener("click", () => {
    tierExplain.hidden = true;
    tier.focus();
  });
  tierExplain.append(dismiss);

  tierExplain.hidden = false;
}

tier.addEventListener("change", () => {
  if (tier.value !== "expert-determination") {
    tierExplain.hidden = true;
    return;
  }
  tier.value = "safe-harbor";
  showTierExplanation();
});

const theme = el("theme");
theme.addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme !== "dark";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  theme.textContent = dark ? "Light theme" : "Dark theme";
  theme.setAttribute("aria-pressed", String(dark));
});

// --- tabs ----------------------------------------------------------------

const TABS = [
  ["tab-masked", "view-masked"],
  ["tab-highlight", "view-highlight"],
  ["tab-split", "view-split"],
  ["tab-inline", "view-inline"],
];

function selectTab(tabId) {
  for (const [otherTab, otherView] of TABS) {
    const selected = otherTab === tabId;
    const node = el(otherTab);
    node.setAttribute("aria-selected", String(selected));
    // Roving tabindex: the tablist is ONE tab stop, and the arrow keys move
    // within it. Without this every tab is its own stop and a keyboard user
    // walks through all four to reach the content of the first.
    node.tabIndex = selected ? 0 : -1;
    el(otherView).hidden = !selected;
  }
}

for (const [index, [tabId]] of TABS.entries()) {
  const node = el(tabId);
  node.tabIndex = index === 0 ? 0 : -1;
  node.addEventListener("click", () => selectTab(tabId));
  node.addEventListener("keydown", (event) => {
    const step =
      event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (step === 0) return;
    event.preventDefault();
    const next = TABS[(index + step + TABS.length) % TABS.length][0];
    selectTab(next);
    el(next).focus();
  });
}

// --- span map sorting ----------------------------------------------------

for (const button of document.querySelectorAll("button.sort")) {
  button.addEventListener("click", () => {
    const column = button.dataset.sort;
    // Clicking the active column flips it; clicking a new one starts ascending.
    // Ascending on confidence puts the LEAST certain spans at the top, which is
    // the end of that column a reviewer is actually looking for.
    state.sort =
      state.sort.column === column
        ? {
            column,
            direction:
              state.sort.direction === "ascending" ? "descending" : "ascending",
          }
        : { column, direction: "ascending" };
    for (const header of document.querySelectorAll("th[data-sort]")) {
      header.setAttribute(
        "aria-sort",
        header.dataset.sort === state.sort.column
          ? state.sort.direction
          : "none",
      );
    }
    render();
  });
}

// --- span and row linkage ------------------------------------------------

// A hovered or focused mark lights its span map row and vice versa, in both
// directions, through the `data-span` ordinal `compose()` stamped on both.
//
// Delegated from the document rather than bound per node: the marks and rows
// are rebuilt on every keystroke, and re-binding two listeners per span each
// time is how a panel that re-renders 8 times a second leaks listeners.
function linkSpan(index) {
  for (const node of document.querySelectorAll(".linked")) {
    node.classList.remove("linked");
  }
  if (index === null) return;
  for (const node of document.querySelectorAll(`[data-span="${index}"]`)) {
    node.classList.add("linked");
  }
}

for (const type of ["mouseover", "focusin"]) {
  document.addEventListener(type, (event) => {
    const owner = event.target.closest?.("[data-span]");
    linkSpan(owner ? owner.dataset.span : null);
  });
}
for (const type of ["mouseout", "focusout"]) {
  document.addEventListener(type, (event) => {
    if (event.target.closest?.("[data-span]")) linkSpan(null);
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
    announce("Marked source saved. It contains the original text.");
  }),
);

// --- start ---------------------------------------------------------------

reportNetwork();
run();
