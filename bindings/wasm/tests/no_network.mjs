// The check behind the sales argument.
//
// "Open devtools and watch the network tab stay empty" is the entire value
// proposition of the browser surface, and a value proposition that is only
// asserted in a README is a value proposition a refactor can delete. This file
// turns it into a test that fails the build.
//
// It proves the claim three independent ways, because each one alone is
// escapable:
//
//   1. STATIC, against the .wasm import table. A wasm module can only reach the
//      outside world through a function its host imports for it. If no import
//      is named after a networking API, the module physically cannot call one,
//      no matter what the glue does.
//   2. STATIC, against the generated JS glue. wasm-bindgen writes the glue, so
//      the glue is where a `js-sys`/`web-sys` dependency would surface a
//      `fetch` or a URL. Grepping it catches an import added upstream of us.
//   3. DYNAMIC, at run time. Every networking global is replaced by a stub that
//      records a call and throws. A full Safe Harbor de-identification and a
//      full two-phase Expert Determination run are then executed. Any stub that
//      fires fails the test and names itself.
//
// Run with: node bindings/wasm/tests/no_network.mjs   (after `just build-wasm`)

import { createRequire } from "node:module";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, "..", "pkg");
const wasmPath = join(pkg, "deid_tr_wasm_bg.wasm");
const gluePath = join(pkg, "deid_tr_wasm.js");

if (!existsSync(wasmPath) || !existsSync(gluePath)) {
  console.error(
    "missing build artifact in bindings/wasm/pkg -- run `just build-wasm` first",
  );
  process.exit(2);
}

// --- 1. The wasm import table ------------------------------------------------

// Names that would mean the module can reach the network. Matched as
// case-insensitive substrings of both the module and the field name of every
// import, so `__wbg_fetch_1a2b3c` is caught as readily as `fetch`.
const NETWORK_NAMES = [
  "fetch",
  "xmlhttprequest",
  "websocket",
  "eventsource",
  "sendbeacon",
  "beacon",
  "webtransport",
  "rtcpeerconnection",
  "importscripts",
  "navigator",
  "cache",
  "serviceworker",
];

/** Read an unsigned LEB128 at `offset`; returns [value, nextOffset]. */
function uleb(bytes, offset) {
  let result = 0;
  let shift = 0;
  for (;;) {
    const byte = bytes[offset++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [result >>> 0, offset];
    shift += 7;
  }
}

/** Every (module, field) pair the wasm binary imports. */
function wasmImports(bytes) {
  assert.deepEqual(
    Array.from(bytes.subarray(0, 4)),
    [0x00, 0x61, 0x73, 0x6d],
    "not a wasm binary",
  );
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const imports = [];
  let offset = 8; // magic + version
  while (offset < bytes.length) {
    const sectionId = bytes[offset++];
    let size;
    [size, offset] = uleb(bytes, offset);
    const end = offset + size;
    if (sectionId === 2) {
      // The import section.
      let count;
      [count, offset] = uleb(bytes, offset);
      for (let i = 0; i < count; i += 1) {
        let length;
        [length, offset] = uleb(bytes, offset);
        const module = decoder.decode(bytes.subarray(offset, offset + length));
        offset += length;
        [length, offset] = uleb(bytes, offset);
        const field = decoder.decode(bytes.subarray(offset, offset + length));
        offset += length;
        imports.push({ module, field });
        // Skip the import descriptor: a kind byte plus its payload.
        const kind = bytes[offset++];
        if (kind === 0x00) {
          [, offset] = uleb(bytes, offset); // typeidx
        } else if (kind === 0x01) {
          offset += 1; // reftype
          const [limitsKind, next] = uleb(bytes, offset);
          offset = next;
          [, offset] = uleb(bytes, offset);
          if (limitsKind === 0x01) [, offset] = uleb(bytes, offset);
        } else if (kind === 0x02) {
          const [limitsKind, next] = uleb(bytes, offset);
          offset = next;
          [, offset] = uleb(bytes, offset);
          if (limitsKind === 0x01) [, offset] = uleb(bytes, offset);
        } else if (kind === 0x03) {
          offset += 2; // valtype + mutability
        } else {
          throw new Error(`unknown import kind ${kind}`);
        }
      }
    }
    offset = end;
  }
  return imports;
}

const wasmBytes = new Uint8Array(readFileSync(wasmPath));
const imports = wasmImports(wasmBytes);
for (const { module, field } of imports) {
  const haystack = `${module}.${field}`.toLowerCase();
  for (const banned of NETWORK_NAMES) {
    assert.ok(
      !haystack.includes(banned),
      `the wasm module imports "${haystack}", which can reach the network`,
    );
  }
}
console.log(`ok  import table: ${imports.length} imports, none networking`);

// --- 2. The generated JS glue -----------------------------------------------

const glue = readFileSync(gluePath, "utf8");
const BANNED_IN_GLUE = [
  "XMLHttpRequest",
  "WebSocket",
  "EventSource",
  "sendBeacon",
  "http://",
  "https://",
  "ws://",
  "wss://",
];
for (const banned of BANNED_IN_GLUE) {
  assert.ok(
    !glue.includes(banned),
    `the generated glue contains "${banned}"`,
  );
}
// `fetch` is checked separately: wasm-bindgen's web glue uses it to load the
// module itself. The nodejs target reads the file from disk instead, so any
// occurrence here is ours and is a defect.
assert.ok(!/\bfetch\s*\(/.test(glue), "the generated glue calls fetch()");
console.log("ok  generated glue: no networking API, no URL");

// --- 3. Run it with every networking global booby-trapped --------------------

const fired = [];
const trap = (name) =>
  function trapped() {
    fired.push(name);
    throw new Error(`${name} was called -- the module tried to use the network`);
  };

for (const name of [
  "fetch",
  "XMLHttpRequest",
  "WebSocket",
  "EventSource",
  "Request",
  "Response",
  "WebTransport",
  "RTCPeerConnection",
]) {
  globalThis[name] = trap(name);
}
globalThis.navigator = new Proxy(
  {},
  {
    get(_target, property) {
      fired.push(`navigator.${String(property)}`);
      throw new Error(`navigator.${String(property)} was read`);
    },
  },
);

const require = createRequire(import.meta.url);
const deid = require(gluePath);

// Synthetic. The TCKN is COMPUTED, never written down (I8): a checksum-valid
// national id in a committed file is what the pre-commit hook blocks.
function validTckn() {
  const stem = [1, 2, 3, 4, 5, 6, 7, 8, 9];
  const odd = stem.filter((_, i) => i % 2 === 0).reduce((a, b) => a + b, 0);
  const even = stem.filter((_, i) => i % 2 === 1).reduce((a, b) => a + b, 0);
  const tenth = (odd * 7 + 100 - even) % 10;
  const eleventh = ([...stem, tenth].reduce((a, b) => a + b, 0)) % 10;
  return [...stem, tenth, eleventh].join("");
}

const tckn = validTckn();
const note = `Hasta Ayşe Yılmaz, TCKN ${tckn}, tel 0(532) 000 00 00. Merkez Bankası'nda çalışıyor.`;

// L5's salt comes from the HOST. `core/` performs no I/O and this binding
// links neither js-sys nor web-sys, so neither can reach an entropy source;
// the page calls crypto.getRandomValues and passes the bytes in. Requiring the
// argument is what makes surrogates the default rather than something a caller
// has to remember.
const salt = new Uint8Array(32);
crypto.getRandomValues(salt);

const safeHarbor = deid.deidentify(note, deid.Tier.SafeHarbor, salt);
assert.ok(!safeHarbor.text.includes(tckn), "the TCKN survived masking");
assert.ok(
  !safeHarbor.text.includes("[TCKN]"),
  "L5 is not wired into the browser build: the output carries a label placeholder",
);
assert.ok(
  /(?<!\d)\d{11}(?!\d)/.test(safeHarbor.text),
  "the TCKN was not replaced by a format-preserving surrogate",
);

// The vocabulary, in the artifact a browser actually loads. `costa'da` and
// `carcinoma'lı` must survive: masking them destroys the note.
const medical = deid.deidentify(
  "Toraks BT'de sol 5. costa'da fraktür; hasta carcinoma'lı değil, MRI'da temiz.",
  deid.Tier.SafeHarbor,
  salt,
);
assert.ok(medical.text.includes("costa'da"), "the anatomical term was masked");
assert.ok(medical.text.includes("carcinoma'lı"), "the diagnosis was masked");
assert.ok(medical.text.includes("MRI'da"), "the abbreviation was masked");

// The opt-out, named for what it costs, and the only way to get a placeholder.
const placeholders = deid.deidentifyWithLabelPlaceholders(
  note,
  deid.Tier.SafeHarbor,
);
assert.ok(placeholders.text.includes("[TCKN]"));
assert.equal(safeHarbor.reidentify(), note, "the round trip is not exact");
assert.ok(safeHarbor.spanCount >= 1);
assert.ok(safeHarbor.auditIsRedacted, "the audit log carries a rationale");

// The two-phase L3 seam, with the completion the HOST's WebGPU model would have
// produced. No model runs here, and none is downloaded: that is the point.
const prompt = deid.contextualPrompt(note);
assert.ok(prompt.includes(note), "the prompt must carry the document");
const hostCompletion = JSON.stringify([
  {
    quote: "Merkez Bankası",
    category: "EMPLOYER_ROLE",
    reason: "employer",
  },
]);
const expert = deid.deidentifyWithContextualResponse(
  note,
  hostCompletion,
  "host-supplied",
  "webgpu",
  "q4_0",
  7n,
  salt,
);
// A quasi-identifier has no format to preserve -- substituting a plausible
// employer would fabricate a clinical fact -- so L5 leaves it as its label.
assert.ok(expert.text.includes("[EMPLOYER_ROLE]"));
assert.ok(!expert.text.includes("Merkez Bankası"));
assert.equal(expert.reidentify(), note);

// Expert Determination must never silently degrade to Safe Harbor.
assert.throws(
  () => deid.deidentify(note, deid.Tier.ExpertDetermination, salt),
  "Expert Determination without a completion must fail, not degrade",
);

assert.deepEqual(fired, [], `networking globals were called: ${fired.join(", ")}`);
console.log("ok  runtime: full de-identification, zero networking calls");
console.log("PASS  nothing is uploaded");
