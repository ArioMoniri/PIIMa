// Loading the wasm module, and arming the network trap behind it.
//
// THE MODULE IS NOT BUNDLED, AND THAT IS DELIBERATE. It is loaded at runtime
// from the sibling `./pkg-web/`, by a dynamic import Vite is told to leave
// alone. Three reasons, in order of weight:
//
//   1. It is the SAME artifact the vanilla panel loads and the same one
//      `just package` ships. If this app bundled its own copy, the two surfaces
//      could disagree about what the pipeline does while both claiming to be
//      deid-tr, and the one with the nicer animation would be the one people
//      believed.
//   2. `bindings/wasm/pkg-web/` is a build output and is gitignored. A bundler
//      import would make `npm run build` fail on a clean checkout until someone
//      had run `just build-wasm`, turning the Rust wasm toolchain into a
//      prerequisite for touching a React component.
//   3. The .wasm stays a separate, checksummable file on disk rather than being
//      base64'd into a JS chunk. A reviewer can hash it against the one in the
//      release bundle.
//
// ORDER MATTERS AND THE VANILLA PANEL LEARNED THIS THE HARD WAY. The trap below
// replaces `fetch`. wasm-bindgen's generated initialiser ALSO uses `fetch`, to
// load its own `.wasm`. Arming the trap first therefore strangles the module
// load ("Failed to fetch") and the panel never starts. So: pull the module in
// with the real `fetch` first, then arm the trap, then initialise from the bytes
// already in memory. The claim this page makes is about CLINICAL TEXT, and no
// note can have been typed at this point -- the editor does not exist until
// React has mounted, which is after this resolves. From the moment the trap is
// armed, every networking global is dead for the rest of the page's life.

import type { DetectedSpan } from "./types";

/** What the loaded module exposes that this app uses. */
interface WasmModule {
  default: (init: { module_or_path: ArrayBuffer }) => Promise<unknown>;
  version: () => string;
  deidentify: (doc: string, tier: unknown, salt: string) => WasmResult;
  Tier: { SafeHarbor: unknown };
}

interface WasmResult {
  readonly spanCount: number;
  span: (index: number) => WasmSpan;
  free: () => void;
}

interface WasmSpan {
  readonly start: number;
  readonly end: number;
  readonly label: string;
  readonly layer: string;
  readonly decision: string;
  readonly confidence: number;
  readonly checksumValidated: boolean;
  readonly replacement: string | null | undefined;
  free: () => void;
}

/** Live evidence that this page makes no requests. Read by the UI. */
export interface NetworkWitness {
  /** Networking globals that were called after the trap was armed. */
  readonly trapped: readonly string[];
  /** Resources the browser actually fetched after the module finished loading. */
  readonly observed: number;
  /** CSP directives that refused a load. A control working, not a leak. */
  readonly blocked: readonly string[];
}

export interface Runtime {
  readonly build: string;
  readonly wasmBytes: number;
  detect: (doc: string, salt: string) => DetectedSpan[];
}

const trapped: string[] = [];
const blocked: string[] = [];
let observedRequests = 0;
let notify: (() => void) | null = null;

/** Subscribe the UI to the counters. Returns an unsubscribe. */
export function onNetworkChange(listener: () => void): () => void {
  notify = listener;
  return () => {
    notify = null;
  };
}

export function networkWitness(): NetworkWitness {
  return { trapped: [...trapped], observed: observedRequests, blocked: [...blocked] };
}

function bumped() {
  notify?.();
}

export async function loadRuntime(): Promise<Runtime> {
  const realFetch = globalThis.fetch.bind(globalThis);
  const wasmUrl = new URL("./pkg-web/deid_tr_wasm_bg.wasm", document.baseURI);
  const wasmBytes = await (await realFetch(wasmUrl)).arrayBuffer();

  for (const name of [
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "WebTransport",
    "RTCPeerConnection",
  ] as const) {
    // A THROWING stub, not a silent no-op. A no-op would let a dependency's
    // telemetry call "succeed" and leave the page looking clean; a throw shows
    // up in the console with a stack trace pointing at whoever called it.
    (globalThis as unknown as Record<string, unknown>)[name] = function trap() {
      trapped.push(name);
      bumped();
      throw new Error(`${name} was called`);
    };
  }
  if (navigator.sendBeacon) {
    navigator.sendBeacon = () => {
      trapped.push("navigator.sendBeacon");
      bumped();
      return false;
    };
  }

  // Armed EARLY, unlike the resource observer below. A declarative load the CSP
  // refuses never reaches the network and so never reaches the resource
  // timeline either -- it is invisible to the other two mechanisms. That is a
  // control WORKING, but it is still the page trying something it should not,
  // and a reader deserves to be told which of the two happened rather than
  // inferring it from a silence. A violation during the module load is a real
  // finding, so this listener has to exist before the load.
  addEventListener("securitypolicyviolation", (event) => {
    blocked.push(event.effectiveDirective || event.violatedDirective);
    bumped();
  });

  // `@vite-ignore` keeps Rollup from resolving this at build time; see the
  // header. It MUST be the async initialiser, not `initSync`: browsers refuse a
  // synchronous `WebAssembly.Module` larger than 4KB on the main thread and this
  // module is over a megabyte, so `initSync` throws a RangeError regardless of
  // how correct its arguments are.
  const glueUrl = new URL("./pkg-web/deid_tr_wasm.js", document.baseURI).href;
  const wasm = (await import(/* @vite-ignore */ glueUrl)) as WasmModule;
  await wasm.default({ module_or_path: wasmBytes });

  // A SECOND, INDEPENDENT counter, INSTALLED HERE AND NOT EARLIER.
  //
  // The baseline has to be the moment the module has finished loading, because
  // that is what the number on screen claims to be: "requests this page made
  // once it was running". An earlier revision installed this before the glue
  // import above, so the observer counted `deid_tr_wasm.js` -- the module's own
  // second file -- and the panel opened reporting "Something reached for the
  // network. 1 resource". A no-network claim that cries wolf on its own load is
  // worse than no claim: the first thing anyone learns is that the counter is
  // noise, and then it is not read on the day it means something.
  //
  // The traps above cover the globals this file can name; the resource timeline
  // counts what the browser actually fetched, including anything a future
  // dependency reaches through a path nobody thought to stub. Two mechanisms
  // disagreeing is itself the signal worth having.
  if (globalThis.PerformanceObserver) {
    new PerformanceObserver((list) => {
      observedRequests += list.getEntries().length;
      bumped();
    }).observe({ type: "resource", buffered: false });
  }

  // THE SIZE IS MEASURED, NEVER ASSERTED. `wasmBytes` is the buffer this tab
  // actually fetched. A hand-written number in the markup would have been
  // correct until the first time the module grew and silently wrong afterwards,
  // and on a page whose pitch is "check this yourself" a false claim about its
  // own weight is the one that costs most, because it is the easiest to check.
  const kb = Math.round(wasmBytes.byteLength / 1024);

  return {
    build: `deid-tr-wasm ${wasm.version()}, ${kb}KB wasm`,
    wasmBytes: wasmBytes.byteLength,
    /**
     * Call the module and flatten its span map into plain objects.
     *
     * The wasm-bindgen handles are freed immediately. They are pointers into
     * the module's linear memory holding the ORIGINAL document, and a panel
     * that re-runs on every keystroke would otherwise accumulate one copy of
     * the clinical note per character typed for the lifetime of the tab.
     */
    detect(doc: string, salt: string): DetectedSpan[] {
      const result = wasm.deidentify(doc, wasm.Tier.SafeHarbor, salt);
      try {
        const spans: DetectedSpan[] = [];
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
    },
  };
}

/**
 * A per-session surrogate salt, drawn from the CSPRNG.
 *
 * Not persisted. Surrogate consistency is a within-document property; a salt
 * that outlived the tab would make the same name map to the same surrogate
 * across two different patients' notes, which is a linkage key.
 */
export function newSalt(): string {
  const draw = new Uint8Array(16);
  crypto.getRandomValues(draw);
  return Array.from(draw, (b) => b.toString(16).padStart(2, "0")).join("");
}
