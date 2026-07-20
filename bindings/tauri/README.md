# bindings/tauri — the desktop application

**This build masks ZERO names.** L2 has no trained model and no weights ship with it, so
`PATIENT_NAME`, `CLINICIAN_NAME` and `RELATIVE_NAME` pass through untouched. The window says so in
its main view, above every result, and every result carries the sentence with it. Nothing in this
directory may be changed to imply otherwise.

## Scope: what is built, and what is only configured

This is the honest version of the boundary, written first because a roadmap item marked done that
cannot be run is the failure mode this project has hit before (D-029, D-037).

| Target | State | What that means |
|---|---|---|
| **Desktop (macOS, Linux, Windows)** | **Built and run.** | `just build-tauri` produces a working executable. Verified on macOS: it compiles offline, launches, and its logic is covered by 17 tests that need no webview. |
| **iOS** | **Configured, never built.** | `bundle.iOS.minimumSystemVersion` is set and the Rust is portable, but `tauri ios init` has never been run, no Xcode project exists, no signing identity is configured, and nothing has been put on a device or a simulator. |
| **Android** | **Configured, never built.** | `bundle.android.minSdkVersion` is set. `tauri android init` has never been run, no Gradle project exists, no NDK toolchain has been proven, nothing has run on a device or an emulator. |

Treat the two mobile rows as **not started**, not as "nearly there". The configuration keys are
there so the next person does not have to guess what they should be; they are not evidence that
anything works. In particular the file-dialog flow, which is the entire file path of this
application, uses a desktop file picker whose mobile equivalent is a different document-provider
model that nobody here has exercised.

### Also not built

- **No installer and no app bundle.** `bundle.active` is `false`, so there is no `.app`, `.dmg`,
  `.msi`, `.deb` or `.AppImage` — `just build-tauri` produces a bare executable. Bundling needs a
  full icon set per platform, and on macOS and Windows it needs code-signing identities that this
  repository does not have and should not pretend to.
- **No auto-update.** Deliberately, permanently: see below.

## Running it

```sh
just build-tauri                                     # also runs the air-gap gate
./bindings/tauri/target/release/deid-tr-desktop
```

**One observed quirk, recorded because it looks like a broken build and is not.** On macOS, an
unbundled binary relaunched within about a second of killing a previous instance sometimes exits
immediately with status 0 and no output. Left more than a second between runs it starts every time
(verified: four consecutive launches, all alive). It is an artifact of relaunching an app that has
no `.app` bundle identity, and it is one more reason the bundling work above is not finished.

`just build-all` includes this and **skips loudly** — never silently — when the Tauri dependency
graph is not in the local cargo cache or, on Linux, when `webkit2gtk-4.1` is missing. The skip
prints the reason and the exact command that fixes it, and is listed again in the closing report.
That is the same rule the wasm half follows.

## What it does

| Command | Effect |
|---|---|
| `about` | version, the disclosure sentence, `masks_names: false`, `network_capable: false` |
| `layer_report` | which of L1–L5 are live in this process, and why not when they are not |
| `expert_tier_gate` | whether Expert Determination can run, and the exact fix when it cannot |
| `deidentify_text` | de-identify text typed into the window |
| `redact_document` | pick a file, redact it, save it — PDF, DOCX, TXT, CSV, JSON, JSON Lines |

## Why it calls the Rust crates directly, not the wasm binding

`bindings/wasm` exists because a browser cannot link `ort` or open a PDF off a disk. Neither
limitation applies to a desktop process: this crate links `deid-tr-core` and `deid-tr-files`
directly. Going through WebAssembly on a host that can run the native crate would cost the real file
formats — PDF and `.docx` handling lives in `deid-tr-files` — and would put a second copy of the
pipeline in the product for no gain.

The consequence worth stating plainly: **the webview never sees a document.** For a file, the bytes
are read, masked and written entirely in Rust; what crosses the IPC boundary is counts, labels and
structural page names. For typed text, what comes back is the de-identified text the user asked for
plus a span map of labels, lengths and synthetic replacements. There is no upload because there is
nothing to upload to, and there is no copy of the note in the webview process either. That is I4
applied to a GUI: the rule that keeps a TCKN out of a log also keeps it out of a renderer's heap,
its devtools and any crash dump the OS takes of it.

## I1 in a GUI: how "runs air-gapped" is enforced

A desktop framework brings a large dependency graph and an ambient expectation of auto-update, crash
reporting and telemetry. All three are network egress from a process that reads clinical documents,
and all three arrive by default in most desktop stacks. So the claim is a gate, not a paragraph:
`just tauri-no-network` runs **before** `just build-tauri` and checks three independent things.

1. **The resolved dependency graph carries no HTTP client and no TLS stack.** Measured, not asserted:
   no `reqwest`, `hyper`, `ureq`, `rustls`, `openssl`, `native-tls`, `mio` or any of the rest of the
   list `just core-no-socket` uses. `tokio` is present — `tauri` and `rfd` use it as an executor —
   and is the one name excluded from the ban; `mio`'s absence is what shows its networking is not
   compiled in, because tokio cannot open a socket without it.
2. **`tauri.conf.json` enables no updater and names no remote origin.** Not "points at a safe URL" —
   absent. The check also refuses `devUrl` and the build hooks, so the window can only ever load
   `./ui`, which is compiled into the binary.
3. **The webview is granted `core:default` and nothing else.** Any other permission fails the build
   until somebody writes down in `docs/DECISIONS.md` which command needs it and why it cannot be
   done from Rust instead.

The CSP is the other half of the same claim: `default-src 'none'` with no `connect-src` beyond the
IPC transport, so a window that may not connect anywhere cannot exfiltrate what it renders. It is
set in `tauri.conf.json`, which is the copy Tauri serves on the custom protocol and which page
content cannot edit; the `<meta>` tag in `ui/index.html` repeats it where a reader of the page will
look for it.

### Why the dialogs are opened from Rust

`tauri-plugin-dialog` has a JS API. Using it would mean granting `dialog:allow-open` and
`dialog:allow-save` to the page, which is a capability the page then holds permanently. Calling the
same plugin from Rust needs no capability at all, which is why the capability file is one line long.
It also means no command takes a path from the page: `redact_document` takes only a tier, and the
file it reads is the one the user picked in the OS dialog a moment earlier. A page that could name a
path is a page that could be made to read `~/.ssh/id_rsa`.

## Why this crate is not a workspace member

Same reasoning as `bindings/python` and the held-out `ort` dependency, recorded in the root
`Cargo.toml`. Resolving Tauri's graph inside the workspace would put it in the **root** `Cargo.lock`
— the file `just core-no-socket` reads and the one `just test-airgapped` must resolve offline.
Held out, the workspace lock never moves, `core/` is provably still socket-free, and a desktop build
is opt-in. This crate has its own `Cargo.lock`, which is committed.

## The Expert Determination tier

`DEID_L3_MODEL` and `DEID_L3_RUNTIME` — the same two variables the CLI reads, so a machine set up
for `deid mask --tier expert` is already set up for this. Both name things on the local filesystem: a
GGUF weights file and an inference executable. There is no host, no endpoint, no token and no
download, and `deid-tr-llm` has no HTTP client in its manifest to add one with.

The gate is checked **before** any document is read and before the file dialog opens, and the tier
control in the window is disabled with the reason attached when it cannot run. A refusal that only
arrives after a user has found their file is a refusal that gets worked around by falling back to
Safe Harbor — which is the one outcome this tier must never produce silently.

## Files

```
Cargo.toml              held out of the workspace, on purpose
tauri.conf.json         CSP, window, no updater, mobile keys (unbuilt)
capabilities/default.json   core:default and nothing else
build.rs                tauri-build
icons/icon.png          generated by scripts/make_tauri_icon.py, regenerated on every build
gen/schemas/            generated by tauri-build; not hand-edited
src/lib.rs              the disclosure and `About`
src/pipeline.rs         all of the behaviour, tested without a webview
src/l3.rs               the tier gate and its refusal
src/main.rs             the window and five commands, thin on purpose
ui/                     index.html, app.css, app.js — no bundler, no npm, no framework
```

`ui/` has no build step because it needs none: three static files, no dependencies, no transpiler.
Opening `ui/index.html` directly in a browser shows the layout but disables both buttons and says
why — a control that silently does nothing is worse than one that is visibly broken, because the
user concludes the document had nothing in it.
