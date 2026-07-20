# Deploying deid-tr

> ## Before anything below: running `deid-serve` as a service is a different decision
>
> This page is about **building, packaging and installing artifacts**, all of which happen on one
> machine and change nothing about the product's central claim.
>
> **`deid-serve` is different.** deid-tr's premise is that PHI never leaves the device. A *server*
> deployment means clinical text crosses a network to reach the service — patient names, TCKNs,
> addresses, diagnoses, in cleartext, because this binary terminates no TLS. That is a legitimate
> architecture inside a segmented hospital network already covered by the institution's KVKK
> obligations. It is an illegitimate one across the open internet, at any scale, for any duration,
> including "just for testing". The line is not technical — both look identical to the process —
> and only you know which side you are on.
>
> The service also holds **span maps** in memory for the session TTL: the table mapping each
> surrogate back to the real identifier it replaced. That is not a derivative of the PHI; it is the
> PHI with the narrative stripped away and an index attached, and it is the most sensitive
> structure in the product.
>
> **Read `docs/DEPLOY-SERVER.md` in full before serving anything**, and run `just deploy-check`
> before exposing anything. `just deploy-local` — loopback, no flags, unreachable from any other
> machine — is the default and needs none of this.

Four commands. Everything they do is in the `justfile`; nothing here is a step you have to
remember, because a step you have to remember is a step that stops happening.

| Command | Produces |
|---|---|
| `just build-all` | every shippable artifact, with a report of what was skipped and why |
| `just package` | `dist/deid-tr-<version>-<target>.tar.gz` + `SHA256SUMS` |
| `just install [PREFIX]` | the three binaries on your PATH (default `~/.local/bin`, no sudo) |
| `just register-mcp` | the MCP client config block, printed, never written |

Plus one per browser surface:

| Command | Produces |
|---|---|
| `just serve-panel` | the vanilla panel on 127.0.0.1:8722 — no build step |
| `just build-panel-app` / `just serve-panel-app` | the React panel on 127.0.0.1:8723 |

`build-all` runs `build-panel-app` when npm is present and **skips it loudly** when it is not,
by the same rule the wasm half follows: a Node toolchain must not become a prerequisite for
touching `core/`. The vanilla panel is unaffected by that skip — it has no build step, which is
exactly why it still exists. See `bindings/panel-app/README.md` for why both surfaces are kept.

## The disclosure that governs all of this

**This build masks no names.** L2 has no trained model and no weights ship, so `PATIENT_NAME`,
`CLINICIAN_NAME` and `RELATIVE_NAME` pass through untouched. Every recipe above says so in its
own output, and `deploy/BUNDLE_README.md` says so in the first section a downloader reads.

The disclosure lives in these places, and they are listed rather than counted because the list
grows every time a surface is added:

- each recipe's own stdout, including `just build-panel-app`
- `deploy/BUNDLE_README.md`, first section
- `bindings/wasm/panel/index.html` — the banner, above the fold, before any output
- `bindings/panel-app/src/components/Banner.tsx` — the same banner on the React surface
- both panel READMEs, under a heading of their own
- `./target/release/deid doctor`

If a change ever makes that untrue, all of the above are what have to change with it. If a
change makes it *more* true — a surface that masks less than the text claims — that is the
defect, not a documentation gap.

**The React panel raises the stakes on this**, which is why it carries the disclosure twice. Its
blackout animation draws a black bar over every masked span, and a black bar is the most
recognisable visual shorthand for "redacted" there is. A bar over a name that is still in the
output would be a stronger false claim than any sentence on the page could make. Rule 1 in
`bindings/panel-app/src/deid/bars.ts` makes that structurally impossible rather than merely
avoided; `bars.test.ts` and `SpanViews.test.tsx` are what keep it that way.

## `just build-all`

Builds `deid`, `deid-mcp`, `deid-serve` in release mode, then the wasm module (both
`--target web` for the panel and `--target nodejs` for the no-upload proof).

The wasm half **skips, loudly, rather than failing** when `wasm32-unknown-unknown` or a
wasm-bindgen is absent. That is the one asymmetry in this file's usual "missing toolchain is
fatal" rule, and it is deliberate: `just build-wasm` is a thing someone asked for, so failing
tells them the truth; `build-all` is the entry point for a contributor who wants the native
binaries, and hard-failing there would make the wasm toolchain a prerequisite for touching
`core/`. The rule being kept is not *never skip* — it is *never skip silently*. A skip prints
the reason, prints the exact command that fixes it, and is listed again in the closing report.

A missing binary after a successful `cargo build` is fatal, not a skip: it means a `[[bin]]`
name drifted from the `bins` variable, and the first symptom would otherwise be an empty bundle.

**The desktop application** (`bindings/tauri`, `just build-tauri`) is built here too, under the
same skip-loudly rule and for the same reason: it skips when the Tauri dependency graph is not in
the local cargo cache — that graph is deliberately outside the workspace lock, so on a machine that
has never fetched it there is nothing to build from — or, on Linux, when `webkit2gtk-4.1` is
missing. Both skips print the exact command that fixes them.

`build-tauri` depends on `just tauri-no-network`, which refuses the build if the desktop graph
acquires an HTTP client or a TLS stack, if `tauri.conf.json` gains an updater or a remote origin,
or if the webview is granted any capability beyond `core:default`. I1 has to survive a GUI, and a
GUI framework is where auto-update and telemetry arrive by default.

What it produces is a **bare executable**, not an installer: `bundle.active` is `false`, so there
is no `.app`, `.dmg`, `.msi` or `.deb`, and mobile is configured but never built. See
`bindings/tauri/README.md`, which leads with the table of what runs and what does not.

## `just package`

Refuses when `build-all` skipped anything. A contributor may build a partial tree; a release
tarball missing a surface would be discovered by whoever unpacked it expecting one.

The bundle:

```
deid-tr-<version>-<target>/
  README.md      generated from deploy/BUNDLE_README.md (version, target, source revision filled in)
  LICENSE        Apache-2.0
  SHA256SUMS     every file above, relative paths, verifiable after extraction
  bin/           deid, deid-mcp, deid-serve
  panel/         the browser panel, static
  pkg-web/       the wasm module the panel loads from ../pkg-web/
```

`dist/SHA256SUMS` covers the tarball itself. Both checksum sets are printed to stdout so a human
can record them out of band — beside the file it checksums, a checksum only proves the download
did not corrupt.

**Reproducibility** here means: same inputs, same tarball bytes. File mtimes are flattened to a
fixed instant, the member list is sorted with `LC_ALL=C`, and `gzip -n` keeps the compressor from
stamping its own timestamp into the header. That removes the incidental nondeterminism; it is not
a claim of bit-for-bit reproducibility across machines, which the compiler decides and this
recipe cannot.

Verified: two consecutive `just package` runs produced identical SHA256.

**No model weights are in the bundle.** There are none to bundle, for any layer, and `deid pull`
is not implemented — the bundle README says both, in place of a user hunting for a model
directory that was never going to exist. `--tier expert` takes a local model the operator
supplies (`--model FILE.gguf --runtime BIN`); if it cannot be wired the run fails rather than
falling back.

## `just install [PREFIX]`

Default `~/.local/bin`, chosen so the default never needs sudo — a tool that asks for root during
install is a tool people install by pasting a root shell command, and this one reads patient
records. A non-writable prefix fails with the fix; the recipe never escalates.

Idempotent via `install -m 0755`: atomic replacement, explicit mode, umask-independent, and safe
over a binary that is currently running. Every path written is printed, and a prefix that is not
on `PATH` gets called out — the set of things that appear on your PATH without telling you should
be empty.

## `just register-mcp`

Prints the config block with the absolute path to the built `deid-mcp` filled in. It does not
write it anywhere.

That is the point of the recipe, not a limitation of it. The config file belongs to a client
outside this repository, and editing someone's assistant configuration from a build step is a
surprise. This tool's posture is that surprises are the defect: a de-identifier that does
something you did not ask for is a de-identifier you cannot reason about. The absolute path is
interpolated because a relative command path resolves against whatever working directory the
client happens to have, and that failure looks like the server hanging rather than a missing
file.

It covers the standard `mcpServers` shape plus the `claude mcp add` form, and names the config
file for each common client. It refuses to print at all when the binary is not built, because a
config pointing at a missing command fails almost silently in every client.

## Serving the packaged panel

From the extracted bundle root — not from `panel/`, because the page loads the module from the
sibling `../pkg-web/`:

```sh
python3 -m http.server --bind 127.0.0.1 8722
# http://127.0.0.1:8722/panel/index.html
```

`--bind 127.0.0.1` is explicit (I3). `deid-serve` likewise defaults to `127.0.0.1:8787` and
refuses an all-interfaces bind unconditionally — `--expose` and `--token` do not unlock `0.0.0.0`
or `::`.

---

# Standing up a fresh server, start to finish

Everything above is about artifacts on one machine. This section is the sequence for a server an
operator will disconnect from — every command in order, nothing left as "and then configure it".

**The disclosure applies to all of it: this build masks no names.** L2 has no trained model and no
weights ship, so `PATIENT_NAME`, `CLINICIAN_NAME` and `RELATIVE_NAME` pass through untouched. What
`deid-serve` does mask is the rule-detectable set — TCKN, VKN, SGK, IBAN, phone, MRN, email, dates.
`just deploy-check` prints the breakdown, and the service prints it again on every start.

## 1. Clone and set up

```sh
git clone https://github.com/ArioMoniri/PIIMa.git
cd PIIMa
./scripts/server-setup.sh
```

The script installs no system packages. It needs `git`, `cargo`, `rustc` and `python3` (with the
`venv` module — on Debian and Ubuntu that is a separate `python3-venv` package) already present,
and it tells you which one is missing rather than installing it for you.

**Running it twice is safe.** Each step checks whether its work is current: the venv is stamped
with the checksum of `scripts/requirements.txt`, `wasm-bindgen` is compared against the pinned
version rather than merely detected, and cargo's own staleness model decides what rebuilds. If your
connection drops during the wasm-bindgen build — the slow step, several minutes — reconnect and run
it again.

## 2. Start the surfaces, detached

```sh
just up
```

Prints which mechanism it used, the pid and port of each surface, and the log path.

| Surface | Address | What it is |
|---|---|---|
| `serve` | `127.0.0.1:8787` | `deid-serve`, the HTTP de-identification service |
| `panel` | `127.0.0.1:8722` | the browser panel, static files only |

**tmux is preferred; nohup is the fallback.** With tmux installed you get a session named
`deid-tr` with one window per surface, which means an operator can attach and watch — and the
thing they will see is `deid-serve`'s startup banner carrying the coverage disclosure. Without
tmux the surfaces run under `nohup` + a pidfile in `.run/`, which survives the same SSH drop but
gives you nothing to attach to. Install tmux if you have the choice.

`just up` is loopback-only in both mechanisms. Detaching a process does not change its bind
posture: `scripts/surfaces.sh` has no host argument to pass, `deid-serve` refuses `0.0.0.0` and
`::` unconditionally, and `scripts/panel_server.py` has `127.0.0.1` as a module constant with no
flag that overrides it (I3).

## 3. Attach, watch, and detach WITHOUT killing anything

This is the step that goes wrong. In an attached tmux session **`Ctrl-C` kills the surface in the
current window.** It is the reflex for "I am done looking at this", and here it stops the service.

```sh
tmux attach -t deid-tr     # attach
                           # Ctrl-b  then  d      <- DETACH. Surfaces keep running.
                           # Ctrl-b  then  n      <- next window (serve <-> panel)
                           # Ctrl-b  then  w      <- pick a window from a list
```

`Ctrl-b` means press and release Ctrl-b, *then* press the next key. It is not a chord.

If you are not attached, you never need any of this:

```sh
just status                # state, pid, mechanism, port, log size, per surface
just logs                  # last 100 lines of both logs
just logs serve -f         # follow one of them; Ctrl-C here stops the TAIL, not the service
```

## 4. Reach it from your laptop

Over an SSH tunnel, which needs no exposure, no TLS and no bearer token, and puts nothing on a
routable interface. Run this **on your laptop**, not on the server:

```sh
ssh -N -L 8787:127.0.0.1:8787 -L 8722:127.0.0.1:8722 YOU@THIS-SERVER
```

`-N` means "no remote command, just the tunnel". Leave it running; it holds the forward open. Then,
still on your laptop:

```sh
open http://127.0.0.1:8722/panel/index.html          # the panel
curl http://127.0.0.1:8787/health                    # the service
```

The `127.0.0.1` on the left of each `-L` is your laptop; the one on the right is the server's
loopback as seen from the server. Neither side is ever a routable address.

## 5. Stop

```sh
just down                  # both surfaces
just down serve            # one of them
```

`down` kills by pidfile — `SIGTERM`, then `SIGKILL` after 5s — removes the tmux window, and then
**connects to the port to confirm nothing is still listening.** It reports the port as free only
after that check passes. If a listener survives, `down` exits non-zero, names the holder via `lsof`
or `ss` where available, and says so plainly. A `down` that reported success over a live listener
would send the operator to `kill -9` against a guessed pid, which is worse than no `down` at all.

## What is in the log files

`just up` is the first thing in this project that **persists** output rather than streaming it to a
terminal, so what reaches `logs/` is an I4 question. What was checked, and what was found:

**`logs/serve.log` — clean, structurally.** `bindings/service/src/log.rs` builds every line from an
operation name, counts, byte offsets, entity labels and `&'static str` tags. There is no field or
method on `Event` that accepts a `&str` slice of a document, so a request body cannot reach it even
by mistake. Driving a note containing a name, a checksum-valid TCKN, a phone number, an email and a
Turkish address through `POST /deidentify` produced exactly this:

```
deid-serve op=request route=/deidentify source_bytes=167 ms=3 session_seq=1 \
    labels=TCKN:1,PHONE:1,EMAIL:1 status=200 response_bytes=1514 outcome=sent
```

Counts and label *kinds*, never values. The session handle is absent by design — it is a bearer
capability over the span map — and `session_seq` correlates a `deidentify` with its `reidentify`
while granting nothing. A request for a path containing a name and a TCKN in its query string
logged `route=unmatched` and the path itself was never written. There is no verbosity flag that
adds text: the only logging flag is `--quiet`, which removes lines.

**`logs/panel.log` — this is what persisting logs actually caught.** The panel server previously
used `http.server`'s stdlib logger, which writes `self.requestline` verbatim. A hand-typed URL
landed in the file complete with its query string:

```
127.0.0.1 - - [...] "GET /AyseYilmaz.html?tckn=10000000147 HTTP/1.1" 404 -
```

Nothing in the panel's own operation can produce that — it masks in the browser and posts nothing,
so every legitimate request is a `GET` for a static asset. But that is a claim about a client, and
the log is written by the server. `scripts/panel_server.py` now applies the rule `deid-serve`
already applied: the query string is discarded, and a path is recorded only when it *matched*
something. The same request now logs:

```
panel_server: 20/Jul/2026 12:24:13 - GET <unmatched> 404
```

Malformed requests log `request rejected before routing` — the stdlib's error path interpolates the
raw request line into its message, and that interpolation is gone.

**One benign artifact.** `up`, `down` and `status` test a port by connecting to it, which is the
only check that behaves the same on macOS and Linux without root. `deid-serve` sees that connect
and logs `route=unread status=400`. Those lines are the port check, not a client error, and they
carry no text.

`logs/` and `.run/` are gitignored. A log file on a machine that processes clinical text is
operational state about one deployment, not a fact about the source tree.

## Where Python comes from

Every Python entry point that imports a THIRD-PARTY package runs `.venv/bin/python`. That is the
set the venv exists for: the eval harness, the red team and the schema tooling all import `yaml`,
and on a shared machine the system `site-packages` is a different set on every login.

Two build-time helpers deliberately use a bare `python3` and are documented in place: the Tauri icon
generator (`justfile:894`) and the capability parser in `tauri-no-network` (`justfile:990`). Both are
stdlib-only, both run before a venv is guaranteed to exist, and neither touches a metric. An earlier
revision of this line claimed "never a bare `python3`", which was simply false; the code was right
and the sentence was not.
`scripts/requirements.txt` pins the exact versions, `just venv` builds and updates it, and `.venv/`
is gitignored. A missing venv produces the setup command and the reason, not a `ModuleNotFoundError`.

This matters more than dependency hygiene usually does: the eval harness *is* the test suite for
model behaviour, so a metric that moves must never have "a different library resolved" among its
candidate explanations. It caught one such case immediately — `mypy --strict eval/` had been passing
on `types-PyYAML` that happened to be installed system-wide on one developer's machine and was a
hard error on a clean one. The stub is now a pinned line in the requirements file.

`just test-airgapped` works inside the venv unchanged: its shim is a pytest plugin injected through
`PYTHONPATH`, which a venv interpreter honours the same as any other. Verified — 111 Python tests
pass with the network shim loaded and zero network operations observed.

`transformers` and `tokenizers` are deliberately **not** in the requirements file. They are imported
lazily by `scripts/gate_tokenizer.py` and `scripts/baseline_incumbent.py`, which are publish-time
tools that reach the network; installing a model downloader into the environment `just
test-airgapped` runs in is exactly the coupling I1 exists to prevent. Both tools print their install
command when you run them on purpose.
