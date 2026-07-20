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

## The disclosure that governs all of this

**This build masks no names.** L2 has no trained model and no weights ship, so `PATIENT_NAME`,
`CLINICIAN_NAME` and `RELATIVE_NAME` pass through untouched. Every recipe above says so in its
own output, and `deploy/BUNDLE_README.md` says so in the first section a downloader reads.

If a change ever makes that untrue, those four places are what have to change with it. If a
change makes it *more* true — a surface that masks less than the text claims — that is the
defect, not a documentation gap.

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
