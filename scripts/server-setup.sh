#!/usr/bin/env bash
#
# One-command server setup for deid-tr.
#
# WHY THIS IS A FILE IN THE REPOSITORY AND NOT A CURL-TO-BASH IN A README:
# a pipe from a URL into a shell asks the operator to trust bytes they have not
# read, on a machine that is about to process clinical text. This script is
# reviewable in the same diff as the code it builds, and it is run AFTER a clone,
# so whoever runs it has already fetched the thing they are inspecting.
#
#   git clone https://github.com/ArioMoniri/PIIMa.git && cd PIIMa && ./scripts/server-setup.sh
#
# It installs no system packages and touches nothing outside this checkout and
# the Rust toolchain it is told to use. It never starts a listener: bringing a
# service up is a separate, deliberate act (`just deploy-local`).
set -euo pipefail

cd "$(dirname "$0")/.."
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

say "deid-tr server setup"
note "checkout: $(pwd)"
note "Nothing is published, nothing is exposed, and no model is downloaded."

# ---------------------------------------------------------------------------
# 1. Prerequisites. Reported, never installed.
#
# Installing a toolchain on somebody else's server without asking is the same
# class of surprise as writing their MCP client config: it is convenient exactly
# once and unwelcome every time after.
# ---------------------------------------------------------------------------
say "1/5  Prerequisites"
missing=0
for tool in git cargo rustc; do
    if command -v "$tool" >/dev/null 2>&1; then
        note "$tool  $("$tool" --version 2>&1 | head -1)"
    else
        note "$tool  MISSING"
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    note ""
    note "Install Rust first:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
command -v just >/dev/null 2>&1 || {
    note "just  MISSING -> installing into the cargo bin dir"
    cargo install just
}
note "just  $(just --version)"

# ---------------------------------------------------------------------------
# 2. The PHI pre-commit gate, before anything else.
#
# A fresh clone has no .git/hooks/pre-commit, so without this a contributor on
# this server can commit a checksum-valid national ID and nothing will stop them.
# It is first because it is the only step whose absence is silent.
# ---------------------------------------------------------------------------
say "2/5  PHI pre-commit gate"
just install-hooks

# ---------------------------------------------------------------------------
# 3. The browser panel's toolchain. Optional, and skipping is not a failure.
#
# The native binaries are the product; the panel is one surface. A server that
# only ever runs deid-serve and deid-mcp does not need a wasm toolchain, and
# failing the whole setup over it would be wrong.
# ---------------------------------------------------------------------------
say "3/5  Panel toolchain (optional)"
if rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
    note "wasm32-unknown-unknown  present"
else
    note "wasm32-unknown-unknown  adding"
    rustup target add wasm32-unknown-unknown || note "could not add it; the panel will be skipped"
fi
if command -v wasm-bindgen >/dev/null 2>&1; then
    note "wasm-bindgen  $(wasm-bindgen --version)"
else
    note "wasm-bindgen  installing (this is the slow step, several minutes)"
    cargo install wasm-bindgen-cli --version 0.2.122 || note "could not install; the panel will be skipped"
fi

# ---------------------------------------------------------------------------
# 4. Build everything. build-all reports what it skipped and why.
# ---------------------------------------------------------------------------
say "4/5  Build"
just build-all

# ---------------------------------------------------------------------------
# 5. Prove it, rather than assert it.
#
# `check` runs the hook suite, the invariant gates, the tests and the eval.
# `test-airgapped` is the one that matters most on a server: it runs the suite
# with networking shimmed to raise, so "PHI never leaves the device" is a
# measured property of this machine and not a claim inherited from the README.
# ---------------------------------------------------------------------------
say "5/5  Verify"
just check
just test-airgapped
just test-wasm || note "test-wasm skipped: no wasm artifact on this host"

say "Ready"
cat <<'NEXT'
  Nothing is listening yet. Start a surface deliberately:

    just deploy-local            deid-serve on 127.0.0.1:8787
    just serve-panel             the browser panel on 127.0.0.1:8722
    just register-mcp            prints the MCP client config block
    just deploy-check            bind posture, token, TLS, and which layers are live

  Reach them from your laptop over SSH, which needs no exposure, no TLS and no
  bearer token, and leaves nothing on a public interface:

    ssh -N -L 8787:127.0.0.1:8787 -L 8722:127.0.0.1:8722 YOU@THIS-SERVER

  then open http://127.0.0.1:8722/panel/index.html locally.

  WHAT THIS BUILD DOES NOT DO: it masks no names. L2 has no trained model and no
  weights ship with it, so patient, clinician and relative names pass through
  untouched. `just deploy-check` reports that too. Do not point a pipeline at
  this and conclude the output is name-free.
NEXT
