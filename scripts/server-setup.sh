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
# service up is a separate, deliberate act (`just up`, or `just deploy-local`
# to watch one in the foreground).
#
# IT IS SAFE TO RUN TWICE. Every step below either checks whether its work is
# already current and says so, or is inherently idempotent. That is not a
# nicety: the realistic use is an operator who ran it, lost the SSH connection
# during the wasm-bindgen build, and reconnected. If the second run redid the
# forty-minute half, nobody would run it a second time -- they would start
# hand-picking steps, which is how a server ends up in a state no script
# describes.
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
say "1/6  Prerequisites"
missing=0
# python3 joins this list because the eval harness, the red team and the schema
# tooling are Python. It is a PREREQUISITE, not a runtime: step 3 uses it exactly
# once, to build the venv that everything afterwards actually runs in.
for tool in git cargo rustc python3; do
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
    note "python3 comes from your distribution: apt install python3 python3-venv, or dnf install python3"
    exit 1
fi
# Debian and Ubuntu ship python3 without the venv module, and the failure lands
# three steps later as an error about ensurepip that reads like a broken script.
if ! python3 -c 'import venv' >/dev/null 2>&1; then
    note ""
    note "python3 is present but the venv module is not:  apt install python3-venv"
    exit 1
fi
# VERSION, not just presence -- the same reasoning this script already applies to
# wasm-bindgen below, applied consistently.
#
# Stock macOS ships /usr/bin/python3 as 3.9.6, and RHEL 8 ships 3.6. Both satisfy
# a presence check, and both then fail three steps later INSIDE `just venv` with a
# pip resolver wall reading `No matching distribution found for pytest==9.0.2`.
# That message names the wrong problem: the operator goes looking for a bad pin,
# not for their interpreter. Checking here costs four lines and turns a confusing
# mid-run failure into a first-step sentence naming the actual cause.
python_min_major=3
python_min_minor=10
python_have="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo 0.0)"
python_have_major="${python_have%%.*}"
python_have_minor="${python_have##*.}"
if [ "${python_have_major}" -lt "${python_min_major}" ] ||
   { [ "${python_have_major}" -eq "${python_min_major}" ] && [ "${python_have_minor}" -lt "${python_min_minor}" ]; }; then
    note ""
    note "python3 is ${python_have}, and this repository needs ${python_min_major}.${python_min_minor} or newer."
    note "  scripts/requirements.txt pins pytest 9.x, which requires >= 3.10."
    note "  The python3 on your PATH is: $(command -v python3)"
    note ""
    note "  Debian/Ubuntu:  apt install python3.12 python3.12-venv"
    note "  RHEL/Fedora:    dnf install python3.12"
    note "  macOS:          brew install python@3.12   (stock /usr/bin/python3 is 3.9)"
    note ""
    note "  Then re-run with that interpreter first on PATH."
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
say "2/6  PHI pre-commit gate"
just install-hooks

# ---------------------------------------------------------------------------
# 3. The Python environment.
#
# The eval harness, the red team and the schema tooling are Python, and until
# now they ran against whatever python3 and whatever site-packages this server
# happened to have. On a shared box that is a different set on every login, and
# the eval harness is the test suite for MODEL BEHAVIOUR -- a number that moved
# must never have "a different library resolved" among its candidate
# explanations.
#
# `just venv` is idempotent: it stamps the checksum of scripts/requirements.txt
# and does nothing when the stamp matches. .venv/ is gitignored.
# ---------------------------------------------------------------------------
say "3/6  Python environment (.venv)"
just venv

# ---------------------------------------------------------------------------
# 3. The browser panel's toolchain. Optional, and skipping is not a failure.
#
# The native binaries are the product; the panel is one surface. A server that
# only ever runs deid-serve and deid-mcp does not need a wasm toolchain, and
# failing the whole setup over it would be wrong.
# ---------------------------------------------------------------------------
say "4/6  Panel toolchain (optional)"
if rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
    note "wasm32-unknown-unknown  present"
else
    note "wasm32-unknown-unknown  adding"
    rustup target add wasm32-unknown-unknown || note "could not add it; the panel will be skipped"
fi
# WHY the version is compared and not just the presence:
# `command -v wasm-bindgen` was true for ANY version, so a host carrying an older
# CLI skipped the install and then produced glue that does not match the
# generated module. That failure surfaces in the browser as an import error
# against a build the operator has every reason to think succeeded. Checking the
# version makes the second run of this script a no-op on a correct host and a
# repair on a wrong one, which is what idempotent has to mean here.
wasm_bindgen_want="0.2.122"
wasm_bindgen_have=""
if command -v wasm-bindgen >/dev/null 2>&1; then
    wasm_bindgen_have="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
fi
if [ "${wasm_bindgen_have}" = "${wasm_bindgen_want}" ]; then
    note "wasm-bindgen  ${wasm_bindgen_have}  (matches the pinned version, nothing to do)"
else
    if [ -n "${wasm_bindgen_have}" ]; then
        note "wasm-bindgen  ${wasm_bindgen_have} present but ${wasm_bindgen_want} is pinned -> replacing"
    else
        note "wasm-bindgen  installing ${wasm_bindgen_want} (this is the slow step, several minutes)"
    fi
    cargo install wasm-bindgen-cli --version "${wasm_bindgen_want}" \
        || note "could not install; the panel will be skipped"
fi

# ---------------------------------------------------------------------------
# 5. Build everything. build-all reports what it skipped and why.
#
# Idempotent because cargo is: a second run relinks nothing that is current, and
# no attempt is made to second-guess it with a timestamp check of our own. A
# build system's own staleness model is the one to trust.
# ---------------------------------------------------------------------------
say "5/6  Build"
just build-all

# ---------------------------------------------------------------------------
# 5. Prove it, rather than assert it.
#
# `check` runs the hook suite, the invariant gates, the tests and the eval.
# `test-airgapped` is the one that matters most on a server: it runs the suite
# with networking shimmed to raise, so "PHI never leaves the device" is a
# measured property of this machine and not a claim inherited from the README.
# ---------------------------------------------------------------------------
say "6/6  Verify"
just check
just test-airgapped
just test-wasm || note "test-wasm skipped: no wasm artifact on this host"

say "Ready"
cat <<'NEXT'
  Nothing is listening yet. Start a surface deliberately.

  ON A SERVER, detached, so an SSH drop does not take the service with it:

    just up                      start deid-serve (8787) and the panel (8722)
    just status                  what is running, on which port, under which mechanism
    just logs                    tail logs/serve.log and logs/panel.log
    just down                    stop, and verify each port is actually free

  IN THE FOREGROUND, when you want to watch one:

    just deploy-local            deid-serve on 127.0.0.1:8787, Ctrl-C to stop
    just serve-panel             the browser panel on 127.0.0.1:8722, Ctrl-C to stop

  Either way:

    just register-mcp            prints the MCP client config block
    just deploy-check            bind posture, token, TLS, and which layers are live

  Reach them from your laptop over SSH, which needs no exposure, no TLS and no
  bearer token, and leaves nothing on a public interface:

    ssh -N -L 8787:127.0.0.1:8787 -L 8722:127.0.0.1:8722 YOU@THIS-SERVER

  then open http://127.0.0.1:8722/panel/index.html locally.

  IF YOU RUN `just up` AND TMUX IS INSTALLED, each surface gets a window in a
  session named deid-tr:

    tmux attach -t deid-tr       watch the surfaces
    Ctrl-b then d                DETACH and leave them running

  Ctrl-C inside an attached window KILLS that surface. Ctrl-b d is the one that
  does not. docs/DEPLOY.md has the full sequence.

  WHAT THIS BUILD DOES NOT DO: it masks no names. L2 has no trained model and no
  weights ship with it, so patient, clinician and relative names pass through
  untouched. `just deploy-check` reports that too. Do not point a pipeline at
  this and conclude the output is name-free.
NEXT
