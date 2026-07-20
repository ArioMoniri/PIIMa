# deid-tr command surface.
#
# WHY every command lives here: if a command is not in the justfile it does not exist. A build
# step that only lives in someone's shell history is a step that silently stops running, and in
# a PHI pipeline the steps that stop running are the gates.

set shell := ["bash", "-uc"]

# WHY every Python entry point below goes through .venv/bin and not `python3`:
# on a shared server `python3` is whichever interpreter the last person put on
# PATH, and its site-packages is whatever the last person pip-installed --user.
# The eval harness IS the test suite for model behaviour, so a metric that moved
# must never have "a different library resolved" as a candidate explanation. The
# venv makes the interpreter part of the checkout. `just venv` builds it,
# scripts/requirements.txt pins it, .gitignore excludes it, and `_venv` below
# turns a missing one into a sentence instead of a ModuleNotFoundError.
venv_dir := ".venv"
python := ".venv/bin/python"
ruff := ".venv/bin/ruff"
mypy := ".venv/bin/mypy"
requirements := "scripts/requirements.txt"
airgap_dir := ".airgap"
dist_dir := "dist"

# Where the detached surfaces keep their pidfiles and their logs. Both are
# gitignored: a pidfile is machine state and a log is operational output, and
# neither is a fact about the source tree.
run_dir := ".run"
log_dir := "logs"

# The three shippable native binaries, and the cargo packages that produce them. Kept in one
# place because `build-all`, `package` and `install` must agree on what "every artifact" means;
# three separate lists is three chances for one of them to quietly ship two of the three.
bins := "deid deid-mcp deid-serve"
bin_pkgs := "-p deid-tr-cli -p deid-tr-mcp -p deid-tr-service"

# List every recipe. Entry point for anyone new to the repo.
default:
    @just --list

# Create or update the Python environment every Python recipe here runs in.
#
# WHY IDEMPOTENT VIA A STAMP AND NOT VIA `pip install` BEING CHEAP: pip with
# everything already satisfied still resolves, which on a server with no route to
# an index is not a no-op, it is a two-minute timeout. The stamp records the
# checksum of scripts/requirements.txt that was last installed successfully; a
# matching stamp means this recipe does nothing and says so. Editing the
# requirements file changes the checksum, which is what makes the stamp honest
# rather than merely fast.
#
# WHY `uv` IS USED WHEN PRESENT: it is an order of magnitude faster and resolves
# the same pins. It is preferred, never required -- a recipe that needs a tool
# the operator has not got is a recipe that does not run.
#
# Create or update .venv from scripts/requirements.txt. Idempotent.
venv:
    #!/usr/bin/env bash
    set -euo pipefail
    stamp="{{venv_dir}}/.requirements.sha256"
    want="$(shasum -a 256 "{{requirements}}" 2>/dev/null || sha256sum "{{requirements}}")"
    want="${want%% *}"
    if [ -x "{{python}}" ] && [ -f "${stamp}" ] && [ "$(cat "${stamp}")" = "${want}" ]; then
        echo "venv: current ({{python}}, {{requirements}} unchanged since last install)"
        exit 0
    fi
    if [ ! -x "{{python}}" ]; then
        # python3 is used HERE and only here: bootstrapping the venv is the one
        # step that cannot already be inside it.
        if ! command -v python3 >/dev/null 2>&1; then
            echo "venv: FAIL - python3 is not installed, so no environment can be created." >&2
            exit 1
        fi
        echo "venv: creating {{venv_dir}} with $(python3 --version)"
        if command -v uv >/dev/null 2>&1; then
            uv venv "{{venv_dir}}"
        else
            python3 -m venv "{{venv_dir}}"
        fi
    fi
    echo "venv: installing {{requirements}}"
    if command -v uv >/dev/null 2>&1; then
        VIRTUAL_ENV="{{venv_dir}}" uv pip install --python "{{python}}" -r "{{requirements}}"
    else
        "{{python}}" -m pip install --quiet --upgrade pip
        "{{python}}" -m pip install -r "{{requirements}}"
    fi
    echo "${want}" > "${stamp}"
    echo "venv: OK - {{python}}"
    "{{python}}" -c 'import sys; print("venv: interpreter", sys.version.split()[0], "at", sys.executable)'

# Assert the venv exists, and turn its absence into a sentence.
#
# WHY a private guard recipe rather than letting the interpreter path fail:
# `.venv/bin/python: No such file or directory` and `ModuleNotFoundError: No
# module named 'yaml'` are both true and neither tells an operator what to type.
# This is a dependency of every Python-running recipe in this file, so the answer
# arrives before the failure does.
_venv:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -x "{{python}}" ]; then
        echo "This repository runs Python out of {{venv_dir}}, which does not exist here." >&2
        echo "  create it with:   just venv" >&2
        echo "  or run full setup: ./scripts/server-setup.sh" >&2
        echo "" >&2
        echo "  WHY not the system python3: on a shared machine its site-packages is a" >&2
        echo "  different set on every login, and the eval harness is the test suite for" >&2
        echo "  model behaviour. A moving library set is a moving metric." >&2
        exit 1
    fi

# The Definition of Done gate. Nothing merges that does not pass this.
#
# WHY verify-hooks and test-hooks come first: they are the cheapest recipes here and they gate
# the gates. A fresh clone has no .git/hooks/pre-commit, so without verify-hooks the PHI
# pre-commit scan silently does not run; and a guard whose own tests are not in `check` rots
# into a guard that passes everything.
check: _venv verify-hooks test-hooks core-no-socket mcp-no-socket fmt lint test drift-check eval
    @echo "check: OK"

# I1, structurally: nothing in core/'s RESOLVED dependency graph can open a socket.
#
# WHY this recipe exists alongside the hook: guard_invariants.sh bans network crates by NAME, and
# a name enumeration only ever covers the clients someone thought of. minreq, ehttp, async-std and
# smol all walked into core/ past that list, and `hyper-util` walked past it by adding a hyphen.
# The enumeration in the edit-time guard is a speed bump that gives fast feedback; THIS is the
# gate, because it reads what cargo actually resolved rather than what a regex guessed - including
# every TRANSITIVE dependency, which no edit-time guard can see at all. A crate pulled in three
# levels down by something innocuous is exactly the shape the hook is structurally blind to.
#
# `--edges normal` excludes dev- and build-dependencies on purpose: a test-only or build-script
# dependency is not linked into the library that touches PHI. The `std::net` check is separate
# because std needs no dependency edge - `use std::net::TcpStream` is a socket with an empty
# dependency list.
core-no-socket:
    #!/usr/bin/env bash
    set -uo pipefail
    # Crates that open a socket, terminate TLS, or exist to drive one that does. Kept in sync with
    # net_crate in scripts/hooks/guard_invariants.sh - the two lists have the same job at
    # different times, and a name in one and not the other is a hole in whichever lacks it.
    socket_crates='^(reqwest|ureq|hyper|hyper-util|h2|h3|tonic|isahc|curl|curl-sys|surf|attohttpc|awc|minreq|ehttp|http-req|async-std|smol|async-io|polling|tungstenite|tokio-tungstenite|quinn|socket2|mio|websocket|actix-web|axum|warp|rocket|tiny_http|trust-dns-resolver|hickory-resolver|native-tls|openssl|rustls|ureq-proto)$'
    if ! command -v cargo >/dev/null 2>&1; then
        echo "core-no-socket: FAIL - cargo is not installed, so the resolved dependency graph" >&2
        echo "  cannot be inspected. This check fails CLOSED: an uninspected graph is not a" >&2
        echo "  clean one, and I1 is the invariant the whole product rests on." >&2
        exit 1
    fi
    tree="$(cargo tree -p deid-tr-core --edges normal --prefix none --no-dedupe 2>/dev/null)" || {
        echo "core-no-socket: FAIL - 'cargo tree -p deid-tr-core' did not resolve." >&2
        exit 1
    }
    # Field 1 is the crate name; the version and any path suffix follow.
    hits="$(printf '%s\n' "$tree" | awk '{ print $1 }' | sort -u | grep -E "$socket_crates" || true)"
    if [ -n "$hits" ]; then
        echo "core-no-socket: FAIL - I1 violated. core/ resolves these socket-capable crates:" >&2
        printf '  %s\n' $hits >&2
        echo "  core/ is pure: rules, checksums, span algebra, surrogates, audit. PHI never" >&2
        echo "  leaves the device, so the crate that touches PHI must be structurally incapable" >&2
        echo "  of sending it. Move the I/O to bindings/, behind a trait core/ defines." >&2
        echo "  If the crate arrived TRANSITIVELY, the direct dependency that pulled it in is" >&2
        echo "  the one to remove or feature-gate - run: cargo tree -p deid-tr-core -i <crate>" >&2
        exit 1
    fi
    # std::net needs no dependency edge, so the graph check above cannot see it.
    net_use="$(grep -rnE '(^|[^a-zA-Z0-9_])std::net(::|[^a-zA-Z0-9_])' core/src --include='*.rs' \
        | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|/\*|\*)' || true)"
    if [ -n "$net_use" ]; then
        echo "core-no-socket: FAIL - I1 violated. core/ imports std::net:" >&2
        printf '%s\n' "$net_use" >&2
        echo "  std::net is a socket with an empty dependency list. Put it in bindings/." >&2
        exit 1
    fi
    echo "core-no-socket: OK (resolved graph clean, no std::net in core/src)"

# Refuse to proceed if this clone's pre-commit hook is missing or stale.
#
# WHY assert rather than auto-install: silently installing an executable into .git on someone
# else's machine is a surprise. Failing loudly with the one command that fixes it is not.
verify-hooks:
    #!/usr/bin/env bash
    set -euo pipefail
    src="scripts/hooks/pre_commit_phi.sh"
    dst=".git/hooks/pre-commit"
    fix="run: just install-hooks"
    if [ ! -f "$src" ]; then
        echo "verify-hooks: FAIL - $src is missing; the PHI gate has no body." >&2
        exit 1
    fi
    if [ ! -e "$dst" ]; then
        echo "verify-hooks: FAIL - $dst does not exist." >&2
        echo "  This clone would commit with NO checksum-valid-TCKN scan (I8). ${fix}" >&2
        exit 1
    fi
    if [ ! -x "$dst" ]; then
        echo "verify-hooks: FAIL - $dst is not executable, so git silently skips it. ${fix}" >&2
        exit 1
    fi
    # A symlink install tracks edits automatically; a copy install goes stale, which is the
    # failure mode this comparison exists to catch.
    if [ -L "$dst" ]; then
        method="symlink"
    else
        method="copy"
    fi
    if ! cmp -s "$src" "$dst"; then
        echo "verify-hooks: FAIL - $dst does not match $src (install method: ${method})." >&2
        echo "  The installed hook is stale, so the guarantees in the source are not the" >&2
        echo "  guarantees being enforced. ${fix}" >&2
        exit 1
    fi
    echo "verify-hooks: OK (${method}, matches ${src})"

# Exercise every PreToolUse guard against its known bypasses.
test-hooks:
    ./scripts/hooks/test_hooks.sh

# WHY: formatting is not taste - a stable format keeps diffs reviewable, and a reviewable
# diff is how a PHI leak gets caught by a human.
# Format Rust and Python sources.
fmt: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f core/Cargo.toml ] || [ -f Cargo.toml ]; then
        cargo fmt --all
    else
        echo "fmt: no Cargo.toml yet, skipping cargo fmt"
    fi
    # The venv's ruff, not PATH's. A formatter whose version varies by login
    # reformats the tree on alternate days and every diff carries the churn.
    "{{ruff}}" format eval/ tests/ scripts/

# WHY -D warnings: a warning nobody fixes is a warning nobody reads.
# Lint Rust and Python, warnings fatal.
lint: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f core/Cargo.toml ] || [ -f Cargo.toml ]; then
        cargo clippy --all-targets -- -D warnings
    else
        echo "lint: no Cargo.toml yet, skipping cargo clippy"
    fi
    # WHY these no longer skip when the tool is absent: they used to print
    # "not installed, skipping" and exit 0, which made `just check` green on a
    # machine where two of its gates did not run. The venv is now a hard
    # prerequisite of this recipe (`_venv`), so absence is a setup error with a
    # fix attached rather than a gate quietly turning itself off.
    "{{ruff}}" check eval/ tests/
    "{{mypy}}" --strict eval/

# Run the deterministic test suite (TDD layer A) in both languages.
test: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f core/Cargo.toml ] || [ -f Cargo.toml ]; then
        cargo test --all
    else
        echo "test: no Cargo.toml yet, skipping cargo test"
    fi
    # eval/redteam/tests/ lives beside the module it tests rather than under tests/, so it
    # is named explicitly here. A red team whose own tests are not in `just check` is a
    # measuring instrument nobody is calibrating.
    {{python}} -m pytest tests/ eval/redteam/tests/ -q

# The eval harness IS the test suite for model behaviour (TDD layer B). Reports only.
eval: _venv
    {{python}} eval/run.py --detector null --out eval/results/latest.json
    {{python}} eval/report.py eval/results/latest.json

# Produce a COMMITTABLE eval artifact and print the command a human runs to commit it.
#
# WHY this recipe has to exist: `just eval` writes eval/results/latest.json, and latest.json is
# gitignored on purpose - it is a mutable pointer overwritten on every run, and committing a
# moving file would make eval_sha meaningless. But I5 requires a COMMITTED run: a model card may
# only cite an eval_sha that exists in git history. Without this recipe the default developer
# path structurally cannot produce a publishable artifact, and the gap gets discovered at
# publish time by whoever is trying to ship.
#
# WHY it does not run git itself: committing is an assertion by a human that these numbers are
# the ones they mean to stand behind. A recipe that commits on their behalf turns provenance
# into automation, which is the exact decoupling D-003 exists to prevent. It prints the command
# and stops.
eval-commit: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    run_id="$(date -u +%Y%m%dT%H%M%SZ)-null"
    out="eval/results/${run_id}.json"
    if [ -e "${out}" ]; then
        echo "eval-commit: ${out} already exists; refusing to overwrite a run artifact" >&2
        exit 1
    fi
    {{python}} eval/run.py --detector null --run-id "${run_id}" --out "${out}"
    echo
    echo "=============================================================================="
    echo "COMMITTABLE ARTIFACT WRITTEN"
    echo "=============================================================================="
    echo "  ${out}"
    echo
    echo "This path is NOT gitignored (only eval/results/latest.json is), so it can carry"
    echo "provenance for a model card (I5)."
    echo
    echo "NOTE: eval_sha inside the artifact reads 'uncommitted' whenever the working tree"
    echo "is dirty at the moment of the run. Commit your source changes FIRST, re-run this"
    echo "recipe, and only then commit the artifact - otherwise the run cannot be tied to"
    echo "a tree state and scripts/publish.py must refuse it."
    echo
    echo "Run this yourself when you are ready. This recipe never runs git:"
    echo
    echo "    git add ${out} && git commit -m \"eval(m0): committed null-detector run ${run_id}\""
    echo

# WHY separate from `eval`: during development you want to see the numbers even when they are
# bad; in CI a failed gate must be fatal.
# Run the eval and exit non-zero on any failed release gate.
eval-gates: _venv
    {{python}} eval/run.py --detector null --out eval/results/latest.json
    {{python}} eval/report.py eval/results/latest.json --gates

# WHY it is safe to re-run: the golden set is append-only (I7). This regenerates derived
# artifacts only; it never deletes or weakens a fixture.
# Rebuild the golden set.
build-gold: _venv
    {{python}} eval/build_gold.py

# Proves I1: zero network syscalls during the core test suite.
#
# WHY an in-process shim rather than a sandbox flag: there is no `unshare` on macOS, and a gate
# that only works on the CI box is a gate the developer never runs. The shim denies connect,
# create_connection, name resolution and urllib, so a network attempt fails the suite loudly and
# names the call site instead of hanging on a timeout. On Linux we additionally drop the network
# namespace, which proves the stronger property at the kernel level. The Rust side is covered
# statically: no HTTP client may appear anywhere in core/'s dependency graph.
#
# WHY the shim is a pytest plugin and not sitecustomize.py: a file named sitecustomize.py on
# PYTHONPATH shadows the interpreter's own, which on some installs is what puts site-packages on
# sys.path - the suite then fails to import its dependencies and the gate looks broken.
# Run the test suite with networking disabled and prove zero network syscalls (I1).
test-airgapped: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{airgap_dir}}"
    cat > "{{airgap_dir}}/airgap_guard.py" <<'PYEOF'
    """Air-gap shim: makes any network use raise, loudly, inside the test process."""

    import socket

    # urllib is imported before anything is patched because http.client captures socket
    # internals at import time; patching first makes the stdlib itself fail to import, which
    # would look like a broken shim rather than a caught violation.
    import urllib.request


    class NetworkAccessDenied(RuntimeError):
        pass


    def _deny(*_args, **_kwargs):
        raise NetworkAccessDenied(
            "I1 violation: the test suite attempted a network operation. "
            "core/ must have no network dependency and must never fetch weights at inference."
        )


    _RealSocket = socket.socket


    class _DeniedSocket(_RealSocket):
        # Subclassed rather than replaced outright because pytest and multiprocessing
        # legitimately create local socket pairs. Only the operations that reach the network
        # are denied, so the gate cannot be dismissed as flaky.
        def connect(self, *_a, **_k):
            _deny()

        def connect_ex(self, *_a, **_k):
            _deny()


    socket.socket = _DeniedSocket
    socket.create_connection = _deny
    socket.getaddrinfo = _deny
    socket.gethostbyname = _deny
    urllib.request.urlopen = _deny
    urllib.request.urlretrieve = _deny
    PYEOF
    mechanism="python-plugin-shim"
    if [ "$(uname -s)" = "Linux" ] && command -v unshare >/dev/null 2>&1; then
        mechanism="unshare -rn + python-plugin-shim"
    fi
    echo "test-airgapped: mechanism = ${mechanism}"
    if [ -f core/Cargo.toml ]; then
        if cargo tree --manifest-path core/Cargo.toml 2>/dev/null | grep -qE '(reqwest|ureq|hyper|tonic|isahc|curl) v[0-9]'; then
            echo "test-airgapped: FAIL - core/ dependency graph contains an HTTP client (I1)" >&2
            exit 1
        fi
        echo "test-airgapped: core/ dependency graph is free of HTTP clients"
    fi
    suite="PYTHONPATH={{airgap_dir}}:${PYTHONPATH:-} DEID_AIRGAPPED=1 {{python}} -m pytest tests/ -q -p airgap_guard"
    if [ "${mechanism}" = "unshare -rn + python-plugin-shim" ]; then
        unshare -rn bash -c "${suite}"
    else
        bash -c "${suite}"
    fi
    if [ -f core/Cargo.toml ] || [ -f Cargo.toml ]; then
        DEID_AIRGAPPED=1 cargo test --all
    fi
    echo "test-airgapped: OK - zero network operations observed (${mechanism})"

# WHY: no backbone ships for Turkish unless its tokenizer round-trips code-switched medical
# terms carrying Turkish morphology (carcinoma'li, MRI'da).
# Run the I6 backbone/language tokenizer gate.
gate-tokenizer: _venv
    {{python}} scripts/gate_tokenizer.py

# WHY it runs the PIPELINE masker: this recipe answers "what does the real product leak", and
# only that question has a gate behind it. It used to run the ORACLE masker, which is a
# gold-derived perfect masker, and eval/harness.py read the resulting file whatever detector it
# was scoring - so 0.0303 PASS appeared identically under the null detector and the real
# pipeline. See D-029.
#
# The reference maskers remain and remain valuable: `--masker null`, `--masker leaky` and
# `--masker oracle` bracket the instrument and are asserted in
# eval/redteam/tests/test_runner.py, because a red team that cannot detect total failure cannot
# validate success. Their reports carry the number under `calibration` and leave the gate
# explicitly WITHHELD.
#
# WHY it does not enforce by default: `just check` does not run this recipe, and a report-only
# default keeps the recipe usable for investigation. `just red-team-gates` is the enforcing
# form. The report lands at eval/results/redteam.json, which is where eval/harness.py reads
# `contextual.reid_rate` from; with no report - or with a report whose masker, detector or
# eval_sha does not match the run being scored - that field stays null, because neither the
# absence of a red-team run nor somebody else's red-team run is a passing score.
#
# L6 validates L3 by trying to re-identify our own output. Eval only, never in the masking path.
red-team: _venv
    {{python}} -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json

# Enforcing form: exit non-zero when the contextual re-ID rate exceeds thresholds.yaml's
# contextual.reid_rate_max (D-008, <= 5%).
red-team-gates: _venv
    {{python}} -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json --gate

# The calibration sweep: all three reference maskers, so the three reference points that prove
# the red team discriminates are reproducible in one command. None of these writes
# eval/results/redteam.json, because none of their numbers may reach the gate.
red-team-calibrate: _venv
    {{python}} -m eval.redteam.runner --masker null   --out eval/results/redteam-calibration-null.json
    {{python}} -m eval.redteam.runner --masker leaky  --out eval/results/redteam-calibration-leaky.json
    {{python}} -m eval.redteam.runner --masker oracle --out eval/results/redteam-calibration-oracle.json

# Run the red team and write every successful attack back as a NEW adversarial fixture file.
# WHY a separate recipe: emission mutates eval/adversarial/, and I7 makes the golden set
# append-only, so growing it is a deliberate act rather than a side effect of looking at a
# number. The writer never opens a committed fixture file - it creates one named for the run.
red-team-emit: _venv
    {{python}} -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json --emit-fixtures

# WHY it refuses by default: publication is irreversible and a card must be a build artifact
# generated from a committed eval run (I5). This recipe never pushes anything.
# Refuse to publish until preflight exists.
publish:
    @echo "publish: refused - preflight not implemented."
    @echo "  Required before this recipe does anything: gate-tokenizer green (I6),"
    @echo "  eval-gates green, card generated by scripts/publish.py from a committed"
    @echo "  eval/results/<run_id>.json, and explicit human approval in-session."
    @exit 1

# Install the pre-commit PHI hook into this clone (.git/hooks is not versioned).
# ---------------------------------------------------------------------------
# M2 - the stdio MCP gateway (bindings/mcp).
# ---------------------------------------------------------------------------

# Build the gateway binary.
#
# WHY release and not debug: this is the binary an MCP client is told to launch, so the path a
# human copies into a client config should be the one they will keep using. A debug binary in a
# client config is a debug binary in production three weeks later.
mcp-build:
    cargo build --release -p deid-tr-mcp
    @echo
    @echo "deid-mcp built. Register it with an MCP client using the ABSOLUTE path:"
    @echo "    $(pwd)/target/release/deid-mcp"
    @echo "See bindings/mcp/README.md for the client configuration."

# Run the gateway in the foreground, reading JSON-RPC from this terminal's stdin.
#
# WHY this is useful despite being awkward to type into: it is the fastest way to confirm the
# binary starts, speaks the protocol, and reports its retention policy. Paste one line, get one
# line. An MCP client failing to start a server gives almost no diagnostic, so having a way to
# talk to it by hand is what turns "the client says it failed" into an actual error message.
mcp-run *ARGS:
    @echo "deid-mcp: reading newline-delimited JSON-RPC on stdin. Ctrl-D to exit." >&2
    @echo '  try: {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":{}}}' >&2
    cargo run --release -p deid-tr-mcp -- {{ARGS}}

# One-shot smoke test: ask the built gateway for its health and print the answer.
#
# WHY it exists next to `mcp-run`: the interactive recipe needs a human to paste a line, so it
# is not something CI or a bisect can use. This one is scriptable and answers the only question
# that matters after a build - does the binary start and does it report that it is not listening.
mcp-health:
    #!/usr/bin/env bash
    set -euo pipefail
    request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":{}}}'
    printf '%s\n' "$request" | cargo run --quiet --release -p deid-tr-mcp -- --quiet

# The gateway's own gate: format, lint, and every test in the crate.
mcp-check: mcp-no-socket
    cargo fmt --all -- --check
    cargo clippy -p deid-tr-mcp --all-targets -- -D warnings
    cargo test -p deid-tr-mcp

# I3, structurally: nothing in the gateway's RESOLVED dependency graph can open a socket.
#
# WHY this exists alongside bindings/mcp/tests/no_listener.rs, which checks the same invariant:
# the test reads SOURCE FILES and the DECLARED dependency table, so it can see
# `use std::net::TcpListener` (which has no dependency edge at all) but is structurally blind to
# a socket crate pulled in three levels down by something innocuous. This recipe reads what
# cargo actually resolved, including every transitive edge, and is blind to std::net. Neither
# check subsumes the other, which is why both run.
#
# This is the same reasoning core-no-socket records, applied to the OTHER crate that must never
# open a socket. The gateway holds the span map - the mapping from surrogate back to real PHI -
# and it is only safe to hold it because it cannot transmit it. `--edges normal` excludes dev-
# and build-dependencies, which are not linked into the shipped binary.
mcp-no-socket:
    #!/usr/bin/env bash
    set -uo pipefail
    # Kept in sync with core-no-socket above and with SOCKET_CRATES in
    # bindings/mcp/tests/no_listener.rs. A name in one list and not the others is a hole in
    # whichever lacks it.
    socket_crates='^(reqwest|ureq|hyper|hyper-util|h2|h3|tonic|isahc|curl|curl-sys|surf|attohttpc|awc|minreq|ehttp|http-req|async-std|smol|async-io|polling|tungstenite|tokio-tungstenite|quinn|socket2|mio|websocket|actix-web|axum|warp|rocket|tiny_http|trust-dns-resolver|hickory-resolver|native-tls|openssl|rustls|ureq-proto)$'
    if ! command -v cargo >/dev/null 2>&1; then
        echo "mcp-no-socket: FAIL - cargo is not installed, so the resolved dependency graph" >&2
        echo "  cannot be inspected. This check fails CLOSED." >&2
        exit 1
    fi
    tree="$(cargo tree -p deid-tr-mcp --edges normal --prefix none --no-dedupe 2>/dev/null)" || {
        echo "mcp-no-socket: FAIL - 'cargo tree -p deid-tr-mcp' did not resolve." >&2
        exit 1
    }
    hits="$(printf '%s\n' "$tree" | awk '{ print $1 }' | sort -u | grep -E "$socket_crates" || true)"
    if [ -n "$hits" ]; then
        echo "mcp-no-socket: FAIL - I3/I1 violated. The MCP gateway resolves these" >&2
        echo "  socket-capable crates:" >&2
        printf '  %s\n' $hits >&2
        echo "  The gateway never speaks to the cloud model - the MCP CLIENT does. That split" >&2
        echo "  is what makes it safe for this process to hold the span map, which is the" >&2
        echo "  literal mapping from surrogate back to real patient identifiers. A gateway" >&2
        echo "  that can open a socket is a gateway that can exfiltrate that table." >&2
        echo "  If the crate arrived TRANSITIVELY, run: cargo tree -p deid-tr-mcp -i <crate>" >&2
        exit 1
    fi
    echo "mcp-no-socket: OK (resolved graph clean, stdio transport only)"

install-hooks:
    ./scripts/hooks/install.sh

# WHY never automatic: a lazy download at inference time is a network call on a machine
# holding PHI (I1). Fetching is an explicit, checksummed, human-run step.
# Placeholder for the explicit weight fetch.
pull:
    @echo "pull: not implemented until M6."
    @echo "  Contract: explicit fetch with a progress bar and a printed checksum;"
    @echo "  air-gapped hosts use 'deid pull --from ./bundle'. Never automatic, never at inference."

# WHY this recipe exists: eval/allowlist/*.txt was 1813 lines of curated medical
# vocabulary that nothing in eval/, scripts/ or this file ever read, so it drifted
# from the fixtures unnoticed for as long as it existed. Two artifacts nobody
# compares always drift. This is the comparison.
#
# --strict is what CI should run once the vocabulary is reconciled: a term
# annotated in a fixture but absent from the vocabulary means L4 has no runtime
# reference for it, which is a masked `carcinoma` waiting to happen.
# Report drift between the fixture annotations and eval/allowlist/*.txt.
allowlist-drift *ARGS: _venv
    {{python}} -m eval.allowlist {{ARGS}}

# The enforcing form, wired into `check`. WHY it is a separate recipe: a `just`
# dependency cannot carry arguments, and a drift report that only ever runs in
# reporting mode is the reason eight terms sat unreconciled while the recipe
# exited 0. Residual drift is legal only when eval.allowlist.DRIFT_EXCEPTIONS
# records why.
drift-check: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    {{python}} -m eval.allowlist --strict --examples 40
    echo "drift-check: OK"

# --- bindings: Python (PyO3) and WASM (wasm-bindgen) -------------------------
#
# WHY these are separate recipes and NOT dependencies of `check`: neither can run
# without a toolchain component that is not part of a Rust install. `check` must
# stay green on a fresh clone with nothing but cargo, or it stops being the gate
# and starts being the thing people skip. Each recipe below therefore states
# exactly what is missing and exits non-zero, rather than printing a warning and
# succeeding -- a build step that passes when it did not run is worse than one
# that fails.

# Build the Python extension in-place for development.
#
# `bindings/python` is deliberately OUTSIDE the cargo workspace (see the
# `exclude` block in Cargo.toml): pyo3 is not in the offline registry cache, so
# a workspace member would force a network resolve on every offline build and
# break `just test-airgapped`, which is a release gate. The consequence is that
# the first run of this recipe needs network access to fetch pyo3 once.
#
# Build the Python extension in-place (PyO3 + maturin).
build-python:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v maturin >/dev/null 2>&1; then
        echo "build-python: maturin is not installed." >&2
        echo "  install with: uv tool install maturin   (or: pipx install maturin)" >&2
        echo "  NOT installed automatically: this recipe would otherwise reach the" >&2
        echo "  network on a machine that handles PHI, which is a decision a human makes." >&2
        exit 1
    fi
    cd bindings/python
    # --release because the debug extension is roughly an order of magnitude
    # slower, and L1's budget is ~1ms per note.
    maturin develop --release

# Build a distributable wheel. abi3 means ONE wheel per platform, not one per
# CPython minor version, so there is a single artifact whose provenance a
# hospital has to check.
#
# Build a distributable abi3 wheel.
build-python-wheel:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v maturin >/dev/null 2>&1; then
        echo "build-python-wheel: maturin is not installed (see 'just build-python')." >&2
        exit 1
    fi
    cd bindings/python && maturin build --release --out dist

# Lint, type-check and test the Python binding.
#
# ruff and mypy --strict run against the SOURCE and the STUB, so they are green
# before any extension exists -- that is why the stub is hand-written and why
# mypy_path points at it. pytest needs the compiled module and says so.
#
# Lint (ruff), type-check (mypy --strict) and test the Python binding.
test-python: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    # Resolved to absolute BEFORE the cd: the venv paths in this file are
    # relative to the repository root, and a relative interpreter path after a
    # cd is a "no such file" two directories away from where it was written.
    py="$(pwd)/{{python}}"
    ruff="$(pwd)/{{ruff}}"
    mypy="$(pwd)/{{mypy}}"
    cd bindings/python
    "${ruff}" format --check .
    "${ruff}" check .
    "${mypy}" --strict
    if "${py}" -c "import deid_tr" >/dev/null 2>&1; then
        "${py}" -m pytest tests/ -q
    else
        echo "test-python: the extension is not importable; run 'just build-python' first." >&2
        exit 1
    fi

# Compile core/ plus the binding to wasm32 and generate the JS glue.
#
# TWO targets are built on purpose. `--target web` is what the PWA and the local
# panel load (bindings/wasm/tests/index.html); `--target nodejs` is what the
# no-upload proof runs under, because asserting against networking globals needs
# a host where they can be replaced before the module loads.
#
# Compile core/ to wasm32 and generate the JS glue for web and node.
build-wasm:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
        echo "build-wasm: the wasm32-unknown-unknown target is not installed." >&2
        echo "  install with: rustup target add wasm32-unknown-unknown" >&2
        echo "  NOT installed automatically: adding a toolchain component is a network" >&2
        echo "  operation, and this repository does not run those on someone's behalf." >&2
        exit 1
    fi
    # Either toolchain works. wasm-pack is the convenience wrapper; wasm-bindgen
    # is what it calls underneath. Accepting both matters because requiring the
    # wrapper made this recipe unrunnable on a machine that had the real tool.
    if command -v wasm-pack >/dev/null 2>&1; then
        cd bindings/wasm
        wasm-pack build --release --target web --out-dir pkg-web
        wasm-pack build --release --target nodejs --out-dir pkg
    elif command -v wasm-bindgen >/dev/null 2>&1; then
        cargo build -p deid-tr-wasm --target wasm32-unknown-unknown --release
        mkdir -p bindings/wasm/pkg-web bindings/wasm/pkg
        wasm-bindgen --target web --out-dir bindings/wasm/pkg-web --no-typescript \
            target/wasm32-unknown-unknown/release/deid_tr_wasm.wasm
        wasm-bindgen --target nodejs --out-dir bindings/wasm/pkg --no-typescript \
            target/wasm32-unknown-unknown/release/deid_tr_wasm.wasm
    else
        echo "build-wasm: neither wasm-pack nor wasm-bindgen is installed." >&2
        echo "  install either: cargo install wasm-pack" >&2
        echo "                  cargo install wasm-bindgen-cli" >&2
        exit 1
    fi


# The no-upload proof, and the recipe the product's central claim rests on.
#
# WHY it is a gate and not a README paragraph: "open devtools, watch the network
# tab stay empty" is the reason a hospital installs the browser surface at all.
# A claim that is only ever written down survives every refactor that breaks it.
# The script checks the .wasm import table, greps the generated glue, and then
# runs a full de-identification with every networking global replaced by a
# throwing stub -- three independent checks, because each one alone is escapable.
#
# Prove the browser build uploads nothing.
test-wasm:
    #!/usr/bin/env bash
    set -euo pipefail
    # The host-target unit tests run everywhere and need no wasm toolchain, so
    # they run first and unconditionally: the logic is checked even on a machine
    # that cannot produce a .wasm at all.
    cargo test -p deid-tr-wasm
    if ! command -v node >/dev/null 2>&1; then
        echo "test-wasm: node is not installed; the no-upload proof cannot run." >&2
        exit 1
    fi
    if [ ! -f bindings/wasm/pkg/deid_tr_wasm_bg.wasm ]; then
        echo "test-wasm: no wasm artifact; run 'just build-wasm' first." >&2
        exit 1
    fi
    node bindings/wasm/tests/no_network.mjs

# Serve the real panel: bindings/wasm/panel/.
#
# WHY THIS RECIPE IS NAMED FOR THE PANEL AND POINTS AT THE PANEL: it used to
# serve bindings/wasm/tests/index.html, the stripped-down offline-proof page.
# That page carries no names-not-masked banner and no confidence slider, so the
# one command anybody runs to look at this product showed the weakest surface
# while the honest one was reachable from no recipe at all. On a tool whose
# headline risk is a clinician assuming names were removed, showing the page
# without the disclosure is the defect, not a packaging detail.
#
# The proof page keeps its own recipe below: it is a real artifact — the minimal
# demonstration with nothing else on it to explain a request away.
#
# Serve the full panel on 127.0.0.1: banner, slider and an empty Network tab.
serve-panel: (_serve "panel/index.html")

# Serve the minimal offline-proof page: bindings/wasm/tests/index.html.
#
# Same module, same load sequence, none of the panel's UI: with as little on the
# page as possible, nothing on screen can be blamed for a request.
#
# Serve the minimal offline-proof page on 127.0.0.1.
serve-offline-proof: (_serve "tests/index.html")

# ---------------------------------------------------------------------------
# The React panel: bindings/panel-app/.
#
# WHY THERE ARE TWO PANELS AND BOTH ARE KEPT. The vanilla panel's pitch is that
# you can open six readable files and audit them with no build step. A bundled
# React app cannot make that claim -- what ships is a hashed chunk nobody diffs
# -- and for a tool whose entire argument is auditability that claim has real
# value. The React app is the better product surface: a page-shaped document
# view, a blackout animation that shows the operation happening, shadcn/ui
# controls. The vanilla page is the minimal auditable proof. Neither replaces
# the other, and a change that deletes one to avoid maintaining two has thrown
# away the thing the other one was for.
#
# BOTH LOAD THE SAME WASM MODULE, from pkg-web/. That is what stops them from
# drifting into two products: the pipeline is one artifact and only the surface
# differs.
# ---------------------------------------------------------------------------

# Build the React panel to bindings/panel-app/dist/ and verify it against the CSP.
build-panel-app:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v npm >/dev/null 2>&1; then
        echo "build-panel-app: npm is not installed." >&2
        echo "  install Node 20 or newer (which ships npm), then re-run." >&2
        echo "  NOT installed automatically: adding a toolchain is a network" >&2
        echo "  operation, and this repository does not run those on someone's behalf." >&2
        exit 1
    fi
    cd bindings/panel-app
    # `npm ci` when there is a lockfile: a build that resolves a different
    # dependency tree than the one that was reviewed is not the build that was
    # reviewed, and on a page making a no-network claim the dependency tree is
    # part of the claim.
    if [ -f package-lock.json ]; then npm ci; else npm install; fi
    npm run build
    # NOT OPTIONAL, AND NOT A SEPARATE RECIPE SOMEONE HAS TO REMEMBER. Vite's
    # defaults emit an inline <script> and data: URLs, both of which the panel's
    # CSP refuses. The config switches them off; this asserts that it still
    # does, against the bytes that were actually produced.
    npm run check-csp
    echo
    echo "build-panel-app: bindings/panel-app/dist/"
    du -sh dist | awk '{print "  total: " $1}'
    find dist -type f -exec ls -l {} \; | awk '{printf "  %8d  %s\n", $5, $NF}' | sort -k2
    echo
    echo "This build masks NO NAMES: L2 has no trained model and no weights ship."

# Serve the React panel on 127.0.0.1:8723.
#
# The wasm module is COPIED into dist/pkg-web/ rather than symlinked or served
# from a second root: the app loads ./pkg-web/ relative to its own directory, so
# the served tree has to contain it. A symlink would work here and break inside
# an extracted release bundle, which is the worse place to find out.
serve-panel-app: _venv build-panel-app
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d bindings/wasm/pkg-web ]; then
        echo "serve-panel-app: no web build; run 'just build-wasm' first." >&2
        exit 1
    fi
    rm -rf bindings/panel-app/dist/pkg-web
    mkdir -p bindings/panel-app/dist/pkg-web
    cp bindings/wasm/pkg-web/* bindings/panel-app/dist/pkg-web/
    echo "Ctrl-C to stop."
    # scripts/panel_server.py, NOT an inline heredoc. That module is where I3
    # lives structurally -- HOST is a constant with no flag that changes it -- and
    # a third caller with its own copy of the bind address is a third place for it
    # to drift to 0.0.0.0 while looking identical in `ps`. It also carries the I4
    # request-logging rules, which a two-line SimpleHTTPRequestHandler would not.
    {{python}} scripts/panel_server.py --port 8723 --directory bindings/panel-app/dist

# Run the React panel's test suite (the blackout animation's three rules).
test-panel-app:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v npm >/dev/null 2>&1; then
        echo "test-panel-app: npm is not installed (see 'just build-panel-app')." >&2
        exit 1
    fi
    cd bindings/panel-app
    if [ -f package-lock.json ]; then npm ci; else npm install; fi
    npx tsc -b
    npm test

# The shared server for both pages above. Private: `just serve-panel` is the
# entry point, and a bare page path is not one.
#
# I3: bound to 127.0.0.1 explicitly, never 0.0.0.0 and never "::". This serves a
# page whose whole point is that nothing leaves the machine; listening on a
# routable interface to do it would be its own punchline.
#
# The document root is bindings/wasm rather than the page's own directory,
# because both pages load the module from the sibling ../pkg-web/ and a root at
# the page directory puts that path outside the served tree.
_serve page: _venv
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d bindings/wasm/pkg-web ]; then
        echo "serve: no web build; run 'just build-wasm' first." >&2
        exit 1
    fi
    if [ ! -f "bindings/wasm/{{page}}" ]; then
        echo "serve: bindings/wasm/{{page}} does not exist." >&2
        exit 1
    fi
    echo "open http://127.0.0.1:8722/{{page}} and watch the Network tab"
    echo "Ctrl-C to stop, or run 'just up' to start it detached instead."
    # Delegated to scripts/panel_server.py rather than inlined here, because
    # `just up` starts the same page detached and a second inline copy of the
    # bind address is a second place for it to drift off 127.0.0.1 (I3). One
    # module, one host constant, both callers.
    exec "{{python}}" scripts/panel_server.py \
        --port 8722 --directory bindings/wasm --page "{{page}}"

# ---------------------------------------------------------------------------
# The desktop surface: bindings/tauri.
# ---------------------------------------------------------------------------

# WHY THE TAURI CRATE IS NOT A WORKSPACE MEMBER, restated here because this is
# where somebody will wonder why every recipe below passes --manifest-path:
# Tauri's graph is large and resolving it inside the workspace would put it in
# the ROOT Cargo.lock, which `just core-no-socket` reads and which
# `just test-airgapped` needs to resolve offline. Held out, the workspace lock
# never moves and the desktop build is opt-in. Same reasoning as bindings/python
# and the held-out `ort` dependency; the manifest records it too.

# Build the desktop application (release).
#
# HARD-FAILS on a missing toolchain, unlike the build-all path below, and for
# the reason this file applies everywhere: `just build-tauri` is a recipe
# somebody ran on purpose, so telling them it cannot happen is the useful
# answer. `build-all` skips instead, loudly.
build-tauri: tauri-no-network
    #!/usr/bin/env bash
    set -euo pipefail
    # `python3`, not `{{python}}`: the icon generator imports only zlib and
    # struct, so making it wait on the project virtualenv would add a dependency
    # it does not have. Regenerated on every build so the committed PNG cannot
    # drift from the script that claims to produce it.
    python3 scripts/make_tauri_icon.py >/dev/null
    cargo build --release --manifest-path bindings/tauri/Cargo.toml
    binary="bindings/tauri/target/release/deid-tr-desktop"
    if [ ! -x "${binary}" ]; then
        echo "build-tauri: FAIL - cargo succeeded but ${binary} does not exist." >&2
        echo "  The [[bin]] name in bindings/tauri/Cargo.toml has drifted from this recipe." >&2
        exit 1
    fi
    echo "build-tauri: built ${binary}"
    echo
    echo "This desktop build masks NO NAMES: L2 has no trained model and no weights ship."
    echo "Run it with: ${binary}"
    echo "It is an unbundled executable. No .app, .dmg, .msi or .deb is produced - see"
    echo "bindings/tauri/README.md, 'What is not built'."

# Run the desktop binding's tests. They need no webview.
test-tauri:
    cargo test --manifest-path bindings/tauri/Cargo.toml

# I1 for the desktop surface: prove the shipped app cannot reach a network.
#
# WHY THIS IS A GATE AND NOT A PARAGRAPH. A GUI framework brings a large
# dependency graph and an ambient expectation of auto-update, crash reporting
# and telemetry - all three are network egress from a process that reads
# clinical documents, and all three arrive by default in most desktop stacks.
# The claim "deid-tr desktop runs air-gapped" is only worth anything if
# something checks it on every build, so this recipe runs BEFORE build-tauri
# rather than after, and build-tauri depends on it.
#
# Three independent checks, because each one alone is escapable:
#   1. the RESOLVED dependency graph carries no HTTP client and no TLS stack;
#   2. tauri.conf.json enables no updater and names no remote origin;
#   3. the capability file grants the webview nothing beyond core:default.
tauri-no-network:
    #!/usr/bin/env bash
    set -uo pipefail
    manifest="bindings/tauri/Cargo.toml"
    conf="bindings/tauri/tauri.conf.json"
    caps="bindings/tauri/capabilities/default.json"
    failed=0

    # Kept in sync with core-no-socket's list, minus `tokio`: tauri and rfd use
    # tokio as an executor and it appears in this graph with no net feature
    # enabled. `mio` IS still banned and its absence is what shows tokio's
    # networking is not compiled in - tokio cannot open a socket without it.
    socket_crates='^(reqwest|ureq|hyper|hyper-util|h2|h3|tonic|isahc|curl|curl-sys|surf|attohttpc|awc|minreq|ehttp|http-req|async-std|smol|async-io|polling|tungstenite|tokio-tungstenite|quinn|socket2|mio|websocket|actix-web|axum|warp|rocket|tiny_http|trust-dns-resolver|hickory-resolver|native-tls|openssl|rustls|ureq-proto)$'

    tree="$(cargo tree --manifest-path "${manifest}" --edges normal --prefix none --no-dedupe 2>/dev/null)" || {
        echo "tauri-no-network: FAIL - the desktop dependency graph did not resolve, so it" >&2
        echo "  could not be inspected. This check fails CLOSED: an uninspected graph is not" >&2
        echo "  a clean one." >&2
        exit 1
    }
    hits="$(echo "${tree}" | awk '{print $1}' | sort -u | grep -E "${socket_crates}" || true)"
    if [ -n "${hits}" ]; then
        echo "tauri-no-network: FAIL - the desktop app links a crate that can open a socket:" >&2
        echo "${hits}" | sed 's/^/    /' >&2
        echo "  I1 says PHI never leaves the device. A network client in this graph is not a" >&2
        echo "  packaging detail; it is the invariant the product rests on. Revert it." >&2
        failed=1
    fi

    # An auto-updater is a scheduled download from a remote origin, on a machine
    # holding patient records. Not "configured to a safe URL" - absent.
    if grep -qE '"(updater|createUpdaterArtifacts)"' "${conf}"; then
        echo "tauri-no-network: FAIL - ${conf} mentions the updater." >&2
        failed=1
    fi
    if grep -qE '"(devUrl|beforeDevCommand|beforeBuildCommand)"' "${conf}"; then
        echo "tauri-no-network: FAIL - ${conf} names a dev server or a build hook. The window" >&2
        echo "  must load only ./ui, which is compiled into the binary." >&2
        failed=1
    fi
    # Every URL in the config, minus the two that are not origins the app talks
    # to: the JSON-schema annotation an editor reads, and the loopback name the
    # webview's own IPC transport uses.
    remote="$(grep -oiE 'https?://[^"[:space:];]+' "${conf}" \
        | grep -viE '^https://schema\.tauri\.app|^http://ipc\.localhost' || true)"
    if [ -n "${remote}" ]; then
        echo "tauri-no-network: FAIL - ${conf} names a remote origin:" >&2
        echo "${remote}" | sed 's/^/    /' >&2
        failed=1
    fi
    # The CSP is the second half of the same claim: a window that may not connect
    # anywhere cannot exfiltrate what it renders.
    if ! grep -q "default-src 'none'" "${conf}"; then
        echo "tauri-no-network: FAIL - ${conf} has no default-src 'none' CSP." >&2
        failed=1
    fi

    # Least privilege in the capability file. Any permission beyond core:default
    # is a door the webview holds open, and each one has to be argued for here.
    #
    # `python3` and not `{{python}}`: this is an invariant gate and must run on a
    # clone with no virtualenv built. It parses JSON and imports nothing outside
    # the standard library, so the interpreter is all it needs.
    granted="$(python3 - "${caps}" <<'PY'
    import json, sys
    with open(sys.argv[1], encoding="utf-8") as handle:
        print("\n".join(json.load(handle)["permissions"]))
    PY
    )" || granted=""
    # FAILS CLOSED. An unreadable or empty permission list is an uninspected
    # one, and an earlier revision of this recipe printed OK when the parse
    # failed -- a gate that passes when it cannot run is not a gate.
    if [ -z "${granted}" ]; then
        echo "tauri-no-network: FAIL - could not read the permission list from ${caps}." >&2
        echo "  Every capability file must grant at least core:default, so an empty result" >&2
        echo "  means the file is missing, malformed, or python3 is not installed." >&2
        failed=1
    fi
    for permission in ${granted}; do
        if [ "${permission}" != "core:default" ]; then
            echo "tauri-no-network: FAIL - ${caps} grants '${permission}'." >&2
            echo "  Only core:default is allowed without an entry in docs/DECISIONS.md saying" >&2
            echo "  which command needs it and why it cannot be done from Rust instead." >&2
            failed=1
        fi
    done

    if [ "${failed}" -ne 0 ]; then exit 1; fi
    echo "tauri-no-network: OK - no HTTP client, no TLS stack, no updater, no remote origin,"
    echo "  CSP default-src 'none', webview granted core:default only."

# ---------------------------------------------------------------------------
# Build and packaging: one command per artifact class, no shell history.
# ---------------------------------------------------------------------------

# Build every shippable artifact.
#
# WHY one recipe rather than "run these four": a release built by remembering four commands is a
# release that ships three of them. The header of this file says a command not in here does not
# exist; the corollary is that "everything" has to be a command too.
#
# WHY the wasm side SKIPS rather than fails, when the rest of this file makes missing toolchains
# fatal: `just build-wasm` is a recipe someone ran on purpose, so failing tells them the thing
# they asked for cannot happen. `build-all` is the entry point for a contributor who just wants
# the native binaries, and hard-failing there makes the wasm toolchain a de facto prerequisite
# for touching core/. The rule this file holds is not "never skip" - it is never skip SILENTLY.
# Every skip below prints what was skipped, why, and the exact command that un-skips it, and the
# closing report lists it again so it cannot scroll past unread.
#
# Build every shippable artifact and report what was built and what was skipped.
build-all:
    #!/usr/bin/env bash
    set -euo pipefail
    built=()
    skipped=()

    echo "build-all: native binaries (release)"
    cargo build --release {{bin_pkgs}}
    for b in {{bins}}; do
        # Asserted rather than assumed: a rename in a [[bin]] section makes cargo succeed while
        # producing a binary under a name that package/ and install/ will not find, and the
        # first symptom would otherwise be an empty bundle.
        if [ ! -x "target/release/${b}" ]; then
            echo "build-all: FAIL - cargo succeeded but target/release/${b} does not exist." >&2
            echo "  The [[bin]] name in bindings/*/Cargo.toml no longer matches 'bins' in this" >&2
            echo "  justfile. Fix one of the two; they are the same list in two places." >&2
            exit 1
        fi
        built+=("target/release/${b}")
    done

    # The browser surface. Two things gate it and they fail differently, so they are reported
    # separately: a missing rustup target is one command away, a missing bindgen is another.
    wasm_skip=""
    if ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
        wasm_skip="the wasm32-unknown-unknown target is not installed (fix: rustup target add wasm32-unknown-unknown)"
    elif ! command -v wasm-pack >/dev/null 2>&1 && ! command -v wasm-bindgen >/dev/null 2>&1; then
        wasm_skip="neither wasm-pack nor wasm-bindgen is installed (fix: cargo install wasm-pack, or cargo install wasm-bindgen-cli)"
    fi
    if [ -z "${wasm_skip}" ]; then
        echo
        echo "build-all: wasm module + panel bundle"
        # Delegated rather than duplicated: build-wasm already encodes which two targets are
        # built and why (web for the panel, nodejs for the no-upload proof). A second copy of
        # that here is a second copy to forget to update.
        just build-wasm
        built+=("bindings/wasm/pkg-web/deid_tr_wasm_bg.wasm")
        built+=("bindings/wasm/pkg/deid_tr_wasm_bg.wasm")
        # The panel is static source, so it is not "built" - but it is unusable without the
        # module it loads from ../pkg-web/, so its readiness is exactly the wasm build's.
        built+=("bindings/wasm/panel/ (static; loads ../pkg-web/)")
    else
        skipped+=("wasm module + panel bundle: ${wasm_skip}")
    fi

    # The React panel. SKIPS LOUDLY when npm is absent, by the same rule the wasm
    # half follows and for the same reason: `build-all` is the entry point for a
    # contributor who wants the native binaries, and hard-failing here would make
    # a Node toolchain a prerequisite for touching core/. Never skip SILENTLY --
    # the skip prints the reason and the command that fixes it, and is listed
    # again in the closing report.
    #
    # THE VANILLA PANEL IS NOT AFFECTED BY THIS SKIP. It has no build step, which
    # is exactly why it still exists: a machine with no Node still gets a working,
    # readable panel out of this repository.
    if ! command -v npm >/dev/null 2>&1; then
        skipped+=("React panel (bindings/panel-app/): npm is not installed (fix: install Node 20 or newer, then re-run; or run 'just build-panel-app' directly)")
    else
        echo
        echo "build-all: React panel (bindings/panel-app/)"
        just build-panel-app
        built+=("bindings/panel-app/dist/ (React + Tailwind + shadcn/ui; loads ./pkg-web/)")
    fi

    # The desktop surface. SKIPS LOUDLY, by the same rule the wasm half follows
    # and for the same reason: `just build-tauri` is a thing somebody asked for,
    # so it fails; `build-all` is the entry point for a contributor who wants the
    # native binaries, and hard-failing here would make a GUI toolchain a
    # prerequisite for touching core/.
    #
    # Two gates, reported separately because they are fixed differently. The
    # first is the one that bites on this project specifically: the Tauri graph
    # is deliberately outside the workspace lock, so on a machine that has never
    # fetched it there is nothing to build from and no way to get it without a
    # network operation this repository will not perform on someone's behalf.
    tauri_skip=""
    if ! cargo metadata --offline --format-version 1 --manifest-path bindings/tauri/Cargo.toml \
            >/dev/null 2>&1; then
        tauri_skip="the Tauri dependency graph is not in this machine's cargo registry cache (fix, once, online: cargo fetch --manifest-path bindings/tauri/Cargo.toml)"
    elif [ "$(uname -s)" = "Linux" ] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
        # macOS has WebKit in the system and Windows has WebView2; only Linux
        # needs a package installed, so only Linux is checked.
        tauri_skip="the webkit2gtk-4.1 development package is not installed (fix: install libwebkit2gtk-4.1-dev, or your distribution's equivalent)"
    fi
    if [ -z "${tauri_skip}" ]; then
        echo
        echo "build-all: desktop application"
        # Delegated rather than duplicated: build-tauri already encodes the
        # air-gap gate it depends on and the icon regeneration.
        just build-tauri
        built+=("bindings/tauri/target/release/deid-tr-desktop")
    else
        skipped+=("desktop application (bindings/tauri): ${tauri_skip}")
    fi

    echo
    echo "=============================================================================="
    echo "BUILD REPORT"
    echo "=============================================================================="
    echo "built:"
    for a in "${built[@]}"; do echo "  + ${a}"; done
    if [ ${#skipped[@]} -eq 0 ]; then
        echo "skipped: nothing"
    else
        echo "skipped:"
        for s in "${skipped[@]}"; do echo "  - ${s}"; done
        echo
        echo "The native side is complete. 'just package' will REFUSE to build a bundle while"
        echo "anything above is skipped, because a distributable missing a surface is worse"
        echo "than no distributable."
    fi
    echo
    echo "This build masks NO NAMES: L2 has no trained model and no weights ship. See"
    echo "deploy/BUNDLE_README.md, or run: ./target/release/deid doctor"

# Assemble a versioned, checksummed, distributable bundle in dist/.
#
# WHY it refuses when build-all skipped something: `build-all` skips so a contributor can work.
# `package` produces the thing a hospital downloads, and a tarball that quietly lacks the browser
# panel would be discovered by whoever unpacked it expecting one. Fail here, loudly, where the
# person who can install the toolchain is standing.
#
# WHY the mtimes get flattened and gzip runs with -n: same inputs must give the same tarball
# bytes, and otherwise the archive differs on every run purely from build timestamps, directory
# order, and the mtime gzip stamps into its own header. That is not full bit-for-bit
# reproducibility across machines - the compiler decides that, not this recipe - but it removes
# the incidental nondeterminism that makes comparing two bundles impossible before you even get
# to the interesting question.
#
# Assemble the versioned, checksummed release bundle in dist/.
package: build-all
    #!/usr/bin/env bash
    set -euo pipefail

    if [ ! -f bindings/wasm/pkg-web/deid_tr_wasm_bg.wasm ]; then
        echo "package: FAIL - no browser panel build (bindings/wasm/pkg-web/)." >&2
        echo "  'just build-all' skipped it; see the reason it printed. A release bundle" >&2
        echo "  ships every surface or it is not a release bundle. Install the wasm" >&2
        echo "  toolchain and re-run." >&2
        exit 1
    fi

    version="$(awk -F'"' '/^\[workspace\.package\]/{f=1} f && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml)"
    if [ -z "${version}" ]; then
        echo "package: FAIL - could not read version from [workspace.package] in Cargo.toml." >&2
        echo "  An unversioned bundle is a bundle nobody can say they are running, which is" >&2
        echo "  the first question asked about a tool that handled a patient record." >&2
        exit 1
    fi
    target="$(rustc -vV | awk '/^host:/{print $2}')"
    commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        commit="${commit}-dirty"
    fi
    name="deid-tr-${version}-${target}"
    stage="{{dist_dir}}/${name}"

    # Rebuilt from scratch every time: an incremental staging directory keeps files that a
    # rename deleted from the build, and the bundle then ships an artifact that no longer exists
    # in the tree it claims to come from.
    rm -rf "${stage}"
    mkdir -p "${stage}/bin" "${stage}/panel" "${stage}/pkg-web"

    for b in {{bins}}; do
        install -m 0755 "target/release/${b}" "${stage}/bin/${b}"
    done
    cp bindings/wasm/panel/* "${stage}/panel/"
    cp bindings/wasm/pkg-web/* "${stage}/pkg-web/"
    install -m 0644 LICENSE "${stage}/LICENSE"

    # The bundle README is a template, not prose generated here: what does and does not work is
    # a claim about the product, and a claim about the product belongs in a file a reviewer can
    # read in a diff rather than inside a shell heredoc in a build script.
    sed -e "s|@@VERSION@@|${version}|g" \
        -e "s|@@TARGET@@|${target}|g" \
        -e "s|@@COMMIT@@|${commit}|g" \
        deploy/BUNDLE_README.md > "${stage}/README.md"

    # An array rather than a shell function because the checksum command is invoked through
    # xargs below, and xargs execs a real binary - it cannot see a function.
    if command -v shasum >/dev/null 2>&1; then
        sha_cmd=(shasum -a 256)
    elif command -v sha256sum >/dev/null 2>&1; then
        sha_cmd=(sha256sum)
    else
        echo "package: FAIL - neither shasum nor sha256sum is available." >&2
        echo "  A bundle nobody can verify is a binary of unknown origin. Fails closed." >&2
        exit 1
    fi

    # Paths are relative to the bundle root so `shasum -a 256 -c SHA256SUMS` works after the
    # user extracts it wherever they extract it.
    ( cd "${stage}" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs "${sha_cmd[@]}" > SHA256SUMS )

    # 2020-01-01T00:00:00Z: an arbitrary fixed instant. Any constant works; what matters is that
    # it is not "now".
    find "${stage}" -exec touch -t 202001010000.00 {} +

    tarball="{{dist_dir}}/${name}.tar.gz"
    rm -f "${tarball}"
    ( cd "{{dist_dir}}" && find "${name}" -print | LC_ALL=C sort \
        | tar -cf - --no-recursion -T - ) | gzip -n > "${tarball}"

    ( cd "{{dist_dir}}" && "${sha_cmd[@]}" "${name}.tar.gz" > SHA256SUMS )

    echo
    echo "=============================================================================="
    echo "BUNDLE: ${tarball}"
    echo "=============================================================================="
    echo "  version ${version}   target ${target}   source ${commit}"
    echo
    echo "Contents (${stage}/SHA256SUMS):"
    sed 's/^/  /' "${stage}/SHA256SUMS"
    echo
    echo "Archive ({{dist_dir}}/SHA256SUMS):"
    sed 's/^/  /' "{{dist_dir}}/SHA256SUMS"
    echo
    echo "Record the archive checksum OUT OF BAND - somewhere that is not this tarball and not"
    echo "the server that will serve it. A checksum shipped beside the file it checksums proves"
    echo "only that the file did not corrupt in transit."
    echo
    echo "NO MODEL WEIGHTS ARE BUNDLED. There are none to bundle, for any layer, and 'deid pull'"
    echo "is not implemented. This build masks NO NAMES. Both are stated in the bundle README so"
    echo "nobody unpacks this looking for a model directory that was never going to be there."

# Install the built binaries to PREFIX (default ~/.local/bin).
#
# WHY ~/.local/bin and not /usr/local/bin: the default must not need sudo. A tool whose install
# step asks for root is a tool that gets installed by pasting a root shell command found on the
# internet, and this one reads patient records.
#
# WHY it prints every path it wrote: this recipe puts executables on someone's PATH. The set of
# things that appear on your PATH without telling you should be empty.
#
# Install the binaries to PREFIX (default ~/.local/bin). No sudo, idempotent.
install prefix="~/.local/bin": build-all
    #!/usr/bin/env bash
    set -euo pipefail
    # Expanded here rather than by just, whose variable substitution does not do tilde expansion
    # and would create a literal './~' directory.
    prefix="$(eval echo "{{prefix}}")"
    mkdir -p "${prefix}"
    if [ ! -w "${prefix}" ]; then
        echo "install: FAIL - ${prefix} is not writable by this user." >&2
        echo "  This recipe never escalates. Choose a writable prefix instead:" >&2
        echo "      just install ~/.local/bin" >&2
        exit 1
    fi
    echo "installed:"
    for b in {{bins}}; do
        # install(1) rather than cp: it replaces the target atomically and sets the mode
        # explicitly, so re-running over a binary that is currently executing does not produce
        # a half-written file, and the result does not depend on the umask of whoever ran it.
        # That is what makes this recipe idempotent rather than merely repeatable.
        install -m 0755 "target/release/${b}" "${prefix}/${b}"
        echo "  ${prefix}/${b}"
    done
    case ":${PATH}:" in
        *":${prefix}:"*) ;;
        *)
            echo
            echo "NOTE: ${prefix} is not on your PATH, so the names above will not resolve."
            echo "  Add this to your shell profile:"
            echo "      export PATH=\"${prefix}:\$PATH\""
            ;;
    esac
    echo
    echo "This build masks NO NAMES. Run 'deid doctor' for this machine's layer report."

# Print the MCP client configuration block. Does NOT write it anywhere.
#
# WHY print and never edit: the config file belongs to a client outside this repository, and
# rewriting somebody's editor or assistant configuration from a build recipe is a surprise. This
# tool's entire posture is that surprises are the defect - a de-identifier that does something
# you did not ask for is a de-identifier you cannot reason about. So it hands you the exact text
# and stops, and you decide where it goes.
#
# WHY the absolute path is interpolated rather than left as a placeholder: a relative command
# path resolves against whatever working directory the client happens to have, and the failure
# looks like the server hanging rather than a missing file. The one detail most likely to be
# pasted wrong is the one this recipe fills in.
#
# Print the MCP client config block for this checkout. Writes nothing.
register-mcp:
    #!/usr/bin/env bash
    set -euo pipefail
    bin="$(pwd)/target/release/deid-mcp"
    if [ ! -x "${bin}" ]; then
        echo "register-mcp: ${bin} does not exist." >&2
        echo "  Build it first: just build-all   (or: just mcp-build)" >&2
        echo "  Refusing to print a config pointing at a binary that is not there - the" >&2
        echo "  client's failure mode for a missing command is nearly silent." >&2
        exit 1
    fi
    cat <<EOF
    ==============================================================================
    MCP REGISTRATION - deid-tr
    ==============================================================================
    Nothing below has been written to any file. Paste it yourself.

    The gateway is LAUNCHED BY THE CLIENT and speaks newline-delimited JSON-RPC on
    stdin/stdout. It is not a service you start and connect to, and it cannot open
    a socket at all - that is what makes it safe for it to hold the span map.

    --- Claude Code ------------------------------------------------------------
    Run:

        claude mcp add deid-tr -- ${bin} --tier safe-harbor --session-ttl 900

    --- Any client using the standard mcpServers config -------------------------
    Add this block, merging into an existing "mcpServers" object if there is one:

    {
      "mcpServers": {
        "deid-tr": {
          "command": "${bin}",
          "args": ["--tier", "safe-harbor", "--session-ttl", "900"]
        }
      }
    }

    It goes in that client's own config file. Common locations:

      Claude Desktop (macOS)   ~/Library/Application Support/Claude/claude_desktop_config.json
      Claude Desktop (Linux)   ~/.config/Claude/claude_desktop_config.json
      Claude Desktop (Windows) %APPDATA%\\Claude\\claude_desktop_config.json
      Claude Code (project)    .mcp.json in the project root
      Cursor                   ~/.cursor/mcp.json  (or .cursor/mcp.json per project)
      VS Code / Continue       the "mcpServers" block of that extension's settings

    Restart the client after editing; these files are read at startup.

    --- Before you send anything real -----------------------------------------
    Call the 'health' tool. It reports which layers are live in the process you
    just started, not which ones are supposed to be.

    THIS BUILD MASKS NO NAMES. L2 has no trained model, so PATIENT_NAME,
    CLINICIAN_NAME and RELATIVE_NAME pass through untouched. TCKN, VKN, SGK,
    IBAN, phone, MRN, email and dates are masked. Do not treat the output as
    Safe Harbor compliant.
    ==============================================================================
    EOF

# ---------------------------------------------------------------------------
# Deployment. The default is the safe one; the unsafe one is loud and typed out.
#
# WHY these two recipes and not a docs page: a deployment procedure that lives in
# prose is a procedure whose steps get skipped in the order they are boring. The
# preflight is the step most worth skipping and least safe to skip, so it is a
# command with an exit code rather than a checklist with a checkbox.
#
# docs/DEPLOY-SERVER.md is the reasoning. These are the two commands it leads with.
# ---------------------------------------------------------------------------

# Run the service on THIS machine, bound to 127.0.0.1. The default deployment.
#
# WHY the command is echoed before it runs: this is the line an operator copies into a runbook,
# a systemd unit or a compose file, and the copy they make should be of the SAFE invocation
# rather than of whatever they reconstruct from memory later. Printing it also means the
# loopback bind is visible on their terminal even though they typed no flag to get it - a
# default nobody can see is a default nobody trusts, and the first thing an untrusting operator
# does is add flags.
#
# ARGS is forwarded so a local run can pick a port or a tier. It cannot reach an all-interfaces
# bind: deid-serve refuses that unconditionally, with --expose, with a token, with both.
#
# Run deid-serve on 127.0.0.1. The default, and the one docs/DEPLOY-SERVER.md leads with.
deploy-local *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p deid-tr-service
    bin="$(pwd)/target/release/deid-serve"
    echo
    echo "deploy-local: running exactly this command --"
    echo
    echo "    ${bin} --host 127.0.0.1 --port 8787 {{ARGS}}"
    echo
    echo "  Bound to loopback. No other machine can reach it, and no flag in this"
    echo "  repository makes it reachable by accident. Ctrl-C to stop."
    echo "  THIS BUILD MASKS NO NAMES: run 'just deploy-check' for the full coverage report."
    echo
    exec "${bin}" --host 127.0.0.1 --port 8787 {{ARGS}}

# The preflight a human runs BEFORE exposing anything.
#
# WHY it is a wrapper around `deid-serve preflight` rather than a shell script that re-checks
# the rules: the rules live in bindings/service/src/bind.rs and the coverage report is read from
# a REAL pipeline built from the same flags. A bash re-implementation would be a second source
# of truth for "does this bind get refused" and "are names masked", and the copy that goes stale
# is always the one that says yes.
#
# Exits non-zero on any FAIL. Warnings - no TLS, no L2 model - do not fail it: they are true of
# every correct deployment too, and a check that fails on the correct default is a check people
# learn to suppress.
#
# Preflight a deployment: bind, token, TLS, and which layers are actually live.
deploy-check *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release --quiet -p deid-tr-service
    echo "deploy-check: nothing is started and no socket is created."
    echo
    # `set -e` would swallow the exit code we specifically want to propagate.
    set +e
    ./target/release/deid-serve preflight {{ARGS}}
    status=$?
    set -e
    echo
    if [ "${status}" -ne 0 ]; then
        echo "deploy-check: FAIL. Do not deploy this. docs/DEPLOY-SERVER.md explains each refusal." >&2
        exit "${status}"
    fi
    echo "deploy-check: no blocking findings. Read the WARN lines before you proceed --"
    echo "  they are the ones that are true of correct deployments as well as broken ones."

# ---------------------------------------------------------------------------
# Detached surfaces: up / down / status / logs
#
# WHY THESE EXIST ALONGSIDE deploy-local AND serve-panel: those two run in the
# foreground and die with the terminal. On a laptop that is correct - you can see
# what you started. Over SSH it is not: the link drops, SIGHUP reaches the
# process group, and the service a clinician was pointed at vanishes for a reason
# unrelated to the service. The foreground recipes stay, because a foreground
# process with a visible log is still the best way to debug one; these are what
# you run on a server.
#
# WHY THE BODY IS IN scripts/surfaces.sh: up, down and status must agree exactly
# on the pidfile path, the port and the mechanism. Three recipes is three chances
# to disagree, and the disagreement surfaces as `just down` claiming success over
# a process still holding the port.
#
# I3 IS UNCHANGED BY DETACHING. Both surfaces bind 127.0.0.1 and the script has
# no host argument to give them. Reach them over an SSH tunnel.
# ---------------------------------------------------------------------------

# Start the surfaces detached (tmux if present, else nohup + pidfile).
up *ARGS:
    ./scripts/surfaces.sh up {{ARGS}}

# Stop the surfaces and VERIFY each port is actually free afterwards.
down *ARGS:
    ./scripts/surfaces.sh down {{ARGS}}

# What is running, under which mechanism, on which port, with which log.
status:
    ./scripts/surfaces.sh status

# Tail the persisted surface logs. `just logs serve -f` follows one of them.
logs *ARGS:
    ./scripts/surfaces.sh logs {{ARGS}}
