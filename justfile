# deid-tr command surface.
#
# WHY every command lives here: if a command is not in the justfile it does not exist. A build
# step that only lives in someone's shell history is a step that silently stops running, and in
# a PHI pipeline the steps that stop running are the gates.

set shell := ["bash", "-uc"]

python := "python3"
airgap_dir := ".airgap"

# List every recipe. Entry point for anyone new to the repo.
default:
    @just --list

# The Definition of Done gate. Nothing merges that does not pass this.
#
# WHY verify-hooks and test-hooks come first: they are the cheapest recipes here and they gate
# the gates. A fresh clone has no .git/hooks/pre-commit, so without verify-hooks the PHI
# pre-commit scan silently does not run; and a guard whose own tests are not in `check` rots
# into a guard that passes everything.
check: verify-hooks test-hooks core-no-socket mcp-no-socket fmt lint test drift-check eval
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
fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f core/Cargo.toml ] || [ -f Cargo.toml ]; then
        cargo fmt --all
    else
        echo "fmt: no Cargo.toml yet, skipping cargo fmt"
    fi
    if command -v ruff >/dev/null 2>&1; then
        ruff format eval/ tests/ scripts/ 2>/dev/null || ruff format eval/ tests/
    else
        echo "fmt: ruff not installed, skipping (pip install ruff)"
    fi

# WHY -D warnings: a warning nobody fixes is a warning nobody reads.
# Lint Rust and Python, warnings fatal.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f core/Cargo.toml ] || [ -f Cargo.toml ]; then
        cargo clippy --all-targets -- -D warnings
    else
        echo "lint: no Cargo.toml yet, skipping cargo clippy"
    fi
    if command -v ruff >/dev/null 2>&1; then
        ruff check eval/ tests/
    else
        echo "lint: ruff not installed, skipping (pip install ruff)"
    fi
    if command -v mypy >/dev/null 2>&1; then
        mypy --strict eval/
    else
        echo "lint: mypy not installed, skipping (pip install mypy)"
    fi

# Run the deterministic test suite (TDD layer A) in both languages.
test:
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
eval:
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
eval-commit:
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
eval-gates:
    {{python}} eval/run.py --detector null --out eval/results/latest.json
    {{python}} eval/report.py eval/results/latest.json --gates

# WHY it is safe to re-run: the golden set is append-only (I7). This regenerates derived
# artifacts only; it never deletes or weakens a fixture.
# Rebuild the golden set.
build-gold:
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
test-airgapped:
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
gate-tokenizer:
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
red-team:
    {{python}} -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json

# Enforcing form: exit non-zero when the contextual re-ID rate exceeds thresholds.yaml's
# contextual.reid_rate_max (D-008, <= 5%).
red-team-gates:
    {{python}} -m eval.redteam.runner --masker pipeline --out eval/results/redteam.json --gate

# The calibration sweep: all three reference maskers, so the three reference points that prove
# the red team discriminates are reproducible in one command. None of these writes
# eval/results/redteam.json, because none of their numbers may reach the gate.
red-team-calibrate:
    {{python}} -m eval.redteam.runner --masker null   --out eval/results/redteam-calibration-null.json
    {{python}} -m eval.redteam.runner --masker leaky  --out eval/results/redteam-calibration-leaky.json
    {{python}} -m eval.redteam.runner --masker oracle --out eval/results/redteam-calibration-oracle.json

# Run the red team and write every successful attack back as a NEW adversarial fixture file.
# WHY a separate recipe: emission mutates eval/adversarial/, and I7 makes the golden set
# append-only, so growing it is a deliberate act rather than a side effect of looking at a
# number. The writer never opens a committed fixture file - it creates one named for the run.
red-team-emit:
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
allowlist-drift *ARGS:
    {{python}} -m eval.allowlist {{ARGS}}

# The enforcing form, wired into `check`. WHY it is a separate recipe: a `just`
# dependency cannot carry arguments, and a drift report that only ever runs in
# reporting mode is the reason eight terms sat unreconciled while the recipe
# exited 0. Residual drift is legal only when eval.allowlist.DRIFT_EXCEPTIONS
# records why.
drift-check:
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
test-python:
    #!/usr/bin/env bash
    set -euo pipefail
    cd bindings/python
    if command -v ruff >/dev/null 2>&1; then
        ruff format --check .
        ruff check .
    else
        echo "test-python: ruff not installed (pip install ruff)" >&2
        exit 1
    fi
    if command -v mypy >/dev/null 2>&1; then
        mypy --strict
    else
        echo "test-python: mypy not installed (pip install mypy)" >&2
        exit 1
    fi
    if {{python}} -c "import deid_tr" >/dev/null 2>&1; then
        {{python}} -m pytest tests/ -q
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
    if ! command -v wasm-pack >/dev/null 2>&1; then
        echo "build-wasm: wasm-pack is not installed." >&2
        echo "  install with: cargo install wasm-pack" >&2
        exit 1
    fi
    cd bindings/wasm
    wasm-pack build --release --target web --out-dir pkg-web
    wasm-pack build --release --target nodejs --out-dir pkg

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

# Serve the offline panel so the network claim can be checked by eye.
#
# I3: bound to 127.0.0.1 explicitly, never 0.0.0.0 and never "::". This serves a
# page whose whole point is that nothing leaves the machine; listening on a
# routable interface to do it would be its own punchline.
#
# Serve the offline panel on 127.0.0.1 so the empty Network tab can be seen.
serve-panel:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d bindings/wasm/pkg-web ]; then
        echo "serve-panel: no web build; run 'just build-wasm' first." >&2
        exit 1
    fi
    echo "open http://127.0.0.1:8722/tests/index.html and watch the Network tab"
    cd bindings/wasm && {{python}} -m http.server 8722 --bind 127.0.0.1
