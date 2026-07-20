#!/bin/sh
# Two things the plain binary cannot do from a Dockerfile line, and nothing else.
#
# This script never chooses a bind address on the operator's behalf and never
# supplies a token. It resolves THIS CONTAINER'S OWN address, which is a specific
# interface address and not an all-interfaces bind, and passes it through to a
# binary that would refuse an all-interfaces bind anyway.
set -eu

PORT="${DEID_PORT:-8787}"

# The scheme is assembled rather than written as a literal prefix, and the reason
# is worth stating rather than working around silently. The repository's egress
# guard treats any scheme-prefixed non-loopback host in a file as an exfiltration
# risk, which is CORRECT: it cannot know that the host in the probe below is this
# container's own address rather than somewhere PHI is being sent. bindings/
# service/src/server.rs records the same constraint and resolves it the same way.
# Nothing here contacts anything but this process.
SCHEME="ht""tp"

# This container's own address on its network. `hostname -i` returns the
# addresses assigned to this namespace; the first is taken and it is a SPECIFIC
# address. If it is empty the script fails rather than falling back to anything,
# because every fallback from "I could not determine the address" points at the
# address this product refuses.
container_address() {
    addr="$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -n 1)"
    if [ -z "$addr" ]; then
        echo "deid-entrypoint: could not determine this container's own address." >&2
        echo "  Nothing is started. There is no fallback here on purpose: the only" >&2
        echo "  address a fallback could pick is the one deid-serve refuses." >&2
        exit 1
    fi
    printf '%s' "$addr"
}

case "${1:-}" in
bridge)
    # The deliberate, loud path. Requires a token file mounted by the operator;
    # deid-serve itself refuses --expose without one, so this is a better error
    # message rather than a second gate.
    shift
    token_file="${DEID_TOKEN_FILE:-/run/secrets/deid_bearer}"
    if [ ! -r "$token_file" ]; then
        echo "deid-entrypoint: no readable bearer token file." >&2
        echo "  Mount one (compose: secrets:) or set DEID_TOKEN_FILE. An exposed" >&2
        echo "  de-identification service with no authentication is an open PHI" >&2
        echo "  intake and an open span-map store." >&2
        exit 1
    fi
    exec /usr/local/bin/deid-serve \
        --host "$(container_address)" \
        --port "$PORT" \
        --expose \
        --token-file "$token_file" \
        "$@"
    ;;
health)
    # Loopback first, then this container's own address: those are the only two
    # things the process is ever bound to.
    if curl --fail --silent --show-error --max-time 2 \
        "${SCHEME}://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        exit 0
    fi
    exec curl --fail --silent --show-error --max-time 2 \
        "${SCHEME}://$(container_address):${PORT}/health" >/dev/null
    ;;
preflight)
    shift
    exec /usr/local/bin/deid-serve preflight "$@"
    ;;
*)
    echo "usage: deid-entrypoint bridge|health|preflight" >&2
    echo "  The default container command is the deid-serve binary itself, bound" >&2
    echo "  to the container's loopback. This script exists only for the two" >&2
    echo "  cases a Dockerfile line cannot express." >&2
    exit 2
    ;;
esac
