#!/usr/bin/env bash
#
# Start, stop, inspect and tail the long-running surfaces, DETACHED.
#
# WHY THIS EXISTS:
# `just deploy-local` and `just serve-panel` run in the foreground and die with
# the terminal. On a laptop that is the right default -- you can see the process
# you started. Over SSH it is the wrong one: the operator's link drops, SIGHUP
# reaches the process group, and the service a clinician is pointed at
# disappears for a reason that has nothing to do with the service.
#
# WHY TMUX IS PREFERRED AND NOHUP IS THE FALLBACK:
# nohup gets the process to survive, and that is all it does. tmux gets the same
# survival AND leaves a live terminal an operator can attach to, which matters
# here because the startup banner of `deid-serve` carries the coverage
# disclosure -- the sentence that says this build masks no names. A mechanism
# where that sentence only ever lands in a file nobody opens is a worse
# mechanism, so tmux wins when it is present. Neither mechanism is silent about
# which one ran: every command below names it.
#
# WHY IT IS A SCRIPT AND NOT FOUR JUSTFILE RECIPES:
# up, down and status have to agree, exactly, on where the pidfile is, what the
# port is and which mechanism was used. Three recipes are three chances to
# disagree, and the disagreement shows up as `just down` reporting success over
# a process that is still holding the port.
#
# I3 IS NOT RELAXED BY DETACHING. Both surfaces bind 127.0.0.1 and neither takes
# a host argument from this script. Reach them with an SSH tunnel; see
# docs/DEPLOY.md.
#
# I4 APPLIES TO THE LOG FILES. This is the first place output is PERSISTED
# rather than streamed to a terminal, so what reaches these files is a privacy
# question and not a housekeeping one. See docs/DEPLOY.md, "What is in the log
# files", for what was checked and what was found.
set -euo pipefail

cd "$(dirname "$0")/.."
readonly REPO="$PWD"

readonly SESSION="deid-tr"
readonly LOG_DIR="logs"
readonly RUN_DIR=".run"
readonly VENV_PY=".venv/bin/python"

# Every surface this script knows about, in start order. Adding one means adding
# a case arm to each of surface_port, surface_cmd and surface_preflight; they are
# kept as three functions over one list rather than one table because a bash 3.2
# associative array does not exist on macOS, and this repo is developed there and
# deployed on Linux.
readonly SURFACES="serve panel"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
fail() { printf '  %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Surface definitions
# ---------------------------------------------------------------------------

surface_port() {
    case "$1" in
        serve) echo 8787 ;;
        panel) echo 8722 ;;
        *) fail "unknown surface: $1"; exit 2 ;;
    esac
}

surface_what() {
    case "$1" in
        serve) echo "deid-serve, the HTTP de-identification service" ;;
        panel) echo "the browser panel, static files only" ;;
        *) fail "unknown surface: $1"; exit 2 ;;
    esac
}

# The exact argv, as a shell-quoted string. `--host 127.0.0.1` is spelled out
# even though it is deid-serve's default, for the same reason `just deploy-local`
# echoes its command: a loopback bind nobody can see is a loopback bind nobody
# trusts, and an operator reading `ps` on a shared box should not have to know
# the default to know the posture.
surface_cmd() {
    case "$1" in
        serve)
            printf '%s --host 127.0.0.1 --port 8787' "$(printf %q "${REPO}/target/release/deid-serve")"
            ;;
        panel)
            # Document root is bindings/wasm, not panel/: both pages load the
            # wasm module from the sibling ../pkg-web/.
            printf '%s %s --port 8722 --directory %s --page panel/index.html' \
                "$(printf %q "${REPO}/${VENV_PY}")" \
                "$(printf %q "${REPO}/scripts/panel_server.py")" \
                "$(printf %q "${REPO}/bindings/wasm")"
            ;;
        *) fail "unknown surface: $1"; exit 2 ;;
    esac
}

# Refuse to start something that cannot work, and name the command that fixes
# it. A surface that starts, fails to find its artifact and exits is a surface
# whose failure the operator discovers from a browser error page.
surface_preflight() {
    case "$1" in
        serve)
            if [ ! -x "target/release/deid-serve" ]; then
                fail "up: target/release/deid-serve is not built."
                fail "    fix: just build-all"
                return 1
            fi
            ;;
        panel)
            if [ ! -x "${VENV_PY}" ]; then
                fail "up: ${VENV_PY} does not exist, so the panel server has no interpreter."
                fail "    fix: just venv     (or: ./scripts/server-setup.sh)"
                return 1
            fi
            if [ ! -d "bindings/wasm/pkg-web" ]; then
                fail "up: bindings/wasm/pkg-web does not exist, so the panel would load nothing."
                fail "    fix: just build-wasm"
                return 1
            fi
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Process and port primitives
# ---------------------------------------------------------------------------

pid_file() { echo "${RUN_DIR}/$1.pid"; }
mech_file() { echo "${RUN_DIR}/$1.mechanism"; }
log_file() { echo "${LOG_DIR}/$1.log"; }

pid_alive() { kill -0 "$1" 2>/dev/null; }

recorded_pid() {
    local f
    f="$(pid_file "$1")"
    [ -f "$f" ] || return 1
    local pid
    pid="$(cat "$f" 2>/dev/null || true)"
    case "${pid}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    echo "${pid}"
}

recorded_mechanism() {
    local f
    f="$(mech_file "$1")"
    if [ -f "$f" ]; then cat "$f"; else echo "unknown"; fi
}

# Is anything listening on this loopback port?
#
# WHY a connect attempt and not lsof/ss: this has to give the same answer on
# macOS and Linux, on a box where the operator may not be root, and lsof is not
# installed everywhere. A successful connect to 127.0.0.1:PORT is the definition
# of "the port is still held" as far as the next `just up` is concerned, which is
# the question `down` actually needs answered.
port_busy() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

# Best-effort attribution for a port we could not free. Advisory only: it runs
# whichever of these tools exists and says nothing if neither does, because a
# down that failed has already told the operator the important part.
port_holder() {
    local port="$1"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true
    elif command -v ss >/dev/null 2>&1; then
        ss -ltnp "sport = :${port}" 2>/dev/null | tail -n +2 || true
    fi
}

tmux_available() { command -v tmux >/dev/null 2>&1; }
tmux_session_exists() { tmux has-session -t "${SESSION}" 2>/dev/null; }
tmux_window_exists() {
    tmux_available || return 1
    tmux_session_exists || return 1
    tmux list-windows -t "${SESSION}" -F '#{window_name}' 2>/dev/null | grep -qx "$1"
}

is_running() {
    local pid
    pid="$(recorded_pid "$1")" || return 1
    pid_alive "${pid}"
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------

up_one() {
    local name="$1"
    local port log pidf cmd
    port="$(surface_port "${name}")"
    log="$(log_file "${name}")"
    pidf="$(pid_file "${name}")"

    if is_running "${name}"; then
        note "${name}: already up (pid $(recorded_pid "${name}"), $(recorded_mechanism "${name}")), left alone"
        return 0
    fi

    # A stale pidfile with a live listener is the dangerous case: starting a
    # second copy would silently fail to bind and the operator would be talking
    # to the OLD build. Refuse and say who to ask.
    if port_busy "${port}"; then
        fail "${name}: port ${port} is already in use by a process this script did not start."
        local holder
        holder="$(port_holder "${port}")"
        [ -n "${holder}" ] && printf '%s\n' "${holder}" >&2
        fail "    Nothing was started. Stop that process, or run: just down"
        return 1
    fi

    surface_preflight "${name}" || return 1

    mkdir -p "${LOG_DIR}" "${RUN_DIR}"
    cmd="$(surface_cmd "${name}")"

    local mechanism
    if tmux_available; then
        mechanism="tmux"
        # `sleep 0.3` before exec is not a stability hack: pipe-pane can only be
        # attached to a window that already exists, so without the pause the
        # process's first lines -- which for deid-serve include the coverage
        # disclosure and the bind address -- can be printed before the pipe is
        # in place and never reach the log. exec means the pane's pid is the
        # service's pid, so the pidfile stays the authority for `down`.
        if tmux_session_exists; then
            tmux new-window -d -t "${SESSION}" -n "${name}" "sh -c 'sleep 0.3; exec ${cmd}'"
        else
            tmux new-session -d -s "${SESSION}" -n "${name}" "sh -c 'sleep 0.3; exec ${cmd}'"
        fi
        tmux pipe-pane -o -t "${SESSION}:${name}" "cat >> $(printf %q "${REPO}/${log}")"
        tmux list-panes -t "${SESSION}:${name}" -F '#{pane_pid}' | head -1 > "${pidf}"
    else
        mechanism="nohup"
        # setsid where available, so the process leaves the SSH session's
        # process group entirely rather than merely ignoring SIGHUP.
        if command -v setsid >/dev/null 2>&1; then
            nohup setsid sh -c "exec ${cmd}" >> "${log}" 2>&1 &
        else
            nohup sh -c "exec ${cmd}" >> "${log}" 2>&1 &
        fi
        echo "$!" > "${pidf}"
    fi
    echo "${mechanism}" > "$(mech_file "${name}")"

    # Started is not the same as listening. Poll the port so `up` reports a fact
    # rather than an intention -- a recipe that says OK and leaves the operator
    # to discover a bind failure in a browser is worse than one that waits.
    local waited=0
    while [ "${waited}" -lt 100 ]; do
        port_busy "${port}" && break
        sleep 0.1
        waited=$((waited + 1))
    done

    local pid
    pid="$(recorded_pid "${name}" || echo '?')"
    if port_busy "${port}"; then
        note "${name}: up  pid=${pid}  mechanism=${mechanism}  127.0.0.1:${port}  log=${log}"
        note "        $(surface_what "${name}")"
    else
        fail "${name}: started (pid=${pid}, ${mechanism}) but nothing is listening on ${port} after 10s."
        fail "    The last lines of ${log}:"
        tail -n 20 "${log}" >&2 2>/dev/null || true
        return 1
    fi
    return 0
}

cmd_up() {
    local names="${*:-${SURFACES}}"
    say "deid-tr up"
    if tmux_available; then
        note "mechanism: tmux (session '${SESSION}', one window per surface)"
    else
        note "mechanism: nohup + pidfile (tmux is not installed on this host)"
        note "           install tmux to get an attachable terminal per surface"
    fi
    local rc=0 name
    for name in ${names}; do
        up_one "${name}" || rc=1
    done
    echo
    if tmux_available; then
        note "attach:  tmux attach -t ${SESSION}"
        note "detach:  Ctrl-b then d      <- NOT Ctrl-C. Ctrl-C kills the surface."
    fi
    note "status:  just status"
    note "logs:    just logs           (add a surface name to narrow it)"
    note "stop:    just down"
    echo
    note "Loopback only. From your laptop:"
    note "  ssh -N -L 8787:127.0.0.1:8787 -L 8722:127.0.0.1:8722 YOU@THIS-SERVER"
    echo
    note "THIS BUILD MASKS NO NAMES: L2 has no trained model and no weights ship, so"
    note "patient, clinician and relative names pass through untouched. 'just deploy-check'"
    note "reports the full coverage picture."
    return "${rc}"
}

# ---------------------------------------------------------------------------
# down
# ---------------------------------------------------------------------------

# Stop one surface and PROVE the port is free afterwards.
#
# A `down` that reports success while a listener still holds the port is worse
# than no `down` at all: the next `up` refuses, the operator concludes the tool
# is broken, and the shortest path from there is `kill -9` against a guessed pid.
down_one() {
    local name="$1"
    local port pidf
    port="$(surface_port "${name}")"
    pidf="$(pid_file "${name}")"

    local pid=""
    pid="$(recorded_pid "${name}" || true)"

    if [ -n "${pid}" ] && pid_alive "${pid}"; then
        kill -TERM "${pid}" 2>/dev/null || true
        local waited=0
        while [ "${waited}" -lt 50 ] && pid_alive "${pid}"; do
            sleep 0.1
            waited=$((waited + 1))
        done
        if pid_alive "${pid}"; then
            note "${name}: pid ${pid} ignored SIGTERM after 5s, sending SIGKILL"
            kill -KILL "${pid}" 2>/dev/null || true
            waited=0
            while [ "${waited}" -lt 50 ] && pid_alive "${pid}"; do
                sleep 0.1
                waited=$((waited + 1))
            done
        fi
    elif [ -n "${pid}" ]; then
        note "${name}: pid ${pid} was already gone"
    fi

    # The tmux window outlives the command it ran only if remain-on-exit is set,
    # but killing it explicitly is what makes `down` idempotent against a window
    # an operator started by hand or one left behind by a crashed pane.
    if tmux_window_exists "${name}"; then
        tmux kill-window -t "${SESSION}:${name}" 2>/dev/null || true
    fi

    rm -f "${pidf}" "$(mech_file "${name}")"

    # The verification, which is the point of the whole function.
    local waited=0
    while [ "${waited}" -lt 30 ] && port_busy "${port}"; do
        sleep 0.1
        waited=$((waited + 1))
    done
    if port_busy "${port}"; then
        fail "${name}: DOWN FAILED - 127.0.0.1:${port} still has a listener."
        local holder
        holder="$(port_holder "${port}")"
        if [ -n "${holder}" ]; then
            printf '%s\n' "${holder}" >&2
        else
            fail "    Could not attribute it: neither lsof nor ss is installed."
        fi
        fail "    Do not assume this surface is stopped. Kill the holder above by hand."
        return 1
    fi

    note "${name}: down, and 127.0.0.1:${port} is free"
    return 0
}

cmd_down() {
    local names="${*:-${SURFACES}}"
    say "deid-tr down"
    local rc=0 name
    for name in ${names}; do
        down_one "${name}" || rc=1
    done
    # An empty session left behind is clutter that makes `tmux attach` show a
    # bare shell, which reads as "something is still running".
    if [ $# -eq 0 ] && tmux_available && tmux_session_exists; then
        if [ -z "$(tmux list-windows -t "${SESSION}" -F '#{window_name}' 2>/dev/null | grep -Ex "$(echo "${SURFACES}" | tr ' ' '|')" || true)" ]; then
            tmux kill-session -t "${SESSION}" 2>/dev/null || true
            note "tmux session '${SESSION}' removed (no surfaces left in it)"
        fi
    fi
    echo
    if [ "${rc}" -eq 0 ]; then
        note "Every surface is stopped and every port is verified free."
    else
        fail "At least one port is still held. Read the lines above before starting anything."
    fi
    return "${rc}"
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

cmd_status() {
    say "deid-tr status"
    if tmux_available; then
        if tmux_session_exists; then
            note "tmux: session '${SESSION}' exists -- attach with 'tmux attach -t ${SESSION}', detach with Ctrl-b d"
        else
            note "tmux: installed, no '${SESSION}' session"
        fi
    else
        note "tmux: not installed; surfaces here run under nohup + pidfile"
    fi
    echo
    local name
    for name in ${SURFACES}; do
        local port log pid state
        port="$(surface_port "${name}")"
        log="$(log_file "${name}")"
        pid="$(recorded_pid "${name}" || echo '-')"
        if is_running "${name}"; then
            state="running"
        elif [ "${pid}" != "-" ]; then
            state="STALE PIDFILE (pid ${pid} is gone)"
        else
            state="stopped"
        fi
        local listening="no"
        port_busy "${port}" && listening="yes"
        local size="-"
        [ -f "${log}" ] && size="$(wc -c < "${log}" | tr -d ' ') bytes"

        note "${name}"
        note "  state       ${state}"
        note "  pid         ${pid}"
        note "  mechanism   $(recorded_mechanism "${name}")"
        note "  listening   ${listening} on 127.0.0.1:${port}"
        note "  log         ${log} (${size})"
        # The disagreement that matters: our pid is dead but the port is held.
        if [ "${state}" != "running" ] && [ "${listening}" = "yes" ]; then
            note "  NOTE        the port is held by a process this script does not track"
        fi
        echo
    done
    note "This build masks no names; 'just deploy-check' reports coverage in full."
}

# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------

cmd_logs() {
    local follow=0
    local names=""
    local arg
    for arg in "$@"; do
        case "${arg}" in
            -f|--follow) follow=1 ;;
            *) names="${names} ${arg}" ;;
        esac
    done
    [ -z "${names}" ] && names="${SURFACES}"

    local existing=""
    local name
    for name in ${names}; do
        surface_port "${name}" >/dev/null
        local log
        log="$(log_file "${name}")"
        if [ -f "${log}" ]; then
            existing="${existing} ${log}"
        else
            note "logs: ${log} does not exist yet (surface never started here)"
        fi
    done
    if [ -z "${existing}" ]; then
        fail "logs: nothing to show. Start something first: just up"
        return 1
    fi
    if [ "${follow}" -eq 1 ]; then
        # shellcheck disable=SC2086
        tail -n 100 -f ${existing}
    else
        # shellcheck disable=SC2086
        tail -n 100 ${existing}
    fi
}

# ---------------------------------------------------------------------------

usage() {
    cat <<'USAGE'
scripts/surfaces.sh <command> [surface...]

  up      [serve|panel]        start detached (tmux if present, else nohup)
  down    [serve|panel]        stop, then verify the port is actually free
  status                       what is running, under which mechanism, on which port
  logs    [surface] [-f]       tail the persisted logs

Surfaces: serve (deid-serve, 127.0.0.1:8787), panel (browser panel, 127.0.0.1:8722).
Both are loopback only. Reach them over an SSH tunnel; see docs/DEPLOY.md.
USAGE
}

case "${1:-}" in
    up) shift; cmd_up "$@" ;;
    down) shift; cmd_down "$@" ;;
    status) shift; cmd_status "$@" ;;
    logs) shift; cmd_logs "$@" ;;
    -h|--help|help|'') usage ;;
    *) fail "surfaces: unknown command '$1'"; echo >&2; usage >&2; exit 2 ;;
esac
