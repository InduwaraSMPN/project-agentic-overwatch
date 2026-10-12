#!/bin/sh
# port_forward.sh -- the three port-forwards a live run reaches, started and stopped as one unit.
#
# WHAT THIS SCRIPT IS
# A live framework-on run talks to three in-cluster endpoints from the host: the Guardian (the only
# mutation path any agent has), Prometheus (the resource collector's source) and Locust (the load
# driver's control plane). Three `kubectl port-forward` processes started by hand are three
# processes nobody remembers to stop, and a forwarder that died mid-run is indistinguishable, from
# the runner's side, from a service that started refusing connections. This script makes the set
# reproducible and its teardown total.
#
#     sh scripts/port_forward.sh up       # start all three, wait until each answers, print a table
#     sh scripts/port_forward.sh status   # report which are live, without changing anything
#     sh scripts/port_forward.sh down     # stop every forwarder this script started
#
# ADR-085 / SUPERVISOR RULING B3: THE FRONTEND IS NO LONGER FORWARDED HERE
# This script used to forward the Online Boutique frontend as the SLO probe's target. On
# 2026-09-12 that pinned the probe timeline to one frontend pod's forwarded connection; eradication
# correctly deleted that pod, and every later probes.csv row read a transport failure although the
# Deployment stayed Ready throughout -- inverting verified recovery for every scenario whose
# eradication replaces a pod. "An SLO describes the Service, not a pod" (ruling B3): the probe now
# runs from a pod inside the cluster, against the frontend Service's cluster-DNS name, with no
# port-forward on the measurement path at all (runner/live_baseline.py::probe_writer;
# infra/probes/deploy/). Guardian, Prometheus and Locust are unaffected -- ruling B3 keeps this
# script for exactly those three -- so they stay here, and FRONTEND_LOCAL_PORT is retired along
# with the row that used it.
#
# The local ports are the defaults `scripts/live_env.sh` composes its three remaining URLs from.
# Override with GUARDIAN_LOCAL_PORT / PROMETHEUS_LOCAL_PORT / LOCUST_LOCAL_PORT, in both places, and
# they stay in step.
#
# WHY PID FILES AND NOT `pkill kubectl`
# A pattern kill would also stop a forwarder some other workstream started, and on a shared WSL2
# host that is somebody else's run. Each forwarder's pid is recorded under RUNTIME_DIR and `down`
# stops only those, verifying that the pid still belongs to a kubectl before signalling it.
#
# STREAMS AND EXIT CODES
# One line per forwarder on stdout; diagnostics on stderr. Exit 0 when the requested action
# completed for all three, 1 otherwise. `up` is idempotent: an already-live forwarder is left alone.
# Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# The remaining three URLs in scripts/live_env.sh, and every live run's Guardian, Prometheus and
# Locust access. scripts/live_env.sh separately exports the in-cluster frontend Service URL because
# that endpoint is intentionally not a host port-forward.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

runtime_dir=${PORT_FORWARD_RUNTIME_DIR:-$repo_root/runs/.port-forward}

# name | namespace | target | local port | remote port. The one place the three are written down.
forwards="guardian|guardian|svc/guardian|${GUARDIAN_LOCAL_PORT:-8080}|8080
prometheus|observability|svc/prometheus-server|${PROMETHEUS_LOCAL_PORT:-9090}|80
locust|locust|svc/locust|${LOCUST_LOCAL_PORT:-8089}|8089"

pid_file() { printf '%s/%s.pid\n' "$runtime_dir" "$1"; }

# True when the recorded pid is alive AND is a kubectl. The second half is what keeps `down` from
# signalling an unrelated process that inherited a recycled pid.
forwarder_alive() {
    _pf_name=$1 _pf_local=$2 _pf_remote=$3
    _pf_file=$(pid_file "$_pf_name")
    [ -f "$_pf_file" ] || return 1
    _pf_pid=$(cat "$_pf_file" 2>/dev/null || true)
    [ -n "$_pf_pid" ] || return 1
    kill -0 "$_pf_pid" 2>/dev/null || return 1
    _pf_cmd=$(ps -o args= -p "$_pf_pid" 2>/dev/null || true)
    case "$_pf_cmd" in
        *kubectl*port-forward*"$_pf_local:$_pf_remote"*) return 0 ;;
        *) return 1 ;;
    esac
}

port_answers() {
    # A TCP connect, not an HTTP request: Locust and Prometheus disagree about what a bare GET / is
    # worth, and readiness of the *forward* is what this asks about.
    "${PYTHON:-python3}" - "$1" <<'PY' 2>/dev/null
import socket, sys
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close()
except OSError:
    raise SystemExit(1)
PY
}

start_one() {
    _name=$1 _ns=$2 _target=$3 _local=$4 _remote=$5
    if forwarder_alive "$_name" "$_local" "$_remote" && port_answers "$_local"; then
        printf '%-11s already live on 127.0.0.1:%s\n' "$_name" "$_local"
        return 0
    fi
    rm -f "$(pid_file "$_name")"
    mkdir -p "$runtime_dir"
    nohup kubectl -n "$_ns" port-forward "$_target" "$_local:$_remote" \
        >"$runtime_dir/$_name.log" 2>&1 &
    printf '%s\n' "$!" >"$(pid_file "$_name")"
    _pf_waited=0
    while [ "$_pf_waited" -lt 60 ]; do
        if port_answers "$_local"; then
            printf '%-11s 127.0.0.1:%-5s -> %s/%s:%s\n' "$_name" "$_local" "$_ns" "$_target" "$_remote"
            return 0
        fi
        forwarder_alive "$_name" "$_local" "$_remote" || break
        sleep 1
        _pf_waited=$((_pf_waited + 1))
    done
    printf 'port-forward: %s never answered on 127.0.0.1:%s; see %s/%s.log\n' \
        "$_name" "$_local" "$runtime_dir" "$_name" >&2
    return 1
}

stop_one() {
    # _remote ($5) is read because forwarder_alive matches on "$_local:$_remote"; without it the
    # liveness glob degrades to "<local>:" and can match a forward on the same local port to a
    # different remote. The other _one helpers take the full (name, ns, target, local, remote).
    _name=$1 _local=$4 _remote=$5
    _pf_file=$(pid_file "$_name")
    if forwarder_alive "$_name" "$_local" "$_remote"; then
        kill "$(cat "$_pf_file")" 2>/dev/null || true
        printf '%-11s stopped\n' "$_name"
    else
        printf '%-11s was not running\n' "$_name"
    fi
    rm -f "$_pf_file"
}

status_one() {
    _name=$1 _local=$4 _remote=$5
    if forwarder_alive "$_name" "$_local" "$_remote" && port_answers "$_local"; then
        printf '%-11s LIVE    127.0.0.1:%s\n' "$_name" "$_local"
    elif forwarder_alive "$_name" "$_local" "$_remote"; then
        printf '%-11s STARTED 127.0.0.1:%s (not answering)\n' "$_name" "$_local"
        return 1
    else
        printf '%-11s DOWN    127.0.0.1:%s\n' "$_name" "$_local"
        return 1
    fi
}

action=${1:-status}
case "$action" in up|down|status) ;; *)
    echo "port-forward: usage: sh scripts/port_forward.sh up|down|status" >&2; exit 1 ;;
esac

failures=0
old_ifs=$IFS
IFS='
'
for row in $forwards; do
    IFS='|'
    # shellcheck disable=SC2086 -- deliberate field split of the pipe-separated row
    set -- $row
    IFS=$old_ifs
    case "$action" in
        up) start_one "$@" || failures=$((failures + 1)) ;;
        down) stop_one "$@" ;;
        status) status_one "$@" || failures=$((failures + 1)) ;;
    esac
    IFS='
'
done
IFS=$old_ifs

if [ "$action" = "down" ]; then
    printf 'port-forward: PASS -- every forwarder this script started is stopped\n'
    exit 0
fi
if [ "$failures" -ne 0 ]; then
    printf 'port-forward: FAIL -- %s of 3 forwarders are not answering\n' "$failures" >&2
    exit 1
fi
printf 'port-forward: PASS -- all 3 forwarders answering\n'
