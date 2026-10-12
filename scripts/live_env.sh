#!/bin/sh
# live_env.sh -- compose the complete environment a live framework-on run needs. SOURCE this file.
#
# WHAT THIS SCRIPT IS
# `runner/live_run.py`'s `dependencies_from_environment()` fails closed on an incomplete
# environment, by design: every live adapter is built from explicit configuration and none is
# guessed. That leaves the operator holding roughly twenty variables, which until now lived in an
# ad-hoc shell line that nobody could review and nobody could reproduce. This file is that line,
# written down.
#
#     . scripts/live_env.sh          # from a WSL2 shell, at the repository root
#     make run COND=... SCN=... INJ=... SEED=... CAMP=...
#
# It is sourced rather than executed: its whole product is exported variables. It prints one
# summary line to stderr and never prints a value that could be a credential.
#
# WHERE EACH NUMBER COMES FROM, AND WHY NONE IS WRITTEN HERE
# The five Guardian capability-token settings are owned by docs/protocols/security-policy.md
# section 2. This file does not restate them -- `the source-of-truth iron rule (AGENTS.md 1)` forbids a
# second copy with a value -- it evaluates `scripts/security_params.py`, which extracts them from
# that section and fails loudly if the wording moves. Cluster coordinates come from the live
# kubeconfig. Host-forwarded service ports come from `scripts/port_forward.sh`, which is the one place that knows
# which three host-reached services a run uses and on which local ports.
#
# THE THREE EVIDENCE PATHS
# MONITOR_EVENTS_PATH, GUARDIAN_AUDIT_PATH and (optionally) ASSERTIONS_PATH are the three
# runtime-owned files `live_run.py` refuses to synthesise. Two of them need a producer step before
# the runner can read them, and this file names both:
#
#   * MONITOR_EVENTS_ROOT points at the live aggregator's per-request event tree. The aggregator is
#     content-addressed, so it writes one `monitor_events.jsonl` fragment per accepted ingestion;
#     `runner/live_evidence.py` collates that tree into the single stream at MONITOR_EVENTS_PATH.
#     The tree is visible on this host because infra/kind-config.yaml mounts the repository's
#     `monitor/runtime/evidence` into both kind nodes as /var/lib/overwatch/evidence, which is the
#     same hostPath monitor/deploy/deployment.yaml mounts into the aggregator pod.
#
#   * GUARDIAN_AUDIT_WORKLOAD turns on the read-out of the Guardian's audit log, which lives on a
#     PVC inside the Guardian pod and stays there: security-policy.md section 1.2 makes the
#     Guardian the sole holder of anything with cluster-mutation rights, and the extraction uses
#     THIS operator's kubeconfig, never the Guardian's ServiceAccount token or signing key.
#
#   * ASSERTIONS_PATH is deliberately left unset. `live_run.py` evaluates assertions itself at run
#     end when it is unset, which is what data-management.md section 3 asks for; set it only to
#     substitute an external evaluator.
#
# WHAT BREAKS IF THIS FILE CHANGES
# Every live run's configuration. It is the operator-facing counterpart of
# `dependencies_from_environment()`; if a variable is added there, it is added here.

if [ -n "${BASH_SOURCE:-}" ] && [ "${BASH_SOURCE}" = "${0}" ]; then
    echo "live-env: source this file, do not execute it: . scripts/live_env.sh" >&2
    exit 1
fi

LC_ALL=C
export LC_ALL

# Sourced files must not leave the caller's shell in -e/-u, and must not cd it anywhere, so the
# repository root is resolved without moving and every step reports rather than aborts.
_live_env_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE:-scripts/live_env.sh}")/.." && pwd)
_live_env_fail=0

# Resolve a Python that can actually RUN a framework-on run, not merely the first that exists. The
# VM mirror carries a repository .venv built on Windows ([[vm-mirror-sync]]); it is executable and --
# after a re-sync -- can import agents/, but it is missing `cryptography`, and an existence- or
# agents-only check would export a PYTHON on which the seal-stage F-GD-01 signature verify (class T,
# needs cryptography for the Ed25519 public key) fails closed: the run seals with a spurious class-T
# failure rather than a clean one. So the probe requires BOTH imports -- `agents` (the graph) and
# `cryptography` (the audit signature verify F-GD-01 loads the public key with) -- and falls through
# to the next candidate when either is missing. An explicit PYTHON is honoured as given.
_live_env_python=${PYTHON:-}
if [ -z "$_live_env_python" ]; then
    for _live_env_candidate in "$_live_env_root/.venv/bin/python" \
        "$HOME/.venvs/agentic-overwatch/bin/python" python3 python; do
        command -v "$_live_env_candidate" >/dev/null 2>&1 || continue
        if PYTHONPATH="$_live_env_root${PYTHONPATH:+:$PYTHONPATH}" "$_live_env_candidate" \
            -c "import agents, cryptography" >/dev/null 2>&1; then
            _live_env_python="$_live_env_candidate"
            break
        fi
    done
    if [ -z "$_live_env_python" ]; then
        echo "live-env: no Python can import the project AND cryptography (tried .venv, ~/.venvs/agentic-overwatch, python3); the seal-stage F-GD-01 signature verify needs cryptography -- set PYTHON to a venv that has both" >&2
        _live_env_fail=1
        _live_env_python=python3
    fi
fi
PYTHON=$_live_env_python
export PYTHON

# --- cluster coordinates ---------------------------------------------------------------------
KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
KUBE_CONTEXT=${KUBE_CONTEXT:-$(kubectl config current-context 2>/dev/null || true)}
if [ -z "$KUBE_CONTEXT" ]; then
    echo "live-env: no current kubectl context and KUBE_CONTEXT is unset" >&2
    _live_env_fail=1
fi
export KUBECONFIG KUBE_CONTEXT

# --- the port-forwarded endpoints ------------------------------------------------------------
# The ports are the ones scripts/port_forward.sh binds; that script is the single place naming the
# services. Overridable so a second operator on the same host can shift the whole block.
GUARDIAN_URL=${GUARDIAN_URL:-http://127.0.0.1:${GUARDIAN_LOCAL_PORT:-8080}}
PROMETHEUS_URL=${PROMETHEUS_URL:-http://127.0.0.1:${PROMETHEUS_LOCAL_PORT:-9090}}
LOCUST_URL=${LOCUST_URL:-http://127.0.0.1:${LOCUST_LOCAL_PORT:-8089}}
export GUARDIAN_URL PROMETHEUS_URL LOCUST_URL

# The SLO probe runs INSIDE the cluster since ADR-085 (B3): it hits the frontend Service by cluster
# DNS from a probe Pod, with no port-forward on the measurement path, so an eradication that replaces
# the served pod no longer reads as an outage. FRONTEND_URL is therefore the in-cluster Service URL,
# NOT a 127.0.0.1 port-forward -- runner/live_run.py reads it as probe_writer's base_url, and a
# loopback value here would send every probe at a dead local port. port_forward.sh no longer binds a
# frontend forward. Override only to a URL reachable from inside the cluster.
FRONTEND_URL=${FRONTEND_URL:-http://frontend.boutique.svc.cluster.local}
export FRONTEND_URL

# --- the three evidence paths ------------------------------------------------------------------
# The aggregator's MONITOR_DATA_DIR is /var/lib/overwatch/evidence/aggregator inside the pod
# (monitor/deploy/config.yaml); the same bytes are here, through the kind extraMount.
# scripts/up.sh records the directory it mounted when it created the cluster; reading that record
# keeps the runner on the same bytes the aggregator writes even when OVERWATCH_EVIDENCE_DIR moved
# the mount off the repository path.
if [ -z "${MONITOR_RUNTIME_DIR:-}" ] && [ -f "$_live_env_root/runs/.cluster-evidence-dir" ]; then
    MONITOR_RUNTIME_DIR=$(tr -d '\r' < "$_live_env_root/runs/.cluster-evidence-dir" | head -n 1)
fi
MONITOR_RUNTIME_DIR=${MONITOR_RUNTIME_DIR:-$_live_env_root/monitor/runtime/evidence}
MONITOR_EVENTS_ROOT=${MONITOR_EVENTS_ROOT:-$MONITOR_RUNTIME_DIR/aggregator/events}
# The collated stream and the extracted audit log are staged under runs/, in a dot-directory, which
# is where live_run.py already puts the runner's other working state (RUNNER_INJECTION_DIR and
# RUNNER_PRIVATE_DIR default to runs/.injection and runs/.private). runs/ is gitignored whole, a
# dot-directory is not a campaign, and the bundle walkers address a bundle as <campaign>/<run-id>,
# so staged bytes cannot be mistaken for evidence.
RUNNER_STAGING_DIR=${RUNNER_STAGING_DIR:-$_live_env_root/runs/.staging}
MONITOR_EVENTS_PATH=${MONITOR_EVENTS_PATH:-$RUNNER_STAGING_DIR/monitor_events.jsonl}
GUARDIAN_AUDIT_PATH=${GUARDIAN_AUDIT_PATH:-$RUNNER_STAGING_DIR/guardian_audit.jsonl}
# ADR-137: the kube-apiserver audit log the runner slices k8s_api_audit.jsonl from. It is the
# audit-log-path infra/kind-config.yaml gives the API server, /var/lib/overwatch/evidence/k8s_audit.jsonl
# on the control-plane node, host-visible on the same evidence extraMount MONITOR_RUNTIME_DIR names --
# so it sits beside the aggregator tree at MONITOR_RUNTIME_DIR/k8s_audit.jsonl. runner/live_run.py
# requires it: a framework-on run cannot corroborate its executions (F-GD-03/F-GD-06) without it.
K8S_API_AUDIT_LOG=${K8S_API_AUDIT_LOG:-$MONITOR_RUNTIME_DIR/k8s_audit.jsonl}
mkdir -p "$RUNNER_STAGING_DIR" || _live_env_fail=1
export MONITOR_RUNTIME_DIR MONITOR_EVENTS_ROOT RUNNER_STAGING_DIR MONITOR_EVENTS_PATH
export GUARDIAN_AUDIT_PATH K8S_API_AUDIT_LOG

# Turns on the read-out in runner/live_evidence.py. Namespace, workload and container match
# guardian/deploy/deployment.yaml. GUARDIAN_AUDIT_REMOTE_PATH is the audit volume's mountPath
# there, not a log file: runner/live_run.py names each attempt's own chain beneath it,
# <run-id>-<attempt suffix>.jsonl, hands that path to scripts/guardian_deploy.sh as
# GUARDIAN_AUDIT_LOG_PATH, and extracts exactly the path it recorded (ADR-058).
# scripts/guardian_deploy.sh refuses a chain anywhere else.
GUARDIAN_AUDIT_NAMESPACE=${GUARDIAN_AUDIT_NAMESPACE:-guardian}
GUARDIAN_AUDIT_WORKLOAD=${GUARDIAN_AUDIT_WORKLOAD:-deployment/guardian}
GUARDIAN_AUDIT_CONTAINER=${GUARDIAN_AUDIT_CONTAINER:-guardian}
GUARDIAN_AUDIT_REMOTE_PATH=${GUARDIAN_AUDIT_REMOTE_PATH:-/var/lib/guardian/audit}
export GUARDIAN_AUDIT_NAMESPACE GUARDIAN_AUDIT_WORKLOAD GUARDIAN_AUDIT_CONTAINER
export GUARDIAN_AUDIT_REMOTE_PATH

# --- Guardian control-plane authentication (ADR-128, M10) ---------------------------------------
# The identity the runner authenticates AS on POST /v1/tokens and POST /v1/phase, and the audience
# the Guardian's ControlPlaneAuthenticator (guardian/app/control_auth.py) requires. These are fixed
# deployment identities, not secrets: they must match guardian/deploy/rbac.yaml's runner-control-plane
# ServiceAccount (namespace guardian) and security-policy.md section 2.1. Defaulted here and
# overridable only for a non-default Guardian namespace. guardian_deploy.sh forwards both into the
# Guardian's configmap, where config.py `_require_text`s them (no default) -- so an unset value here
# is a Guardian that will not start, which is the safe failure.
GUARDIAN_CONTROL_PLANE_SUBJECT=${GUARDIAN_CONTROL_PLANE_SUBJECT:-system:serviceaccount:guardian:runner-control-plane}
GUARDIAN_CONTROL_PLANE_AUDIENCE=${GUARDIAN_CONTROL_PLANE_AUDIENCE:-guardian-control-plane}
export GUARDIAN_CONTROL_PLANE_SUBJECT GUARDIAN_CONTROL_PLANE_AUDIENCE

# --- Guardian audit-chain signature verification (ADR-130, M10) ---------------------------------
# The Ed25519 audit chain has two keys. The PRIVATE key is a Secret the Guardian mounts and signs
# with (guardian/deploy/deployment.yaml, guardian-audit-signing-key); the operator creates it out of
# band and it never leaves the cluster (rule 4, rule 10). The PUBLIC key is what the M10 fidelity gate
# check F-GD-01 verifies the chain against, read from GUARDIAN_AUDIT_PUBLIC_KEY as a PEM file path. It
# is passed through, never defaulted: the runner must not invent a key, and an unset value makes
# F-GD-01 SKIP the signature half (naming this variable) rather than claim an unverified pass. Set it
# to the public key matching the deployed private one to make the campaign's chains signature-checked.
#   openssl pkey -in audit-signing-key.pem -pubout -out audit-public-key.pem   # from the private key
GUARDIAN_AUDIT_PUBLIC_KEY=${GUARDIAN_AUDIT_PUBLIC_KEY:-}
export GUARDIAN_AUDIT_PUBLIC_KEY
if [ -z "$GUARDIAN_AUDIT_PUBLIC_KEY" ]; then
    echo "live-env: GUARDIAN_AUDIT_PUBLIC_KEY is unset; F-GD-01 will not verify audit signatures" >&2
    echo "live-env: set it to the PEM public key matching guardian-audit-signing-key (ADR-130)" >&2
fi

# ASSERTIONS_PATH stays unset on purpose; see the header. `unset` rather than empty, because
# live_run.py treats an empty value as absent but a stale export from an earlier shell as present.
unset ASSERTIONS_PATH 2>/dev/null || true

# --- runner working directories ----------------------------------------------------------------
# RUNNER_INJECTION_DIR and RUNNER_PRIVATE_DIR are deliberately NOT set: live_run.py defaults them to
# runs/.injection and runs/.private, and a second opinion here would only be a second thing to keep
# in step. RUNNER_PRIVATE_DIR holds the G2 arm's issued token file, so its mode is tightened here
# rather than left to the umask of whoever ran first.
mkdir -p "$_live_env_root/runs/.private" || _live_env_fail=1
chmod 700 "$_live_env_root/runs/.private" 2>/dev/null || true

# --- Guardian capability-token settings, read from the protocol --------------------------------
_live_env_params=$("$PYTHON" "$_live_env_root/scripts/security_params.py") || _live_env_fail=1
if [ -n "$_live_env_params" ]; then
    eval "$_live_env_params"
    export GUARDIAN_TOKEN_TTL_SECONDS GUARDIAN_TOKEN_MAX_TTL_SECONDS GUARDIAN_TOKEN_ALGORITHM
    export GUARDIAN_REPLAY_CACHE_ENTRIES GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS
fi

# --- model configuration -----------------------------------------------------------------------
# MODEL_PROVIDER_STRING and MODEL_ALIAS are read from infra/versions.env, which is their single
# home (AGENTS.md iron rule; ADR-005 fixes the alias by name). They are read rather than restated:
# a literal here would be a second home for a pin every sealed bundle records in
# versions_env_sha256. agents/registry/model.py fails closed when the provider string is unset --
# "a run that could not name its model would produce a bundle nobody can reproduce" (risk R-01) --
# and that failure lands at the FIRST model call, which is after the Monitor export, so a run can
# get most of the way through before it surfaces. Exporting them here is what stops that.
for _live_env_pin in MODEL_PROVIDER_STRING MODEL_ALIAS; do
    if [ -z "$(eval "printf '%s' \"\${$_live_env_pin:-}\"")" ]; then
        _live_env_value=$(sed -n "s/^${_live_env_pin}=//p" "$_live_env_root/infra/versions.env" \
            | tr -d '\r' | head -n 1)
        if [ -n "$_live_env_value" ]; then
            eval "${_live_env_pin}=\$_live_env_value"
        else
            echo "live-env: ${_live_env_pin} is absent from infra/versions.env" >&2
            _live_env_fail=1
        fi
    fi
done
export MODEL_PROVIDER_STRING MODEL_ALIAS
unset _live_env_pin _live_env_value

# The provider credential lives in .env, which is gitignored and is the only place a secret may
# sit (AGENTS.md iron rule 4). dev_llm_env.sh maps it onto LiteLLM's OpenAI-compatible variables
# but does nothing when DEV_LLM_KEY is not already in the environment, so .env is sourced
# first. `set -a` is scoped to this block and restored immediately: leaving the caller's shell in
# allexport is exactly the side effect the header promises this file does not have.
if [ -f "$_live_env_root/.env" ]; then
    set -a
    . "$_live_env_root/.env"
    set +a
fi

# The credential mapping lives in its own file and never prints; sourcing it here keeps the
# operator to one command.
if [ -f "$_live_env_root/scripts/dev_llm_env.sh" ]; then
    . "$_live_env_root/scripts/dev_llm_env.sh"
fi

# The credential is checked for PRESENCE only, and never printed. It is a warning rather than a
# failure because the offline and Monitor-only paths need no model at all; the run that does need
# one refuses on its own. Warning here turns a failure that arrives after the whole infrastructure
# phase into one the operator sees before the run starts.
if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "live-env: no provider credential in the environment; set DEV_LLM_KEY in .env" >&2
    echo "live-env: the infrastructure phase will run and the first model call will then refuse" >&2
fi
if [ -z "${OPENAI_BASE_URL:-}" ]; then
    echo "live-env: no provider base URL; set DEV_LLM_BASE_URL in .env" >&2
    echo "live-env: without it LiteLLM may send the custom_openai request to the default endpoint" >&2
fi

if [ "$_live_env_fail" -eq 0 ]; then
    printf 'live-env: composed for context %s; evidence staging %s\n' \
        "$KUBE_CONTEXT" "$RUNNER_STAGING_DIR" >&2
else
    printf 'live-env: INCOMPLETE -- see the messages above; the runner will refuse to start\n' >&2
fi

unset _live_env_root _live_env_fail _live_env_python _live_env_params
