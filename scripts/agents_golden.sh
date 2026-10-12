#!/bin/sh
# agents_golden.sh — the golden-path gate (`make agents-golden`).
#
# WHAT THIS GATE IS
# docs/milestones/M4-agents.md's first Definition-of-done item: the golden path completes, with
# per-phase spans and verbatim messages captured [T-05, T-14 golden]. This script runs S1-HIER
# through the four docs/02-architecture.md section 1.6 phases against a real Guardian, writes the
# artefacts, and then CHECKS them — four phase spans present in order, a messages record for every
# model call, and a tokens entry naming the exact provider string for each. `make agents-golden`
# delegates here, as docs/04-repo-conventions.md section 1 requires of every gate.
#
# IT RUNS S1-HIER x G0-FULL AND NOTHING ELSE, AND TAKES NO CONDITION PARAMETER
# Conflict M4-C8's resolution, and it is a deliberate absence rather than an oversight. ADR-023 puts
# every condition flag in the runner's hands and forbids anything under agents/ from reaching one,
# and docs/04-repo-conventions.md section 3 fixes this target's signature as taking no parameters.
# A MODE= or COND= variable here would be exactly the reach that rule refuses. The G1-LOGONLY and
# G3-UNQUOTED arms are exercised by agents/tests/test_flag_exercise.py, which drives the SAME graph
# against a Guardian started with a different GUARDIAN_MODE and against differently quoted evidence
# — the same mechanism M6's runner will use, so nothing about it changes when the runner arrives.
#
# THE THREE TIERS, AND WHY THIS SCRIPT REFUSES RATHER THAN DEGRADES
# docs/plans/M4-implementation-plan.md splits M4's verification three ways because collapsing them
# would let "no provider key yet" masquerade as "blocked on Docker":
#
#   Tier A   offline — no network, no Docker, no credential, no token spent. The whole agents/tests
#            suite, including agents/tests/test_golden_path.py, which drives this same driver
#            against an in-process Guardian with a scripted model.
#   Tier A'  needs a provider credential only. THIS SCRIPT with no --script: live dev-tier inference
#            through the LiteLLM alias, the exact provider string recorded per call, and risk R-10
#            measured — whether the free model emits well-formed tool calls, at what retry rate.
#   Tier B   needs the gated Docker Desktop WSL2-integration setting: the same run against a
#            Guardian that actually mutates a cluster, with Langfuse and the OTel collector.
#
# So this script requires a reachable Guardian and a resolved model, and it REFUSES with a named
# prerequisite when either is absent. It does not fall back to a scripted model and it does not
# start a Guardian of its own with a fake executor: either would produce a green `make agents-golden`
# that proved something weaker than the Definition of done asks for, and the whole point of naming
# three tiers is that a tier's evidence says which tier produced it.
#
# WHY THE GUARDIAN IS A URL AND NOT SOMETHING THIS SCRIPT STARTS
# guardian/ is the sole credential holder. Starting it needs a signing key, a policy bundle, an opa
# binary and an executor choice — all of which are deployment concerns that the guardian-first
# iron rule (AGENTS.md 1) keeps out of the agent layer's reach, and agents/golden.py imports nothing from guardian/ for the same
# reason. GUARDIAN_URL names an already-running Guardian: `python -m guardian.app` locally at
# Tier A', or the deployed Service at Tier B. The refusal message below states exactly what to set.
#
# INTERPRETER SELECTION
# $PYTHON if set, else python3, else python — the same order scripts/parity_check.sh and
# scripts/install_runtime_deps.sh use, and the last fallback is what makes this work on the Windows
# development host where Git for Windows provides sh but the interpreter on PATH is `python`.
#
# UNLIKE THE PARITY GATE, THIS ONE NEEDS THE PINNED RUNTIME SET
# parity_check.sh runs in a CI job that installs nothing, so agents/registry/ is standard-library
# only. This script is not in that job — it is not in ci.yml at all, because it needs a credential
# and a service that no runner has — and it does need LiteLLM. It says so, naming
# scripts/install_runtime_deps.sh, rather than failing on an ImportError traceback. ADR-025's
# discipline: a gate reports what it needs and where the pin lives.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options — so it runs under dash in WSL2 Ubuntu, under
# Git Bash on the Windows host, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

# --- parameters, every one overridable and every one defaulted to something honest --------------
#
# These are environment variables rather than target parameters because section 3 fixes
# `make agents-golden` as taking none. They are not condition flags: none of them selects an arm,
# and GUARDIAN_MODE is deliberately absent from this list — the Guardian's arm is set where the
# Guardian is started, which is not here.
CONDITION="S1-HIER"
OUT_ROOT=${AGENTS_GOLDEN_OUT:-runs/.golden}
NAMESPACE=${AGENTS_GOLDEN_NAMESPACE:-boutique}
# The evidence the golden path reasons over. A Monitor fixture at Tier A', a live aggregator's
# emitted stream at Tier B — the same bytes either way, which is what keeps the two comparable.
# M5 owns the scenario library; this is one incident, not a corpus.
EVIDENCE=${AGENTS_GOLDEN_EVIDENCE:-monitor/fixtures/four-source-incident/expected/monitor_events.jsonl}
# The run identifier must match what the Guardian was started with: guardian.rego's permit rule
# requires scope.run_consistent, so a mismatch is denied on every action rather than on the first.
RUN_ID=${GUARDIAN_RUN_ID:-RUN-G0-FULL-SCN01-INJA-S07}
SEED=${AGENTS_GOLDEN_SEED:-7}
# Tier B opts into the collector explicitly. The endpoint is not a credential; agents send no
# authorization header, while the collector alone owns LANGFUSE_OTLP_AUTH (ADR-032).
SPAN_EXPORTER=${AGENTS_SPAN_EXPORTER:-file}
OTLP_TRACES_ENDPOINT=${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT:-http://127.0.0.1:4318/v1/traces}

interpreter=""
if [ -n "${PYTHON-}" ]; then
    interpreter=$PYTHON
elif command -v python3 >/dev/null 2>&1; then
    interpreter=python3
elif command -v python >/dev/null 2>&1; then
    interpreter=python
fi

if [ -z "$interpreter" ]; then
    echo "agents-golden: no Python interpreter found. Set PYTHON to the interpreter to use." >&2
    exit 1
fi

PYTHONIOENCODING=utf-8
export PYTHONIOENCODING
PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH

# --- prerequisite: the driver imports ---------------------------------------------------------
if ! "$interpreter" -c 'import agents.golden' >/dev/null 2>&1; then
    echo "agents-golden: $interpreter cannot import agents.golden." >&2
    echo "agents-golden: Install the pinned runtime set for this component:" >&2
    echo "agents-golden:     sh scripts/install_runtime_deps.sh agents" >&2
    echo "agents-golden: Or point this gate at an interpreter that already has it:" >&2
    echo "agents-golden:     PYTHON=<path> make agents-golden" >&2
    exit 1
fi

# --- --issuers: print the registered-issuer set this condition needs, and stop -----------------
# A subcommand rather than a separate script, because the set is a property of the composition
# manifest and the person who needs it is the person about to start a Guardian for this run. It is
# answered BEFORE the Guardian check below, because the only caller is somebody who has not started
# one yet -- the refusal message quotes this very invocation, so requiring a Guardian to ask which
# issuers a Guardian needs would be a loop nobody could get out of.
if [ "${1-}" = "--issuers" ]; then
    exec "$interpreter" -c "
from agents.golden import registered_issuers
from agents.registry.loader import load_registry
print(','.join(registered_issuers(load_registry().compositions['$CONDITION'])))
"
fi

# --- prerequisite: a reachable Guardian --------------------------------------------------------
if [ -z "${GUARDIAN_URL-}" ]; then
    echo "agents-golden: PREREQUISITE ABSENT — GUARDIAN_URL is not set." >&2
    echo "agents-golden: This gate is Tier A'/Tier B: it drives the agent layer against a REAL" >&2
    echo "agents-golden: Guardian over HTTP. It does not start one, because guardian/ is the sole" >&2
    echo "agents-golden: credential holder and assembling it from here is the coupling" >&2
    echo "agents-golden: the guardian-first iron rule (AGENTS.md 1) forbids." >&2
    echo "agents-golden:" >&2
    echo "agents-golden: Start one and point this at it, with its run id matching RUN_ID above:" >&2
    echo "agents-golden:     GUARDIAN_MODE=G0-FULL GUARDIAN_RUN_ID=$RUN_ID \\" >&2
    echo "agents-golden:     GUARDIAN_REGISTERED_ISSUERS=\"\$(sh scripts/agents_golden.sh --issuers)\" \\" >&2
    echo "agents-golden:     GUARDIAN_SIGNING_KEY=... GUARDIAN_POLICY_BUNDLE_PATH=guardian/policies \\" >&2
    echo "agents-golden:     GUARDIAN_EXECUTOR=kubernetes python -m guardian.app" >&2
    echo "agents-golden:     GUARDIAN_URL=http://127.0.0.1:8080 make agents-golden" >&2
    echo "agents-golden:" >&2
    echo "agents-golden: The offline half of this evidence is agents/tests/test_golden_path.py," >&2
    echo "agents-golden: which drives the same driver against an in-process Guardian at Tier A." >&2
    exit 1
fi

# --- prerequisite: the model alias resolves ----------------------------------------------------
if ! "$interpreter" -c 'from agents.registry.model import resolve_provider_string; resolve_provider_string()' >/dev/null 2>&1; then
    echo "agents-golden: PREREQUISITE ABSENT — MODEL_PROVIDER_STRING does not resolve." >&2
    echo "agents-golden: This gate calls the model for real. ADR-005 fixes the dev/pilot tier and" >&2
    echo "agents-golden: infra/versions.env pins the provider string; a run that could not name" >&2
    echo "agents-golden: its model would produce a bundle nobody can reproduce (risk R-01), so" >&2
    echo "agents-golden: there is no default and no fallback." >&2
    echo "agents-golden:" >&2
    echo "agents-golden: Set it from the pin, and put the provider credential in .env:" >&2
    echo "agents-golden:     MODEL_PROVIDER_STRING=\$(grep '^MODEL_PROVIDER_STRING=' infra/versions.env | cut -d= -f2-)" >&2
    exit 1
fi

if [ ! -f "$EVIDENCE" ]; then
    echo "agents-golden: the evidence stream $EVIDENCE does not exist." >&2
    echo "agents-golden: Set AGENTS_GOLDEN_EVIDENCE to a file of emitted EvidenceEvent JSON" >&2
    echo "agents-golden: objects, one per line — a Monitor fixture, or a live aggregator's output." >&2
    exit 1
fi

# --- the run -----------------------------------------------------------------------------------
out="$OUT_ROOT/$CONDITION"
rm -rf "$out"
mkdir -p "$out"

echo "agents-golden: condition   $CONDITION"
echo "agents-golden: guardian    $GUARDIAN_URL"
echo "agents-golden: evidence    $EVIDENCE"
echo "agents-golden: artefacts   $out"

"$interpreter" -m agents.golden \
    --guardian-url "$GUARDIAN_URL" \
    --out "$out" \
    --condition "$CONDITION" \
    --run-id "$RUN_ID" \
    --executor-id "executor-$RUN_ID" \
    --namespace "$NAMESPACE" \
    --seed "$SEED" \
    --evidence "$EVIDENCE" \
    --span-exporter "$SPAN_EXPORTER" \
    --otlp-traces-endpoint "$OTLP_TRACES_ENDPOINT"

# --- the checks --------------------------------------------------------------------------------
# The driver already refuses when the four phases were not traversed. What is checked here is the
# artefact rather than the run: the Definition of done is about what a reader can open afterwards,
# and a driver that ran correctly but wrote nothing would satisfy neither T-05 nor T-14.
"$interpreter" - "$out" <<'PYCHECK'
import json
import sys
from pathlib import Path

from agents.registry import PHASES

out = Path(sys.argv[1])
problems = []


def read_lines(name):
    path = out / name
    if not path.exists():
        problems.append(f"{name} was not written")
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_spans():
    path = out / "spans.otel.json"
    if not path.exists():
        problems.append("spans.otel.json was not written")
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    spans = document.get("spans") if isinstance(document, dict) else None
    if not isinstance(spans, list) or not all(isinstance(span, dict) for span in spans):
        problems.append("spans.otel.json is not a JSON object carrying a spans array")
        return []
    return spans


spans = read_spans()
messages = read_lines("messages.jsonl")
tokens = json.loads((out / "tokens.json").read_text(encoding="utf-8")) if (out / "tokens.json").exists() else []

# T-05's actual wording is "four phase spans present IN ORDER", so order is asserted and not
# membership. A run that visited containment before detection would satisfy a set comparison.
phase_spans = [span["attributes"]["phase"] for span in spans if span["name"] == "phase"]
if tuple(phase_spans) != tuple(PHASES):
    problems.append(
        f"phase spans are {phase_spans!r}; expected the four section 1.6 phases in order {list(PHASES)!r}"
    )

# Every node span must sit inside its phase span. A flat trace would carry the same span names and
# tell a reader nothing about which phase a node ran in.
by_id = {span["span_id"]: span for span in spans}
for span in spans:
    if span["name"] != "node":
        continue
    parent = by_id.get(span["parent_id"] or "")
    if parent is None or parent["name"] != "phase":
        problems.append(f"node span {span['span_id']} is not nested inside a phase span")

if not messages:
    problems.append("messages.jsonl is empty: no model call was recorded verbatim")

# One tokens entry per model call, each naming the model that ANSWERED rather than the alias asked
# for. data-management.md requires the exact model identity per call, and risk R-01 is that the
# alias and the model stop being the same thing without anybody noticing.
if len(tokens) != len(messages):
    problems.append(f"{len(tokens)} tokens entr(y/ies) for {len(messages)} model call(s)")
for entry in tokens:
    model = entry.get("model", "")
    if not model or "/" not in model:
        problems.append(f"tokens entry {entry.get('index')} carries model {model!r}, not a provider string")

if problems:
    for problem in problems:
        print(f"agents-golden: {problem}", file=sys.stderr)
    print(f"agents-golden: FAIL — {len(problems)} problem(s)", file=sys.stderr)
    raise SystemExit(1)

print(
    f"agents-golden: PASS — {len(phase_spans)} phase span(s) in order, {len(spans)} span(s), "
    f"{len(messages)} verbatim message(s), {len(tokens)} tokens entr(y/ies)"
)
PYCHECK
