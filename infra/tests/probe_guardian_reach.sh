#!/bin/sh
#
# probe_guardian_reach.sh -- show that only the agent layer can reach the Guardian's mediation
# surface, in a way that could have come out the other way. ADR-076; traceability row T-44; the
# executable check behind docs/protocols/security-policy.md section 6's reach statement. The policy
# under test is infra/netpol/guardian-ingress.yaml.
#
# THIS IS A TIER B CHECK. IT NEEDS A LIVE CLUSTER AND MUST NEVER RUN IN ci.yml, for the reason
# infra/tests/probe_agent_to_api.sh gives for itself. pytest collects only test_*.py and *_test.py,
# so this file is not collected; nothing under infra/tests/ may import or shell out to it.
#
# WHAT IT ASSERTS, BOTH DIRECTIONS
#   1-policy-present    the NetworkPolicy exists in `guardian`, so a pass below is about this policy
#   2-agents-admitted   a pod in `agents` gets HTTP 200 from the Guardian's /healthz through its
#                       Service. This is also the positive control: image, curl, cluster DNS, the
#                       Service, the Guardian and the port all work, in the same minute as part 3
#   3-target-denied     the IDENTICAL request from a pod in the target namespace (default `boutique`,
#                       the attacker's foothold in four of the five scenarios) times out: curl exit
#                       28, the mode of a silently dropped packet. Exit 0 is an OPEN boundary; exits
#                       6 and 7 are DNS and refusal defects, not demonstrated denials
#   4-attribution       the Cilium agent on the GUARDIAN POD's node reports a 'Policy denied' drop
#                       naming the Guardian pod's IP. Ingress is enforced at the destination
#                       endpoint, so the destination's agent is the one that can see it -- the
#                       mirror image of probe_agent_to_api.sh, which reads the source's node
#   5-port-forward      the Guardian answers /healthz through a kubectl port-forward, which is how
#                       the runner and the host-side agent graph reach it
#   6-probes-healthy    the Guardian pod is still Ready with an unchanged restart count, so the
#                       kubelet's health checks were not cut off by the policy
#
# THE MONITOR READINESS RACE
#   `cilium-dbg monitor` prints its listening banner before it attaches to the agent socket, so the
#   banner alone is not readiness. scripts/netpol_proof.sh learned this as a flake. Part 3 therefore
#   repeats the denied request, bounded, until one timeout also produces this flow's drop event, and
#   only then records the verdict. If the monitor never starts, part 3 still stops at the first
#   timeout and part 4 says why it could not attribute it.
#
# STREAMS AND EXIT CODES
#   One verdict line per assertion on stdout, raw evidence indented beneath it, one summary line
#   last. Exit 0 when every assertion held, 1 otherwise, 2 when the run could not examine the
#   cluster at all. Strict POSIX sh.

set -eu
LC_ALL=C
export LC_ALL

GUARDIAN_NS="guardian"
POLICY_NAME="guardian-ingress-agents-only"
AGENT_NS="agents"
TARGET_NS="${TARGET_NS:-boutique}"
HEALTH_PATH="/healthz"
SERVICE_URL="http://guardian.${GUARDIAN_NS}.svc.cluster.local:8080${HEALTH_PATH}"
PROBE_IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.53"
PROBE_CONTAINER="probe"
AGENT_POD="guardian-reach-probe-agents"
TARGET_POD="guardian-reach-probe-target"

# Bounds, not thresholds: how long to wait for the cluster, never an experiment parameter.
READY_TIMEOUT="150s"
CURL_MAX_TIME=5
ADMIT_ATTEMPTS=6
MONITOR_ATTEMPTS=30
DENY_ATTEMPTS=10
EVIDENCE_MAX_LINES=12

work=$(mktemp -d) || exit 2
problems="$work/problems"
: > "$problems"
assert_total=0
assert_pass=0
monitor_pid=""
forward_pid=""
curl_rc=0
http_code=""

record_pass() {
    assert_total=$((assert_total + 1))
    assert_pass=$((assert_pass + 1))
    printf 'guardian-reach-probe: %s PASS — %s\n' "$1" "$2"
}

record_fail() {
    assert_total=$((assert_total + 1))
    printf 'guardian-reach-probe: %s FAIL — %s\n' "$1" "$2"
    printf '%s: %s\n' "$1" "$2" >> "$problems"
}

evidence_text() {
    printf '%s\n' "$1" | sed 's/^/    | /'
}

evidence_file() {
    if [ ! -s "$1" ]; then
        printf '    | (no output)\n'
        return 0
    fi
    sed -n "1,${EVIDENCE_MAX_LINES}p" "$1" | sed 's/^/    | /'
}

cleanup() {
    if [ -n "$monitor_pid" ]; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
        monitor_pid=""
    fi
    if [ -n "$forward_pid" ]; then
        kill "$forward_pid" 2>/dev/null || true
        wait "$forward_pid" 2>/dev/null || true
        forward_pid=""
    fi
    kubectl -n "$AGENT_NS" delete pod "$AGENT_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl -n "$TARGET_NS" delete pod "$TARGET_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

abort() {
    printf 'guardian-reach-probe: ABORT — %s\n' "$1"
    exit 2
}

command -v kubectl >/dev/null 2>&1 || abort "kubectl is not on PATH"
command -v curl >/dev/null 2>&1 || abort "curl is not on PATH (needed for the port-forward check)"
kubectl get namespace "$GUARDIAN_NS" >/dev/null 2>&1 || abort "namespace $GUARDIAN_NS does not exist"
kubectl get namespace "$AGENT_NS" >/dev/null 2>&1 || abort "namespace $AGENT_NS does not exist"
kubectl get namespace "$TARGET_NS" >/dev/null 2>&1 || abort "namespace $TARGET_NS does not exist"

guardian_pod=$(kubectl -n "$GUARDIAN_NS" get pods -l app.kubernetes.io/name=guardian \
    --field-selector=status.phase=Running -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)
[ -n "$guardian_pod" ] || abort "no running Guardian pod in $GUARDIAN_NS"
guardian_ip=$(kubectl -n "$GUARDIAN_NS" get pod "$guardian_pod" -o 'jsonpath={.status.podIP}')
guardian_node=$(kubectl -n "$GUARDIAN_NS" get pod "$guardian_pod" -o 'jsonpath={.spec.nodeName}')
restarts_before=$(kubectl -n "$GUARDIAN_NS" get pod "$guardian_pod" \
    -o 'jsonpath={.status.containerStatuses[0].restartCount}')
printf 'guardian-reach-probe: Guardian pod %s/%s is %s on node %s (restarts %s)\n' \
    "$GUARDIAN_NS" "$guardian_pod" "$guardian_ip" "$guardian_node" "$restarts_before"

# --- 1: the policy under test is present -------------------------------------------------------

if kubectl -n "$GUARDIAN_NS" get networkpolicy "$POLICY_NAME" -o yaml > "$work/policy.yaml" 2>&1; then
    record_pass "1-policy-present" "NetworkPolicy $GUARDIAN_NS/$POLICY_NAME is applied"
else
    record_fail "1-policy-present" \
        "NetworkPolicy $GUARDIAN_NS/$POLICY_NAME is absent; apply infra/netpol/guardian-ingress.yaml"
    evidence_file "$work/policy.yaml"
fi

# --- fixtures: one pod in each namespace, identical spec ---------------------------------------

make_pod() {
    kubectl apply -f - >/dev/null <<POD_MANIFEST
apiVersion: v1
kind: Pod
metadata:
  name: $2
  namespace: $1
  labels:
    app.kubernetes.io/name: $2
    app.kubernetes.io/part-of: agentic-overwatch
spec:
  terminationGracePeriodSeconds: 0
  automountServiceAccountToken: false
  # PodSecurity "restricted": the target namespace warns on anything less, and a probe that
  # needed privileges the attacker's foothold does not have would not be measuring that foothold.
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: $PROBE_CONTAINER
      image: $PROBE_IMAGE
      args:
        - pause
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
POD_MANIFEST
}

# A previous run's pods are deleted without waiting; applying over a pod still terminating fails.
kubectl -n "$AGENT_NS" delete pod "$AGENT_POD" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl -n "$TARGET_NS" delete pod "$TARGET_POD" --ignore-not-found --wait=true >/dev/null 2>&1 || true
make_pod "$AGENT_NS" "$AGENT_POD"
make_pod "$TARGET_NS" "$TARGET_POD"
kubectl -n "$AGENT_NS" wait --for=condition=Ready "pod/$AGENT_POD" --timeout="$READY_TIMEOUT" \
    >/dev/null || abort "the probe pod in $AGENT_NS never became Ready"
kubectl -n "$TARGET_NS" wait --for=condition=Ready "pod/$TARGET_POD" --timeout="$READY_TIMEOUT" \
    >/dev/null || abort "the probe pod in $TARGET_NS never became Ready"

probe_once() {
    curl_rc=0
    kubectl exec -n "$1" "$2" -c "$PROBE_CONTAINER" -- \
        curl --silent --show-error --output /dev/null --max-time "$CURL_MAX_TIME" \
        --write-out '%{http_code}' "$SERVICE_URL" > "$work/curl.out" 2> "$work/curl.err" \
        || curl_rc=$?
    http_code=$(cat "$work/curl.out" 2>/dev/null || true)
}

# --- 2: the agent layer is admitted (and the harness works) ------------------------------------

i=0
while [ "$i" -lt "$ADMIT_ATTEMPTS" ]; do
    probe_once "$AGENT_NS" "$AGENT_POD"
    [ "$curl_rc" -ne 0 ] || [ "$http_code" != "200" ] || break
    i=$((i + 1))
    sleep 2
done
if [ "$curl_rc" -eq 0 ] && [ "$http_code" = "200" ]; then
    record_pass "2-agents-admitted" \
        "a pod in $AGENT_NS reached the Guardian (HTTP 200), so the harness and the admitted path work"
    evidence_text "curl exit 0, HTTP 200, target $SERVICE_URL"
else
    record_fail "2-agents-admitted" \
        "a pod in $AGENT_NS could not reach the Guardian (curl exit $curl_rc, HTTP '$http_code')"
    evidence_file "$work/curl.err"
    evidence_text "Either in-cluster mediation is broken or the harness is; a denial in part 3 is"
    evidence_text "not evidence about policy until this passes."
fi

# --- 4 support: the drop monitor on the Guardian pod's node ------------------------------------

cilium_pod=$(kubectl -n kube-system get pods -l k8s-app=cilium \
    --field-selector "spec.nodeName=$guardian_node" \
    -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)
monitor_bin=""
if [ -n "$cilium_pod" ]; then
    if kubectl -n kube-system exec "$cilium_pod" -c cilium-agent -- cilium-dbg version \
        >/dev/null 2>&1; then
        monitor_bin="cilium-dbg"
    elif kubectl -n kube-system exec "$cilium_pod" -c cilium-agent -- cilium version \
        >/dev/null 2>&1; then
        monitor_bin="cilium"
    fi
fi
monitor_started=0
: > "$work/monitor.out"
if [ -n "$monitor_bin" ]; then
    # stdin is /dev/null on purpose. Run under `timeout` (or any wrapper that gives this script its
    # own process group) a backgrounded kubectl that touches the terminal is stopped by SIGTTIN and
    # never prints its banner, which reads exactly like a monitor that failed to start.
    kubectl -n kube-system exec "$cilium_pod" -c cilium-agent -- \
        "$monitor_bin" monitor --type drop < /dev/null > "$work/monitor.out" 2>&1 &
    monitor_pid=$!
    i=0
    while [ "$i" -lt "$MONITOR_ATTEMPTS" ]; do
        if grep -q 'Listening for events' "$work/monitor.out" 2>/dev/null; then
            monitor_started=1
            break
        fi
        i=$((i + 1))
        sleep 1
    done
fi

flow_drops() {
    grep -F 'Policy denied' "$work/monitor.out" 2>/dev/null | grep -F "$guardian_ip" \
        > "$work/drops_flow" 2>/dev/null || true
}

# --- 3: the target namespace is denied, asserted by failure MODE -------------------------------

i=0
while [ "$i" -lt "$DENY_ATTEMPTS" ]; do
    probe_once "$TARGET_NS" "$TARGET_POD"
    [ "$curl_rc" -eq 28 ] || break
    flow_drops
    if [ "$monitor_started" -ne 1 ] || [ -s "$work/drops_flow" ]; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
case "$curl_rc" in
    28)
        record_pass "3-target-denied" \
            "a pod in $TARGET_NS timed out (curl exit 28), which is how a dropped packet fails"
        evidence_text "curl exit 28 after ${CURL_MAX_TIME}s, target $SERVICE_URL"
        ;;
    0)
        record_fail "3-target-denied" \
            "THE BOUNDARY IS OPEN: a pod in $TARGET_NS got HTTP $http_code from the Guardian"
        evidence_text "security-policy.md section 6's reach statement does not hold on this cluster."
        ;;
    6)
        record_fail "3-target-denied" "curl exit 6 is a DNS failure, not a demonstrated denial"
        evidence_file "$work/curl.err"
        ;;
    7)
        record_fail "3-target-denied" \
            "curl exit 7 is a refused or unreachable connection; a policy drop gives exit 28"
        evidence_file "$work/curl.err"
        ;;
    *)
        record_fail "3-target-denied" \
            "curl exit $curl_rc is not a recognised mode; treated as unproven, never as a denial"
        evidence_file "$work/curl.err"
        ;;
esac

# --- 4: the denial is attributed to Cilium's policy engine -------------------------------------

flow_drops
if [ "$monitor_started" -ne 1 ]; then
    record_fail "4-attribution" \
        "no drop monitor ran on node $guardian_node, so the drop could not be attributed"
    evidence_text "cilium pod: ${cilium_pod:-none}; monitor binary: ${monitor_bin:-neither}"
    evidence_file "$work/monitor.out"
elif [ -s "$work/drops_flow" ]; then
    record_pass "4-attribution" \
        "the agent on $guardian_node dropped traffic to $guardian_ip with reason 'Policy denied'"
    evidence_file "$work/drops_flow"
else
    record_fail "4-attribution" \
        "the monitor on $guardian_node recorded no 'Policy denied' drop naming $guardian_ip"
    evidence_file "$work/monitor.out"
fi

# --- 5: the port-forward path still answers ----------------------------------------------------

forward_port=$((18000 + $$ % 1000))
kubectl -n "$GUARDIAN_NS" port-forward "svc/guardian" "${forward_port}:8080" \
    > "$work/forward.out" 2>&1 &
forward_pid=$!
forward_code=""
i=0
while [ "$i" -lt 15 ]; do
    forward_code=$(curl --silent --output /dev/null --max-time 3 --write-out '%{http_code}' \
        "http://127.0.0.1:${forward_port}${HEALTH_PATH}" 2>/dev/null || true)
    [ "$forward_code" != "200" ] || break
    i=$((i + 1))
    sleep 1
done
if [ "$forward_code" = "200" ]; then
    record_pass "5-port-forward" \
        "the Guardian answered /healthz through kubectl port-forward (HTTP 200)"
else
    record_fail "5-port-forward" \
        "no HTTP 200 through kubectl port-forward (last status '$forward_code'); the runner path is cut"
    evidence_file "$work/forward.out"
fi

# --- 6: the kubelet's probes were not cut off --------------------------------------------------

ready=$(kubectl -n "$GUARDIAN_NS" get pod "$guardian_pod" \
    -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
restarts_after=$(kubectl -n "$GUARDIAN_NS" get pod "$guardian_pod" \
    -o 'jsonpath={.status.containerStatuses[0].restartCount}' 2>/dev/null || true)
if [ "$ready" = "True" ] && [ "$restarts_after" = "$restarts_before" ]; then
    record_pass "6-probes-healthy" \
        "the Guardian pod is Ready with restart count unchanged at $restarts_after"
else
    record_fail "6-probes-healthy" \
        "Guardian Ready=$ready, restarts $restarts_before -> $restarts_after; health checks may be cut"
fi

if [ -s "$problems" ]; then
    printf 'guardian-reach-probe: FAIL — %s of %s assertion(s) failed:\n' \
        "$((assert_total - assert_pass))" "$assert_total"
    sed 's/^/  /' "$problems"
    exit 1
fi
printf 'guardian-reach-probe: PASS — %s/%s assertion(s) held; %s admitted, %s denied and attributed to Cilium policy on %s, port-forward and kubelet probes intact\n' \
    "$assert_pass" "$assert_total" "$AGENT_NS" "$TARGET_NS" "$guardian_node"
