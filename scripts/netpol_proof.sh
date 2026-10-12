#!/bin/sh
#
# netpol_proof.sh -- prove that NetworkPolicy is actually enforced in this cluster, and that the
# enforcement is attributable to Cilium's policy engine rather than merely coincident with it.
# Milestone task M1-T1.1, and the executable form of M1's Definition-of-done line "NetworkPolicy
# enforcement demonstrated (a denied test connection)". ADR-014 records the design.
#
# WHY A FAILED CONNECTION IS NOT A PROOF
#   This script is longer than "apply a policy, watch curl fail" because that check cannot support
#   the claim it appears to support. A connection that fails proves nothing on its own: a wrong
#   port, a crashed server, an unresolvable name and an enforced policy are indistinguishable from
#   the caller's side, and all four produce a red curl. Worse, "NetworkPolicy applied successfully"
#   proves less than nothing, because the Kubernetes API server accepts and stores a NetworkPolicy
#   object whether or not any CNI is watching for one. A cluster running a CNI that does not
#   implement policy at all -- kindnet, which is what kind installs unless told otherwise -- will
#   accept every policy it is given, list them on request, and enforce none of them. A check that
#   stopped at the API response would report green on precisely the cluster this project must not
#   have.
#
# THE FOUR PARTS
#   Each is an independent way for the claim to be false, and the run fails if any of them does not
#   hold.
#     1. Cilium is the only CNI. The kube-system DaemonSet list must contain cilium and must not
#        contain kindnet, and Cilium must report itself healthy. If kindnet were present, every
#        later part would be measuring the wrong datapath.
#     2. Positive control. With no policy in the probe namespace, the client reaches the server and
#        gets HTTP 200. Without this, a denial in part 3 is indistinguishable from a broken
#        harness, so a failure here abandons the case rather than continuing into a meaningless
#        denial.
#     3. Denial, asserted by failure MODE and not merely by failure. The same request must fail
#        with curl exit 28, an operation timeout, which is what packets being silently dropped
#        looks like from the sender. Exit 6 and exit 7 are explicitly rejected: 6 is "could not
#        resolve host", which is a resolver defect, and 7 is "failed to connect", which is a
#        listener defect. Both would be red curls that say nothing about policy, and treating
#        either as a pass is the exact error this part exists to prevent.
#     4. Attribution and reversal. While the denied request is in flight, the Cilium agent on the
#        server's node is asked for its drop events, and one of them must name this flow with the
#        reason "Policy denied". That is the only artefact in the whole run that names the policy
#        engine as the cause rather than inferring it. Then the policy is deleted and the same
#        request must return 200 again, which is what rules out the alternative explanation that
#        the server simply died between part 2 and part 3.
#
# WHY PARTS 3 AND 4 SHARE ONE REQUEST
#   The request whose exit status is asserted in part 3 is the same request the drop monitor is
#   recording for part 4. That is deliberate and it is stronger than running two: attribution
#   attached to a different request than the one that timed out would leave open the possibility
#   that the timeout and the drop had different causes.
#
# TWO CASES: SAME NODE AND CROSS NODE
#   Everything below runs twice, once with the client and the server scheduled onto one node and
#   once with them on different nodes, and neither case subsumes the other. Cross-node is where a
#   half-configured datapath most often leaks, because the packet must survive encapsulation and
#   decapsulation before any policy decision is reached. Same-node is where a policy enforced only
#   at the encapsulation layer would falsely pass, because such a policy never sees a purely local
#   flow. A green result in one case and a red one in the other is a real and informative outcome,
#   which is why each case reports its own four verdicts instead of the run reporting one.
#
# THIS SCRIPT NEEDS A RUNNING CLUSTER, SO IT CANNOT RUN IN ci.yml
#   ci.yml's four jobs run on a hosted runner with no Kubernetes at all, and its per-component
#   pytest step is explicitly a unit-test step over fixtures. Nothing in this file can execute
#   there: it talks to an API server on its first substantive line and every assertion it makes is
#   about a datapath. Its home is the bringup job of .github/workflows/env-bringup.yml, which is
#   the one workflow that has a cluster, and that workflow already invokes it by path.
#
#   The corollary is a constraint on other code, not on this file: nothing under infra/tests/ may
#   import, shell out to, or otherwise depend on this script. Those tests are pure unit tests that
#   must pass on a runner with no cluster, and a dependency on this script would make the lint job
#   fail for the absence of an environment rather than for a defect. If a future test needs to
#   assert something this script establishes, the assertion belongs in this script and the evidence
#   belongs in the workflow log.
#
# OUTPUT CONTRACT
#   stdout carries one greppable verdict line per assertion, in the form
#     netpol-proof: <case> <part> PASS|FAIL -- <evidence>
#   with the raw evidence for that assertion indented beneath it behind a "|" gutter, and exactly
#   one summary line at the end in the same shape scripts/check_hygiene.sh uses. stderr carries the
#   consolidated failure list and the diagnosis. A caller that wants only the verdicts can grep
#   stdout for "netpol-proof:" and ignore the gutter lines; a human reading the log gets the raw
#   kubectl and curl output that each verdict was derived from, which is the point of printing it.
#
# CLEANUP
#   The probe namespace is deleted on exit, by trap, but only when this run is the one that created
#   it; a namespace that already existed is left alone and the script says so. Either way the line
#   is printed, so a log always states what happened to the fixtures.
#
# THIS SCRIPT NEVER WRITES TO GIT AND HOLDS NO CREDENTIALS
#   It reads the cluster through whatever kubeconfig the caller already has, creates and deletes
#   objects in one throwaway namespace, and touches nothing else. It is not part of the
#   Guardian-mediated path and must never become one: it is test scaffolding for the substrate,
#   not agent code.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs identically under Git Bash on
#   Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in CI.

set -eu

# Byte-stable kubectl, grep and curl output regardless of the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, never hardcoded, so the script behaves the
# same whether it is invoked by make, by the env-bringup workflow, or by hand from an arbitrary
# working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

NS="netpol-probe"
PROBE_DIR="infra/netpol/probe"
SERVER_POD="netpol-probe-server"
CLIENT_POD="netpol-probe-client"
SERVER_SVC="netpol-probe-server"
TARGET_URL="http://$SERVER_SVC.$NS.svc.cluster.local:8080/"

# Bounds, not thresholds. Every duration and count below limits how long this script waits for the
# cluster to catch up with something it just asked for; none of them is an experiment parameter,
# a service-level objective or a budget, all of which belong exclusively to
# docs/protocols/evaluation-protocol.md under the source-of-truth iron rule (AGENTS.md 1). They are
# deliberately loose, because a bound that fires while an image is still being pulled reports a
# policy failure for a slow network, which is the one wrong answer this script must never give.
READY_TIMEOUT="150s"     # kubectl wait for a fixture pod to become Ready, including the image pull
DELETE_TIMEOUT="60s"     # kubectl delete for the fixture pods between the two cases
CURL_MAX_TIME=5          # curl --max-time: makes exit 28 reachable, and reachable quickly
POLICY_ATTEMPTS=15       # bounded polls for the datapath to catch up with a policy change
MONITOR_ATTEMPTS=15      # bounded polls for the drop monitor to announce that it is listening
EVIDENCE_MAX_LINES=15    # cap on raw evidence lines printed beneath one verdict

work=$(mktemp -d) || exit 1
problems="$work/problems"
: > "$problems"

created_ns=0
ns_known=0
cleanup_done=0
monitor_pid=""
# Where the running monitor lives, so stop_monitor can end it inside the pod and not only its local
# kubectl client. Empty until start_drop_monitor is called.
monitor_remote_pod=""
monitor_remote_bin=""
assert_total=0
assert_pass=0
case_total=0
case_pass=0
curl_rc=0

# --- reporting helpers -------------------------------------------------------------------

# One verdict line per assertion, on stdout, in a fixed shape so the log is greppable. A failure
# also appends to the problem file, which is what the summary counts and what stderr prints at the
# end; nothing else writes to that file, so the exit status and the printed list cannot disagree.
record_pass() {
    assert_total=$((assert_total + 1))
    assert_pass=$((assert_pass + 1))
    printf 'netpol-proof: %s %s PASS — %s\n' "$1" "$2" "$3"
}

record_fail() {
    assert_total=$((assert_total + 1))
    printf 'netpol-proof: %s %s FAIL — %s\n' "$1" "$2" "$3"
    printf '%s %s: %s\n' "$1" "$2" "$3" >> "$problems"
}

# Raw evidence, indented behind a gutter so that a reader can tell at a glance which lines are this
# script speaking and which are kubectl, curl or the Cilium agent speaking. An assertion that
# printed a verdict and no evidence would be asking to be believed rather than showing its working.
# The output is capped. A busy cluster's drop stream can run to hundreds of lines, and a
# verdict followed by an unbounded dump buries the next verdict; the count of what was
# withheld is printed so the log never implies it showed everything. The cap applies to
# evidence only -- verdict lines and the failure list are always complete.
evidence_file() {
    if [ ! -s "$1" ]; then
        printf '    | (no output)\n'
        return 0
    fi
    evidence_lines=$(awk 'END {print NR+0}' "$1")
    sed -n "1,${EVIDENCE_MAX_LINES}p" "$1" | sed 's/^/    | /'
    if [ "$evidence_lines" -gt "$EVIDENCE_MAX_LINES" ]; then
        printf '    | ... and %s further line(s), not shown\n' \
            "$((evidence_lines - EVIDENCE_MAX_LINES))"
    fi
}

evidence_text() {
    printf '%s\n' "$1" | sed 's/^/    | /'
}

# Used only for conditions that make the whole run meaningless -- no kubectl, no cluster, a cluster
# too small to express the cross-node case. These are not failed assertions about the datapath;
# they are reasons the datapath could not be examined, and conflating the two would let a broken
# environment be reported as a broken network.
abort() {
    printf 'netpol-proof: %s\n' "$1" >&2
    printf 'netpol-proof: FAIL — %s\n' "$1"
    exit 1
}

# --- cleanup -----------------------------------------------------------------------------

stop_monitor() {
    if [ -n "$monitor_pid" ]; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
        monitor_pid=""
    fi
    # Killing the local `kubectl exec` closes the stream but does NOT stop the process inside the
    # pod: `cilium-dbg monitor` keeps running, attached to the agent's monitor socket, so a proof
    # leaked one per case per node. Fifteen had accumulated in the agent on kind-worker after a
    # handful of runs. Terminate it where it runs, by the exact argv start_drop_monitor started it
    # with, so nothing else in the pod matches -- and only when this run actually started one.
    if [ -n "$monitor_remote_pod" ] && [ -n "$monitor_remote_bin" ]; then
        kubectl -n kube-system exec "$monitor_remote_pod" -c cilium-agent -- \
            pkill -f "$monitor_remote_bin monitor --type drop" >/dev/null 2>&1 || true
    fi
}

# Registered for EXIT as well as the three signals, and guarded against running twice, because a
# handler that fires on TERM and again on EXIT would print its line twice and delete a namespace it
# had already deleted. The namespace delete does not wait: this handler runs on the way out of a
# proof that has already reported its verdicts, and blocking the exit for thirty seconds of
# namespace finalisation would only make an interrupted run feel hung.
cleanup() {
    [ "$cleanup_done" -eq 0 ] || return 0
    cleanup_done=1
    stop_monitor
    if [ "$ns_known" -eq 0 ]; then
        # The run stopped before it reached the namespace step, so it has nothing to say about
        # the namespace. Claiming it was left in place would be an assertion never checked.
        rm -rf "$work"
        return 0
    fi
    if [ "$created_ns" -eq 1 ]; then
        kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        printf 'netpol-proof: cleanup — deleted namespace %s, which this run created\n' "$NS"
    else
        printf 'netpol-proof: cleanup — left namespace %s alone; it predates this run\n' "$NS"
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

# --- environment ---------------------------------------------------------------------------

if ! command -v kubectl >/dev/null 2>&1; then
    echo "netpol-proof: kubectl is not on PATH. This script talks to an API server;" >&2
    echo "netpol-proof: without one there is nothing here to check." >&2
    abort "kubectl is not on PATH"
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "netpol-proof: no reachable cluster. This proof needs a running kind cluster" >&2
    echo "netpol-proof: with Cilium already installed; bring one up, then re-run." >&2
    abort "no reachable cluster"
fi

for f in namespace.yaml server.yaml client.yaml deny-ingress.yaml; do
    [ -f "$PROBE_DIR/$f" ] || abort "$PROBE_DIR/$f is missing; the fixtures are incomplete."
done

# --- node discovery ------------------------------------------------------------------------

# Node names are discovered rather than written down, because kind derives them from the cluster
# name: a cluster created under any name but the default has no node called kind-worker, and a
# hardcoded pair would work on one machine and mystify the next.
kubectl get nodes -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}' \
    > "$work/nodes" 2>/dev/null || true
node_count=$(awk 'NF {n++} END {print n+0}' "$work/nodes")

# The control-plane node is identified by its role label rather than by position, and the other
# node is whatever is left. If the label is absent -- a cluster this script was not written for --
# the first two names in order are used instead, which still expresses both cases correctly even
# though it can no longer say which node is which.
cp_node=$(kubectl get nodes -l node-role.kubernetes.io/control-plane \
    -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)

node_one=""
node_two=""
while IFS= read -r n; do
    [ -n "$n" ] || continue
    if [ "$n" = "$cp_node" ]; then
        [ -n "$node_one" ] || node_one="$n"
    else
        [ -n "$node_two" ] || node_two="$n"
    fi
done < "$work/nodes"

if [ -z "$node_one" ] || [ -z "$node_two" ]; then
    node_one=$(sed -n '1p' "$work/nodes")
    node_two=$(sed -n '2p' "$work/nodes")
fi

if [ "$node_count" -lt 2 ] || [ -z "$node_two" ]; then
    echo "netpol-proof: this cluster reports $node_count node name(s). The cross-node" >&2
    echo "netpol-proof: case cannot be expressed on fewer than two, and a single-node" >&2
    echo "netpol-proof: result is not the claim M1 makes. Recreate the cluster from" >&2
    echo "netpol-proof: infra/kind-config.yaml, or record the reduction as an ADR-001" >&2
    echo "netpol-proof: deviation." >&2
    abort "cluster has $node_count node(s); two are required"
fi

# The server sits on node_two, which is the non-control-plane node whenever the role label exists,
# because that is where ordinary workloads belong. The client moves: onto the same node for the
# first case, onto node_one for the second. infra/netpol/probe/client.yaml carries the
# control-plane toleration that the second placement needs.
echo "netpol-proof: nodes discovered -- server node $node_two, cross-node client node $node_one"

# --- fixtures ------------------------------------------------------------------------------

# The namespace is created only if it is absent, and the flag set here is the only thing that
# authorises the trap to delete it. Deleting a namespace the run did not create would be a
# surprise, and a proof script that surprises its operator is one nobody will run twice.
ns_known=1
if kubectl get namespace "$NS" >/dev/null 2>&1; then
    created_ns=0
    printf 'netpol-proof: namespace %s already exists; it will be reused and not deleted\n' "$NS"
else
    kubectl apply -f "$PROBE_DIR/namespace.yaml" >/dev/null
    created_ns=1
    printf 'netpol-proof: namespace %s created by this run; it will be deleted on exit\n' "$NS"
fi

# The one dynamic value in the fixtures is the node name, carried as a NODE_NAME_PLACEHOLDER token
# that is substituted here into a temporary copy. server.yaml's header records why this is a sed
# substitution and not a patch, an overlay or envsubst; the short version is that spec.nodeSelector
# is immutable after creation, so it cannot be patched in at all. Node names are DNS-1123
# subdomains and therefore contain no sed metacharacter, which is what makes the plain substitution
# safe.
apply_fixture() {
    sed "s/NODE_NAME_PLACEHOLDER/$2/g" "$PROBE_DIR/$1" > "$work/$1"
    kubectl apply -f "$work/$1" >/dev/null
}

# Between the two cases the pods are destroyed and recreated rather than moved, because
# spec.nodeSelector cannot be changed on a live pod. The policy is removed too, so that every case
# starts from the same unpoliced state its positive control assumes. Readiness is waited for
# explicitly, with a bound: a proof that slept a fixed number of seconds and hoped would report a
# race as a network result.
reset_fixtures() {
    kubectl -n "$NS" delete networkpolicy --all --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pod "$SERVER_POD" "$CLIENT_POD" \
        --ignore-not-found --now --timeout="$DELETE_TIMEOUT" >/dev/null 2>&1 || true
    apply_fixture server.yaml "$1"
    apply_fixture client.yaml "$2"
    kubectl -n "$NS" wait --for=condition=Ready "pod/$SERVER_POD" \
        --timeout="$READY_TIMEOUT" >/dev/null
    kubectl -n "$NS" wait --for=condition=Ready "pod/$CLIENT_POD" \
        --timeout="$READY_TIMEOUT" >/dev/null
}

# One request from the client to the server, through the Service DNS name. Sets the global curl_rc
# to curl's own exit status -- kubectl exec propagates the remote command's status -- and leaves
# the HTTP status code in curl.out and any curl diagnostic in curl.err, both of which are printed
# as evidence. --max-time is what makes exit 28 reachable, and reachable soon: without it a dropped
# packet would retry until the kernel gave up minutes later. --output /dev/null discards the body,
# because the assertion is about the status line and the exit code, not the payload.
probe_once() {
    curl_rc=0
    kubectl exec -n "$NS" "$CLIENT_POD" -c client -- \
        curl --silent --show-error --output /dev/null \
        --max-time "$CURL_MAX_TIME" --write-out '%{http_code}' \
        "$TARGET_URL" > "$work/curl.out" 2> "$work/curl.err" || curl_rc=$?
    return 0
}

# --- part 1: Cilium is the only CNI ---------------------------------------------------------

# Re-asserted in each case rather than checked once at the top. The DaemonSet listing is
# cluster-scoped and its verdict is by construction the same both times, but a case that inherited
# it would not be a self-contained proof, and the health half genuinely is per-node: what matters
# for a given case is that the agent is up on the node whose datapath that case exercises.
part_cni() {
    case_label="$1"

    kubectl -n kube-system get daemonset -o name > "$work/ds" 2>"$work/ds.err" || true
    if grep -q '/cilium$' "$work/ds"; then
        if grep -q 'kindnet' "$work/ds"; then
            record_fail "$case_label" "1-sole-cni" \
                "kindnet is present alongside cilium; the datapath under test is wrong"
        else
            record_pass "$case_label" "1-sole-cni" \
                "kube-system runs the cilium DaemonSet and no kindnet DaemonSet"
        fi
    else
        record_fail "$case_label" "1-sole-cni" \
            "no cilium DaemonSet in kube-system; nothing in this cluster implements NetworkPolicy"
    fi
    evidence_file "$work/ds"

    # The cilium CLI reports agent, operator and endpoint health together, so it is preferred when
    # present. The DaemonSet's own desired-versus-ready counts are the fallback, and they are a
    # real assertion rather than a placeholder: an agent missing on any node is an unenforced node.
    if command -v cilium >/dev/null 2>&1; then
        cilium_rc=0
        cilium status > "$work/cstatus" 2>&1 || cilium_rc=$?
        if [ "$cilium_rc" -eq 0 ]; then
            record_pass "$case_label" "1-cilium-health" "cilium status reports healthy"
        else
            record_fail "$case_label" "1-cilium-health" \
                "cilium status exited $cilium_rc; the agent does not consider itself healthy"
        fi
        evidence_file "$work/cstatus"
    else
        ds_desired=$(kubectl -n kube-system get daemonset cilium \
            -o 'jsonpath={.status.desiredNumberScheduled}' 2>/dev/null || true)
        ds_ready=$(kubectl -n kube-system get daemonset cilium \
            -o 'jsonpath={.status.numberReady}' 2>/dev/null || true)
        ds_desired=${ds_desired:-0}
        ds_ready=${ds_ready:-0}
        if [ "$ds_desired" -gt 0 ] && [ "$ds_desired" = "$ds_ready" ]; then
            record_pass "$case_label" "1-cilium-health" \
                "cilium DaemonSet ready on every node it is scheduled to ($ds_ready/$ds_desired)"
        else
            record_fail "$case_label" "1-cilium-health" \
                "cilium DaemonSet is $ds_ready/$ds_desired ready; at least one node has no agent"
        fi
        evidence_text "cilium DaemonSet desiredNumberScheduled=$ds_desired numberReady=$ds_ready"
        evidence_text "(the cilium CLI is not on PATH, so the DaemonSet counts are the evidence)"
    fi
}

# --- part 2: positive control ----------------------------------------------------------------

# Returns non-zero to tell the caller to abandon the case. That is the whole point of a positive
# control: if the client cannot reach the server when nothing is stopping it, then the denial in
# part 3 would be evidence of a broken harness dressed up as evidence of a working policy, and
# continuing would manufacture exactly the false green this script exists to prevent.
part_positive_control() {
    case_label="$1"
    probe_once
    http_code=$(cat "$work/curl.out" 2>/dev/null || true)
    if [ "$curl_rc" -eq 0 ] && [ "$http_code" = "200" ]; then
        record_pass "$case_label" "2-positive-control" \
            "with no policy in $NS, the client got HTTP 200 from the server"
        evidence_text "curl exit 0, HTTP $http_code, target $TARGET_URL"
        return 0
    fi
    record_fail "$case_label" "2-positive-control" \
        "unpoliced request failed (curl exit $curl_rc, HTTP '$http_code'); the harness is broken"
    evidence_text "curl exit $curl_rc, HTTP '$http_code', target $TARGET_URL"
    evidence_file "$work/curl.err"
    evidence_text "Parts 3 and 4 are skipped for this case: a denial is only meaningful after a"
    evidence_text "success, so asserting one now would prove nothing about policy."
    return 1
}

# --- part 4 support: the drop monitor ----------------------------------------------------------

# The Cilium agent that can see the drop is the one on the SERVER's node, because a default-deny
# ingress policy is enforced at the destination endpoint: the packet is dropped after it arrives,
# not before it leaves. Looking at the client's agent in the cross-node case would show nothing and
# the proof would fail for the wrong reason.
cilium_pod_on_node() {
    kubectl -n kube-system get pods -l k8s-app=cilium \
        --field-selector "spec.nodeName=$1" \
        -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true
}

# Modern Cilium images ship the agent's debug CLI as cilium-dbg; older ones ship it as cilium. The
# rename is invisible from outside the pod, so the binary is probed rather than assumed, and the
# probe is a version subcommand rather than a shell test because the agent image is not guaranteed
# to contain a shell. A hardcoded name would make this proof silently unrunnable on whichever
# generation of image it was not written against.
monitor_binary_in() {
    if kubectl -n kube-system exec "$1" -c cilium-agent -- cilium-dbg version >/dev/null 2>&1; then
        printf 'cilium-dbg\n'
    elif kubectl -n kube-system exec "$1" -c cilium-agent -- cilium version >/dev/null 2>&1; then
        printf 'cilium\n'
    else
        printf '\n'
    fi
}

# Started before the denied request and left running across the whole retry loop, so that whichever
# attempt is the one that times out is also an attempt the monitor was recording. The wait below is
# a bounded poll on the agent's own "listening" banner rather than a fixed sleep: a fixed sleep
# would either be too short, losing the event, or too long, and neither is a fact about the
# cluster.
start_drop_monitor() {
    monitor_remote_pod=$1
    monitor_remote_bin=$2
    : > "$work/monitor.out"
    # stdin from /dev/null: under `timeout` or any wrapper that puts this script in its own process
    # group, a backgrounded kubectl that touches the terminal is stopped by SIGTTIN and never prints
    # its banner, which reads exactly like a monitor that failed to start (ADR-076).
    kubectl -n kube-system exec "$1" -c cilium-agent -- \
        "$2" monitor --type drop < /dev/null > "$work/monitor.out" 2>&1 &
    monitor_pid=$!
    # The banner is NOT one fixed string, and matching only the long form made this proof fail its
    # FIRST case every single time. Which lines `cilium-dbg monitor` prints depends on whether it is
    # the first reader to attach since the agent last started: the first one prints only
    # "Press Ctrl-C to quit", and every later one prints
    # "Listening for events on N CPUs with MxK of shared memory" before it (measured on kind,
    # Cilium 1.20.1, by restarting the agent and running the monitor three times: invocation 1 saw
    # only the short banner, invocations 2 and 3 saw the long one within 1s). The same-node case is
    # always the first to attach, so it always lost this race, while the cross-node case -- which
    # attaches second -- passed on the strength of the first case's attach. That is a verdict about
    # the order the cases run in, not about the cluster. Accept either line; "Press Ctrl-C to quit"
    # is the one both wordings share.
    #
    # This remains only a "the process is up and printing" gate. The readiness that matters is the
    # bounded probe loop in the caller, which waits for a policy drop naming this flow before the
    # request it will assert on is generated.
    i=0
    while [ "$i" -lt "$MONITOR_ATTEMPTS" ]; do
        if grep -q -e 'Listening for events' -e 'Press Ctrl-C to quit' \
            "$work/monitor.out" 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

# --- parts 3 and 4: denial, attribution, reversal -----------------------------------------------

part_denial_and_attribution() {
    case_label="$1"
    server_node="$2"

    server_ip=$(kubectl -n "$NS" get pod "$SERVER_POD" \
        -o 'jsonpath={.status.podIP}' 2>/dev/null || true)

    cilium_pod=$(cilium_pod_on_node "$server_node")
    monitor_bin=""
    if [ -n "$cilium_pod" ]; then
        monitor_bin=$(monitor_binary_in "$cilium_pod")
    fi

    kubectl apply -f "$PROBE_DIR/deny-ingress.yaml" >/dev/null

    monitor_started=0
    if [ -n "$monitor_bin" ]; then
        if start_drop_monitor "$cilium_pod" "$monitor_bin"; then
            monitor_started=1
        fi
    fi

    # The monitor prints its listening banner before attaching to the agent socket, so the banner
    # alone is not a readiness signal. Bounded readiness probes wait until one timeout also produces
    # this flow's policy-drop event. Only then is the request asserted by parts 3 and 4 generated.
    # If the monitor did not start, part 3 still stops at the first timeout and part 4 reports why it
    # cannot attribute it.
    monitor_ready=0
    i=0
    while [ "$i" -lt "$POLICY_ATTEMPTS" ]; do
        probe_once
        grep -F 'Policy denied' "$work/monitor.out" > "$work/drops" 2>/dev/null || true
        : > "$work/drops_flow"
        if [ -n "$server_ip" ]; then
            grep -F "$server_ip" "$work/drops" > "$work/drops_flow" 2>/dev/null || true
        fi
        if [ "$curl_rc" -eq 28 ]; then
            if [ "$monitor_started" -ne 1 ] || [ -s "$work/drops_flow" ]; then
                [ "$monitor_started" -ne 1 ] || monitor_ready=1
                break
            fi
        fi
        i=$((i + 1))
        sleep 1
    done

    if [ "$monitor_ready" -eq 1 ]; then
        monitor_lines=$(awk 'END {print NR+0}' "$work/monitor.out")
        probe_once
        i=0
        while [ "$i" -lt "$MONITOR_ATTEMPTS" ]; do
            sed -n "$((monitor_lines + 1)),\$p" "$work/monitor.out" > "$work/monitor_probe.out"
            grep -F 'Policy denied' "$work/monitor_probe.out" > "$work/drops" 2>/dev/null || true
            : > "$work/drops_flow"
            if [ -n "$server_ip" ]; then
                grep -F "$server_ip" "$work/drops" > "$work/drops_flow" 2>/dev/null || true
            fi
            [ ! -s "$work/drops_flow" ] || break
            i=$((i + 1))
            sleep 1
        done
    fi

    denied_rc="$curl_rc"
    denied_code=$(cat "$work/curl.out" 2>/dev/null || true)

    stop_monitor

    # Part 3: the failure MODE, not merely the failure.
    case "$denied_rc" in
        28)
            record_pass "$case_label" "3-denial" \
                "curl exit 28: the request timed out, which is what dropped packets look like"
            evidence_text "curl exit 28 (operation timed out) after ${CURL_MAX_TIME}s"
            evidence_text "target $TARGET_URL"
            ;;
        6)
            record_fail "$case_label" "3-denial" \
                "curl exit 6 is an unresolvable name: a DNS defect, not a policy"
            evidence_text "curl exit 6 (could not resolve host). The deny-ingress policy"
            evidence_text "restricts ingress to the server pod alone and leaves CoreDNS"
            evidence_text "untouched, so this is a resolver problem and the denial is unproven."
            ;;
        7)
            record_fail "$case_label" "3-denial" \
                "curl exit 7 is a refused connection, which is a listener defect, not a policy"
            evidence_text "curl exit 7 (failed to connect). A refusal means something sent a"
            evidence_text "reset: the server died, or the Service lost its endpoint. A policy"
            evidence_text "drops packets silently and gives exit 28, so enforcement is unproven."
            ;;
        0)
            record_fail "$case_label" "3-denial" \
                "request still returned HTTP $denied_code with the policy in force"
            evidence_text "The API server accepted the NetworkPolicy and nothing enforced it."
            evidence_text "This is the failure this proof exists to catch: an object that"
            evidence_text "exists and a datapath that ignores it."
            ;;
        *)
            record_fail "$case_label" "3-denial" \
                "curl exit $denied_rc is neither 28 nor a mode this proof recognises"
            ;;
    esac
    evidence_file "$work/curl.err"

    # Part 4a: attribution. This is the only assertion in the run that names Cilium's policy engine
    # as the cause rather than inferring it from a symptom. The readiness loop above finds policy
    # drops to this server; after attachment is established, drops_flow is replaced with events from
    # the asserted request only, so an earlier readiness probe cannot supply its attribution.

    if [ "$monitor_started" -ne 1 ]; then
        record_fail "$case_label" "4-attribution" \
            "no drop monitor ran on node $server_node, so the drop could not be attributed"
        evidence_text "cilium agent pod on $server_node: '${cilium_pod:-none found}'"
        evidence_text "monitor binary: probed cilium-dbg then cilium, found ${monitor_bin:-neither}"
        evidence_file "$work/monitor.out"
    elif [ -s "$work/drops_flow" ]; then
        record_pass "$case_label" "4-attribution" \
            "the agent on $server_node dropped this flow with reason 'Policy denied'"
        evidence_text "server pod IP $server_ip, agent pod $cilium_pod, binary $monitor_bin"
        evidence_file "$work/drops_flow"
    elif [ -s "$work/drops" ]; then
        record_fail "$case_label" "4-attribution" \
            "policy drops were seen on $server_node but none names the server IP $server_ip"
        evidence_text "The engine denied something, but not demonstrably this flow, so the timeout"
        evidence_text "in part 3 and the drop below are not shown to have the same cause."
        evidence_file "$work/drops"
    else
        record_fail "$case_label" "4-attribution" \
            "no 'Policy denied' drop event on $server_node while the request was timing out"
        evidence_text "Something stopped the packet, but Cilium's policy engine did not say it was"
        evidence_text "the one that did, so the denial is observed and not attributed."
        evidence_file "$work/monitor.out"
    fi

    # Part 4b: reversal. Deleting the policy and getting 200 again is what excludes the competing
    # explanation for everything above -- that the server pod simply stopped working between part 2
    # and part 3. Without it, a crashed server and an enforced policy remain indistinguishable, and
    # the run would have proved only that something went wrong at roughly the right moment.
    kubectl delete -f "$PROBE_DIR/deny-ingress.yaml" --ignore-not-found >/dev/null 2>&1 || true

    i=0
    while [ "$i" -lt "$POLICY_ATTEMPTS" ]; do
        probe_once
        restored_code=$(cat "$work/curl.out" 2>/dev/null || true)
        if [ "$curl_rc" -eq 0 ] && [ "$restored_code" = "200" ]; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    restored_code=$(cat "$work/curl.out" 2>/dev/null || true)

    if [ "$curl_rc" -eq 0 ] && [ "$restored_code" = "200" ]; then
        record_pass "$case_label" "4-reversal" \
            "with the policy deleted the same request returned HTTP 200 again"
        evidence_text "curl exit 0, HTTP $restored_code, after deleting the deny-ingress policy"
    else
        record_fail "$case_label" "4-reversal" \
            "request did not recover after the policy was deleted (curl exit $curl_rc)"
        evidence_text "curl exit $curl_rc, HTTP '$restored_code'. The denial in part 3 therefore"
        evidence_text "cannot be separated from the possibility that the server stopped serving."
        evidence_file "$work/curl.err"
    fi
}

# --- case runner ---------------------------------------------------------------------------

# Wrapped in an OR list so that an unexpected non-zero status inside a case ends that case rather
# than the run: the second case is worth attempting even when the first one collapsed, because
# same-node passing and cross-node failing is itself a diagnosis. The consequence is that set -e is
# suspended inside case_body, so every command in it that may legitimately fail is guarded
# explicitly rather than relying on the shell.
case_body() {
    case_label="$1"
    reset_fixtures "$2" "$3"
    part_cni "$case_label"
    part_positive_control "$case_label" || return 1
    part_denial_and_attribution "$case_label" "$2"
    return 0
}

run_case() {
    case_label="$1"
    printf 'netpol-proof: === case %s: server on %s, client on %s ===\n' "$1" "$2" "$3"
    before=$(awk 'END {print NR+0}' "$problems")
    case_body "$1" "$2" "$3" || true
    after=$(awk 'END {print NR+0}' "$problems")
    case_total=$((case_total + 1))
    if [ "$before" -eq "$after" ]; then
        case_pass=$((case_pass + 1))
        printf 'netpol-proof: case %s GREEN\n' "$case_label"
    else
        printf 'netpol-proof: case %s RED, %s failed assertion(s)\n' \
            "$case_label" "$((after - before))"
    fi
}

# --- run both cases ---------------------------------------------------------------------------

run_case "same-node" "$node_two" "$node_two"
run_case "cross-node" "$node_two" "$node_one"

# --- report -----------------------------------------------------------------------------------

# stderr carries the consolidated failure list and the diagnosis; stdout carries exactly one
# summary line, in the shape scripts/check_hygiene.sh established, so that a caller can read the
# result without parsing the stream above it.
problem_count=$(awk 'END {print NR+0}' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        echo "netpol-proof: FAIL — $problem_count failed assertion(s):"
        echo
        cat "$problems"
        echo
        echo "Each item above is a statement about this cluster, not about this script. Read the"
        echo "raw evidence printed beneath the matching verdict line on stdout before changing"
        echo "anything: part 1 failing means the CNI is wrong, part 2 failing means the fixtures"
        echo "are wrong, and part 3 or 4 failing means policy is not being enforced or not"
        echo "demonstrably by Cilium. ADR-014 records why each part is required."
    } >&2
    printf 'netpol-proof: FAIL — %s of %s assertion(s) failed across %s case(s)\n' \
        "$problem_count" "$assert_total" "$case_total"
    exit 1
fi

# Two printf calls, one output line: the first deliberately has no trailing newline. The
# format string is longer than a source line should be, and splitting the call is the only
# way to keep both the source readable and the summary a single greppable line.
printf 'netpol-proof: PASS — %s/%s case(s) green, %s/%s assertion(s) held ' \
    "$case_pass" "$case_total" "$assert_pass" "$assert_total"
printf '(same-node on %s; cross-node client %s to server %s)\n' \
    "$node_two" "$node_one" "$node_two"
exit 0
