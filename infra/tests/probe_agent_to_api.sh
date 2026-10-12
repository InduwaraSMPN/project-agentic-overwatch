#!/bin/sh
#
# probe_agent_to_api.sh -- show, from inside the agent namespace, that the agent layer cannot reach
# the Kubernetes API server, and show it in a way that could have come out the other way. Milestone
# task M3-T3.5, traceability row T-11, and the executable form of
# docs/protocols/security-policy.md section 1 invariant 3: "No direct path: agent namespace cannot
# reach the K8s API -- Cilium default-deny NetworkPolicy; verified by an in-cluster probe that must
# fail (T-11)." The policy under test is infra/netpol/agents-default-deny.yaml.
#
# THIS IS A TIER B CHECK. IT NEEDS A LIVE CLUSTER AND MUST NEVER RUN IN ci.yml.
#   Every assertion below talks to an API server and to a Cilium agent. .github/workflows/ci.yml's
#   four jobs run on a hosted runner with no Kubernetes at all, so nothing here can execute there.
#   Its home is the bringup job of .github/workflows/env-bringup.yml, which is the one workflow that
#   has a cluster, or an operator's runbook -- the same boundary ADR-014 draws for
#   scripts/netpol_proof.sh and for exactly the same reason.
#
#   READ THIS BEFORE MOVING OR RENAMING THIS FILE. It sits in infra/tests/, which ci.yml's
#   "Unit tests -- infra" step runs `python -m pytest infra/tests` over, armed by
#   hashFiles('infra/tests/**'). That guard is ALREADY armed by the Python tests beside this file,
#   so adding a shell script does not arm anything that was previously inert; and pytest collects
#   only files matching its python_files patterns -- `test_*.py` and `*_test.py` -- so a `.sh` file
#   is not collected, not imported and not executed. Both halves were checked rather than assumed,
#   and the check is recorded in the M3 execution log. The constraint that follows is on OTHER code,
#   not on this file: nothing under infra/tests/ may import, shell out to, or otherwise depend on
#   this script. Those are pure unit tests that must pass on a runner with no cluster, and a
#   dependency on this script would turn the lint job red for the absence of an environment rather
#   than for a defect.
#
#   ONE KNOWN GAP, STATED SO IT IS NOT DISCOVERED LATER. scripts/check_hygiene.sh block (c) sweeps
#   index line endings over `Makefile`, `scripts/*.sh`, `scripts/*.py` and `infra/*.env`. This path
#   matches none of them, so this script is outside the CRLF tripwire that every other shell entry
#   point in the repository sits inside, and a CRLF copy of it could be committed without any check
#   noticing -- until dash refused to run it on a cluster host. docs/plans/M3-implementation-plan.md
#   names both this path and the "logic lives in scripts/" convention that would have covered it;
#   the path is what the plan, the milestone DoD table and guardian/README.md all reference by name,
#   so it is honoured here and the gap is written down rather than silently resolved by moving the
#   file. Closing it is a one-word pathspec change plus an EOL_MIN_ROWS bump, and it belongs to
#   whoever next edits that script.
#
# ============================================================================================
# WHY A SCRIPT WHOSE PASS CONDITION IS A FAILURE HAS TO BE THIS CAREFUL
# ============================================================================================
#
#   "The probe failing to connect is the pass condition" is the whole design, and it is also the
#   whole danger: a test that passes when something fails will pass on a broken harness, and a
#   broken harness is the normal state of a first bring-up. A wrong port, a pod that never started,
#   a namespace that does not exist, a DNS outage, an API server that is down and an enforced policy
#   all produce the same red curl. ADR-014 made this argument for M1's mechanism proof and this
#   script inherits it; what it does not inherit is M1's artefact, because the flow is different in
#   three ways that each change what a correct assertion looks like.
#
#   DIFFERENCE 1 -- THE TARGET SPEAKS TLS, SO "curl FAILED" HAS A NEW AND WORSE FALSE POSITIVE.
#     M1 curled a plain-HTTP fixture, so its only realistic non-zero outcomes were timeout, DNS and
#     refusal. The Kubernetes API server is HTTPS with a private CA, so a request that REACHES it
#     and completes a TCP handshake can still exit non-zero -- classically 60, "peer certificate
#     cannot be authenticated with known CA", and its relatives 35, 51, 58 and 77. Every one of
#     those is a REACHABILITY SUCCESS wearing the costume of a failure. A script that accepted
#     "curl exited non-zero" here would certify an open boundary. So this script asserts one exit
#     code as the pass -- 28 -- and treats the TLS family as an explicit, separately-worded FAILURE
#     that says in as many words that the packet arrived.
#
#     `--insecure` is passed for the same reason, and it is not a weakening of anything. The
#     question this probe asks is whether a packet can get there, not whether the certificate is
#     trustworthy; with verification on, an open boundary reports exit 60 and a reader has to know
#     the exit-code table to see that it means "reached". With verification off, an open boundary
#     reports exit 0 and an HTTP status, which no reader can misread. Turning verification back on
#     would make the dangerous outcome look like the safe one.
#
#   DIFFERENCE 2 -- THE DENIAL IS AT EGRESS, SO THE DROP IS ON THE SOURCE'S NODE.
#     M1's policy denied ingress, so the packet died at the destination and its drop event belonged
#     to the Cilium agent on the SERVER's node. Here the policy denies egress, so the packet dies as
#     it leaves the probe pod and the event belongs to the agent on the PROBE POD's node. Reading
#     the wrong agent would show nothing and the proof would fail for a reason that has nothing to
#     do with policy. This is the mirror image of the note in scripts/netpol_proof.sh, and it is
#     stated here because it is precisely the kind of thing that gets copied across unchanged.
#
#   DIFFERENCE 3 -- THERE IS NO REVERSAL STEP, AND ITS ABSENCE IS DELIBERATE.
#     M1's fourth part deleted the policy and showed the request working again, which is what
#     excluded "the server died between step 2 and step 3". The equivalent here would be deleting
#     the agent namespace's default-deny on a live cluster -- removing the security invariant under
#     test, and leaving it removed if the run were interrupted between the delete and the re-apply.
#     M1 could do that safely because its policy lived in a throwaway namespace it created and
#     destroyed; this one is the boundary the artefact's central security claim rests on. The
#     positive control below takes over the role reversal played, and the mechanism-level
#     apply-deny-delete-restore evidence already exists: scripts/netpol_proof.sh produced it at M1,
#     in a namespace where doing so cost nothing. That division is exactly what ADR-014 set up when
#     it said M3-T3.5 "inherits the pattern rather than the artefact".
#
# ============================================================================================
# THE POSITIVE CONTROL: WHICH ONE IS IN THIS SCRIPT, WHICH ONE IS NOT, AND WHY
# ============================================================================================
#
#   Without a positive control a denial proves nothing, so there is one here and it is not optional:
#   part 3 runs the IDENTICAL request, with the identical image, arguments and target, from a pod in
#   a throwaway namespace that no policy selects, and requires it to reach the API server. A single
#   green line there retires the whole list of alternative explanations at once -- the image works,
#   curl works, cluster DNS works, the `kubernetes` Service routes, the API server is up and
#   answering, and the URL and port are right. It belongs IN this script rather than in a runbook
#   because it is worthless unless it runs in the same minute, on the same cluster, as the denial it
#   qualifies; a control an operator is asked to remember is a control that is present in the
#   procedure and absent from the evidence.
#
#   It also costs nothing that matters. It creates and destroys its own namespace, touches no
#   policy, and cannot leave the agent namespace's boundary in a different state than it found it.
#   That is the property that makes it safe to automate.
#
#   THE OTHER CONTROL -- the one that removes the policy and shows the same request succeeding from
#   the agent namespace ITSELF -- is deliberately NOT here. It is the stronger control, because it
#   would attribute the denial to THIS policy rather than to "something about the agent namespace",
#   and it is refused anyway: it requires deleting the artefact's security boundary on a live
#   cluster, and an interrupted run would leave it deleted with nothing announcing it. Its job is
#   split between two things that do not carry that risk. Part 6 attributes the drop to Cilium's
#   policy engine by reading the datapath's own drop event, which is a stronger attribution than a
#   before-and-after comparison and does not require the boundary to be touched. And the
#   G2-SHAREDCRED arm supplies the before-and-after for free: applying
#   infra/netpol/agents-g2-open.yaml is a supported, reviewed, reversible change to exactly one
#   object, and this script is expected to report failure while it is in force (see IT REFUSES TO
#   RUN IN THE G2 ARM). An operator who wants
#   the policy-removed control runs the Tier B G2 sequence, which is a runbook step with an ADR
#   behind it rather than an ad-hoc deletion inside a test.
#
# ============================================================================================
# TWO TARGETS, BECAUSE THE API SERVER HAS TWO ADDRESSES ON THIS CLUSTER
# ============================================================================================
#
#   A namespace-scoped egress policy is only a boundary if it covers every way to the destination,
#   and on kind there are two:
#     (a) the `kubernetes` ClusterIP Service in `default`, reached by DNS at
#         kubernetes.default.svc.cluster.local:443 -- the path every in-cluster client takes;
#     (b) the API server's real listener, which on kind is a static Pod in the control-plane node's
#         HOST network namespace, so its address is a node address on port 6443, reachable with no
#         DNS and no Service at all.
#   Both are probed, separately, and both must time out. Testing only (a) would certify a boundary
#   that a client could walk around by reading one environment variable; testing only (b) would miss
#   whatever the Service path resolves to. The address and port for (b) are DISCOVERED from the
#   cluster -- the EndpointSlice behind the `kubernetes` Service, falling back to the control-plane
#   node's InternalIP -- rather than written down, for the reason scripts/netpol_proof.sh discovers
#   node names: a hardcoded address works on one machine and mystifies the next.
#
#   Target (a) is also what makes the "not exit 6" assertion mean something. The policy under test
#   permits DNS deliberately, so a name-resolution failure during the denial step is a real defect
#   in that permission -- not an artefact of the test -- and it is reported as a failure rather than
#   quietly counted as a denial.
#
# WHY THE PROBE POD CARRIES NO SERVICEACCOUNT TOKEN
#   `automountServiceAccountToken: false` is set on the pod spec, so what this script measures is
#   REACHABILITY and nothing else. With a token mounted, a probe that got through would also be
#   authenticated, and a run that accidentally opened the boundary would be a run in which a test
#   fixture held a cluster credential. The setting is on the pod rather than inherited, so the probe
#   does not depend on the namespace's `default` ServiceAccount having been configured -- it
#   measures the network even if the credential half has regressed, which keeps the two invariants
#   independently diagnosable.
#
# WHY THE FIXTURES ARE INLINE RATHER THAN MANIFEST FILES
#   M1's probe kept four manifests beside its script because they carried a substituted node-name
#   placeholder and had to be readable as standalone objects. These two pods have no substituted
#   field and no policy object: they need no node pinning, because the control-plane node's
#   NoSchedule taint and the absence of any toleration already guarantee the probe pod lands on a
#   worker, which is where agents run and which is what makes the API server a REMOTE node from it.
#   Inlining them removes the unsubstituted-placeholder failure mode entirely, keeps the whole probe
#   in one file that can be copied onto a jump host and run, and -- the reason that decides it --
#   avoids leaving a committed manifest for a pod in the real `agents` namespace lying around for
#   somebody to apply by accident. This script consequently reads no repository file at all and can
#   be run from any working directory.
#
# WHAT THIS SCRIPT DOES NOT PROVE
#   - That the boundary would hold against a pod with `hostNetwork: true`, which has no Cilium
#     endpoint and escapes every NetworkPolicy. That is closed by admission -- the `agents`
#     namespace enforces the Pod Security Baseline profile, which forbids hostNetwork -- and it is
#     not testable here, because such a pod cannot be created in that namespace to test it with.
#   - That the API server is unreachable by any protocol whatever. It probes HTTPS on the two
#     addresses the API server actually answers on. A default-deny egress covers more than that, but
#     what is EVIDENCED is what was probed.
#   - Anything about `pods/exec` or `pods/portforward`, which tunnel through the API server rather
#     than to it, and are refused in guardian/deploy/rbac.yaml by RBAC. Note that this script's own
#     use of `kubectl exec` is not such a path and does not weaken the result: exec reaches the
#     container through the API server and the kubelet, so it is not a network flow originating in
#     the probe pod and no egress policy applies to it. That is why a pod under total default-deny
#     egress can still be driven by exec at all.
#   - Anything about the Guardian's own mediation. A closed network path is one of the two
#     independent facts FR4.2 needs; the other is that no credential exists outside `guardian`, and
#     guardian/deploy/rbac.yaml's Tier B assertions are what establish that.
#
# IT REFUSES TO RUN IN THE G2 ARM, RATHER THAN REPORTING A FAILURE
#   Under G2-SHAREDCRED the boundary is deliberately open, so every denial assertion below would
#   fail correctly and the log would read like a broken cluster. Part 2 detects the arm by reading
#   the CiliumNetworkPolicy's spec -- `egressDeny` is G0, `egress` is G2 -- and aborts with an
#   explanation instead. That is an environment condition, not a failed assertion about the
#   datapath, and conflating the two would let a deliberate configuration be recorded as a security
#   regression.
#
# CLEANUP, CREDENTIALS AND GIT
#   The probe pod in `agents` and the throwaway control namespace are removed on exit by trap, and
#   only when this run created them; anything that predates the run is left alone and the script
#   says so. The script writes nothing to git, reads the cluster through whatever kubeconfig the
#   caller already has, and holds, prints and mounts no credential of any kind. It is test
#   scaffolding for the substrate and must never become part of the Guardian-mediated path.
#
# OUTPUT CONTRACT
#   stdout carries one greppable verdict line per assertion, in the form
#     agent-api-probe: <part> PASS|FAIL -- <evidence>
#   with raw evidence indented beneath it behind a "|" gutter, and exactly one summary line at the
#   end in the shape scripts/check_hygiene.sh established. stderr carries the consolidated failure
#   list and the diagnosis. Exit 0 only if every assertion held.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options, no jq -- so it runs identically under Git
#   Bash on Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in the bringup workflow.

set -eu

# Byte-stable kubectl, grep and curl output regardless of the ambient locale.
LC_ALL=C
export LC_ALL

# No repo-root discovery and no `cd`: this script reads no file from the repository. See WHY THE
# FIXTURES ARE INLINE.

AGENT_NS="agents"
CONTROL_NS="agent-api-probe-control"
PROBE_POD="agent-api-probe"
CONTROL_POD="agent-api-probe-control"
PROBE_CONTAINER="probe"
# The same image scripts/netpol_proof.sh uses, for the reasons infra/netpol/probe/server.yaml gives:
# it ships a real curl -- and the whole denial assertion is a claim about libcurl's exit codes -- it
# needs no configuration, and it lives on registry.k8s.io rather than behind Docker Hub's anonymous
# pull limit. Pinned, because a floating tag in a proof is a proof that can change meaning without a
# commit.
PROBE_IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.53"
EGRESS_NETPOL="agents-default-deny-egress"
BOUNDARY_CNP="agents-kube-apiserver-boundary"
# /version is served to unauthenticated callers by the default `system:public-info-viewer` binding,
# so the positive control gets a clean 200 rather than a 401 it would have to special-case. The
# denial assertions do not depend on the path at all -- a dropped packet never reaches a route.
API_PATH="/version"
API_DNS_URL="https://kubernetes.default.svc.cluster.local:443$API_PATH"

# Bounds, not thresholds. Every duration and count below limits how long this script waits for the
# cluster to catch up with something it just asked for; none is an experiment parameter, a
# service-level objective or a budget, all of which belong exclusively to
# docs/protocols/evaluation-protocol.md under .agents/rules/00-source-of-truth.md.
READY_TIMEOUT="150s"     # kubectl wait for a fixture pod to become Ready, including the image pull
CURL_MAX_TIME=5          # curl --max-time: makes exit 28 reachable, and reachable quickly
MONITOR_ATTEMPTS=15      # bounded polls for the drop monitor to announce that it is listening
EVIDENCE_MAX_LINES=15    # cap on raw evidence lines printed beneath one verdict

work=$(mktemp -d) || exit 1
problems="$work/problems"
: > "$problems"

created_control_ns=0
created_probe_pod=0
cleanup_done=0
monitor_pid=""
assert_total=0
assert_pass=0
curl_rc=0
http_code=""

# --- reporting helpers -------------------------------------------------------------------

record_pass() {
    assert_total=$((assert_total + 1))
    assert_pass=$((assert_pass + 1))
    printf 'agent-api-probe: %s PASS — %s\n' "$1" "$2"
}

record_fail() {
    assert_total=$((assert_total + 1))
    printf 'agent-api-probe: %s FAIL — %s\n' "$1" "$2"
    printf '%s: %s\n' "$1" "$2" >> "$problems"
}

# Raw evidence, indented behind a gutter so a reader can tell which lines are this script speaking
# and which are kubectl, curl or the Cilium agent speaking. Capped, with the withheld count printed,
# so a busy drop stream cannot bury the next verdict.
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

# Used only for conditions that make the whole run meaningless -- no kubectl, no cluster, no agent
# namespace, a cluster in the G2 arm. These are not failed assertions about the datapath; they are
# reasons the datapath could not be examined, and conflating the two would let a broken or
# deliberately-opened environment be reported as a security result.
abort() {
    printf 'agent-api-probe: %s\n' "$1" >&2
    printf 'agent-api-probe: ABORT — %s\n' "$1"
    exit 1
}

# --- cleanup -----------------------------------------------------------------------------

stop_monitor() {
    if [ -n "$monitor_pid" ]; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
        monitor_pid=""
    fi
}

# Registered for EXIT as well as the three signals, and guarded against running twice. Only objects
# this run created are removed: deleting something the run did not create would be a surprise, and a
# probe that surprises its operator is one nobody will run twice. The deletes do not wait, because
# this handler runs on the way out of a run that has already reported its verdicts.
cleanup() {
    [ "$cleanup_done" -eq 0 ] || return 0
    cleanup_done=1
    stop_monitor
    if [ "$created_probe_pod" -eq 1 ]; then
        kubectl -n "$AGENT_NS" delete pod "$PROBE_POD" \
            --ignore-not-found --wait=false >/dev/null 2>&1 || true
        printf 'agent-api-probe: cleanup — deleted pod %s/%s, which this run created\n' \
            "$AGENT_NS" "$PROBE_POD"
    fi
    if [ "$created_control_ns" -eq 1 ]; then
        kubectl delete namespace "$CONTROL_NS" \
            --ignore-not-found --wait=false >/dev/null 2>&1 || true
        printf 'agent-api-probe: cleanup — deleted namespace %s, which this run created\n' \
            "$CONTROL_NS"
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

# --- environment ---------------------------------------------------------------------------

if ! command -v kubectl >/dev/null 2>&1; then
    echo "agent-api-probe: kubectl is not on PATH. This probe runs inside a cluster's" >&2
    echo "agent-api-probe: namespaces; without an API server there is nothing to check." >&2
    abort "kubectl is not on PATH"
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "agent-api-probe: no reachable cluster. This is a Tier B check: bring up the kind" >&2
    echo "agent-api-probe: cluster with Cilium, apply infra/netpol/agents-default-deny.yaml," >&2
    echo "agent-api-probe: then re-run." >&2
    abort "no reachable cluster"
fi

if ! kubectl get namespace "$AGENT_NS" >/dev/null 2>&1; then
    echo "agent-api-probe: namespace $AGENT_NS does not exist. It is created by" >&2
    echo "agent-api-probe: infra/netpol/agents-default-deny.yaml, in the same object set as the" >&2
    echo "agent-api-probe: policy that protects it. Apply that file, then re-run." >&2
    abort "namespace $AGENT_NS does not exist"
fi

# --- part 1: Cilium is the enforcing CNI -----------------------------------------------------

# Asserted first and asserted at all for the reason ADR-014 gives: the Kubernetes API accepts and
# stores a NetworkPolicy whether or not any CNI implements it, and kindnet -- which kind installs
# unless told otherwise -- implements none. Without this part the rest of the run would be measuring
# an unknown datapath, and a green result would be unattributable however clean it looked.
kubectl -n kube-system get daemonset -o name > "$work/ds" 2>"$work/ds.err" || true
if grep -q '/cilium$' "$work/ds"; then
    if grep -q 'kindnet' "$work/ds"; then
        record_fail "1-sole-cni" \
            "kindnet is present alongside cilium; the datapath under test is wrong"
    else
        record_pass "1-sole-cni" \
            "kube-system runs the cilium DaemonSet and no kindnet DaemonSet"
    fi
else
    record_fail "1-sole-cni" \
        "no cilium DaemonSet in kube-system; nothing in this cluster implements NetworkPolicy"
fi
evidence_file "$work/ds"

# The cilium CLI reports agent, operator and endpoint health together, so it is preferred when
# present. The DaemonSet's own desired-versus-ready counts are the fallback, and they are a real
# assertion rather than a placeholder: an agent missing on any node is an unenforced node.
if command -v cilium >/dev/null 2>&1; then
    cilium_rc=0
    cilium status > "$work/cstatus" 2>&1 || cilium_rc=$?
    if [ "$cilium_rc" -eq 0 ]; then
        record_pass "1-cilium-health" "cilium status reports healthy"
    else
        record_fail "1-cilium-health" \
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
        record_pass "1-cilium-health" \
            "cilium DaemonSet ready on every node it is scheduled to ($ds_ready/$ds_desired)"
    else
        record_fail "1-cilium-health" \
            "cilium DaemonSet is $ds_ready/$ds_desired ready; at least one node has no agent"
    fi
    evidence_text "cilium DaemonSet desiredNumberScheduled=$ds_desired numberReady=$ds_ready"
    evidence_text "(the cilium CLI is not on PATH, so the DaemonSet counts are the evidence)"
fi

# --- part 2: the boundary objects are present, and the cluster is in the G0 arm ---------------

# This part is NOT the proof and must not be read as one -- object presence is a statement about
# etcd, which is exactly what ADR-014 rejects as evidence. It exists so that a denial observed later
# cannot be attributed to a policy that was never applied: without it, running this script against a
# cluster with no agent policy at all would produce whatever failure that cluster produces and the
# log would still say "the boundary held".
netpol_present=$(kubectl -n "$AGENT_NS" get networkpolicy "$EGRESS_NETPOL" \
    -o 'jsonpath={.metadata.name}' 2>/dev/null || true)
if [ "$netpol_present" = "$EGRESS_NETPOL" ]; then
    record_pass "2-policy-present" \
        "NetworkPolicy $AGENT_NS/$EGRESS_NETPOL exists (presence only; enforcement is parts 4-6)"
else
    record_fail "2-policy-present" \
        "NetworkPolicy $AGENT_NS/$EGRESS_NETPOL is absent; apply agents-default-deny.yaml"
fi
evidence_text "kubectl -n $AGENT_NS get networkpolicy $EGRESS_NETPOL -> '${netpol_present:-none}'"

# The arm is read off the CiliumNetworkPolicy's own spec rather than from a flag, because the
# cluster is the thing being measured and a flag would only say what somebody intended.
cnp_deny=$(kubectl -n "$AGENT_NS" get ciliumnetworkpolicies.cilium.io "$BOUNDARY_CNP" \
    -o 'jsonpath={.spec.egressDeny[0].toEntities[0]}' 2>/dev/null || true)
cnp_allow=$(kubectl -n "$AGENT_NS" get ciliumnetworkpolicies.cilium.io "$BOUNDARY_CNP" \
    -o 'jsonpath={.spec.egress[0].toEntities[0]}' 2>/dev/null || true)

if [ "$cnp_allow" = "kube-apiserver" ]; then
    echo "agent-api-probe: this cluster is in the G2-SHAREDCRED arm: the CiliumNetworkPolicy" >&2
    echo "agent-api-probe: $AGENT_NS/$BOUNDARY_CNP carries an egress ALLOW to kube-apiserver," >&2
    echo "agent-api-probe: which is infra/netpol/agents-g2-open.yaml doing exactly its job. The" >&2
    echo "agent-api-probe: boundary is open on purpose, so every denial assertion below would" >&2
    echo "agent-api-probe: fail correctly and the log would read like a regression. Re-apply" >&2
    echo "agent-api-probe: infra/netpol/agents-default-deny.yaml to restore G0, then re-run." >&2
    abort "cluster is in the G2-SHAREDCRED arm; the denial is deliberately lifted"
fi

if [ "$cnp_deny" = "kube-apiserver" ]; then
    record_pass "2-boundary-cnp" \
        "CiliumNetworkPolicy $AGENT_NS/$BOUNDARY_CNP denies egress to entity kube-apiserver"
else
    record_fail "2-boundary-cnp" \
        "CiliumNetworkPolicy $AGENT_NS/$BOUNDARY_CNP does not deny entity kube-apiserver"
fi
evidence_text "spec.egressDeny[0].toEntities[0] -> '${cnp_deny:-none}'"
evidence_text "spec.egress[0].toEntities[0]     -> '${cnp_allow:-none}'  (empty is the G0 arm)"

# --- discovery: the API server's own address, for the second target ---------------------------

# Discovered, never written down. The EndpointSlice behind the `kubernetes` Service in `default` is
# the authoritative answer to "where does the API server actually listen"; the control-plane node's
# InternalIP with the conventional 6443 is the fallback for a cluster whose slice cannot be read.
# Which source was used is printed, because a fallback that is invisible is a fallback that gets
# mistaken for the real thing.
api_ip=$(kubectl -n default get endpointslices.discovery.k8s.io \
    -l kubernetes.io/service-name=kubernetes \
    -o 'jsonpath={.items[0].endpoints[0].addresses[0]}' 2>/dev/null || true)
api_port=$(kubectl -n default get endpointslices.discovery.k8s.io \
    -l kubernetes.io/service-name=kubernetes \
    -o 'jsonpath={.items[0].ports[0].port}' 2>/dev/null || true)
api_source="EndpointSlice for default/kubernetes"

if [ -z "$api_ip" ]; then
    api_ip=$(kubectl get nodes -l node-role.kubernetes.io/control-plane \
        -o 'jsonpath={.items[0].status.addresses[?(@.type=="InternalIP")].address}' \
        2>/dev/null || true)
    api_port="6443"
    api_source="control-plane node InternalIP (EndpointSlice lookup returned nothing)"
fi
api_port=${api_port:-6443}

echo "agent-api-probe: API server direct address discovered as ${api_ip:-unknown}:$api_port"
echo "agent-api-probe: source — $api_source"

# --- part 3: positive control, from a namespace no policy selects ------------------------------

if kubectl get namespace "$CONTROL_NS" >/dev/null 2>&1; then
    created_control_ns=0
    printf 'agent-api-probe: namespace %s already exists; it will be reused and not deleted\n' \
        "$CONTROL_NS"
else
    kubectl create namespace "$CONTROL_NS" >/dev/null
    created_control_ns=1
    printf 'agent-api-probe: namespace %s created by this run; it will be deleted on exit\n' \
        "$CONTROL_NS"
fi

kubectl apply -f - >/dev/null <<CONTROL_POD_MANIFEST
apiVersion: v1
kind: Pod
metadata:
  name: $CONTROL_POD
  namespace: $CONTROL_NS
  labels:
    app.kubernetes.io/name: $CONTROL_POD
    app.kubernetes.io/part-of: agentic-overwatch
spec:
  terminationGracePeriodSeconds: 0
  automountServiceAccountToken: false
  containers:
    - name: $PROBE_CONTAINER
      image: $PROBE_IMAGE
      args:
        - pause
CONTROL_POD_MANIFEST

kubectl -n "$CONTROL_NS" wait --for=condition=Ready "pod/$CONTROL_POD" \
    --timeout="$READY_TIMEOUT" >/dev/null \
    || abort "the control pod never became Ready; the harness cannot be trusted"

# One request. Sets the global curl_rc to curl's own exit status -- kubectl exec propagates the
# remote command's status -- and leaves the HTTP status in curl.out and any diagnostic in curl.err.
# --max-time is what makes exit 28 reachable and reachable soon; without it a dropped packet retries
# until the kernel gives up minutes later. --insecure is discussed at length in the header.
probe_once() {
    curl_rc=0
    kubectl exec -n "$1" "$2" -c "$PROBE_CONTAINER" -- \
        curl --silent --show-error --insecure --output /dev/null \
        --max-time "$CURL_MAX_TIME" --write-out '%{http_code}' \
        "$3" > "$work/curl.out" 2> "$work/curl.err" || curl_rc=$?
    http_code=$(cat "$work/curl.out" 2>/dev/null || true)
    return 0
}

probe_once "$CONTROL_NS" "$CONTROL_POD" "$API_DNS_URL"
control_rc="$curl_rc"
control_code="$http_code"

if [ "$control_rc" -eq 0 ] && [ -n "$control_code" ] && [ "$control_code" != "000" ]; then
    record_pass "3-positive-control" \
        "an unpoliced pod reached the API server (HTTP $control_code), so the harness works"
    evidence_text "curl exit 0, HTTP $control_code, target $API_DNS_URL"
    evidence_text "This retires, in one line: broken image, broken curl, broken cluster DNS, a"
    evidence_text "mis-routed kubernetes Service, a down API server, and a wrong URL or port."
else
    record_fail "3-positive-control" \
        "unpoliced request failed (curl exit $control_rc, HTTP '$control_code'); harness broken"
    evidence_text "curl exit $control_rc, HTTP '$control_code', target $API_DNS_URL"
    evidence_file "$work/curl.err"
    evidence_text "Parts 4 to 6 still run, but read them with this in mind: a denial observed"
    evidence_text "after a failed positive control is not evidence about policy."
fi

# --- the probe pod, in the agent namespace ------------------------------------------------------

# No nodeSelector and no toleration: the control-plane node's NoSchedule taint keeps this pod on a
# worker, which is where the agent layer runs and which is what makes the API server a REMOTE node
# from it. See WHY THE FIXTURES ARE INLINE.
kubectl apply -f - >/dev/null <<PROBE_POD_MANIFEST
apiVersion: v1
kind: Pod
metadata:
  name: $PROBE_POD
  namespace: $AGENT_NS
  labels:
    app.kubernetes.io/name: $PROBE_POD
    app.kubernetes.io/part-of: agentic-overwatch
spec:
  terminationGracePeriodSeconds: 0
  automountServiceAccountToken: false
  containers:
    - name: $PROBE_CONTAINER
      image: $PROBE_IMAGE
      args:
        - pause
PROBE_POD_MANIFEST
created_probe_pod=1

# The image pull is the kubelet's work, not the pod's, so a total default-deny egress does not stop
# this pod starting. That is worth knowing before reading a Ready timeout as a policy result.
kubectl -n "$AGENT_NS" wait --for=condition=Ready "pod/$PROBE_POD" \
    --timeout="$READY_TIMEOUT" >/dev/null \
    || abort "the probe pod in $AGENT_NS never became Ready; the harness cannot be trusted"

probe_ip=$(kubectl -n "$AGENT_NS" get pod "$PROBE_POD" \
    -o 'jsonpath={.status.podIP}' 2>/dev/null || true)
probe_node=$(kubectl -n "$AGENT_NS" get pod "$PROBE_POD" \
    -o 'jsonpath={.spec.nodeName}' 2>/dev/null || true)
probe_node_ip=$(kubectl get node "$probe_node" \
    -o 'jsonpath={.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)

printf 'agent-api-probe: probe pod %s/%s is %s on node %s\n' \
    "$AGENT_NS" "$PROBE_POD" "${probe_ip:-unknown}" "${probe_node:-unknown}"

# A one-node cluster, or a cluster whose control-plane node carries no NoSchedule taint, puts the
# probe on the API server's own node. The flow is then to the LOCAL host rather than to a remote
# node, which is a different security identity and therefore a different measurement. It is
# reported rather than failed, because it is a property of the cluster and not a defect in the
# policy.
if [ -n "$probe_node_ip" ] && [ "$probe_node_ip" = "$api_ip" ]; then
    echo "agent-api-probe: NOTE — the probe pod is on the API server's own node, so the flow" >&2
    echo "agent-api-probe: under test is pod-to-local-host rather than pod-to-remote-node. That" >&2
    echo "agent-api-probe: is a different Cilium identity and it is not the placement the agent" >&2
    echo "agent-api-probe: layer runs in. Read the result accordingly, and prefer a two-node" >&2
    echo "agent-api-probe: cluster built from infra/kind-config.yaml." >&2
fi

# --- part 6 support: the drop monitor, on the SOURCE's node --------------------------------------

# Egress is enforced at the source endpoint, so the agent that can see this drop is the one on the
# PROBE POD's node. scripts/netpol_proof.sh reads the destination's node because its policy denied
# ingress; copying that across unchanged would show nothing here. See DIFFERENCE 2 in the header.
cilium_pod=$(kubectl -n kube-system get pods -l k8s-app=cilium \
    --field-selector "spec.nodeName=$probe_node" \
    -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)

# Modern Cilium images ship the agent's debug CLI as cilium-dbg; older ones ship it as cilium. The
# rename is invisible from outside the pod, so the binary is probed rather than assumed, and the
# probe is a version subcommand rather than a shell test because the agent image is not guaranteed
# to contain a shell.
monitor_bin=""
if [ -n "$cilium_pod" ]; then
    if kubectl -n kube-system exec "$cilium_pod" -c cilium-agent -- \
        cilium-dbg version >/dev/null 2>&1; then
        monitor_bin="cilium-dbg"
    elif kubectl -n kube-system exec "$cilium_pod" -c cilium-agent -- \
        cilium version >/dev/null 2>&1; then
        monitor_bin="cilium"
    fi
fi

monitor_started=0
if [ -n "$monitor_bin" ]; then
    : > "$work/monitor.out"
    # stdin from /dev/null, for the reason scripts/netpol_proof.sh's start_drop_monitor gives.
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

# --- parts 4 and 5: the denial, asserted by failure MODE ------------------------------------------

# One classifier for both targets, so the two paths cannot drift into being judged by different
# rules. curl exit 28 is the only pass. Every other outcome is named, because "it failed" and "it
# failed the way a dropped packet fails" are different claims and only the second one is evidence.
classify_denial() {
    case "$curl_rc" in
        28)
            record_pass "$1" \
                "curl exit 28: timed out, which is what a silently dropped packet looks like"
            evidence_text "curl exit 28 (operation timed out) after ${CURL_MAX_TIME}s"
            evidence_text "target $2"
            ;;
        0)
            record_fail "$1" \
                "THE BOUNDARY IS OPEN: the request completed with HTTP $http_code"
            evidence_text "curl exit 0, HTTP $http_code, target $2. A pod in $AGENT_NS reached the"
            evidence_text "Kubernetes API server. security-policy.md section 1.3 does not hold on"
            evidence_text "this cluster and traceability row T-11 is not closed."
            ;;
        6)
            record_fail "$1" \
                "curl exit 6 is an unresolvable name: a DNS defect, not a demonstrated denial"
            evidence_text "curl exit 6 (could not resolve host). The policy under test PERMITS DNS"
            evidence_text "to CoreDNS deliberately, so this is a defect in that permission or in"
            evidence_text "the resolver -- not the drop this part exists to observe."
            ;;
        7)
            record_fail "$1" \
                "curl exit 7 is a refused or unreachable connection, not a policy drop"
            evidence_text "curl exit 7 (failed to connect). A refusal means something answered:"
            evidence_text "a reset, or an ICMP unreachable. A policy drops silently and gives exit"
            evidence_text "28, so what stopped this packet is not shown to be the policy."
            ;;
        35|51|58|60|77)
            record_fail "$1" \
                "curl exit $curl_rc is a TLS-layer failure: the TCP connection SUCCEEDED"
            evidence_text "curl exit $curl_rc against $2. The transport reached the API server and"
            evidence_text "the handshake is what failed -- a certificate, a cipher or a CA problem."
            evidence_text "This is a REACHABLE boundary reported by a non-zero exit code, and it is"
            evidence_text "the false pass this script exists to refuse. --insecure is already set,"
            evidence_text "so a TLS error here also means something is intercepting the connection."
            ;;
        *)
            record_fail "$1" \
                "curl exit $curl_rc is not a mode this probe recognises; treat it as unproven"
            evidence_text "curl exit $curl_rc against $2. An unrecognised status is reported as a"
            evidence_text "failure rather than assumed to be a denial: kubectl exec returns its"
            evidence_text "own status when the pod is gone, and that must never read as a pass."
            ;;
    esac
    evidence_file "$work/curl.err"
}

probe_once "$AGENT_NS" "$PROBE_POD" "$API_DNS_URL"
classify_denial "4-denial-service-path" "$API_DNS_URL"

if [ -n "$api_ip" ]; then
    api_direct_url="https://$api_ip:$api_port$API_PATH"
    probe_once "$AGENT_NS" "$PROBE_POD" "$api_direct_url"
    classify_denial "5-denial-node-path" "$api_direct_url"
    evidence_text "This target needs no DNS and no Service: it is the API server's own listener,"
    evidence_text "discovered from $api_source. A boundary that closed only the Service path could"
    evidence_text "be walked around by reading one environment variable."
else
    record_fail "5-denial-node-path" \
        "the API server's direct address could not be discovered, so the second path is untested"
    evidence_text "Neither the EndpointSlice for default/kubernetes nor a control-plane node"
    evidence_text "InternalIP yielded an address. The Service path was tested; the host-network"
    evidence_text "path was not, and this run therefore does not cover both ways in."
fi

stop_monitor

# --- part 6: attribution --------------------------------------------------------------------------

# The only assertion in the run that names Cilium's policy engine as the cause rather than inferring
# it from a symptom. Two-stage on purpose: the first stage finds drops the agent attributed to
# policy, the second requires one of them to name the probe pod's own address, so that an unrelated
# policy drop elsewhere in the cluster cannot be mistaken for evidence about this flow.
grep -F 'Policy denied' "$work/monitor.out" > "$work/drops" 2>/dev/null || true
: > "$work/drops_flow"
if [ -n "$probe_ip" ] && [ -s "$work/drops" ]; then
    grep -F "$probe_ip" "$work/drops" > "$work/drops_flow" 2>/dev/null || true
fi

if [ "$monitor_started" -ne 1 ]; then
    record_fail "6-attribution" \
        "no drop monitor ran on node ${probe_node:-unknown}, so the drop could not be attributed"
    evidence_text "cilium agent pod on ${probe_node:-unknown}: '${cilium_pod:-none found}'"
    evidence_text "monitor binary: probed cilium-dbg then cilium, found ${monitor_bin:-neither}"
    evidence_file "$work/monitor.out"
elif [ -s "$work/drops_flow" ]; then
    record_pass "6-attribution" \
        "the agent on $probe_node dropped this flow with reason 'Policy denied'"
    evidence_text "probe pod IP $probe_ip, agent pod $cilium_pod, binary $monitor_bin"
    evidence_file "$work/drops_flow"
elif [ -s "$work/drops" ]; then
    record_fail "6-attribution" \
        "policy drops were seen on $probe_node but none names the probe pod IP ${probe_ip:-unknown}"
    evidence_text "The engine denied something, but not demonstrably this flow, so the timeouts in"
    evidence_text "parts 4 and 5 and the drops below are not shown to have the same cause."
    evidence_file "$work/drops"
else
    record_fail "6-attribution" \
        "no 'Policy denied' drop event on ${probe_node:-unknown} while the requests were timing out"
    evidence_text "Something stopped the packets, but Cilium's policy engine did not say it was the"
    evidence_text "one that did, so the denial is observed and not attributed. A timeout with no"
    evidence_text "drop event is also what a black-holed route looks like."
    evidence_file "$work/monitor.out"
fi

# --- report ---------------------------------------------------------------------------------------

problem_count=$(awk 'END {print NR+0}' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        echo "agent-api-probe: FAIL — $problem_count failed assertion(s):"
        echo
        cat "$problems"
        echo
        echo "Each item is a statement about this cluster, not about this script. Read the raw"
        echo "evidence beneath the matching verdict line on stdout before changing anything:"
        echo "part 1 failing means the CNI is wrong, part 2 failing means the policy was never"
        echo "applied, part 3 failing means the harness is broken and nothing after it is evidence,"
        echo "and parts 4, 5 or 6 failing means the agent namespace can reach the Kubernetes API or"
        echo "cannot be shown not to. A failure in part 4 or 5 with curl exit 0 is the serious one:"
        echo "security-policy.md section 1.3 does not hold and T-11 is open. ADR-014 records why"
        echo "each part is required and infra/netpol/agents-default-deny.yaml records what the"
        echo "policy does and does not cover."
    } >&2
    printf 'agent-api-probe: FAIL — %s of %s assertion(s) failed\n' \
        "$problem_count" "$assert_total"
    exit 1
fi

# Two printf calls, one output line: the first deliberately has no trailing newline. The format
# string is longer than a source line should be, and splitting the call is the only way to keep both
# the source readable and the summary a single greppable line.
printf 'agent-api-probe: PASS — %s/%s assertion(s) held; ' "$assert_pass" "$assert_total"
printf 'pod %s/%s on %s reached neither %s nor the API server at %s:%s\n' \
    "$AGENT_NS" "$PROBE_POD" "${probe_node:-unknown}" "$API_DNS_URL" \
    "${api_ip:-unknown}" "$api_port"
exit 0
