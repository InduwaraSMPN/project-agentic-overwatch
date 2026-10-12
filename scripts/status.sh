#!/bin/sh
#
# status.sh -- print one line per declared component and exit non-zero if any component that
# should be running is not. Backs `make status`, whose contract is docs/04-repo-conventions.md
# section 3: "cluster, app, monitor, guardian health summary".
#
# WHAT THIS CHECK IS FOR, WHICH IS NOT "INFORMATION"
# docs/protocols/evaluation-protocol.md section 5 rule 1 makes a green `make status` the preflight
# gate for every single run. That is the only reason the exit status matters: a run that starts
# against a half-present environment produces a bundle that looks like every other bundle, and the
# defect surfaces, if at all, as unexplained variance in Chapter 5. So this script is a gate that
# happens to print a report, not a report that happens to return a number.
#
# WHY THE COMPONENT SET IS DATA AND NOT CODE
# The contract names a Monitor and a Guardian. Neither exists at M1 -- they land at M2 and M3 --
# so a status implementation written against the M1 tree would check the two components that do
# exist and print PASS. It would keep printing PASS at M7 with the Guardian down, unless somebody
# had remembered to come back and extend it. infra/status/components.yaml is that list, declared
# once, with the milestone that deploys each component; this script executes it and refuses to
# have an opinion about which components exist. Its header carries the schema and the rest of the
# argument.
#
# HOW "HAS THIS COMPONENT LANDED" IS DECIDED
# Each row carries an explicit `landed: true|false` value. Milestone workflow status is not deploy
# state: M2 may be gated after its offline Python package lands while its Falco and aggregator
# workloads do not, and M3 may be active while its Guardian is only an in-process Tier-A service.
# Treating either state as deployed makes an M1 bring-up fail for honest later-milestone work.
#
# The explicit value is maintained with the deployment surface: the change that authors the
# workload flips `landed` to true, fills the health-check coordinates and names its owner path.
# Once true, deleting or renaming that owner cannot silently downgrade the check; it is a failure.
# A missing or unrecognised value also fails, so malformed data cannot remove a component from the
# gate. This mechanism and its update obligation are recorded in ADR-044.
#
# PLACEHOLDER ROWS CLOSE THEMSELVES
# M2's and M3's rows carry "?" in the fields only those milestones can fill. While the milestone
# has not landed, the row prints not-deployed and the "?" is correct. The moment the milestone
# lands, an unfilled "?" becomes a FAILURE naming infra/status/components.yaml, so a placeholder
# cannot survive into the milestone that was supposed to replace it.
#
# THREE PRECONDITIONS, CHECKED BEFORE ANY COMPONENT
#   kubectl on PATH. Without it nothing can be observed, and "observed nothing" must not read as
#   "nothing is wrong".
#   A reachable cluster on the current context. A `make status` that exits 0 on a machine with no
#   cluster would let a run start against nothing at all. There is no environment in which the
#   preflight gate for a run should be green with no cluster, so this is unconditional.
#   The current context is a kind context. This project's cluster is kind (ADR-001); a status
#   check that would happily gate a run against whatever cluster kubectl last pointed at is a
#   footgun with no upside. There is deliberately no environment variable to relax this, for the
#   reason scripts/grep_guard.sh gives about its own absent exemption mechanism: an escape hatch
#   added before the first real need is sized to convenience rather than to risk.
#
# AND ONE FLOOR
# At least one component must have been checked. Zero checked components produce zero problems,
# and an all-clear over nothing is byte-identical to an all-clear over everything -- the same
# defect the M0 audit found in scripts/check_hygiene.sh's EOL sweep. Before M1's first manifests
# land, the honest answer is that this gate cannot yet certify anything, and it says so.
#
# OUTPUT SHAPE
# Per-component detail on stderr, one summary line on stdout, PASS/FAIL wording -- the conventions
# scripts/check_hygiene.sh established, so that a caller can capture the verdict without parsing
# the report and a human reading a terminal sees both.
#
# ENVIRONMENT
#   COMPONENTS_FILE          declared component set, default infra/status/components.yaml
#   STATUS_KUBECTL_TIMEOUT   per-request timeout passed to kubectl, default 10s. It bounds the
#                            runtime of a status check against an unreachable API server; it
#                            changes no verdict that a longer wait would change.
#   UP_PROFILE               which bring-up profile's components this check reports over, default
#                            `full` (every component). `substrate` omits the components whose
#                            deployment needs operator-supplied material no ephemeral machine has --
#                            today the Guardian alone, whose `guardian-signing-key` is operator-
#                            supplied out of band and which ADR-114 forbids any path in this
#                            repository from creating. See the PROFILES paragraph of
#                            infra/status/components.yaml. A RUN'S PREFLIGHT MUST NEVER SET IT:
#                            evaluation-protocol section 5 rule 1 gates every run on this check,
#                            the Guardian is exactly what that gate must see, and the summary line
#                            names the profile so a weakened gate cannot read as a full one.
#
# STREAMS
#   stdout: exactly one summary line. stderr: one line per component, the precondition results,
#   and the remediation. Exit 0 when every landed component is healthy, 1 otherwise.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs identically under Git Bash on
#   Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in CI.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

COMPONENTS_FILE=${COMPONENTS_FILE:-infra/status/components.yaml}
STATUS_KUBECTL_TIMEOUT=${STATUS_KUBECTL_TIMEOUT:-10s}
UP_PROFILE=${UP_PROFILE:-full}

case "$UP_PROFILE" in
    full|substrate) ;;
    *)
        printf 'status: FAIL — UP_PROFILE is %s, not one of full, substrate\n' "$UP_PROFILE" >&2
        printf 'status: FAIL — unknown bring-up profile\n'
        exit 1
        ;;
esac

if [ ! -f "$COMPONENTS_FILE" ]; then
    printf 'status: FAIL — declared component set not found at %s (owned by M1-T1.6)\n' \
        "$COMPONENTS_FILE" >&2
    printf 'status: FAIL — component set missing\n'
    exit 1
fi

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM
rows="$work/rows"
problems="$work/problems"
: > "$problems"

problem() {
    printf '%s\n' "$1" >> "$problems"
}

# --- read the declared component set ------------------------------------------------------------

# The same parser scripts/up.sh and scripts/down.sh carry, extended to emit whole records. Strip
# the CR a Windows checkout may carry, drop blanks and comments, treat a leading "- " as the start
# of a record, split on the first colon, and strip one layer of double quotes. Fields are emitted
# pipe-separated because no field may contain a pipe -- ids, milestones, kinds, namespaces, names
# and paths cannot, and the description field is prose the schema constrains.
awk '
    function emit() {
        if (id == "") return
        printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", id, milestone, landed, kind, namespace, name, min_count, owner, required_in, description
    }
    {
        line = $0
        sub(/\r$/, "", line)
        sub(/^[ \t]+/, "", line)
        if (line == "" || substr(line, 1, 1) == "#") next
        isnew = 0
        if (substr(line, 1, 2) == "- ") {
            isnew = 1
            line = substr(line, 3)
            sub(/^[ \t]+/, "", line)
        }
        ci = index(line, ":")
        if (ci == 0) next
        k = substr(line, 1, ci - 1)
        v = substr(line, ci + 1)
        sub(/^[ \t]+/, "", v)
        sub(/[ \t]+$/, "", v)
        sub(/^"/, "", v)
        sub(/"$/, "", v)
        if (k !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next
        if (isnew) {
            emit()
            id = ""; milestone = ""; landed = ""; kind = ""; namespace = ""
            name = ""; min_count = ""; owner = ""; required_in = ""; description = ""
        } else if (id == "" && k != "id") {
            next
        }
        if (k == "id") id = v
        else if (k == "milestone") milestone = v
        else if (k == "landed") landed = v
        else if (k == "kind") kind = v
        else if (k == "namespace") namespace = v
        else if (k == "name") name = v
        else if (k == "min_count") min_count = v
        else if (k == "owner") owner = v
        else if (k == "required_in") required_in = v
        else if (k == "description") description = v
    }
    END { emit() }
' "$COMPONENTS_FILE" > "$rows"

# A record whose first key is not `id` is dropped by the parser above, silently, which would take
# a component out of the gate without saying so. Count what the file declares and what the parser
# produced, and refuse to report at all if the two disagree.
declared_records=$(awk '{ line = $0; sub(/^[ \t]+/, "", line) }
                        line ~ /^-[ \t]+id:/ { n++ }
                        END { print n + 0 }' "$COMPONENTS_FILE")
parsed_records=$(awk 'END { print NR }' "$rows")

if [ "$declared_records" -ne "$parsed_records" ]; then
    {
        printf 'status: FAIL — %s declares %s component record(s) but %s parsed.\n' \
            "$COMPONENTS_FILE" "$declared_records" "$parsed_records"
        echo "Every record must begin with its 'id' key; see the SCHEMA section of that file."
    } >&2
    printf 'status: FAIL — component set is malformed\n'
    exit 1
fi

if [ "$parsed_records" -eq 0 ]; then
    printf 'status: FAIL — %s declares no components at all\n' "$COMPONENTS_FILE" >&2
    printf 'status: FAIL — component set is empty\n'
    exit 1
fi

# --- preconditions ------------------------------------------------------------------------------

report() {
    printf 'status: %-20s %-13s %s\n' "$1" "$2" "$3" >&2
}

cluster_reachable=0
cluster_reason=""
kube_context=""

if ! command -v kubectl >/dev/null 2>&1; then
    cluster_reason="kubectl is not on PATH"
    problem "kubectl is not on PATH, so no component could be observed"
else
    kube_context=$(kubectl config current-context 2>/dev/null || true)
    if [ -z "$kube_context" ]; then
        cluster_reason="no current kubectl context"
        problem "kubectl has no current context, so there is no cluster to gate a run against"
    elif ! kubectl --request-timeout="$STATUS_KUBECTL_TIMEOUT" get --raw=/version >/dev/null 2>&1
    then
        cluster_reason="cluster unreachable on context $kube_context"
        problem "the API server on context $kube_context did not answer within $STATUS_KUBECTL_TIMEOUT"
    else
        case "$kube_context" in
            kind-*)
                cluster_reachable=1
                ;;
            *)
                cluster_reason="context $kube_context is not a kind context"
                msg="the current context is $kube_context, which is not a kind cluster."
                msg="$msg This project's environment is kind (ADR-001) and make status will not"
                msg="$msg gate a run against a cluster it did not create"
                problem "$msg"
                ;;
        esac
    fi
fi

if [ "$cluster_reachable" -eq 1 ]; then
    report "cluster-context" "ok" "$kube_context"
else
    report "cluster-context" "FAIL" "$cluster_reason"
fi

kget() {
    kubectl --request-timeout="$STATUS_KUBECTL_TIMEOUT" "$@" > "$work/out" 2> "$work/err"
}

# One kubectl error line, trimmed, so that a component's detail column stays one line.
kerr() {
    awk 'NF { print; exit }' "$work/err" 2>/dev/null || true
}

# --- per-kind health checks -----------------------------------------------------------------------
#
# Each sets check_ok to 1 or 0 and check_detail to one line of evidence. jsonpath is used rather
# than table output because column headers and widths are presentation and have changed between
# kubectl releases, while these field paths are API. An absent numeric field prints empty and is
# read as zero, which is correct: .status.readyReplicas is absent, not zero, on a Deployment that
# has never had a ready pod.

check_nodes() {
    if ! kget get nodes -o 'jsonpath={range .items[*]}{.metadata.name}{"|"}{range @.status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}'
    then
        check_ok=0
        check_detail="kubectl get nodes failed: $(kerr)"
        return 0
    fi
    nodes_total=$(awk 'NF { n++ } END { print n + 0 }' "$work/out")
    nodes_ready=$(awk -F'|' '$2 == "True" { n++ } END { print n + 0 }' "$work/out")
    check_detail="$nodes_ready/$nodes_total node(s) Ready (floor $check_min, context $kube_context)"
    if [ "$nodes_ready" -ge "$check_min" ] && [ "$nodes_ready" -eq "$nodes_total" ]; then
        check_ok=1
    else
        check_ok=0
    fi
}

# A workload scaled to zero replicas is reported unhealthy, not vacuously healthy: `want > 0` is
# part of the condition. This matters for Locust specifically, which is deployed IDLE -- at zero
# simulated users -- and not at zero replicas. An idle Locust has a running pod waiting to be
# driven; a Locust scaled to zero has nothing to drive, and a run gated on that would produce a
# bundle with an empty locust_stats.csv and no indication of why.
check_one_workload() {
    if ! kget -n "$check_ns" get "$check_kind" "$check_name" -o "jsonpath=$1"; then
        check_ok=0
        check_detail="$check_kind $check_ns/$check_name not found: $(kerr)"
        return 0
    fi
    want=$(awk -F'|' '{ print ($1 == "" ? 0 : $1 + 0) }' "$work/out")
    have=$(awk -F'|' '{ print ($2 == "" ? 0 : $2 + 0) }' "$work/out")
    check_detail="$check_kind $check_ns/$check_name $have/$want ready (floor $check_min)"
    if [ "$have" -ge "$want" ] && [ "$have" -ge "$check_min" ] && [ "$want" -gt 0 ]; then
        check_ok=1
    else
        check_ok=0
    fi
}

# The "@all" form: every object of the kind in the namespace must be ready, and there must be at
# least min_count of them. The floor is what stops the sweep passing over an empty namespace,
# where zero objects produce zero unready objects.
check_all_workloads() {
    if ! kget -n "$check_ns" get "${check_kind}s" -o "jsonpath=$1"; then
        check_ok=0
        check_detail="listing ${check_kind}s in $check_ns failed: $(kerr)"
        return 0
    fi
    all_total=$(awk 'NF { n++ } END { print n + 0 }' "$work/out")
    all_ready=$(awk -F'|' 'NF >= 3 {
                    want = ($2 == "" ? 0 : $2 + 0)
                    have = ($3 == "" ? 0 : $3 + 0)
                    if (want > 0 && have >= want) n++
                } END { print n + 0 }' "$work/out")
    check_detail="namespace $check_ns: $all_ready/$all_total ${check_kind}(s) ready (floor $check_min)"
    if [ "$all_total" -ge "$check_min" ] && [ "$all_ready" -eq "$all_total" ]; then
        check_ok=1
    else
        check_ok=0
    fi
}

DEPLOY_ONE='{.spec.replicas}{"|"}{.status.readyReplicas}'
DEPLOY_ALL='{range .items[*]}{.metadata.name}{"|"}{.spec.replicas}{"|"}{.status.readyReplicas}{"\n"}{end}'
DS_ONE='{.status.desiredNumberScheduled}{"|"}{.status.numberReady}'
DS_ALL='{range .items[*]}{.metadata.name}{"|"}{.status.desiredNumberScheduled}{"|"}{.status.numberReady}{"\n"}{end}'

# --- the report ------------------------------------------------------------------------------------

checked=0
healthy=0
skipped=0
not_required=0
milestones_pending=""

while IFS='|' read -r c_id c_ms c_landed c_kind c_ns c_name c_min c_owner c_required c_desc; do
    [ -n "$c_id" ] || continue

    # A component the active profile does not require is reported and skipped. An ABSENT
    # `required_in` means every profile, so an omitted key can only ADD a requirement and never
    # drop one. A value naming a profile this script does not know is a FAILURE rather than a skip:
    # the direction that matters here is a typo silently taking the Guardian out of a run's gate.
    if [ -n "$c_required" ]; then
        case "$c_required" in
            full|substrate|full,substrate|substrate,full) ;;
            *)
                detail="invalid required_in value '$c_required' in $COMPONENTS_FILE"
                report "$c_id" "FAIL" "$detail"
                problem "$c_id: $detail — expected a comma-separated subset of full, substrate"
                continue
                ;;
        esac
        case ",$c_required," in
            *",$UP_PROFILE,"*) ;;
            *)
                not_required=$((not_required + 1))
                report "$c_id" "not-required" "(profile $UP_PROFILE) $c_desc"
                continue
                ;;
        esac
    fi

    case "$c_landed" in
        false)
            skipped=$((skipped + 1))
            case " $milestones_pending " in
                *" $c_ms "*) ;;
                *) milestones_pending="$milestones_pending $c_ms" ;;
            esac
            report "$c_id" "not-deployed" "($c_ms) $c_desc"
            continue
            ;;
        true)
            ;;
        *)
            checked=$((checked + 1))
            detail="invalid landed value '$c_landed' in $COMPONENTS_FILE; expected true or false"
            report "$c_id" "FAIL" "$detail"
            problem "$c_id: $detail"
            continue
            ;;
    esac

    checked=$((checked + 1))

    if [ -z "$c_owner" ] || [ "$c_owner" = "?" ] || [ ! -e "$c_owner" ]; then
        detail="landed component's deploy surface is absent: $c_owner"
        report "$c_id" "FAIL" "$detail"
        problem "$c_id: $detail"
        continue
    fi

    if [ "$c_ns" = "?" ] || [ "$c_name" = "?" ]; then
        detail="component is landed but the check specification is still a placeholder"
        report "$c_id" "FAIL" "$detail"
        problem "$c_id: $detail — fill namespace and name in $COMPONENTS_FILE"
        continue
    fi

    if [ "$cluster_reachable" -eq 0 ]; then
        report "$c_id" "FAIL" "not observed — $cluster_reason"
        problem "$c_id: not observed — $cluster_reason"
        continue
    fi

    check_ok=0
    check_detail=""
    check_ns=$c_ns
    check_name=$c_name
    check_kind=$c_kind
    check_min=$c_min
    [ -n "$check_min" ] || check_min=1

    case "$c_kind" in
        nodes)
            check_nodes
            ;;
        deployment|statefulset)
            if [ "$c_name" = "@all" ]; then
                check_all_workloads "$DEPLOY_ALL"
            else
                check_one_workload "$DEPLOY_ONE"
            fi
            ;;
        daemonset)
            if [ "$c_name" = "@all" ]; then
                check_all_workloads "$DS_ALL"
            else
                check_one_workload "$DS_ONE"
            fi
            ;;
        *)
            check_ok=0
            check_detail="unrecognised kind '$c_kind' in $COMPONENTS_FILE"
            ;;
    esac

    if [ "$check_ok" -eq 1 ]; then
        healthy=$((healthy + 1))
        report "$c_id" "ok" "$check_detail"
    else
        report "$c_id" "FAIL" "$check_detail"
        problem "$c_id: $check_detail"
    fi
done < "$rows"

# --- the vacuity floor ------------------------------------------------------------------------------

# Zero checked components produce zero problems, and an all-clear over nothing reads exactly like
# an all-clear over everything. Before M1's first manifests land this is the honest state of the
# repository, and the gate says so rather than certifying an environment it never looked at.
if [ "$checked" -eq 0 ]; then
    msg="no component in $COMPONENTS_FILE has landed yet, so this gate certified nothing."
    msg="$msg docs/protocols/evaluation-protocol.md section 5 rule 1 gates every run on a green"
    msg="$msg make status, and a green over an empty check set would gate nothing"
    problem "$msg"
fi

# --- report -----------------------------------------------------------------------------------------

pending_note=""
if [ -n "$milestones_pending" ]; then
    pending_note=$(printf '%s' "$milestones_pending" | sed -e 's/^ *//' -e 's/ *$//' -e 's/  */, /g')
    pending_note=" (${pending_note})"
fi

# A weakened gate must not read as a full one. The profile is named on the summary line whenever it
# has left a component out, which is the only case in which a green here means less than "every
# declared component is up".
profile_note=""
if [ "$not_required" -gt 0 ]; then
    profile_note=", $not_required not required in profile $UP_PROFILE"
fi

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        echo
        echo "status: FAIL — $problem_count problem(s):"
        echo
        cat "$problems"
        echo
        echo "Each item above is a property of the environment or of the declared component set,"
        echo "not of this check. Bring the environment up with 'make up'; if a component is"
        echo "declared in $COMPONENTS_FILE but its manifests are not in the tree, the milestone"
        echo "named on the row is the one that owes them. docs/protocols/evaluation-protocol.md"
        echo "section 5 rule 1 gates every run on this check, so do not start a run until it is"
        echo "green."
    } >&2
    printf 'status: FAIL — %s problem(s); %s of %s component(s) healthy, %s not deployed%s%s\n' \
        "$problem_count" "$healthy" "$checked" "$skipped" "$pending_note" "$profile_note"
    exit 1
fi

printf 'status: PASS — %s/%s declared component(s) healthy on context %s, %s not deployed%s%s\n' \
    "$healthy" "$checked" "$kube_context" "$skipped" "$pending_note" "$profile_note"
exit 0
