#!/bin/sh
# Build and apply the Guardian workload. No credential is generated here: the signing Secret must
# already exist, so its lifecycle remains outside source control and outside this script's output.
#
# GUARDIAN_AUDIT_LOG_PATH is required and never defaulted (ADR-058, completing ADR-054 on the
# Guardian side). The runner names one attempt-unique chain per attempt,
# <audit volume>/<run-id>-<attempt suffix>.jsonl, and reads exactly that path back out of the pod.
# A path derived here from the run id alone would let a retry of one canonical run id reopen the
# failed attempt's chain -- its run-start genesis and any decision it made -- and the retry's
# bundle would then carry another attempt's evidence under its own run id. So the value is checked
# before anything touches the cluster: a .jsonl chain for this run, directly on the audit volume
# guardian/deploy/deployment.yaml mounts, which is what lets it survive a pod restart.
set -eu
LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

# The Guardian's audit volume: the mountPath guardian/deploy/deployment.yaml gives it. The replay
# store below lives on it too. runner/live_evidence.py's GUARDIAN_AUDIT_ROOT names the same
# directory, and runner/tests/test_guardian_deploy.py holds the three spellings equal.
audit_dir=/var/lib/guardian/audit

mode=${GUARDIAN_MODE:-G0-FULL}
case "$mode" in G0-FULL|G1-LOGONLY|G2-SHAREDCRED) ;; *) echo "guardian-deploy: invalid runner mode $mode" >&2; exit 1 ;; esac

require_runner_setting() {
    eval "setting=\${$1:-}"
    [ -n "$setting" ] || { echo "guardian-deploy: runner setting $1 is required" >&2; exit 1; }
}
for setting_name in GUARDIAN_RUN_ID GUARDIAN_REGISTERED_ISSUERS GUARDIAN_AUDIT_LOG_PATH \
    GUARDIAN_TOKEN_TTL_SECONDS GUARDIAN_TOKEN_MAX_TTL_SECONDS GUARDIAN_TOKEN_ALGORITHM \
    GUARDIAN_REPLAY_CACHE_ENTRIES GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS \
    GUARDIAN_CONTROL_PLANE_SUBJECT GUARDIAN_CONTROL_PLANE_AUDIENCE; do
    require_runner_setting "$setting_name"
done

if [ "$(dirname -- "$GUARDIAN_AUDIT_LOG_PATH")" != "$audit_dir" ]; then
    echo "guardian-deploy: GUARDIAN_AUDIT_LOG_PATH must name a chain directly on the Guardian's audit volume $audit_dir; got $GUARDIAN_AUDIT_LOG_PATH" >&2
    exit 1
fi
case "$(basename -- "$GUARDIAN_AUDIT_LOG_PATH")" in
    "$GUARDIAN_RUN_ID"-?*.jsonl) ;;
    *)
        echo "guardian-deploy: GUARDIAN_AUDIT_LOG_PATH must name this attempt's own chain, $audit_dir/$GUARDIAN_RUN_ID-<attempt suffix>.jsonl; got $GUARDIAN_AUDIT_LOG_PATH" >&2
        exit 1
        ;;
esac

# One cluster, one lock (supervisor ruling B6, docs/plans/supervisor-rulings-2026-09-13.md; ADR-087).
# runner/run_lock.py's cluster_lease holds a coordination.k8s.io Lease in this namespace for the
# whole live attempt, with holderIdentity "<run_id>/<started_at>/<host>/<pid>". Checking it again
# here -- immediately before the one action that actually endangers another run, rewriting this
# Guardian's identity -- is the second half of that lock, not a redundant one: it is what catches a
# direct or manual invocation of this script that never went through the runner at all (`make up`
# bring-up is exactly that, which is why an absent or stale lease must still let it through), and
# the small window between the runner acquiring the lease and this script actually running.
#
# jsonpath, not `-o json`: this script is strict POSIX sh with no jq, and every other guard script
# in scripts/ already reads a single field this way rather than parsing JSON (see scripts/status.sh).
# holderIdentity is a plain "/"-delimited string rather than JSON for the same reason: ${x%%/*}
# reads the run id back out with parameter expansion alone.
lease_namespace=guardian
lease_name=live-run-lock
if ! lease_line=$(kubectl -n "$lease_namespace" get lease "$lease_name" \
    -o jsonpath='{.spec.holderIdentity}|{.spec.renewTime}|{.spec.leaseDurationSeconds}' 2>&1); then
    case "$lease_line" in
        *NotFound*) lease_line="" ;;  # no lease yet: fresh bring-up and the first-ever run proceed
        *)
            echo "guardian-deploy: could not read the run lock lease $lease_namespace/$lease_name: $lease_line" >&2
            exit 1
            ;;
    esac
fi
if [ -n "$lease_line" ]; then
    holder_identity=$(printf '%s' "$lease_line" | cut -d'|' -f1)
    renew_time=$(printf '%s' "$lease_line" | cut -d'|' -f2)
    lease_duration=$(printf '%s' "$lease_line" | cut -d'|' -f3)
    holder_run_id=${holder_identity%%/*}
    # Refuses only on affirmative evidence of a fresh foreign holder. Anything this cannot parse --
    # a timestamp date(1) rejects, an empty duration -- is treated the same as absent rather than as
    # a reason to block: this check backs up runner/run_lock.py's own compare-and-swap, it is not
    # the only place contamination is caught, and a parsing edge case must not itself become a
    # permanent deploy deadlock.
    if [ -n "$lease_duration" ] && renew_epoch=$(date -u -d "$renew_time" +%s 2>/dev/null); then
        now_epoch=$(date -u +%s)
        fresh_until=$((renew_epoch + lease_duration))
        # A campaign holding the Lease across its whole span (ADR-101) exports its exact holder
        # identity to every attempt it drives as RUNNER_CAMPAIGN_LEASE_HOLDER. An attempt running
        # under that campaign is not a foreign holder, which is how runner/run_lock.py's re-entrant
        # cluster_lease already treats it; only an exact identity match is accepted (ADR-104).
        if [ "$fresh_until" -gt "$now_epoch" ] && [ "$holder_run_id" != "$GUARDIAN_RUN_ID" ] \
            && [ "$holder_identity" != "${RUNNER_CAMPAIGN_LEASE_HOLDER:-}" ]; then
            echo "guardian-deploy: refusing to reconfigure -- $lease_namespace/$lease_name is held by run '$holder_run_id' for $((fresh_until - now_epoch))s more, not GUARDIAN_RUN_ID=$GUARDIAN_RUN_ID. One cluster, one lock: see runner/run_lock.py and ADR-087." >&2
            exit 1
        fi
    fi
fi

kubectl apply -f guardian/deploy/rbac.yaml
# Who may reach the mediation surface: pods in `agents`, and nothing else (ADR-076). Applied on every
# deploy, and the runner deploys at the start of every attempt, so the reach boundary is identical in
# every arm and no condition flag can alter it. The namespace exists once rbac.yaml has applied.
kubectl apply -f infra/netpol/guardian-ingress.yaml
kubectl -n guardian get secret guardian-signing-key >/dev/null 2>&1 || {
    echo "guardian-deploy: guardian/guardian-signing-key is absent; create it out of band" >&2
    exit 1
}
# ADR-130: the Ed25519 audit-signing key. deployment.yaml mounts it as a required volume, so a pod
# would otherwise hang Pending on a missing Secret; fail here with the same out-of-band message the
# token key gives. Generate and load it once, out of source control (rule 4, rule 10):
#   openssl genpkey -algorithm ed25519 -out audit-signing-key.pem
#   kubectl -n guardian create secret generic guardian-audit-signing-key \
#     --from-file=audit-signing-key=audit-signing-key.pem
kubectl -n guardian get secret guardian-audit-signing-key >/dev/null 2>&1 || {
    echo "guardian-deploy: guardian/guardian-audit-signing-key is absent; create it out of band (ADR-130)" >&2
    exit 1
}

sh scripts/guardian_image.sh
kubectl -n guardian create configmap guardian-runtime --dry-run=client -o yaml \
  --from-literal="GUARDIAN_MODE=$mode" \
  --from-literal="GUARDIAN_RUN_ID=$GUARDIAN_RUN_ID" \
  --from-literal="GUARDIAN_REGISTERED_ISSUERS=$GUARDIAN_REGISTERED_ISSUERS" \
  --from-literal="GUARDIAN_CONTROL_PLANE_SUBJECT=$GUARDIAN_CONTROL_PLANE_SUBJECT" \
  --from-literal="GUARDIAN_CONTROL_PLANE_AUDIENCE=$GUARDIAN_CONTROL_PLANE_AUDIENCE" \
  --from-literal="GUARDIAN_TOKEN_TTL_SECONDS=$GUARDIAN_TOKEN_TTL_SECONDS" \
  --from-literal="GUARDIAN_TOKEN_MAX_TTL_SECONDS=$GUARDIAN_TOKEN_MAX_TTL_SECONDS" \
  --from-literal="GUARDIAN_TOKEN_ALGORITHM=$GUARDIAN_TOKEN_ALGORITHM" \
  --from-literal="GUARDIAN_REPLAY_CACHE_ENTRIES=$GUARDIAN_REPLAY_CACHE_ENTRIES" \
  --from-literal="GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS=$GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS" \
  --from-literal=GUARDIAN_POLICY_BUNDLE_PATH=/app/guardian/policies \
  --from-literal=GUARDIAN_POLICY_ENTRYPOINT=data.guardian.decision \
  --from-literal=GUARDIAN_ISSUANCE_ENTRYPOINT=data.guardian.issuance.decision \
  --from-literal=GUARDIAN_POLICY_TIMEOUT_SECONDS=2 \
  --from-literal="GUARDIAN_AUDIT_LOG_PATH=$GUARDIAN_AUDIT_LOG_PATH" \
  --from-literal=GUARDIAN_REPLAY_STORE_PATH=/var/lib/guardian/audit/guardian_replay.sqlite3 \
  --from-literal=GUARDIAN_EXECUTOR=kubernetes | kubectl apply -f -
kubectl apply -f guardian/deploy/deployment.yaml
kubectl -n guardian rollout restart deployment/guardian
kubectl -n guardian rollout status deployment/guardian --timeout="${GUARDIAN_ROLLOUT_TIMEOUT:-300s}"
# The existing port-forward targets a pod selected before this rollout. Restart only the managed
# Guardian forwarder so the agent cannot race a terminated pod after a per-run Guardian restart.
sh scripts/port_forward.sh down >/dev/null 2>&1 || true
sh scripts/port_forward.sh up >/dev/null
printf 'guardian-deploy: PASS — Guardian ready in mode %s (live cluster verification not implied)\n' "$mode"
