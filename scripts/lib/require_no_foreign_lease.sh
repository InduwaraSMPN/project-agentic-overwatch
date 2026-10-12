# shellcheck shell=sh
# require_no_foreign_lease.sh -- the "one cluster, one lock" lease guard, as a sourceable function.
#
# WHAT THIS IS
# The lease half of the run lock (supervisor ruling B6, docs/plans/supervisor-rulings-2026-09-13.md;
# ADR-087, ADR-101, ADR-104), lifted verbatim out of scripts/guardian_deploy.sh:51-99 so that a
# hand-run cluster script can refuse to touch a cluster another run holds. V24 recorded that the
# pre-campaign scripts/*_tmp.sh ran WITHOUT this check -- calibrate_five_tmp.sh "bypasses the lease"
# -- which is exactly the contamination the lease exists to stop. A hand-run script that mutates the
# shared cluster sources this file and calls the function before its first mutating action.
#
# WHY A SOURCEABLE FUNCTION RATHER THAN A COPY IN EACH SCRIPT
# The alternative is the check pasted into every hand-run script, and a check pasted five times is a
# check that will be fixed in four of them. guardian_deploy.sh keeps its own inline copy for now
# (it is another workstream's file and is not edited here); this library is the single home every
# NEW or archived hand-run script draws from, so the refusal logic has exactly one place to be right.
#
# CONTRACT
#   require_no_foreign_lease [run_id]
#     run_id  the canonical run id claiming the cluster; defaults to $GUARDIAN_RUN_ID. A hand-run
#             calibration or probe that has no run id of its own passes a stable label ("manual-...")
#             so the refusal message names who is asking.
#   Returns 0 when the cluster is free to touch -- no lease, an expired lease, an unparseable lease,
#   or a lease this run (or its campaign, via $RUNNER_CAMPAIGN_LEASE_HOLDER) already holds -- and 1
#   with a message on stderr when a fresh FOREIGN holder owns it. The caller decides what a refusal
#   means; the idiom is `require_no_foreign_lease "$RUN_ID" || exit 1`, so a refusal aborts the
#   hand-run script exactly as the inline check aborts guardian_deploy.sh. It never calls `exit`
#   itself, so sourcing it cannot take down an interactive shell.
#
# WHY IT REFUSES ONLY ON AFFIRMATIVE EVIDENCE (unchanged from guardian_deploy.sh)
# Anything this cannot parse -- a NotFound, a timestamp date(1) rejects, an empty duration -- is
# treated the same as absent rather than as a reason to block: this backs up runner/run_lock.py's own
# compare-and-swap, it is not the only place contamination is caught, and a parsing edge case must
# not itself become a permanent deploy deadlock.
#
# PORTABILITY
# Strict POSIX sh -- no bashisms, no jq. Reads a single jsonpath field with kubectl and parameter
# expansion, the way scripts/status.sh and guardian_deploy.sh already do, so it runs under dash in
# WSL2 Ubuntu, under Git Bash on the Windows host, and on ubuntu-latest.
#
# WHAT BREAKS IF THIS FILE CHANGES
# Every hand-run cluster script that sources it. The authority for the behaviour is
# scripts/guardian_deploy.sh:51-99 and ADR-087; keep the two in step, and prefer moving
# guardian_deploy.sh onto this library over letting the two diverge.

# The lease coordinates. The same namespace/name runner/run_lock.py's cluster_lease holds and
# guardian_deploy.sh checks; named here as overridable variables only so a test can point the guard
# at a throwaway lease without editing the function.
: "${GUARDIAN_LEASE_NAMESPACE:=guardian}"
: "${GUARDIAN_LEASE_NAME:=live-run-lock}"

require_no_foreign_lease() {
    rnfl_run_id=${1:-${GUARDIAN_RUN_ID:-}}
    if [ -z "$rnfl_run_id" ]; then
        echo "require-no-foreign-lease: no run id given and GUARDIAN_RUN_ID is unset; pass the run id (or a 'manual-<who>' label) so a refusal can name who is asking" >&2
        return 1
    fi

    # jsonpath, not `-o json`: strict POSIX sh with no jq, exactly as guardian_deploy.sh reads it.
    # holderIdentity is a plain "/"-delimited string, so ${x%%/*} reads the run id back out with
    # parameter expansion alone.
    if ! rnfl_line=$(kubectl -n "$GUARDIAN_LEASE_NAMESPACE" get lease "$GUARDIAN_LEASE_NAME" \
        -o jsonpath='{.spec.holderIdentity}|{.spec.renewTime}|{.spec.leaseDurationSeconds}' 2>&1); then
        case "$rnfl_line" in
            *NotFound*) return 0 ;;  # no lease yet: fresh bring-up and the first-ever run proceed
            *)
                echo "require-no-foreign-lease: could not read the run lock lease $GUARDIAN_LEASE_NAMESPACE/$GUARDIAN_LEASE_NAME: $rnfl_line" >&2
                return 1
                ;;
        esac
    fi
    [ -n "$rnfl_line" ] || return 0

    rnfl_holder=$(printf '%s' "$rnfl_line" | cut -d'|' -f1)
    rnfl_renew=$(printf '%s' "$rnfl_line" | cut -d'|' -f2)
    rnfl_duration=$(printf '%s' "$rnfl_line" | cut -d'|' -f3)
    rnfl_holder_run=${rnfl_holder%%/*}

    # Only an affirmatively fresh, foreign holder refuses. A duration or renewTime this cannot parse
    # is treated as absent, per the header.
    if [ -n "$rnfl_duration" ] && rnfl_renew_epoch=$(date -u -d "$rnfl_renew" +%s 2>/dev/null); then
        rnfl_now=$(date -u +%s)
        rnfl_fresh_until=$((rnfl_renew_epoch + rnfl_duration))
        # A campaign holding the Lease across its whole span (ADR-101) exports its exact holder
        # identity as RUNNER_CAMPAIGN_LEASE_HOLDER; an attempt under that campaign is not foreign,
        # which is how runner/run_lock.py's re-entrant cluster_lease already treats it (ADR-104).
        if [ "$rnfl_fresh_until" -gt "$rnfl_now" ] && [ "$rnfl_holder_run" != "$rnfl_run_id" ] \
            && [ "$rnfl_holder" != "${RUNNER_CAMPAIGN_LEASE_HOLDER:-}" ]; then
            echo "require-no-foreign-lease: refusing -- $GUARDIAN_LEASE_NAMESPACE/$GUARDIAN_LEASE_NAME is held by run '$rnfl_holder_run' for $((rnfl_fresh_until - rnfl_now))s more, not '$rnfl_run_id'. One cluster, one lock: see runner/run_lock.py and ADR-087." >&2
            return 1
        fi
    fi
    return 0
}
