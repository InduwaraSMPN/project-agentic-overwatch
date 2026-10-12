#!/bin/sh
# controls.sh -- the no-model plumbing check: positive and negative controls, one scenario, both
# controls, against the LIVE cluster (supervisor rulings 2026-09-13, "General rules" item 2, and
# section 5: "the controls are no-model by design and are the right instrument to verify the
# merged plumbing"). This is an OPERATOR script -- nothing in this repository's automated
# verification runs it. `runner/tests/test_controls.py` is the offline proof that
# `runner/controls.py`'s logic is correct; this script exercises the identical logic against a
# real, deployed Guardian and a real cluster instead of an in-process one.
#
# WHAT IT DOES, IN ORDER, PER CONTROL (positive, then negative)
#   1. Redeploys the Guardian (scripts/guardian_deploy.sh) with a fresh per-attempt audit chain
#      path (ADR-054/ADR-058) and this scenario's four phase-Supervisor ids registered as
#      issuers -- the same redeploy path a real campaign run uses, so this instrument exercises
#      it too, and the same run id for both controls so guardian_deploy.sh's own Lease re-check
#      (runner/run_lock.py) never sees a foreign holder between them.
#   2. Submits the control's scripted actions (or nothing) through the real Guardian client
#      (`python -m runner.controls submit`) -- mint one single-use capability per action, spend
#      it. Only the positive control holds the cluster Lease (runner/run_lock.cluster_lease, held
#      inside that command): the negative control mutates nothing and needs no exclusive hold.
#   3. Extracts the Guardian's own audit chain out of its pod
#      (`python -m runner.controls extract-audit`), read-only, with the operator's own
#      kubeconfig -- never the Guardian's credential (security-policy.md section 1.2). This step
#      exists because the chain lives on the Guardian's own volume, not in this script's working
#      directory, until copied out.
#   4. Scores the bundle (`python -m runner.controls evaluate`) against the scenario's ground
#      truth and prints one line per assertion and required substep, labelled harm-only or
#      act-requiring, plus a PASS/FAIL verdict for the control.
#   5. Tears down anything the positive control's containment action created: the Guardian labels
#      every object it creates with the run id (ADR-081), so teardown selects on that label
#      alone -- the same label pair `scenarios/attackers/apply.py`'s own teardown selects
#      Guardian-created objects on -- plus this scenario's quarantine label as a backstop, in
#      case a partial failure left eradication's own delete unreached.
#
# PRECONDITIONS THIS SCRIPT CHECKS FOR BUT DOES NOT PERFORM
#   * The three cluster mutations the supervisor rulings hold outside this stream: the slo-probe
#     image built and loaded, the slo-probe namespace applied, and a v4 Guardian image already
#     built (see docs/plans/supervisor-rulings-2026-09-13.md, "Live run: HOLD the model run").
#   * `. scripts/live_env.sh` sourced in THIS shell first. It composes GUARDIAN_URL, KUBECONFIG,
#     KUBE_CONTEXT, the five security-policy.md-owned token settings (via
#     scripts/security_params.py -- never restated here; the source-of-truth iron rule (AGENTS.md 1)
#     forbids a second copy with a value) and GUARDIAN_AUDIT_* for the extraction step. This
#     script only checks that they are present; it does not compose them itself.
#   * The in-cluster SLO probe image and namespace are ready. The live CLI creates one independent
#     full-window probe per polarity and waits for it before evaluating the pre-teardown snapshot.
#
# USAGE
#   . scripts/live_env.sh
#   SCENARIO=SCN-SIM-01 sh scripts/controls.sh
#
# STREAMS AND EXIT CODE
#   Strict POSIX sh. One scenario per invocation, both controls, one combined PASS/FAIL summary.
#   Exit 0 only if BOTH controls matched their prediction (positive: every assertion and required
#   substep passed; negative: every act-requiring one failed and every harm-only one still
#   passed). Exit 1 on any step failure or on either control not matching its prediction.
#
# WHAT BREAKS IF THIS FILE CHANGES
#   The only rehearsal of the merged plumbing before the pilot (supervisor rulings section 5).
#   ADR-089.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

scenario=${SCENARIO:?SCENARIO is required, e.g. SCN-SIM-01 or SCN-CVE-04}
case "$scenario" in
    SCN-SIM-01|SCN-SIM-02|SCN-SIM-03|SCN-CVE-04|SCN-CVE-05) ;;
    *)
        printf 'controls: %s is not one of the five scenarios this stream covers -- ' "$scenario" >&2
        printf 'SCN-SIM-01, SCN-SIM-02, SCN-SIM-03, SCN-CVE-04 and SCN-CVE-05 (see ' >&2
        printf 'runner/controls.py, whose _NOT_YET_WIRED map is now empty)\n' >&2
        exit 1
        ;;
esac

# scripts/live_env.sh composes every one of these; this script only checks they made it into THIS
# shell rather than composing any of them itself (see the header's PRECONDITIONS section).
for setting_name in GUARDIAN_URL FRONTEND_URL KUBECONFIG KUBE_CONTEXT GUARDIAN_TOKEN_TTL_SECONDS \
    GUARDIAN_TOKEN_MAX_TTL_SECONDS GUARDIAN_TOKEN_ALGORITHM GUARDIAN_REPLAY_CACHE_ENTRIES \
    GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS GUARDIAN_AUDIT_NAMESPACE GUARDIAN_AUDIT_WORKLOAD \
    GUARDIAN_AUDIT_CONTAINER GUARDIAN_AUDIT_REMOTE_PATH; do
    eval "setting_value=\${$setting_name:-}"
    if [ -z "$setting_value" ]; then
        echo "controls: $setting_name is unset; source scripts/live_env.sh first" >&2
        exit 1
    fi
done

out_root=${CONTROLS_OUT_DIR:-runs/.controls/$scenario}
mkdir -p "$out_root"

# The four phase-Supervisor role ids agents/prompts/compositions/S1-HIER.yaml declares, comma
# joined: runner/controls.py mints one capability per action under exactly these (its
# supervisor_id_for), one issuer per phase, so the deployed Guardian must register all four.
registered_issuers="supervisor-detection-and-investigation,supervisor-containment,"
registered_issuers="${registered_issuers}supervisor-eradication,supervisor-verified-recovery"

# One run id for BOTH controls of this invocation (positive and negative), not one each: it is
# what the outer cluster Lease's holder identity is drawn from, and scripts/guardian_deploy.sh
# re-checks that same Lease immediately before every redeploy against ITS OWN GUARDIAN_RUN_ID --
# two different run ids across the two controls would make the second redeploy's re-check see a
# foreign holder from the first. Only the attempt suffix on GUARDIAN_AUDIT_LOG_PATH varies between
# them (ADR-054), which is exactly the "two attempts, one canonical id" shape that field exists
# for.
run_id="RUN-G0-FULL-$scenario-INJ-A-101"

overall_status=0

teardown_control() {
    control_name=$1
    printf 'controls: [%s/%s] tearing down Guardian-created objects (run-id=%s)\n' \
        "$scenario" "$control_name" "$run_id" >&2
    # The same label pair guardian/app/executor.py stamps on every object it creates (ADR-081)
    # and scenarios/attackers/apply.py's own teardown selects Guardian-created objects on --
    # spelled here rather than imported, since this is a shell script and that pairing is pinned
    # equal across the two Python modules by scenarios/tests.
    kubectl --kubeconfig "$KUBECONFIG" --context "$KUBE_CONTEXT" -n boutique delete \
        networkpolicy -l "agentic-overwatch.io/run-id=$run_id,agentic-overwatch.io/managed-by=guardian" \
        --ignore-not-found=true >/dev/null 2>&1 || true
    # Backstop: the quarantine label runner/controls.py's containment action applies is not the
    # run-id label (the Guardian does not stamp a run label on a patch, only on what it creates),
    # so a positive control that failed partway between containment and eradication could leave a
    # labelled-but-undeleted replica behind. Harmless when eradication already ran: nothing
    # matches.
    kubectl --kubeconfig "$KUBECONFIG" --context "$KUBE_CONTEXT" -n boutique delete \
        pod -l "agentic-overwatch.io/quarantine=true" --ignore-not-found=true >/dev/null 2>&1 || true
}

run_one_control() {
    control_name=$1
    out_dir="$out_root/$control_name"
    mkdir -p "$out_dir"

    suffix=$("$python_bin" -c 'import uuid; print(uuid.uuid4().hex)')
    audit_log_path="/var/lib/guardian/audit/${run_id}-${suffix}.jsonl"

    printf 'controls: [%s/%s] redeploying the Guardian (run_id=%s)\n' \
        "$scenario" "$control_name" "$run_id" >&2
    GUARDIAN_MODE=G0-FULL \
    GUARDIAN_RUN_ID="$run_id" \
    GUARDIAN_REGISTERED_ISSUERS="$registered_issuers" \
    GUARDIAN_AUDIT_LOG_PATH="$audit_log_path" \
        sh scripts/guardian_deploy.sh

    live_status=0
    "$python_bin" -m runner.controls live --scenario "$scenario" --control "$control_name" \
        --run-id "$run_id" --out "$out_dir" --guardian-url "$GUARDIAN_URL" \
        --kubeconfig "$KUBECONFIG" --context "$KUBE_CONTEXT" \
        --audit-namespace "$GUARDIAN_AUDIT_NAMESPACE" \
        --audit-workload "$GUARDIAN_AUDIT_WORKLOAD" \
        --audit-container "$GUARDIAN_AUDIT_CONTAINER" \
        --audit-remote-path "$audit_log_path" --frontend-url "$FRONTEND_URL" || live_status=$?
    if [ "$live_status" -ne 0 ]; then
        printf 'controls: [%s/%s] FAIL -- live control exited %s; see output above\n' \
            "$scenario" "$control_name" "$live_status" >&2
        overall_status=1
    fi

    # apply_plan owns scenario teardown; this remains a best-effort backstop for Guardian-created
    # objects if the process was interrupted outside Python's finally block.
    teardown_control "$control_name"
}

run_one_control positive
run_one_control negative

if [ "$overall_status" -eq 0 ]; then
    printf 'controls: PASS -- %s positive and negative controls both matched their prediction\n' \
        "$scenario"
else
    printf 'controls: FAIL -- %s: see the per-control summaries above\n' "$scenario" >&2
fi
exit "$overall_status"
