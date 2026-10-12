#!/bin/sh
# known_bad_replay.sh -- the known-bad replay over the real v1 corpus (M10 plan P4, §5, §10 DoD).
#
# WHAT THIS IS
# The Definition-of-done command for P4, verbatim:
#     python -m runner.fidelity --campaign-dir runs/CAMP-20260914-campaign --known-bad
# The known-bad replay runs the treatment-fidelity registry over the v1 campaign -- a corpus of KNOWN
# DEFECTS (V1-V28) -- and asks not "did anything fail" but "did every check that names a v1 defect
# raise its flag". Exit 0 means every expected flag was raised, so the replay proves the CHECKS work;
# a successful replay is a corpus FULL of failures, which is the point (see runner/fidelity/__main__.py
# for why the exit-code meaning is inverted in this mode). Its CI-safe synthetic sibling is
# scripts/fidelity_check.sh; the logic is the registry's, not this shell's.
#
# THE v1 CORPUS IS AN OPTIONAL, LOCAL-ONLY INPUT
# runs/ is gitignored (data-management protocol; the corpus is backed up on the VM mirror, not in git),
# so it is present on the researcher's host and absent on a CI runner and on a fresh clone. This script
# therefore GUARDS the corpus the way scripts/baseline.sh guards its optional OFFLINE inputs: when the
# corpus is absent it prints a clear skip and exits 0, so a caller (or CI) that runs it without the
# corpus is not failed for a missing input it was never expected to have. When the corpus IS present it
# runs the replay and forwards the verdict: exit 0 only if every expected flag was raised, non-zero
# with the missing flags named otherwise. The synthetic proof (scripts/fidelity_check.sh) is the one
# that must be green everywhere; this one is local evidence, gathered where the corpus lives.
#
# STREAMS AND EXIT CODES
# `python -m runner.fidelity --known-bad` prints one machine-readable summary line on stdout and the
# per-check detail on stderr; this script forwards both and its exit code (0 = every expected flag
# raised; 1 = a flag was missing, i.e. a check that should have caught a v1 defect did not). A missing
# corpus is a skip with exit 0. Strict POSIX sh.
#
# ENVIRONMENT
#   CAMPAIGN=<dir> the corpus to replay (default: runs/CAMP-20260914-campaign, the v1 campaign).
#   PYTHON=<path>  the interpreter to use.
#   GUARDIAN_AUDIT_PUBLIC_KEY=<pem> REQUIRED. See the block below.
#
# WHY THE PUBLIC KEY IS REQUIRED RATHER THAN OPTIONAL
# F-GD-01's §5 expectation is "unsigned in v1": the check raises it by verifying the v1 chain against
# the operator's Ed25519 public key and finding no signature on any record (defect V18). Without the
# key the check cannot reach that verdict at all -- it either skips (no anchor ledger readable) or
# passes (ledger present and the head anchored) -- so a replay run without the key can NEVER raise
# F-GD-01 and can never reach exit 0. It would also be the unearned security claim ADR-022 exists not
# to make, reported as a missing flag rather than as the configuration gap it is. So this wrapper
# refuses to start without it and names the variable, rather than letting a class-T security check be
# quietly absent from the proof. On the campaign host the key is
# /opt/agentic-overwatch/audit-public-key.pem.
#
# SCOPE THE VARIABLE TO THIS COMMAND; DO NOT EXPORT IT FOR A WHOLE P0-OFFLINE RUN
# `GUARDIAN_` is the Guardian process's own namespace, and
# agents/tests/test_executor_env_scan.py asserts that no `GUARDIAN_*` key is visible in the
# environment an Executor runs in (rule 10, ADR-023). A shell that exported the key for an entire
# P0-offline run therefore FAILS the agents suite -- the guard working exactly as designed, and its
# failure message says so ("If a shell exported one for a local Guardian, unset it for this run
# rather than narrowing the scan"). Prefer
#     env GUARDIAN_AUDIT_PUBLIC_KEY=/opt/agentic-overwatch/audit-public-key.pem sh scripts/known_bad_replay.sh
# over `export GUARDIAN_AUDIT_PUBLIC_KEY=...`, so the variable lives only as long as this replay.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make known-bad-replay` and the §10 DoD line. runner/fidelity/ owns the replay; this only guards its
# corpus and forwards its verdict. ADR-120, ADR-146.

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

campaign=${CAMPAIGN:-runs/CAMP-20260914-campaign}

if [ ! -d "$campaign" ] || [ ! -f "$campaign/campaign.json" ]; then
    echo "known-bad-replay: SKIP — the v1 corpus $campaign is not present on this host." >&2
    echo "known-bad-replay: It is gitignored and lives on the researcher's host and the VM mirror," >&2
    echo "known-bad-replay: not in a clone or on a CI runner; the synthetic proof (scripts/fidelity_check.sh)" >&2
    echo "known-bad-replay: is the one that runs everywhere. Set CAMPAIGN=<dir> to point at a corpus." >&2
    echo "known-bad-replay: SKIP — v1 corpus absent ($campaign); nothing to replay"
    exit 0
fi

if [ -z "${GUARDIAN_AUDIT_PUBLIC_KEY:-}" ]; then
    echo "known-bad-replay: FAIL — GUARDIAN_AUDIT_PUBLIC_KEY is unset, so F-GD-01 cannot raise its" >&2
    echo "known-bad-replay: §5 expectation ('unsigned in v1', defect V18) and the replay cannot reach" >&2
    echo "known-bad-replay: exit 0. Point it at the operator's Ed25519 PUBLIC key (PEM), SCOPED to this" >&2
    echo "known-bad-replay: one command rather than exported:" >&2
    echo "known-bad-replay:     env GUARDIAN_AUDIT_PUBLIC_KEY=/opt/agentic-overwatch/audit-public-key.pem \\" >&2
    echo "known-bad-replay:         sh scripts/known_bad_replay.sh" >&2
    echo "known-bad-replay: A globally exported GUARDIAN_ key fails agents/tests/test_executor_env_scan.py" >&2
    echo "known-bad-replay: (rule 10, ADR-023). The key is public and verifies only; it signs nothing." >&2
    exit 1
fi

if [ ! -r "$GUARDIAN_AUDIT_PUBLIC_KEY" ]; then
    echo "known-bad-replay: FAIL — GUARDIAN_AUDIT_PUBLIC_KEY=$GUARDIAN_AUDIT_PUBLIC_KEY is not a" >&2
    echo "known-bad-replay: readable file, so F-GD-01 would fail on a key-loading error rather than on" >&2
    echo "known-bad-replay: the unsigned v1 chain it exists to flag." >&2
    exit 1
fi

# --no-ledger: the known-bad replay is a VALIDATION pass over the v1 corpus, not a campaign. It must
# not write fidelity_ledger.jsonl into runs/CAMP-20260914-campaign/, which is kept read-only as
# formative evidence (ADR-136 / D9); and the per-report append over the whole ~875-directory corpus is
# needless I/O for a run whose only output is the pass/fail verdict. The ledger belongs to a real v2
# campaign run, not to this replay.
exec "$python_bin" -m runner.fidelity --campaign-dir "$campaign" --known-bad --no-ledger
