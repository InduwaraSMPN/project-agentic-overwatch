#!/bin/sh
#
# guardian_test.sh -- the Guardian's policy gate: `opa test` over guardian/policies/, then the
# adversarial suite, with both halves reported by name.
#
# WHAT THIS GATE ASSERTS
#   docs/04-repo-conventions.md section 3 fixes the contract: `opa test` over guardian/policies/ --
#   PASS RATE AND A COVERAGE FLOOR, BOTH PRINTED -- plus the adversarial suite, in which every case
#   asserts three things: denied, with a structured reason code, and present in the hash-chained
#   record. The two-figure requirement is the M3 plan's conflict M3-C9: docs/milestones/M3-guardian.md
#   states the Definition of done as "`opa test` 100%", and "100%" conflates two different claims.
#   Every test passing says nothing about whether any test reached a given rule; full coverage says
#   nothing about whether the rules that ran produced the right answers. This script prints both and
#   fails on either.
#
# THE COVERAGE FLOOR IS 100, AND THE REASON IS THE BUNDLE'S SIZE AND ITS JOB
#   guardian/policies/ is two policy files and their two test files, and every line in them is on
#   the decision path of the component whose failures are silent. An uncovered line there is a line
#   whose behaviour nothing has demonstrated, in the one place this project cannot afford that. The
#   usual argument for a floor below 100 -- that a large codebase has a long tail of lines not worth
#   a test -- has no purchase on a bundle this small.
#
#   `opa test --coverage` measures every file it loads, test files included, and that is kept rather
#   than filtered: an uncovered line in a *_test.rego file is a test helper nothing calls, which is
#   untested weight in a security suite and is worth failing on for its own sake.
#
#   100 is a floor that holds today rather than an aspiration -- the run that landed this script
#   reported 639 covered lines and 0 uncovered. Lowering it later is an ADR naming what could not be
#   covered and why, not an edit to the number here.
#
#   THE FLOOR IS CHECKED HERE RATHER THAN WITH `opa test --threshold`, AND THAT IS A CORRECTION.
#   `--threshold` is the obvious instrument and it was tried first. When the threshold is NOT met it
#   writes one line to stderr and emits NO REPORT AT ALL -- so the figure section 3 requires to be
#   printed is exactly the figure that disappears in the one case anybody needs it. Observed on the
#   pinned version: `Code coverage threshold not met: got 99.69 instead of 100.00` on stderr, empty
#   stdout. So the report is taken without the flag, both figures are printed on every run whatever
#   they say, and the comparison is made below.
#
#   The comparison that governs is on the LINE COUNT, not on the percentage, and at a floor of 100
#   it is the stricter of the two: OPA reports coverage as a float, so one uncovered line in a large
#   bundle prints as 100.00 and a percentage test would pass it. A line count cannot round. The
#   percentage is compared as well, so that a future ADR lowering the floor governs through the
#   number it states rather than through this paragraph.
#
#   A report that cannot be parsed is a FAILURE, never a pass. That is what stops a change in OPA's
#   output format from silently turning the floor off, which is the standing risk of checking a
#   figure in a shell script rather than in the tool that produced it.
#
# WHY THIS SCRIPT ACQUIRES `opa` ITSELF, WITH A CHECKSUM CHECK
#   ADR-025. `make guardian-test` runs in ci.yml's `hygiene` job. The workflow installs pytest and
#   the Guardian's pinned Python runtime dependencies because the adversarial half is mandatory, but
#   OPA acquisition remains here: putting it in the workflow would make the command a developer runs
#   and the command CI runs stop being the same bytes, which is exactly what section 1's
#   logic-lives-in-scripts rule exists to prevent.
#
#   The checksum is the security half and it is not optional. OPA decides every permit and every
#   deny in this artefact. A binary fetched over the network and executed unverified is an
#   unverified component on the decision path: the pin in infra/versions.env would name a version
#   and guarantee nothing about the bytes, and `versions_env_sha256` in every sealed bundle would be
#   recording a label rather than a component.
#
#   THE EXPECTED DIGESTS ARE PINNED HERE RATHER THAN FETCHED ALONGSIDE THE BINARY. Each OPA release
#   publishes a `.sha256` sidecar beside each asset; the values in the table below were read from
#   those sidecars for the pinned version and are recorded in the repository, which is the point.
#   Fetching the digest at run time from the same server, in the same moment, as the thing it
#   describes would detect a corrupted transfer and nothing else -- and a mutated release asset is
#   precisely the case ADR-025 names. A digest committed here is a digest a reviewer saw.
#
#   Consequence, stated rather than discovered: bumping OPA_VERSION in infra/versions.env WITHOUT
#   updating the table below makes this gate fail with an unknown-version message. That is the
#   intended order of events -- a version bump on the decision path is a reviewed change, and ADR-025
#   makes it a hotfix ADR after the v1.0 freeze.
#
#   A binary already on PATH at the pinned version is used as it stands, per ADR-025, and is NOT
#   checksummed: the guarantee this script offers is about what it fetches, not about what a
#   developer installed by other means. Which of the three paths ran -- PATH, cache, fetch -- is on
#   the summary line of every run, so that distinction is never left to be inferred.
#
# BOTH HALVES ARE REQUIRED
#   This target is the Guardian gate, not merely the OPA gate. Once guardian/tests/ exists, a PASS
#   must mean the adversarial suite actually ran and passed. Reporting overall success while the
#   selected interpreter cannot import pytest or the Guardian contracts makes `make guardian-test`
#   weaker than the Definition of Done it is used to evidence. An absent or unrunnable suite is
#   therefore a hard failure that names the selected interpreter and the dependency-install command.
#
#   CI's lint job separately installs the runtime dependencies and runs guardian/tests directly.
#   The hygiene job must consequently install those dependencies too, or stop invoking this combined
#   target; preserving an install-free job is not a reason for a security gate to pass without its
#   adversarial half.
#
# VACUOUS PASSES ARE REFUSED
#   A gate that succeeds over nothing reads, in a log, exactly like a gate that succeeds over
#   everything -- monitor_replay.sh's phrasing, and the same rule applies here. An empty
#   guardian/policies/, a bundle with no *_test.rego, a test run that executed zero tests
#   (`--fail-on-empty`), and a Python suite whose files collect no case are each a failure.
#
# STREAMS AND EXIT CODES
#   stdout carries one summary line, in check_hygiene.sh's shape. stderr carries the per-item
#   detail. Exit 0 only when every half that ran passed.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options, and no jq, which is not in this toolchain.
#   Runs under dash in WSL2 Ubuntu, under Git Bash on the Windows host, and on ubuntu-latest.

set -eu

# Byte-exact matching and byte-stable tool output whatever the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root from this script's own location, so behaviour is identical from make, from CI, or by
# hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

POLICY_DIR="guardian/policies"
SUITE_DIR="guardian/tests"
VERSIONS_FILE="infra/versions.env"
RELEASE_BASE="https://github.com/open-policy-agent/opa/releases/download"

# See the header. Compared below against both the reported percentage and the uncovered line count.
COVERAGE_FLOOR=100

usage() {
    echo "usage: sh scripts/guardian_test.sh"
    echo "  OPA_BIN=<path>        use this binary instead of resolving one (version still checked)"
    echo "  OPA_CACHE_DIR=<dir>   where a fetched binary is kept"
    echo "  PYTHON=<path>         interpreter for the adversarial suite"
}

case "${1:-}" in
    "") ;;
    -h|--help) usage; exit 0 ;;
    *)
        printf 'guardian-test: unknown argument %s\n' "$1" >&2
        usage >&2
        exit 1
        ;;
esac

fail() {
    printf 'guardian-test: FAIL — %s\n' "$1"
    exit 1
}

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM

# --- the bundle must exist, and must carry both policy and tests -----------------------------
# Counted before anything runs, so the two vacuous shapes -- no policy at all, and policy with no
# tests -- are refused with a message that says which one happened rather than with whatever OPA
# would have said about an empty load.
if [ ! -d "$POLICY_DIR" ]; then
    echo "guardian-test: $POLICY_DIR does not exist; run from a full checkout" >&2
    fail "$POLICY_DIR is absent"
fi

policy_count=0
test_file_count=0
for candidate in "$POLICY_DIR"/*.rego; do
    [ -f "$candidate" ] || continue
    case "$candidate" in
        *_test.rego) test_file_count=$((test_file_count + 1)) ;;
        *)           policy_count=$((policy_count + 1)) ;;
    esac
done

if [ "$policy_count" -eq 0 ]; then
    {
        echo "guardian-test: $POLICY_DIR holds no policy .rego file."
        echo "Deny-by-default is a rule the bundle expresses, not a state the absence of a bundle"
        echo "produces: an empty bundle denies everything while looking configured, and this gate"
        echo "must not report that as a pass."
    } >&2
    fail "no policy file in $POLICY_DIR"
fi

if [ "$test_file_count" -eq 0 ]; then
    {
        echo "guardian-test: $POLICY_DIR holds $policy_count policy file(s) and no *_test.rego."
        echo "ADR-003's obligation is a policy that is exhaustively testable offline; an untested"
        echo "policy bundle passing this gate would satisfy the letter of 'opa test' and none of it."
    } >&2
    fail "no *_test.rego in $POLICY_DIR"
fi

# --- which OPA, and which bytes ---------------------------------------------------------------
if [ ! -f "$VERSIONS_FILE" ]; then
    echo "guardian-test: $VERSIONS_FILE not found; run from a full checkout" >&2
    fail "$VERSIONS_FILE is absent"
fi

# infra/versions.env is contractually values-only -- its header rule 1 forbids logic, command
# substitution, shell expansion and conditionals -- which is what makes dot-sourcing it safe rather
# than an arbitrary-code hazard. install_cluster_tools.sh reads it the same way.
# shellcheck disable=SC1090
. "./$VERSIONS_FILE"

if [ -z "${OPA_VERSION:-}" ]; then
    {
        echo "guardian-test: OPA_VERSION is empty in $VERSIONS_FILE."
        echo "An unpinned policy engine is not reproducible, and the version is part of every sealed"
        echo "bundle's versions_env_sha256 (ADR-025), so this is a hard failure rather than a default."
    } >&2
    fail "OPA_VERSION is unpinned"
fi

opa_bare_version=${OPA_VERSION#v}

# The release asset for this host, and the sha256 published beside it for OPA_VERSION. Linux takes
# the `_static` asset: it carries no libc dependency, so the same pin behaves identically on a
# runner image and on whatever distribution a developer's WSL2 happens to be.
host_platform="$(uname -s)/$(uname -m)"
case "$host_platform" in
    Linux/x86_64|Linux/amd64)
        opa_asset="opa_linux_amd64_static"
        opa_sha256="c9f985ce0d345f5484006ade2c695ed9e3f308e4441139e46695c5c182ac0839"
        ;;
    Linux/aarch64|Linux/arm64)
        opa_asset="opa_linux_arm64_static"
        opa_sha256="19dcb5186fd394c32023918c53eaacda55f835abb05e13e0f9a766dd1429494f"
        ;;
    Darwin/x86_64)
        opa_asset="opa_darwin_amd64"
        opa_sha256="80a9e2bce1a44fd81dc4b5415439918786b4685f0709d533d0005abea7e10e02"
        ;;
    Darwin/arm64)
        opa_asset="opa_darwin_arm64"
        opa_sha256="805ce3f336154150bef73bafa2dab8806631851bccc7cae95bef46ffabdf8fc3"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        opa_asset="opa_windows_amd64.exe"
        opa_sha256="fc932e644652d5634bc0d7a5e5f455dd26ebf5b243682a81eddf6d387a901e2e"
        ;;
    *)
        {
            printf 'guardian-test: no pinned OPA asset for this host (%s).\n' "$host_platform"
            echo "Add the release asset name and the sha256 from its published .sha256 sidecar to the"
            echo "table in this script, or point the gate at a binary you trust: OPA_BIN=<path>."
        } >&2
        fail "unsupported host $host_platform"
        ;;
esac

# The digests above were read from the sidecars published for ONE version. A bump without a matching
# table edit would otherwise verify new bytes against an old digest and fail with a checksum
# mismatch, which reads like tampering. This says what actually happened instead.
PINNED_FOR_VERSION="v1.19.1"
if [ "$OPA_VERSION" != "$PINNED_FOR_VERSION" ]; then
    {
        printf 'guardian-test: %s pins OPA_VERSION=%s, but the digest table in this script was\n' \
            "$VERSIONS_FILE" "$OPA_VERSION"
        printf 'taken from the assets published for %s.\n' "$PINNED_FOR_VERSION"
        echo "Update the table from the new release's published .sha256 sidecars, e.g."
        printf '  curl -sSfL %s/%s/<asset>.sha256\n' "$RELEASE_BASE" "$OPA_VERSION"
        echo "and update PINNED_FOR_VERSION in the same edit. Verifying new bytes against an old"
        echo "digest would fail as though the release had been tampered with, which is a worse"
        echo "message than this one."
    } >&2
    fail "digest table is pinned to $PINNED_FOR_VERSION, not $OPA_VERSION"
fi

sha256_of() {
    # One digest, lower-case hex, no filename. Two implementations because coreutils and the perl
    # tool are what this project's hosts actually offer; no digest tool at all is a failure rather
    # than a reason to run unverified bytes.
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        return 1
    fi
}

opa_version_of() {
    # `opa version` prints "Version: 1.19.1" with no leading v, so the pin is compared bare.
    "$1" version 2>/dev/null | awk '$1 == "Version:" { print $2; exit }'
}

cache_dir=${OPA_CACHE_DIR:-"${XDG_CACHE_HOME:-$HOME/.cache}/agentic-overwatch/opa"}/$OPA_VERSION
cached_binary="$cache_dir/$opa_asset"

opa_bin=""
opa_source=""

if [ -n "${OPA_BIN:-}" ]; then
    # An explicit choice. The version is still checked -- running a different OPA than the one the
    # bundle digest records is not something to do by accident -- but the bytes are the caller's.
    [ -x "$OPA_BIN" ] || fail "OPA_BIN=$OPA_BIN is not an executable file"
    found=$(opa_version_of "$OPA_BIN" || true)
    [ "$found" = "$opa_bare_version" ] || \
        fail "OPA_BIN=$OPA_BIN reports version '${found:-unknown}', but $VERSIONS_FILE pins $OPA_VERSION"
    opa_bin=$OPA_BIN
    opa_source="OPA_BIN (version checked, bytes not)"
elif command -v opa >/dev/null 2>&1 && [ "$(opa_version_of opa || true)" = "$opa_bare_version" ]; then
    # ADR-025's skip-if-present branch: a developer with the pinned version installed pays nothing.
    opa_bin=opa
    opa_source="PATH (version checked, bytes not)"
else
    if [ ! -f "$cached_binary" ]; then
        command -v curl >/dev/null 2>&1 || {
            {
                echo "guardian-test: no opa at the pinned version and no curl to fetch one."
                printf 'Install OPA %s by hand and re-run, or point the gate at it: OPA_BIN=<path>.\n' \
                    "$OPA_VERSION"
            } >&2
            fail "cannot acquire opa: curl is absent"
        }
        mkdir -p "$cache_dir"
        printf 'guardian-test: fetching %s %s (%s)\n' "$opa_asset" "$OPA_VERSION" "$host_platform" >&2
        # --fail so an HTML error page never lands on disk as a "binary"; --location because the
        # release URL redirects. Downloaded beside the target and moved only once it verifies, so an
        # interrupted fetch can never leave a partial file that a later run would trust.
        if ! curl -sSfL --retry 3 --retry-delay 2 -o "$cached_binary.part" \
                "$RELEASE_BASE/$OPA_VERSION/$opa_asset"; then
            rm -f "$cached_binary.part"
            {
                printf 'guardian-test: could not fetch %s/%s/%s\n' \
                    "$RELEASE_BASE" "$OPA_VERSION" "$opa_asset"
                echo "The gate fails closed rather than running without a policy engine: a green"
                echo "guardian-test that never evaluated a policy is the one outcome this milestone"
                echo "must not produce. Retry with network access, or supply OPA_BIN=<path>."
            } >&2
            fail "could not fetch opa $OPA_VERSION for $host_platform"
        fi
        mv "$cached_binary.part" "$cached_binary"
        chmod 0755 "$cached_binary" 2>/dev/null || true
        opa_source="fetched and checksum-verified"
    else
        opa_source="cache, checksum re-verified"
    fi

    # Verified on EVERY run, not only after a download. Re-hashing costs a fraction of a second and
    # it means a cache mutated between runs is caught, rather than trusted because it was verified
    # once, some time ago, by a process nobody can see from here.
    actual=$(sha256_of "$cached_binary") || {
        {
            echo "guardian-test: neither sha256sum nor shasum is available, so the fetched binary"
            echo "cannot be verified. OPA decides every permit and every deny in this artefact, and"
            echo "an unverified executable on that path is not a smaller problem than no engine at"
            echo "all -- so this fails rather than proceeding without the check."
        } >&2
        fail "no sha256 tool available to verify $cached_binary"
    }
    if [ "$actual" != "$opa_sha256" ]; then
        rm -f "$cached_binary"
        {
            printf 'guardian-test: checksum mismatch for %s\n' "$opa_asset"
            printf '  expected %s\n' "$opa_sha256"
            printf '  actual   %s\n' "$actual"
            echo "The file has been removed. The pin names a version; this digest is what makes the"
            echo "pin mean a particular set of bytes (ADR-025). Do not work around this."
        } >&2
        fail "checksum mismatch for $opa_asset"
    fi
    opa_bin=$cached_binary
fi

opa_reported=$(opa_version_of "$opa_bin" || true)
[ -n "$opa_reported" ] || fail "$opa_bin does not report an OPA version; it is not a usable engine"

# --- half one: opa test ------------------------------------------------------------------------
echo "guardian-test: half 1 of 2 -- opa test over $POLICY_DIR" >&2

test_out="$work/opa-test.out"
test_rc=0
"$opa_bin" test "$POLICY_DIR" -v --fail-on-empty > "$test_out" 2>&1 || test_rc=$?

# Observed once, on a Windows host whose temp directory was swept while a fetch was in flight: the
# working directory vanished, the redirect failed before OPA ran, and the run died on a `sed` that
# could not open a file nobody had written. `set -e` made that fail closed, which is the property
# that matters, but the message described the symptom rather than the cause. One line is cheaper
# than the next person rediscovering it from a stray sed error.
[ -f "$test_out" ] || fail "the working directory $work vanished mid-run; there is no result to read"

sed 's/^/  /' "$test_out" >&2

# `PASS: n/m`, and `FAIL: n/m` beside it when anything failed. Read from OPA's own summary rather
# than counted here, so the figure printed is the engine's.
pass_line=$(awk '$1 == "PASS:" { print $2 }' "$test_out" | tail -n 1)
fail_line=$(awk '$1 == "FAIL:" { print $2 }' "$test_out" | tail -n 1)
[ -n "$pass_line" ] || pass_line="0/0"

if [ "$test_rc" -ne 0 ]; then
    {
        printf '\nguardian-test: opa test exited %s (passed %s%s)\n' \
            "$test_rc" "$pass_line" "${fail_line:+, failed $fail_line}"
        echo "Never weaken guardian/policies/ to make a test pass. If policy legitimately blocks a"
        echo "case, extend the policy deliberately, with a comment and an ADR note"
        echo "(the guardian-first iron rule (AGENTS.md 1))."
    } >&2
    printf 'guardian-test: FAIL — opa: %s test(s) passed%s (opa %s via %s)\n' \
        "$pass_line" "${fail_line:+, $fail_line failed}" "$opa_reported" "$opa_source"
    exit 1
fi

# --- half one, second figure: coverage ----------------------------------------------------------
coverage_json="$work/coverage.json"
coverage_rc=0
"$opa_bin" test "$POLICY_DIR" --coverage --format=json --fail-on-empty \
    > "$coverage_json" 2> "$work/coverage.err" || coverage_rc=$?

if [ "$coverage_rc" -ne 0 ]; then
    { echo "guardian-test: the coverage run failed:"; cat "$work/coverage.err"; } >&2
    fail "opa test --coverage exited $coverage_rc"
fi

# OPA's report is one object per loaded file under "files", then the aggregate. Per-file entries are
# indented four spaces and their fields six; the aggregate's fields sit at two. Parsing on that is
# safe only because the engine is pinned to one version -- and an unparseable report fails the gate
# below rather than passing it, which is what keeps the floor on if the format ever moves.
#
# `not_covered_lines` is omitted per file when it is zero and is always present at the aggregate;
# the aggregate one starts as a sentinel rather than as 0, so an absent key reads as "unknown" and
# is refused instead of reading as "none uncovered".
#
# A file key is JSON, so a Windows path separator arrives as an escaped pair. The class-plus-plus
# spelling collapses a RUN of separators to one slash; a single-character pattern would turn each
# escaped pair into two.
awk '
    BEGIN { total_uncovered = "?"; total_covered = "?"; total_pct = "" }
    /^    "[^"]*": \{$/ {
        name = $0
        sub(/^ *"/, "", name)
        sub(/": \{$/, "", name)
        gsub(/[\\]+/, "/", name)
        file_uncovered = 0
        next
    }
    /^      "not_covered_lines":/ { v = $2; sub(/,$/, "", v); file_uncovered = v; next }
    /^      "coverage":/          { v = $2; sub(/,$/, "", v); print "FILE", name, v, file_uncovered; next }
    /^  "covered_lines":/         { v = $2; sub(/,$/, "", v); total_covered = v; next }
    /^  "not_covered_lines":/     { v = $2; sub(/,$/, "", v); total_uncovered = v; next }
    /^  "coverage":/              { v = $2; sub(/,$/, "", v); total_pct = v }
    END { if (total_pct != "") { print "TOTAL", total_pct, total_covered, total_uncovered } }
' "$coverage_json" > "$work/coverage.txt"

coverage_total=$(awk '$1 == "TOTAL" { print $2 }' "$work/coverage.txt")
covered_lines=$(awk '$1 == "TOTAL" { print $3 }' "$work/coverage.txt")
uncovered_lines=$(awk '$1 == "TOTAL" { print $4 }' "$work/coverage.txt")

# Printed BEFORE the comparison, so the figures are in the transcript whether this passes or fails.
# ORS rather than an escape in the awk format string, so nothing here turns on how a shell quotes a
# backslash inside a single-quoted program.
{
    printf 'guardian-test: coverage over %s (floor %s%%, and no uncovered line)\n' \
        "$POLICY_DIR" "$COVERAGE_FLOOR"
    awk '$1 == "FILE" { printf "  %-44s %6.2f%%  %s uncovered line(s)" ORS, $2, $3, $4 }' \
        "$work/coverage.txt"
} >&2

parse_problem=""
case "$coverage_total"  in ''|*[!0-9.]*) parse_problem="aggregate percentage" ;; esac
case "$covered_lines"   in ''|*[!0-9]*)  parse_problem="covered line count" ;; esac
case "$uncovered_lines" in ''|*[!0-9]*)  parse_problem="uncovered line count" ;; esac

if [ -n "$parse_problem" ]; then
    {
        printf 'guardian-test: could not read the %s from the coverage report.\n' "$parse_problem"
        echo "docs/04-repo-conventions.md section 3 requires the coverage figure to be PRINTED, and"
        echo "an unprintable figure is a broken gate rather than a passing one -- a report this"
        echo "script cannot read is a floor it cannot apply. Raw report, first 40 lines:"
        head -n 40 "$coverage_json"
    } >&2
    fail "coverage report could not be parsed"
fi

coverage_short=$(awk -v v="$coverage_total" 'BEGIN { printf "%.2f", v }')
total_lines=$((covered_lines + uncovered_lines))

# Two comparisons. The line count is the one that governs at a floor of 100; the percentage is kept
# so that a future ADR lowering the floor governs through the number it states. See the header.
below_floor=0
[ "$uncovered_lines" -eq 0 ] || below_floor=1
awk -v got="$coverage_total" -v floor="$COVERAGE_FLOOR" \
    'BEGIN { exit !(got + 0 >= floor + 0) }' || below_floor=1

if [ "$below_floor" -ne 0 ]; then
    {
        printf '\nguardian-test: coverage %s%% (%s of %s line(s), %s uncovered) is below the floor of %s%%\n' \
            "$coverage_short" "$covered_lines" "$total_lines" "$uncovered_lines" "$COVERAGE_FLOOR"
        awk '$1 == "FILE" && $4 + 0 > 0 { printf "  %s has %s uncovered line(s)" ORS, $2, $4 }' \
            "$work/coverage.txt"
        echo "An uncovered line in a deny-by-default bundle is a line whose behaviour nothing has"
        echo "demonstrated. Add the test; lowering the floor is an ADR, not an edit."
    } >&2
    printf 'guardian-test: FAIL — opa: %s test(s) passed, coverage %s%% (%s uncovered line(s)) below floor %s%% (opa %s via %s)\n' \
        "$pass_line" "$coverage_short" "$uncovered_lines" "$COVERAGE_FLOOR" "$opa_reported" "$opa_source"
    exit 1
fi

# --- half two: the adversarial suite -------------------------------------------------------------
echo "guardian-test: half 2 of 2 -- the adversarial suite ($SUITE_DIR)" >&2

# Interpreter resolution, identical to scripts/monitor_replay.sh's so that two gates in one
# repository never disagree about which Python they mean: $PYTHON if set, else the repository
# virtualenv if one exists, else python3 -- which is what CI gets, since .venv/ is gitignored and
# never exists on a runner. The chosen interpreter is printed, so the resolution is never a guess.
#
# The WSL2 subtlety monitor_replay.sh sets out at length applies here unchanged and is cross-
# referenced rather than restated: reached through /mnt/c, a virtualenv built on the Windows side is
# visible from the Linux side and its .exe runs under binfmt, so this resolution falls through to a
# WINDOWS interpreter when no POSIX .venv/bin/python exists. That is a genuine pass of the suite's
# logic and it is NOT evidence about Linux. Naming an interpreter explicitly is what tests that
# path: PYTHON=~/.venvs/agentic-overwatch/bin/python make guardian-test
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

suite_status=""
suite_rc=0

# THE HALF EXISTS WHEN IT HAS CASES, NOT WHEN IT HAS A DIRECTORY.
# guardian/tests/ acquires its package marker and its shared harness before its first case, so a
# directory test would report the half as present and then fail on pytest's "no tests collected"
# for the whole window between those two commits. That is the same defect as a guard armed on the
# directory that will hold a corpus rather than on the corpus -- docs/04-repo-conventions.md
# section 4 records it for `make determinism-check`, where a README announcing a directory would
# have fired the gate before anything existed to gate. Counting `test_*.py` is the corpus test.
suite_case_count=0
if [ -d "$SUITE_DIR" ]; then
    suite_case_count=$(find "$SUITE_DIR" -type f -name 'test_*.py' 2>/dev/null | wc -l | tr -d ' ')
fi

if [ "$suite_case_count" -eq 0 ]; then
    {
        printf '  %s holds no test_*.py. The adversarial suite -- forged, expired, out-of-scope,\n' "$SUITE_DIR"
        echo "  replayed and unknown-issuer tokens, each asserted denied, with a structured reason"
        echo "  code, and present in the hash-chained record -- is a required half of this gate."
    } >&2
    suite_status="FAILED (no test_*.py present)"
    suite_rc=1
elif ! "$python_bin" -c 'import pytest' >/dev/null 2>&1 \
        || ! "$python_bin" -c 'import guardian.app.models' >/dev/null 2>&1; then
    {
        printf '  %s exists, but %s cannot import pytest and the Guardian contracts.\n' \
            "$SUITE_DIR" "$python_bin"
        echo "  The adversarial half is required; this gate cannot report PASS without running it."
        echo "  Install the pinned dependencies, then re-run:"
        echo "    sh scripts/install_runtime_deps.sh guardian"
        echo "    PYTHON=<path> sh scripts/guardian_test.sh"
    } >&2
    suite_status="FAILED (not runnable: $python_bin lacks pytest or Guardian dependencies)"
    suite_rc=1
else
    suite_out="$work/pytest.out"
    # The engine-backed cases in the suite resolve OPA through OPA_BIN or PATH
    # (guardian/app/opa.py). When half one used the cached binary, neither held it, so those
    # cases skipped while this half reported passed. Hand the suite the binary half one just
    # verified, so both halves evaluate policy with the same engine and those cases run.
    OPA_BIN="$opa_bin" "$python_bin" -m pytest "$SUITE_DIR" -q > "$suite_out" 2>&1 || suite_rc=$?
    sed 's/^/  /' "$suite_out" >&2
    case "$suite_rc" in
        0)
            suite_status="passed, $suite_case_count file(s) ($python_bin)"
            ;;
        5)
            # pytest's "no tests were collected". Reached only when test_*.py files exist and none
            # of them yielded a case, which is a defect in the suite rather than a state it passes
            # through: a run over nothing is refused here exactly as an empty fixture corpus is
            # refused by scripts/monitor_replay.sh and an empty test set by --fail-on-empty above.
            {
                printf '\n  %s holds %s test_*.py file(s) and pytest collected no case from them.\n' \
                    "$SUITE_DIR" "$suite_case_count"
                echo "  A suite that runs nothing is refused rather than reported as a pass."
            } >&2
            suite_status="FAILED (test files present, no case collected)"
            ;;
        *)
            suite_status="FAILED (pytest exited $suite_rc)"
            ;;
    esac
fi

if [ "$suite_rc" -ne 0 ]; then
    printf 'guardian-test: FAIL — opa: %s test(s) passed, coverage %s%% (%s of %s line(s), %s uncovered); adversarial suite: %s\n' \
        "$pass_line" "$coverage_short" "$covered_lines" "$total_lines" "$uncovered_lines" \
        "$suite_status"
    exit 1
fi

printf 'guardian-test: PASS — opa: %s test(s) passed, coverage %s%% (%s of %s line(s), %s uncovered, floor %s%%); adversarial suite: %s [opa %s via %s]\n' \
    "$pass_line" "$coverage_short" "$covered_lines" "$total_lines" "$uncovered_lines" \
    "$COVERAGE_FLOOR" "$suite_status" "$opa_reported" "$opa_source"
exit 0
