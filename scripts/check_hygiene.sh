#!/bin/sh
#
# check_hygiene.sh -- turn the git-hygiene claims behind milestone task M0-T0.1 (asserted as
# done by docs/milestones/M0-inception.md; the obligations live in docs/04-repo-conventions.md
# sections 1 and 5) into checks that fail the moment any of them stops being true. Backs the
# `hygiene` CI job added by M0-T0.5; the identical check runs locally via this script, which is
# the point of keeping logic out of the workflow file.
#
# THE FOUR BLOCKS
#   (a) Ignore coverage. Every path class docs/04-repo-conventions.md section 5 names via its
#       .gitignore lines must actually be ignored. The probes are invented paths -- .env,
#       runs/x, foo.key and so on -- because git check-ignore tests the RULE, not the
#       filesystem: the claim under test is "the pattern is covered", not "these files exist",
#       so a passing probe proves the rule without the junk ever being created.
#   (b) Nothing forbidden is tracked. An ignore rule does not untrack a file committed before
#       the rule or force-added past it, so coverage alone proves nothing about the index.
#       The tracked tree is enumerated once and matched against the ignore classes: runs/,
#       .venv/ and __pycache__/ at any depth (mirroring gitignore semantics for unanchored
#       patterns), .env and *.key at any depth, and .ruff_cache/ -- which no .gitignore line
#       names, so only the tracked-files check guards it.
#   (c) Line-ending tripwire. core.autocrlf=true on the Windows host plus actions/checkout
#       forcing autocrlf=false means a CRLF Makefile or script can sit in commits yet never
#       surface in a CI run (recorded as conflict C11 in the M0 plan: CI alone will never catch
#       it). The index EOL column of git ls-files --eol is therefore checked directly -- the
#       index is what a fresh clone receives. The working-tree column (w/) is deliberately not
#       checked: a CRLF working copy on Windows is legitimate; only the committed bytes are the
#       contract. The block is a derived sweep anchored by a hardcoded core list and a row
#       floor; the reasoning for that three-part shape is written out at the block itself.
#       STRICT_EOL is the only knob in this script that changes any block's severity, and it
#       changes only this one.
#   (d) Directory existence. The unstarred top-level entries of the section 1 folder map -- the
#       ten directories it draws at the root of its tree -- must exist in the working tree.
#       The assertion stops at the root: the map's deeper entries, named in its comment column,
#       are not walked here. Starred entries are excluded by the map's own convention -- a star
#       reads "to create when first needed", so an absence is correct rather than a defect;
#       runs/ is the one starred root entry, and it is gitignored besides. The list is
#       restated below, with its source cited, because a tree walk cannot know which
#       directories a document asserts and which it merely reserves.
#       context/ (the read-only dissertation ground truth) and the assistant trees were
#       removed from the artefact in the M9 strip-down, so they are no longer asserted here.
#
# ENVIRONMENT
#   STRICT_EOL -- default 1, meaning strict. At 1, block (c) contributes its findings to the
#   failure list like every other block. At 0, block (c) is downgraded to a warning: the
#   offending files and the remediation are still printed in full, on stderr, but they no longer
#   contribute to the exit status. Blocks (a), (b) and (d) stay strict at every setting; there
#   is no knob that relaxes them.
#
#   The escape hatch exists for one situation. .gitattributes normalises line endings for every
#   clone, but git applies it to already-tracked files only when the working tree is
#   re-normalised, which is a deliberate, reviewable commit rather than an automatic effect of
#   adding the file. Between adding .gitattributes and running that pass, a developer needs to
#   be able to run the other three blocks and read their result without block (c)'s expected
#   failures drowning it. STRICT_EOL=0 is that run and nothing else.
#
#   CI always runs strict. Nothing in .github/workflows/ci.yml sets STRICT_EOL, so the workflow
#   gets the default, and the relaxed mode cannot leak into a pull request check. The relaxed
#   mode also announces itself on both streams on every run, pass or fail, so a run that was
#   relaxed can never be mistaken in a log for a run that was strict.
#
# WHY TRACKED FILES ONLY
#   Candidate paths come from git ls-files, so the check sees exactly what a fresh clone
#   contains: an untracked local scratch file cannot fail it, and a tracked file cannot hide.
#
# THIS SCRIPT NEVER WRITES TO GIT
#   Every git invocation below is an inspection -- rev-parse, check-ignore, ls-files. The
#   remediation printed for a line-ending failure is a command for a human to run, not one this
#   script runs itself.
#
# STREAMS
#   stdout carries exactly one summary line. stderr carries the per-item failure list, any
#   STRICT_EOL notice, and the failure diagnosis. Success exits 0; any failed item exits 1 with
#   every failure named.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so the check runs identically
#   under Git Bash on Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in CI.

set -eu

# Byte-stable git and grep output regardless of the ambient locale.
LC_ALL=C
export LC_ALL

# See ENVIRONMENT above. Default strict, so an unset variable -- which is what CI, make and a
# plain shell all supply -- is the strict setting.
STRICT_EOL=${STRICT_EOL:-1}

# Repo root is derived from the script's own location, never hardcoded, so the script works
# from any working directory and from any clone path.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "hygiene: not inside a git work tree; cannot inspect the index" >&2
    exit 1
fi

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM
problems="$work/problems"
: > "$problems"

# --- (a) ignore coverage -----------------------------------------------------------

ignored_checked=0
ignore_probe() {
    ignored_checked=$((ignored_checked + 1))
    if ! git check-ignore -q -- "$1"; then
        printf 'not gitignored (04-repo-conventions.md section 5): %s\n' "$1" >> "$problems"
    fi
}
ignore_probe '.env'
ignore_probe 'runs/x'
ignore_probe 'foo.key'
ignore_probe 'x/__pycache__/y'
ignore_probe '.venv/x'

# --- (b) nothing forbidden is tracked -----------------------------------------------

# One enumeration, one pass. POSIX case patterns rather than a per-class pathspec query, and
# `*` in a case pattern crosses directory boundaries -- exactly the at-any-depth semantics
# gitignore itself applies to its unanchored patterns. Bare .env is listed separately because
# `*/.env` requires a parent directory and must not match a top-level .env.
git ls-files -z | tr '\000' '\n' > "$work/tracked"
while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in
        runs/*|*/runs/*)
            printf 'tracked under runs/: %s\n' "$path" >> "$problems" ;;
        .venv/*|*/.venv/*)
            printf 'tracked under .venv/: %s\n' "$path" >> "$problems" ;;
        __pycache__/*|*/__pycache__/*)
            printf 'tracked under __pycache__/: %s\n' "$path" >> "$problems" ;;
        .env|*/.env)
            printf 'tracked .env file: %s\n' "$path" >> "$problems" ;;
        *.key)
            printf 'tracked key file: %s\n' "$path" >> "$problems" ;;
        .ruff_cache/*)
            printf 'tracked under .ruff_cache/: %s\n' "$path" >> "$problems" ;;
    esac
done < "$work/tracked"

# --- (c) line-ending tripwire ---------------------------------------------------------

# git ls-files --eol prints "<index-eol>  <worktree-eol>  attr/...  <path>". Field 1 is the
# index EOL and must be i/lf; the last field is the path. No path matched here contains
# whitespace, so awk field splitting is safe.
#
# THE SHAPE: A DERIVED SWEEP, A HARDCODED CORE, AND A ROW FLOOR. WHY ALL THREE.
#   The sweep is derived. Whatever git currently tracks in the covered classes -- Makefile,
#   scripts/*.sh, scripts/*.py, infra/*.env -- is listed, and every row must read i/lf. A
#   derived set is the right default because it cannot go stale: a script added next milestone
#   is covered the moment it is tracked, with no edit here to forget.
#
#   Derivation alone, however, cannot close the hole it appears to close, and that is the defect
#   this block previously had. The candidate list and the answer come from the same index. A
#   path that stops being tracked -- renamed, deleted, or removed from the index -- leaves the
#   listing at the same moment it leaves the sweep, so the sweep reports no mismatch. Zero rows
#   produce zero mismatches, and an all-clear over nothing is byte-identical to an all-clear
#   over everything. The check printed PASS while testing nothing.
#
#   So the sweep is anchored by a hardcoded core: the paths whose index EOL is load-bearing for
#   the build itself. Makefile, because GNU make rejects a CRLF recipe. The four scripts make
#   and CI delegate to, plus this one, because dash rejects a CRLF script. infra/versions.env,
#   because `make versions-sha` hashes it and the entire point of that hash is that it is the
#   same in every clone. Each must be PRESENT in the listing, and absence is its own failure
#   with its own message. That turns the block from a filter over whatever happened to be there
#   into an assertion about named paths, which is what a tripwire has to be.
#
#   The second half of the conjunction -- each core path also reads i/lf -- is left to the sweep
#   rather than repeated in the core loop. Every core path is by construction a row the sweep
#   reads, so a wrong EOL on one is already reported once; reporting it twice would only make
#   the failure list harder to read.
#
#   EOL_MIN_ROWS is the third guard: the sweep must match at least as many rows as there are
#   core paths, since by construction it matches all of them and usually more. A listing shorter
#   than that means the pathspec itself has collapsed, which is a different defect from a single
#   missing path and is reported separately so the log distinguishes the two. The floor is
#   deliberately a literal and NOT computed from the core list, because a floor derived from the
#   list it guards moves whenever that list moves and therefore guards nothing. Retiring a core
#   path is meant to require editing two places in one reviewable commit.
#
#   M6-T6.1 EXTENDED BOTH A SIXTH TIME: twenty-nine core paths to thirty-four, EOL_MIN_ROWS from
#   29 to 34. Five added, all M6 shell entry points -- scripts/run.sh, scripts/baseline.sh and
#   scripts/campaign.sh, which `make run`/`make baseline`/`make campaign` delegate to;
#   scripts/analyze.sh, which `make analyze` delegates to; and scripts/backup_sync.sh, the
#   three-copy sync (R-09). Each is executed by make and dash rejects a CRLF one, so each qualifies
#   on this block's own test. runner/*.py and analysis/*.py are Python entry points but sit outside
#   this sweep's pathspec (Makefile, scripts/*.sh, scripts/*.py, infra/*.env, infra/tests/*.sh) and
#   are covered by ruff and their component pytest steps instead; only the shell scripts are named
#   here. The pathspec already selects scripts/*.sh, so it did not need widening; the two halves
#   moved in one edit, the procedure the next two paragraphs describe.
#
#   M9 RETIRED ONE: thirty-five core paths to thirty-four, EOL_MIN_ROWS from 35 to 34.
#   scripts/docs_build.sh, the documentation site's build entry point, was deleted with the
#   site itself rather than left to assert. The list and the floor move together here for the
#   reason THE FIRST paragraph of this block gives: a floor derived from the list it guards
#   would move whenever the list moves and therefore guard nothing, so the literal is edited
#   in the same reviewable commit as the list.
#
#   M5-T5.6 EXTENDED BOTH A FIFTH TIME: twenty-five core paths to twenty-nine, EOL_MIN_ROWS from
#   25 to 29. Four added, all M5 entry points. Three are shell -- scripts/scenario_determinism.sh,
#   the scenario half of `make determinism-check` and the file .github/workflows/ci.yml's nightly
#   step invokes; scripts/scenario_guard.sh, which that workflow's guardrail-grep job runs unguarded
#   on every change; and scripts/cve_mirror.sh, which `sh scripts/cve_mirror.sh --verify` drives. The
#   fourth is scripts/blind_view.py, a Python entry point run by a scorer at M7 and by
#   scenarios/tests/, named on the same pattern versions_env_sha256.py already sits in the list by.
#   The pathspec already selects scripts/*.sh and scripts/*.py, so it did not need widening this
#   time; only the two halves the paragraph above pairs moved, in one edit, the procedure it describes.
#
#   M4-T4.5 EXTENDED BOTH A FOURTH TIME: twenty-two core paths to twenty-five, EOL_MIN_ROWS from
#   22 to 25. The three added are M4's shell entry points -- scripts/parity_check.sh, which `make
#   parity-check` delegates to and which .github/workflows/ci.yml arms on the first tracked file
#   under agents/prompts/; scripts/prompt_purity_grep.sh, which that workflow's guardrail-grep job
#   runs unguarded on every change; and scripts/agents_golden.sh, which `make agents-golden`
#   delegates to. Each qualifies on this block's own stated test and on nothing weaker: dash rejects
#   a CRLF script, and each of the three is executed by make, by CI, or by both, so a carriage
#   return in the index turns a gate into a syntax error that no CI run on a Windows-authored commit
#   would otherwise reveal. The pathspec did not need widening this time -- all three are
#   scripts/*.sh, which it already selects -- so only the two halves the paragraph above pairs
#   moved, in one edit, which is the procedure it describes.
#
#   M3-T3.8 EXTENDED BOTH A THIRD TIME, and widened the PATHSPEC for the first time: eighteen core
#   paths to twenty-two, EOL_MIN_ROWS from 18 to 22. Three of the four added are M3's own scripts --
#   guardian_test.sh, audit_verify.sh and policy_purity_grep.sh -- which make and CI invoke and which
#   dash would reject with CRLF.
#
#   The fourth is why the pathspec moved and not only the list. infra/tests/probe_agent_to_api.sh is
#   a shell script, it runs against a live cluster at Tier B, and it matched none of Makefile,
#   scripts/*.sh, scripts/*.py or infra/*.env -- so it sat outside the tripwire every other shell
#   entry point in this repository sits inside. Naming it in the core list alone would not have
#   fixed that: the core loop asserts a path is PRESENT in the listing, and a path the pathspec
#   never selects can never be present, so the check would have failed rather than covered it. The
#   pathspec now selects infra/tests/*.sh and the file is named in the core list on top of that.
#
#   M2-T2.7a EXTENDED BOTH: fourteen core paths to eighteen, EOL_MIN_ROWS from 14 to 18.
#   The four added are M2's scripts -- monitor_guard.sh and install_runtime_deps.sh, which
#   .github/workflows/ci.yml invokes directly, and monitor_replay.sh and monitor_determinism.sh,
#   which `make monitor-replay` and `make determinism-check` delegate to. Each qualifies on this
#   block's own stated test: dash rejects a CRLF script, and every one of them is executed by CI,
#   by make, or by both. The floor moved with the list in the same edit, for the reason the
#   paragraph above gives.
#
#   M1-T1.6 EXTENDED BOTH, IN ONE COMMIT, WHICH IS THE PROCEDURE THE PARAGRAPH ABOVE DESCRIBES.
#   The core list rose from seven paths to fourteen and EOL_MIN_ROWS from 7 to 14. The seven
#   added paths are the environment lifecycle scripts -- preflight, up, down, nuke, status --
#   plus scripts/netpol_proof.sh and scripts/install_cluster_tools.sh. Each qualifies on the same
#   test as the original seven: its index line endings are load-bearing for the build, because
#   dash rejects a CRLF script and every one of them is invoked by `make`, by
#   .github/workflows/env-bringup.yml, or by both. The floor moved with the list rather than
#   after it, so there is no interval in which the sweep could have gone vacuous unnoticed.
eol="$work/eol"
eol_problems="$work/eol_problems"
: > "$eol_problems"

EOL_MIN_ROWS=34

git ls-files --eol -- Makefile 'scripts/*.sh' 'scripts/*.py' 'infra/*.env' \
    'infra/tests/*.sh' > "$eol"
eol_listed=$(awk 'END { print NR }' "$eol")

awk '$1 != "i/lf" { print "index EOL is not lf: " $1 "  " $NF }' "$eol" >> "$eol_problems"

if [ "$eol_listed" -lt "$EOL_MIN_ROWS" ]; then
    printf 'EOL sweep matched %s tracked file(s), below the floor of %s: the pathspec in this script no longer describes the repository, so the sweep is passing vacuously\n' \
        "$eol_listed" "$EOL_MIN_ROWS" >> "$eol_problems"
fi

eol_core_total=0
eol_core_present=0
for core_path in Makefile infra/versions.env scripts/check_hygiene.sh scripts/grep_guard.sh \
                 scripts/lint.sh scripts/verify_slots.sh scripts/versions_env_sha256.py \
                 scripts/install_cluster_tools.sh scripts/preflight.sh scripts/up.sh \
                 scripts/down.sh scripts/nuke.sh scripts/status.sh scripts/netpol_proof.sh \
                 scripts/install_runtime_deps.sh scripts/monitor_guard.sh \
                 scripts/monitor_replay.sh scripts/monitor_determinism.sh \
                 scripts/guardian_test.sh scripts/audit_verify.sh \
                 scripts/policy_purity_grep.sh infra/tests/probe_agent_to_api.sh \
                 scripts/parity_check.sh scripts/prompt_purity_grep.sh \
                 scripts/agents_golden.sh scripts/scenario_determinism.sh \
                 scripts/scenario_guard.sh scripts/cve_mirror.sh scripts/blind_view.py \
                 scripts/run.sh scripts/baseline.sh scripts/campaign.sh scripts/analyze.sh \
                 scripts/backup_sync.sh; do
    eol_core_total=$((eol_core_total + 1))
    if awk -v want="$core_path" '$NF == want { found = 1 } END { exit !found }' "$eol"; then
        eol_core_present=$((eol_core_present + 1))
    else
        printf 'expected path absent from the EOL listing -- untracked, renamed or deleted, so nothing checked its line endings: %s\n' \
            "$core_path" >> "$eol_problems"
    fi
done

# Route this block's findings by severity. Strict is the default and is what CI runs; the
# ENVIRONMENT section of the header explains why the relaxed setting exists at all.
eol_relaxed=0
if [ "$STRICT_EOL" = "0" ]; then
    eol_relaxed=1
    echo "hygiene: STRICT_EOL=0 — block (c), line endings, is ADVISORY for this run. Blocks (a), (b) and (d) stay strict. CI never sets this variable, so CI always runs strict." >&2
else
    cat "$eol_problems" >> "$problems"
fi

# --- (d) directory existence -----------------------------------------------------------
# Source: docs/04-repo-conventions.md section 1 folder map -- every unstarred directory it draws
# (.github/workflows, docs, infra, monitor, guardian, agents, scenarios, runner, analysis,
# scripts). runs/ is starred and gitignored: absent by design.
dir_total=0
dir_present=0
for dir in .github/workflows docs infra monitor guardian \
           agents scenarios runner analysis scripts; do
    dir_total=$((dir_total + 1))
    if [ -d "$dir" ]; then
        dir_present=$((dir_present + 1))
    else
        printf 'directory asserted by 04-repo-conventions.md section 1 is missing: %s\n' \
            "$dir" >> "$problems"
    fi
done

# --- report -----------------------------------------------------------------------------

# The advisory warning is printed before the pass/fail decision so that it appears whether or
# not another block failed: a downgraded line-ending finding must never be hidden by an
# unrelated failure taking the run to a FAIL summary.
eol_problem_count=$(awk 'END { print NR }' "$eol_problems")
if [ "$eol_relaxed" -eq 1 ] && [ "$eol_problem_count" -gt 0 ]; then
    {
        echo "hygiene: WARNING — $eol_problem_count line-ending problem(s), downgraded by STRICT_EOL=0:"
        echo
        cat "$eol_problems"
        echo
        echo "These do not affect the exit status of this run. They would fail the check under"
        echo "the default STRICT_EOL=1, which is what CI runs."
        echo
        echo "Remediation, to be run by a human: 'git add --renormalize .', then review and"
        echo "commit the result. This script only inspects git; it never writes to it."
    } >&2
fi

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        echo "hygiene: FAIL — $problem_count problem(s):"
        echo
        cat "$problems"
        echo
        echo "Each item above is a repository defect, not a check defect: fix the repo, not"
        echo "this script. Its contract is docs/04-repo-conventions.md sections 1 and 5."
    } >&2
    printf 'hygiene: FAIL — %s problem(s)\n' "$problem_count"
    exit 1
fi

if [ "$eol_relaxed" -eq 1 ]; then
    printf 'hygiene: PASS — %s ignore probes covered, 0 forbidden files tracked, %s file(s) in the EOL sweep, %s/%s expected path(s) present; EOL group ADVISORY (STRICT_EOL=0) with %s line-ending problem(s) not counted, %s/%s asserted directories present\n' \
        "$ignored_checked" "$eol_listed" "$eol_core_present" "$eol_core_total" \
        "$eol_problem_count" "$dir_present" "$dir_total"
    exit 0
fi

printf 'hygiene: PASS — %s ignore probes covered, 0 forbidden files tracked, %s file(s) i/lf in the index (floor %s, %s/%s expected path(s) individually present), %s/%s asserted directories present\n' \
    "$ignored_checked" "$eol_listed" "$EOL_MIN_ROWS" "$eol_core_present" "$eol_core_total" \
    "$dir_present" "$dir_total"
exit 0
