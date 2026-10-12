#!/bin/sh
# policy_purity_grep.sh — machine enforcement of ADR-023's isolation assertion 7, and the static
# counterpart of the bundle-hash assertion (isolation assertion 1).
#
# WHAT THE RULE IS
# `the guardian-first iron rule (AGENTS.md 1)`: "The G1-LOGONLY / G2-SHAREDCRED ablation arms are activated
# ONLY via the runner's condition flags — never by editing Guardian code or policy inline."
# `docs/plans/M3-implementation-plan.md` turns that into a check with a named owner: a script
# "asserting that no file under guardian/policies/ mentions any arm or mode token". This is that
# script.
#
# WHY THE POLICY BUNDLE IS WHERE THE RULE IS EASIEST TO BREAK
# Rego already evaluates a decision, so a mode input and a rule returning permit-with-a-warning
# under G1 is a small, readable, tempting change — ADR-023 names it as the rejected alternative it
# most expects somebody to reach for. The cost is not a failing test; it is an invalid arm. With the
# mode inside the policy, G0-versus-G1 becomes a comparison of two policy evaluations rather than of
# one policy evaluated twice, and dissertation §3.5.4's "each configuration removes exactly one
# property" stops describing the design even while every test stays green. Silent invalidity is the
# failure mode this script exists to make loud.
#
# WHY THIS IS *STATIC* WHEN THERE IS ALREADY A BUNDLE-HASH ASSERTION
# The two prove different things and neither implies the other. The sha256 assertion proves the
# three arms load the *same bytes*; it says nothing about what those bytes contain, so a bundle that
# is mode-aware in all three arms equally would pass it. This grep reads the bytes and says nothing
# about which arm loaded them. Together they close both halves: the same policy everywhere, and a
# policy that cannot name an arm at all.
#
# WHY TWO PATTERNS AND NOT ONE
# Pattern 1 is the literal rule: the canonical condition ids of `docs/07-glossary-and-ids.md`, in
# either hyphen or underscore spelling and in any case, because `G1_LOGONLY` names the same arm as
# `G1-LOGONLY` and `guardian/app/config.py` rejects the underscore spelling at startup precisely
# because somebody will write it. Pattern 2 is defence in depth against the same arm reached under
# another name: a policy that never writes "G1-LOGONLY" but branches on `input.guardian.mode`, or
# on an `enforce`, `dry_run`, `shadow` or `bypass` key, is mode-aware policy with the token filed
# off. Its word list is `MODE_SHAPED_FIELD_NAMES` from `guardian/app/config.py` — the repository's
# single definition of what a mode-shaped name is — matched in that module's own normalised sense,
# so `guardian_mode`, `guardian-mode`, `guardianMode` and `GUARDIAN_MODE` are one entry and not four.
# Restating a shorter list here would be a second home for that definition and a weakening chosen
# for convenience; rule 00 forbids the first and grep_guard.sh's header forbids the second.
#
# THERE IS DELIBERATELY NO EXEMPTION MECHANISM
# No allowlist file, no inline sentinel, no per-path skip, and no comment-stripping pass: every
# tracked file under guardian/policies/ is scanned in full, whatever its extension, comments and
# prose included. This is `scripts/grep_guard.sh`'s stance and it is taken here for that script's
# own reason — an exemption added before the first true positive is sized to convenience rather than
# to risk, and dropping comments from the scan is that same hole under a tidier name, because a
# comment reading "under G1-LOGONLY this rule permits" is evidence the policy is mode-aware whether
# or not the code below it is.
#
# UNTIL THERE IS AN ADR, THE PROSE MOVES AND NOT THE CHECK
# The false positives to expect are all in pattern 2 and all in comments: `audit`, `condition` and
# `enforce` are ordinary words for describing a deny-by-default policy. A Rego comment that needs to
# say one of them says it another way — "every decision is recorded in the hash chain" rather than
# "audited", "the rule holds when" rather than "the condition is", "denies" rather than "enforces".
# That costs one sentence and keeps the guard honest about what it has actually read. If M3's policy
# work produces a false positive worth arguing about, that is an ADR at the milestone that produced
# it — with the alternatives written down — and not a hole punched here in advance of any evidence
# about what a real false positive looks like.
#
# SCOPE AND EXIT CODES
# Tracked files only (git ls-files), so an untracked local scratch file cannot fail CI and the check
# sees exactly what a fresh clone contains. Exit 0 on a clean scan or on a vacuous pass — vacuous
# meaning guardian/policies/ is absent or holds no tracked files at all, which is the state before
# M3-T3.2 lands its first .rego — and exit 1 on any hit. Strict POSIX sh: this runs under dash on
# WSL2 Ubuntu and on ubuntu-latest.

set -eu

# Repo root derived from this script's own location, so behaviour is identical whether the script is
# invoked by make, by CI, by the flag-isolation suite, or by hand from an arbitrary directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

policy_root=guardian/policies

# The bundle is authored at M3-T3.2 and may not exist yet — in a fresh clone the directory is absent
# entirely, because git does not track an empty one. A guard that goes red for the whole window
# between "the script landed" and "the policy landed" is a guard nobody is still reading by the time
# it has something to say, so the pre-bundle state is an explicit vacuous pass rather than a failure.
if [ ! -d "$policy_root" ]; then
    echo "policy-purity: $policy_root absent (pre-T3.2) — arm/mode purity guard vacuously passes"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
files="$work/files"
hits="$work/hits"
: > "$hits"

git ls-files -z -- "$policy_root/*" | tr '\0' '\n' > "$files"

# `tr` is the POSIX-portable way to consume -z output; `read -d ''` is a bashism. The only case in
# which that conversion is ambiguous is a tracked path containing a literal newline, so compare the
# two encodings and prove it rather than assume it. git quotes such a path on the non-z path, which
# collapses it to one line, so the counts diverge exactly when the assumption breaks.
z_lines=$(wc -l < "$files" | tr -d ' ')
nl_lines=$(git ls-files -- "$policy_root/*" | wc -l | tr -d ' ')
if [ "$z_lines" != "$nl_lines" ]; then
    echo "policy-purity: refusing to run — a tracked path under $policy_root contains a newline" >&2
    exit 1
fi

if [ "$z_lines" -eq 0 ]; then
    echo "policy-purity: $policy_root holds no tracked files (pre-T3.2) — arm/mode purity guard vacuously passes"
    exit 0
fi

# Every tracked path under the bundle is a candidate; there is no filtering step between the
# candidate list and the scan.
scan_count=$z_lines

arm_token_pattern='\b(G0[_-]FULL|G1[_-]LOGONLY|G1[_-]LOG[_-]ONLY|G2[_-]SHAREDCRED|G2[_-]SHARED[_-]CRED|G3[_-]UNQUOTED|S1[_-]HIER|S2[_-]FLAT|S3[_-]SINGLE)\b'
mode_word_pattern='\b(arm|audit|bypass|condition|dry[_.-]?run|enforce|enforcement|guardian[_.-]?mode|log[_.-]?only|mode|override|shadow|skip)\b'

# scan <pattern-name> <extended-regex>
# Appends one line per hit to $hits, formatted path:line: <matching line>, tagged with the pattern
# that fired. -I skips binary files; -E is required because the patterns are extended regexes; -i
# because the mode-shaped word list is matched in guardian/app/config.py's case-folded sense and an
# arm named in lower case is still an arm named.
scan() {
    scan_name=$1
    scan_pattern=$2
    while IFS= read -r scan_file; do
        [ -n "$scan_file" ] || continue
        grep -niEI -e "$scan_pattern" -- "$scan_file" | while IFS= read -r scan_hit; do
            scan_lineno=${scan_hit%%:*}
            scan_text=${scan_hit#*:}
            printf '%s:%s: %s   <-- [%s]\n' \
                "$scan_file" "$scan_lineno" "$scan_text" "$scan_name"
        done >> "$hits"
    done < "$files"
}

scan arm-token        "$arm_token_pattern"
scan mode-shaped-word "$mode_word_pattern"

hit_count=$(wc -l < "$hits" | tr -d ' ')

if [ "$hit_count" -gt 0 ]; then
    {
        echo "policy-purity: FAIL — $policy_root names an arm or a mode ($hit_count hit(s))"
        echo
        cat "$hits"
        echo
        echo "Patterns:"
        echo "  arm-token         $arm_token_pattern"
        echo "  mode-shaped-word  $mode_word_pattern"
        echo
        echo "The Guardian mode is a start-time, runner-only parameter (ADR-023, the guardian-first iron rule (AGENTS.md 1))."
        echo "Policy is mode-blind: it decides the same way in G0-FULL, G1-LOGONLY and G2-SHAREDCRED,"
        echo "and what differs between the arms is what the Guardian does with the decision."
        echo "Fix the policy, or reword the comment — see this script's header."
        echo "There is no exemption mechanism by design."
    } >&2
    exit 1
fi

echo "policy-purity: PASS — scanned $scan_count tracked file(s) under $policy_root against 2 arm/mode patterns; no hits"
exit 0
