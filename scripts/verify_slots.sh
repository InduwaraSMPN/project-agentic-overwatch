#!/bin/sh
#
# verify_slots.sh -- fail while any unbound dissertation VERIFY slot remains in a tracked
# file. Backs `make verify-slots` (docs/04-repo-conventions.md section 3) and milestone
# task M0-T0.3; the burn-down itself is M0-T0.6.
#
# MARKER CONVENTION
#   A slot is written as U+27E6 (MATHEMATICAL LEFT WHITE SQUARE BRACKET) immediately
#   followed by the ASCII word VERIFY. Matching that prefix catches both the long form used
#   throughout the kit -- U+27E6 VERIFY-DISSERTATION <section anchor> U+27E7 -- and the bare
#   form at docs/milestones/M0-inception.md line 43. Matching is fixed-string (grep -F),
#   never a regular expression, so the multibyte literal needs no escaping and cannot be
#   mangled by a shell or grep dialect difference. The marker is spelled out exactly once,
#   on the MARKER= line below, so there is a single place to read its definition.
#
# SENTINEL OPT-OUT
#   A matching line that also contains the literal text  verify-slots:ignore  is exempt. It
#   is counted and reported, never failed on. Exemption exists for meta-references: lines
#   that describe the convention rather than carry an unbound slot. In Markdown, write the
#   sentinel as a trailing HTML comment -- <!-- verify-slots:ignore --> -- which is invisible
#   when the page is rendered, so the prose stays clean for the reader and the examiner.
#   The MARKER= line below carries the sentinel for precisely this reason: the definition of
#   the marker is not itself an unbound slot. Exemption is per line, never per file, so a
#   real slot elsewhere in an exempted file is still caught.
#
# WHY THE SCAN IS REPO-WIDE AND NOT docs/-ONLY
#   Three markers live outside docs/: AGENTS.md, the source-of-truth iron rule (AGENTS.md 1) and
#   context/README.md. docs/milestones/M0-inception.md line 43 states the obligation as
#   every marker, not every marker under docs/, so a docs/-only scan would under-report and
#   the Definition-of-Done item would be satisfiable while unbound slots remained. Candidate
#   files come from git ls-files, so the check sees exactly what a fresh clone contains: an
#   untracked scratch file cannot fail it, and a file that is tracked cannot hide from it.
#
# EXCLUSION
#   context/submitted-* is skipped. It is read-only ground truth -- the marker convention
#   does not apply to the dissertation itself -- and skipping it also keeps a 636 KB PDF and
#   a 4302-line text extraction out of every invocation.
#
# DO NOT REIMPLEMENT THIS WITH RIPGREP DEFAULTS
#   rg skips dot-directories unless told otherwise and therefore silently misses
#   the source-of-truth iron rule (AGENTS.md 1); that exact blind spot was observed during M0
#   exploration. git ls-files plus POSIX grep has no such default.
#
# STREAMS
#   stdout carries the machine-readable match list and exactly one summary line. stderr
#   carries human diagnostics. On success stdout is the summary line and nothing else.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only grep options. Runs identically under Git Bash
#   on Windows, under dash in WSL2 and on ubuntu-latest in CI, which is what lets M0-T0.3 be
#   verified without a running Linux distro (see the plan's "Logic lives in scripts/*.sh").

set -eu

# Byte-exact matching, and it stops grep from declaring a file binary because its bytes do
# not decode under the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root is derived from the script's own location, never hardcoded, so the script works
# from any working directory and from any clone path.
cd "$(dirname "$0")/.." || exit 1

MARKER='⟦VERIFY'  # verify-slots:ignore -- this is the marker definition, not a slot
SENTINEL='verify-slots:ignore'

# TRIP-WIRE
#   Adding a sentinel is a one-character-cheap way to silence this check, so cap how many
#   exempted lines the repository may hold. Crossing the cap is a failure with its own
#   message: it means the convention is being suppressed rather than satisfied.
#
#   The cap equals the live count on purpose -- there is no headroom. The test below is
#   exempt_count > EXEMPT_CAP, so deleting a meta-reference never trips it and only adding
#   one does, which is exactly the edit that wants a reviewer. Headroom would let additions
#   land without anyone re-reading the accounting below, and that accounting would drift out
#   of step with the repository -- the failure this cap exists to prevent. So: whoever adds a
#   line describing the marker convention raises this number AND updates the accounting
#   below, in the same edit. A red build at that moment is the coupling working, not a bug.
#
#   WHERE THE NUMBER COMES FROM (recount any time with: sh scripts/verify_slots.sh)
#     10  the convention's own definition sites across the kit, one exempted line each:
#           the source-of-truth iron rule (AGENTS.md 1), AGENTS.md, context/README.md,
#           docs/04-repo-conventions.md, docs/README.md, docs/prompts-playbook.md (2),
#           docs/milestones/M0-inception.md (3). These ten pre-date the sentinel.
#      2  docs/plans/M0-implementation-plan.md -- its verify-slots design-decision
#           section and its Verification table -- written during M0, after the cap was set.
#      1  the MARKER= line in THIS script. The marker's definition is not itself a slot,
#           and it is the one everybody forgets when recounting by hand.
#     --
#     13
#
#   Supersedes an earlier note here reading "12 -> 14 ... three meta-references in the
#   implementation plan": 12 + 3 is 15, and it omitted the MARKER= line entirely. ADR-009
#   carries the corrected accounting and the no-headroom argument.
EXEMPT_CAP=13

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "verify-slots: not inside a git work tree; cannot enumerate tracked files" >&2
    exit 1
fi

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM

hits="$work/hits"
: > "$hits"

# git ls-files -z is NUL-separated; POSIX read has no -d, so translate to newlines. Paths
# containing a literal newline would split, but git rejects those on every platform this
# repository targets and none exist here.
git ls-files -z | tr '\000' '\n' > "$work/files"

while IFS= read -r path; do
    case "$path" in
        context/submitted-*) continue ;;
    esac
    # Tracked but deleted from the working tree, or a submodule gitlink.
    [ -f "$path" ] || continue
    # /dev/null is passed as a second file so grep always prefixes the path. With a single
    # file argument grep omits the prefix and the output format would silently change.
    grep -nF -- "$MARKER" /dev/null "$path" >> "$hits" || :
done < "$work/files"

grep -F -- "$SENTINEL" "$hits" > "$work/exempt" || :
grep -vF -- "$SENTINEL" "$hits" > "$work/unbound" || :

unbound_count=$(awk 'END { print NR }' "$work/unbound")
exempt_count=$(awk 'END { print NR }' "$work/exempt")

status=0

if [ "$unbound_count" -gt 0 ]; then
    echo "verify-slots: unbound dissertation slots -- bind each from context/ per M0-T0.6," >&2
    echo "verify-slots: or add the sentinel if the line only describes the convention:" >&2
    # grep prints path:line:text; insert one space after the line number to match the
    # documented report format path:line: <text>.
    sed 's/:\([0-9][0-9]*\):/:\1: /' "$work/unbound"
    status=1
fi

if [ "$exempt_count" -gt "$EXEMPT_CAP" ]; then
    printf 'verify-slots: TRIP-WIRE -- %s exempted lines exceeds the cap of %s.\n' \
        "$exempt_count" "$EXEMPT_CAP" >&2
    echo "verify-slots: the sentinel is for meta-references that describe the convention." >&2
    echo "verify-slots: a real slot must be bound from context/, not silenced. Raise" >&2
    echo "verify-slots: EXEMPT_CAP in this script only with a recorded reason." >&2
    status=1
fi

printf 'verify-slots: %s unbound, %s exempted meta-references\n' \
    "$unbound_count" "$exempt_count"

exit "$status"
