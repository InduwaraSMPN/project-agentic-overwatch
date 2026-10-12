#!/bin/sh
#
# lint.sh -- run the repository's Python lint and format checks. Backs `make lint`
# (docs/04-repo-conventions.md section 3) and the `lint` job in .github/workflows/ci.yml, both
# of which delegate here so the lint command has exactly one definition.
#
# WHY A SCRIPT AND NOT AN INLINE RECIPE
#   The M0 plan's "Logic lives in scripts/*.sh, not in recipes" applies to every implemented
#   target: Windows has no make, so a behaviour written into a recipe is unrunnable on the
#   development host, while the same script runs unchanged from Git Bash, from dash under WSL2
#   and on ubuntu-latest. CI calls this file directly, exactly as it calls verify_slots.sh,
#   grep_guard.sh and check_hygiene.sh, so a local run and a CI run execute the same bytes.
#
# CONFIGURATION LIVES IN pyproject.toml
#   Rule selection, line length, src roots and excludes all come from [tool.ruff] there, and
#   nothing is passed on the command line below. One configuration home, with no second set of
#   settings hiding in this script or in the workflow. The ruff version itself is pinned by the
#   workflow rather than here, because a CI tool version is not an experiment parameter and the
#   pin belongs next to the install step that applies it.
#
# BOTH CHECKS ALWAYS RUN
#   A failing `ruff check` does not skip the format check. The two report different classes of
#   problem, so stopping at the first would hide the second until the next invocation and turn
#   one fix-and-rerun cycle into two. The exit status is non-zero if either check failed.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options.

set -eu

# Repo root derived from this script's own location, so behaviour is identical whether the script
# is invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

if [ -x .venv/bin/ruff ]; then
    ruff_bin=.venv/bin/ruff
elif [ -x .venv/Scripts/ruff.exe ]; then
    ruff_bin=.venv/Scripts/ruff.exe
elif command -v ruff >/dev/null 2>&1; then
    ruff_bin=ruff
else
    echo "lint: ruff is not on PATH. Install the version pinned by the lint job in" >&2
    echo "lint: .github/workflows/ci.yml, so local findings match the CI log." >&2
    exit 1
fi

status=0

"$ruff_bin" check . || status=1
"$ruff_bin" format --check . || status=1

exit "$status"
