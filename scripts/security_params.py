"""Print the Guardian's capability-token parameters as shell assignments, read from the protocol.

WHY THIS SCRIPT EXISTS
----------------------
``scripts/guardian_deploy.sh`` requires five runtime settings and supplies no default for any of
them, deliberately: a Guardian that started on a value nobody chose would be enforcing a TTL that
appears in no document. The values belong to ``docs/protocols/security-policy.md`` section 2, which
that file names as their single source of truth, and ``the source-of-truth iron rule (AGENTS.md 1)``
allows other files to reference them and never to restate one with a value.

An operator env script that wrote ``GUARDIAN_TOKEN_TTL_SECONDS=300`` would be a restatement, and a
second place to update. This script reads the numbers out of the protocol prose instead, with
anchored patterns, and fails loudly when an anchor stops matching. That failure mode is the point:
if section 2 is reworded, an operator is told to come and re-anchor the extraction rather than
being handed a stale number that still parses.

USAGE
-----
    eval "$(python scripts/security_params.py)"

Emits, on stdout, one ``NAME=value`` line per setting, in a fixed order, quoted for ``sh``. Writes
nothing else to stdout, so the output is safe to ``eval``. Exits 1 with a diagnostic on stderr when
any of the five cannot be extracted.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
`scripts/live_env.sh` and any operator recipe that composes a Guardian deployment. Adding a default
here would reintroduce exactly the second source of truth the fail-closed design exists to prevent.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
PROTOCOL: Final = REPO_ROOT / "docs" / "protocols" / "security-policy.md"
SECTION_HEADING: Final = "## 2. Capability token parameters"

# Each entry is (env name, human description, pattern, converter). The patterns are anchored on
# words section 2 uses as terms of art -- "TTL", "replay cache", "algorithm" -- rather than on line
# positions, so ordinary reflowing of the paragraph does not break them but a change of meaning
# does.
_EXTRACTORS: Final = (
    (
        "GUARDIAN_TOKEN_TTL_SECONDS",
        "the default token TTL",
        re.compile(r"`TTL\s*=\s*(\d+)s`"),
        int,
    ),
    (
        "GUARDIAN_TOKEN_MAX_TTL_SECONDS",
        "the per-phase TTL ceiling",
        re.compile(r"override allowed,\s*≤\s*(\d+)s"),
        int,
    ),
    (
        "GUARDIAN_TOKEN_ALGORITHM",
        "the token signing algorithm",
        re.compile(r"algorithm\s+(HS\d{3})\b"),
        str,
    ),
    (
        "GUARDIAN_REPLAY_CACHE_ENTRIES",
        "the replay cache size in jti",
        re.compile(r"replay\s+cache of the last\s+`(\d+)`\s+jti"),
        int,
    ),
    (
        "GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS",
        "the replay cache window",
        re.compile(r"jti\s+or\s+(\d+)h\b"),
        lambda hours: int(hours) * 3600,
    ),
)


def _section_two(text: str) -> str:
    """Return section 2's body with whitespace normalised, or raise when it is not present."""
    start = text.find(SECTION_HEADING)
    if start < 0:
        raise LookupError(f"{PROTOCOL} has no section headed {SECTION_HEADING!r}")
    end = text.find("\n## ", start + len(SECTION_HEADING))
    body = text[start : end if end > 0 else len(text)]
    return " ".join(body.split())


def main() -> int:
    try:
        section = _section_two(PROTOCOL.read_text(encoding="utf-8"))
    except (OSError, LookupError) as error:
        print(f"security-params: {error}", file=sys.stderr)
        return 1

    lines: list[str] = []
    for name, description, pattern, convert in _EXTRACTORS:
        match = pattern.search(section)
        if match is None:
            print(
                f"security-params: cannot read {description} from "
                f"{PROTOCOL.relative_to(REPO_ROOT).as_posix()} section 2. The value is owned there "
                "and is never defaulted here; re-anchor the pattern in scripts/security_params.py "
                "against the current wording.",
                file=sys.stderr,
            )
            return 1
        lines.append(f"{name}='{convert(match.group(1))}'")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
