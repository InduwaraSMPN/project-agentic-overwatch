r"""Run and baseline identifiers: parsed by a closed-vocabulary grammar, never split on hyphens.

WHY A GRAMMAR AND NOT ``split("-")``
--------------------------------------
``RUN-G0-FULL-SCN-CVE-03-INJ-A-101`` is nine hyphen-separated pieces for four components, and
``BASE-LOAD-STEADY-101`` is four for two. Every component carries an internal hyphen -- the arm
token (``G0-FULL``), the scenario (``SCN-CVE-03``), the injection condition (``INJ-A``), the load
profile (``LOAD-STEADY``). ``run_id.split("-")`` therefore produces plausible garbage rather than an
error, which is the worst available failure mode for the one comparison ``data-management.md`` §2
calls "total": the campaign validator parses these four components out of the identifier and checks
them field for field against the manifest, 750 times.

So the parser is a single anchored regex over closed vocabularies. ``<COND>`` is one of the arm
tokens ``07-glossary-and-ids.md`` §Condition IDs fixes, ``<SCN>`` is ``SCN-(CVE|SIM)-\d{2}``,
``<INJ>`` is one of the five injection-condition values, ``<SEED>`` is the fixed three-digit field,
and ``-R<n>`` is terminal and optional. The glossary already argues this is unambiguous: "Because
``-R<n>`` is terminal and ``<SEED>`` is a fixed three-digit field, the suffix never makes the
identifier ambiguous to parse", and every ``LOAD-`` component starts with a letter, so nothing in a
profile slug can be mistaken for the seed.

Both parsers are total and RAISE rather than returning ``None``, for the reason
``infra/locust/registry.py``'s ``resolve`` gives in its own docstring: an identifier that does not
parse is a defect to surface, not a value to default. The formatting inverses and a round-trip
property test over the whole grid keep parse and format from drifting.

THE CELL KEY IS ONE FUNCTION
------------------------------
The **cell key** is the identifier with any ``-R<n>`` suffix stripped. Three separate rules read it
-- rerun retention, "exactly one valid attempt per cell", and matched-pair formation -- so three
open-coded strippings would be three chances to disagree. It is :func:`cell_key`, once.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
Every parse of an identifier in the campaign: the validator's field-for-field check (T-23), the
order generator's cell enumeration (T-24), and the sealer's identifier-versus-manifest comparison.
ADR-039.
"""

import re
from dataclasses import dataclass
from typing import Final

__all__ = (
    "ARM_TOKENS",
    "CANONICAL_ARMS",
    "INJECTION_CONDITIONS",
    "BaselineId",
    "IdError",
    "RunId",
    "cell_key",
    "format_baseline_id",
    "format_run_id",
    "parse_baseline_id",
    "parse_run_id",
)

# The seven condition tokens 07-glossary-and-ids.md §Condition IDs fixes. A run identifier may carry
# any of them; the SIX-arm canonical set the grid closes on lives in runner/grid.py, where S1-HIER
# is resolved to its canonical alias G0-FULL. The parser recognises S1-HIER so a manifest carrying
# it can be parsed and then rejected by the validator's "no arm issued twice" rule, rather than
# failing to parse and hiding the defect.
ARM_TOKENS: Final[tuple[str, ...]] = (
    "S1-HIER",
    "S2-FLAT",
    "S3-SINGLE",
    "G0-FULL",
    "G1-LOGONLY",
    "G2-SHAREDCRED",
    "G3-UNQUOTED",
)

# The canonical six arms the grid is counted over. S1-HIER is absent: it is an alias of G0-FULL, and
# a campaign carrying both is invalid (glossary; data-management §2). Restated here as a tuple the
# grid module imports, so "which six" has one home.
CANONICAL_ARMS: Final[tuple[str, ...]] = (
    "G0-FULL",
    "S2-FLAT",
    "S3-SINGLE",
    "G1-LOGONLY",
    "G2-SHAREDCRED",
    "G3-UNQUOTED",
)

INJECTION_CONDITIONS: Final[tuple[str, ...]] = ("INJ-NONE", "INJ-A", "INJ-B", "INJ-C", "INJ-D")

# Assembled from the vocabularies above so the regex and the tuples cannot disagree. Longest-first
# alternation on the arm tokens is not needed here because each is anchored by the surrounding
# hyphens and none is a prefix of another, but the injection alternation puts INJ-NONE first for
# readability.
_ARM_ALT = "|".join(re.escape(token) for token in ARM_TOKENS)
_INJ_ALT = "|".join(re.escape(token) for token in INJECTION_CONDITIONS)

RUN_ID_PATTERN: Final = re.compile(
    rf"^RUN-(?P<cond>{_ARM_ALT})-(?P<scn>SCN-(?:CVE|SIM)-[0-9]{{2}})-(?P<inj>{_INJ_ALT})"
    rf"-(?P<seed>[0-9]{{3}})(?:-R(?P<rerun>[1-9][0-9]*))?$"
)

# A load-profile slug: LOAD- then letter-led uppercase-alphanumeric segments, the exact shape
# infra/locust/registry.py's PROFILE_ID_PATTERN fixes. Every segment starts with a letter, so the
# terminal -\d{3} seed can never be a profile segment.
BASELINE_ID_PATTERN: Final = re.compile(
    r"^BASE-(?P<load>LOAD-[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*)"
    r"-(?P<seed>[0-9]{3})(?:-R(?P<rerun>[1-9][0-9]*))?$"
)


class IdError(Exception):
    """An identifier does not parse under the closed-vocabulary grammar."""


@dataclass(frozen=True)
class RunId:
    """The four grid coordinates a run identifier carries, plus its optional rerun attempt.

    ``attempt`` is ``None`` for the unsuffixed first attempt and an integer >= 2 for a rerun,
    exactly
    as the glossary defines ``-R<n>``.
    """

    condition: str
    scenario_id: str
    injection_condition: str
    seed: int
    attempt: int | None = None


@dataclass(frozen=True)
class BaselineId:
    """A framework-off baseline identifier: a load profile and a seed, no arm and no scenario."""

    load_profile_id: str
    seed: int
    attempt: int | None = None


def parse_run_id(run_id: str) -> RunId:
    """Parse a grid-run identifier, raising :class:`IdError` if the grammar rejects it."""
    match = RUN_ID_PATTERN.match(run_id)
    if match is None:
        raise IdError(
            f"{run_id!r} is not a RUN-<COND>-<SCN>-<INJ>-<SEED>[-R<n>] identifier over the fixed "
            "vocabularies (07-glossary-and-ids.md §Run & campaign IDs)"
        )
    rerun = match.group("rerun")
    return RunId(
        condition=match.group("cond"),
        scenario_id=match.group("scn"),
        injection_condition=match.group("inj"),
        seed=int(match.group("seed")),
        attempt=int(rerun) if rerun is not None else None,
    )


def parse_baseline_id(baseline_id: str) -> BaselineId:
    """Parse a framework-off baseline identifier, raising :class:`IdError` on a malformed one."""
    match = BASELINE_ID_PATTERN.match(baseline_id)
    if match is None:
        raise IdError(
            f"{baseline_id!r} is not a BASE-<LOAD>-<SEED>[-R<n>] identifier "
            "(07-glossary-and-ids.md "
            "§Run & campaign IDs)"
        )
    rerun = match.group("rerun")
    return BaselineId(
        load_profile_id=match.group("load"),
        seed=int(match.group("seed")),
        attempt=int(rerun) if rerun is not None else None,
    )


def format_run_id(run: RunId) -> str:
    """The formatting inverse of :func:`parse_run_id`. Round-trips over the whole grid, by test."""
    if run.condition not in ARM_TOKENS:
        raise IdError(f"{run.condition!r} is not one of the fixed arm tokens")
    if run.injection_condition not in INJECTION_CONDITIONS:
        raise IdError(
            f"{run.injection_condition!r} is not one of the five injection-condition values"
        )
    base = f"RUN-{run.condition}-{run.scenario_id}-{run.injection_condition}-{run.seed:03d}"
    return base if run.attempt is None else f"{base}-R{run.attempt}"


def format_baseline_id(baseline: BaselineId) -> str:
    """The formatting inverse of :func:`parse_baseline_id`."""
    base = f"BASE-{baseline.load_profile_id}-{baseline.seed:03d}"
    return base if baseline.attempt is None else f"{base}-R{baseline.attempt}"


def cell_key(identifier: str) -> str:
    """The identifier with any terminal ``-R<n>`` stripped: the key three separate rules read.

    Accepts either a run or a baseline identifier -- both take the same suffix on the same rule --
    and raises :class:`IdError` on anything that parses as neither, so a caller cannot pass a
    malformed identifier and receive it back unchanged.
    """
    run_match = RUN_ID_PATTERN.match(identifier)
    if run_match is not None:
        run = parse_run_id(identifier)
        return format_run_id(
            RunId(run.condition, run.scenario_id, run.injection_condition, run.seed)
        )
    baseline_match = BASELINE_ID_PATTERN.match(identifier)
    if baseline_match is not None:
        baseline = parse_baseline_id(identifier)
        return format_baseline_id(BaselineId(baseline.load_profile_id, baseline.seed))
    raise IdError(f"{identifier!r} parses as neither a run nor a baseline identifier")
