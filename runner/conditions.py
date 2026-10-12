r"""The condition-flag matrix (T6.1): the flags each arm sets, set here and only here.

WHAT THIS MODULE OWNS
-----------------------
``M6-runner.md`` T6.1's whole content is that condition flags -- the structure and guardrail arms --
are set by the runner from the ``COND`` coordinate, and nowhere else. This is a single frozen table
mapping each of the six canonical arms to its flag tuple, so a run's arm is a lookup, not
a branch scattered across the runner. ``.agents/rules/10-guardian-first.md`` already requires the
Guardian arms be "activated ONLY via the runner's condition flags"; ADR-040 extends that to all six,
G3 included.

THREE PROPERTIES OF THIS TABLE ARE TESTS, NOT PROSE
-----------------------------------------------------
1. **Each arm differs from the shared arm in exactly one column** -- §3.5.4's "each configuration
   removes exactly one property", expressed as an assertion over the table. ``G2-SHAREDCRED`` is the
   documented exception and differs in two (guardian_mode AND the netpol overlay), the
   non-orthogonality ``evaluation-protocol.md`` §1 and ADR-024 record; the test encodes that
   exception by name and fails if any *other* arm acquires a second difference -- a test that
   tolerated two differences silently could not see the defect it exists for.
2. **G3-UNQUOTED routes to the Monitor, not the Guardian.** ``guardian/app/config.py`` rejects
   ``GUARDIAN_MODE=G3-UNQUOTED`` by name at startup -- correctly, since G3 removes a Monitor
   property and runs under full mediation. So the G3 row carries ``guardian_mode='G0-FULL'`` and
   ``aggregator_quoting=False``, reaching ``monitor/aggregator/cli.py``'s existing ``--no-quoting``.
   M2 left that toggle reachable as configuration only; M6 owes that nothing but this table
   ever sets it, the same obligation T-13 carries for G1 and G2.
3. **The manifest's flag fields are written from this table, never from the environment.** The
   bundle records the condition the runner *selected*; the flag-isolation test asserts the two
   agree, so a run whose environment was tampered with cannot seal as a clean arm.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The condition-flag isolation tests (T-13's agent-layer half, extended to G3) and the manifest fields
every framework-on bundle seals with. ADR-040.
"""

from dataclasses import dataclass
from typing import Final

from runner.ids import CANONICAL_ARMS

__all__ = ("CONDITION_FLAGS", "ConditionFlags", "flags_for")


@dataclass(frozen=True)
class ConditionFlags:
    """The flag tuple one arm selects. Written verbatim into the run manifest's flag fields.

    ``netpol_overlay`` is ``"default-deny"`` for every arm except G2, whose overlay is ``"opened"``
    (``infra/netpol/agents-g2-open.yaml``). It is not a manifest field today (conflict M6-C3 records
    that the bundle has no record of whether the overlay applied); it is carried here because the
    runner applies it, and named so the one-property-differs test can see G2's second difference.
    """

    graph_id: str
    guardian_mode: str
    aggregator_quoting: bool
    netpol_overlay: str


# The six canonical arms. G0-FULL (== S1-HIER) is the shared full-architecture reference every other
# arm is one property away from. G3 carries guardian_mode G0-FULL because it removes a MONITOR
# property, not a Guardian one, and guardian/app/config.py refuses GUARDIAN_MODE=G3-UNQUOTED.
CONDITION_FLAGS: Final[dict[str, ConditionFlags]] = {
    "G0-FULL": ConditionFlags("hierarchical", "G0-FULL", True, "default-deny"),
    "S2-FLAT": ConditionFlags("flat", "G0-FULL", True, "default-deny"),
    "S3-SINGLE": ConditionFlags("single", "G0-FULL", True, "default-deny"),
    "G1-LOGONLY": ConditionFlags("hierarchical", "G1-LOGONLY", True, "default-deny"),
    "G2-SHAREDCRED": ConditionFlags("hierarchical", "G2-SHAREDCRED", True, "opened"),
    "G3-UNQUOTED": ConditionFlags("hierarchical", "G0-FULL", False, "default-deny"),
}

# The arm allowed to differ from the shared arm in two columns, with its citation. Any OTHER arm
# acquiring a second difference is a defect the one-property-differs test must catch.
G2_EXCEPTION: Final = "G2-SHAREDCRED"


def flags_for(condition: str) -> ConditionFlags:
    """The flag tuple for one arm. Raises on an unknown or non-canonical arm token."""
    if condition not in CONDITION_FLAGS:
        raise KeyError(
            f"{condition!r} is not one of the six canonical arms {sorted(CANONICAL_ARMS)}; "
            "S1-HIER is an alias of G0-FULL and is not a separate arm"
        )
    return CONDITION_FLAGS[condition]
