r"""The injection harness: a pure planner, a cluster-facing applier, and the content they draw from.

THE SPLIT, AND WHY IT IS TWO PROGRAMS RATHER THAN ONE WITH A FLAG
-------------------------------------------------------------------
:mod:`scenarios.attackers.plan` is pure. Given ``(scenario_id, injection_condition, seed)`` plus the
scenario's manifest and the content pools, it emits an **injection plan**: a JSONL stream of events
carrying logical offsets in milliseconds from ``t0``, in an explicit total order, with no clock, no
network and no cluster anywhere in its reach.

:mod:`scenarios.attackers.apply` takes a plan and executes it against a live cluster, writing
``injection.log.jsonl`` -- each plan event copied verbatim with its ``applied`` block filled in.

Three things follow, and they are why the extra program is worth it:

1. **Determinism is checkable at M5, with no cluster.** ``scripts/scenario_determinism.sh`` diffs
   *plans*. That is the whole of traceability row T-17's property -- same seed twice, identical
   injected sequence -- and it needs nothing M1 owes.
2. **The wall clock is structurally excluded rather than avoided by discipline.** A plan carries no
   absolute time because the planner has no ``t0`` to read. Contrast ADR-019, where the
   non-reproducible quantity had to be held out of the comparison; here there is nothing to hold
   out.
3. ``injection.log.jsonl`` stays a record of what happened rather than a pre-computed prediction,
   which is what ``docs/protocols/data-management.md`` section 1 calls it.

A single program with ``--dry-run`` was rejected: the dry run and the real run would share a code
path, so a non-determinism firing only on the live path would be invisible to the check. That is the
same reason ``scripts/monitor_determinism.sh`` is a separate gate from ``scripts/monitor_replay.sh``
rather than a flag on it. ADR-035.

THIS PACKAGE IS OUTSIDE THE GUARDIAN'S TRUST BOUNDARY, DELIBERATELY
--------------------------------------------------------------------
The applier holds a kubeconfig, and that does not breach ``.agents/rules/10-guardian-first.md``:
that rule binds "code under ``agents/``", and ``docs/02-architecture.md`` section 5 draws the
injection harness in its own subgraph, perturbing the environment so telemetry reaches the Monitor
-- never routed through the Guardian. Routing it through the Guardian would mean the Guardian
authorising the incident it exists to defend against. What that obliges instead is enforced by
``scripts/scenario_guard.sh``: no import edge between ``agents/`` and ``scenarios/`` in either
direction, no cluster reach from the planner, and the applier running from the developer or runner
kubeconfig rather than from anything copied out of ``guardian/``.
"""

from typing import Final

__all__ = (
    "INJECTION_CLASSES",
    "INJECTION_CONDITIONS",
    "MECHANISMS",
    "PHASES",
    "PLAN_SCHEMA_VERSION",
)

# The plan format's version, and an input to the seed derivation. Including it there means a format
# change is a visible plan change rather than a silent one: two plans written under different
# schema versions cannot accidentally compare equal.
PLAN_SCHEMA_VERSION: Final = "v1"

# Bound in source order at M0-T0.7 finding 6. The A-D lettering is the kit's, not the
# dissertation's, and the pending cross-walk to [Patel, 2026a]'s own labels must not be pre-empted
# by it -- see scenarios/groundtruth/README.md.
INJECTION_CLASSES: Final[tuple[str, ...]] = ("INJ-A", "INJ-B", "INJ-C", "INJ-D")

# The grid's fifth dimension. INJ-NONE first, because it is the coordinate the other four are read
# against rather than a fifth class.
INJECTION_CONDITIONS: Final[tuple[str, ...]] = ("INJ-NONE",) + INJECTION_CLASSES

MECHANISMS: Final[tuple[str, ...]] = ("chaosmesh", "cve", "attacker", "workload")

# Spelled as docs/protocols/evaluation-protocol.md section 3 spells them, which is also how
# agents/registry/__init__.py and guardian/app/models.py spell them. A second spelling anywhere is
# a phase label that joins to nothing.
PHASES: Final[tuple[str, ...]] = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)
