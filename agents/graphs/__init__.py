r"""The three topologies: thin compositions of one node registry, one tool registry, one block set.

WHAT THIS PACKAGE IS
--------------------
``docs/02-architecture.md`` section 4 assigns each structure arm a file here --
``agents/graphs/hier.py``, ``flat.py`` and ``single.py``, each "composing shared registries" -- and
``docs/adr/ADR-002-agent-framework-langgraph.md`` chose LangGraph as the runtime that drives them.
Nothing in this package authors behaviour: :mod:`agents.graphs.nodes` holds the four role
behaviours, :mod:`agents.tools.registry` holds the tools, ``agents/prompts/`` holds every byte a
model reads, and each module here says only **which behaviours exist and how they are wired**.

WHAT A GRAPH IS PERMITTED TO DIFFER IN
----------------------------------------
Exactly one thing: its wiring, as its composition manifest declares it. The three modules read the
same registry, instantiate factories from the same behaviour table, and offer tools from the same
tool registry. What ``agents/prompts/compositions/<condition>.yaml`` decides -- which roles exist,
which blocks each carries, which tools each holds, and what each is allocated per phase -- is what
makes the three different.

So there is **no condition parameter inside a node** and no branch on an arm anywhere below
:func:`build`. ADR-027 rejects both outright: the branch would be the confound, and it would be
invisible to ``make parity-check``, which compares registries rather than control flow. A reader
checking that claim should be able to do it by reading three short files, which is why these files
are short.

THE FOUR PHASES ARE THE GRAPH, IN EVERY TOPOLOGY
--------------------------------------------------
FR2.2 requires phase coverage -- detection-and-investigation, containment, eradication,
verified-recovery -- "each behind its Supervisor", and FR5.1 requires the run to *progress* through
them. Every topology therefore traverses all four in order; what differs is how many roles are
involved in each. ``S1-HIER`` runs a coordination node, the phase's own planning node, an
execution node and a consolidation node; ``S2-FLAT`` and ``S3-SINGLE`` run their single node.
Traceability row T-05 closes on "four §1.6 phase spans present in order", which is a property of
the traversal rather than of the topology, and that is why it is assertable across all three arms.

WHY LANGGRAPH IS IMPORTED AT MODULE SCOPE HERE AND NOWHERE ELSE
-----------------------------------------------------------------
``agents/registry/`` is standard-library only, because ``scripts/parity_check.sh`` runs in a CI job
that installs nothing (conflict M4-C1). This package is the boundary: a graph is a runtime object,
it is never built by the parity gate, and ADR-002 chose the runtime -- so the import is honest here
and would be a dependency leak one directory up. :mod:`agents.graphs.plan` is the part the gate and
the tests can reach without it.
"""

from typing import Final

__all__ = ("CONDITION_MODULES",)

# The mapping from a condition id to the module that composes it. Named here so that the runner
# (M6) resolves a condition without importing three modules and choosing between them, and so that
# the set of topologies is a list rather than a convention about file names.
CONDITION_MODULES: Final[dict[str, str]] = {
    "S1-HIER": "agents.graphs.hier",
    "S2-FLAT": "agents.graphs.flat",
    "S3-SINGLE": "agents.graphs.single",
}
