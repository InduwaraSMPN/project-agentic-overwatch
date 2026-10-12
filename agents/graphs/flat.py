r"""``S2-FLAT`` -- one coordinator, no phase Supervisors, no Executors. Structure arm C2.

WHAT THIS MODULE DECIDES
------------------------
The same one thing :mod:`agents.graphs.hier` decides, and it decides it more briefly: in every
phase, the single role the manifest declares runs, once. ``docs/07-glossary-and-ids.md`` types this
arm "flat single coordinator; no phase-specific Supervisors, no subordinate Executors", and a
traversal of one step per phase is that sentence as a data structure.

Everything else comes from ``agents/prompts/compositions/S2-FLAT.yaml``: the coordinator carries
the four Supervision blocks and the two execution blocks that S1-HIER spreads across six roles,
holds all four tools from the one tool registry (the D1-A ``cluster_api_request`` tool included, as
the acting role in every arm does), and is allocated, per phase, the sum of what S1-HIER allocates
its roles in that phase. ``make parity-check`` asserts that sum rather than
trusting it, which is what section 3.5.4's "the same budget ... as the hierarchical
configuration's combined per-phase allocation" needs in order to be a claim about the artefact
rather than about the author's intention.

THE COORDINATOR RUNS THE **COORDINATION** BEHAVIOUR, NOT A FOURTH ONE
-----------------------------------------------------------------------
Its manifest entry declares ``node: coordination`` -- the same behaviour S1-HIER's Orchestrator
runs, instantiated from the same factory in :data:`agents.graphs.nodes.NODE_FACTORIES`. That is
ADR-027's whole point restated at the place it is easiest to get wrong: the registries are indexed
by *behaviour*, and a graph selects which behaviours exist and how they are wired. A "flat
coordinator" behaviour written specially for this arm would be a second implementation of
coordination, and any difference between the two -- including one nobody intended -- would land in
the results as a topology effect. There is one implementation, so there is no such difference to
land.

WHAT MAKES THIS ARM DIFFERENT FROM ``S3-SINGLE``, GIVEN THAT BOTH RUN ONE NODE
--------------------------------------------------------------------------------
Not this file. The two modules are near-identical because the difference is not in the wiring: it
is in the ``structural`` blocks each manifest names. S2-FLAT carries
``structural.s2.no-supervisors`` and ``structural.s2.no-executors`` -- it keeps the
flat-coordinator framing, and tells the model
that there is no tier beneath it to delegate to. S3-SINGLE carries
``structural.s3.uncompressed-supervision``, whose parity target is the Supervision layer
specifically: parity policy section 2 rule 5 requires that layer's role descriptions and procedure
text be present "uncompressed into one prompt", concatenated rather than re-authored.

That difference is exactly what the ``structural`` parity class exists to bound, and it is why the
structural-block cap in ``prompt-parity-policy.md`` section 3 is a real measured number rather than
a formality. Two files that look alike and two prompts that are demonstrably not alike is the
correct shape here, and a reader who expected the divergence to be visible in Python is looking one
layer too low.

WHY THE PHASES ARE STILL FOUR
-------------------------------
Deleting two role tiers does not delete the incident lifecycle. FR2.2 requires phase coverage and
FR5.1 requires the run to progress through the four phases in order; what S2-FLAT removes is the
*delegation* between tiers, not the phases themselves. Traceability row T-05 closes on four phase
spans present in order, and it closes for this arm on the same evidence as for the other two --
which is only possible because the phases are a property of the traversal rather than of the
topology.
"""

from typing import Final

from agents.graphs.plan import GraphPlan, plan_for
from agents.registry.loader import Composition, PromptRegistry, RegistryError, load_registry

__all__ = ("CONDITION", "build", "order")

# The condition this module composes. See agents/graphs/hier.py for why this is a constant.
CONDITION: Final = "S2-FLAT"


def order(composition: Composition, phase: str) -> tuple[str, ...]:
    """Return the single role that runs in ``phase``.

    ``phase`` is accepted and unused: this arm's answer does not depend on it, and a signature that
    said so by omitting the parameter could not satisfy
    :data:`~agents.graphs.plan.PhaseRoleOrder`. Keeping the shape uniform is what lets
    :func:`agents.graphs.plan.plan_for` be one function rather than three.

    Raises :class:`~agents.registry.loader.RegistryError` when the manifest declares anything other
    than exactly one role. "Flat" is a claim about role count, so a manifest that grew a second role
    would have stopped being this arm, and the failure belongs at build time where somebody is
    reading a diff -- not in a results table three milestones later.
    """
    del phase
    if len(composition.roles) != 1:
        raise RegistryError(
            f"{composition.condition}: a flat topology declares exactly one role and the manifest "
            f"declares {len(composition.roles)} "
            f"({', '.join(role.role_id for role in composition.roles)})"
        )
    return (composition.roles[0].role_id,)


def build(registry: PromptRegistry | None = None) -> GraphPlan:
    """Build the plan for ``S2-FLAT``, loading the registry when one is not supplied."""
    return plan_for(registry if registry is not None else load_registry(), CONDITION, order)
