r"""``S3-SINGLE`` -- one agent carrying the Supervision layer uncompressed. Structure arm C3.

WHAT THIS MODULE DECIDES
------------------------
One role runs in every phase, once. ``docs/07-glossary-and-ids.md`` types this arm as a single
agent, and with three role tiers removed there is nothing left for a wiring rule to arrange.

The interesting content of this arm is not here and is not meant to be. It is in
``agents/prompts/compositions/S3-SINGLE.yaml``, which gives the one role the **same block ids**
S1-HIER's four Supervisors carry -- ``role.supervision.common`` and the four phase blocks --
concatenated into one prompt rather than re-authored as a summary. Parity policy section 2 rule 5
is explicit that the single-agent arm's parity target is the Supervision layer's role descriptions
and procedure text "uncompressed into one prompt", and "the same block ids" is what makes that
checkable: ``make parity-check`` compares block digests across conditions, so a re-authored
paraphrase would fail the shared-block identity assertion rather than quietly become a second
independent variable.

WHY ONE AGENT DOES NOT MEAN ONE PHASE
---------------------------------------
The arm removes tiers, not the incident lifecycle. FR2.2's four phases and FR5.1's progression
through them hold for every topology; what S3-SINGLE removes is delegation entirely -- the same
agent plans and acts, in each phase in turn. Row T-05's four phase spans are therefore present here
as well, and on the same evidence.

WHY THE BEHAVIOUR IS ``coordination`` AND NOT A THIRD IMPLEMENTATION
----------------------------------------------------------------------
The manifest entry declares ``node: coordination``, the same behaviour S1-HIER's Orchestrator and
S2-FLAT's coordinator run. ADR-027's registries are indexed by behaviour, and a
"single-agent behaviour" written for this arm would be a third implementation of the same loop;
any accidental difference between the three would enter the results as a topology effect that no
gate could see, because ``make parity-check`` compares registries rather than control flow. What
makes this agent behave differently from the other two arms' single node is its prompt and its
tools, both of which its manifest decides.

WHAT SEPARATES THIS FILE FROM ``agents/graphs/flat.py``
---------------------------------------------------------
Almost nothing, and that is correct -- see the corresponding section in that module. The two arms
differ in their ``structural`` blocks: S2-FLAT carries the flat-coordinator framing
(``structural.s2.no-supervisors``, ``structural.s2.no-executors``), while this arm carries
``structural.s3.single-agent`` and ``structural.s3.uncompressed-supervision``. That divergence is
bounded by the ``structural`` parity class and by the cap
``docs/protocols/prompt-parity-policy.md`` section 3 owns, which is where a reader should look for
it. Duplicating an ordering rule in two short files is a smaller cost than a shared helper that
would have to be parameterised by arm -- and a parameter naming the arm is the one thing ADR-027
refuses outright.
"""

from typing import Final

from agents.graphs.plan import GraphPlan, plan_for
from agents.registry.loader import Composition, PromptRegistry, RegistryError, load_registry

__all__ = ("CONDITION", "build", "order")

# The condition this module composes. See agents/graphs/hier.py for why this is a constant.
CONDITION: Final = "S3-SINGLE"


def order(composition: Composition, phase: str) -> tuple[str, ...]:
    """Return the single role that runs in ``phase``.

    ``phase`` is accepted and unused, for the reason :func:`agents.graphs.flat.order` gives.

    Raises :class:`~agents.registry.loader.RegistryError` when the manifest declares anything other
    than exactly one role, because "single" is a claim about role count and a manifest that grew a
    second role would have stopped being this arm.
    """
    del phase
    if len(composition.roles) != 1:
        raise RegistryError(
            f"{composition.condition}: a single-agent topology declares exactly one role and the "
            f"manifest declares {len(composition.roles)} "
            f"({', '.join(role.role_id for role in composition.roles)})"
        )
    return (composition.roles[0].role_id,)


def build(registry: PromptRegistry | None = None) -> GraphPlan:
    """Build the plan for ``S3-SINGLE``, loading the registry when one is not supplied."""
    return plan_for(registry if registry is not None else load_registry(), CONDITION, order)
