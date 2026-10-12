r"""Composing a condition's prompts from the block registry -- the one renderer the gate also uses.

WHAT THIS MODULE IS
-------------------
``docs/protocols/prompt-parity-policy.md`` section 2 rule 1 says "code composes blocks by ID". This
is that code. Given a loaded :class:`~agents.registry.loader.PromptRegistry` and a condition, it
produces the exact instruction text each role receives, and nothing else.

**It is shared by the parity gate and the graph runtime, and that sharing is the point.** Section 3
requires the check to "render all composed prompts per role" and then tokenize them. A checker with
its own rendering path measures a prompt no run ever used: the two would agree on the day they were
written and diverge on the first day somebody changed a separator, and the gate would report green
over bytes the model never saw. So ``agents/graphs/`` calls :func:`compose_condition` to build what
it sends, ``agents/registry/parity.py`` calls the same function to build what it counts, and there
is no second implementation for the two to disagree about. That is conflict M4-C2's real
resolution, and it is why this module lives in the agent layer rather than under ``analysis/`` or
``scripts/``. ADR-027.

THE JOINING RULE, AND WHY IT IS STATED RATHER THAN LEFT TO A ``join``
---------------------------------------------------------------------
Block bodies are concatenated in the order the manifest lists them, separated by exactly one blank
line, with no other transformation. :func:`~agents.registry.loader._normalise_body` has already
folded line endings to LF and reduced each body to exactly one trailing newline, so the separator
is a single ``"\n"`` and the composed text is a pure function of ``(block ids, block bytes)``.

Three things follow, and each is load-bearing for a different check:

*The composition is byte-reproducible.* Two runs on two hosts compose the same bytes, so
``prompt_registry_sha256`` in a run manifest identifies what was actually sent. Rule 20's
determinism, applied to the prompt layer.

*Token counts are additive over blocks.* Every block ends in a newline and the separator is a
newline, so no pre-token piece can straddle a block boundary
(:mod:`agents.registry.tokenizer` explains why). A condition's total is therefore the sum of its
blocks' counts plus the separators, which is what lets a parity failure name the block that grew
rather than reporting one number that moved.

*Nothing is inserted that a block did not author.* No heading, no numbering, no "You are a…"
preamble, no separator text. Every byte a model reads is in ``agents/prompts/``, which is what
``scripts/prompt_purity_grep.sh`` and ``agents/tests/test_prompt_purity.py`` check for from the
other side.

WHAT "TOTAL INSTRUCTION TOKENS PER CONDITION" COUNTS, AND WHY IT IS PER BLOCK AND NOT PER NODE
-----------------------------------------------------------------------------------------------
Section 3 asserts that the total is within a tolerance of the cross-condition mean, and the unit
that total is measured in has to be decided before the number means anything. It is **the sum over
the distinct blocks a condition references**, each counted once, and not the sum over role
instantiations.

The alternative reading -- sum every composed role prompt -- makes the assertion unsatisfiable by
construction, which is the clearest possible sign that it is the wrong reading. ``S1-HIER``
instantiates six roles and ``S3-SINGLE`` instantiates one, so a per-instantiation total would put
them a factor of several apart no matter what the registry said, and no tolerance short of "any"
would ever pass. A check that can only fail is not a check.

The per-block reading is also the one section 3.5.4's own sentence asks for: prompt-budget parity
exists "so that an observed difference is not attributable merely to one configuration receiving
more guidance tokens than another". *Guidance* is the instruction content a condition is given.
Instantiating that content at more nodes is the **topology** -- which is the manipulated variable,
not a confound to be equalised away. Equalising it would mean deleting guidance from the
hierarchical arm until its node count stopped showing, which would change the thing under study in
order to measure it.

What is left to bound after that reading is the residual: the topology-necessitated connective
blocks, which differ per condition by construction. Those are exactly what ``parity_class:
structural`` tags and what section 3's per-block cap bounds, and the ±2% tolerance is what holds
their *aggregate* difference small. That is why the structural cap is a real number rather than a
formality: it is the only thing standing between "a sentence saying who you report to" and "a
second helping of guidance under a topology label".

:attr:`ComposedCondition.total_tokens` is therefore the distinct-block sum, and per-role counts are
kept beside it because a failure has to be attributable to a role as well as to a block.

WHAT IS COUNTED AND WHAT IS NOT
--------------------------------
Section 3 bounds "total instruction tokens per condition". Instructions are what this module
composes: role blocks, tool documentation blocks, safety framing, output format. **Evidence is not
an instruction and is not counted here.** An ``EvidenceEvent`` rendered by
:mod:`agents.registry.renderer` is environment-derived run-time data whose volume is bounded by
``evaluation-protocol.md`` section 4's caps and whose content differs by scenario, seed and
injection condition -- so folding it into a parity number would make that number a property of the
scenario rather than of the registry, and two conditions would "differ" because one of them met a
noisier incident.

That separation is also what keeps the ``G3-UNQUOTED`` arm clean. Quoting lengthens text; if
evidence counted towards an instruction budget, the quoted and unquoted arms would carry different
instruction budgets and the guardrail ablation would be confounded by an accounting choice.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
------------------------------------------
*It does not decide which blocks a role gets.* The manifest does. This module refuses to reorder,
deduplicate or supply a default block, because each of those would be a composition decision taken
in code rather than in the registry -- and the registry is the artefact Chapter 3 describes.

*It does not know which condition it is composing for, beyond looking the manifest up by name.*
There is no branch here on ``S1-HIER`` versus ``S2-FLAT``. ADR-027 rejects a condition parameter
reaching behaviour outright: the branch would be the confound.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from agents.registry.loader import Composition, PromptBlock, PromptRegistry, RegistryError
from agents.registry.tokenizer import count_tokens

__all__ = (
    "BLOCK_SEPARATOR",
    "ComposedCondition",
    "ComposedRole",
    "compose_condition",
    "compose_role",
)

# One blank line between blocks. Each body already ends in exactly one newline, so a single "\n"
# here produces exactly one empty line between two blocks and no trailing blank at the end.
BLOCK_SEPARATOR: Final = "\n"


@dataclass(frozen=True)
class ComposedRole:
    """One role's instruction text, the blocks it came from, and its token count.

    ``blocks`` is kept beside ``text`` because a parity failure is a question about *which* block
    changed, and a report that could only say "S2-FLAT is 4.1% over" would send the reader back to
    re-derive what this object already knows.
    """

    role_id: str
    node: str
    phase: str | None
    text: str
    blocks: tuple[PromptBlock, ...]
    token_count: int

    def structural_blocks(self) -> tuple[PromptBlock, ...]:
        """The topology-necessitated blocks section 2 rule 2 tags and section 3 caps."""
        return tuple(block for block in self.blocks if block.is_structural)

    def shared_blocks(self) -> tuple[PromptBlock, ...]:
        """The blocks section 3 requires to be byte-identical across every condition."""
        return tuple(block for block in self.blocks if not block.is_structural)


@dataclass(frozen=True)
class ComposedCondition:
    """Every role of one condition, composed, with the totals the parity check compares.

    ``total_tokens`` is the **distinct-block** sum the module docstring argues for: every block this
    condition's manifest references, counted once, whatever number of roles instantiate it. A block
    held by four Supervisors is one piece of guidance given four times over, not four pieces.

    ``blocks`` carries those distinct blocks, keyed by id, so that a failure message can name the
    block that grew rather than the condition whose number moved.
    """

    condition: str
    roles: Mapping[str, ComposedRole]
    blocks: Mapping[str, PromptBlock]
    total_tokens: int
    tool_names: tuple[str, ...]

    def instantiated_tokens(self) -> int:
        """The sum over role instantiations -- what is actually sent, per run, across all roles.

        Deliberately **not** what parity compares, for the reason the module docstring gives, and
        published anyway because it is the number a cost estimate needs and the number a reader
        will otherwise try to derive from the table and get wrong. The two differ by exactly the
        repetition topology causes.
        """
        return sum(role.token_count for role in self.roles.values())

    def role(self, role_id: str) -> ComposedRole:
        """Return the named composed role, or raise naming what this condition holds."""
        try:
            return self.roles[role_id]
        except KeyError:
            raise RegistryError(
                f"{self.condition}: no composed role {role_id!r}; this condition composes "
                f"{', '.join(sorted(self.roles))}"
            ) from None


def compose_role(registry: PromptRegistry, composition: Composition, role_id: str) -> ComposedRole:
    """Compose one role's instruction text from the blocks its manifest entry names.

    The order is the manifest's, exactly. Reordering here -- sorting by id, hoisting safety framing
    to the front, grouping shared before structural -- would each be defensible in isolation and
    would each move a composition decision out of the registry and into code, where Chapter 3
    cannot describe it and a reviewer reading the manifest would not see it.
    """
    role = composition.role(role_id)
    blocks = tuple(registry.block(block_id) for block_id in role.block_ids)
    text = BLOCK_SEPARATOR.join(block.body for block in blocks)
    return ComposedRole(
        role_id=role.role_id,
        node=role.node,
        phase=role.phase,
        text=text,
        blocks=blocks,
        token_count=count_tokens(text),
    )


def compose_condition(registry: PromptRegistry, condition: str) -> ComposedCondition:
    """Compose every role of ``condition``.

    Raises :class:`~agents.registry.loader.RegistryError` when the condition has no manifest. That
    is the fail-closed half of the gate's contract stated at the earliest point it can be: parity
    asserts an equality across conditions, so a missing condition means nothing was proved rather
    than nothing being wrong, and a checker that skipped it would make deleting a manifest the
    easiest way to pass.
    """
    try:
        composition = registry.compositions[condition]
    except KeyError:
        raise RegistryError(
            f"no composition manifest for condition {condition!r} under "
            f"{registry.root / 'compositions'}. The registry declares "
            f"{', '.join(sorted(registry.compositions)) or 'none'}"
        ) from None

    composed = {
        role.role_id: compose_role(registry, composition, role.role_id)
        for role in composition.roles
    }
    # Distinct by block id, in sorted order so that two runs build the mapping identically. Rule 20
    # forbids anything a run depends on resting on the order roles happened to be declared in, and
    # a gate verdict is such a thing.
    distinct = {
        block.block_id: block
        for block in sorted(
            {block.block_id: block for role in composed.values() for block in role.blocks}.values(),
            key=lambda block: block.block_id,
        )
    }
    return ComposedCondition(
        condition=condition,
        roles=composed,
        blocks=distinct,
        total_tokens=sum(count_tokens(block.body) for block in distinct.values()),
        tool_names=composition.tool_names(),
    )
