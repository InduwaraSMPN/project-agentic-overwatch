r"""The agent layer's registry: one block set, one tool set, three wirings, one token count.

WHAT THIS PACKAGE IS
--------------------
``docs/adr/ADR-002-agent-framework-langgraph.md`` fixes the shape -- one node registry, one tool
registry, one prompt registry, with ``agents/graphs/{hier,flat,single}.py`` as thin compositions --
and ``docs/protocols/prompt-parity-policy.md`` makes "the conditions differ only in wiring" a
machine-checked invariant rather than an intention. This package is the machinery both of those
documents assume: it loads the prompt registry, composes a condition's prompts from it, renders
environment-derived evidence into them, digests the registry for the run manifest, counts the
tokens the parity gate compares, and refuses when any of that cannot be done honestly.

WHY IT LIVES HERE AND NOT IN ``analysis/stats/``
------------------------------------------------
``prompt-parity-policy.md`` section 3 heads itself "spec for ``analysis/stats/parity_check.py``",
and that home is wrong in a way two other binding documents make concrete. ``data-management.md``
section 8 binds ``analysis/`` to read "only ``runs/`` raw files (never ``metrics.json`` caches,
never live services)" -- a parity check reads ``agents/`` and no bundle at all, so putting it there
would be the first breach of that section in the repository. ``04-repo-conventions.md`` section 1
separately requires every gate's *logic* to live in ``scripts/``, which is where
``scripts/parity_check.sh`` sits.

The deciding argument is neither of those, though, and it is worth stating because it is what
settles where the *composer* goes rather than merely where the checker does not go. **The check
must count exactly the bytes the graph sends.** A checker with its own rendering path measures a
prompt no run ever used, and would go green on a registry the graphs compose differently. So the
composer is agent-layer code shared by the gate and the runtime, it lives here, and
``scripts/parity_check.sh`` is the one-line gate script section 1 asks for. Section 3's path is
corrected to name this home. ADR-027.

``agents/registry/`` sits deliberately outside ``agents/prompts/``, ``agents/tools/`` and
``agents/tests/`` so that it can land in a commit *before* the one that arms three CI guards at
once -- ``hashFiles('agents/prompts/**')`` arms the parity step, ``hashFiles('agents/tests/**')``
arms a pytest step, and the first tracked file under either would otherwise fire a gate whose
implementation had not landed. That ordering is M3's lesson applied: acquisition and guards land
before the file that arms them.

STANDARD LIBRARY ONLY, AND THAT IS A GATE REQUIREMENT RATHER THAN A PREFERENCE
------------------------------------------------------------------------------
Nothing in this package imports a third-party module. Not PyYAML, not Pydantic, not a tokenizer
distribution. The reason is conflict M4-C1 in ``docs/plans/M4-implementation-plan.md``:
``.github/workflows/ci.yml``'s parity step runs inside the ``guardrail-grep`` job, which checks out
the repository and runs shell scripts and **installs nothing at all**. A parity checker with a
dependency would fail there for a dependency reason rather than a code reason -- precisely the
shape ADR-025 records for M3's two guards tripping together.

ADR-025's own resolution was "a gate script acquires what it needs", and that is the alternative
this package rejects: a ``pip install`` inside a grep job would put a package index on the critical
path of a check that is supposed to take a second, and would make the gate's result depend on
network reachability. Standard library only costs one small YAML-subset parser
(:mod:`agents.registry.loader`) and one small reference tokenizer
(:mod:`agents.registry.tokenizer`), both of which are strict about their grammar for the reason
``monitor/tests/test_limits_match_protocol.py`` gives about its own parser: a parser that shrugs at
a line it does not recognise could silently miss the very thing it exists to compare. ADR-028.

The two modules that *do* reach outside -- :mod:`agents.registry.model`, which resolves the LiteLLM
alias, and :mod:`agents.registry.tracing`, which emits spans -- import their backends lazily and
degrade to something honest when the backend is absent. Neither is imported by the parity path.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*Prompt text.* Every byte a model reads comes from ``agents/prompts/``. This package composes,
counts, digests and renders; it authors nothing. ``scripts/prompt_purity_grep.sh`` and
``agents/tests/test_prompt_purity.py`` are what make that a check rather than a habit.

*A condition parameter inside a node.* ADR-027 rejects a ``condition`` argument reaching node
behaviour outright: the branch would be the confound. A condition selects which composition
manifest is loaded, and nothing below that point knows which arm it is in.

*A Kubernetes client, an invocation of the Kubernetes command-line client, or a cluster connection.*
``.agents/rules/10-guardian-first.md``, enforced by ``scripts/grep_guard.sh`` over every tracked
file under ``agents/``, prose included.

*Any number a protocol owns.* The structural-block cap and the budget tolerances belong to
``prompt-parity-policy.md`` section 3; :mod:`agents.registry.limits` mirrors that block and
``agents/tests/test_limits_match_parity_policy.py`` parses it and fails on drift, which is
ADR-016's pattern applied a third time -- section 4 for M1's probe constants, section 4 for M2's
Monitor limits, section 3 here.
"""

from typing import Final

# The condition identifiers this package composes for, in the order docs/07-glossary-and-ids.md
# section "Condition IDs" lists them. A tuple rather than a set, because the parity table is
# printed in this order and a table whose row order moved between runs would be a table nobody
# could diff. G0-FULL is not a member: it is the guardrail study's name for the same arm S1-HIER
# names in the structure study, and the glossary is explicit that a campaign containing both is
# the shared arm issued twice.
STRUCTURE_CONDITIONS: Final[tuple[str, ...]] = ("S1-HIER", "S2-FLAT", "S3-SINGLE")

# The four incident-response phases, in the order FR2.2 and docs/02-architecture.md section 1 give
# them. The spelling is `guardian.app.models.Phase`'s, exactly -- these strings travel into an
# ActionRequest's `phase` field and into a capability token's `phase` claim, and a second spelling
# would be a denial under scope.phase-mismatch that nothing in the agent layer could explain. The
# two modules do not import each other (the agent layer ships as its own container and the coupling
# would run the wrong way), so agents/tests/ holds a test that they agree -- ADR-022's shape, one
# rule stated once, two homes, and a check that makes "copy" mean "copy that cannot drift".
PHASES: Final[tuple[str, ...]] = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)

# The four role behaviours ADR-027 indexes the node registry by. A graph selects which of these
# exist and how they are wired; it does not add a fifth, and no node function takes a condition
# parameter. S1-HIER instantiates coordination once, phase planning four times and bounded
# execution per task; S2-FLAT instantiates one node carrying all four phases' planning blocks;
# S3-SINGLE instantiates one node carrying the Supervision layer's blocks concatenated. That the
# three are compositions of one behaviour set rather than three node sets is what makes parity
# provable by construction instead of by inspection.
NODE_KINDS: Final[tuple[str, ...]] = (
    "coordination",
    "phase-planning",
    "bounded-execution",
    "consolidation",
)

__all__ = ("NODE_KINDS", "PHASES", "STRUCTURE_CONDITIONS")
