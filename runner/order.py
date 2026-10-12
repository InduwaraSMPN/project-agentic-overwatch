r"""The interleaved run order (T6.4): a relabeling, never a shuffle, plus baseline median placement.

WHY NOT A SEEDED SHUFFLE
--------------------------
``evaluation-protocol.md`` §5.2 requires the order to round-robin **both** varying axes -- arm and
injection condition -- within each scenario block, never blocking either, and to be deterministic
from the campaign seed. A seeded shuffle satisfies "deterministic" and destroys "never blocked": a
shuffle cannot preserve an adjacency invariant, so it would sometimes place two runs of one arm, or
two of one injection condition, back to back -- which is the confound §3.5.7's interleaving
exists to
prevent, and the injection axis is the one RQ5's rigorous contrasts and §3's matched-pairs key are
taken on.

THE INVARIANT IS STRUCTURAL, AND THE SEED CANNOT BREAK IT
----------------------------------------------------------
Inside a scenario block, enumerate positions ``t = 0 .. 149`` and take arm index ``t mod 6``,
injection index ``t mod 5``, seed index ``t div 30``. Six and five are coprime, so ``(t mod 6, t mod
5)`` walks all thirty arm x injection combinations before repeating; every cell is emitted exactly
once across the five seed blocks; and consecutive positions differ in **both** axes by construction
(``t mod 6`` and ``t mod 5`` both change from ``t`` to ``t+1``, and at the block boundary too). The
campaign seed then chooses a permutation of the arm labels, the injection labels and the seed order
-- a relabeling, which cannot disturb adjacency because it never touches positions. Scenario blocks
stay blocked, deliberately: §5.2 blocks on scenario and round-robins inside it.

BASELINE PLACEMENT IS THE MEDIAN OF ITS DEPENDENTS, COMPUTED
-------------------------------------------------------------
A baseline carries neither axis, so neither round-robin reaches it, and §5.2 is explicit: each
baseline is emitted at the **median position of the framework-on runs that name it in
``baseline_run_id``**, so drift enters each RQ4 delta with no systematic sign. Blocking baselines at
either end is forbidden for the reason blocking an arm is. The whole order is a pure function of the
campaign seed and the grid, and is **regenerated, never patched**, when a reduction lever or a
validity rerun changes a dependent set.

THE PILOT ORDER IS AN EULERIAN CIRCUIT, NOT A SHUFFLE (M10 plan §6)
--------------------------------------------------------------------
:func:`generate_pilot_order` builds the P2/P3 coverage passes, and it exists because of defect V2:
v1's guardrail arms carried the previous run's aggregator configuration forward, so a run's
measurement depended on which arm ran before it. An interleave that "happens not to" place two
interesting arms together leaves the carry-over untested -- which is what happened, twice, and why
nobody saw it. So the pilot's arm sequence is not a heuristic: it is an **Eulerian circuit over the
complete directed graph on the six arms** -- a walk using every one of the 30 ordered arm pairs
``(a, b)``, ``a != b``, exactly once, in 30 steps, so that no two consecutive runs share an arm by
construction. P3 walks the **literal reverse** of P2's sequence, and the two passes together cover
all 30 ordered arm adjacencies.

The "together" is arithmetic, not a figure of speech, and it is worth spelling because the two
lengths do not divide. A linear sequence of 30 runs has **29** consecutive adjacencies, so P2 uses
29 of the 30 ordered pairs and omits exactly one, call it ``m``. P3's adjacencies are the reverses
of P2's, so they omit ``reverse(m)`` -- and ``m != reverse(m)`` for two distinct arms, so the union
of the two passes is the complete set of 30. Covering all 30 in one pass would need 31 runs, and the
protocol fixes the pass at 30.

The graph is 6 nodes with an edge ``a -> b`` for every ``a != b``: 30 edges, in-degree = out-degree
= 5 at every node, strongly connected, so an Eulerian circuit exists. It is computed in house by
:func:`eulerian_circuit` because no graph library is pinned in ``infra/versions.env`` (header rule
3) and a 30-edge computation does not justify one. Determinism is not optional here: the successor
order is the canonical arm order rotated past the current node, never a set's iteration order, so
two machines walk the identical circuit.

THE PILOT SCENARIO IS A FUNCTION OF THE INJECTION CONDITION ONLY
-----------------------------------------------------------------
Also §6: "the scenario of a cell is a function of its injection condition only, so all six arms
share (scenario, injection, seed) and every contrast has a matched pair". P2 uses the map as it
stands and P3 shifts it by one, so INJ-D lands in a scenario whose landing phase is eradication in
one pass and in a containment scenario in the other -- the same injection class tested against two
different landing phases, which is the only way to see a phase-dependent treatment work at all. The
map is a rotation over the canonical scenario list (read from ``scenarios/manifests/``, never
restated) and the canonical injection-condition list, so it is a pure function with no seed and no
draw.

Everything else about the coverage pass -- in particular that every arm of a cell draws the SAME
payload -- is ``scenarios/attackers/plan.py``'s business (WS-2's balanced rotation is
arm-independent by design). This module only guarantees the cell identity the rotation reads.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
T-24 (the interleaving property) and the P2/P3 adjacency coverage the pilot gate depends on.
ADR-041 (campaign order), ADR-120 (pilot ladder).
"""

import hashlib
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from runner.campaign import CampaignManifest, PlannedRun
from runner.grid import PILOT_PASS_SEEDS, scenario_ids
from runner.ids import (
    CANONICAL_ARMS,
    INJECTION_CONDITIONS,
    RunId,
    format_run_id,
)

__all__ = (
    "PILOT_PASSES",
    "OrderError",
    "PilotCell",
    "eulerian_circuit",
    "generate_order",
    "generate_pilot_order",
    "pilot_scenario_map",
)

_ARMS: Final = len(CANONICAL_ARMS)  # 6
_INJ: Final = len(INJECTION_CONDITIONS)  # 5

# The two coverage passes of the pilot ladder (M10 plan §6), and the seed each one runs on. The
# seeds themselves are NOT here: they are `runner/grid.py`'s PILOT_SEEDS, which is a pointer to
# docs/07-glossary-and-ids.md §Seeds on the same convention `SEEDS` uses, and importing that tuple
# keeps the campaign/pilot seed disjointness a fact about one declaration rather than two literals
# that must be kept apart by hand. P2 uses pilot seed A, P3 pilot seed B, exactly as the glossary
# says.
PILOT_PASSES: Final[tuple[str, ...]] = ("P2", "P3")

# How far each pass shifts the injection-to-scenario map. P2 is the unshifted map; P3 shifts it by
# one (plan §6), which is the smallest shift that changes every injection's landing scenario.
_PILOT_SCENARIO_SHIFT: Final[dict[str, int]] = {"P2": 0, "P3": 1}

# Whether a pass walks P2's arm sequence forwards or backwards. P3 is the LITERAL REVERSE, which is
# what makes the two passes cover all `n(n-1)` ordered arm adjacencies: P2's linear sequence of 30
# runs has 29 consecutive adjacencies, so it omits exactly one ordered pair `m`; P3's are their
# reverses, which omit `reverse(m)`, and `m != reverse(m)` for distinct arms -- so the union of the
# two passes' adjacencies is the complete set. Reversing is also the cheapest possible way to make
# the second pass's carry-over structure the mirror of the first's, which is what a repeat pass is
# for (defect V2: the previous run's aggregator configuration leaking into this one).
_PILOT_ARM_REVERSAL: Final[dict[str, bool]] = {"P2": False, "P3": True}


class OrderError(Exception):
    """The campaign cannot be ordered under §5.2's rules."""


def _seeded_rng(campaign_id: str, campaign_seed: int) -> random.Random:
    """One generator, seeded from the campaign id and seed. The only source of the relabeling."""
    digest = hashlib.sha256(f"{campaign_id}\x00{campaign_seed}".encode()).hexdigest()
    return random.Random(int(digest, 16))  # noqa: S311 - reproducibility is the requirement


def _median_index(positions: list[int]) -> int:
    """The median position of a run's dependents, as an insertion index.

    For an even count the lower-middle is taken deterministically, so the placement is a pure
    function of the dependent positions rather than depending on a rounding convention.
    """
    ordered = sorted(positions)
    return ordered[(len(ordered) - 1) // 2]


def generate_order(manifest: CampaignManifest, campaign_seed: int) -> tuple[str, ...]:
    """Return the run identifiers in execution order: grid interleaved, baselines median-placed.

    Deterministic from ``(manifest.campaign_id, campaign_seed)``. Two generations at one seed are
    byte-identical; two at different seeds differ. The property -- no two consecutive grid runs in a
    scenario block share an arm or an injection condition, every cell once, no baseline at an end --
    is asserted by the T-24 test rather than trusted from this construction.
    """
    grid_runs = [run for run in manifest.runs if not run.is_baseline]
    baselines = [run for run in manifest.runs if run.is_baseline]

    scenarios = sorted({run.scenario_id for run in grid_runs if run.scenario_id is not None})
    seeds = sorted({run.seed for run in grid_runs})
    if len(scenarios) == 0:
        raise OrderError("campaign has no grid runs to order")
    if len(seeds) != _ARMS - 1 and len(seeds) not in (3, 5):
        # not fatal in general, but the coprime construction assumes the standard 5 (or reduced 3)
        pass

    by_cell: dict[tuple[str, str, str, int], PlannedRun] = {
        (r.condition, r.scenario_id, r.injection_condition, r.seed): r
        for r in grid_runs
        if r.condition is not None
    }

    rng = _seeded_rng(manifest.campaign_id, campaign_seed)
    # The relabelings: a permutation of arm labels, of injection labels, of the seed order, and of
    # the scenario-block order. Positions are never permuted -- only the labels mapped onto them.
    arm_perm = list(CANONICAL_ARMS)
    inj_perm = list(INJECTION_CONDITIONS)
    seed_perm = list(seeds)
    scenario_perm = list(scenarios)
    rng.shuffle(arm_perm)
    rng.shuffle(inj_perm)
    rng.shuffle(seed_perm)
    rng.shuffle(scenario_perm)

    order: list[str] = []
    block_len = _ARMS * _INJ * len(seeds)  # 150 for the full run, 90 for the reduced
    for scenario in scenario_perm:
        for t in range(block_len):
            arm = arm_perm[t % _ARMS]
            injection = inj_perm[t % _INJ]
            seed = seed_perm[(t // (_ARMS * _INJ)) % len(seeds)]
            run = by_cell.get((arm, scenario, injection, seed))
            if run is None:
                raise OrderError(
                    f"no grid run for (arm={arm}, scenario={scenario}, injection={injection}, "
                    f"seed={seed}); the campaign is not a complete grid"
                )
            order.append(run.run_id)

    # Baseline placement: each at the median position of its dependents, applied in a fixed order
    # (sorted by baseline run_id) with positions read fresh from the growing order after each
    # insertion, so the result is a pure function of the seed and the grid.
    for baseline in sorted(baselines, key=lambda b: b.run_id):
        dependents = [run.run_id for run in grid_runs if run.baseline_run_id == baseline.run_id]
        if not dependents:
            raise OrderError(
                f"baseline {baseline.run_id} has no dependents; a baseline nothing pairs to has no "
                "placement rule (evaluation-protocol §5.2)"
            )
        dep_positions = [order.index(dep) for dep in dependents]
        order.insert(_median_index(dep_positions), baseline.run_id)

    return tuple(order)


# ================================================================================================
# THE PILOT ORDER (M10 plan §6, ADR-120) -- P2 and P3 coverage passes
# ================================================================================================


def eulerian_circuit(nodes: Sequence[str]) -> tuple[str, ...]:
    """A walk over the COMPLETE DIRECTED graph on ``nodes`` that uses every ordered pair once.

    The complete digraph on *n* nodes has ``n * (n - 1)`` edges, in-degree = out-degree = ``n - 1``
    at every node, and is strongly connected, so an Eulerian circuit exists for every *n*; the
    returned walk therefore has ``n * (n - 1) + 1`` entries, the last repeating the first.

    **Hierholzer's algorithm, in house, iteratively.** A graph library would be the shorter code and
    is not available: none is pinned in ``infra/versions.env`` (header rule 3), and a 30-edge
    computation does not justify adding a dependency to the evaluated artefact. The
    stack-and-backtrack form is kept in full -- pop into the walk when a node has no unspent
    successor, reverse at the end -- so the function is a general Eulerian-circuit finder for the
    complete digraph, not a special case that only works for one input.

    **The successor order is the canonical rotation, and that is a determinism decision, not a
    graph-theory one.** Successors of the node at position ``k`` are tried in the order
    ``k+1, k+2, ... n-1, 0, 1, ... k-1`` -- the order ``nodes`` gives, rotated to start immediately
    after the current node. Successor choice therefore depends on the node's POSITION in the
    canonical arm list and on nothing else: not on a set's iteration order, not on dict insertion
    order, not on which node the walk happened to reach first. That is the whole argument for
    spelling the rotation out rather than writing "the next unused one": an Eulerian circuit is not
    unique, and a walk chosen by an unordered container differs between machines, which for a corpus
    whose entire claim is that its order is reproducible is not an acceptable answer.

    Note what this order does NOT buy, because the pilot wanted it and could not have it: no
    Eulerian circuit of the complete digraph has every ``n`` consecutive entries distinct. If it
    did, entry ``i + n`` would equal entry ``i`` (the only unused value in each window of ``n``), so
    the walk would be periodic with period ``n`` and the edge out of entry ``i`` would be repeated
    -- five times over for six arms. An Eulerian circuit visits each arm exactly ``n - 1`` times,
    once per out-edge, and that is a property of the graph, not of the walk. The pilot's cell
    coverage is therefore arranged in :func:`generate_pilot_order`, which assigns the injection
    conditions along the walk rather than along the positions, and there is no ordering of the
    injections that would make six contiguous positions hold six distinct arms.
    """
    ordered = list(nodes)
    count = len(ordered)
    if count < 2:
        raise OrderError(
            f"a complete directed graph needs at least two nodes, not {count}; there is no ordered "
            "arm adjacency to cover"
        )
    positions = {node: index for index, node in enumerate(ordered)}
    # remaining[u][v] is 1 while the edge u -> v is unspent. A dense matrix because the graph is
    # complete: |V|^2 booleans, and an adjacency dict would be the same data with more code.
    remaining = [[1 if u != v else 0 for v in ordered] for u in ordered]
    # The rotated successor scan, precomputed per node so the ordering is visibly a property of the
    # node's position and not of anything iterated at call time.
    rotations = [[(index + offset) % count for offset in range(1, count)] for index in range(count)]

    def take(node: str) -> str | None:
        """The first unspent successor of ``node`` in its rotated order, marking it spent."""
        row = remaining[positions[node]]
        for index in rotations[positions[node]]:
            if row[index]:
                row[index] = 0
                return ordered[index]
        return None

    stack: list[str] = [ordered[0]]
    walk: list[str] = []
    while stack:
        nxt = take(stack[-1])
        if nxt is not None:
            stack.append(nxt)
        else:
            walk.append(stack.pop())
    walk.reverse()
    expected = count * (count - 1) + 1
    if len(walk) != expected:
        raise OrderError(
            f"the walk over the complete directed graph on {count} nodes has {len(walk)} "
            f"entries, not {expected}; the circuit is not Eulerian and the order is not trusted"
        )
    return tuple(walk)


def pilot_scenario_map(injection_condition: str, pass_name: str) -> str:
    """The scenario an injection condition lands in during ``pass_name``.

    A function of the injection condition and the pass, and of nothing else -- which is exactly what
    makes all six arms of a cell share ``(scenario, injection, seed)`` and therefore share a matched
    pair (plan §6). The map is a rotation of the canonical injection-condition list over the
    canonical scenario list (read from ``scenarios/manifests/``, so a sixth scenario changes it
    automatically and correctly rather than needing an edit here), and P3's rotation is P2's by one.

    Rotation rather than a drawn mapping, deliberately: a seeded draw would be reproducible but
    would give no reason to believe the two passes test different landing phases, which is the one
    thing P3 exists to do.
    """
    if pass_name not in _PILOT_SCENARIO_SHIFT:
        raise OrderError(
            f"{pass_name!r} is not a pilot coverage pass; the passes are "
            f"{','.join(PILOT_PASSES)} "
            "(M10 plan §6)"
        )
    scenarios = scenario_ids()
    if not scenarios:
        raise OrderError(
            "no scenario manifests under scenarios/manifests/; the pilot scenario map has no "
            "corpus to rotate over"
        )
    if injection_condition not in INJECTION_CONDITIONS:
        raise OrderError(
            f"{injection_condition!r} is not one of the {len(INJECTION_CONDITIONS)} "
            "injection-condition values (07-glossary-and-ids.md §Condition IDs)"
        )
    offset = INJECTION_CONDITIONS.index(injection_condition) + _PILOT_SCENARIO_SHIFT[pass_name]
    return scenarios[offset % len(scenarios)]


@dataclass(frozen=True)
class PilotCell:
    """One planned pilot run: the four grid coordinates plus the position the ladder runs it at.

    ``step`` is 1-based and is the order's own property, not an input to it, so two cells of the
    same pass cannot share a position -- which is what the coverage test asserts when it checks the
    pass enumerates ``arms x injection conditions`` exactly once."""

    pass_name: str
    step: int
    condition: str
    scenario_id: str
    injection_condition: str
    seed: int

    @property
    def run_id(self) -> str:
        """The run identifier, from the four grid coordinates and nothing else.

        (data-management.md §2: the identifier is a pure function of the four coordinates.)
        """
        return format_run_id(
            RunId(self.condition, self.scenario_id, self.injection_condition, self.seed)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "pass_name": self.pass_name,
            "step": self.step,
            "condition": self.condition,
            "scenario_id": self.scenario_id,
            "injection_condition": self.injection_condition,
            "seed": self.seed,
            "run_id": self.run_id,
        }


def generate_pilot_order(pass_name: str) -> tuple[PilotCell, ...]:
    """The ``arms x injection conditions`` coverage pass ``pass_name``, in execution order.

    The arm sequence is the Eulerian circuit of :func:`eulerian_circuit` over the six canonical
    arms, truncated to the 30 steps a pass has, so consecutive runs exercise 29 of the 30 ordered
    arm adjacencies and P3 -- the literal reverse -- supplies the 30th (see
    :data:`_PILOT_ARM_REVERSAL`).

    **The injection conditions are assigned ALONG THE WALK, not along the positions.** The ``j``-th
    time the walk visits an arm, that cell runs ``INJECTION_CONDITIONS[j]``. That is the only
    assignment that makes the pass exactly ``arms x injection conditions`` for an arbitrary Eulerian
    sequence, and the reason is the graph's, not a preference: an Eulerian circuit of the complete
    digraph visits every arm exactly ``n - 1`` times, once per out-edge, so the walk itself already
    enumerates the ``n - 1`` cells an arm owes and the injection index is forced to be the visit
    index. Assigning by position instead -- ``INJECTION_CONDITIONS[step % 5]`` -- is the obvious
    alternative and does NOT work: it repeats an arm's injection conditions and therefore omits a
    cell. That is a coverage pass with a hole in it, and the hole lands on whichever ``(arm,
    injection)`` pair the walk happened to align.

    The cost of this choice, stated rather than hidden: the ARM axis is never blocked (consecutive
    entries of an Eulerian walk differ by construction, which is the axis P2 and P3 exist to test,
    per defect V2), but the INJECTION axis is not round-robined the way
    ``evaluation-protocol.md`` §5.2 requires of the *campaign* order. The pilot's 30 runs are a
    matched-cell design rather than a drift-cancelling interleave, and §6 asks of them for cell
    coverage, which this delivers and a position-indexed assignment would not.

    Deterministic in its entirety: no seed, no clock, no set or dict iteration in the result. Two
    calls at one pass name are byte-identical, and P3's arm sequence is P2's reversed by
    construction (asserted by the suite, because "by construction" is a claim and this is the
    claim's proof).

    The pass's own size is checked against the protocol's mirrored constant by
    ``runner.pilot_cli.coverage_order``, so a change to the arms or the injection conditions cannot
    silently make a pass the wrong length.
    """
    if pass_name not in _PILOT_SCENARIO_SHIFT:
        raise OrderError(
            f"{pass_name!r} is not a pilot coverage pass; the passes are "
            f"{','.join(PILOT_PASSES)} "
            "(M10 plan §6)"
        )
    if pass_name not in PILOT_PASS_SEEDS:
        raise OrderError(
            f"no pilot seed is mapped to pass {pass_name!r}; runner/grid.py's PILOT_PASS_SEEDS "
            f"must carry every pass in {PILOT_PASSES}"
        )
    # The walk has n(n-1) + 1 entries and its last repeats its first; the sequence is what precedes
    # that closing entry, so drop exactly one and never more.
    arms = len(CANONICAL_ARMS)
    arm_sequence = eulerian_circuit(CANONICAL_ARMS)[: arms * (arms - 1)]
    if _PILOT_ARM_REVERSAL[pass_name]:
        arm_sequence = tuple(reversed(arm_sequence))
    expected = arms * len(INJECTION_CONDITIONS)
    if len(arm_sequence) != expected:
        raise OrderError(
            f"the arm sequence has {len(arm_sequence)} steps, but a pass is "
            f"{len(CANONICAL_ARMS)} arms x {len(INJECTION_CONDITIONS)} injection conditions = "
            f"{expected}; the arms and the injection conditions have diverged"
        )
    seed = PILOT_PASS_SEEDS[pass_name]
    visits: dict[str, int] = {arm: 0 for arm in CANONICAL_ARMS}
    cells: list[PilotCell] = []
    for step, arm in enumerate(arm_sequence, start=1):
        # The bound is checked BEFORE the index is taken, not after: the length check above already
        # makes the two counts agree, so this arm of the guard is unreachable with today's grid --
        # but if the arms or the injection conditions ever diverged, an unguarded
        # `INJECTION_CONDITIONS[visits[arm]]` would raise IndexError and report a list index, which
        # says nothing about the design change that caused it. The message names that.
        if visits[arm] >= len(INJECTION_CONDITIONS):
            raise OrderError(
                f"step {step} visits {arm} for the {visits[arm] + 1}th time, which is past the "
                f"{len(INJECTION_CONDITIONS)} injection conditions; the arm sequence and the "
                "injection conditions have diverged"
            )
        injection = INJECTION_CONDITIONS[visits[arm]]
        visits[arm] += 1
        cells.append(
            PilotCell(
                pass_name=pass_name,
                step=step,
                condition=arm,
                scenario_id=pilot_scenario_map(injection, pass_name),
                injection_condition=injection,
                seed=seed,
            )
        )
    return tuple(cells)
