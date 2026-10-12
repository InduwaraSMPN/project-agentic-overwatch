r"""Regression: the S2/S3 delegation override lands last, and outranks every loop it overrides.

WHAT THIS TEST GUARDS AGAINST
------------------------------
``role.coordination.mission`` was authored for ``S1-HIER``'s Orchestrator, whose
``max_tool_calls`` is 0, and it says plainly "you do not act on the cluster ... you do not mint
capabilities, and you do not request changes. Delegation is the whole of your contribution."
``S2-FLAT`` and ``S3-SINGLE`` also carry that block -- it is ``shared``, per section 2 rule 2 of
``docs/protocols/prompt-parity-policy.md`` -- because the coordinator/single-agent role is *also*
the Orchestrator's role for the through-line and account-of-itself responsibilities that block
states. Left unqualified in those two conditions, the ban on minting capabilities and acting is
contradicted by ``structural.s2.no-executors``'s "you mint your own capability for each task, make
the call yourself" earlier in the same prompt. That contradiction was the measured defect: S2-FLAT
reached the Guardian in only 1/125 sealed cells and S3-SINGLE in 11/125.

**Placement is the fix, and it is the whole of the fix.** ADR-109's prompt change (adding the
override) was not enough: ``role.supervision.common`` -- the supervise-and-delegate loop, authored
for S1 where minting *is* the action -- was composed *after* the override, so the override never
reached the operational loop and the post-ADR-109 probe
``runs/CAMP-20260923-structure-probe`` reproduced the defect. M10's WS-1 row therefore moved the
block again, to the last prose position immediately before the tool documentation, and ADR-121
supersedes ADR-109 prospectively. Both are asserted below, at the manifest level *and* in the
composed bytes, because a model reads the prompt in order and manifest order is only a proxy for
that.

The other two cases here are the code half of the same defect, and neither is a prompt question:
after a granted self-mint the acting role's next context must carry the scope it was just granted
(``test_capability_scope_refreshed_after_self_mint`` -- F-AG-01, and the reason the v1 arms minted
23 times and reached the Guardian 0 times), and a redundant re-mint of a capability it already holds
must be refused by the graph rather than by the model choosing not to ask again (D11,
``test_duplicate_mint_refused_in_every_arm``).

WHY THE MARKERS BELOW ARE PARTLY DERIVED
-----------------------------------------
The override's own opening sentence is spelled as a literal, because a test that derived the string
it was checking for from the block it was checking would agree with any rewording whatsoever. The
three blocks the override must *follow* are the other way round: each contributes its own first
line, read from the registry, so this file cannot fall out of step with a block that was re-authored
under it -- which is precisely the failure mode that produced the v1 defect.
"""

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.graphs.nodes import PhaseResult, build_node  # noqa: E402
from agents.registry.composer import compose_condition  # noqa: E402
from agents.registry.loader import Budget, PromptRegistry  # noqa: E402
from agents.registry.model import ScriptedClient, ToolCall  # noqa: E402
from agents.tools.guardian_client import GuardianClient  # noqa: E402
from agents.tools.registry import (  # noqa: E402
    ACTION_TOOL,
    COMPLETE_PHASE_TOOL,
    ISSUE_TOKEN_TOOL,
    PHASE_OUTCOMES,
)
from harness import (  # noqa: E402
    InProcessGuardian,
    build_in_process_guardian,
    node_context,
)

# The exact substring role.coordination.mission uses to state the ban this override must outrank.
_DELEGATION_BAN = "Delegation is the whole of your contribution"

# The exact substring structural.s2s3.acts-itself opens with. Spelled here rather than read from the
# block, because the claim being made is about the override *existing and being recognisable* -- a
# test that computed its marker from the block would pass against a block emptied of content.
_OVERRIDE_MARKER = "The supervise-and-delegate loop does not apply here"

# The two other blocks the override outranks, and why each is named. The plan's WS-1 row requires
# the
# override to follow both; ``role.supervision.common`` is the one ADR-109's placement lost to, and
# ``role.execution.procedure`` is the one that tells the role to make one request at a time and read
# what comes back, which is the reading that turns "mint" into "mint and then stop".
_OVERRIDDEN_BLOCKS = (
    "role.coordination.mission",
    "role.coordination.procedure",
    "role.supervision.common",
    "role.execution.mission",
    "role.execution.procedure",
)

# The block whose position is asserted, and the prefix that marks a tool-documentation block. The
# prefix is the contract `agents/tools/registry.py` fixes: every entry's `doc_block` is
# `tool.<name>`.
_OVERRIDE_BLOCK = "structural.s2s3.acts-itself"
_TOOL_BLOCK_PREFIX = "tool."

_ROLE_BY_CONDITION = {
    "S2-FLAT": "coordinator",
    "S3-SINGLE": "agent",
}


def _opening_line(registry: PromptRegistry, block_id: str) -> str:
    """Return the first non-empty line of a block's body, read from the registry.

    Used for the blocks the override must follow. Each contributes its own opening sentence, so a
    block that was re-authored moves this file's expectations with it and the assertions below stay
    about *relative order* -- which is the property -- rather than about a string somebody happened
    to copy out of a block that has since changed.
    """
    body = registry.block(block_id).body
    for line in body.splitlines():
        if line.strip():
            opening = line.strip()
            break
    else:
        raise AssertionError(
            f"block {block_id!r} has no non-empty line, so it cannot be found in "
            "any composed prompt"
        )
    assert opening in body
    return opening


def test_acts_itself_block_is_in_the_manifest_immediately_before_the_tool_documentation(
    registry: PromptRegistry,
) -> None:
    """Both manifests place the override at the last prose position, adjacent to the tool docs.

    Rewritten by M10 from its ADR-109 form, which asserted adjacency to
    ``role.coordination.mission``. That assertion was true and the defect was still live, because
    being adjacent to the delegation ban says nothing about the supervision loop the model actually
    follows: the override was outranked by a block composed after it. The position that makes the
    override the last prose instruction a reading model meets -- immediately before the tool
    documentation, which is where the model looks next -- is the one asserted here.

    Checked at the manifest level as well as the composed-text level below: a manifest edit that
    moved the override two slots down, past a block whose body happens not to change the byte
    ordering the text-level assertion checks, would otherwise pass silently.
    """
    for condition, role_id in _ROLE_BY_CONDITION.items():
        block_ids = list(registry.compositions[condition].role(role_id).block_ids)
        index = block_ids.index(_OVERRIDE_BLOCK)

        assert block_ids[index + 1].startswith(_TOOL_BLOCK_PREFIX), (
            f"{condition}/{role_id}: {_OVERRIDE_BLOCK} must be immediately followed by the tool "
            f"documentation, found {block_ids[index + 1]!r} in its place. Every block after it"
            " must "
            "be a tool block, so the override is the last thing the model reads before it starts "
            "deciding which tool to call"
        )
        prose_after = [
            block for block in block_ids[index + 1 :] if not block.startswith(_TOOL_BLOCK_PREFIX)
        ]
        assert not prose_after, (
            f"{condition}/{role_id}: prose block(s) {prose_after} follow {_OVERRIDE_BLOCK}, so the "
            "override is not the last instruction before the tool documentation"
        )
        assert all(
            block_ids.index(block_id) < index
            for block_id in _OVERRIDDEN_BLOCKS
            if block_id in block_ids
        ), (
            f"{condition}/{role_id}: {_OVERRIDE_BLOCK} sits at index {index} and does not follow "
            f"every block it overrides. Positions:"
            "{[(b, block_ids.index(b)) for b in _OVERRIDDEN_BLOCKS]}"
        )


def test_acts_itself_override_follows_the_delegation_ban_in_composed_text(
    registry: PromptRegistry,
) -> None:
    """In the composed S2-FLAT and S3-SINGLE prompts, the override's text comes after all four.

    Extended by M10 from its ADR-109 form, which checked the delegation ban alone. The ban was
    necessary and not sufficient: ``role.supervision.common``'s supervise-and-delegate loop and
    ``role.execution.procedure``'s one-request-at-a-time rule are both composed *after*
    ``role.coordination.mission`` in these two manifests, so an override that merely trailed the ban
    trailed three other instructions as well -- and that is what the v1 corpus measured.

    A model reads the prompt in order, so what matters is not manifest order in the abstract but
    where each string actually lands in the bytes sent. This asserts that directly, by string index
    in the joined role text, for the ban (a literal) and for each of the four overridden blocks (its
    own opening line, read from the registry).
    """
    for condition, role_id in _ROLE_BY_CONDITION.items():
        composed = compose_condition(registry, condition)
        text = composed.roles[role_id].text

        override_index = text.find(_OVERRIDE_MARKER)
        assert override_index != -1, (
            f"{condition}/{role_id}: acts-itself override text not found in prompt"
        )

        preceding = (("the delegation ban", _DELEGATION_BAN),) + tuple(
            (block_id, _opening_line(registry, block_id)) for block_id in _OVERRIDDEN_BLOCKS
        )
        for label, marker in preceding:
            marker_index = text.find(marker)
            assert marker_index != -1, (
                f"{condition}/{role_id}: {label} text not found in prompt, so the override's "
                "position relative to it cannot be asserted"
            )
            assert override_index > marker_index, (
                f"{condition}/{role_id}: the acts-itself override (offset {override_index}) must"
                " come "
                f"after {label} (offset {marker_index}), so the model reads the override last. "
                f"Composed order was {[b for b in composed.roles[role_id].blocks]}"
            )

    # The override's content is the second half of ADR-121 and the reason the placement matters: it
    # has to say that the narrowest action is a mint *and then* an act, or a model that is told only
    # that it may act has no instruction to spend the capability it just asked for.
    body = registry.block(_OVERRIDE_BLOCK).body
    for fragment in ("mint, then guardian_action", "two calls in one turn"):
        assert fragment in body, (
            f"{_OVERRIDE_BLOCK} no longer states {fragment!r}: {body!r}. The v1 defect was not"
            " that "
            "the acting role was forbidden to act but that nothing told it to act on the mint it"
            " had "
            "just been granted"
        )


def test_s1_hier_orchestrator_keeps_the_unqualified_delegation_ban(
    registry: PromptRegistry,
) -> None:
    """S1-HIER must not gain the override: its Orchestrator really does not act.

    The fix is scoped to S2-FLAT and S3-SINGLE by design -- S1-HIER has real Supervisors and
    Executors to delegate to, so role.coordination.mission's ban is correct there unqualified.
    This guards against the override block leaking into S1-HIER's manifest by a copy-paste error.
    """
    block_ids = list(registry.compositions["S1-HIER"].role("orchestrator").block_ids)
    assert _OVERRIDE_BLOCK not in block_ids


# --------------------------------------------------------------------------------------------
# The code half: the acting role can act on what it just minted, and does not re-mint for free
# --------------------------------------------------------------------------------------------

# The scope one mint asks for, and the action that spends it. Both are shaped by the registry's own
# grammars rather than invented, so a future change to a tool schema does not make this file's
# fixture silently invalid: the node refuses a malformed call, and a case that passed for that
# reason would be testing nothing. `definitions_for` is the projection the model is offered and the
# node validates against, so reading the required keys out of it is reading the contract.
_PHASE = "containment"
_MINT_ARGUMENTS: dict[str, object] = {
    "executor_id": "coordinator-containment-01",
    "verbs": ["get", "list"],
    "resources": ["pods"],
    "namespaces": ["boutique"],
}
_ACTION_ARGUMENTS: dict[str, object] = {
    "verb": "get",
    "resource": "pods",
    "namespace": "boutique",
    "name": None,
    "params": {},
    "justification": "read the workload the evidence names",
}

# The graph-side refusal code D11 names, and the only string in this repository that carries it. A
# Guardian refusal arrives as an `error` too (issue_authority_exceeded and friends), so a reader of
# `results.json` tells the two apart by this value and not by the shape -- which is the point.
_DUPLICATE_MINT_ERROR = "duplicate_capability_held"

# A generous allocation for the guard cases, declared here rather than read from the manifest. The
# subject of these cases is the D11 guard, which is budget-independent; borrowing S1-HIER's
# containment Supervisor (3 turns, 2 tool calls) would make a three-call scenario fail on the
# budget and report it as a defect in the guard. The *roles* are still the shipped ones, which is
# the property "in every arm" is about.
_GUARD_BUDGET = Budget(max_turns=12, max_tool_calls=12)


def _mint_call(arguments: dict[str, object] | None = None) -> ToolCall:
    """One ``issue_capability_token`` call over the scope above, or a variant of it."""
    return ToolCall(
        name=ISSUE_TOKEN_TOOL.name,
        arguments=dict(_MINT_ARGUMENTS if arguments is None else arguments),
    )


def _minting_node(registry: PromptRegistry, condition: str):
    """Build the node the condition's *minting* role runs, read off the manifest.

    The role that holds ``issue_capability_token``: S1-HIER's phase Supervisor, and the single node
    in S2-FLAT and S3-SINGLE. That is the same reading the graph uses -- ``_conduct`` derives
    ``hands_off`` from whether the role *also* holds ``guardian_action`` -- so "in every arm" is
    covered without a table of role names that a manifest edit could invalidate.
    """
    composition = registry.compositions[condition]
    entry = next(role for role in composition.roles if ISSUE_TOKEN_TOOL.name in role.tools)
    return build_node(
        compose_condition(registry, condition).role(entry.role_id),
        budget=_GUARD_BUDGET,
        tools=entry.tools,
    )


def _frames(context_text: str) -> tuple[dict[str, object], ...]:
    """Every runtime task frame in one composed conversation, parsed, in order.

    Recognised by shape rather than position: the conversation is the injected inputs, then the
    rendered evidence, then the frame(s), and only the last is this file's subject.
    """
    frames: list[dict[str, object]] = []
    for line in context_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict) and "capability_scope" in decoded and "environment" in decoded:
            frames.append(decoded)
    return tuple(frames)


@pytest.mark.parametrize("condition", sorted(_ROLE_BY_CONDITION))
def test_capability_scope_refreshed_after_self_mint(
    guardian: InProcessGuardian, registry: PromptRegistry, condition: str
) -> None:
    """After a granted self-mint, the acting role's next context carries the scope it was granted.

    The code half of the V1 defect, and F-AG-01's subject. In v1 the acting role built its runtime
    task frame once with ``capability_scope: null`` and never rebuilt it, and the only thing
    appended
    after a granted mint was the bare string ``"issuance granted: <jti>"`` -- so the model was told
    it had a capability and never told what it covered. ``RUN-S2-FLAT-SCN-CVE-04-INJ-A-101`` is the
    shape of the result: 23 mints, 0 Guardian decisions, because a model that cannot see the scope
    it just asked for has nothing to act *with*.

    The assertion is on the second call's context rather than on a returned value, because the
    refresh exists only to change the bytes the next request carries. The scope compared against is
    the call's own arguments, which is the model-chosen claim the Guardian will check -- so a
    refresh
    that substituted a *different* scope would fail here too.

    Scoped to the two self-minting arms by construction, and the reason is worth stating: S1-HIER's
    Supervisor holds the issuance tool and not the action tool, so its mint is handed to a freshly
    built Executor whose frame is ``_run_delegated_task``'s, and the Supervisor's own frame keeps
    ``capability_scope: null`` because it is going to act with nothing. ``test_s1_hier_does_not_
    refresh_its_own_frame`` below holds that half.
    """
    role_id = _ROLE_BY_CONDITION[condition]
    composition = registry.compositions[condition]
    entry = composition.role(role_id)
    node = build_node(
        compose_condition(registry, condition).role(role_id),
        budget=composition.budgets[_PHASE][role_id],
        tools=entry.tools,
    )
    model = ScriptedClient(
        [
            _mint_call(),
            ToolCall(name=ACTION_TOOL.name, arguments=dict(_ACTION_ARGUMENTS)),
            ToolCall(
                name=COMPLETE_PHASE_TOOL.name,
                arguments={"outcome": PHASE_OUTCOMES[0], "summary": "acted on the granted scope"},
            ),
        ]
    )

    result = node(node_context(guardian, model=model, supervisor_id="", executor_id=""), _PHASE)

    assert len(model.calls) >= 2, (
        f"{condition}: the acting role made {len(model.calls)} model call(s) against a script of "
        f"three. It is asking for a capability and never spending it, which is the v1 shape: "
        f"{[call.context[-200:] for call in model.calls]}"
    )

    first_frames = _frames(model.calls[0].context)
    assert first_frames and first_frames[-1]["capability_scope"] is None, (
        f"{condition}: the opening frame already carries a scope ({first_frames[-1]!r}). The frame "
        "under test is the one rebuilt after the mint; if the opening frame were populated, this "
        "case could not tell a refresh from a frame that was never null"
    )

    refreshed = _frames(model.calls[1].context)
    assert refreshed, (
        f"{condition}: the second context carries no runtime task frame, so there is nothing to "
        f"assert a scope on:\n{model.calls[1].context}"
    )
    scope = refreshed[-1]["capability_scope"]
    assert scope is not None, (
        f"{condition}: after a granted self-mint the next model context still reports "
        f"capability_scope: null. F-AG-01 requires a non-null scope after every granted self-mint, "
        "and the v1 evidence is 23 mints and 0 Guardian decisions in one run -- a model that"
        " cannot "
        "see what it was just granted has nothing to act with"
    )
    assert scope == dict(_MINT_ARGUMENTS), (
        f"{condition}: the refreshed frame carries scope {scope!r} against the"
        "{dict(_MINT_ARGUMENTS)!r} "
        "the mint call asked for. A refresh that substituted a different claim would tell the"
        " model "
        "it holds something the Guardian was never asked to mint"
    )

    # And the refresh is what made the third call possible: the action tool is only offered after a
    # granted mint, so an arm that never refreshed would have answered the second call with a tool
    # it
    # was not offered.
    assert result.outcome == PHASE_OUTCOMES[0], f"{result.outcome!r}: {result.summary!r}"
    actions = [action for action in result.actions if action.get("kind") == "action"]
    assert len(actions) == 1, (
        f"{condition}: the phase recorded {len(actions)} submitted action(s): {result.actions!r}. "
        "The mint was granted, so exactly one mediated action was reachable"
    )
    assert actions[0].get("decided") is True, (
        f"{condition}: the one action reached no decision: {actions[0]!r}"
    )


def test_s1_hier_does_not_refresh_its_own_frame(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """S1-HIER's Supervisor mints for somebody else, so its own frame stays empty. On purpose.

    The scope refresh is scoped to a *self*-mint, and this is the case that says so. A Supervisor
    holding the issuance tool and not the action tool hands its capability to a freshly built
    Executor, so claiming that scope in its own frame would be a claim it is going to act with
    nothing -- and, since ``available.add(ACTION_TOOL.name)`` is likewise gated on ``not
    hands_off``,
    nothing would follow from it. The frame stays null and the Executor frame
    (``_run_delegated_task``)
    carries the granted scope, which ``test_golden_path.py`` walks end to end.
    """
    composition = registry.compositions["S1-HIER"]
    entry = composition.role("supervisor-containment")
    node = build_node(
        compose_condition(registry, "S1-HIER").role(entry.role_id),
        budget=_GUARD_BUDGET,
        tools=entry.tools,
    )
    model = ScriptedClient(
        [
            _mint_call(),
            ToolCall(
                name=COMPLETE_PHASE_TOOL.name,
                arguments={"outcome": PHASE_OUTCOMES[0], "summary": "minted and handed off"},
            ),
        ]
    )

    node(node_context(guardian, model=model, supervisor_id="", executor_id=""), _PHASE)

    assert len(model.calls) >= 2, (
        f"S1-HIER: the Supervisor made {len(model.calls)} call(s) against a script of two, so the "
        "second context was never composed and this case asserts nothing"
    )
    assert _frames(model.calls[0].context)[-1]["capability_scope"] is None
    assert all(frame["capability_scope"] is None for frame in _frames(model.calls[1].context)), (
        "S1-HIER's Supervisor refreshed its own capability_scope. That role hands the capability"
        " to a "
        "freshly built Executor and holds no action tool, so a scope in its own frame would be a "
        "claim about a capability it is not going to spend -- and the v1 fix it would be claiming"
        " to "
        "complete is the self-mint case these two arms need"
    )


class _CountingClient(GuardianClient):
    """A :class:`~agents.tools.guardian_client.GuardianClient` that counts the mints it forwards.

    A subclass rather than a wrapper so the node sees the shipped client, and counting rather than
    recording the bodies because the assertion is "the Guardian was not asked a second time": a
    forwarded call that returned a refusal would look identical to a graph-side refusal unless the
    *call* is what is being counted.
    """

    def __init__(self, inner: GuardianClient) -> None:
        super().__init__(inner._transport, caller_auth=inner._caller_auth)
        self.mints: list[Mapping[str, Any]] = []

    def issue_capability_token(self, **request: Any) -> Any:
        self.mints.append(request)
        return super().issue_capability_token(**request)


@pytest.mark.parametrize("condition", sorted(_ROLE_BY_CONDITION) + ["S1-HIER"])
def test_duplicate_mint_refused_in_every_arm(
    guardian: InProcessGuardian, registry: PromptRegistry, condition: str
) -> None:
    """An identical, unspent capability is refused by the graph, in all three arms, with no call.

    D11, and the evidence it answers: the v1 flat and single arms minted the same scope over and
    over -- one run reached 23 mints and 0 Guardian decisions -- because nothing stopped a redundant
    re-mint, and a loop that never acts is a floor effect the ablation would have read as a
    topology result.

    The guard is a *graph* refusal rather than a prompt instruction, for the reason the plan gives
    and ADR-121 records: an instruction the model may decline is a measurement of the model, and
    what is wanted here is a property of the instrument. So the assertion is not that the model was
    told -- it is that the second identical mint never reached the Guardian, which is counted on a
    subclass of the shipped client rather than read out of a prompt.

    Three controls, all of which must hold or the guard would be a *too* aggressive rule:

    * a **different** scope in the same phase is a fresh mint and does reach the Guardian;
    * an identical scope is refused only while it is **unspent** -- once the capability has been
      spent, the same scope is a new task and must be mintable again, or an arm could perform only
      one mint-and-act pair per phase and the realizable-action budget (parity assertion 5) would be
      fiction;
    * the order of ``verbs``/``resources``/``namespaces`` is not part of a capability's identity:
      the Guardian mints the *product* of the three lists, so ``[get, list]`` and ``[list, get]``
      are one capability, and a guard that treated them as two would miss the duplicate it exists
      to catch.
    """
    node = _minting_node(registry, condition)

    scope_reordered = {
        **_MINT_ARGUMENTS,
        "verbs": list(reversed(_MINT_ARGUMENTS["verbs"])),  # type: ignore[arg-type]
        "resources": list(reversed(_MINT_ARGUMENTS["resources"])),  # type: ignore[arg-type]
    }
    wider = {**_MINT_ARGUMENTS, "resources": ["pods", "deployments"]}

    def drive(*answers: ToolCall) -> tuple[PhaseResult, list[Mapping[str, Any]]]:
        """Run one scripted phase on its own context; return the result and the forwarded mints.

        A fresh context per sub-case, because the mint records D11 keeps live on the context *for
        the run* -- sharing one would make each control inherit the previous sub-case's held
        capabilities and every case below would be asserting over state it did not create. That is
        the guard working as designed, and a fixture that did not respect it would be testing the
        order the cases happen to run in.
        """
        counting = _CountingClient(guardian.client)
        context = node_context(
            guardian, model=ScriptedClient(list(answers)), supervisor_id="", executor_id=""
        )
        object.__setattr__(context, "guardian", counting)
        return node(context, _PHASE), counting.mints

    close = ToolCall(
        name=COMPLETE_PHASE_TOOL.name,
        arguments={"outcome": PHASE_OUTCOMES[0], "summary": "closed"},
    )

    # (a) identical scope, unspent -> refused, no Guardian call.
    result, mints = drive(_mint_call(), _mint_call(), close)

    assert len(mints) == 1, (
        f"{condition}: the Guardian was asked for a capability {len(mints)} time(s) where the "
        "script asked once. D11 refuses an identical, unexpired, unused capability *before* any "
        "Guardian call, so a second request here means the guard did not fire"
    )
    refusals = [
        action
        for action in result.actions
        if action.get("kind") == "issue" and action.get("refused")
    ]
    assert [action["error"] for action in refusals] == [_DUPLICATE_MINT_ERROR], (
        f"{condition}: the duplicate mint was recorded as {refusals!r} rather than one structured "
        f"refusal carrying {_DUPLICATE_MINT_ERROR!r}. The refusal is what results.json and the"
        " span "
        "carry, and a shape a reader cannot distinguish from a Guardian refusal is a shape nobody "
        "will count"
    )
    assert refusals and refusals[0]["jti"] is None, (
        f"{condition}: the duplicate refusal carries a jti ({refusals!r}). No Guardian call was "
        "made, so there is no issuance to attribute and a jti here would be a fabrication"
    )

    # (b) a different scope is a fresh mint.
    _, mints = drive(_mint_call(), _mint_call(wider), close)
    assert len(mints) == 2, (
        f"{condition}: two mints of *different* scopes reached the Guardian {len(mints)} time(s). "
        "D11's guard is over an identical capability, and a guard that refused any second mint"
        " would "
        "cap every arm at one action per phase"
    )

    # (c) ordering is not part of a capability's identity.
    _, mints = drive(_mint_call(), _mint_call(scope_reordered), close)
    assert len(mints) == 1, (
        f"{condition}: re-minting the same scope with its lists reversed reached the Guardian "
        f"{len(mints)} time(s). guardian/token/ signs the product of the three lists, so the order "
        "carries no meaning and a guard that treated it as meaning would miss the duplicate it "
        "exists to catch"
    )

    # (d) a spent capability is no longer held, so the same scope is mintable again. This is the
    # control that keeps the guard from being "one mint per phase", which is what makes (a) a
    # duplicate check rather than a quota. It needs a role that holds the action tool as well, since
    # a capability can only be *spent* by one that can act with it -- which is S2-FLAT and
    # S3-SINGLE,
    # and is exactly the two arms the scope refresh is for. A separate Guardian is built for it
    # because the first three sub-cases have already spent this one's replay store.
    if condition not in _ROLE_BY_CONDITION:
        return

    spent_root = guardian.audit_log_path.parent / "spent-capability"
    fresh = build_in_process_guardian(spent_root)
    counting = _CountingClient(fresh.client)
    spending = ScriptedClient(
        [
            _mint_call(),
            ToolCall(name=ACTION_TOOL.name, arguments=dict(_ACTION_ARGUMENTS)),
            _mint_call(),
            ToolCall(
                name=COMPLETE_PHASE_TOOL.name,
                arguments={"outcome": PHASE_OUTCOMES[0], "summary": "closed"},
            ),
        ]
    )
    context = node_context(fresh, model=None, supervisor_id="", executor_id="")
    object.__setattr__(context, "guardian", counting)
    object.__setattr__(context, "model", spending)
    result = _minting_node(registry, condition)(context, _PHASE)

    assert len(counting.mints) == 2, (
        f"{condition}: mint, act, mint-the-same-scope reached the Guardian {len(counting.mints)} "
        "time(s). A capability is single-use, so once one has been spent the role holds nothing"
        " and "
        "the identical scope is a fresh task, not a duplicate -- without this a role could perform "
        "one mint-and-act pair per phase and parity assertion 5's realizable-action count would be"
        " a "
        "number no arm could reach"
    )
    assert all(
        action.get("refused") is not True
        for action in result.actions
        if action.get("kind") == "issue"
    ), (
        f"{condition}: a mint after the previous capability was spent was refused:"
        "{result.actions!r}"
    )
