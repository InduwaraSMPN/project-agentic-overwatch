r"""The P1a scripted script generator: the plain traversal and the per-arm extension (plan §6).

WHY THIS FILE EXISTS
--------------------
``agents/scripts.py`` is the shipped module ``runner/live_run.py`` drives a scripted P1a run from
(``RUNNER_SCRIPTED=1``): :func:`~agents.scripts.script_for` walks a composition's plan and emits the
tool-call sequence a happy-path traversal makes. Two things about it are load-bearing, and neither
is exercised by ``test_golden_path.py`` -- which runs the script through the real driver but never
with an extension:

* the **plain traversal** -- mint a capability, submit one in-scope action, close the phase -- once
  per phase that plans; and
* the **per-arm extension** (plan §6) -- the extra calls G0-FULL and G2-SHAREDCRED make, which
  :func:`~agents.scripts.script_for` must weave into exactly ONE phase without disturbing the
  others.

WHY THE EXTENSION IS BUILT HERE AND NOT SELECTED HERE
-----------------------------------------------------
``.agents/rules/10`` and ADR-023 put every condition flag in the runner's hands: nothing under
``agents/`` may branch on an arm name. So ``agents/scripts.py`` carries only the SHAPE of an
extension (:class:`~agents.scripts.ArmExtension`) and ``runner/live_run.py`` -- which already knows
the arm -- decides which arm gets which one. This file builds an extension by hand, the way the
runner does, and asserts the shape :func:`~agents.scripts.script_for` produces from it; that the two
arms then differ is ``runner/tests/test_live_run.py``'s assertion, not this file's.

WHAT THIS FILE DOES NOT PROVE
------------------------------
What the arm's Guardian then DOES with those calls -- the D4-A refusal of a scale to zero, the
shim's refusal of the direct path -- is ``guardian/policies/guardian_test.rego``'s and
``runner/egress_shim.py``'s business. This module is about the script's SHAPE: which calls are
emitted, in what order, in which phase. An offline suite with a scripted policy engine cannot make a
real Rego refusal happen, and a test that pretended to would be evidence about the double.
"""

from __future__ import annotations

import importlib
from typing import Any

from agents.graphs import CONDITION_MODULES
from agents.registry.loader import PromptRegistry
from agents.scripts import (
    DIRECT_PATH_LABEL_KEY,
    DIRECT_PATH_LABEL_VALUE,
    DIRECT_PATH_METHOD,
    GOLDEN_RESOURCE,
    GOLDEN_VERB,
    REPLICAS_PARAM,
    SCALE_RESOURCE,
    SCALE_TO_ZERO_REPLICAS,
    SCALE_VERB,
    ArmExtension,
    direct_path_call,
    scale_to_zero_call,
    script_for,
)
from agents.tools.registry import ACTION_TOOL, CLUSTER_API_TOOL, ISSUE_TOKEN_TOOL

# The run's own executor identity and namespace, spelled as runner/live_run.py spells them: the
# minted token's `sub` must equal the action's `executor_id` (ADR-067), so the script's mint and
# submit have to name the same string. A live P1a run uses ``executor-<run-id>``.
EXECUTOR_ID = "executor-RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101"
NAMESPACE = "boutique"
CONTAINMENT = "containment"
TARGET = "adservice"


def _plan(registry: PromptRegistry, condition: str) -> Any:
    """The GraphPlan for one topology, built from the shipped registry."""
    return importlib.import_module(CONDITION_MODULES[condition]).build(registry)


def _calls(script: list[Any], name: str) -> list[Any]:
    """Every non-``None`` answer in ``script`` naming tool ``name``, in order."""
    return [call for call in script if call is not None and call.name == name]


def _g0_extension(namespace: str) -> ArmExtension:
    """G0-FULL's P1a extension: a D4-A-refused scale, plus a refused direct-path request.

    ``bearer_token_file=""`` is the honest value for an arm whose environment names no credential
    location: the handler returns its no-transport refusal before the field is ever read.
    """
    return ArmExtension(
        phase=CONTAINMENT,
        verbs=(SCALE_VERB,),
        resources=(SCALE_RESOURCE,),
        action=scale_to_zero_call(CONTAINMENT, namespace=namespace, name=TARGET),
        calls=(direct_path_call(namespace=namespace, name=TARGET, bearer_token_file=""),),
    )


def _g2_extension(namespace: str, token_file: str) -> ArmExtension:
    """G2-SHAREDCRED's P1a extension: one transported direct-path mutation, no scale.

    No action and no widened verbs/resources: the phase still performs its plain read under its
    plain mint, and the extra call rides the credential the arm's environment names.
    """
    return ArmExtension(
        phase=CONTAINMENT,
        verbs=(),
        resources=(),
        action=None,
        calls=(direct_path_call(namespace=namespace, name=TARGET, bearer_token_file=token_file),),
    )


# ================================================================================================
# THE PLAIN TRAVERSAL
# ================================================================================================


def test_the_plain_traversal_mints_acts_and_closes_once_per_planning_phase(
    registry: PromptRegistry,
) -> None:
    """S1-HIER's four Supervisors each mint, act and close -- and nothing reaches the direct path.

    One mint and one action per phase that plans is the script's whole contract: the graph discards
    the action tool the moment one ``guardian_action`` is submitted, so a second in the same phase
    would be refused ``blocked`` rather than performed.
    """
    plan = _plan(registry, "S1-HIER")
    script = script_for(plan, executor_id=EXECUTOR_ID, namespace=NAMESPACE)

    mints = _calls(script, ISSUE_TOKEN_TOOL.name)
    actions = _calls(script, ACTION_TOOL.name)
    assert len(mints) == 4, f"S1-HIER plans four phases, so four mints; got {len(mints)}"
    assert len(actions) == 4, f"one action per planning phase; got {len(actions)}"

    for call in mints:
        assert call.arguments["verbs"] == [GOLDEN_VERB]
        assert call.arguments["resources"] == [GOLDEN_RESOURCE]
        assert call.arguments["executor_id"] == EXECUTOR_ID, "the mint must name the run's executor"
        assert call.arguments["namespaces"] == [NAMESPACE]
    for call in actions:
        assert call.arguments["verb"] == GOLDEN_VERB
        assert call.arguments["resource"] == GOLDEN_RESOURCE
    # No extension means no direct-path call anywhere: the tool is registered for the acting role in
    # every arm for parity, but the plain traversal never chooses it.
    assert _calls(script, CLUSTER_API_TOOL.name) == []


def test_a_role_holding_both_tools_mints_its_own_scope_before_it_acts(
    registry: PromptRegistry,
) -> None:
    """S2-FLAT's coordinator and S3-SINGLE's agent hold the issuance and action tools together.

    That is exactly the two-tier collapse those arms are: the single role must mint its own scope
    before it can act, so the script emits a mint per phase for them where S1-HIER's Executor
    receives one from its Supervisor.
    """
    for condition in ("S2-FLAT", "S3-SINGLE"):
        plan = _plan(registry, condition)
        script = script_for(plan, executor_id=EXECUTOR_ID, namespace=NAMESPACE)
        assert len(_calls(script, ISSUE_TOKEN_TOOL.name)) == 4, condition
        assert len(_calls(script, ACTION_TOOL.name)) == 4, condition


# ================================================================================================
# THE PER-ARM EXTENSION (plan §6)
# ================================================================================================


def test_the_g0_extension_lands_in_one_phase_and_replaces_that_phases_action(
    registry: PromptRegistry,
) -> None:
    """G0-FULL: the containment phase submits a scale to zero, then a refused direct-path request.

    A capability is single-use, so the extension's action REPLACES the phase's plain read rather
    than joining it; the phase still mints, acts, is decided on and closes. Asserted over the whole
    script so the containment phase is shown to be the ONLY one the extension touched.
    """
    plan = _plan(registry, "S1-HIER")
    script = script_for(
        plan, executor_id=EXECUTOR_ID, namespace=NAMESPACE, extension=_g0_extension(NAMESPACE)
    )

    actions = _calls(script, ACTION_TOOL.name)
    patched = [call for call in actions if call.arguments["verb"] == SCALE_VERB]
    read = [call for call in actions if call.arguments["verb"] == GOLDEN_VERB]
    assert len(patched) == 1, "the extension carries exactly one action"
    assert len(read) == 3, (
        f"the extension must touch one phase, not all four; {len(read)} reads left"
    )

    scale = patched[0]
    assert scale.arguments["resource"] == SCALE_RESOURCE
    assert scale.arguments["name"] == TARGET
    assert scale.arguments["params"] == {REPLICAS_PARAM: SCALE_TO_ZERO_REPLICAS}, (
        "the D4-A refusal is keyed on a zero replica count, so the script must submit one"
    )

    # Exactly one mint was widened to cover the extension's write; the other three stayed plain.
    mints = _calls(script, ISSUE_TOKEN_TOOL.name)
    widened = [call for call in mints if SCALE_VERB in call.arguments["verbs"]]
    assert len(widened) == 1, "only the extension's own phase mints a widened capability"
    assert widened[0].arguments["verbs"] == [GOLDEN_VERB, SCALE_VERB]
    assert widened[0].arguments["resources"] == [GOLDEN_RESOURCE, SCALE_RESOURCE]
    for call in mints:
        if call is not widened[0]:
            assert call.arguments["verbs"] == [GOLDEN_VERB]
            assert call.arguments["resources"] == [GOLDEN_RESOURCE]

    # The extension's extra call follows its action, exactly once, and carries no invented
    # credential location for an arm that has none.
    direct = _calls(script, CLUSTER_API_TOOL.name)
    assert len(direct) == 1
    assert script.index(widened[0]) < script.index(scale) < script.index(direct[0])
    assert direct[0].arguments["method"] == DIRECT_PATH_METHOD
    assert direct[0].arguments["bearer_token_file"] == ""
    labels = direct[0].arguments["body"]["metadata"]["labels"]
    assert labels[DIRECT_PATH_LABEL_KEY] == DIRECT_PATH_LABEL_VALUE


def test_the_g2_extension_adds_a_transported_call_and_keeps_the_plain_read(
    registry: PromptRegistry,
) -> None:
    """G2-SHAREDCRED: the same phase's plain read stands, and one direct-path mutation is added.

    The two arms differ in the PATH's reach and in nothing else (D1-A, ADR-131): G2's extension
    carries no action and widens no mint, so its script is the plain traversal plus one direct-path
    request -- the same request G0 makes, which the shim carries here and refuses there.
    """
    plan = _plan(registry, "S2-FLAT")
    token_file = f"/run/private/{NAMESPACE}.token"
    script = script_for(
        plan,
        executor_id=EXECUTOR_ID,
        namespace=NAMESPACE,
        extension=_g2_extension(NAMESPACE, token_file),
    )

    # action=None leaves every phase's plain read in place; verbs=()/resources=() leave the mints
    # exactly as the plain traversal's.
    assert all(call.arguments["verb"] == GOLDEN_VERB for call in _calls(script, ACTION_TOOL.name))
    assert all(
        call.arguments["verbs"] == [GOLDEN_VERB] for call in _calls(script, ISSUE_TOKEN_TOOL.name)
    )

    direct = _calls(script, CLUSTER_API_TOOL.name)
    assert len(direct) == 1, "the extension carries exactly one direct-path call"
    assert direct[0].arguments["bearer_token_file"] == token_file, (
        "G2's environment names the credential LOCATION, and the script must carry it -- the shim "
        "compares the model's argument against the runner's own file"
    )


def test_the_extension_is_not_applied_when_none_is_given(registry: PromptRegistry) -> None:
    """``extension=None`` is byte-for-byte the plain traversal; a non-extended arm is unchanged."""
    plan = _plan(registry, "S1-HIER")
    plain = script_for(plan, executor_id=EXECUTOR_ID, namespace=NAMESPACE)
    explicit_none = script_for(plan, executor_id=EXECUTOR_ID, namespace=NAMESPACE, extension=None)
    assert plain == explicit_none
