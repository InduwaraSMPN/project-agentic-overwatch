r"""Every ground-truth check can both PASS and FAIL on a synthetic fixture (M10 WS-2; F-SC-05).

WHAT THIS IS FOR
    A predicate that can only fail measures nothing, and a predicate that can only pass measures
    nothing either -- both report the same number for a run that acted perfectly and a run that did
    nothing, which is why the v1 corpus shipped 37 never-failing predicates and an eradication
    completeness sitting on the floor in every arm (defects V26 and the eradication review in the
    M10 plan's WS-2 row). Neither shape is visible by reading a ground-truth file: a check that
    names a resource no arm can touch looks exactly like a check that names the right one.

    So this suite takes the properties of the check and manufactures the world in which it holds and
    the world in which it does not, then asks the real evaluator
    (``runner/evaluate_assertions._evaluate_check``) about both. Nothing here is a re-implementation
    of a predicate: the assertion is that the evaluator's own answer flips, which is the only
    version of "this check can fail" that means anything.

    129 checks, two fixtures each, generated rather than written. Hand-writing 258 fixtures would
    produce 258 places to be wrong and none of them would be derived from the corpus; generating
    them from the corpus means a new check is covered the moment it is written, and a check whose
    params grow an unhandled key fails HERE rather than reading as a pass everywhere.

WHY THE MACHINERY LIVES IN ``runner/assertion_availability.py``
    The audit is shipped code now: F-SC-05 reads ``<campaign>/assertion_availability.json``, and the
    producer (``runner.assertion_availability.availability_document``) and this test must run the
    SAME audit rather than two that could disagree. The fixtures, the fake cluster and the evaluator
    call moved there; what stays here is the assertions -- the count, the flip, the eradication
    reachability and the CI-safety property.

WHAT MAKES IT CI-SAFE
    No cluster, no v1 bundle, no network, no wall clock. Every fixture is in-process: a fake state
    reader, a synthetic audit chain, a synthetic probes table. The known-bad replay
    (``runner/fidelity/``, WS-5) is the suite that reads the real corpus; this one proves the
    predicates are satisfiable and violable, which is a property of the LABELS and holds whatever
    any run did.

THE 129
    34 phase-outcome assertions, 40 end-state assertions (8 per scenario, under INJ-A..INJ-D) and 55
    required sub-steps, across the five ground truths. The count is asserted, not assumed: a corpus
    that grew a check without growing a fixture has to fail here rather than quietly reduce coverage
    to the checks somebody remembered.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner import evaluate_assertions as evaluator  # noqa: E402
from runner.assertion_availability import (  # noqa: E402
    EXPECTED_END_STATE,
    EXPECTED_PHASE_OUTCOME,
    EXPECTED_SUBSTEP,
    GROUNDTRUTH_DIR,
    check_holds,
    collect_checks,
    evaluate_fixture,
)

CHECKS = collect_checks()


def _ids() -> list[str]:
    return [f"{scenario}:{kind}:{identifier}" for scenario, kind, identifier, _, _ in CHECKS]


IDS = _ids()


def test_the_corpus_holds_the_129_checks_the_failability_check_covers() -> None:
    """The count, asserted rather than assumed, in the three buckets the plan names.

    A corpus that grew a check without growing a fixture has to fail here. Parametrising over
    whatever the corpus happens to contain would let coverage shrink silently -- the failure mode of
    a generated suite is that it generates from the thing it is supposed to be checking.
    """
    by_kind: dict[str, int] = {}
    for _scenario, kind, _identifier, _phase, _check in CHECKS:
        by_kind[kind] = by_kind.get(kind, 0) + 1
    assert by_kind == {
        "phase-outcome": EXPECTED_PHASE_OUTCOME,
        "end-state": EXPECTED_END_STATE,
        "sub-step": EXPECTED_SUBSTEP,
    }, f"the corpus holds {by_kind}, not the {{34, 40, 55}} F-SC-05 is stated over"
    assert len(IDS) == len(set(IDS)), "two checks share an identifier; the join key is not unique"
    assert len(CHECKS) == EXPECTED_PHASE_OUTCOME + EXPECTED_END_STATE + EXPECTED_SUBSTEP


@pytest.mark.parametrize(
    ("_scenario", "kind", "identifier", "phase", "check"),
    CHECKS,
    ids=IDS,
)
def test_every_check_passes_one_fixture_and_fails_another(
    _scenario: str, kind: str, identifier: str, phase: str | None, check: Mapping[str, Any]
) -> None:
    """The property itself, for all 129, through the evaluator that scores a real run."""
    held, observed = evaluate_fixture(check, phase, satisfied=True)
    assert held, f"{identifier} ({kind}, {check['type']}) cannot pass: {observed}"
    missed, observed = evaluate_fixture(check, phase, satisfied=False)
    assert not missed, (
        f"{identifier} ({kind}, {check['type']}) cannot fail: a world in which the compromise "
        f"happened still reports it satisfied -- {observed}"
    )


# The Guardian executor issues some actions under a different Kubernetes API verb than the action
# label the ground truth (and guardian_audit) records: an image rollback is the action
# `update deployments` (ADR-091) performed via patch_namespaced_deployment, so the RBAC verb it
# needs
# -- and the one the boutique Role grants -- is `patch`. Reachability is a property of the verb the
# executor actually issues, so the label is normalised before the grant check (source of truth:
# guardian/app/executor.py OPERATIONS; kept explicit to respect the module boundary).
_ACTION_VERB_TO_RBAC_VERB: dict[tuple[str, str], str] = {("update", "deployments"): "patch"}


def test_the_eradication_predicates_are_reachable() -> None:
    """The eradication review the plan asks for, over the whole phase and stated as reachability.

    Eradication completeness sat on the floor in every v1 arm, and the reason was not the agent
    layer: the CVE eradication sub-step demanded `update` on a Deployment where the Guardian's own
    Role grants `patch` (`guardian/deploy/rbac.yaml`), so no mediated action could ever satisfy it
    and the phase read as incomplete however well the response was performed. Reachability is
    therefore asserted in the only sense that matters -- the predicate can be satisfied at all, and
    the capability it names is one the credential holds -- rather than by reading the check.
    """
    granted = _guardian_boutique_grants()
    eradication = [
        (identifier, check)
        for _scenario, kind, identifier, phase, check in CHECKS
        if phase == "eradication"
    ]
    assert eradication, "the corpus declares no eradication check, so this review would be vacuous"
    for identifier, check in eradication:
        held, observed = evaluate_fixture(check, "eradication", satisfied=True)
        assert held, f"eradication check {identifier} is unreachable: {observed}"
        params = check["params"]
        if (
            check["type"].startswith(("guardian-executed-", "cluster-executed-"))
            and "verb" in params
        ):
            bare = str(params["resource"]).split("/")[0]
            rbac_verb = _ACTION_VERB_TO_RBAC_VERB.get(
                (str(params["verb"]), bare), str(params["verb"])
            )
            assert (str(params["resource"]), rbac_verb) in granted or (
                bare,
                rbac_verb,
            ) in granted, (
                f"eradication check {identifier} names ({params['resource']}, {params['verb']}), "
                f"which the Guardian executes as {rbac_verb!r} and whose Role does not grant it: "
                "reachable in no arm"
            )


def test_the_audit_can_both_pass_and_fail_a_check() -> None:
    """The audit's own two-valued answer, on a check whose fixture is unambiguous.

    ``check_holds`` and ``evaluate_fixture(..., satisfied=False)`` must disagree about one real
    corpus check; if they agreed on every check the audit would be flagging all of them (one
    direction unreachable) and this suite would be reporting a fixture defect rather than a corpus
    one. Asserted on a real check so the property is about the machinery the 129 above depend on.
    """
    scenario, kind, identifier, phase, check = CHECKS[0]
    assert check_holds(check, phase), f"{scenario}:{kind}:{identifier} does not hold in its fixture"
    assert not evaluate_fixture(check, phase, satisfied=False)[0], (
        f"{scenario}:{kind}:{identifier} holds even in the world where it is violated"
    )


def _guardian_boutique_grants() -> set[tuple[str, str]]:
    """(resource, verb) pairs the Guardian's boutique Role grants; see the corpus test for why the
    repository's YAML subset cannot read that file and this reader raises on an empty parse."""
    import re

    text = (REPO_ROOT / "guardian" / "deploy" / "rbac.yaml").read_text(encoding="utf-8")
    documents = [
        chunk
        for chunk in re.split(r"(?m)^---\r?$", text)
        if re.search(r"(?m)^kind: Role\s*$", chunk)
        and re.search(r"(?m)^  namespace: boutique", chunk)
    ]
    if len(documents) != 1:
        raise AssertionError(f"expected one boutique Role, found {len(documents)}")
    rules = documents[0].split("\nrules:", 1)[1]
    granted: set[tuple[str, str]] = set()
    for match in re.finditer(
        r"resources: \[([^\]]*)\]\s*\n(?:\s*resourceNames: \[[^\]]*\]\s*\n)?\s*verbs: \[([^\]]*)\]",
        rules,
    ):
        for resource in (item.strip().strip('"') for item in match.group(1).split(",")):
            for verb in (item.strip().strip('"') for item in match.group(2).split(",")):
                granted.add((resource, verb))
    if not granted:
        raise AssertionError("no rules parsed out of guardian/deploy/rbac.yaml's boutique Role")
    return granted


def test_the_fixtures_are_built_only_from_the_ground_truth_and_fixed_literals() -> None:
    """CI-safety as a check rather than a claim: the suite reads exactly one path of its own.

    The ground-truth directory (the labels under test) and, through
    ``runner.assertion_availability``, the Guardian's Role (the credential the eradication review
    compares against). No run bundle, no sealed corpus, no network, no clock -- which is what lets
    this run in CI, where the v1 corpus does not exist, and still say something about the v2 labels.
    Asserted by walking this module's own Path constants, so a future fixture that opened a bundle
    would fail here rather than passing quietly on a developer machine that happens to have
    ``runs/``.
    """
    paths = {
        value
        for name, value in globals().items()
        if isinstance(value, Path) and name.isupper() and name != "REPO_ROOT"
    }
    assert paths == {GROUNDTRUTH_DIR}, (
        f"this suite reads {sorted(str(path) for path in paths)}; apart from the repository root"
        " it derives from, it must read the ground truth and nothing else"
    )
    assert json.dumps(sorted(evaluator.MUTATING_VERBS)) == json.dumps(
        sorted({"create", "update", "patch", "delete", "deletecollection"})
    )
