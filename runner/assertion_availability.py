r"""The assertion-failability audit: every ground-truth check can both PASS and FAIL (F-SC-05).

WHAT THIS IS FOR
----------------
A predicate that can only fail measures nothing, and a predicate that can only pass measures nothing
either -- both report the same number for a run that acted perfectly and a run that did nothing,
which is why the v1 corpus shipped 37 never-failing predicates and an eradication completeness
sitting on the floor in every arm (defects V26 and the eradication review in the M10 plan's WS-2
row). Neither shape is visible by reading a ground-truth file: a check that names a resource no arm
can touch looks exactly like a check that names the right one.

So this module takes the properties of each check and manufactures the world in which it holds and
the world in which it does not, then asks the real evaluator
(``runner/evaluate_assertions._evaluate_check``) about both. Nothing here is a re-implementation
of a predicate: the assertion is that the evaluator's own answer flips, which is the only version
of "this check can fail" that means anything.

WHY IT IS SHIPPED CODE AND NOT ONLY A TEST
------------------------------------------
F-SC-05 reads ``<campaign>/assertion_availability.json``, and this module is its producer: it writes
``{"never_fails": [...], "always_fails": [...], "checks": N}`` through
:func:`availability_document`. The audit used to live only inside the pytest module
(``runner/tests/test_assertion_predicate_failability.py``); it moved here so the producer and the
test run the SAME audit rather than two that could disagree -- the test asserts the property, the
producer records it, and one implementation is what keeps them the same claim.

CI-SAFE BY CONSTRUCTION
-----------------------
No cluster, no v1 bundle, no network, no wall clock. Every fixture is in-process: a fake state
reader, a synthetic audit chain, a synthetic probes table. The only paths read are the ground-truth
directory (the labels under test) and the Guardian's Role (the credential the eradication review
compares against). The known-bad replay (``runner/fidelity/``, WS-5) is the suite that reads the
real corpus; this one proves the predicates are satisfiable and violable, which is a property of the
LABELS and holds whatever any run did.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final

from scenarios.schemas import yamlsubset

from runner import evaluate_assertions as evaluator

__all__ = (
    "EXPECTED_END_STATE",
    "EXPECTED_PHASE_OUTCOME",
    "EXPECTED_SUBSTEP",
    "GROUNDTRUTH_DIR",
    "availability_document",
    "check_holds",
    "check_is_violable",
    "collect_checks",
    "evaluate_fixture",
)

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
GROUNDTRUTH_DIR: Final = REPO_ROOT / "scenarios" / "groundtruth"

# The counts the M10 plan states for the failability check (F-SC-05): 34 phase-outcome, 40 end-state
# and 55 sub-step predicates across the five ground truths.
EXPECTED_PHASE_OUTCOME: Final = 34
EXPECTED_END_STATE: Final = 40
EXPECTED_SUBSTEP: Final = 55

# A resource no ground-truth check names and the Guardian's Role does not grant, used to build an
# action that matches nothing. Chosen so the non-matching fixture cannot accidentally satisfy a
# check by sharing its resource: `configmaps` appears in no check in the corpus.
UNMATCHED_RESOURCE: Final = "configmaps"

# A control-plane timestamp for the synthetic actions. Fixed, because the payload attribution's
# "after delivery" comparison reads it; nothing in this module depends on it being "now".
TS: Final = "2026-01-01T00:00:01Z"


# --------------------------------------------------------------------------- the corpus, collected


def collect_checks() -> list[tuple[str, str, str, str | None, dict]]:
    """Every check in the corpus as (scenario_id, kind, identifier, phase, check)."""
    found: list[tuple[str, str, str, str | None, dict]] = []
    for path in sorted(GROUNDTRUTH_DIR.glob("SCN-*.yaml")):
        document = yamlsubset.parse(path.read_text(encoding="utf-8"))
        scenario_id = str(document["scenario_id"])
        for assertion in document["assertions"]:
            found.append(
                (
                    scenario_id,
                    "phase-outcome",
                    str(assertion["assertion_id"]),
                    None,
                    assertion["check"],
                )
            )
        for phase, labels in document["phases"].items():
            for substep in labels["required_substeps"]:
                found.append(
                    (
                        scenario_id,
                        "sub-step",
                        f"{phase}/{substep['substep_id']}",
                        str(phase),
                        substep["check"],
                    )
                )
        for condition, labels in document["conditions"].items():
            for assertion in labels["end_state_assertions"]:
                found.append(
                    (
                        scenario_id,
                        "end-state",
                        f"{condition}/{assertion['assertion_id']}",
                        None,
                        assertion["check"],
                    )
                )
    return found


# --------------------------------------------------------------------------- the fixtures


class FakeCluster:
    """A state reader whose whole world is the two fields the checks read.

    ``workloads`` and ``resources`` are supplied by the fixture builders, so a fixture is a
    description of the cluster state a check needs and nothing else. An absent workload reads as
    zero ready replicas, which is the same thing the live reader reports for a Deployment that does
    not exist -- so a check that passes here passes for the reason it would pass there.
    """

    def __init__(
        self,
        *,
        workloads: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
        resources: Mapping[tuple[str | None, str], list[dict[str, Any]]] | None = None,
    ) -> None:
        self.workloads = dict(workloads or {})
        self.resources = {key: list(value) for key, value in (resources or {}).items()}

    def list_resource(self, namespace: str | None, resource: str) -> list[dict[str, Any]]:
        return self.resources.get((namespace, resource), [])

    def workload(self, namespace: str, workload: str) -> Mapping[str, Any] | None:
        return self.workloads.get((namespace, workload))


def _matching_action(params: Mapping[str, Any], *, seq: int = 1) -> dict[str, Any]:
    """A mediated action that matches ``params`` -- built from the params, not written per check.

    The verb follows the check: an explicit `verb`, or the read ceiling's `get` when the check names
    a specific object and `list` when it does not (a namespace-scoped list covers every object of
    that kind, so it satisfies a named one). The name follows `name`, else `name_prefix` plus a
    generated suffix, else the empty name a namespace-wide verb carries. Every fixed-shape param the
    matcher compares is copied straight through, and a scale-to-zero is rendered the way the
    Guardian records it: the replica count as the STRING "0".
    """
    action_params: dict[str, Any] = {}
    if params.get("scale_to_zero") is True:
        action_params["replicas"] = "0"
    elif "replicas" in params:
        action_params["replicas"] = str(params["replicas"])
    for key in (
        "selector_key",
        "selector_value",
        "label_key",
        "label_value",
        "subject_kind",
        "subject_name",
        "subject_namespace",
    ):
        if key in params:
            action_params[key] = params[key]
    if params.get("any_read_verb"):
        verb = "get" if ("name" in params or "name_prefix" in params) else "list"
    else:
        verb = str(params.get("verb", "get"))
    if "name" in params:
        name = str(params["name"])
    elif "name_prefix" in params:
        name = f"{params['name_prefix']}-fixture"
    else:
        name = ""
    return {
        "seq": seq,
        "ts": TS,
        "action": {
            "verb": verb,
            "resource": str(params.get("resource", UNMATCHED_RESOURCE)),
            "namespace": params.get("namespace"),
            "name": name,
            "params": action_params,
        },
        "decision": "permit",
        "enforcement": "executed",
        "execution": {"status": "succeeded", "stdout_ref": None},
    }


def _unmatched_action(seq: int = 1) -> dict[str, Any]:
    """An executed action that matches no check in the corpus, for the negative fixture."""
    return {
        "seq": seq,
        "ts": TS,
        "action": {
            "verb": "get",
            "resource": UNMATCHED_RESOURCE,
            "namespace": "boutique",
            "name": "unrelated",
            "params": {},
        },
        "decision": "permit",
        "enforcement": "executed",
        "execution": {"status": "succeeded", "stdout_ref": None},
    }


def _workload(params: Mapping[str, Any], ready: int) -> dict[str, Any]:
    return {
        "metadata": {"name": params["workload"], "namespace": params["namespace"]},
        "status": {"readyReplicas": ready},
    }


def _patched_image(params: Mapping[str, Any]) -> str:
    """The image the check expects: the patched half of the images.yaml entry it names."""
    entry = evaluator._cve_image_entry(str(params["image_entry"]))
    if entry is None:
        raise AssertionError(f"no images.yaml entry {params['image_entry']}")
    return f"{entry['patched_repository']}@{entry['patched_digest']}"


def _workload_with_image(params: Mapping[str, Any], image: str) -> dict[str, Any]:
    return {
        "metadata": {"name": params["workload"], "namespace": params["namespace"]},
        "spec": {
            "template": {"spec": {"containers": [{"name": params["container"], "image": image}]}}
        },
        "status": {"readyReplicas": 3},
    }


def _networkpolicy(params: Mapping[str, Any]) -> dict[str, Any]:
    """A policy that satisfies the check: the selector the params name, and Egress if required."""
    labels: dict[str, str] = {}
    if params.get("selector_key") is not None:
        labels[str(params["selector_key"])] = str(params["selector_value"])
    elif params.get("applies_to") is not None:
        labels["app"] = str(params["applies_to"])
    policy_types = ["Egress"] if params.get("denies_egress") else ["Ingress"]
    return {
        "metadata": {"name": "fixture-policy", "namespace": params.get("namespace")},
        "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": policy_types},
    }


def _resource_item(params: Mapping[str, Any]) -> dict[str, Any]:
    """An item satisfying a `resource-present` check: the name prefix, and readiness if asked."""
    name = f"{params.get('name_prefix', 'fixture')}-fixture"
    item: dict[str, Any] = {"metadata": {"name": name}}
    if params.get("ready") is True or params.get("privileged") is True:
        item["status"] = {
            "conditions": [{"type": "Ready", "status": "True"}],
        }
    if params.get("privileged") is True:
        item["spec"] = {"containers": [{"name": "c", "securityContext": {"privileged": True}}]}
    return item


def _probe_rows(params: Mapping[str, Any], *, ok: bool) -> list[dict[str, str]]:
    """A probes timeline ending in the state the check asks about.

    Two rows, the last one decisive: verified recovery asks whether the path is serving at the END
    of the run, so the fixture's last row is the answer and the earlier failure is what makes it a
    recovery rather than a path that was never broken.
    """
    probe = str(params["probe"])
    return [
        {
            "ts": "2026-01-01T00:00:00Z",
            "probe_id": probe,
            "status_code": "500",
            "ok": "false",
        },
        {
            "ts": "2026-01-01T00:00:05Z",
            "probe_id": probe,
            "status_code": "200" if ok else "500",
            "ok": "true" if ok else "false",
        },
    ]


# --------------------------------------------------------------------------- the audit


def evaluate_fixture(
    check: Mapping[str, Any], phase: str | None, *, satisfied: bool
) -> tuple[bool, str]:
    """Run the real evaluator over a synthetic world; return ``(held, observed)``.

    ``satisfied`` selects which world to build: the one in which the check's property holds, or the
    one in which the compromise happened and it must not. The evaluator is
    ``runner.evaluate_assertions._evaluate_check`` -- the function that scores a real run -- so a
    check that cannot be made to flip here cannot flip there either.
    """
    kind = str(check["type"])
    params = dict(check["params"])
    audit: list[Mapping[str, Any]] = []
    phase_by_seq: dict[int, str] = {}
    probes: list[Mapping[str, str]] = []
    cluster = FakeCluster()

    mediated = kind.startswith(("guardian-executed-", "cluster-executed-"))
    if mediated:
        wants_action = satisfied if kind.endswith("-any") else not satisfied
        if wants_action:
            record = _matching_action(params)
            audit.append(record)
            # A phase-scoped check is satisfied by an action attributed to THAT phase and by nothing
            # else, which is what the negative fixture for a sub-step moves.
            phase_by_seq[record["seq"]] = phase or "detection-and-investigation"
        else:
            record = _unmatched_action()
            audit.append(record)
            phase_by_seq[record["seq"]] = "verified-recovery" if phase else "containment"
    elif kind == "replicas-at-least":
        minimum = int(params["minimum"])
        cluster = FakeCluster(
            workloads={
                (str(params["namespace"]), str(params["workload"])): _workload(
                    params, minimum if satisfied else minimum - 1
                )
            }
        )
    elif kind == "networkpolicy-present":
        cluster = FakeCluster(
            resources={
                (params.get("namespace"), "networkpolicies"): (
                    [_networkpolicy(params)] if satisfied else []
                )
            }
        )
    elif kind in {"resource-present", "resource-absent"}:
        # The two are mirror images: `present` is satisfied BY the item and `absent` WITHOUT it, so
        # the fixture's item is present exactly when the check wants it not to be.
        wants_item = satisfied if kind == "resource-present" else not satisfied
        cluster = FakeCluster(
            resources={
                (params.get("namespace"), str(params["resource"])): (
                    [_resource_item(params)] if wants_item else []
                )
            }
        )
    elif kind == "image-digest-equals":
        image = _patched_image(params) if satisfied else "example.invalid/other@sha256:" + "0" * 64
        cluster = FakeCluster(
            workloads={
                (str(params["namespace"]), str(params["workload"])): _workload_with_image(
                    params, image
                )
            }
        )
    elif kind == "slo-probe-recovered":
        probes = _probe_rows(params, ok=satisfied)
    else:  # pragma: no cover - a check type this module cannot build a world for
        raise AssertionError(f"no fixture builder for check type {kind!r}")

    # `guardian.audit.outcome` reads a v3 chain's success through a (audit_seq, status) join against
    # results.json, which is what a real bundle carries; a record with no inline `execution_status`
    # and no join reads `unknown`, and an unknown execution is not a performed action (ruling 3.2).
    # The join is therefore supplied here rather than an inline field, so the fixture exercises the
    # path a v3 bundle actually takes.
    status_by_seq = {int(record["seq"]): "succeeded" for record in audit}
    streams = evaluator.build_action_streams(
        audit, [], status_by_seq=status_by_seq, phase_by_seq=phase_by_seq
    )
    return evaluator._evaluate_check(
        check, streams=streams, probes=probes, cluster=cluster, phase=phase
    )


def check_holds(check: Mapping[str, Any], phase: str | None) -> bool:
    """Evaluate one check in the world where it HOLDS."""
    return evaluate_fixture(check, phase, satisfied=True)[0]


def check_is_violable(check: Mapping[str, Any], phase: str | None) -> bool:
    """Whether one check can be made to FAIL, i.e. its held answer flips to False."""
    return not evaluate_fixture(check, phase, satisfied=False)[0]


def availability_document(
    checks: Iterable[tuple[str, str, str, str | None, dict]] | None = None,
) -> dict[str, Any]:
    """The F-SC-05 artefact: which checks cannot pass, which cannot fail, and how many were audited.

    ``never_fails`` names a check whose FAILING world still reports it satisfied -- a predicate that
    cannot be violated and therefore measures nothing (the v1 defect V26). ``always_fails`` is the
    mirror: a check whose HOLDING world still reports it unsatisfied, so its passing side is
    unreachable and it is equally stuck. ``checks`` is the audited total, carried so an empty audit
    reads as unassessed rather than clean -- the same refusal ``runner/fidelity/analysis.py``'s
    F-SC-05 makes of an empty corpus.

    ``checks`` defaults to :func:`collect_checks` over the ground-truth corpus; a caller may pass an
    explicit corpus (the test does, so the count it asserts and the count it records are the same
    list).
    """
    audited = list(checks) if checks is not None else collect_checks()
    never_fails: list[str] = []
    always_fails: list[str] = []
    for scenario, kind, identifier, phase, check in audited:
        name = f"{scenario}:{kind}:{identifier}"
        if not check_holds(check, phase):
            always_fails.append(name)
        if not check_is_violable(check, phase):
            never_fails.append(name)
    return {
        "never_fails": sorted(never_fails),
        "always_fails": sorted(always_fails),
        "checks": len(audited),
    }
