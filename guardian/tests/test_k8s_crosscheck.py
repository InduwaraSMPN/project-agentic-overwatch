r"""The API-server audit cross-check (ADR-137): the Guardian's account held against the cluster's.

``guardian/audit/k8s_crosscheck.py`` reads two independent records -- the Guardian's own decision
  chain
and the API server's audit log -- and answers the question the Guardian cannot answer about itself:
did
anything mutate the target application that the Guardian did not mediate, and if so who. These cases
exercise the two findings F-GD-03 is worded against (an unmatched execution and an unexpected
principal), the matching that clears an honest run, and the malformed-line tolerance.
"""

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.audit.k8s_crosscheck import (  # noqa: E402
    MALFORMED_AUDIT_EVENT,
    UNEXPECTED_PRINCIPAL,
    UNMATCHED_EXECUTION,
    ApiMutation,
    CrossCheckError,
    PrincipalAllowList,
    crosscheck,
    executed_actions_from_records,
    parse_api_audit_events,
    read_api_audit_file,
)

# The expected-principal set as security-policy.md section 2.1 declares it (ADR-137). This suite
# builds
# it here rather than importing a module constant, because the protocol owns the set and the
# production
# caller mirrors it there; a fixture proving the checker works needs only a faithful instance of the
# shape, not the one home.
EXPECTED = PrincipalAllowList(
    exact=frozenset({"kubernetes-admin", "system:serviceaccount:agents:g2-executor"}),
    prefixes=("system:serviceaccount:kube-system:", "system:node:"),
)

WINDOW_OPEN = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)


def _guardian_deployment_scale(name: str, *, seq: int, when: datetime | None = WINDOW_OPEN) -> dict:
    """A sealed Guardian decision record for an executed patch on one deployment."""
    return {
        "seq": seq,
        "record_type": "decision",
        "enforcement": "executed",
        "decision": "permit",
        "ts": (when or WINDOW_OPEN).isoformat(),
        "action": {
            "verb": "patch",
            "resource": "deployments.apps",
            "namespace": "boutique",
            "name": name,
        },
    }


def _api_mutation(
    verb: str, resource: str, name: str, principal: str, *, when: datetime = WINDOW_OPEN
) -> dict:
    """A raw audit.k8s.io/v1 Event for one mutation, the shape the control-plane node writes."""
    return {
        "kind": "Event",
        "verb": verb,
        "objectRef": {"resource": resource, "namespace": "boutique", "name": name},
        "user": {"username": principal},
        "requestReceivedTimestamp": when.isoformat(),
    }


def test_an_honest_run_matches_every_executed_mutation() -> None:
    """A Guardian patch and an expected controller pod-create both clear the cross-check."""
    records = [
        {"seq": 0, "record_type": "run-start", "run_id": "RUN-A"},
        _guardian_deployment_scale("cartservice", seq=1),
    ]
    mutations, parse_findings = parse_api_audit_events(
        [
            _api_mutation("patch", "deployments", "cartservice", "kubernetes-admin"),
            _api_mutation(
                "create",
                "pods",
                "cartservice-abc",
                "system:serviceaccount:kube-system:replicaset-controller",
            ),
        ]
    )
    report = crosscheck(
        executed_actions=executed_actions_from_records(records),
        api_mutations=mutations,
        expected_principals=EXPECTED,
        parse_findings=parse_findings,
    )
    assert report.ok, [str(finding) for finding in report.findings]
    assert report.matched == 1  # the Guardian's patch
    assert report.unmatched == 0
    assert report.unattributed == 0


def test_a_mutation_by_an_unexpected_principal_is_flagged() -> None:
    """A direct patch by a principal outside the expected set is an unattributed mutation.

    This is the finding V28 made invisible and ADR-137 restores: something changed the target
    application that the Guardian did not mediate and no controller, kubelet, Chaos Mesh actor, G2
    credential or admin user made.
    """
    mutations, _ = parse_api_audit_events(
        [
            _api_mutation(
                "delete", "deployments", "paymentservice", "system:serviceaccount:agents:intruder"
            )
        ]
    )
    report = crosscheck(executed_actions=[], api_mutations=mutations, expected_principals=EXPECTED)
    assert not report.ok
    assert report.unattributed == 1
    kinds = {finding.kind for finding in report.findings}
    assert kinds == {UNEXPECTED_PRINCIPAL}
    offender = report.findings[0]
    assert offender.principal == "system:serviceaccount:agents:intruder"
    assert offender.line == 1


def test_the_g2_principal_is_expected_only_because_the_set_lists_it() -> None:
    """The G2 credential's direct mutation clears the check, because section 2.1 names it expected.

    The same event by any other agents-namespace ServiceAccount does not, which is what makes the
    set
    an allowlist rather than a namespace pass.
    """
    g2, _ = parse_api_audit_events(
        [
            _api_mutation(
                "patch", "deployments", "adservice", "system:serviceaccount:agents:g2-executor"
            )
        ]
    )
    assert crosscheck(executed_actions=[], api_mutations=g2, expected_principals=EXPECTED).ok

    other, _ = parse_api_audit_events(
        [_api_mutation("patch", "deployments", "adservice", "system:serviceaccount:agents:default")]
    )
    assert not crosscheck(executed_actions=[], api_mutations=other, expected_principals=EXPECTED).ok


def test_an_executed_guardian_record_with_no_api_mutation_is_flagged() -> None:
    """The Guardian's chain says it acted; the API-server record does not corroborate it."""
    records = [_guardian_deployment_scale("cartservice", seq=1)]
    report = crosscheck(
        executed_actions=executed_actions_from_records(records),
        api_mutations=[],
        expected_principals=EXPECTED,
    )
    assert not report.ok
    assert report.unmatched == 1
    finding = report.findings[0]
    assert finding.kind == UNMATCHED_EXECUTION
    assert finding.seq == 1


def test_a_blocked_or_read_only_record_contributes_no_executed_mutation() -> None:
    """Only an executed mutating decision is a mutation to attribute; a block and a read are not."""
    records = [
        {
            "seq": 1,
            "record_type": "decision",
            "enforcement": "blocked",
            "decision": "deny",
            "ts": WINDOW_OPEN.isoformat(),
            "action": {"verb": "delete", "resource": "pods", "namespace": "boutique", "name": "x"},
        },
        {
            "seq": 2,
            "record_type": "decision",
            "enforcement": "executed",
            "decision": "permit",
            "ts": WINDOW_OPEN.isoformat(),
            "action": {"verb": "get", "resource": "pods", "namespace": "boutique", "name": "x"},
        },
    ]
    assert executed_actions_from_records(records) == []


def test_a_g1_denied_but_executed_mutation_is_matched_like_a_permit() -> None:
    """Under G1-LOGONLY a denied action is still executed, so it must match the API record too."""
    records = [
        {
            "seq": 1,
            "record_type": "decision",
            "enforcement": "executed",
            "decision": "deny",
            "guardian_mode": "G1-LOGONLY",
            "ts": WINDOW_OPEN.isoformat(),
            "action": {
                "verb": "delete",
                "resource": "pods",
                "namespace": "boutique",
                "name": "frontend-1",
            },
        }
    ]
    actions = executed_actions_from_records(records)
    assert len(actions) == 1
    mutations, _ = parse_api_audit_events(
        [_api_mutation("delete", "pods", "frontend-1", "kubernetes-admin")]
    )
    assert crosscheck(
        executed_actions=actions, api_mutations=mutations, expected_principals=EXPECTED
    ).ok


def test_duplicate_api_mutations_are_matched_one_to_one() -> None:
    """A second identical mutation of one object is judged on its own principal, not the first's
    match.
        The Guardian executed one patch; two patches appear in the API log. The first is the
        Guardian's;
        the
        second is a duplicate whose principal must stand on its own -- here an unexpected one, so it
        is
        flagged rather than borrowing the first's Guardian attribution.
    """
    records = [_guardian_deployment_scale("cartservice", seq=1)]
    mutations, _ = parse_api_audit_events(
        [
            _api_mutation("patch", "deployments", "cartservice", "kubernetes-admin"),
            _api_mutation(
                "patch", "deployments", "cartservice", "system:serviceaccount:agents:intruder"
            ),
        ]
    )
    report = crosscheck(
        executed_actions=executed_actions_from_records(records),
        api_mutations=mutations,
        expected_principals=EXPECTED,
    )
    assert report.matched == 1
    assert report.unattributed == 1


def test_a_malformed_audit_line_is_reported_not_swallowed(tmp_path: Path) -> None:
    """One unreadable line becomes a finding; the rest of the file is still read."""
    path = tmp_path / "k8s_api_audit.jsonl"
    good = _api_mutation("patch", "deployments", "cartservice", "kubernetes-admin")
    path.write_bytes(
        ('{"kind": "Event", not json\n' + __import__("json").dumps(good) + "\n").encode("utf-8")
    )
    mutations, findings = read_api_audit_file(path)
    assert len(mutations) == 1
    assert [finding.kind for finding in findings] == [MALFORMED_AUDIT_EVENT]
    assert findings[0].line == 1


def test_an_empty_expected_principal_set_is_refused() -> None:
    """A cross-check with nothing expected would flag every controller write; it refuses to run."""
    with pytest.raises(CrossCheckError):
        crosscheck(
            executed_actions=[],
            api_mutations=[
                ApiMutation("patch", "deployments", "boutique", "x", "kubernetes-admin", None, 1)
            ],
            expected_principals=PrincipalAllowList(exact=frozenset(), prefixes=()),
        )


def test_a_read_event_is_not_counted_as_a_mutation() -> None:
    """A get logged at Metadata level under the widened policy is dropped, not attributed."""
    mutations, findings = parse_api_audit_events(
        [_api_mutation("get", "pods", "cartservice-1", "system:serviceaccount:agents:whoever")]
    )
    assert mutations == []
    assert findings == []


def test_executed_action_folds_the_group_qualified_resource() -> None:
    """``deployments.apps`` in a Guardian record matches ``deployments`` in the API objectRef."""
    action = executed_actions_from_records([_guardian_deployment_scale("cartservice", seq=1)])[0]
    assert action.resource == "deployments"
