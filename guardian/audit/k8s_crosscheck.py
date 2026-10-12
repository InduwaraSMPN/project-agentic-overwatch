r"""Cross-check executed Guardian records against the API server's own audit log (ADR-137).

WHAT THIS MODULE IS
-------------------
``guardian/audit/verify.py`` proves the Guardian's own hash chain is internally consistent and, with
the ``seal.json`` anchor and the Ed25519 signatures (ADR-130), that it was not truncated or
rewritten.
Both are statements about *the Guardian's account of itself*. Neither can see a mutation the
Guardian
never recorded, because a mutation the Guardian never recorded is not in the Guardian's chain.

``docs/plans/M10-implementation-plan.md`` V28 is that gap made concrete: under the v1 audit policy
  the
API server logged no workload mutation at all, so an executed Guardian action and a direct G2 action
were equally invisible to the API-plane record. The remediation widens
``infra/audit/audit-policy.yaml``
to log every mutation the Guardian's Role can make (and the G2 mirror), and this module is the check
that reads that second, independent record and holds it against the Guardian's.

The question it answers is the one the Guardian cannot answer about itself: **did anything mutate
the
target application that the Guardian did not mediate, and if so, who did it?** Every mutation in
``k8s_api_audit.jsonl`` is either the effect of an executed Guardian record -- matched by verb,
  object
and time -- or it is not, and every mutation that is not must have been made by a principal in the
expected-principal set ``docs/protocols/security-policy.md`` section 2.1 owns (ADR-137): the
ReplicaSet
controller and garbage collector, the kubelet, Chaos Mesh, the G2 credential in the arm that holds
it,
and kind's admin user. Anything else is an unattributed mutation, which is exactly the finding
F-GD-03
exists to raise.

WHY THE EXPECTED-PRINCIPAL SET IS A PARAMETER AND NOT A CONSTANT HERE
---------------------------------------------------------------------
``.agents/rules/00-source-of-truth.md`` allows the set exactly one home, and that home is
``security-policy.md`` section 2.1 -- the plan says so in as many words ("single-homed in
  security-policy
section 2 with a mirror test"). So this module does not restate it: :func:`crosscheck` takes a
:class:`PrincipalAllowList` the caller built from that mirror, and the runner wiring supplies it. A
second copy here would be a second home for a security-relevant list, in the component least able to
afford one, and it would drift from the protocol the day either changed.

WHY STANDARD LIBRARY ONLY, AND WHY IT ACCEPTS PLAIN MAPPINGS
------------------------------------------------------------
Like the rest of ``guardian/audit/`` (ADR-022), this module imports nothing from ``guardian/app/``
and
nothing outside the standard library: it is on the path the runner and analysis read a sealed bundle
with, where the Guardian's contract layer is not present. It consumes the Guardian's decision
records
as plain mappings (the shape :func:`guardian.audit.chain.read_chain` yields) and the API-server
audit
lines as the raw ``audit.k8s.io/v1`` ``Event`` objects the control-plane node writes, so nothing
here
depends on a Kubernetes client being importable.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``runner/validate.py`` wires :func:`crosscheck` into the seal-time and corpus checks (the runner
  agent
owns that wiring; this module exposes the function it calls). F-GD-03 in the fidelity registry is
worded against :data:`UNEXPECTED_PRINCIPAL` and :data:`UNMATCHED_EXECUTION`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from guardian.audit.outcome import succeeded as outcome_succeeded

__all__ = [
    "MUTATING_VERBS",
    "ApiMutation",
    "CrossCheckError",
    "CrossCheckReport",
    "ExecutedAction",
    "Finding",
    "MALFORMED_AUDIT_EVENT",
    "PrincipalAllowList",
    "UNEXPECTED_PRINCIPAL",
    "UNMATCHED_EXECUTION",
    "crosscheck",
    "executed_actions_from_records",
    "parse_api_audit_events",
    "read_api_audit_file",
]

# The verbs that change cluster state. A read leaves no mutation to attribute, so only these produce
# a
# row the cross-check must account for. ``deletecollection`` is included even though the Guardian's
# own
# RBAC refuses it (guardian/deploy/rbac.yaml): a direct-path or controller deletion by collection is
# still a mutation, and this module reads what the API server saw, not what the Guardian may do.
MUTATING_VERBS: Final = frozenset({"create", "update", "patch", "delete", "deletecollection"})

# The enforcement value that means the Guardian did not block the action, so it reached the
# executor.
# A blocked decision changed nothing and has no cluster mutation to match; only an executed one
# does.
_ENFORCEMENT_EXECUTED: Final = "executed"

# Finding kinds. Named constants rather than free text so a report is greppable and a test can
# assert a
# kind without matching a sentence, on guardian/audit/verify.py's pattern.
UNEXPECTED_PRINCIPAL: Final = "unexpected-principal"
UNMATCHED_EXECUTION: Final = "unmatched-execution"
MALFORMED_AUDIT_EVENT: Final = "malformed-audit-event"

# The default window, in seconds, within which an API-server mutation is taken to be the effect of
# an
# executed Guardian record with the same verb and object. It is a wide tolerance on purpose: the two
# timestamps come from different clocks (the Guardian's host and the control-plane node), the API
# record is stamped when the request is received and the Guardian's when the decision is sealed, and
# a
# rollout can put seconds between the two. Matching is primarily by verb and object; time only
# disambiguates when the same object is mutated more than once. The caller may narrow it once
# P0-live
# has measured the real host-to-control-plane skew (security-policy.md section 2.1 /
# evaluation-protocol
# section 4 own the measured bound).
DEFAULT_TIME_TOLERANCE_SECONDS: Final = 120.0


class CrossCheckError(Exception):
    """The cross-check could not be run over the inputs it was given.

    Raised for an input that is structurally unusable -- an API-audit file that is not JSON lines,
    an
    expected-principal list that is empty. A malformed *individual* audit event is not this: it is a
    :data:`MALFORMED_AUDIT_EVENT` finding, because one bad line must not hide the rest of the file.
    """


@dataclass(frozen=True)
class ExecutedAction:
    """One mutation the Guardian executed, as read from its decision chain.

    ``resource`` is the bare kind (``deployments``, never ``deployments.apps``): the API server's
    ``objectRef.resource`` is bare, and folding the Guardian's optionally group-qualified spelling
      onto
    it here is what lets the two be compared by string equality. ``name`` is ``None`` for a
    collection-scoped action, which never matches a named API mutation and is reported as unmatched
    if
    it is a mutating verb.
    """

    verb: str
    resource: str
    namespace: str | None
    name: str | None
    ts: datetime | None
    seq: int | None = None


@dataclass(frozen=True)
class ApiMutation:
    """One mutation the API server recorded, as read from ``k8s_api_audit.jsonl``.

    ``principal`` is ``user.username`` from the audit ``Event`` -- the identity the API server
    authenticated, which is the fact the Guardian's own chain cannot carry because the Guardian
    never
    saw this request. ``line`` is the one-based position in the file, for a finding a reader can
    locate.
    """

    verb: str
    resource: str
    namespace: str | None
    name: str | None
    principal: str | None
    ts: datetime | None
    line: int


@dataclass(frozen=True)
class Finding:
    """One thing the cross-check could not account for, located by file line and principal.

    ``seq`` is the Guardian record's sequence number for an :data:`UNMATCHED_EXECUTION`; ``line`` is
      the
    API-audit file line for an :data:`UNEXPECTED_PRINCIPAL` or a :data:`MALFORMED_AUDIT_EVENT`. The
    one
    that does not apply is ``None``, and both are carried because the two record streams number
    themselves independently and a reader needs whichever names the stream the finding is about.
    """

    kind: str
    detail: str
    seq: int | None = None
    line: int | None = None
    principal: str | None = None

    def __str__(self) -> str:
        where = f"seq={self.seq}" if self.seq is not None else f"line={self.line}"
        who = f" principal={self.principal!r}" if self.principal is not None else ""
        return f"{where}{who} {self.kind}: {self.detail}"


@dataclass(frozen=True)
class PrincipalAllowList:
    """The principals a non-Guardian mutation may be attributed to (security-policy.md section 2.1).

    Two shapes, because the protocol's set is two shapes. ``exact`` holds full identities such as
    ``kubernetes-admin`` and ``system:serviceaccount:agents:g2-executor``. ``prefixes`` holds the
    families the protocol writes with a trailing ``*`` -- ``system:serviceaccount:kube-system:`` for
    the
    controller and the garbage collector, ``system:node:`` for the kubelet -- matched by prefix so
    that
    every member of the family is covered without enumerating node names that vary per cluster.

    The caller builds it from the protocol mirror; this module states no membership of its own, for
    the
    reason the module docstring gives about single-homing a security-relevant set.
    """

    exact: frozenset[str]
    prefixes: tuple[str, ...]

    def matches(self, principal: str | None) -> bool:
        """Return ``True`` if ``principal`` is an expected non-Guardian mutator.

        A ``None`` principal never matches: an audit event the API server could not attribute is not
        an
        expected mutation, it is one the check cannot clear, and clearing it silently would be the
        blind spot ADR-137 closes.
        """
        if principal is None:
            return False
        if principal in self.exact:
            return True
        return any(principal.startswith(prefix) for prefix in self.prefixes)


@dataclass(frozen=True)
class CrossCheckReport:
    """The result of one cross-check: the findings, and the counts a reader wants
    without recounting.
        ``ok`` is the property F-GD-03 reads. ``matched`` is how many executed Guardian mutations
        were
        found in the API-server record, ``unmatched`` how many were not, and ``unattributed`` how
        many
        API
        mutations belonged to neither the Guardian nor the expected-principal set -- the three
        numbers a
        seal-time summary line carries so a run's cross-check is legible without re-reading the
        streams.
    """

    findings: tuple[Finding, ...]
    matched: int
    unmatched: int
    unattributed: int
    api_mutation_count: int
    executed_mutation_count: int
    # ADR-144: unmatched mutations outside the incident namespace(s), skipped from the
    # unexpected-principal check. Zero when the check is unscoped (incident_namespaces=None). It is
    # a count, not a finding: a cluster controller mutating kube-system is not the attack surface,
    # so it is neither judged nor hidden.
    out_of_scope: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings


def _bare_resource(resource: object) -> str | None:
    """Return a resource without its API group, or ``None`` when it is not a usable string.

    ``deployments.apps`` and ``deployments`` fold to the same value, matching the executor's own
    ``_bare_resource`` so the two streams compare by string equality. A non-string is ``None``
      rather
    than an error: it is one record's defect, not the file's, and the caller reports it as one.
    """
    if not isinstance(resource, str) or not resource:
        return None
    return resource.split(".", 1)[0]


def _text(value: object) -> str | None:
    """Return ``value`` if it is a non-empty string, else ``None``."""
    return value if isinstance(value, str) and value else None


def _parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp, tolerating the trailing ``Z`` the API server writes.

    Returns ``None`` rather than raising on anything unparseable: a timestamp is used only to
    disambiguate two mutations of one object, so a missing or malformed one falls back to matching
    by
    verb and object alone rather than failing the whole cross-check.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def executed_actions_from_records(
    records: Iterable[Mapping[str, Any]],
    *,
    status_by_seq: Mapping[int, str] | None = None,
) -> list[ExecutedAction]:
    """Extract the executed *mutations* from a sequence of Guardian decision records.

    ``records`` are the plain mappings :func:`guardian.audit.chain.read_chain` yields
    (``parsed.record`` for a sound line). A record contributes an :class:`ExecutedAction` only when
    it is a decision the Guardian did not block -- ``enforcement == "executed"`` -- and its action
    is a mutating verb, because a read and a blocked decision leave no cluster mutation to
    attribute. Run-start and execution follow-up records carry no ``action`` and are skipped by that
    same shape check.

    The enforcement gate, not the decision, is what selects these: under G1-LOGONLY a *denied*
    action is still executed, and a G1 deny-but-executed mutation must be matched to the API record
    exactly as a G0 permit-and-executed one is. That is the arm whose whole content is "the Guardian
    logs but does not block", and a cross-check that only followed permits would miss every mutation
    G1 exists to let through.

    ``status_by_seq`` (ADR-144) is the ADR-082 execution outcome per decision ``seq``, from
    :func:`guardian.audit.outcome.bundle_status_by_seq`. When given, a decision whose execution did
    NOT succeed is excluded: ``enforcement == "executed"`` records the decision to act, but a
    *failed* execution (the k8s call was attempted and did not take effect) produced no successful
    mutation, so requiring it to match an API record is a false UNMATCHED_EXECUTION -- exactly what
    the M10 smoke run surfaced when an agent's image-patch eradication failed on a scenario with no
    patched image. This mirrors ``runner/evaluate_assertions.py``'s "executed AND succeeded" stream,
    so the two read the outcome the one way ``guardian/audit/outcome.py`` owns. ``None`` keeps the
    pre-ADR-144 behaviour -- every ``enforcement == "executed"`` decision, whatever its outcome --
    so a caller with no outcome map (and every existing test) is unchanged.
    """
    actions: list[ExecutedAction] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if _text(record.get("enforcement")) != _ENFORCEMENT_EXECUTED:
            continue
        if status_by_seq is not None and not outcome_succeeded(record, status_by_seq):
            continue
        action = record.get("action")
        if not isinstance(action, Mapping):
            continue
        verb = _text(action.get("verb"))
        resource = _bare_resource(action.get("resource"))
        if verb is None or resource is None or verb not in MUTATING_VERBS:
            continue
        seq = record.get("seq")
        actions.append(
            ExecutedAction(
                verb=verb,
                resource=resource,
                namespace=_text(action.get("namespace")),
                name=_text(action.get("name")),
                ts=_parse_timestamp(record.get("ts")),
                seq=seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
            )
        )
    return actions


def parse_api_audit_events(
    events: Iterable[Mapping[str, Any]], *, start_line: int = 1
) -> tuple[list[ApiMutation], list[Finding]]:
    """Turn API-server audit ``Event`` objects into mutations, naming the malformed ones.

    Returns the mutations and a list of :data:`MALFORMED_AUDIT_EVENT` findings, because one
    unreadable
    event must not hide the rest of the file -- the same reason ``guardian/audit/chain.py`` names a
    defect on a :class:`~guardian.audit.chain.ParsedRecord` rather than raising on the first bad
    line.

    Only mutating verbs are returned. A read event is logged by the widened policy at ``Metadata``
    level
    and is not a mutation to attribute, so it is dropped here rather than carried and filtered
    later.
    """
    mutations: list[ApiMutation] = []
    findings: list[Finding] = []
    for offset, event in enumerate(events):
        line = start_line + offset
        if not isinstance(event, Mapping):
            findings.append(
                Finding(
                    MALFORMED_AUDIT_EVENT,
                    f"audit event is not an object: {type(event).__name__}",
                    line=line,
                )
            )
            continue
        verb = _text(event.get("verb"))
        object_ref = event.get("objectRef")
        object_ref = object_ref if isinstance(object_ref, Mapping) else {}
        resource = _bare_resource(object_ref.get("resource"))
        if verb is None or verb not in MUTATING_VERBS:
            continue
        if resource is None:
            # A mutating verb on a non-resource URL, or one whose objectRef the policy did not
            # record.
            # It cannot be matched to an object-scoped Guardian action, so it is a malformed
            # *mutation*
            # rather than a droppable read: reported so it is neither silently matched nor silently
            # cleared.
            findings.append(
                Finding(
                    MALFORMED_AUDIT_EVENT, f"{verb} event carries no objectRef.resource", line=line
                )
            )
            continue
        user = event.get("user")
        user = user if isinstance(user, Mapping) else {}
        mutations.append(
            ApiMutation(
                verb=verb,
                resource=resource,
                namespace=_text(object_ref.get("namespace")),
                name=_text(object_ref.get("name")),
                principal=_text(user.get("username")),
                ts=(
                    _parse_timestamp(event.get("requestReceivedTimestamp"))
                    or _parse_timestamp(event.get("stageTimestamp"))
                ),
                line=line,
            )
        )
    return mutations, findings


def read_api_audit_file(path: Path) -> tuple[list[ApiMutation], list[Finding]]:
    """Read ``k8s_api_audit.jsonl`` into mutations and malformed-line findings.

    Read as bytes and decoded as UTF-8, and a trailing carriage return stripped from each line, on
    ``guardian/audit/chain.py``'s reason: a fixture checked out on the Windows host arrives with
      CRLF,
    and a reader that split on bytes would mis-parse a correct file.
    """
    raw = Path(path).read_bytes().decode("utf-8")
    events: list[Mapping[str, Any]] = []
    findings: list[Finding] = []
    for index, line in enumerate(raw.split("\n"), start=1):
        stripped = line[:-1] if line.endswith("\r") else line
        if not stripped.strip():
            continue
        try:
            loaded = json.loads(stripped)
        except ValueError as error:
            findings.append(Finding(MALFORMED_AUDIT_EVENT, f"not JSON: {error}", line=index))
            continue
        if not isinstance(loaded, dict):
            findings.append(
                Finding(
                    MALFORMED_AUDIT_EVENT,
                    f"not a JSON object but a {type(loaded).__name__}",
                    line=index,
                )
            )
            continue
        loaded["__line__"] = index
        events.append(loaded)
    # Re-thread the true file line onto each event so a finding points at the right line even though
    # blank and malformed lines were skipped above.
    mutations: list[ApiMutation] = []
    for event in events:
        line = int(event.pop("__line__"))
        parsed, parse_findings = parse_api_audit_events([event], start_line=line)
        mutations.extend(parsed)
        findings.extend(parse_findings)
    return mutations, findings


def _within_tolerance(
    left: datetime | None, right: datetime | None, tolerance_seconds: float
) -> bool:
    """Return ``True`` when two timestamps are close enough, or when either is absent.

    Absent-means-match is deliberate: the timestamp only disambiguates two mutations of one object,
    and
    refusing a match for a missing timestamp would turn "the clocks did not both record" into an
    unattributed mutation, which is a false finding about a correct run.
    """
    if left is None or right is None:
        return True
    return abs((left - right).total_seconds()) <= tolerance_seconds


def crosscheck(
    *,
    executed_actions: Sequence[ExecutedAction],
    api_mutations: Sequence[ApiMutation],
    expected_principals: PrincipalAllowList,
    parse_findings: Sequence[Finding] = (),
    time_tolerance_seconds: float = DEFAULT_TIME_TOLERANCE_SECONDS,
    incident_namespaces: frozenset[str] | None = None,
) -> CrossCheckReport:
    """Hold the Guardian's executed mutations against the API server's record. Never raises on data.

    Two directions, because a gap in either is a finding of its own kind.

    *Every API mutation is accounted for.* Each :class:`ApiMutation` is matched, by verb, object and
    time, to an executed Guardian record. A match means the Guardian mediated it. A mutation with no
    match must have been made by a principal in ``expected_principals`` -- the controllers, the
    kubelet,
    Chaos Mesh, the G2 credential, kind's admin user -- and a mutation that matches neither is an
    :data:`UNEXPECTED_PRINCIPAL`: something changed the target application that the Guardian did not
    mediate and that no expected actor made.

    *Every executed Guardian mutation happened.* An executed record with no matching API mutation is
    an
    :data:`UNMATCHED_EXECUTION`: the Guardian's chain says it acted and the API server's record does
    not
    corroborate it. In v1 every execution was unmatched because no mutation was logged at all (V28);
    under the widened policy an unmatched execution is a real discrepancy.

    Matching is one-to-one: an API mutation consumes the Guardian record it matched, so a second
    identical API mutation of the same object -- a retry, a controller re-reconcile -- is judged on
    its
    own principal rather than borrowing the first one's Guardian match. Each executed record is
    therefore matched at most once, which is what makes an :data:`UNMATCHED_EXECUTION` count
    meaningful.

    ``parse_findings`` are folded in unchanged (the malformed-event findings from parsing), so a
      caller
    that parsed with :func:`parse_api_audit_events` or :func:`read_api_audit_file` passes them
    straight
    through and the report carries the whole picture.

    Raises :class:`CrossCheckError` only for an unusable *configuration* -- an empty
    expected-principal
    list -- never for the data being checked, on ``guardian/audit/verify.py``'s rule that a checker
    of
    hostile-shaped input reports rather than crashes.
    """
    if not expected_principals.exact and not expected_principals.prefixes:
        raise CrossCheckError(
            "the expected-principal set is empty, so every non-Guardian mutation would be reported. "  # noqa: E501 - message
            "Build it from security-policy.md section 2.1 (ADR-137) and pass it in"
        )

    findings: list[Finding] = list(parse_findings)
    remaining = list(executed_actions)
    matched = 0
    unattributed = 0
    out_of_scope = 0

    for mutation in api_mutations:
        index = _match_index(mutation, remaining, time_tolerance_seconds)
        if index is not None:
            del remaining[index]
            matched += 1
            continue
        # ADR-144: the unexpected-principal check is the attack surface's, and the attack surface is
        # the incident namespace(s) -- the target application, where the Guardian's Role and the G2
        # mirror are scoped. The widened audit policy (ADR-137) cannot scope by namespace, so the
        # slice also carries cluster-plane churn (kube-scheduler, controller-manager, CNI, kubelet,
        # kube-state-metrics) in kube-system/observability/default that no expected-principal set
        # can anticipate without an ever-growing allowlist. When incident_namespaces is given, an
        # unmatched mutation outside it is out of scope -- counted, never a finding -- because a
        # controller mutating a namespace the threat model gives no actor reach to is not what this
        # check judges. None keeps the unscoped, check-everywhere behaviour every existing caller
        # and fixture has.
        if incident_namespaces is not None and mutation.namespace not in incident_namespaces:
            out_of_scope += 1
            continue
        if not expected_principals.matches(mutation.principal):
            unattributed += 1
            findings.append(
                Finding(
                    UNEXPECTED_PRINCIPAL,
                    f"{mutation.verb} {mutation.resource}"
                    f"{'/' + mutation.name if mutation.name else ''}"
                    f"{' in ' + mutation.namespace if mutation.namespace else ''} was made by a "
                    "principal that is neither an executed Guardian action nor in the expected set",
                    line=mutation.line,
                    principal=mutation.principal,
                )
            )

    for action in remaining:
        findings.append(
            Finding(
                UNMATCHED_EXECUTION,
                f"the Guardian recorded executing {action.verb} {action.resource}"
                f"{'/' + action.name if action.name else ''}"
                f"{' in ' + action.namespace if action.namespace else ''}, but no matching mutation "  # noqa: E501 - message
                "appears in the API-server audit log",
                seq=action.seq,
            )
        )

    return CrossCheckReport(
        findings=tuple(findings),
        matched=matched,
        unmatched=len(remaining),
        unattributed=unattributed,
        api_mutation_count=len(api_mutations),
        executed_mutation_count=len(executed_actions),
        out_of_scope=out_of_scope,
    )


def _match_index(
    mutation: ApiMutation, candidates: Sequence[ExecutedAction], tolerance_seconds: float
) -> int | None:
    """Return the index of the first executed action that matches ``mutation``, or ``None``.

    A match is exact on verb, bare resource, namespace and name, and within the time tolerance. The
    first match wins and the caller removes it, so the pairing is one-to-one; a duplicate API
    mutation
    of one object then finds no candidate and is judged on its own principal.
    """
    for index, action in enumerate(candidates):
        if (
            action.verb == mutation.verb
            and action.resource == mutation.resource
            and action.namespace == mutation.namespace
            and action.name == mutation.name
            and _within_tolerance(action.ts, mutation.ts, tolerance_seconds)
        ):
            return index
    return None
