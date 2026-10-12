r"""The real executor: the one object in this system permitted to change the cluster.

WHAT THIS MODULE IS
-------------------
``docs/02-architecture.md`` section 1 types the Guardian ``trusted; sole credential holder``, and
``docs/protocols/security-policy.md`` section 1.2 states the invariant plainly: only ``guardian/``
holds a kubeconfig or ServiceAccount able to mutate the target cluster, and its own RBAC is least
privilege. :class:`guardian.app.mediation.ActionExecutor` is the interface that boundary is drawn
on. This module is the implementation behind it, and it is reached from exactly one place --
:meth:`guardian.app.mediation.Mediator._seal`, after an audit record has already been sealed.

Everything above it has been running against
:class:`guardian.app.mediation.FakeActionExecutor` since M3, which is why that class exists in the
shipped module rather than in a test file. Which of the two a process gets is
:class:`guardian.app.config.ExecutorKind`, a required setting with no default, for the reason that
enum argues at length: a Guardian that fell back to the fake would mediate every action perfectly,
write an audit log saying ``executed``, and change nothing anywhere.

``scripts/grep_guard.sh`` SCANS ``agents/`` AND NOT ``guardian/``, AND THAT ASYMMETRY IS THE POINT
---------------------------------------------------------------------------------------------------
The guard that machine-enforces ``.agents/rules/10-guardian-first.md`` greps every tracked file
under ``agents/`` for a Kubernetes client import, a shell-out to the cluster command-line tool, the
generated API client class names, the three configuration loaders and the environment variable that
points a client at a cluster -- with no exemption mechanism of any kind. It does not scan
``guardian/``.

That is not an oversight in the guard and it is not a gap this file slips through. Rule 10 does not
say "nobody may hold a Kubernetes client"; it says the only mutation path from an agent to the
cluster is the Guardian, so that every mutation passes a deny-by-default reference monitor and lands
in its audit log. A rule forbidding the client *everywhere* would forbid the enforcement point
itself and leave the system with no way to act at all. **This file is what the guard is protecting:
the single place the prohibition points at.** So the two halves are one decision -- the credential
lives here, and nowhere else may reach around it -- and the check is scoped to the half where a
violation would be silent. A direct client call under ``agents/`` voids the study's central claim
and looks like ordinary code; a client call here is the claim being implemented.

The reader-facing consequence is worth stating because it is easy to get backwards: an import of the
Kubernetes package appearing in this file is correct, and the same import appearing anywhere under
``agents/`` fails CI. Nothing in ``guardian/app/`` other than this module imports it, and nothing in
this module is reachable except through :class:`guardian.app.mediation.ActionExecutor`.

WHY THE CLIENT IS IMPORTED LAZILY, INSIDE THE CONSTRUCTOR
-----------------------------------------------------------
``import guardian.app.executor`` must succeed on a machine with no Kubernetes package installed.
Three things depend on that and none of them is a convenience: ruff and the import-time contract
guards run in a CI job that installs only the pinned runtime set; ``guardian/tests/`` drives this
class with an injected double and must be able to import the module to do so; and
``guardian/app/composition.py`` imports this module unconditionally, because a composition root that
imported its executor conditionally would be a composition root with a branch in it that only one
deployment ever takes.

So the import is inside :meth:`KubernetesActionExecutor.__init__` and happens only when no client
was supplied. That places the failure exactly where it belongs -- a Guardian configured
``GUARDIAN_EXECUTOR=kubernetes`` on a host without the client refuses to start, loudly, with a
message naming the package -- while a Guardian configured ``fake``, a linter, and a test suite never
reach it at all.

``client`` is a constructor argument for that second reason and for one more. An injected double is
what makes the four properties below testable without a cluster: that a mapped call succeeds, that
an API failure becomes a recorded failure rather than an exception, that an unmapped verb/resource
pair is a *refusal* rather than a crash, and that the argument-building is what this module says it
is. A cluster-only test of those would be a Tier B test of things that are not about a cluster.

EXECUTION NEVER RAISES, AND ``stdout_ref`` IS ALWAYS NULL IN M4
----------------------------------------------------------------
:class:`guardian.app.mediation.ActionExecutor`'s contract is "never raises for an ordinary failure",
and :meth:`guardian.app.mediation.Mediator._execute` catches anyway -- because an exception escaping
here would unwind *after* the audit record was appended saying the Guardian did not block, leaving
the log claiming an execution the caller never heard about. Belt and braces is right here: this
module returns
``ExecutionOutcome(status=FAILED, stdout_ref=None)`` for every ordinary failure, and the mediator's
catch is the second line for a defect neither of us anticipated.

Note carefully what a failure means and does not mean.
:attr:`~guardian.app.models.Enforcement.EXECUTED` on the record says the Guardian did not block;
this outcome says what happened next. A failed attempt is still an attempt that was not blocked,
which is exactly what evaluation-protocol section 3's policy-compliant action rate counts, so
collapsing the two would be losing the distinction the measure is built on.

``stdout_ref`` is ``None`` on every path, and that is the contract rather than a stub.
:class:`~guardian.app.models.ExecutionOutcome`'s own docstring fixes the field as a root-relative
pointer that "can hold no content, by construction" and permits null "when nothing ran or when the
executor produced no output worth referencing". This executor writes no file: a Kubernetes API call
returns an object, not a stream, and the record of what was attempted is the audit chain's already.
The day something here does produce a bundle-relative artefact -- a diff, a captured manifest -- the
field is where it is named, and the pointer grammar is what stops the artefact being inlined.

THE OPERATION TABLE IS SMALL, EXPLICIT, AND REFUSES WHAT IT CANNOT EXPRESS
---------------------------------------------------------------------------
:data:`OPERATIONS` maps a ``(verb, resource)`` pair onto one API-group method, and everything not in
it is refused. It is a table rather than a chain of conditionals so that "what can this Guardian
actually do to a cluster" is a list a reviewer reads in one screen, and so that the answer is the
same list the authority policy in ``guardian/policies/authority.rego`` is written against.

Three consequences are deliberate.

*An unmapped pair is a refused execution, never a crash and never an improvisation.* A capability
may legitimately authorise a verb this executor has not implemented -- the authority policy declares
what a *phase* may ever carry, which is a policy ceiling, while this table is what M4 built. The two
are allowed to differ, and where they do the honest outcome is a recorded failure. Guessing a
similar-looking call would be the executor substituting its own answer for the one it was asked for,
which is the failure ``guardian/token/issuer.py`` refuses for TTL clamping and for the same reason.

*Whole-object replacement is absent.* ``ActionSpec.params`` is a flat mapping of scalars by contract
-- :data:`~guardian.app.models.ParamValue` admits a string, a bool, an int, a float or null and no
nested structure -- so a full resource manifest cannot be expressed in a request at all. Rather than
widen the request contract, which is the one place attacker-authored data enters, M4 implements the
structured operations a flat parameter set *can* say precisely, and leaves ``update`` unmapped. The
authority policy still declares it, because what a phase may be granted and what this build performs
are different statements.

*Every body this module sends is constructed here from named parameters, never passed through.* A
request cannot hand the API server an arbitrary object, because there is no path by which one could
be spelled. That is a much stronger property than validating a body would have been, and it comes
free from the contract.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every mutation the study ever observes. The scenarios in M5 are written against the pairs below, and
``guardian/policies/authority.rego`` declares the ceiling they sit under.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from guardian.app.config import GuardianStartupError
from guardian.app.models import ActionSpec, ExecutionOutcome, ExecutionStatus
from scenarios.schemas import yamlsubset

# The Python package the real client lives in, named once so the refusal message and the import
# cannot disagree about what to install.
KUBERNETES_PACKAGE: Final = "kubernetes"

# The four API groups this Guardian reaches, as attribute names on the client bundle below. Named
# constants rather than strings at each row of the table, so a typo in a row is an import-time
# AttributeError on a fixture rather than a run-time failure on one action.
CORE_GROUP: Final = "core_v1"
APPS_GROUP: Final = "apps_v1"
NETWORKING_GROUP: Final = "networking_v1"
# ADR-083: RoleBinding revocation (containment) and removal (eradication). A fourth group rather
# than folding into CORE_GROUP, because RBAC objects are their own API group
# (rbac.authorization.k8s.io) and the client bundle mirrors the server's own grouping.
RBAC_GROUP: Final = "rbac_v1"

# The parameter names the body builders below read. Each is a *named* translation rather than a
# pass-through: see the module docstring on why no request can hand the API server an object.
REPLICAS_PARAM: Final = "replicas"
LABEL_KEY_PARAM: Final = "label_key"
LABEL_VALUE_PARAM: Final = "label_value"
SELECTOR_KEY_PARAM: Final = "selector_key"
SELECTOR_VALUE_PARAM: Final = "selector_value"
IMAGE_ENTRY_PARAM: Final = "image_entry"
# ADR-083: which subject a RoleBinding-revocation names. Three parameters rather than one opaque
# string, for the reason every other body-builder in this module reads named scalars: a subject is
# identified by its kind, its name and (for a ServiceAccount, the only kind a scenario in this repo
# ever grants) its namespace, and a caller cannot express anything this table does not have a slot
# for.
SUBJECT_KIND_PARAM: Final = "subject_kind"
SUBJECT_NAME_PARAM: Final = "subject_name"
SUBJECT_NAMESPACE_PARAM: Final = "subject_namespace"
CVE_IMAGES_FILE: Final = Path(__file__).resolve().parents[2] / "scenarios" / "cve" / "images.yaml"

# The NetworkPolicy shape containment may create: selected pods keep application traffic inside the
# Boutique namespace and DNS, but lose every other egress path, including the Kubernetes API in the
# default namespace. Ingress is unchanged, so containment does not itself make the storefront fail.
NETWORK_POLICY_API_VERSION: Final = "networking.k8s.io/v1"
NETWORK_POLICY_KIND: Final = "NetworkPolicy"
NETWORK_POLICY_TYPES: Final = ("Egress",)

# The labels every object this Guardian *creates* carries (ADR-081). Before them, a containment
# policy carried no label that `scenarios/attackers/apply.py`'s teardown could select, so it
# outlived its run and contained the next run's attacker before its incident began. On 2026-09-13
# the two SCN-SIM-02 runs that started with an earlier run's egress policy in `boutique` recorded no
# Kubernetes-audit evidence of their attack at all; every run that started clean recorded it.
# The key spellings are the applier's own `_RUN_LABEL_KEY` family; scenarios/tests pins them equal.
RUN_ID_LABEL_KEY: Final = "agentic-overwatch.io/run-id"
MANAGED_BY_LABEL_KEY: Final = "agentic-overwatch.io/managed-by"
MANAGED_BY_GUARDIAN: Final = "guardian"
# Kubernetes label values: at most 63 characters, alphanumeric at both ends, `-_.` inside.
_LABEL_VALUE: Final = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)$")


class ExecutorUnavailable(GuardianStartupError):
    """The real executor could not be built, so this Guardian must not start.

    Raised from the constructor when the Kubernetes client package is absent and no client was
    injected. A distinct type so that :mod:`guardian.app.composition` can say *which* collaborator
    was unbuildable without parsing a message, and a construction-time failure rather than a
    per-request one because a Guardian that cannot act has no correct behaviour available to it: it
    would permit, record ``executed``, and change nothing -- the exact failure
    :class:`guardian.app.config.ExecutorKind` exists to make impossible by configuration.

    A :class:`~guardian.app.config.GuardianStartupError` subclass, for the reason
    :class:`~guardian.app.opa.OpaBinaryUnavailable` and
    :class:`~guardian.app.policy.PolicyBundleError` are: the sentence above says this Guardian must
    not start, and ``guardian/app/__main__.py`` is the process entry point that makes "must not
    start" mean "exit non-zero with the message intact". It catches that base class and nothing
    wider -- deliberately, because a bare ``except Exception`` there would turn a stack trace an
    operator needs into an exit code -- so a plain ``RuntimeError`` here was the one construction
    failure that escaped as a traceback instead of as the refusal its own docstring promises. Three
    unbuildable collaborators, one hierarchy, one catcher.
    """


@dataclass(frozen=True)
class _Operation:
    """One row of :data:`OPERATIONS`: which API group, which method, and what it is handed.

    ``needs_name`` distinguishes an object-scoped call from a collection-scoped one -- listing pods
    in a namespace names no object, and :class:`~guardian.app.models.ActionSpec` types ``name`` as
    nullable for exactly that reason. A row that needs a name and is handed a null is refused rather
    than defaulted, because the empty string is a name nobody created.

    ``build_body`` is ``None`` for a read or a delete and otherwise a function from the request's
    parameters to the object sent. Every one of them constructs its result; none passes a caller's
    structure through.

    ``build_body_from_current`` (ADR-083) is the one exception to "every body is built from the
    request alone": revoking a RoleBinding subject has to name which entry to remove, and the only
    way to remove exactly one entry from a list without touching the rest is to have read the list
    first. It is a function of the request *and* the object this executor has just read back with
    ``read_method`` -- never of a caller-supplied structure -- so the same guarantee holds one step
    removed: the body is still constructed here, from named parameters and from server state this
    executor fetched itself, and a caller's ``params`` still cannot shape it into anything but a
    reference to which existing entry to take out.
    """

    group: str
    method: str
    needs_name: bool
    build_body: Callable[[ActionSpec], dict[str, Any]] | None = None
    # True for a row that creates a new object: its body gains the run labels, so the run's
    # teardown can find and remove it (ADR-081). Patches and deletes create nothing to clean up.
    creates_object: bool = False
    # ADR-083. Mutually exclusive with build_body: a row sets at most one of the two, and
    # _call_arguments raises if a row were ever to set both, because a body built two different ways
    # is a body neither builder can be trusted to describe.
    build_body_from_current: Callable[[ActionSpec, Mapping[str, Any]], list[Any]] | None = None
    read_method: str | None = None


def _scale_body(action: ActionSpec) -> dict[str, Any]:
    """Build a scale patch from a ``replicas`` parameter, or raise -- and never scale to zero.

    ``replicas`` is required to be a non-negative decimal *string*: a ``bool`` and an ``int`` are
    both turned away by the ``isinstance(raw, str)`` gate, which matters because ``bool`` is a
    subclass of ``int`` and ``replicas: true`` would otherwise read as one replica -- a value nobody
    asked for, applied to a running workload, from a request that looked like a type error.

    **Zero is refused here as well, and that is D4-A (ADR-129) made defence-in-depth.** Scaling a
    Deployment to zero is a distinct capability no phase holds: ``guardian/policies/`` denies an
    action whose normalised replica count is zero before this executor is ever reached, and
    ``guardian/app/policy.py`` hands that policy the *normalised* count so ``"00"`` cannot slip past
    the rule as a string. This function closes the same door from the other side. The Guardian is
    the sole mutation path (security-policy.md section 1.2), so a scale-to-zero that reached the
    executor would be a permit the policy should never have produced, and the honest response is a
    refused execution rather than a workload taken to zero. ``int(raw)`` collapses every spelling of
    zero -- ``"0"``, ``"00"``, ``"000"`` -- to the same integer, so the refusal cannot be evaded by
    writing the count differently, exactly as the policy's own normalisation cannot.
    """
    raw = action.params.get(REPLICAS_PARAM)
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal():
        raise ValueError(f"{REPLICAS_PARAM!r} must be a non-negative integer string")
    replicas = int(raw)
    if replicas == 0:
        raise ValueError(
            "scaling a Deployment to zero is a capability no phase holds (D4-A, ADR-129); the "
            "Guardian's executor refuses it as the policy denies it -- see guardian/policies/"
        )
    return {"spec": {"replicas": replicas}}


def _image_body(action: ActionSpec) -> dict[str, Any]:
    """Resolve one trusted catalog entry to its exact patched application image (ADR-091)."""
    if set(action.params) != {IMAGE_ENTRY_PARAM}:
        raise ValueError(f"deployment update accepts only {IMAGE_ENTRY_PARAM!r}")
    entry_id = action.params[IMAGE_ENTRY_PARAM]
    document = yamlsubset.parse(CVE_IMAGES_FILE.read_text(encoding="utf-8"))
    matches = [
        entry
        for entry in document.get("images", ())
        if entry.get("id") == entry_id or entry.get("component") == entry_id
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown CVE image entry {entry_id!r}")
    entry = matches[0]
    container = entry.get("container")
    if entry.get("component") != action.name or not isinstance(container, str) or not container:
        raise ValueError("CVE image entry does not belong to this deployment container")
    repository = entry.get("patched_repository")
    digest = entry.get("patched_digest")
    if not isinstance(repository, str) or not isinstance(digest, str):
        raise ValueError("CVE image entry has no patched image pin")
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("CVE image entry has a malformed patched digest")
    return {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": container,
                            "image": f"{repository}@{digest}",
                            "imagePullPolicy": "Never",
                        }
                    ]
                }
            }
        }
    }


def _label_body(action: ActionSpec) -> dict[str, Any]:
    """Build a metadata-label patch from a key and a value parameter, or raise."""
    key = action.params.get(LABEL_KEY_PARAM)
    value = action.params.get(LABEL_VALUE_PARAM)
    if not isinstance(key, str) or not key or not isinstance(value, str):
        raise ValueError(f"{LABEL_KEY_PARAM!r} and {LABEL_VALUE_PARAM!r} must both be strings")
    return {"metadata": {"labels": {key: value}}}


def _isolation_network_policy_body(action: ActionSpec) -> dict[str, Any]:
    """Build a deny-all NetworkPolicy selecting one workload, or raise.

    The one object-creating operation M4 performs, and the shape is fixed here rather than supplied:
    a pod selector taken from a single label, both policy types named, and no rule of any kind -- so
    the object isolates the selected workload and can express nothing else. A body that a caller
    could shape would be a body that could open a path rather than close one, which is the opposite
    of what a containment capability is for.
    """
    key = action.params.get(SELECTOR_KEY_PARAM)
    value = action.params.get(SELECTOR_VALUE_PARAM)
    if action.name is None:
        raise ValueError("a NetworkPolicy create requires a name")
    if not isinstance(key, str) or not key or not isinstance(value, str):
        raise ValueError(f"{SELECTOR_KEY_PARAM!r} and {SELECTOR_VALUE_PARAM!r} must be strings")
    return {
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {"name": action.name},
        "spec": {
            "podSelector": {"matchLabels": {key: value}},
            "policyTypes": list(NETWORK_POLICY_TYPES),
            "egress": [
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "boutique"}
                            }
                        }
                    ]
                },
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                            }
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                },
            ],
        },
    }


def _revoke_rolebinding_subject_body(
    action: ActionSpec, current: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Build a JSON Patch that removes exactly one matching subject, or raise (ADR-083).

    Supervisor ruling section 3.1 item 2: "a new Guardian operation whose fixed body can only
    remove a subject, never add one, on the same principle as ``_isolation_network_policy_body``."
    That principle applied here is a JSON Patch with exactly two possible operation kinds, ``test``
    and ``remove`` -- there is no ``add`` or ``replace`` anywhere in this function, so no value any
    caller could put in ``action.params`` can make it grant a subject rather than take one away.
    Compare :data:`~guardian.app.models.ParamValue`, which admits no nested structure at all: even a
    caller that tried to smuggle a whole patch document through a parameter could not, because the
    contract this function reads from cannot carry one.

    ``current`` is this executor's own read of the RoleBinding, taken immediately before this body
    is built (see :func:`_call_arguments`) -- never a caller-supplied structure. The three named
    parameters say *which* subject to remove; everything about *how* the removal is expressed comes
    from what the server just reported the object to contain.

    The ``test`` operation ahead of ``remove`` is the race guard the supervisor's design notes ask
    for: it names the exact subject this function found at that index, so if the object changed
    between the read and the patch being applied -- another writer, or a second concurrent
    Executor -- the index no longer matching what ``test`` expects fails the whole patch atomically,
    rather than removing whatever now happens to sit at that position.

    A subject that does not exist is a refusal, not a silent no-op: the caller asked for a specific
    removal, and "there was nothing to remove" is a different fact from "the removal happened",
    which is exactly the ambiguity ADR-082 exists to stop conflating for execution outcomes in
    general. Raising here is what turns it into a recorded ``failed`` rather than a lie that nothing
    was wrong.
    """
    kind = action.params.get(SUBJECT_KIND_PARAM)
    name = action.params.get(SUBJECT_NAME_PARAM)
    namespace = action.params.get(SUBJECT_NAMESPACE_PARAM)
    if not isinstance(kind, str) or not kind or not isinstance(name, str) or not name:
        raise ValueError(f"{SUBJECT_KIND_PARAM!r} and {SUBJECT_NAME_PARAM!r} must both be strings")
    if namespace is not None and (not isinstance(namespace, str) or not namespace):
        raise ValueError(f"{SUBJECT_NAMESPACE_PARAM!r} must be a non-empty string, or absent")
    subjects = current.get("subjects")
    if not isinstance(subjects, list):
        subjects = []
    for index, subject in enumerate(subjects):
        if not isinstance(subject, Mapping):
            continue
        if (
            subject.get("kind") == kind
            and subject.get("name") == name
            and subject.get("namespace") == namespace
        ):
            value = {"kind": kind, "name": name}
            if namespace is not None:
                value["namespace"] = namespace
            return [
                {"op": "test", "path": f"/subjects/{index}", "value": value},
                {"op": "remove", "path": f"/subjects/{index}"},
            ]
    raise ValueError(
        f"no subject matching kind={kind!r} name={name!r} namespace={namespace!r} in the current "
        f"RoleBinding {action.name!r}; refusing rather than guessing which entry to remove"
    )


# What this Guardian can do to a cluster, in full. Keys are (verb, bare resource) -- see
# `_bare_resource` for why a group-qualified spelling folds onto the same row. Anything absent is
# refused, which is the module docstring's first deliberate consequence.
OPERATIONS: Final[Mapping[tuple[str, str], _Operation]] = {
    # Reads. Available to every phase the authority policy grants them to, and the only operations
    # detection-and-investigation has at all.
    ("get", "pods"): _Operation(CORE_GROUP, "read_namespaced_pod", needs_name=True),
    ("list", "pods"): _Operation(CORE_GROUP, "list_namespaced_pod", needs_name=False),
    ("get", "services"): _Operation(CORE_GROUP, "read_namespaced_service", needs_name=True),
    ("list", "services"): _Operation(CORE_GROUP, "list_namespaced_service", needs_name=False),
    ("list", "events"): _Operation(CORE_GROUP, "list_namespaced_event", needs_name=False),
    ("get", "deployments"): _Operation(APPS_GROUP, "read_namespaced_deployment", needs_name=True),
    ("list", "deployments"): _Operation(APPS_GROUP, "list_namespaced_deployment", needs_name=False),
    ("get", "replicasets"): _Operation(APPS_GROUP, "read_namespaced_replica_set", needs_name=True),
    ("list", "replicasets"): _Operation(
        APPS_GROUP, "list_namespaced_replica_set", needs_name=False
    ),
    ("list", "networkpolicies"): _Operation(
        NETWORKING_GROUP, "list_namespaced_network_policy", needs_name=False
    ),
    # Containment. Scale a workload down, label one for quarantine, isolate one with a policy.
    ("patch", "deployments"): _Operation(
        APPS_GROUP, "patch_namespaced_deployment", needs_name=True, build_body=_scale_body
    ),
    ("update", "deployments"): _Operation(
        APPS_GROUP, "patch_namespaced_deployment", needs_name=True, build_body=_image_body
    ),
    ("patch", "pods"): _Operation(
        CORE_GROUP, "patch_namespaced_pod", needs_name=True, build_body=_label_body
    ),
    ("create", "networkpolicies"): _Operation(
        NETWORKING_GROUP,
        "create_namespaced_network_policy",
        needs_name=False,
        build_body=_isolation_network_policy_body,
        creates_object=True,
    ),
    # ADR-083 (supervisor ruling §3.1 item 2): revoke an escalation by removing the one subject an
    # incident granted it, from a RoleBinding that stays in place for the next phase to examine or
    # remove. Reads the current object first -- see _revoke_rolebinding_subject_body -- so this row
    # is the one place `read_method` is set.
    ("patch", "rolebindings"): _Operation(
        RBAC_GROUP,
        "patch_namespaced_role_binding",
        needs_name=True,
        build_body_from_current=_revoke_rolebinding_subject_body,
        read_method="read_namespaced_role_binding",
    ),
    # Eradication. Removal, and the withdrawal of an isolation policy or a RoleBinding once it is no
    # longer needed.
    ("delete", "pods"): _Operation(CORE_GROUP, "delete_namespaced_pod", needs_name=True),
    ("delete", "deployments"): _Operation(
        APPS_GROUP, "delete_namespaced_deployment", needs_name=True
    ),
    ("delete", "networkpolicies"): _Operation(
        NETWORKING_GROUP, "delete_namespaced_network_policy", needs_name=True
    ),
    # ADR-083 (supervisor ruling §3.1 item 3): the RoleBinding a compromised object's escalation
    # depended on, removed outright once containment's subject-only revocation is no longer enough
    # and the object it named is being replaced rather than merely defused.
    ("delete", "rolebindings"): _Operation(
        RBAC_GROUP, "delete_namespaced_role_binding", needs_name=True
    ),
}


def _bare_resource(resource: str) -> str:
    """Return the resource without its API group: ``deployments.apps`` becomes ``deployments``.

    :data:`~guardian.app.models.RESOURCE_PATTERN` admits an optional group suffix, so one kind can
    reach this executor under two spellings and both denote the same thing. Folding here means
    :data:`OPERATIONS` carries one row per kind rather than one per spelling, which is what keeps
    the table readable as the answer to "what can this Guardian do".

    A custom resource retains its own name -- ``ciliumnetworkpolicies.cilium.io`` folds to
    ``ciliumnetworkpolicies``, which is absent from the table and therefore refused. That is the
    correct outcome for M4: the Cilium client is not in the pinned runtime set, and an executor that
    pretended otherwise would fail at the API server instead of at the table.
    """
    return resource.split(".", 1)[0]


@dataclass(frozen=True)
class KubernetesApis:
    """The four API-group objects this executor calls, bundled so a double is one object.

    Deliberately a plain container rather than a protocol with thirteen methods on it. The methods
    are :data:`OPERATIONS`' business and change when that table changes; what is stable is that
    there are four groups, and a test double therefore supplies four objects rather than
    reimplementing an interface that would have to be edited alongside every new row.

    ``rbac_v1`` is ADR-083's addition, required rather than defaulted like the other three: a caller
    that built a double before this row existed is a caller this dataclass should make say so, at
    construction, rather than one that discovers the gap the first time containment tries to revoke
    a subject.
    """

    core_v1: Any
    apps_v1: Any
    networking_v1: Any
    rbac_v1: Any


class KubernetesActionExecutor:
    """Perform one permitted action against the cluster, and report what happened.

    Construction takes ``apis`` when a caller has them -- which is what
    ``guardian/tests/`` does, with a double -- and otherwise builds them from the Kubernetes client
    package, imported at that moment and not before. The module docstring gives the three reasons
    the import is lazy and why the constructor is where the failure belongs.

    ``in_cluster`` selects which of the client's two configuration loaders is used. It defaults to
    true because the deployed shape is a Pod with a projected ServiceAccount -- the credential
    boundary security-policy section 1.2 draws -- and a default of "read the developer's local
    cluster configuration file" would be a Guardian whose credential depends on whose machine it
    started on.
    """

    def __init__(
        self,
        *,
        apis: KubernetesApis | None = None,
        in_cluster: bool = True,
        run_id: str | None = None,
    ) -> None:
        # ``run_id`` is the run this Guardian was deployed for (``GUARDIAN_RUN_ID``). Objects it
        # creates are labelled with it so that run's teardown removes them (ADR-081). A value that
        # cannot be a label is refused here, at startup, rather than on the first containment.
        if run_id is not None and _LABEL_VALUE.fullmatch(run_id) is None:
            raise ValueError(f"run id {run_id!r} is not a valid Kubernetes label value")
        self._object_labels: dict[str, str] = (
            {RUN_ID_LABEL_KEY: run_id, MANAGED_BY_LABEL_KEY: MANAGED_BY_GUARDIAN}
            if run_id is not None
            else {}
        )
        self._apis = apis if apis is not None else _load_cluster_apis(in_cluster=in_cluster)

    def execute(self, action: ActionSpec, *, request_id: str) -> ExecutionOutcome:
        """Attempt ``action``. Returns an outcome for every path and raises on none of them.

        ``request_id`` is accepted because the protocol declares it and is deliberately unused: it
        identifies the attempt in the audit chain, which has already recorded it, and passing it to
        the API server would put a Guardian-internal identifier into cluster objects for no reader's
        benefit.

        The three refusal paths and the one success path all end at
        :class:`~guardian.app.models.ExecutionOutcome`, and the failures are not distinguished in
        it: the record of *what* was attempted is the audit chain's, the structured vocabulary of
        *why* a decision went the way it did is :class:`~guardian.app.models.ReasonCode`'s, and this
        field says only whether the attempt worked. Adding a third vocabulary here would be a third
        place a run has to be explained from.
        """
        del request_id
        operation = OPERATIONS.get((action.verb, _bare_resource(action.resource)))
        if operation is None:
            return _failed()
        if operation.needs_name and action.name is None:
            return _failed()
        try:
            method = getattr(getattr(self._apis, operation.group), operation.method)
            arguments = _call_arguments(
                operation, action, apis=self._apis, object_labels=self._object_labels
            )
            method(**arguments)
        # Deliberately unselective, and deliberately not narrowed to the client's own exception
        # type: that type is only importable when the package is installed, and an executor whose
        # failure handling depended on an optional import would raise on the machines least able to
        # cope with it. Every failure is the same outcome here anyway -- see the class docstring.
        except Exception:
            return _failed()
        return ExecutionOutcome(status=ExecutionStatus.SUCCEEDED, stdout_ref=None)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    """Return ``value`` as a plain mapping: itself if it already is one, else its ``to_dict()``.

    Every generated Kubernetes client model (``V1RoleBinding`` included) exposes ``to_dict()``; a
    test double is free to hand back a plain ``dict`` instead, which is what keeps
    ``guardian/tests/test_executor.py``'s fakes from having to reconstruct a client model just to be
    read from. Anything else is a defect in the double or the client, not a shape this executor
    should guess at, so it raises rather than returning an empty mapping that would read as "no
    subjects" and refuse every revocation for the wrong reason.
    """
    if isinstance(value, Mapping):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        dumped = to_dict()
        if isinstance(dumped, Mapping):
            return dumped
    raise TypeError(f"expected a mapping or an object with to_dict(), got {type(value).__name__}")


def _call_arguments(
    operation: _Operation,
    action: ActionSpec,
    *,
    apis: KubernetesApis,
    object_labels: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the keyword arguments for one client call from a validated action.

    Keywords rather than positional arguments, because the client's generated methods take
    ``(name, namespace, body)`` in an order that is consistent but not obviously so, and a
    transposed pair would send a namespace where a name belongs -- which the API server would
    happily accept as a lookup of an object that does not exist, producing a *plausible* failure
    rather than an obvious one.

    Every value comes from a field the contract has already validated: ``namespace`` is a DNS-1123
    label and ``name`` a DNS-1123 subdomain, so neither can hold a traversal, a separator, a scheme,
    a percent-escape or a homoglyph. The body, where there is one, is constructed by one of the
    builders above from named scalars -- or, for :attr:`_Operation.build_body_from_current`
    (ADR-083), from named scalars plus an object this function reads back from the cluster itself
    first, through ``apis`` and ``operation.read_method``. A failure of that read -- not found,
    denied, unreachable -- propagates to :meth:`KubernetesActionExecutor.execute`'s own ``except``
    exactly as a failure of the write would, and is reported the same way: a failed attempt, never a
    crash and never a guess at what the object might have contained.

    The Kubernetes Python client selects the JSON Patch content type for a ``PATCH`` call precisely
    when the body it is handed is a ``list`` rather than a ``dict`` (its own
    ``select_header_content_type``), so a body built by ``build_body_from_current`` -- always a list
    of ``test``/``remove`` operations -- needs no explicit content-type argument here to be sent as
    one.
    """
    arguments: dict[str, Any] = {"namespace": action.namespace}
    if operation.needs_name:
        arguments["name"] = action.name
    if operation.build_body is not None:
        body = operation.build_body(action)
        if operation.creates_object and object_labels:
            metadata = body.setdefault("metadata", {})
            metadata["labels"] = {**metadata.get("labels", {}), **object_labels}
        arguments["body"] = body
    elif operation.build_body_from_current is not None:
        if operation.read_method is None:  # pragma: no cover - a table row bug, not a runtime one
            raise ValueError(f"{operation!r} sets build_body_from_current with no read_method")
        read = getattr(getattr(apis, operation.group), operation.read_method)
        current = _as_mapping(read(name=action.name, namespace=action.namespace))
        arguments["body"] = operation.build_body_from_current(action, current)
        arguments["_content_type"] = "application/json-patch+json"
    return arguments


def _failed() -> ExecutionOutcome:
    """The one failure outcome, built in one place so no path can invent a different shape."""
    return ExecutionOutcome(status=ExecutionStatus.FAILED, stdout_ref=None)


def _load_cluster_apis(*, in_cluster: bool) -> KubernetesApis:
    """Import the Kubernetes client, load a credential, and return the three API groups.

    The only place in ``guardian/`` that imports the client package, and the only place that loads a
    cluster credential. Both facts are the credential boundary security-policy section 1.2 draws,
    expressed as code rather than as a convention.

    A missing package is :class:`ExecutorUnavailable` naming what to install, and so is a
    configuration load that fails -- a Guardian that could not find its ServiceAccount is a Guardian
    with no credential, and starting it would produce a run in which every permitted action failed
    for a reason nobody would look for in the audit log.
    """
    try:
        # Function-scoped on purpose. See the module docstring: `import guardian.app.executor`
        # must succeed on a host with no Kubernetes package, or the lint job, the contract guards
        # and the test suite all fail for a dependency reason on a module none of them executes.
        from kubernetes import client, config
    except ImportError as error:
        raise ExecutorUnavailable(
            f"the {KUBERNETES_PACKAGE!r} package is not installed, so the real executor cannot be "
            "built. Install it, or start this Guardian with the fake executor if it is not meant "
            "to reach a cluster -- which is a choice GUARDIAN_EXECUTOR makes explicit"
        ) from error

    try:
        if in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
    except Exception as error:
        raise ExecutorUnavailable(
            "no cluster credential could be loaded. guardian/ is the sole credential holder "
            "(security-policy.md section 1.2), so a Guardian without one cannot act at all"
        ) from error

    return KubernetesApis(
        core_v1=client.CoreV1Api(),
        apps_v1=client.AppsV1Api(),
        networking_v1=client.NetworkingV1Api(),
        rbac_v1=client.RbacAuthorizationV1Api(),
    )
