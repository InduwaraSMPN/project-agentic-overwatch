r"""The one pipeline: verify, build the input, evaluate, enforce per mode, append audit, execute.

WHAT THIS MODULE IS
-------------------
``docs/plans/M3-implementation-plan.md``'s T3.1 requires that the pipeline be "fixed in one place",
and this is that place. Every mutation the agent layer ever causes in the target environment is the
result of one call to :meth:`Mediator.decide`, and every refusal is the result of one call to
:meth:`Mediator.decide` or :meth:`Mediator.reject`. There is no second ordering of these steps
anywhere in the repository, no shortcut for a request that looks harmless, and no path that reaches
the executor without having passed through the audit sink first.

The module is written against a caller that is assumed hostile. That is not a posture: the threat
model puts the LLM layer in position P1 with arbitrary request content, P2 with arbitrary token
bytes, P3 with unbounded volume and ordering, and P5 with attacker-authored context arriving through
the four injection classes. So the interesting properties below are not the happy path -- they are
what happens when a step fails, and what a future edit is prevented from doing.

TWO PROPERTIES ARE STRUCTURAL, AND THE REST OF THIS DOCSTRING IS ABOUT HOW
---------------------------------------------------------------------------
**A decision cannot be returned without an audit append**, and **the G0-versus-G1 audit difference
cannot escape three fields**. Both are requirements that a careful implementation satisfies and a
later careless edit breaks, which is exactly the class of requirement that has to be moved into the
types rather than left in the reviewer's head.

*No decision without an append.* ``docs/protocols/security-policy.md`` section 1.4 requires permit
and deny alike to produce hash-chained records, and the M3 plan states the corollary that shapes the
whole milestone: "an unaudited block is invisible to the evaluation whether or not it happened",
which makes it worse than an unblocked action, because an unblocked action at least leaves a trace
somewhere. Three mechanisms carry it:

1. :class:`~guardian.app.models.ActionResult` requires ``audit_seq``, a non-nullable sequence number
   whose only source is an append that has already happened. :func:`result_from_record` is the sole
   construction site of an ``ActionResult`` in this package and it takes a sealed
   :class:`~guardian.app.models.AuditRecord` as its argument, so the type system, not the control
   flow, is what makes an unaudited result unrepresentable.
2. Both public entry points have **exactly one ``return`` statement each**, and it is
   ``return self._seal(...)``. A future branch added inside :meth:`_adjudicate` cannot return early
   with a decision, because :meth:`_adjudicate` does not return an ``ActionResult`` -- it returns a
   :class:`Verdict`, which is inert until :meth:`_seal` turns it into a record.
3. :meth:`_seal` calls the sink and lets a failing append **propagate**. It does not catch, it does
   not retry into a degraded mode, and it does not return a result with a placeholder sequence
   number. A Guardian that cannot write its audit log has no correct answer available to it, and the
   only safe behaviour is to answer nothing -- which :mod:`guardian.app.main` turns into a 503 with
   no detail.

*The G0-versus-G1 difference is confined to three fields.* ADR-023's isolation assertion 2 is the
load-bearing one: the same request sequence under ``G0-FULL`` and under ``G1-LOGONLY``, records
diffed field by field, with the **only** permitted differences being ``guardian_mode``, the
enforcement field and the execution block -- decision, reason code, rule id, ordering and ``jti``
handling identical. Making that hold by construction rather than by care takes three decisions:

1. :func:`adjudicate` is a **module-level function, not a method**. It has no ``self``, therefore no
   configuration, therefore no mode. Everything it needs arrives as an explicit keyword argument and
   :func:`assert_mode_blind` refuses to let this module import if any of those arguments is *named*
   like a mode flag or *typed* :class:`~guardian.app.models.GuardianMode`. The function that decides
   what happened cannot see which arm it is running in.
2. :class:`Verdict` -- everything :func:`adjudicate` produces -- is guarded at import by
   :func:`~guardian.app.models.reject_field_names` and
   :func:`~guardian.app.models.reject_field_types` against the same mode vocabulary
   :mod:`guardian.app.config` guards the request tree with. So the mode cannot be smuggled out of a
   mode-blind function inside its own result.
3. The mode is read on the decision path in **exactly one expression**, inside
   :func:`enforcement_for`, and that function's entire output is one
   :class:`~guardian.app.models.Enforcement` value. Every other field of the audit draft is copied
   from the :class:`Verdict`. The confinement is therefore not a property of the diff -- it is a
   property of where the mode is legible at all.

The consequence worth stating plainly, because it is the arm's whole content: under ``G1-LOGONLY``
a ``deny`` is followed by execution. Every ``deny``, including a forged token and an out-of-scope
verb, because ``G1-LOGONLY`` removes *enforcement* rather than removing some enforcement.
Verification still runs, the ``jti`` is still spent, the reason code is still the reason code -- the
Guardian simply does not stop the action, and the record says so in the enforcement field while
``decision`` keeps its meaning unchanged. That is what makes a G1 record distinguishable from a G0
deny by a ``grep``, which is what ``docs/protocols/evaluation-protocol.md`` section 3's two RQ5
measures need and what section 7's protected contrast rests on.

THE ORDER OF THE STEPS IS ITSELF A DECISION
--------------------------------------------
``append audit`` comes **before** ``execute``, and the reverse would be indefensible: an action that
reached the cluster and then failed to be recorded is the one outcome the evaluation cannot see and
the operator cannot undo. Appending first costs the ability to record whether the execution
succeeded in the same record -- which is why
:attr:`~guardian.app.models.Enforcement.EXECUTED` is defined as "the Guardian did not block" rather
than as "the cluster succeeded", and why the attempt's outcome lives on
:attr:`~guardian.app.models.ActionResult.execution` instead. ``models.py`` states that reading; this
module is where it is relied upon.

**``reserve cap`` sits between ``verify token`` and ``evaluate`` (ADR-129), and the two placements
around it are each forced by something.** It cannot come before the verification, because the
per-token counter is keyed on the capability's ``jti`` and a *claimed* ``jti`` is an attacker-chosen
key -- one fresh forged value per request would mint a fresh bucket each time. It cannot come after
the evaluation, because a cap checked once the policy has already permitted is a cap that N
concurrent requests can each pass before any of them learns the budget was gone.
:mod:`guardian.app.limits` argues the mechanism; the position in this pipeline is the ordering, and
this paragraph is where a later edit that moves it will be noticed.

``verify token`` comes before ``build the OPA input``, and that ordering is enforced by a type
rather than by discipline: :func:`~guardian.app.policy.build_policy_input` requires a
:class:`~guardian.app.models.CapabilityTokenClaims`, which only a verifier produces, so a document
describing an unverified token cannot be constructed and no policy can be asked to permit on one.

WHY EVERY COLLABORATOR IS A PROTOCOL DEFINED HERE, AND NOT AN IMPORT
---------------------------------------------------------------------
The token service is ``guardian/token/`` (M3-T3.3), the chain is ``guardian/audit/`` (M3-T3.6), the
policy bundle is ``guardian/policies/`` (M3-T3.2) and the real executor is Tier B, gated on M1
delivering a cluster. This module imports none of them. Each is reached through a narrow protocol
declared below, and the reason is not tidiness:

*It is what the other packages already asked for.* ``guardian/audit/chain.py`` declares its own
``SupportsModelDump`` protocol specifically so that the chain does not import
``guardian.app.models`` -- ADR-022 argues that the audit chain must stay standard-library and must
not become downstream of the mediation API's module graph. ``guardian/token/verifier.py`` publishes
its reason vocabulary as a tuple of strings and says in as many words that the app layer "must not
be import-coupled to the verifier's internals". Reaching across those boundaries from this side
would defeat both decisions while leaving their docstrings claiming otherwise.

*The two vocabularies genuinely differ, and the seam is where that is reconciled.*
``guardian.token.verifier.DenialReason`` spells its values ``token_expired`` and
``token_signature_invalid``; :class:`~guardian.app.models.ReasonCode` spells the same outcomes
``temporal.expired`` and ``authenticity.signature-invalid``, because the app vocabulary carries the
threat-model family in the value. Neither is wrong and neither is a superset of the other. An
adapter maps one to the other, it belongs to the commit that wires the two packages together, and
putting it behind :class:`TokenVerifier` means the mapping is a visible, testable object rather than
a pile of conditionals inside the pipeline.

*It keeps the pipeline drivable before any of them exists.* Everything below runs today against a
verifier, a sink and an executor supplied by the caller, which is what lets T3.8's adversarial cases
be written against the real pipeline rather than against a mock of it.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
*An audit sink implementation.* :class:`AuditSink` returns a sealed
:class:`~guardian.app.models.AuditRecord`, and sealing one means assigning ``seq``, ``prev_hash``
and ``hash`` -- which is chain arithmetic, and ADR-022 allows the canonicalisation rule exactly one
implementation in ``guardian/audit/canonical.py``. A convenience sink here would be a second one, in
the component least able to afford a second definition of what a hash covers. A test that needs a
sink supplies one; the production sink is ``guardian/audit/``'s writer behind an adapter.

*Any policy logic.* See :mod:`guardian.app.policy`'s docstring for why a Python decision procedure
alongside the Rego one is two policies rather than one with a fallback.

*A clock that is not injected.* ``ts`` reaches the record through the ``clock`` argument, defaulting
to the real one. It is injectable because ADR-023's isolation assertion 2 diffs two records field by
field, and a wall-clock timestamp would differ between the two runs for a reason that has nothing to
do with the arms -- so the assertion would either be written with an exception nobody could justify
or would be written against a frozen clock, which is this argument.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every adversarial case in T3.8 asserts three things about one call into this module -- denied, with
a structured code, and present in the chain. Every RQ5 number in Chapter 4 is computed from records
this module drafted. M4's agent-side client speaks to the surface :mod:`guardian.app.main` puts in
front of it. After the pilot gate freeze at ``v1.0``, AGENTS.md iron rule 6 makes a behaviour change
here a logged hotfix ADR.
"""

import inspect
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol, get_type_hints, runtime_checkable

from guardian.app.config import MODE_SHAPED_FIELD_NAMES, GuardianConfig, GuardianStartupError
from guardian.app.limits import ActionCapReserver
from guardian.app.models import (
    ACTION_RESULT_SCHEMA_VERSION,
    AUDIT_RECORD_SCHEMA_VERSION,
    AUDIT_RECORD_TYPE_DECISION,
    AUDIT_RECORD_TYPE_EXECUTION,
    IDENTIFIER_MAX_CHARS,
    IDENTIFIER_PATTERN,
    SECRET_SHAPED_FIELD_NAMES,
    ActionCapCounters,
    ActionCapReservation,
    ActionRequest,
    ActionResult,
    ActionSpec,
    AuditedAction,
    AuditRecord,
    CapabilityTokenClaims,
    Decision,
    Enforcement,
    ExecutionOutcome,
    ExecutionRecord,
    ExecutionRecordDraft,
    ExecutionStatus,
    GuardianMode,
    Identifier,
    ReasonCode,
    ReasonGroup,
    RecordTimestamp,
    TokenIssueRequest,
    TokenIssueResponse,
    _iter_annotation_types,
    _normalise_field_name,
    _validate_action_enforcement,
    _validate_decision_consistency,
    forbidden_param_names,
    recordable_params,
    reject_field_names,
    reject_field_types,
)
from guardian.app.policy import (
    PolicyBundle,
    PolicyDecision,
    PolicyEngine,
    build_policy_input,
    evaluate_policy,
)
from pydantic import BaseModel, ConfigDict, model_validator

# Four private names are imported from :mod:`guardian.app.models` above, and the reason is
# single-homing rather than convenience. ``_validate_action_enforcement`` is imported because
# models.py's own docstring says it is "Shared with :class:`guardian.app.mediation.AuditDraft`" --
# a draft that the sealed record would then reject is a failure *after* the append, which is the one
# place a Guardian must never fail. ``_validate_decision_consistency`` is the same invariant for the
# decision half. ``_normalise_field_name`` and ``_iter_annotation_types`` are the folding rule and
# the annotation walk that models.py's own guards use; a second copy of either would mean the guard
# in this file and the guard in that one could disagree about what ``guardianMode`` normalises to,
# which is precisely the drift .agents/rules/00-source-of-truth.md exists to prevent.

# The audit record's identifier grammar, compiled once. Used only to check a value the *runner*
# supplied -- see Mediator.__init__ -- so that a Guardian whose configured run id could not be
# written into a record refuses to start rather than failing at its first append.
_IDENTIFIER = re.compile(IDENTIFIER_PATTERN)

# The longest a structured issuance-refusal code may be. Not a protocol number and not a security
# parameter: it is a bound on a string that an issuer implementation hands to
# :mod:`guardian.app.main` for return to a caller, and it exists so that a refusal code cannot
# become a payload. Generous enough for any vocabulary a token service would sensibly define.
REFUSAL_CODE_MAX_CHARS: Final = 64


class MediationError(RuntimeError):
    """Base class for the failures this module raises rather than returns.

    Everything that is a *decision* -- including every denial, including a Guardian defect -- comes
    back as an :class:`~guardian.app.models.ActionResult`. What is left, and what this hierarchy
    covers, is the case where no decision could be reached at all: the audit sink refused or failed.
    A separate name exists so that :mod:`guardian.app.main` can answer that case differently from a
    denial without inspecting a message, because the two are genuinely different events and
    collapsing them would let an outage be scored as an enforcement.
    """


class AuditUnavailable(MediationError):
    """The audit sink could not seal a record, so no decision may be returned.

    Raised by :meth:`Mediator._seal` when the sink raises or when the record it returned does not
    describe the decision that was drafted. Both are refusals to answer, and the refusal is the
    point: security-policy section 1.4 requires every decision to be audited, and a Guardian that
    returned a decision it could not record would be producing exactly the invisible outcome the M3
    plan's threat-model corollary is about.
    """


class TokenIssuanceRefused(MediationError):
    """A ``POST /v1/tokens`` request could not be honoured, with a structured code saying why.

    Deliberately named differently from ``guardian.token.issuer.TokenIssueRefused``, which it does
    not import and is not: this is the *seam's* exception, carrying whatever closed vocabulary the
    wired issuer publishes, and a traceback that named both the same thing would hide which side of
    the boundary a failure came from.

    ``code`` is a structured token from the issuer's own vocabulary and is bounded, because it is
    returned to a caller the threat model treats as hostile. ``detail`` is never returned over the
    wire by :mod:`guardian.app.main`; it exists for the Guardian's operational log.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code if _is_refusal_code(code) else "issue_refused"
        self.detail = detail


def _is_refusal_code(value: object) -> bool:
    """Return ``True`` if ``value`` is a short structured code fit to return to a hostile caller."""
    return isinstance(value, str) and 0 < len(value) <= REFUSAL_CODE_MAX_CHARS and value.isascii()


# --------------------------------------------------------------------------------------------
# The mode-blindness guards
#
# Two import-time checks, public because ADR-023's isolation suite asserts on them directly. They
# answer the same question from two sides -- a value named like a mode, and a value typed like one
# -- for the reason guardian/app/config.py gives about its own pair: either alone is one rename
# away from being useless.
# --------------------------------------------------------------------------------------------


def assert_mode_blind(function: Callable[..., Any], *, why: str) -> None:
    """Raise ``TypeError`` if ``function`` takes a parameter that could carry the Guardian mode.

    Checks parameter *names* against :data:`~guardian.app.config.MODE_SHAPED_FIELD_NAMES` in the
    normalised form :mod:`guardian.app.models` folds to, and parameter *annotations* against
    :class:`~guardian.app.models.GuardianMode` anywhere inside them -- so a
    ``Mapping[str, GuardianMode]`` is caught as surely as a bare one.

    Applied to :func:`adjudicate` at import. That is the whole mechanism behind ADR-023's isolation
    assertion 2: if the function that produces the decision, the reason code and the rule id cannot
    take the mode as an input, then no arrangement of the code below can make those three fields
    depend on the arm, and the field-by-field diff the assertion performs is confined by
    construction rather than by the diff happening to come out clean on the inputs somebody chose.

    The return annotation is deliberately not checked: :class:`Verdict` is guarded separately, by
    the model-level name and type guards, and checking the return type here would duplicate that in
    a place where it would be easy to weaken one copy and not the other.
    """
    hints = get_type_hints(function)
    offenders: list[str] = []
    for name in inspect.signature(function).parameters:
        if _normalise_field_name(name) in MODE_SHAPED_FIELD_NAMES:
            offenders.append(name)
        annotation = hints.get(name)
        if annotation is not None and GuardianMode in set(_iter_annotation_types(annotation)):
            offenders.append(f"{name}: {GuardianMode.__name__}")
    if offenders:
        raise TypeError(
            f"{function.__qualname__}: mode-aware parameter(s) {sorted(offenders)}: {why}"
        )


# --------------------------------------------------------------------------------------------
# Shared model configuration
# --------------------------------------------------------------------------------------------


class _MediationModel(BaseModel):
    """Unknown key is an error, and an instance cannot be edited after it exists.

    The same two settings :class:`guardian.app.models._GuardianContractModel` fixes, declared here
    rather than inherited, for the reason that class's docstring gives: a model in another module
    that wants these settings states them itself instead of importing a base and inheriting a policy
    it did not read. ``frozen=True`` matters more than usual for :class:`Verdict` -- a verdict that
    could be edited between adjudication and sealing would put a mutation point between the decision
    and the record of it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------------------------
# The verdict: everything decided, and nothing about which arm decided it
# --------------------------------------------------------------------------------------------


class Verdict(_MediationModel):
    """What the pipeline concluded about one request, before the mode has been consulted.

    Every field of the audit record except ``ts``, the two mode-dependent fields and the three the
    chain assigns. That is not a coincidence of layout: it is the statement that everything a record
    says about *what happened* is decided without reference to the arm, which is ADR-023's
    isolation assertion 2 expressed as a data structure rather than as a test.

    ``action`` is null exactly when no request was ever parsed -- the oversize and malformed-body
    cases. It is :class:`~guardian.app.models.AuditedAction` rather than
    :class:`~guardian.app.models.ActionSpec` because the audited projection is the one that carries
    ``justification``, and security-policy section 1.5 requires the justification to be logged. The
    executor is handed a projection *back* to an ``ActionSpec`` by :func:`executable_action`, so the
    Guardian executes exactly the action it drafted a record for.

    ``token_jti`` and ``iss`` are populated only from verified values. An accepted claim set is the
    usual source; an authentic subject- or phase-mismatch refusal may retain the pair after
    signature verification and issuer registration. A forged, malformed or group-A token carries
    only *claimed* values, and copying one into an attribution field would record attacker-authored
    text as though the Guardian had established it; a null plus a group-A reason code is the honest
    record
    of "we do not know who this was, and here is why". ``models.py`` states that reading for the
    record; this class is where it is produced.

    ``caps_reservation`` (ADR-129) is the handle :meth:`Mediator._settle_caps` needs to finish what
    :func:`adjudicate` started, and it is here rather than in a return tuple because the module's
    structural property is that everything a decision needs travels on this one inert object until
    :meth:`Mediator._seal` turns it into a record. It is never a record field: what the record
    carries is the *counters*, not the keys, for the reason
    :class:`~guardian.app.models.ActionCapReservation` gives.
    """

    decision: Decision
    reason_code: ReasonCode
    policy_rule_id: Identifier | None
    run_id: Identifier | None
    request_id: Identifier | None
    token_jti: Identifier | None
    iss: Identifier | None
    action: AuditedAction | None
    caps_reservation: ActionCapReservation | None = None

    @model_validator(mode="after")
    def _check_decision_consistency(self) -> "Verdict":
        """Reject a verdict whose decision, reason group and rule id disagree.

        The same invariant :class:`~guardian.app.models.ActionResult` and
        :class:`~guardian.app.models.AuditRecord` enforce, applied here so that a contradiction is
        caught while a decision is being *formed* rather than while it is being *recorded*. The
        difference matters: a failure at append is a failure after the point of no return.
        """
        _validate_decision_consistency(self.decision, self.reason_code, self.policy_rule_id)
        return self

    @classmethod
    def refusal(cls, reason_code: ReasonCode, *, run_id: Identifier | None) -> "Verdict":
        """Return a verdict for a request that never became one: no action, no attribution.

        The oversize and malformed-body path, and the Guardian-fault path. Nothing the body carried
        was established -- not who sent it, not which request it was, not what it asked for -- so
        every one of those is null. Security-policy section 1.4 still requires the refusal to be
        audited, which is why a record shape that can describe it exists at all.

        ``run_id`` is the one exception, and where it comes from is the whole argument. It is the
        run this *Guardian* was started for -- start-time configuration, handed in by
        :class:`Mediator` -- and never anything the body said, so writing it records no
        attacker-authored text as established. It was null here until ADR-058, and every such
        record then broke ADR-054's rule that each Guardian record carries its bundle's run id,
        which analysis enforces as a hard error. It is required with no default so that no future
        caller can drop it by omission; null remains the honest value only for a Guardian that
        pins no run.
        """
        if reason_code.group is ReasonGroup.PERMIT:
            raise ValueError(
                f"{reason_code.value!r} is the permit vocabulary; a request that never parsed "
                "cannot have been permitted"
            )
        return cls(
            decision=Decision.DENY,
            reason_code=reason_code,
            policy_rule_id=None,
            run_id=run_id,
            request_id=None,
            token_jti=None,
            iss=None,
            action=None,
        )


reject_field_names(
    Verdict,
    MODE_SHAPED_FIELD_NAMES,
    why=(
        "a verdict is produced by a mode-blind function and must not be able to carry the arm out "
        "of it; ADR-023's isolation assertion 2 permits the G0-versus-G1 audit difference to reach "
        "only guardian_mode, the enforcement field and the execution block, and a mode-shaped "
        "field here would be a fourth route"
    ),
)
reject_field_types(
    Verdict,
    (GuardianMode,),
    why=(
        "no field of a verdict may be typed GuardianMode under any name; the arm reaches the audit "
        "draft through enforcement_for and by no other route"
    ),
)


# --------------------------------------------------------------------------------------------
# The audit draft: the record body, minus the three fields the chain owns
# --------------------------------------------------------------------------------------------


class AuditDraft(_MediationModel):
    """Everything an :class:`~guardian.app.models.AuditRecord` carries except ``seq``/``prev_hash``/
    ``hash``.

    The object handed to :class:`AuditSink`. Field order matches
    :class:`~guardian.app.models.AuditRecord`'s so that a reader comparing the two finds them in the
    same sequence; the canonical serialiser sorts keys, so declaration order affects no bytes.

    This is the **only** place in the module where ``guardian_mode`` and ``enforcement`` exist
    together with the rest of the record, and it is therefore the only place the arm is visible on
    the decision path. Both values arrive already computed -- the mode from
    :class:`~guardian.app.config.GuardianConfig`, the enforcement from :func:`enforcement_for` --
    and everything else is copied from a :class:`Verdict`. That copy is what confines ADR-023's
    permitted difference to two record fields and one field of the result.

    Both of :class:`~guardian.app.models.AuditRecord`'s body invariants are enforced here, on
    purpose and by importing the same two functions the record uses rather than restating them.
    ``models.py`` names this class specifically: a draft that the sealed record would reject is a
    failure that surfaces *after* the append, and the append is the one operation in this pipeline
    that must not fail. The chain invariant -- ``prev_hash`` null exactly at ``seq`` zero -- is not
    checked here, because none of those three fields exists on a draft. Chain arithmetic is
    ``guardian/audit/``'s, per ADR-022.

    ``action_caps`` is the draft's ``None`` only in the sense the record's is: a decision made
    before its token was verified reserved nothing, so it reports no counters rather than six
    zeroes.
    The mapping from a reservation to this field happens once, in :meth:`Mediator._seal`, so the
    question of which object owns a counter is settled in a single expression rather than at every
    construction site.
    """

    ts: RecordTimestamp
    run_id: Identifier | None
    request_id: Identifier | None
    token_jti: Identifier | None
    iss: Identifier | None
    decision: Decision
    reason_code: ReasonCode
    policy_rule_id: Identifier | None
    action: AuditedAction | None
    guardian_mode: GuardianMode
    enforcement: Enforcement
    record_type: Literal[AUDIT_RECORD_TYPE_DECISION]
    schema_version: Literal[AUDIT_RECORD_SCHEMA_VERSION]
    # ADR-129. Nullable rather than defaulted, unlike the record's: a draft is always built by
    # _seal, so there is never a caller relying on an omission here, and a field that could be
    # forgotten is a record that silently reports no caps.
    action_caps: ActionCapCounters | None

    @model_validator(mode="after")
    def _check_draft_consistency(self) -> "AuditDraft":
        """Reject a draft the sealed record would reject, at the point it is still cheap."""
        _validate_decision_consistency(self.decision, self.reason_code, self.policy_rule_id)
        _validate_action_enforcement(self.action, self.enforcement)
        return self


reject_field_names(
    AuditDraft,
    SECRET_SHAPED_FIELD_NAMES,
    why=(
        "audit records are born clean (ADR-022, plan conflict M3-C5), and the draft is what is "
        "actually handed to the sink -- so the guard models.py applies to AuditRecord has to apply "
        "here too, or a secret-shaped field could be introduced on the one object that reaches the "
        "chain"
    ),
)


# --------------------------------------------------------------------------------------------
# Enforcement: the single expression on the decision path that reads the mode
# --------------------------------------------------------------------------------------------


def enforcement_for(decision: Decision, mode: GuardianMode, *, action_formed: bool) -> Enforcement:
    """Return what the Guardian does about ``decision`` under ``mode``.

    **This is the only place in the mediation path where the Guardian mode is read.** Everything
    else about a record comes from a :class:`Verdict`, which a mode-blind function produced and
    which is guarded against carrying a mode at all. Confining the arm to one three-branch function
    is what makes ADR-023's isolation assertion 2 a property of the code rather than an observation
    about a particular test run.

    The three readings, and each is
    :class:`~guardian.app.models.Enforcement`'s definition rather than an interpretation of it:

    ``not-applicable`` when no action was formed. Mode-independent, deliberately: ``G1-LOGONLY``
    does not resurrect an action that never parsed, so an oversize body is refused identically in
    every arm and the G0/G1 diff on such a record is empty but for ``guardian_mode``.

    ``executed`` when the decision is a permit, in every arm. A permit that the Guardian passes on
    is the ordinary case and no arm changes it.

    ``executed`` when the decision is a deny and the arm is ``G1-LOGONLY``; ``blocked`` otherwise.
    That single line is the entire content of the G1 arm -- the Guardian logs but does not block --
    and it applies to *every* denial, an unverifiable token included, because the arm removes
    enforcement rather than removing some of it. ``G2-SHAREDCRED`` blocks exactly as ``G0-FULL``
    does: its delta is the environment, the NetworkPolicy and the issued credential, and ADR-024
    records that its agent-side surface is an open question rather than a Guardian behaviour.
    """
    if not action_formed:
        return Enforcement.NOT_APPLICABLE
    if decision is Decision.PERMIT:
        return Enforcement.EXECUTED
    if mode is GuardianMode.G1_LOGONLY:
        return Enforcement.EXECUTED
    return Enforcement.BLOCKED


# --------------------------------------------------------------------------------------------
# The collaborator seams
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenVerification:
    """A verdict on one presented capability token: accepted with claims, or refused with a code.

    A value rather than an exception, for the reason ``guardian/token/verifier.py`` gives about its
    own outcome type and which is worth repeating because it is the same argument this whole module
    turns on: every denial has to be *audited*, and a value the caller must consume is far harder to
    drop than an exception a caller can catch and ignore.

    Exactly one of ``claims`` and ``reason_code`` is set, checked at construction so that a partial
    outcome cannot travel. A refusal may additionally carry the all-or-neither pair ``verified_jti``
    and ``verified_issuer``, but only for subject or phase mismatch: those checks happen after the
    signature, claim shape and issuer registration are established. This keeps authentic crossed
    capabilities attributable without ever trusting fields from forged, malformed or group-A
    tokens. ``reason_code`` is drawn from :class:`~guardian.app.models.ReasonCode` -- the *app*
    vocabulary, carrying the threat-model family in the value -- which is what the adapter around a
    real verifier is responsible for producing. It may not be a permit-group code: a token being
    authentic is not the same event as an action being permitted, and one code meaning both would
    make the policy-compliant action rate uncomputable.

    The raw bearer string never appears on this object or in any exception raised from the pipeline.
    """

    claims: CapabilityTokenClaims | None
    reason_code: ReasonCode | None
    verified_jti: Identifier | None = None
    verified_issuer: Identifier | None = None

    def __post_init__(self) -> None:
        if (self.claims is None) == (self.reason_code is None):
            raise ValueError(
                "a token verification carries claims or a reason code, never both and never "
                "neither: an outcome that is both would let a refused token reach policy, and an "
                "outcome that is neither would deny with nothing to record"
            )
        if self.reason_code is not None and self.reason_code.group is ReasonGroup.PERMIT:
            raise ValueError(
                f"{self.reason_code.value!r} is the permit vocabulary and cannot refuse a token"
            )
        attributed = self.verified_jti is not None or self.verified_issuer is not None
        if (self.verified_jti is None) != (self.verified_issuer is None):
            raise ValueError("verified jti and issuer attribution must be present together")
        attributable_codes = {
            ReasonCode.SCOPE_SUBJECT_MISMATCH,
            ReasonCode.SCOPE_PHASE_MISMATCH,
        }
        if attributed and (self.claims is not None or self.reason_code not in attributable_codes):
            raise ValueError("only subject- or phase-mismatch refusals may carry attribution")

    @property
    def accepted(self) -> bool:
        """``True`` when the token was authentic, live, in scope and unspent."""
        return self.claims is not None

    @classmethod
    def accept(cls, claims: CapabilityTokenClaims) -> "TokenVerification":
        """Return an accepting outcome carrying the validated claim set."""
        return cls(claims=claims, reason_code=None)

    @classmethod
    def refuse(
        cls,
        reason_code: ReasonCode,
        *,
        verified_jti: Identifier | None = None,
        verified_issuer: Identifier | None = None,
    ) -> "TokenVerification":
        """Return a refusal, optionally carrying already-verified attribution."""
        return cls(
            claims=None,
            reason_code=reason_code,
            verified_jti=verified_jti,
            verified_issuer=verified_issuer,
        )


@runtime_checkable
class TokenVerifier(Protocol):
    """Everything the pipeline needs to know about a presented token, in one call.

    An implementation answers four questions and returns one outcome: is this token authentic
    (group A), is it live and within its permitted lifetime (group B), does it cover this run
    (group C), and has this ``jti`` already been spent (group D). Which of the four failed is
    carried in the reason code, because the M3 plan's adversarial table decomposes exactly that way
    and RQ5's per-class analysis reads it.

    ``bearer`` is typed ``object`` rather than ``str`` on purpose. It arrives from an HTTP body
    under threat-model position P2 and may be any JSON value at all, so a ``str`` annotation would
    be a promise the caller cannot keep. An implementation **must not raise** on hostile input;
    every path returns a :class:`TokenVerification`.

    ``expected_run_id`` is the run *this process* was started for, never the one the request
    claimed. ``ActionRequest.run_id`` is attacker-settable, so an Executor holding a token minted
    for another run can simply set the request field to match the token and pass any
    self-consistency check.

    ``expected_phase`` and ``expected_subject`` are the opposite: they come from the *request*, and
    the asymmetry with ``expected_run_id`` is the single most important thing to understand about
    this signature. There is no process-level value they could be taken from. A Guardian pinned to
    one phase and one Executor is a Guardian that cannot serve a four-phase run, which is what M4's
    conflict M4-C5 records; taking them from the token being checked would make the check compare a
    value with itself. So they are the sender's declaration, checked against the verified ``sub``
    and ``phase`` claims -- **attribution, not authentication**, argued at length on
    :class:`~guardian.app.models.ActionRequest` and recorded in ADR-030 as a Chapter 5 limitation.

    What is deliberately *not* a parameter is the set of registered issuers and the token
    parameters ``security-policy.md`` section 2 owns. Both are start-time configuration and belong
    in the implementation's construction, not in a per-request argument: a registry that could vary
    per call is a registry a caller could vary.

    **The two reconciliations this protocol recorded as owed are now discharged, and how they were
    settled is kept here rather than deleted -- a paragraph that says only "resolved" leaves the
    next reader to rediscover why the seam has the shape it has.**

    First, the verifier required an ``expected_phase`` and an ``expected_subject`` that an
    :class:`~guardian.app.models.ActionRequest` did not carry. That was settled by amending the
    request contract: ``ActionRequest`` is at ``v2`` and carries ``executor_id`` and ``phase``, the
    two parameters above are supplied per request from those fields, and
    :attr:`~guardian.app.models.ReasonCode.SCOPE_PHASE_MISMATCH` and
    :attr:`~guardian.app.models.ReasonCode.SCOPE_SUBJECT_MISMATCH` are producible from this seam by
    a Guardian serving every phase of a run. The rejected alternative was the harness's:
    start-time configuration with no default, which is fail-closed and correct for a test and
    implies one Guardian process per ``(phase, executor)`` pair. The amendment
    ``docs/02-architecture.md`` section 3 is owed for the two new fields is named on
    ``ActionRequest`` itself.

    Second, the issuer was recorded as not stamping
    :data:`~guardian.app.models.CAPABILITY_TOKEN_SCHEMA_VERSION` into the tokens it mints, which
    would have made this Guardian refuse its own credentials under
    :attr:`~guardian.app.models.ReasonCode.TOKEN_CLAIMS_MALFORMED`. That reading was **stale rather
    than wrong when written**: ``guardian/token/issuer.py`` stamps the claim at the point of
    signing, from a constant whose two homes ``guardian/tests/test_token_contract_seam.py`` holds
    equal, and a minted token verifies. Nothing was changed to discharge it; what was added is a
    regression case that mints through the real issuer and asserts the claim decodes and validates,
    so the property cannot lapse silently.
    """

    def verify(
        self,
        bearer: object,
        *,
        expected_run_id: str | None,
        expected_phase: str,
        expected_subject: str,
    ) -> TokenVerification:
        """Return a verdict on ``bearer`` for this run, and for the phase and Executor declared."""
        ...


@runtime_checkable
class TokenIssuer(Protocol):
    """The ``POST /v1/tokens`` surface's collaborator: mint one capability token, or refuse.

    An implementation stamps ``iss`` and ``sub`` from the *authenticated* identity of the caller,
    never from values an Executor supplied -- an Executor that could name its own ``sub`` could mint
    itself another Executor's scope. It applies the per-phase override ceiling
    ``security-policy.md`` section 2 owns, and it **refuses rather than truncates** a lifetime above
    it, because a control that quietly substitutes its own answer reports success for something
    other than what was asked.

    It raises :class:`TokenIssuanceRefused` with a structured code. It does not return a sentinel:
    an issuance that failed and a token that was minted are different shapes, and a nullable token
    field would be a field every caller has to have an opinion about.

    **This surface is not authenticated, the gap is named rather than hidden, and what has changed
    is its consequence rather than its existence.**
    :class:`~guardian.app.models.TokenIssueRequest`'s docstring records it too: ``supervisor_id``
    and ``executor_id`` are self-declared, nothing in the model establishes that the caller is the
    Supervisor it names, and the threat model gives the agent layer network reach to this surface
    (position P4).

    M4's conflict M4-C6 showed that this was worse than the issue side alone could see:
    ``guardian.rego`` grants exactly what the token's allow-claim covers, so an unauthenticated
    party that could mint a claim could obtain the permit that follows from it, and the mediated arm
    would not be mediated. The answer taken is *not* an authentication this deployment shape cannot
    provide -- see FR3.1 -- but a **bound on what may be minted**: the composition root wraps the
    implementation behind this protocol with a deny-by-default authority check in the same OPA
    bundle, and an over-wide request is refused with :class:`TokenIssuanceRefused` carrying
    ``issue_authority_exceeded``. An unauthenticated mint therefore grants nothing an authorised
    Supervisor could not already have obtained.

    The residual gap is recorded rather than closed, and it is exactly this: caller identity is
    still not established, so a party reaching this surface can still mint *within* the declared
    authority and can still name any ``iss`` and any ``sub`` it likes. ADR-031, and
    ``guardian/tests/test_token_issuance_exposure.py``, which is written as a demonstration of what
    remains open rather than as a test of a defence that exists.
    """

    def issue(self, request: TokenIssueRequest) -> TokenIssueResponse:
        """Mint one token for ``request``, or raise :class:`TokenIssuanceRefused`."""
        ...


@runtime_checkable
class ActionExecutor(Protocol):
    """The only thing in this system permitted to change the cluster, behind one method.

    The real implementation is Tier B: it holds the Guardian's ServiceAccount -- the sole credential
    with cluster-mutation rights under ``security-policy.md`` section 1.2 -- and it is gated on M1
    delivering a kind cluster. Everything above it is written and testable now because this is a
    protocol rather than a client.

    An implementation is reached **only** from :meth:`Mediator._seal`, and only after an audit
    record has been sealed. It receives an :class:`~guardian.app.models.ActionSpec` that has already
    passed the contract grammars, so ``namespace`` is a DNS-1123 label and ``name`` is a DNS-1123
    subdomain and neither can hold a traversal, a scheme, a percent-escape or a homoglyph.

    It should not raise; :meth:`Mediator._execute` catches anyway and records a failed attempt,
    because an exception escaping here would turn a permitted-and-audited decision into a response
    the caller never receives, leaving the log claiming an execution the caller cannot see.
    """

    def execute(self, action: ActionSpec, *, request_id: str) -> ExecutionOutcome:
        """Attempt ``action`` and report what happened. Never raises for an ordinary failure."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Seal one draft into the hash chain and return the record as written.

    The return type is the sealed :class:`~guardian.app.models.AuditRecord`, not a mapping, and that
    choice is what makes "no decision without an append" a type-level property: ``seq`` exists only
    on a record, :class:`~guardian.app.models.ActionResult` requires it, and
    :func:`result_from_record` is the only constructor of one.

    An implementation appends -- it never rewrites, never reorders and never redacts. ADR-022 is
    explicit that a log the writer is permitted to rewrite is a log whose verification proves only
    that the writer rewrote it consistently.

    **The adapter over ``guardian/audit/chain.py`` has one reconciliation to make, and it is
    flagged here because the two landed contracts disagree.** ``AuditChainWriter`` represents the
    genesis predecessor as sixty-four ``0`` characters, while
    :class:`~guardian.app.models.AuditRecord` requires ``prev_hash`` to be *null* exactly at
    ``seq`` zero and rejects any record where that does not hold. Both are deliberate and neither
    can be edited from here: the sentinel is what the chain hashes at the first link, and the null
    is what the record contract states. Whoever wires the two must decide which representation the
    ``AuditRecord`` carries, note that the stored ``hash`` was computed over the *other* one, and
    record the choice -- it is a genuine cross-file conflict under
    ``.agents/rules/00-source-of-truth.md``, not an implementation detail.
    """

    def append(self, draft: AuditDraft) -> AuditRecord:
        """Append ``draft`` to the chain and return the sealed record, or raise."""
        ...

    def append_execution(self, draft: ExecutionRecordDraft) -> ExecutionRecord:
        """Append an execution follow-up (ADR-082) and return the sealed record, or raise.

        A second method rather than a wider ``append`` accepting either draft shape, on the pattern
        :class:`AuditChainSink`'s own ``record_run_start`` already sets: the two writes have
        different callers, different timing and different failure handling --
        :meth:`Mediator._seal` treats a failure here as best-effort (see
        :meth:`Mediator._append_execution_record`), while a failed decision append is
        :class:`AuditUnavailable` -- and a single overloaded method would blur a distinction that
        matters to every caller of this protocol.
        """
        ...


class FakeActionExecutor:
    """An executor that touches nothing and remembers everything. The pipeline's test double.

    T3.1's requirement is that "execution sits behind an interface with a fake implementation, so
    the whole pipeline is testable before a cluster exists", and this is that fake. It exists in the
    shipped module rather than in a test file for one reason worth stating: it is the executor a
    Guardian is given when there is no cluster, and having exactly one such object -- named, with a
    docstring saying what it is not -- is better than each test growing its own, which is how a
    "fake" eventually acquires behaviour somebody starts relying on.

    It imports no Kubernetes client and shells out to nothing, which is the same prohibition
    ``.agents/rules/10-guardian-first.md`` places on ``agents/`` and is checked for this package by
    ``scripts/grep_guard.sh``. ``calls`` records every action it was asked to perform, in order, so
    that a test can assert the *negative* case that matters most: under ``G0-FULL`` a denial leaves
    this list untouched, and under ``G1-LOGONLY`` the identical denial appends to it.

    ``status`` is settable so that the failed-execution path can be driven without an executor that
    raises. A failed attempt is still an attempt that was not blocked, which is what the
    policy-compliant action rate counts, and the difference is only visible if a test can produce
    one.
    """

    def __init__(
        self,
        *,
        status: ExecutionStatus = ExecutionStatus.SUCCEEDED,
        stdout_ref: str | None = None,
    ) -> None:
        self.status = status
        self.stdout_ref = stdout_ref
        self.calls: list[tuple[str, ActionSpec]] = []

    def execute(self, action: ActionSpec, *, request_id: str) -> ExecutionOutcome:
        """Record the attempt and report the configured outcome. Changes nothing anywhere."""
        self.calls.append((request_id, action))
        return ExecutionOutcome(status=self.status, stdout_ref=self.stdout_ref)


# --------------------------------------------------------------------------------------------
# Projections
# --------------------------------------------------------------------------------------------


def audited_action(request: ActionRequest) -> AuditedAction:
    """Project a request onto the audited action: the five action fields plus the justification.

    ``justification`` travels with the action rather than beside it because
    ``docs/protocols/security-policy.md`` section 1.5 requires it to be *logged* and M3-T3.6's
    replay must reconstruct "what was attempted, and the reason given for it" -- which is one fact,
    not two. The bound is the contract's; scrubbing it before hashing is ``guardian/audit/``'s, and
    is what makes ``data-management.md`` section 5's pre-seal sanitizer a no-op on this file.

    ``params`` goes through :func:`~guardian.app.models.recordable_params` rather than verbatim,
    and this is the **one** place that happens, because this is the one place attacker-chosen keys
    become a record body. Verbatim, a caller sending ``params: {"api_key": "..."}`` made
    ``guardian/audit/chain.py`` refuse the append, which :mod:`guardian.app.main` answers as a 503
    with **no record written at all** -- so a caller could act in a way ``guardian_audit.jsonl``
    does not contain, which is the M3 plan's threat-model corollary happening rather than being
    guarded against. The projection is the identity on every key that is not credential-shaped, so
    a legitimate action's record is unchanged; the rule and the reasoning are stated once, beside
    :data:`~guardian.app.models.UNRECORDABLE_PARAM_NAMES`.

    **``ActionRequest`` v2's ``executor_id`` and ``phase`` are deliberately NOT projected into the
    record, and the decision is taken here rather than left implicit.** The tempting reading is that
    a record should say who presented the request, and this projection is where that would land.
    Three arguments say otherwise, and they run in the same direction.

    *The attribution security-policy section 1.4 asks for is already there, in verified form.* That
    section requires the record to carry the token ``jti`` and the issuer, and
    :class:`~guardian.app.models.AuditRecord` carries both -- populated only from values the
    verifier authenticated, including the retained pair on subject- and phase-mismatch refusals. The
    capability's ``sub`` is the Executor the Guardian *established* the token
    was minted for; ``request.executor_id`` is what the sender *said*. Putting the second beside the
    first would place an attacker-authored string in the same record as an established one, in
    adjacent fields, distinguishable only by somebody remembering which was which -- and a record is
    read months later, in a data frame, by somebody who was not here.

    *When the two disagree the request never reaches this projection.* The verifier refuses under
    :attr:`~guardian.app.models.ReasonCode.SCOPE_SUBJECT_MISMATCH` or
    :attr:`~guardian.app.models.ReasonCode.SCOPE_PHASE_MISMATCH`, the reason code is in the chain,
    and the record already says exactly what happened while retaining the token's verified ``jti``
    and issuer. The request declaration would therefore add only attacker-authored text, not
    stronger attribution.

    *Architecture section 3's record field list is closed, and this module does not get to open it.*
    :class:`~guardian.app.models.AuditRecord` already carries three fields section 3 does not list,
    each argued in its own conflict and its own ADR, and the amendment section 3 owes for
    ``policy_rule_id`` is still outstanding. Adding a fourth on a "records should say who" intuition
    -- with no protocol asking for it and both RQ5 measures computable without it -- would be
    exactly the carelessly-added field ``models.py``'s docstring opens by warning about, in the one
    contract four milestones then depend on.

    What would change this is a genuine subject binding: were the presenting identity ever
    *established* rather than declared -- per-executor transport identity, which FR3.1's "no
    standing credentials" currently precludes -- then it would be a fact worth recording, and it
    would be recorded as one field, not two. That is Chapter 5's, and ADR-030's.
    """
    action = request.action
    return AuditedAction(
        verb=action.verb,
        resource=action.resource,
        namespace=action.namespace,
        name=action.name,
        params=recordable_params(action.params),
        justification=request.justification,
    )


def executable_action(audited: AuditedAction) -> ActionSpec:
    """Project an audited action back onto the spec the executor is handed.

    The reverse of :func:`audited_action`, minus the justification, which is evidence rather than
    instruction and has no business reaching a cluster. Going through the audited projection rather
    than keeping the original :class:`~guardian.app.models.ActionSpec` alongside it is deliberate:
    it makes "the Guardian executes exactly the action it drafted a record for" true by
    construction, where holding two objects would make it true by their happening to agree.

    **This function is unchanged by the withholding rule, and that is the point rather than an
    omission.** :func:`~guardian.app.models.recordable_params` is the identity on every key that is
    not credential-shaped, so what a legitimate action executes is byte-identical to what it always
    was. It could not be made "audit-side only" in any case: the two available shapes are keeping
    the original spec beside the audited one, which is the arrangement the paragraph above rejects,
    and reversing the transformation here, which is impossible once a value has been withheld. The
    residue is that under ``G1-LOGONLY`` -- the arm in which a denial is still executed -- an
    executor handed such an action sees :data:`~guardian.app.models.WITHHELD_PARAM_VALUE` rather
    than the credential the agent supplied. That is the correct residue: ``G1-LOGONLY`` removes
    *enforcement*, and a record that never carries a credential is ADR-022's born-clean rule, which
    is not an enforcement property and does not vary by arm. Under ``G0-FULL`` the question does
    not arise, because such a request is denied and blocked and no executor is reached at all.
    """
    return ActionSpec(
        verb=audited.verb,
        resource=audited.resource,
        namespace=audited.namespace,
        name=audited.name,
        params=audited.params,
    )


def result_from_record(record: AuditRecord, execution: ExecutionOutcome) -> ActionResult:
    """Build the response from a sealed record. **The only construction site of an ActionResult.**

    Every outcome field is copied from the record rather than from anything the pipeline still
    holds, so the answer the caller receives and the record the study is scored from cannot
    disagree: they are the same values, read once. ``audit_seq`` comes from ``record.seq``, whose
    only source is an append that already happened -- which is what makes an unaudited decision
    unrepresentable rather than merely unlikely.

    ``execution`` is the one thing the record does not carry, for the reason the module docstring
    gives about ordering: the append precedes the attempt, so whether the cluster succeeded is not
    knowable when the record is written. :attr:`~guardian.app.models.Enforcement.EXECUTED` on the
    record means the Guardian did not block; this field means what happened next.
    """
    return ActionResult(
        decision=record.decision,
        reason_code=record.reason_code,
        policy_rule_id=record.policy_rule_id,
        execution=execution,
        audit_seq=record.seq,
        schema_version=ACTION_RESULT_SCHEMA_VERSION,
    )


# --------------------------------------------------------------------------------------------
# Adjudication: mode-blind by construction
# --------------------------------------------------------------------------------------------


def adjudicate(
    request: ActionRequest,
    *,
    verifier: TokenVerifier,
    policy_engine: PolicyEngine,
    caps: ActionCapReserver,
    expected_run_id: str | None,
    evaluation_timeout_seconds: float,
) -> Verdict:
    """Decide what happened, without any knowledge of which arm the Guardian is running in.

    A module-level function rather than a method, and that is the design rather than a style
    preference: with no ``self`` there is no :class:`~guardian.app.config.GuardianConfig`, and with
    no configuration there is no mode. :func:`assert_mode_blind` is applied to this function
    immediately below and refuses the import if any parameter is named or typed like a mode flag, so
    the property survives a future edit that adds an argument innocently.

    Four steps, in the order T3.1 fixes and for the reasons the module docstring gives:

    1. **Verify the token**, against the run this process was started for and against the phase and
       Executor the request declares. A refusal ends adjudication with the verifier's structured
       reason. Attribution is null unless the verifier retained an authenticated ``jti`` and issuer
       for a subject- or phase-mismatch refusal; forged, malformed and other group-A refusals never
       contribute claimed values. The action is still carried, because the request did parse and
       what was attempted is exactly what the audit chain exists to hold.

       The two declared values are passed straight through, unnormalised and unchecked by this
       function, and that is deliberate on both counts. Normalising them here would mean this
       function deciding what counts as the same Executor, which is a scope question belonging to
       the verifier; checking them here would put a second refusal path beside the one that already
       produces :attr:`~guardian.app.models.ReasonCode.SCOPE_PHASE_MISMATCH` and
       :attr:`~guardian.app.models.ReasonCode.SCOPE_SUBJECT_MISMATCH` with the right codes.
    2. **Refuse a credential-shaped ``params`` key.** A request whose parameters had to be withheld
       from the record to keep it appendable is not one to execute: security-policy section 1.5's
       spirit is that agent-supplied text is evidence and never instruction, and a Guardian that
       permitted an action it could not record faithfully would be permitting on strictly less
       information than it logged. It denies under
       :attr:`~guardian.app.models.ReasonCode.POLICY_PARAM_NAME_FORBIDDEN`, keeping the action --
       which by then carries the withheld keys, so the record says what the agent tried.

       **Placed after step 1 and not before it**, deliberately. A forged token presented alongside
       a credential-shaped parameter is an authenticity finding first: putting this check earlier
       would let a caller mask a group A denial behind a group E one by adding a key, and would
       cost the record its ``jti`` and ``iss`` attribution for no gain. Placed *before* step 4 for
       the mirror-image reason -- the policy engine cannot see ``params`` at all, so it has nothing
       to say about this, and asking it anyway would spend a decision on a question it is not
       shown.
    3. **Reserve against the two action caps** (ADR-129), which is why this step exists at all and
       why it is here and not one place earlier or later. After the verification, because the
       per-token counter is keyed on the *verified* ``jti`` and a claimed one is an attacker-chosen
       key. Before the evaluation, because a budget checked after the policy has already permitted
       is a budget that every concurrently-arriving request passes before any of them learns it was
       gone. A cap refusal is a full denial -- the action, the ``jti`` and the issuer are all
       carried
       -- and it is the one denial on this path that is about a *bound* rather than about the action
       or the policy, which is why it has its own code
       (:attr:`~guardian.app.models.ReasonCode.SCOPE_ACTION_CAP_EXCEEDED`) and why a run's
       refusals must not be able to spend the budget that its permits draw on. The settlement is not
       here: it needs the decision, and :meth:`Mediator._settle_caps` is where the decision and the
       arm are both in hand.
    4. **Build the OPA input document.** It requires a verified claim set by type, so this step
       cannot run before step 1 succeeded. ``justification`` and ``params`` are excluded from it by
       a partition checked at import; see :mod:`guardian.app.policy`.
    5. **Evaluate.** :func:`~guardian.app.policy.evaluate_policy` never raises and never permits on
       an error path, so an engine outage, an overrun or an unreadable answer arrives here as a
       denial with a code saying which.

    The ``run_id`` written into the record is the Guardian's own when the process pinned one, and
    the request's otherwise. A record is evidence produced by *this* Guardian in *this* run and
    ``analysis/`` groups by that field, so letting an attacker-settable value decide which run a
    record belongs to would let the agent layer scatter its own denials across runs. The claim the
    request made is not lost: a mismatch is what the verifier denies on, under
    :attr:`~guardian.app.models.ReasonCode.SCOPE_RUN_MISMATCH`. **The per-run cap is keyed on the
    same value**, deliberately: it is the only run identity the Guardian can establish, and a cap
    keyed on a different one would be a cap an attacker could step outside by varying a field.
    """
    action = audited_action(request)
    run_id = expected_run_id if expected_run_id is not None else request.run_id

    verification = verifier.verify(
        request.token,
        expected_run_id=expected_run_id,
        expected_phase=request.phase,
        expected_subject=request.executor_id,
    )
    if not verification.accepted:
        return Verdict(
            decision=Decision.DENY,
            reason_code=_refusal_code(verification),
            policy_rule_id=None,
            run_id=run_id,
            request_id=request.request_id,
            token_jti=verification.verified_jti,
            iss=verification.verified_issuer,
            action=action,
        )

    claims = verification.claims
    if claims is None:  # pragma: no cover - TokenVerification's invariant makes this unreachable
        raise MediationError("an accepted verification carried no claims")

    if forbidden_param_names(request.action.params):
        return Verdict(
            decision=Decision.DENY,
            reason_code=ReasonCode.POLICY_PARAM_NAME_FORBIDDEN,
            policy_rule_id=None,
            run_id=run_id,
            request_id=request.request_id,
            token_jti=claims.jti,
            iss=claims.iss,
            action=action,
        )

    # ADR-129: the reserve, before the engine is asked anything. `run_id` is the Guardian's own
    # wherever it pinned one (the docstring above), and `claims.jti` is the verified one -- the two
    # keys the caps count against, and neither of them attacker-chosen at this point.
    reservation = caps.reserve(run_key=run_id, token_key=claims.jti)
    if not reservation.granted:
        return Verdict(
            decision=Decision.DENY,
            reason_code=ReasonCode.SCOPE_ACTION_CAP_EXCEEDED,
            policy_rule_id=None,
            run_id=run_id,
            request_id=request.request_id,
            token_jti=claims.jti,
            iss=claims.iss,
            action=action,
            caps_reservation=reservation,
        )

    document = build_policy_input(request=request, claims=claims, guardian_run_id=expected_run_id)
    outcome: PolicyDecision = evaluate_policy(
        policy_engine, document, timeout_seconds=evaluation_timeout_seconds
    )
    return Verdict(
        decision=outcome.decision,
        reason_code=outcome.reason_code,
        policy_rule_id=outcome.rule_id,
        run_id=run_id,
        request_id=request.request_id,
        token_jti=claims.jti,
        iss=claims.iss,
        action=action,
        caps_reservation=reservation,
    )


def _refusal_code(verification: TokenVerification) -> ReasonCode:
    """Return the verifier's reason code, or a Guardian fault if it somehow supplied none.

    :class:`TokenVerification`'s own invariant makes the fallback unreachable through the
    constructor, and it is here anyway because this is the enforcement path: a ``None`` reaching
    :class:`Verdict` would raise inside a model validator during adjudication, and a Guardian fault
    that denies and audits is a strictly better outcome than one that unwinds.
    """
    return verification.reason_code or ReasonCode.POLICY_GUARDIAN_FAULT


assert_mode_blind(
    adjudicate,
    why=(
        "adjudicate produces the decision, the reason code and the policy rule id, and ADR-023's "
        "isolation assertion 2 requires all three to be identical across G0-FULL and G1-LOGONLY. A "
        "parameter able to carry the arm into this function is a parameter able to make them "
        "differ, and the field-by-field diff would then be checking an outcome instead of a "
        "mechanism"
    ),
)


# --------------------------------------------------------------------------------------------
# The mediator
# --------------------------------------------------------------------------------------------


class Mediator:
    """The pipeline, assembled once and asked one question at a time.

    Construction takes the configuration and the four collaborators. Nothing is read from the
    environment here -- :class:`~guardian.app.config.GuardianConfig` already did that, once, at
    process start -- and nothing is constructed lazily, so a Guardian that is going to fail because
    a collaborator is missing fails while it is being built rather than in front of a request.

    The two entry points are :meth:`decide`, for a request that parsed, and :meth:`reject`, for a
    body that did not. Both have exactly one ``return`` and both go through :meth:`_seal`, which is
    the only method that touches the audit sink or the executor. That is the shape the module
    docstring's first structural property rests on.
    """

    def __init__(
        self,
        *,
        config: GuardianConfig,
        policy_bundle: PolicyBundle,
        policy_engine: PolicyEngine,
        verifier: TokenVerifier,
        executor: ActionExecutor,
        audit_sink: AuditSink,
        caps: ActionCapReserver,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if config.run_id is not None and not _is_record_identifier(config.run_id):
            raise GuardianStartupError(
                f"the configured run id {config.run_id!r} is not writable into an audit record. "
                "Every record this Guardian produces would be refused by the chain, so it does not "
                "start: a run id is an identifier, matching "
                f"{IDENTIFIER_PATTERN} and at most {IDENTIFIER_MAX_CHARS} characters"
            )
        self._config = config
        self._policy_bundle = policy_bundle
        self._policy_engine = policy_engine
        self._verifier = verifier
        self._executor = executor
        self._audit_sink = audit_sink
        # ADR-129. Required with no default, and the default would be the dangerous one: a Mediator
        # assembled without caps would be a Guardian that enforces no action budget at all, while
        # every record it wrote looked exactly like one that does. Fail-closed is also the cheaper
        # mistake here -- an assembly that omits the argument raises at start, where somebody is
        # watching, rather than at the thirty-third action of a campaign.
        self._caps = caps
        self._clock = clock

    @property
    def policy_bundle(self) -> PolicyBundle:
        """The loaded bundle, whose :attr:`~guardian.app.policy.PolicyBundle.digest` ADR-023's
        isolation assertion 1 compares across three differently configured Guardians.
        """
        return self._policy_bundle

    @property
    def max_request_bytes(self) -> int:
        """The transport-level bound :mod:`guardian.app.main` gates an incoming body against.

        Read from configuration, which derives its default from the request model's own field
        bounds, so the gate can never be narrower than what the model would accept and no
        legitimate action is refused as oversize.
        """
        return self._config.max_request_bytes

    def decide(self, request: ActionRequest) -> ActionResult:
        """Adjudicate one parsed request, audit the outcome, and return it.

        One statement, and the composition is the contract: :meth:`_adjudicate` cannot audit,
        cannot execute and cannot build a result, while :meth:`_seal` does all three and is the only
        thing that does. A branch added inside adjudication therefore cannot produce an unaudited
        decision, because it has nothing to produce a decision *with*.

        **The ``finally`` is ADR-129's and it is load-bearing.** :func:`adjudicate` reserves against
        the two action caps before it evaluates, and the reservation has to be settled by whoever
        holds the decision -- including on the path where the decision never reached a caller,
        because a failing append raises :class:`AuditUnavailable` out of :meth:`_seal` and the
        action was never attempted. Without the ``finally`` that path would leak a reservation, and
        a leaked reservation is budget a run can never get back: a Guardian whose audit sink fails
        twice early and then recovers would refuse the rest of a run's legitimate actions under
        ``scope.action-cap-exceeded`` for a reason that has nothing to do with what the agent did.
        Releasing on every exit and spending only on a permit is the whole settlement rule, and
        :meth:`_settle_caps` says why it keys on the decision.
        """
        verdict = self._adjudicate(request)
        try:
            return self._seal(verdict)
        finally:
            self._settle_caps(verdict)

    def reject(self, reason_code: ReasonCode) -> ActionResult:
        """Audit and return a refusal for a body that never became a request.

        The oversize and malformed paths, which ``security-policy.md`` section 1.4 still requires to
        be recorded -- an unaudited refusal is invisible to the evaluation exactly as an unaudited
        block is. Nothing about the body is recorded beyond the reason: it did not parse, so there
        is no established request id and no action, and inventing either would put
        attacker-authored text into the chain as though the Guardian had verified it. The run the
        record belongs to is this Guardian's own configured one, which no body supplies (ADR-058).
        """
        return self._seal(Verdict.refusal(reason_code, run_id=self._config.run_id))

    def _adjudicate(self, request: ActionRequest) -> Verdict:
        """Run :func:`adjudicate`, turning any defect in this Guardian into an audited denial.

        The ``except`` is unselective on purpose. A fault in the Guardian's own pipeline is not an
        attack, but it must fail the way an attack fails -- denied, with a structured code, and
        present in the chain -- because a fault that silently permitted would be the single worst
        failure this component has, and because a fault whose symptoms differ from a denial's is a
        fault the attacker can use to map the implementation.

        ``BaseException`` is not caught: a ``KeyboardInterrupt`` or a ``SystemExit`` is the process
        being shut down, and a reference monitor that kept answering while being killed would be
        worse than one that stopped.
        """
        try:
            return adjudicate(
                request,
                verifier=self._verifier,
                policy_engine=self._policy_engine,
                caps=self._caps,
                expected_run_id=self._config.run_id,
                evaluation_timeout_seconds=self._config.policy.evaluation_timeout_seconds,
            )
        except Exception:
            return Verdict.refusal(ReasonCode.POLICY_GUARDIAN_FAULT, run_id=self._config.run_id)

    def _settle_caps(self, verdict: Verdict) -> None:
        """Spend or release the reservation :func:`adjudicate` took. Never raises.

        **The condition is the decision and nothing else -- not the mode, and not the execution
        outcome.** Both alternatives break something this module exists to protect:

        * keying on ``enforcement is EXECUTED`` would make the G0-versus-G1 counters differ. Under
          ``G1-LOGONLY`` a deny is followed by execution, so a run's budget would be spent by
          different actions in the two arms, and ADR-023's isolation assertion 2 -- which permits
          the
          G0/G1 difference to reach ``guardian_mode``, the enforcement field and the execution
          block,
          and nothing else -- would be broken by a counter. The counters are written into the record
          as well, so the divergence would be visible in the sealed bundles Chapter 4 reads.
        * keying on whether the action actually *reached the cluster* would make a permitted action
          whose execution failed release its slot, and then a run whose executor was broken would
          keep being permitted indefinitely -- the cap would bound the cluster, not the authority.

        So the rule is the plan's own: consumed exactly when the decision was a permit, released
        otherwise. That is also why a cap can be a bound on a *loop* rather than a tax on being
        wrong: a run's thirty-two slots are spent by the actions it was actually allowed to take,
        and
        a thousand policy denials cost it nothing.
        """
        reservation = verdict.caps_reservation
        if reservation is None:
            return
        try:
            self._caps.settle(reservation, consumed=verdict.decision is Decision.PERMIT)
        # Deliberately unselective and deliberately swallowed, like :meth:`_append_execution_record`
        # and for a slightly different reason: the decision is already sealed and answered by the
        # time this runs, so a store that cannot record the settlement leaves the run one
        # reservation
        # out of step -- a budget spent early or held once too long -- where raising would turn a
        # permitted-and-audited action into a 503 the caller cannot distinguish from "nothing
        # happened". The leak is bounded (one slot, once, per decision) and it fails towards
        # refusing, which is the direction this component is allowed to fail in.
        except Exception:
            return

    def _seal(self, verdict: Verdict) -> ActionResult:
        """Append the record, then execute if the arm did not block, then answer. In that order.

        The **only** method that reaches the audit sink or the executor, and the only path by which
        an :class:`~guardian.app.models.ActionResult` comes into existence.

        A failing append propagates as :class:`AuditUnavailable` and no result is returned. That is
        the deliberate answer to a Guardian that cannot record what it decided: the M3 plan's
        threat-model corollary makes an unaudited block worse than an unblocked action, because an
        unblocked action at least leaves a trace somewhere, and returning a decision the log does
        not contain would be producing exactly that.

        The record the sink returns is checked against the draft before anything is executed. A sink
        that altered the decision, the reason, the attribution or the arm is a sink whose file no
        longer describes what the caller was told, and finding that out at ``make audit-verify``
        time -- months later, on a sealed bundle -- is the failure ADR-022 is written to avoid.
        Scrubbable content is exempt from the comparison: ``guardian/audit/`` bounds and scrubs
        ``justification`` before hashing, which it is required to do, so the action block is
        deliberately not compared field for field.

        **ADR-082 adds one step, after execution and before the answer is built.**
        :meth:`_append_execution_record` writes a follow-up naming what ``self._execute`` returned,
        so the chain itself -- not only the response this method is about to return -- carries
        whether the action succeeded. It runs after the decision is already sealed and after the
        action has already been attempted, which is what keeps the append-before-execute ordering
        this docstring's first paragraph is about: the *decision* still cannot be reached without an
        audit append, and adding a second, later append about its outcome does not change that.
        """
        enforcement = enforcement_for(
            verdict.decision, self._config.mode, action_formed=verdict.action is not None
        )
        draft = AuditDraft(
            ts=self._clock(),
            run_id=verdict.run_id,
            request_id=verdict.request_id,
            token_jti=verdict.token_jti,
            iss=verdict.iss,
            decision=verdict.decision,
            reason_code=verdict.reason_code,
            policy_rule_id=verdict.policy_rule_id,
            action=verdict.action,
            guardian_mode=self._config.mode,
            enforcement=enforcement,
            record_type=AUDIT_RECORD_TYPE_DECISION,
            schema_version=AUDIT_RECORD_SCHEMA_VERSION,
            # ADR-129: the counters the decision was made under, which is a property of the
            # reservation and not of the settlement -- the settlement has not happened yet, and the
            # question the record answers is "what did the budget look like when this was decided".
            action_caps=(
                None if verdict.caps_reservation is None else verdict.caps_reservation.counters
            ),
        )
        try:
            record = self._audit_sink.append(draft)
        except Exception as error:
            raise AuditUnavailable(
                "the audit sink could not seal the decision, so none is returned: "
                "security-policy.md section 1.4 requires every decision to be recorded"
            ) from error
        _assert_record_matches_draft(record, draft)
        execution = self._execute(verdict, enforcement)
        self._append_execution_record(record, execution)
        return result_from_record(record, execution)

    def _execute(self, verdict: Verdict, enforcement: Enforcement) -> ExecutionOutcome:
        """Attempt the action if and only if the Guardian did not block it.

        The condition is :class:`~guardian.app.models.Enforcement` and nothing else -- not the
        decision, and not the mode. Both of those already fed :func:`enforcement_for`, and reading
        either again here would be a second place the arm is legible on the decision path, which is
        the thing ADR-023's confinement argument depends on not existing.

        An executor that raises produces a failed attempt rather than an exception. The record has
        already been appended saying the Guardian did not block, so unwinding here would leave the
        log claiming an execution the caller never heard about -- and a failed attempt is still an
        attempt that was not blocked, which is what the policy-compliant action rate counts.
        """
        if enforcement is not Enforcement.EXECUTED or verdict.action is None:
            return ExecutionOutcome(status=ExecutionStatus.NOT_ATTEMPTED, stdout_ref=None)
        request_id = verdict.request_id or ""
        try:
            return self._executor.execute(executable_action(verdict.action), request_id=request_id)
        except Exception:
            return ExecutionOutcome(status=ExecutionStatus.FAILED, stdout_ref=None)

    def _append_execution_record(self, record: AuditRecord, execution: ExecutionOutcome) -> None:
        """Append the execution follow-up (ADR-082) for ``record``. Never raises.

        Called from :meth:`_seal`, once per decision, for every decision -- not only an executed
        one. :class:`~guardian.app.models.ExecutionRecordDraft`'s own docstring argues why: a write
        conditioned on ``enforcement`` would append a different number of records per arm for the
        same request sequence, because ``G1-LOGONLY`` executes what ``G0-FULL`` blocks, and that
        would put chain *position* on the list of things ADR-023's isolation assertion 2 permits the
        arm to change. Writing one, always, keeps a decision's ``seq`` a function of how many
        decisions preceded it and nothing else.

        **Deliberately does not raise, unlike the decision append in :meth:`_seal`.** The two are
        not the same kind of failure. A decision that could not be recorded is a decision that must
        not be answered at all -- the M3 plan's threat-model corollary that an unaudited block is
        invisible to the evaluation, which is why that append's failure is :class:`AuditUnavailable`
        and propagates. By the time this method runs, the decision is already durably recorded and,
        for an executed one, the action has already been attempted against the cluster; raising here
        would turn a real outcome -- permitted, and either applied or not -- into a 503 the caller
        cannot distinguish from "nothing happened", which is a *worse* blind spot than the one this
        record exists to close, not a smaller version of the same one. The caller's own answer is
        unaffected either way: ``result_from_record`` in :meth:`_seal` builds
        :class:`~guardian.app.models.ActionResult` from ``record`` and ``execution`` directly, never
        from this record, so a caller learns what happened to its action exactly as it always has.

        The residual this leaves is named rather than hidden: if the audit sink cannot write at all
        -- the same fault that would make the *decision* append fail, encountered one step later --
        the chain simply lacks this decision's execution record, and :mod:`guardian.audit.outcome`
        resolves it as ``unknown`` for a v4 chain exactly as it already does for a v3 one that never
        had this record to begin with. That is no worse than today's status quo for every decision
        this ADR does not touch, and it is a strictly rarer fault than the one ADR-082 fixes: an
        executed decision whose outcome the chain records incorrectly, versus one whose outcome the
        chain -- on a Guardian already failing to write its own audit file -- does not record at
        all.
        """
        draft = ExecutionRecordDraft(
            ts=self._clock(),
            run_id=record.run_id,
            decision_seq=record.seq,
            execution_status=execution.status,
            record_type=AUDIT_RECORD_TYPE_EXECUTION,
            schema_version=AUDIT_RECORD_SCHEMA_VERSION,
        )
        try:
            self._audit_sink.append_execution(draft)
        # Deliberately unselective, and deliberately swallowed. See the docstring above: unlike the
        # decision append this method follows, a failure here must not become a response the caller
        # cannot distinguish from "nothing happened", because by this point something already has.
        except Exception:
            return


# The record fields a sink may not change. The action block is absent because the chain is required
# to bound and scrub `justification` before hashing (ADR-022), so a difference there is correct
# behaviour rather than a defect. Everything listed is a value the caller is told and the study is
# scored on, and the two must be the same values.
SEALED_RECORD_INVARIANT_FIELDS: Final = (
    "run_id",
    "request_id",
    "token_jti",
    "iss",
    "decision",
    "reason_code",
    "policy_rule_id",
    "guardian_mode",
    "enforcement",
    "record_type",
    "schema_version",
    # ADR-129. A sink that dropped or rewrote the counters would produce records whose budget
    # readings are fiction, and the difference would not show up until Chapter 4 computed a
    # bounded-agent finding from them.
    "action_caps",
)


def _assert_record_matches_draft(record: AuditRecord, draft: AuditDraft) -> None:
    """Raise :class:`AuditUnavailable` if the sealed record contradicts what was decided."""
    mismatched = [
        name
        for name in SEALED_RECORD_INVARIANT_FIELDS
        if getattr(record, name) != getattr(draft, name)
    ]
    if mismatched:
        raise AuditUnavailable(
            f"the audit sink returned a record differing from the decision in {mismatched}; no "
            "result is returned, because the caller's answer and the sealed record must be the "
            "same values read once"
        )


def _is_record_identifier(value: object) -> bool:
    """Return ``True`` if ``value`` is a string an audit record would accept as an identifier."""
    return (
        isinstance(value, str)
        and len(value) <= IDENTIFIER_MAX_CHARS
        and _IDENTIFIER.fullmatch(value) is not None
    )


def as_wire_mapping(model: BaseModel) -> Mapping[str, Any]:
    """Return the JSON-ready form of a contract model.

    One helper rather than a ``model_dump(mode="json")`` at every call site, so that the wire form
    of a Guardian contract is produced one way. It is deliberately *not* a canonical serialiser:
    ADR-022 allows the chain's byte contract exactly one implementation, in
    ``guardian/audit/canonical.py``, and a second definition of "canonical" arriving here as a
    convenience is the defect ADR-010 closed for ``versions_env_sha256`` reappearing one layer up.
    Callers that need chain bytes use the audit module; callers that need an HTTP body use this.
    """
    return model.model_dump(mode="json")
