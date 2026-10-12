r"""The Guardian's start-time configuration: read once, immutable after, and fail-closed both ways.

WHAT THIS MODULE IS
-------------------
Everything the Guardian's behaviour depends on that is not the request in front of it. The
condition arm it is running under, the capability-token parameters that
``docs/protocols/security-policy.md`` section 2 owns, the signing key, the policy bundle location,
the two Rego entrypoints inside it, the run it was started for, the Supervisors registered to issue
tokens in that run, which executor is assembled, and the transport bound on a request body.

The whole module exists to make one sentence true: **the Guardian's behaviour is a function of what
the runner configured at process start, and of nothing the agent layer can reach.**
``docs/plans/M3-implementation-plan.md`` states the hard requirement -- ``G1-LOGONLY`` and
``G2-SHAREDCRED`` must be reachable *only* by runner flags, never by editing Guardian code or
policy -- and ``docs/milestones/M3-guardian.md``'s Definition of Done makes that a scored item under
traceability row T-13. A mode that a request could set, or that a policy file could select, would
turn the guardrail ablation into a measurement of the agent layer's ingenuity rather than of the
Guardian's properties.

FAIL CLOSED IN BOTH DIRECTIONS, WHICH IS TWO RULES AND NOT ONE
---------------------------------------------------------------
*An unrecognised value is a startup error.* ``GUARDIAN_MODE=G1_LOGONLY``, ``GUARDIAN_MODE=g1``,
``GUARDIAN_MODE=G3-UNQUOTED`` -- each raises :class:`GuardianStartupError` naming the accepted set.
The tempting alternative, "fall back to the default when the value is not understood", is precisely
the defect this rule exists to prevent: a runner that misspells the arm would silently produce a
campaign of ``G0-FULL`` runs labelled ``G1-LOGONLY``, every bundle would validate, and the RQ5
contrast would be computed from data that does not exist. The M3 plan lists "an unrecognised mode
refuses to start" as isolation test 4 for exactly this reason.

*An absent value that has a safe reading takes the strongest reading; an absent value that has none
is an error.* The mode defaults to ``G0-FULL`` -- full mediation, the arm with the most enforcement
-- so a configuration mistake cannot weaken the Guardian, only leave it strict. Everything else has
no safe reading and therefore no default: no signing key, no TTL, no replay-cache size, no policy
bundle path. Section 2's numbers in particular carry no fallback, because a plausible-looking
default is how a campaign goes green against a value nobody chose. That is
``monitor/aggregator/limits.py``'s rule, applied to the component where the cost of getting it wrong
is a security claim rather than a cap.

WHY SECTION 2'S NUMBERS APPEAR HERE AS FIELDS AND NOWHERE AS LITERALS
----------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 2 is the single source of truth for the token TTL, the
per-phase override ceiling, the replay cache's size and window, and the signing algorithm.
``.agents/rules/00-source-of-truth.md`` allows each exactly one home and permits other files to
reference but never to restate. So :class:`TokenParameters` declares the *shape* of those values --
five required fields with their units and their invariants -- and states none of them. The runner
reads section 2 and supplies them; this module refuses to start without them.

This is deliberately a different pattern from ``infra/probes/constants.py`` and
``monitor/aggregator/limits.py``, which mirror their protocol block into code and hold the two equal
with a parsing test. That shape is right when the values are read by a library that has no
configuration surface. It is wrong here, because a mirrored constant is a *code* home for a number,
and code under ``guardian/`` is the one place where a reviewer must be able to say "this file
contains no security parameter" without reading it closely. Configuration keeps the number in the
runner's hands, which is also where the M3 plan's isolation tests need it: the same Guardian binary
runs every arm, and only its inputs differ.

WHAT MAKES "MODE IS NOT REQUEST-SETTABLE" STRUCTURAL
-----------------------------------------------------
Four separate mechanisms, because any one of them alone is one refactor away from being useless.

1. :class:`GuardianConfig` is frozen. ``config.mode = GuardianMode.G1_LOGONLY`` raises at run time,
   so no code path anywhere can mutate the arm after start -- the M3 plan's isolation test 6.
2. The only constructors are :meth:`GuardianConfig.from_mapping` and
   :meth:`GuardianConfig.from_environment`, and both take a ``Mapping[str, str]`` of start-time
   keys. Neither has a parameter that could accept an ``ActionRequest``, and every key they read
   carries the ``GUARDIAN_`` prefix, which no request field is named.
3. :data:`MODE_SHAPED_FIELD_NAMES` is applied to the whole ``ActionRequest`` tree at *import* time
   by :func:`guardian.app.models.reject_field_names`. A future edit that adds ``mode``,
   ``enforce``, ``dry_run`` or ``bypass`` to a request model makes this module fail to import,
   which is to say the Guardian does not start and CI does not go green.
4. :func:`guardian.app.models.reject_field_types` catches the same thing under a different name: no
   field anywhere in the request tree may be *typed* :class:`~guardian.app.models.GuardianMode`.

What none of these can do -- and the honesty matters -- is stop a hostile agent putting
``{"guardian_mode": "G1-LOGONLY"}` inside ``action.params``, which is a free-form mapping. Nothing
reads it: ``params`` is excluded from the OPA input document by construction
(:mod:`guardian.app.policy`), and no code in this package looks up a configuration value from
request data. The M3 plan's isolation test 5 asserts exactly that -- a request carrying a mode field
in ``params`` or ``justification`` changes nothing -- and it is a behavioural test because the
property is behavioural.

THE SIGNING KEY
---------------
Security-policy section 2 puts it in ``guardian/`` only, "provided via env/Secret, rotated on
demand", and rule 10 forbids copying it anywhere -- not into tests, not into ``.env``. Two
consequences are enforced here. It is a :class:`~pydantic.SecretStr`, so it does not appear in a
repr, a log line, an exception's field context or a ``model_dump``; recovering it takes an explicit
``get_secret_value()`` call that a reviewer can grep for. And it is required with no default, so
**a missing key is a startup error**: there is no development key, no example key and no
empty-string fallback in this repository, because a Guardian that starts with a known key is a
Guardian whose tokens anyone can mint.

:data:`SIGNING_KEY_FILE_ENV_VAR` is the Kubernetes path -- a projected Secret volume, read at start
and never re-read -- and it is preferred over the inline variable when both are present, because a
mounted Secret is the deployment shape section 2 asks for and an inline value is the developer
convenience. A blank value in either is treated as absent rather than as a key.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every arm of the guardrail ablation, and therefore every RQ5 result. The M3 plan's flag-isolation
group tests this module directly: default is ``G0-FULL``, an unrecognised mode refuses to start,
mode is not request-settable, mode is immutable after start. A change that weakens any of those
invalidates T-13.
"""

import os
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Final

from guardian.app.models import (
    ACTION_REQUEST_MAX_BYTES,
    ActionRequest,
    GuardianMode,
    reject_field_names,
    reject_field_types,
)
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator

# --------------------------------------------------------------------------------------------
# Environment keys
#
# Every key the runner may set, named once. The GUARDIAN_ prefix is not cosmetic: it is what
# makes point 2 of the module docstring checkable, since no field of any request model is spelled
# this way and no request can therefore contribute a key to this namespace.
# --------------------------------------------------------------------------------------------

ENV_PREFIX: Final = "GUARDIAN_"

MODE_ENV_VAR: Final = f"{ENV_PREFIX}MODE"
RUN_ID_ENV_VAR: Final = f"{ENV_PREFIX}RUN_ID"
REGISTERED_ISSUERS_ENV_VAR: Final = f"{ENV_PREFIX}REGISTERED_ISSUERS"
SIGNING_KEY_ENV_VAR: Final = f"{ENV_PREFIX}SIGNING_KEY"
SIGNING_KEY_FILE_ENV_VAR: Final = f"{ENV_PREFIX}SIGNING_KEY_FILE"
LIFETIME_SECONDS_ENV_VAR: Final = f"{ENV_PREFIX}TOKEN_TTL_SECONDS"
MAX_LIFETIME_SECONDS_ENV_VAR: Final = f"{ENV_PREFIX}TOKEN_MAX_TTL_SECONDS"
ALGORITHM_ENV_VAR: Final = f"{ENV_PREFIX}TOKEN_ALGORITHM"
REPLAY_CACHE_ENTRIES_ENV_VAR: Final = f"{ENV_PREFIX}REPLAY_CACHE_ENTRIES"
REPLAY_CACHE_WINDOW_ENV_VAR: Final = f"{ENV_PREFIX}REPLAY_CACHE_WINDOW_SECONDS"
REPLAY_STORE_PATH_ENV_VAR: Final = f"{ENV_PREFIX}REPLAY_STORE_PATH"
POLICY_BUNDLE_PATH_ENV_VAR: Final = f"{ENV_PREFIX}POLICY_BUNDLE_PATH"
POLICY_ENTRYPOINT_ENV_VAR: Final = f"{ENV_PREFIX}POLICY_ENTRYPOINT"
ISSUANCE_ENTRYPOINT_ENV_VAR: Final = f"{ENV_PREFIX}ISSUANCE_ENTRYPOINT"
POLICY_TIMEOUT_ENV_VAR: Final = f"{ENV_PREFIX}POLICY_TIMEOUT_SECONDS"
AUDIT_LOG_PATH_ENV_VAR: Final = f"{ENV_PREFIX}AUDIT_LOG_PATH"
# ADR-130 (M10): the Ed25519 private key the Guardian signs each audit record's chain hash with, as
# a file path (a projected Secret volume, read once at start). OPTIONAL and file-only. Absent, the
# Guardian writes an unsigned v1 chain exactly as every pre-M10 caller does; present, every appended
# record carries an Ed25519 signature over its hash (guardian/audit/chain.py). File-only and never
# an inline value -- a private key inlined in an env var would sit in the pod spec for every
# `kubectl describe` to read, which is the token key's own reason for its *_FILE form. The live
# deployment sets it (guardian/deploy/deployment.yaml) so the campaign's chains are signed; a Tier-A
# or offline Guardian that sets nothing stays unsigned and unchanged.
AUDIT_SIGNING_KEY_FILE_ENV_VAR: Final = f"{ENV_PREFIX}AUDIT_SIGNING_KEY_FILE"
MAX_REQUEST_BYTES_ENV_VAR: Final = f"{ENV_PREFIX}MAX_REQUEST_BYTES"
EXECUTOR_ENV_VAR: Final = f"{ENV_PREFIX}EXECUTOR"
# ADR-128 (M10): the identity the control-plane caller must present, and the audience its token must
# name, both verified by a Guardian-side TokenReview (guardian/app/control_auth.py). Required with
# no
# default, on this module's rule for every security parameter: a Guardian that fell back to a known
# subject or a blank audience would authenticate the wrong caller, or none, while looking
# configured.
# security-policy.md section 2.1 owns the values; the runner supplies them.
CONTROL_PLANE_SUBJECT_ENV_VAR: Final = f"{ENV_PREFIX}CONTROL_PLANE_SUBJECT"
CONTROL_PLANE_AUDIENCE_ENV_VAR: Final = f"{ENV_PREFIX}CONTROL_PLANE_AUDIENCE"

# The separator for list-valued keys. A comma rather than a space, because a Supervisor identifier
# cannot contain either and a comma survives every shell, Kubernetes env-var syntax and Makefile
# quoting this project uses without needing to be escaped.
LIST_SEPARATOR: Final = ","

# The action-cap store's file name, beside the audit log (ADR-129;
# GuardianConfig.action_cap_store_path).
# Named here rather than at the property so that the one place that spells it is the one place that
# documents it, and so a deployment manifest or a test that needs to recognise the file can import
# the
# name instead of restating the string.
ACTION_CAP_STORE_FILENAME: Final = "guardian_action_caps.sqlite3"

# Field names that must never appear anywhere in the request tree, in the normalised form
# guardian.app.models._normalise_field_name produces. The list is written from the attacker's
# point of view rather than from ours: these are the words a hostile agent would reach for when
# guessing what turns enforcement off.
MODE_SHAPED_FIELD_NAMES: Final = frozenset(
    {
        "arm",
        "audit",
        "bypass",
        "condition",
        "dryrun",
        "enforce",
        "enforcement",
        "guardianmode",
        "logonly",
        "mode",
        "override",
        "shadow",
        "skip",
    }
)


class ExecutorKind(StrEnum):
    """Which executor the composition root assembles. Required, with no default, and here is why.

    :class:`guardian.app.mediation.ActionExecutor` is the only interface in this system permitted to
    change the cluster, and there are exactly two implementations: the real Kubernetes client in
    :mod:`guardian.app.executor`, and :class:`guardian.app.mediation.FakeActionExecutor`, which
    touches nothing and records what it was asked to do.

    **Choosing between them is a decision, so it is spelled rather than defaulted.** A default of
    ``fake`` would be a Guardian that looks configured, answers every route, permits actions, writes
    an audit log that says ``executed`` -- and changes nothing, anywhere, ever. That is the single
    most expensive failure this component can have, because every artefact it produces is
    well-formed and a campaign built on it would be scored months later against a cluster that was
    never touched. A default of ``kubernetes`` fails in the opposite and much cheaper direction, but
    it would mean a developer's Guardian trying to reach an API server nobody asked it to reach.
    ``guardian/app/main.py`` already refuses to ship a composition root that "quietly substitutes
    fakes"; this enum is how that refusal survives one being written.

    The fake is legitimate and is named here as a first-class value rather than smuggled in through
    a test hook. It is the executor a Guardian is given when there is no cluster --
    ``guardian/app/mediation.py`` argues that where it is defined -- and the whole content of this
    field is that choosing it is now an explicit act by whoever started the process.

    An unrecognised value is a startup error naming the accepted set, exactly as an unrecognised
    ``GUARDIAN_MODE`` is, and for the same reason: a runner that misspelled its intent must not be
    quietly given the other one.
    """

    FAKE = "fake"
    KUBERNETES = "kubernetes"


class GuardianStartupError(RuntimeError):
    """The Guardian cannot start with the configuration it was given.

    A distinct type rather than a bare ``ValueError`` because the caller that catches it is the
    process entry point, and what it must do is exit non-zero with the message intact rather than
    fall back to anything. Every message names the offending key and, where there is one, the
    accepted set -- the person reading it is by definition somebody whose runner flag did not do
    what they expected, and "invalid configuration" would send them to read this file.
    """


class _ConfigModel(BaseModel):
    """Shared configuration for every model in this module: unknown key is an error, and frozen.

    ``extra="forbid"`` catches the misspelled key that would otherwise be silently ignored --
    which for a security parameter means running with the default the field would have had, or
    failing on a required field while the value the operator actually supplied sits unread one
    character away from its name. ``frozen=True`` is the immutability the M3 plan's isolation test
    6 asserts, and it applies to the nested models as well as the outer one so that
    ``config.token.ttl_seconds = 0`` fails for the same reason ``config.mode = ...`` does.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class TokenParameters(_ConfigModel):
    """The capability-token parameters, whose values ``security-policy.md`` section 2 owns.

    Five fields, no defaults, and no value stated anywhere in this file. The runner reads section 2
    and supplies them; a Guardian started without one of them does not start. See the module
    docstring for why this is configuration rather than a mirrored constant.

    What each field means, because a number with an implicit unit can be read two ways:

    ``lifetime_seconds`` is the default token time-to-live. ``max_lifetime_seconds`` is the ceiling
    a per-phase override may not exceed -- section 2 permits an override and bounds it, and the
    plan's group B requires a token whose lifetime exceeds the ceiling to be *rejected* rather than
    silently truncated. ``algorithm`` is the single JWS algorithm the verifier will accept, and it
    is a single value rather than a list on purpose: an explicit one-element allowlist is what
    defeats ``alg: none`` and the algorithm-confusion attack, and a list-shaped field is an
    invitation to add a second entry. ``replay_cache_entries`` and ``replay_cache_window_seconds``
    are the two halves of section 2's "last N jti or one hour, whichever larger" rule; the
    "whichever larger" behaviour is M3-T3.3's to implement, and the plan's eviction-replay case is
    the only test that proves it was.

    The one invariant enforced here is that the default lifetime cannot exceed the ceiling. It is
    checked at construction rather than at issuance because a configuration that could never issue
    a valid token should fail at start, when somebody is watching, and not at the first request of
    a campaign run.
    """

    lifetime_seconds: int = Field(gt=0)
    max_lifetime_seconds: int = Field(gt=0)
    algorithm: str = Field(min_length=1, max_length=16, pattern=r"^[A-Za-z0-9]+$")
    replay_cache_entries: int = Field(gt=0)
    replay_cache_window_seconds: int = Field(gt=0)

    @model_validator(mode="after")
    def _check_lifetime_ordering(self) -> "TokenParameters":
        """Reject a default lifetime above the ceiling it is supposed to sit under."""
        if self.lifetime_seconds > self.max_lifetime_seconds:
            raise ValueError(
                f"default token lifetime {self.lifetime_seconds}s exceeds the ceiling "
                f"{self.max_lifetime_seconds}s; both are owned by security-policy.md section 2"
            )
        return self


class PolicyEngineSettings(_ConfigModel):
    """Where the policy bundle is, which rule answers, and how long the engine may take.

    ``bundle_path`` is the directory :class:`guardian.app.policy.PolicyBundle` loads and digests.
    The digest is what the M3 plan's isolation test 1 asserts equal across ``G0-FULL``,
    ``G1-LOGONLY`` and ``G2-SHAREDCRED`` -- the direct machine proof that the arms cannot be
    reached through policy -- so the path is configuration rather than a constant precisely so that
    the same bundle can be pointed at from three differently configured processes and shown to
    hash the same.

    ``entrypoint`` is the fully qualified Rego rule the Guardian evaluates, e.g. a decision rule
    under ``data.guardian``. It is configuration and not a literal because M3-T3.2 owns the
    bundle's internal naming and this module must not pin it before that task has made the choice.

    ``evaluation_timeout_seconds`` bounds one policy evaluation. There is no protocol number for it
    -- it is a transport-level bound on a local call, not an evaluation parameter -- and it has no
    default here for the same reason nothing else does: a timeout that nobody chose is a timeout
    that fires for reasons nobody can explain. Exceeding it denies under
    :attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_TIMEOUT`, never permits.
    """

    bundle_path: Path
    entrypoint: str = Field(min_length=1, max_length=256)
    evaluation_timeout_seconds: float = Field(gt=0)


class GuardianConfig(_ConfigModel):
    """The whole of the Guardian's start-time state. Built once, never mutated, never request-fed.

    ``mode`` is the only field with a default, and the default is the strongest arm. See the module
    docstring for the two-directional fail-closed rule and for the four mechanisms that keep the
    value out of a request's reach.

    ``run_id`` is the run this process was started for, and it is what a cross-run token is checked
    against. It cannot be checked against the request instead: ``ActionRequest.run_id`` is
    attacker-controlled (threat-model position P1), so an Executor holding a token minted for
    another run can simply set the request field to match the token and pass any self-consistency
    check. The field is nullable and *required* -- no default -- so that starting a Guardian that
    pins no run is a decision somebody made explicitly rather than one they fell into. A null is a
    development posture; the runner always sets it in a campaign.

    ``registered_issuers`` is the set of Supervisor identifiers permitted to have issued a token
    for this run, and an empty tuple is meaningful rather than degenerate: with deny-by-default it
    means every token is refused under
    :attr:`~guardian.app.models.ReasonCode.TOKEN_ISSUER_UNKNOWN`, which is the correct reading of
    "no Supervisor is registered". A tuple rather than a set so that ``frozen=True`` is not
    undermined by an in-place ``add``, and so the value round-trips deterministically into any
    diagnostic that dumps the configuration.

    ``max_request_bytes`` defaults to :data:`~guardian.app.models.ACTION_REQUEST_MAX_BYTES`, which
    is derived from the request model's own field bounds rather than chosen. That is what makes the
    transport gate safe by construction: it can never be narrower than what the model would accept,
    so no legitimate action is refused as oversize. A runner may raise it; a runner that lowers it
    is choosing to reject valid requests, which the field's presence makes an explicit choice.

    ``executor`` names which executor the composition root assembles, and it has no default for the
    reason :class:`ExecutorKind` argues at length: the alternative is a Guardian that mediates
    perfectly and mutates nothing while every artefact it produces looks correct.

    ``replay_store_path`` is the Guardian-owned SQLite file that persists spent ``jti`` values
    across restart. It is required because an implicit working-directory path can silently land on
    ephemeral storage; production must point it at the Guardian's persistent volume (ADR-045).

    ``issuance_entrypoint`` is the Rego rule that bounds what a capability token may be minted to
    carry -- M4's conflict M4-C6, and the deny-by-default authority policy that answers it. It sits
    beside ``policy`` rather than inside :class:`PolicyEngineSettings`, and the placement is a
    decision: that class is what :meth:`guardian.app.policy.PolicyBundle.load` is handed, its two
    fields are the two the *loader* needs, and a loader that carried an entrypoint it never uses
    would invite the reading that it validates one. The bundle is the same bundle in both cases --
    that is the whole point of M4-C6's answer, since a second bundle would be a second digest and
    ADR-023's equal-across-arms proof would cover half the policy -- so the path and the timeout are
    shared and only the rule differs. Required with no default, like every other entrypoint: a
    Guardian that cannot name the rule bounding its own issuance does not start, rather than minting
    against a rule nobody chose.
    """

    mode: GuardianMode = GuardianMode.G0_FULL
    run_id: str | None
    registered_issuers: tuple[str, ...]
    token: TokenParameters
    policy: PolicyEngineSettings
    issuance_entrypoint: str = Field(min_length=1, max_length=256)
    # ADR-128: the control-plane caller's expected identity and audience. Required, no default --
    # see
    # the env-var comment above. They are plain strings rather than a nested model because there are
    # exactly two and neither has an invariant tying it to the other.
    control_plane_subject: str = Field(min_length=1, max_length=256)
    control_plane_audience: str = Field(min_length=1, max_length=256)
    signing_key: SecretStr
    replay_store_path: Path
    audit_log_path: Path
    # ADR-130: the path to the Ed25519 audit-signing key, or None for an unsigned chain. A path
    # only, never the material -- composition.py reads and parses the PEM at assembly, where
    # importing a crypto library is appropriate and this module stays free of one (ADR-022's spirit:
    # the audit chain and config both avoid the crypto import; the assembler is where it belongs).
    audit_signing_key_file: Path | None = None
    executor: ExecutorKind
    max_request_bytes: int = Field(default=ACTION_REQUEST_MAX_BYTES, gt=0)

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "GuardianConfig":
        """Build the configuration from the process environment, or from ``environ`` if given.

        The injectable mapping exists so that M3-T3.7's isolation tests can build three
        configurations in one process without touching ``os.environ`` -- which is global, shared
        with every other test in the session, and the classic source of a test that passes alone
        and fails in a suite. Default is the real environment, so the production path takes no
        special argument.
        """
        return cls.from_mapping(os.environ if environ is None else environ)

    @classmethod
    def from_mapping(cls, source: Mapping[str, str]) -> "GuardianConfig":
        """Build the configuration from runner keys, or raise :class:`GuardianStartupError`.

        Every failure below is a refusal to start. None of them is recoverable at run time, and
        none falls back: an unparseable integer, an unknown mode, a missing key and an absent
        signing key all leave the process with no correct behaviour available to it, and the only
        safe thing a reference monitor can do in that position is not run.

        The signature takes a ``Mapping[str, str]`` and nothing else. That is the second of the
        four mechanisms the module docstring lists: there is no parameter here through which an
        ``ActionRequest`` could reach the mode.
        """
        mode = _parse_mode(source.get(MODE_ENV_VAR))
        signing_key = _read_signing_key(source)
        token = TokenParameters(
            lifetime_seconds=_require_int(source, LIFETIME_SECONDS_ENV_VAR),
            max_lifetime_seconds=_require_int(source, MAX_LIFETIME_SECONDS_ENV_VAR),
            algorithm=_require_text(source, ALGORITHM_ENV_VAR),
            replay_cache_entries=_require_int(source, REPLAY_CACHE_ENTRIES_ENV_VAR),
            replay_cache_window_seconds=_require_int(source, REPLAY_CACHE_WINDOW_ENV_VAR),
        )
        policy = PolicyEngineSettings(
            bundle_path=Path(_require_text(source, POLICY_BUNDLE_PATH_ENV_VAR)),
            entrypoint=_require_text(source, POLICY_ENTRYPOINT_ENV_VAR),
            evaluation_timeout_seconds=_require_float(source, POLICY_TIMEOUT_ENV_VAR),
        )
        overridden_bytes = source.get(MAX_REQUEST_BYTES_ENV_VAR)
        try:
            return cls(
                mode=mode,
                run_id=_optional_text(source, RUN_ID_ENV_VAR),
                registered_issuers=_parse_list(source.get(REGISTERED_ISSUERS_ENV_VAR)),
                token=token,
                policy=policy,
                issuance_entrypoint=_require_text(source, ISSUANCE_ENTRYPOINT_ENV_VAR),
                control_plane_subject=_require_text(source, CONTROL_PLANE_SUBJECT_ENV_VAR),
                control_plane_audience=_require_text(source, CONTROL_PLANE_AUDIENCE_ENV_VAR),
                signing_key=SecretStr(signing_key),
                replay_store_path=Path(_require_text(source, REPLAY_STORE_PATH_ENV_VAR)),
                audit_log_path=Path(_require_text(source, AUDIT_LOG_PATH_ENV_VAR)),
                audit_signing_key_file=_optional_audit_signing_key_file(source),
                executor=_parse_executor(source.get(EXECUTOR_ENV_VAR)),
                max_request_bytes=(
                    ACTION_REQUEST_MAX_BYTES
                    if overridden_bytes is None or not overridden_bytes.strip()
                    else _require_int(source, MAX_REQUEST_BYTES_ENV_VAR)
                ),
            )
        except ValidationError as error:
            raise GuardianStartupError(f"invalid Guardian configuration: {error}") from error

    @property
    def action_cap_store_path(self) -> Path:
        """Where the two action caps' counters live (ADR-129). Derived, never configured.

        **Beside the audit log, and the reason is that these two files are the same kind of thing.**
        The audit log is this run's append-only evidence and the cap store is this run's running
        budget against the same authority, for the same run, on the same volume. A Guardian whose
        budget survived on one filesystem and whose evidence survived on another would be a Guardian
        that could be restarted onto a fresh volume -- resetting its budget to full -- while its
        sealed bundle still carried the counters of the run before. Putting them together makes that
        a move of two files rather than one, and the runner already has to place the audit log.

        Derived rather than a required environment variable, and that is the departure from this
        module's rule for everything else here. Every other path is a *choice* an operator makes
        about where run state lands; this one has no configuration to get wrong, and a setting for
        it
        would be a way to point a run's budget at a working directory, which is precisely the
        ephemeral-storage mistake ``replay_store_path`` is required to prevent. The cap *values* are
        the settings a deployment might want, and those are not configurable either -- see
        :mod:`guardian.app.limits` for why they are mirrored from the protocol instead.
        """
        return self.audit_log_path.with_name(ACTION_CAP_STORE_FILENAME)


def _parse_mode(raw: str | None) -> GuardianMode:
    """Return the configured arm, defaulting to the strongest, or raise on an unrecognised value.

    The two halves of the module docstring's fail-closed rule live in these six lines, and both
    matter. An absent or blank value yields ``G0-FULL``: full mediation is the arm that cannot be
    weakened by a configuration mistake, so the default is safe in the only direction a default
    can be. A *present* value that is not a member raises, naming what was accepted -- because the
    operator who set it clearly intended an arm, and quietly giving them a different one would
    produce a campaign whose labels and whose behaviour disagree.

    ``G3-UNQUOTED`` is among the values this rejects, and rejecting it is correct: it is the
    Monitor's aggregator-quoting flag (architecture section 4, owned by M2-T2.6) and the Guardian
    does not implement it. Accepting it here would let a runner believe an arm was in force that
    nothing in this process could produce.
    """
    if raw is None or not raw.strip():
        return GuardianMode.G0_FULL
    try:
        return GuardianMode(raw.strip())
    except ValueError as error:
        accepted = ", ".join(mode.value for mode in GuardianMode)
        raise GuardianStartupError(
            f"{MODE_ENV_VAR}={raw!r} is not a Guardian mode; accepted values are {accepted}. "
            "The mode is set only by the runner and only at process start"
        ) from error


def _parse_executor(raw: str | None) -> ExecutorKind:
    """Return the configured executor, or raise -- there is no default in either direction.

    The shape is :func:`_parse_mode`'s deliberately, minus its first branch, and the missing branch
    is the decision. A mode has a *safe* absent reading: ``G0-FULL`` is the arm with the most
    enforcement, so a configuration mistake leaves the Guardian strict. An executor has none.
    Absent-means-fake produces a Guardian that mediates flawlessly and mutates nothing, with every
    audit record saying ``executed``; absent-means-kubernetes produces one that reaches for an API
    server nobody pointed it at. Neither is a reading a configuration mistake should be able to
    reach, so an unset value is a refusal to start, exactly as a missing signing key is.

    A present value outside the accepted set raises naming the set, for :func:`_parse_mode`'s own
    reason: the operator who set it clearly intended one of them, and quietly giving them the other
    would be a Guardian doing something other than what it was told.
    """
    if raw is None or not raw.strip():
        raise GuardianStartupError(
            f"required Guardian setting {EXECUTOR_ENV_VAR} is unset or blank; accepted values are "
            f"{', '.join(kind.value for kind in ExecutorKind)}. There is no default: a Guardian "
            "that fell back to the fake executor would mediate every action correctly and change "
            "nothing, and every artefact it produced would look right"
        )
    try:
        return ExecutorKind(raw.strip())
    except ValueError as error:
        accepted = ", ".join(kind.value for kind in ExecutorKind)
        raise GuardianStartupError(
            f"{EXECUTOR_ENV_VAR}={raw!r} is not a Guardian executor; accepted values are {accepted}"
        ) from error


def _read_signing_key(source: Mapping[str, str]) -> str:
    """Return the token signing key, or raise because a Guardian without one must not start.

    The file variable wins when both are set, because a projected Kubernetes Secret is the shape
    ``security-policy.md`` section 2 asks for and an inline environment value is the developer
    convenience -- if a deployment supplies both, the mounted Secret is the one that was meant.

    A blank value counts as absent in both forms. An empty signing key would verify nothing while
    looking configured, which is the worst of the three possible outcomes.

    There is deliberately no default, no bundled development key and no generated one. A generated
    key would make each restart invalidate every live token -- silently, and only under load. A
    bundled one would be a signing key in the repository, which rule 10 forbids outright and which
    would make every capability token in the project forgeable by anyone who has cloned it.
    """
    key_path = source.get(SIGNING_KEY_FILE_ENV_VAR)
    if key_path is not None and key_path.strip():
        try:
            material = Path(key_path.strip()).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise GuardianStartupError(
                f"{SIGNING_KEY_FILE_ENV_VAR}={key_path!r} could not be read: {error}"
            ) from error
        if not material:
            raise GuardianStartupError(f"{SIGNING_KEY_FILE_ENV_VAR}={key_path!r} is empty")
        return material
    inline = source.get(SIGNING_KEY_ENV_VAR)
    if inline is None or not inline.strip():
        raise GuardianStartupError(
            f"no token signing key: set {SIGNING_KEY_ENV_VAR} or {SIGNING_KEY_FILE_ENV_VAR}. "
            "security-policy.md section 2 keeps the key in guardian/ only, via env or Secret; "
            "there is no default and no development key"
        )
    return inline.strip()


def _optional_audit_signing_key_file(source: Mapping[str, str]) -> Path | None:
    """Return the audit-signing key path when set, else ``None`` (ADR-130).

    Absent or blank is ``None`` -- the unsigned v1 chain every pre-M10 caller and every offline
    Guardian writes, unchanged. Set-but-unreadable, or set-but-empty, is a startup failure and not a
    silent fall-back to unsigned: a Guardian told to sign that cannot read its key must refuse to
    start, because ``a Guardian that looked configured to sign while writing an unsigned chain`` is
    the worst of the three outcomes, exactly as :func:`_read_signing_key` says of a blank token key.
    The file's *contents* are parsed by ``guardian/app/composition.py`` at assembly; this only fixes
    that the path names a present, non-empty file so the failure lands at start, not at the first
    append.
    """
    raw = source.get(AUDIT_SIGNING_KEY_FILE_ENV_VAR)
    if raw is None or not raw.strip():
        return None
    path = Path(raw.strip())
    try:
        present = path.is_file() and path.stat().st_size > 0
    except OSError as error:
        raise GuardianStartupError(
            f"{AUDIT_SIGNING_KEY_FILE_ENV_VAR}={raw!r} could not be read: {error}"
        ) from error
    if not present:
        raise GuardianStartupError(
            f"{AUDIT_SIGNING_KEY_FILE_ENV_VAR}={raw!r} names no readable, non-empty file; a "
            "Guardian told to sign its audit chain must not start unsigned (ADR-130)"
        )
    return path


def _require_text(source: Mapping[str, str], key: str) -> str:
    """Return a required non-blank string setting, or raise naming the key."""
    value = source.get(key)
    if value is None or not value.strip():
        raise GuardianStartupError(f"required Guardian setting {key} is unset or blank")
    return value.strip()


def _optional_text(source: Mapping[str, str], key: str) -> str | None:
    """Return an optional string setting, treating a blank value as unset."""
    value = source.get(key)
    return value.strip() if value is not None and value.strip() else None


def _require_int(source: Mapping[str, str], key: str) -> int:
    """Return a required integer setting, or raise naming the key and what was found.

    Parsed strictly: ``"300s"``, ``"3e2"`` and ``"300.0"`` all raise rather than being coerced.
    A token lifetime that a shell quoted with its unit attached must not become a different number
    than the one the operator wrote.
    """
    raw = _require_text(source, key)
    try:
        return int(raw)
    except ValueError as error:
        raise GuardianStartupError(f"{key}={raw!r} is not an integer") from error


def _require_float(source: Mapping[str, str], key: str) -> float:
    """Return a required real-valued setting, or raise naming the key and what was found."""
    raw = _require_text(source, key)
    try:
        return float(raw)
    except ValueError as error:
        raise GuardianStartupError(f"{key}={raw!r} is not a number") from error


def _parse_list(raw: str | None) -> tuple[str, ...]:
    """Return a comma-separated setting as a tuple, dropping blank entries.

    Blank entries are dropped rather than preserved so that a trailing comma, which every operator
    eventually leaves behind, does not register an issuer named "" -- an identifier that could
    never match a real ``iss`` claim but that would sit in a dumped configuration looking like a
    registration.
    """
    if raw is None:
        return ()
    return tuple(item.strip() for item in raw.split(LIST_SEPARATOR) if item.strip())


# The third and fourth mechanisms from the module docstring, applied at import so that a request
# model which drifts towards being mode-aware breaks the build rather than the ablation. They live
# in this module rather than in models.py because the *rule* is this module's -- models.py knows
# what a request looks like; config.py knows what must never influence it.
reject_field_names(
    ActionRequest,
    MODE_SHAPED_FIELD_NAMES,
    why=(
        "the Guardian mode is a start-time, runner-only parameter (M3 plan, ADR-014); a request "
        "field able to name it would make the G1-LOGONLY and G2-SHAREDCRED arms reachable by the "
        "hostile agent layer the ablation is measuring"
    ),
)
reject_field_types(
    ActionRequest,
    (GuardianMode,),
    why=(
        "no field of a request may be typed GuardianMode under any name; the arm reaches the "
        "process through GuardianConfig at start and by no other route"
    ),
)
