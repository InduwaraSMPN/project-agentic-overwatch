r"""The OPA seam: one bundle with one digest, one input document, and one way to fail.

WHAT THIS MODULE IS
-------------------
``docs/02-architecture.md`` section 2 puts an OPA evaluation between the Guardian's token check and
its executor, and ``docs/protocols/security-policy.md`` section 1.1 fixes what that evaluation must
mean: "absent an explicit permit rule, deny with a reason code". This module is the boundary between
the Guardian's Python and that policy engine. It does three things and refuses to do a fourth.

It **loads the policy bundle once and publishes its sha256**, because ADR-023 makes that digest the
direct machine proof that the guardrail arms cannot be reached through policy. It **builds the input
document**, additively and from a closed field partition, so that the two attacker-authored fields
``justification`` and ``params`` are absent by construction rather than by care. And it **turns an
engine result into a decision**, on a single narrow path where a permit is possible and a wide one
where everything else denies.

The fourth thing -- deciding anything -- is not here. No rule in this file says which verb on which
resource in which namespace is allowed; that is ``guardian/policies/``'s job, written in Rego,
tested by ``opa test``, and reviewed as policy rather than as code. A decision procedure implemented
twice, once in Rego and once in Python "for the tests", is two policies whose divergence nobody
would notice until an evaluation depended on it. The only engine class defined below,
:class:`UnavailablePolicyEngine`, has no permit path at all.

WHY THE BUNDLE DIGEST IS COMPUTED THE WAY IT IS
-----------------------------------------------
ADR-023 states the requirement in one sentence: the sha256 of the loaded bundle is "asserted **equal
across G0, G1 and G2**. Not 'equivalent', not 'semantically the same' -- the same bytes." The
reason the assertion is made on the bundle rather than on the decisions is also ADR-023's, and it is
worth keeping in view while reading :meth:`PolicyBundle.load`: behaviour is what the ablation is
*measuring*, so a test that compared G0's and G1's decisions would be asserting the finding rather
than the mechanism, and would pass for a G1 built by editing policy so long as the edit happened to
be decision-preserving on the test inputs. The digest is upstream of all of that.

Three properties of the digest follow, and none of them is the obvious implementation:

*Line endings are normalised to LF before hashing.* This is ADR-010's rule and ADR-022's, applied
one layer up. ``.gitattributes`` normalises tracked text to LF in the index while the development
host checks out with CRLF, so a byte-level hash of a ``.rego`` file records **which host loaded the
bundle** rather than which policy was loaded. The isolation assertion would then pass on Linux, fail
on Windows, and mean nothing on either -- the identical defect ADR-010 was written to close.

*Paths are part of the digest, sorted, and length-prefixed together with their contents.* Sorting
removes any dependence on directory iteration order. Including the path means renaming a rule file
moves the hash, which it should: a bundle is a set of named modules and OPA resolves packages by
what it finds. Length-prefixing removes the concatenation ambiguity that would otherwise let two
different file sets hash identically.

*Every regular non-hidden file is included, not just ``*.rego``.* A filter is a place to hide a
file. A bundle carrying policy data, a second entrypoint, or anything else the engine can see must
move the digest, and the cheapest way to guarantee that is to have no exclusions to reason about.
Hidden files are skipped because editor and VCS droppings are not part of what OPA loads.

WHY ``justification`` AND ``params`` CANNOT REACH POLICY, AND WHY THAT IS STRUCTURAL
------------------------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 1.5 requires LLM-supplied free text to be "logged,
never evaluated as policy". ``docs/plans/M3-implementation-plan.md``'s conflict M3-C10 records that
the Monitor half of section 1.5 is covered by traceability row T-03 and **the Guardian half is
covered by nothing**, which is why the exclusion is built here as a checked property rather than as
a convention. The threat model's position P1 gives the agent every field of the request, and P5
makes the content itself attacker-authored under injection class INJ-B: a ``justification`` is a
place a hostile agent writes Rego fragments, and ``params`` is a place it writes mode-switch
instructions. Neither is dangerous while no policy can read it.

The mechanism is a **closed partition, checked at import**, rather than a subtraction. The tempting
implementation is ``request.model_dump()`` with two keys popped, and it fails in the one way that
matters: a field added to :class:`~guardian.app.models.ActionSpec` next year is a field that
silently starts reaching policy, because subtraction only removes what somebody remembered to name.
So every field of :class:`~guardian.app.models.ActionRequest`,
:class:`~guardian.app.models.ActionSpec` and :class:`~guardian.app.models.CapabilityTokenClaims` is
assigned to exactly one of two tuples below -- included or excluded -- and
:func:`_assert_field_partition` refuses to let this module import if any field is in neither or in
both. A future edit that adds a field to a request model does not silently leak it and does not
silently drop it; it stops the Guardian from starting until somebody decides which side it falls on.

The runtime half is :func:`assert_document_is_clean`, which walks the finished document and rejects
any key -- at any depth -- that names an excluded field or that is shaped like a mode flag. It runs
on **every** call, not only under test, for the reason ``.agents/rules/40-monitor-non-llm.md`` gives
about its own three guards: a check that only runs in the suite is a check that holds until somebody
skips the suite. It cannot produce a false positive, because every key in the document is a literal
in this file; attacker-controlled strings appear only as values.

The mode-flag half of that walk is ADR-023's. Policy must be **mode-blind**: an input document
carrying ``guardian_mode`` would make the arms reachable through policy exactly as an edit to the
bundle would, and would do it in a way the bundle digest could not see.
:data:`~guardian.app.config.MODE_SHAPED_FIELD_NAMES` is imported rather than restated, so the list
the request models are guarded against and the list the policy input is guarded against are the
same list.

THE SECOND DOCUMENT: WHAT MAY BE MINTED, AND WHY IT IS BUILT HERE RATHER THAN AT THE ROUTE
--------------------------------------------------------------------------------------------
:func:`build_issuance_input` is the input document for the *authority* entrypoint -- the rule that
bounds what a capability may carry before one is signed. It exists because of M4's conflict M4-C6,
and the conflict is worth restating because it is sharper than it looks: ``guardian.rego``'s single
permit rule grants **exactly what the token's allow-claim covers**, and ``POST /v1/tokens``
establishes no caller identity. So any party with network reach to the issue surface mints a claim
and the permit follows -- the mediated arm is not mediated, and RQ5's contrast measures nothing.

The answer taken is *not* to authenticate the caller, which cannot be done between in-process nodes
without the standing credentials FR3.1 forbids. It is to make an unauthenticated mint **grant
nothing an authorised Supervisor could not already have obtained**: a human-authored, per-phase
declaration of the widest verbs, resources and namespaces a capability for that phase may ever
carry, evaluated deny-by-default before anything is signed. The residual gap -- caller identity is
still not established, and a party reaching the surface can still mint *within* the declared
authority and can still name any ``sub`` and any ``iss`` -- is **recorded rather than closed**, here
and on :class:`guardian.app.mediation.TokenIssuer` and in ADR-031.

Three properties of this document follow from where it lives:

*It is in the same bundle.* The authority rules ship in ``guardian/policies/`` beside the action
rules, so :attr:`PolicyBundle.digest` still hashes one directory and ADR-023's equal-across-arms
assertion is unchanged. A second bundle would have been a second digest, and the machine proof that
the guardrail arms cannot be reached through policy would have covered half the policy.

*It carries no free text, because the contract has none.*
:class:`~guardian.app.models.TokenIssueRequest` declares six fields and a version, every one of them
a bounded identifier, a closed vocabulary, a bounded list or an integer. There is no
``justification`` to withhold and no ``params`` to exclude. The document is nonetheless walked by
:func:`assert_document_is_clean` exactly as the action document is, and the field partition below is
checked at import exactly as the request partition is -- because "there is nothing to exclude today"
is a statement about today, and the check is what makes a field added tomorrow a build failure
rather than a silent new input to policy.

*It is built here rather than in :mod:`guardian.app.main`.* The route's job is to parse bytes into a
contract; deciding what an engine is shown is this module's, and having exactly one file that builds
policy input is what makes "no free text ever reaches an engine" checkable by reading one file.

FAILING CLOSED IS THE MOST IMPORTANT PROPERTY IN THIS FILE
-----------------------------------------------------------
``docs/plans/M3-implementation-plan.md`` states it plainly for group E: OPA unavailable or timing
out "fails **closed**, denying and auditing rather than degrading to permit". A policy engine that
returns permit when it cannot be reached is not a weaker Guardian, it is an absent one, and the
failure is silent -- which is the failure mode this whole milestone is designed against.

Three structures carry it, because a single ``try`` around a large function is exactly the shape
that stops covering the case somebody adds underneath it:

1. **A permit cannot be constructed without a rule id.** :meth:`PolicyDecision.permit` raises unless
   it is given one that matches the audit record's identifier grammar. So a permit that no rule
   granted is not a value this module can produce, which is
   :class:`~guardian.app.models.ActionResult`'s invariant enforced one layer earlier -- at the point
   where the mistake would be made rather than at the point where it would be caught.
2. **Interpretation is total and lives in its own function.** :func:`interpret_policy_result` takes
   whatever the engine returned -- any object at all, including ``None`` -- and returns a decision.
   It has exactly one ``return`` that produces a permit and it is guarded by four checks; every
   other path returns a denial with a reason code that says which of the three engine failures
   happened. It performs no I/O, so it cannot itself fail in a way that needs catching.
3. **The call is wrapped, and the wrapper's ``except`` is not selective.** :func:`evaluate_policy`
   catches :class:`PolicyEngineTimeout` and :class:`PolicyEngineUnavailable` by name, then catches
   ``Exception`` and denies anyway. An engine that raises something this module has never heard of
   is an engine that failed, and the correct reading of an unrecognised failure is the same as the
   correct reading of a recognised one.

The timeout is enforced by the **caller** as well as declared to the callee. :func:`evaluate_policy`
passes ``timeout_seconds`` to the engine and *also* measures the elapsed monotonic time, denying
under :attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_TIMEOUT` if the call overran even when it
returned a permit. An engine that ignores its timeout argument would otherwise make the bound a
suggestion, and the bound exists because position P3 of the threat model is unbounded request
volume: an evaluation that can take arbitrarily long is a denial-of-service surface on the one
component that must stay available to be able to deny.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
T3.2's Rego bundle reads the document this module emits, so the field partition below is the
contract those rules are written against. The isolation suite reads :attr:`PolicyBundle.digest`.
M3-C10's test reads :data:`EXCLUDED_FROM_POLICY_INPUT` and asserts against the same constant the
builder is checked against, which is the only way that test proves something about the code rather
than restating it.
"""

import hashlib
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

from guardian.app.config import MODE_SHAPED_FIELD_NAMES, GuardianStartupError, PolicyEngineSettings
from guardian.app.models import (
    IDENTIFIER_MAX_CHARS,
    IDENTIFIER_PATTERN,
    ActionRequest,
    ActionSpec,
    AllowClaim,
    CapabilityTokenClaims,
    Decision,
    ReasonCode,
    TokenIssueRequest,
    _normalise_field_name,
)
from pydantic import BaseModel

# --------------------------------------------------------------------------------------------
# The input document's own version
#
# Not a protocol number and not one of architecture section 3's contracts: this is the shape the
# Rego rules parse, and it needs a version for the reason every other contract in this repository
# has one -- a policy that cannot tell which input shape it is reading is a policy that infers the
# shape from which keys happen to be present, which is the guess models.py's schema_version exists
# to remove. T3.2's entrypoint should reject an input document at a version it does not know.
# --------------------------------------------------------------------------------------------

POLICY_INPUT_SCHEMA_VERSION: Final = "v1"

# The issuance document's version, and deliberately its own token rather than a share of the one
# above. The two documents describe different questions -- "may this action proceed" and "may this
# capability be minted" -- and are read by different entrypoints, so a single version would move for
# a reason that has nothing to do with half the bundle, and each half would have to guess whether a
# bump concerned it.
ISSUANCE_INPUT_SCHEMA_VERSION: Final = "v1"

# --------------------------------------------------------------------------------------------
# The field partition
#
# Every field of every model that feeds the document appears in exactly one of these tuples, and
# _assert_field_partition below refuses to let this module import unless that is true. See the
# module docstring for why this is a partition rather than a subtraction.
# --------------------------------------------------------------------------------------------

# From ActionRequest. request_id and run_id identify the attempt; both are attacker-settable and
# are offered to policy as claims about the attempt rather than as established facts, which is why
# the Guardian's own run id is published separately under the "guardian" key.
POLICY_INPUT_REQUEST_FIELDS: Final = ("request_id", "run_id")

# `justification` is section 1.5's free text and is the whole subject of conflict M3-C10. `token`
# is the bearer credential: policy is handed the *verified claims*, never the string, so there is
# no path by which an unverified token could be evaluated as though it had been checked, and no
# path by which a live credential could reach an engine's own logs. `action` is expanded into its
# own section below rather than nested wholesale, and `schema_version` is the request contract's
# version rather than the document's -- the document carries its own.
#
# `executor_id` and `phase` arrived with ActionRequest v2 (M4-C5) and are excluded, which is a
# decision rather than an omission and is the reason the partition check exists at all. Policy
# already has both facts in *verified* form: `capability.sub` and `capability.phase` are claims a
# verifier accepted, and adjudication cannot reach this builder without that acceptance having
# happened -- build_policy_input requires a CapabilityTokenClaims by type. The request's own
# `executor_id` and `phase` are the *agent's declaration* of the same two facts, and the verifier
# has already refused the request when the two disagree, under SCOPE_SUBJECT_MISMATCH or
# SCOPE_PHASE_MISMATCH. Emitting them anyway would give every rule two spellings of one fact, one
# established and one attacker-authored, differing only in a case that never reaches policy -- and
# the first rule that reached for the shorter path would be reading the attacker's copy. A document
# is safest when each fact appears once, in its verified form.
POLICY_INPUT_EXCLUDED_REQUEST_FIELDS: Final = frozenset(
    {"token", "justification", "action", "schema_version", "executor_id", "phase"}
)

# From ActionSpec. These four are what an authorisation decision is about: who may do what, to
# which kind of object, where, and to which one.
POLICY_INPUT_ACTION_FIELDS: Final = ("verb", "resource", "namespace", "name")

# `params` is the request's one free-form structure and the second half of M3-C10. A hostile agent
# writing Rego fragments or mode-switch instructions into it is writing into a field no policy will
# ever read. It is recorded in the audit chain, which is what section 1.5 asks for.
POLICY_INPUT_EXCLUDED_ACTION_FIELDS: Final = frozenset({"params"})

# The one scalar D4-A (ADR-129) lifts out of the excluded `params`, and the action field the
# builder projects it into. `params` stays excluded wholesale -- it is attacker-authored free-form
# data and no rule may read it -- but the scale-to-zero rule needs exactly one fact from it: whether
# a deployment write asks for zero replicas. That fact is taken as a *normalised integer* under a
# field name of this module's own, never the raw string and never the `params` mapping, so a rule
# reading `action.replicas` sees a value the agent cannot spell around (`"0"` and `"00"` are one
# integer) and still never sees a byte of free text. `REPLICAS_PARAM` is the request parameter name
# and must equal `guardian.app.executor.REPLICAS_PARAM`; it is restated rather than imported so this
# module stays the single, self-contained definition of what an engine is shown, and guardian/tests
# keeps the two sides of the scale path honest against each other.
REPLICAS_PARAM: Final = "replicas"
POLICY_INPUT_REPLICAS_KEY: Final = "replicas"

# The `(verb, bare-resource)` pairs a replica count is meaningful for, and the only pairs the
# builder attaches `POLICY_INPUT_REPLICAS_KEY` to. Both are deployment writes -- `patch` is the
# scale path and `update` the image-replacement path -- and both are pairs
# `guardian/app/executor.py`'s OPERATIONS routes to a deployment. Attaching the field anywhere else
# would put a key no rule reads into the document, the additive-construction discipline this module
# exists to keep.
POLICY_INPUT_REPLICA_CARVE_OUT: Final = frozenset(
    {("patch", "deployments"), ("update", "deployments")}
)

# From CapabilityTokenClaims, and only ever from a claim set a verifier has already accepted.
POLICY_INPUT_CAPABILITY_FIELDS: Final = ("iss", "sub", "run_id", "phase", "allow")

# Deliberately withheld from policy, and each for its own reason. `iat` and `exp` are excluded
# because temporal validity is settled before policy runs, by the token verifier, against the
# parameters security-policy.md section 2 owns; putting them in the document invites a Rego rule to
# re-decide expiry and creates a second home for a protocol number. `jti` is excluded because
# single-use enforcement is the replay cache's and a policy cannot enforce it -- a rule that read
# `jti` could only pretend to. `schema_version` is the token contract's version, not this
# document's.
POLICY_INPUT_EXCLUDED_CAPABILITY_FIELDS: Final = frozenset({"jti", "iat", "exp", "schema_version"})

# From TokenIssueRequest, for the authority entrypoint. Every field the contract declares except
# its own version: what a capability would be minted for is exactly what the authority rule has to
# be shown, and withholding any of it would be asking a policy to bound something it cannot see.
# `allow` is expanded into plain lists by the builder, on the same reasoning as the capability
# section's, so it is named here and overwritten there.
ISSUANCE_INPUT_REQUEST_FIELDS: Final = (
    "supervisor_id",
    "executor_id",
    "run_id",
    "phase",
    "ttl_seconds",
    "allow",
)

# `schema_version` is the issue contract's version, not this document's -- the document carries its
# own, ISSUANCE_INPUT_SCHEMA_VERSION, for the reason stated beside it.
ISSUANCE_INPUT_EXCLUDED_REQUEST_FIELDS: Final = frozenset({"schema_version"})

# The union of the two field names conflict M3-C10 is about, published so that the M3-C10 test
# asserts against the same constant the builder is checked against rather than against a string it
# repeats. A test that restates the name it is testing proves only that somebody typed it twice.
EXCLUDED_FROM_POLICY_INPUT: Final = frozenset({"justification", "params"})

# Every key name the finished document may not contain at any depth, in the normalised form
# guardian.app.models._normalise_field_name produces. Three groups, three reasons: the M3-C10
# fields; the bearer-credential names, so that no future edit can put a token into a document that
# is passed to an external process; and every mode-shaped name, because ADR-023's requirement that
# policy be mode-blind is a requirement about what the engine can see, and a mode reaching Rego
# through the input document would be invisible to the bundle digest that is supposed to prove it
# cannot.
FORBIDDEN_DOCUMENT_KEYS: Final = (
    frozenset(_normalise_field_name(name) for name in EXCLUDED_FROM_POLICY_INPUT)
    | frozenset({"token", "bearer", "authorization", "credential", "secret", "signature"})
    | MODE_SHAPED_FIELD_NAMES
)

# The three lists inside an allow claim, in architecture section 3's order.
ALLOW_CLAIM_KEYS: Final = ("verbs", "resources", "namespaces")

# --------------------------------------------------------------------------------------------
# Bundle loading
# --------------------------------------------------------------------------------------------

# What OPA is given. Not filtered by extension: see the module docstring on why a filter is a place
# to hide a file. This suffix is used only to answer "is there any policy here at all".
REGO_SUFFIX: Final = ".rego"

# Separator between the length-prefixed fields of the digest pre-image. A NUL cannot appear in a
# path and cannot appear in the decimal length that precedes each blob, so the pre-image parses
# unambiguously and no two distinct bundles can produce the same bytes.
_DIGEST_SEPARATOR: Final = b"\x00"


class PolicyBundleError(GuardianStartupError):
    """The policy bundle could not be loaded, so this Guardian must not start.

    A subclass of :class:`~guardian.app.config.GuardianStartupError` rather than a new hierarchy,
    because the caller that handles it is the same process entry point and what it must do is the
    same thing: exit non-zero with the message intact. Being a distinct name as well as a startup
    error lets the composition root report *which* half of the configuration was unusable without
    parsing a message.

    Refusing to start is the deliberate answer to a missing or empty bundle, and the alternative is
    worth naming because it looks safer than it is. A Guardian that loaded no policy and therefore
    denied everything would be fail-closed in the narrow sense and catastrophic in the wide one: a
    whole campaign of denials, every run bundle valid, every record honestly recorded, and nothing
    anywhere saying that the policy the study is about was never loaded. A refusal to start is loud
    at the only moment it is still cheap.
    """


@dataclass(frozen=True)
class PolicyBundle:
    """A loaded policy bundle, its entrypoint, and the digest that proves which bytes were loaded.

    Frozen, and loaded exactly once at process start. Nothing re-reads the directory: a bundle that
    could change under a running Guardian would make :attr:`digest` a statement about the past, and
    the isolation assertion ADR-023 rests on would be comparing two claims rather than two loads.

    ``files`` carries the relative POSIX paths in the order they were digested. It exists for
    diagnostics -- a digest that does not match is a fact, and the file list is what turns it into
    something a person can investigate -- and it is a tuple so that the frozen dataclass is frozen
    all the way down.
    """

    path: Path
    entrypoint: str
    digest: str
    files: tuple[str, ...]

    @classmethod
    def load(cls, settings: PolicyEngineSettings) -> "PolicyBundle":
        """Read the bundle at ``settings.bundle_path`` and compute its digest, or refuse to start.

        Takes the whole :class:`~guardian.app.config.PolicyEngineSettings` rather than a path and
        an entrypoint separately, so that the two values that must agree -- where the bundle is and
        which rule inside it answers -- come from one place and cannot be supplied inconsistently
        by a caller assembling them by hand.

        Every failure raises :class:`PolicyBundleError`. There is no partial load: a directory with
        one unreadable file is not a bundle that is mostly fine, it is a bundle whose digest would
        describe something other than what OPA would evaluate.
        """
        root = Path(settings.bundle_path)
        if not root.exists():
            raise PolicyBundleError(
                f"policy bundle path {str(root)!r} does not exist. The Guardian does not start "
                "without a policy: deny-by-default is a rule the bundle expresses, not a state the "
                "absence of a bundle produces"
            )
        if not root.is_dir():
            raise PolicyBundleError(
                f"policy bundle path {str(root)!r} is not a directory; a bundle is the set of "
                "files OPA loads, and hashing one file would not describe what was evaluated"
            )

        paths = sorted(
            (item for item in root.rglob("*") if item.is_file() and not _is_hidden(item, root)),
            key=lambda item: item.relative_to(root).as_posix(),
        )
        if not any(item.suffix == REGO_SUFFIX for item in paths):
            raise PolicyBundleError(
                f"policy bundle {str(root)!r} contains no {REGO_SUFFIX} file. An empty bundle "
                "denies every action while looking configured, which is the one failure this "
                "component must never present as normal operation"
            )

        digest = hashlib.sha256()
        names: list[str] = []
        for item in paths:
            relative = item.relative_to(root).as_posix()
            try:
                content = _normalise_line_endings(item.read_bytes())
            except OSError as error:
                raise PolicyBundleError(
                    f"policy bundle file {relative!r} could not be read: {error}"
                ) from error
            digest.update(str(len(relative)).encode("ascii"))
            digest.update(_DIGEST_SEPARATOR)
            digest.update(relative.encode("utf-8"))
            digest.update(_DIGEST_SEPARATOR)
            digest.update(str(len(content)).encode("ascii"))
            digest.update(_DIGEST_SEPARATOR)
            digest.update(content)
            digest.update(_DIGEST_SEPARATOR)
            names.append(relative)

        return cls(
            path=root,
            entrypoint=settings.entrypoint,
            digest=digest.hexdigest(),
            files=tuple(names),
        )


def _is_hidden(item: Path, root: Path) -> bool:
    """Return ``True`` if any path segment below ``root`` begins with a dot.

    Editor swap files, ``.gitignore`` and VCS metadata are not what OPA loads, and letting them
    into the digest would make the isolation assertion depend on whether somebody had a file open.
    The check is on every segment rather than only the name, so a whole hidden directory is skipped
    without needing a second rule.
    """
    return any(part.startswith(".") for part in item.relative_to(root).parts)


def _normalise_line_endings(content: bytes) -> bytes:
    """Return ``content`` with CRLF and lone CR collapsed to LF.

    ADR-010's rule, applied to the bundle for ADR-022's reason. A ``.rego`` file is tracked text;
    ``.gitattributes`` normalises it to LF in the index and the development host checks it out with
    CRLF, so a raw byte hash would record which host loaded the bundle rather than which policy was
    loaded -- and the equal-across-arms assertion would then hold or fail for a reason that has
    nothing to do with the arms.

    Lone CR is folded as well as CRLF. It is not a line ending any tool here produces, and leaving
    it unnormalised would mean the rule covered the case that occurs and not the case that would be
    hardest to notice.
    """
    return content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


# --------------------------------------------------------------------------------------------
# The input document
# --------------------------------------------------------------------------------------------


class PolicyInputError(RuntimeError):
    """The document the builder produced is not one this Guardian is willing to send to an engine.

    Raised only by :func:`assert_document_is_clean`, and therefore only by a defect in this file:
    every key in the document is a literal here, so a violation means somebody added one. It is a
    ``RuntimeError`` rather than a startup error because it is reachable per-request, and
    :mod:`guardian.app.mediation` treats it as it treats any other fault in its own pipeline --
    deny under :attr:`~guardian.app.models.ReasonCode.POLICY_GUARDIAN_FAULT`, audit it, and return
    it. A Guardian defect must fail the way an attack fails, or the two become distinguishable to
    the attacker by their symptoms.
    """


def build_policy_input(
    *,
    request: ActionRequest,
    claims: CapabilityTokenClaims,
    guardian_run_id: str | None,
) -> dict[str, Any]:
    """Build the OPA input document for one verified request. Never carries free text.

    ``claims`` is required and is not nullable, which is the structural statement that **policy
    runs only on an authentic token**. A document describing an unverified claim set cannot be
    built, so no ordering mistake in :mod:`guardian.app.mediation` can put an unchecked token in
    front of a policy that might permit on it. It is typed
    :class:`~guardian.app.models.CapabilityTokenClaims` -- the model, not a mapping -- so the only
    way to reach this function is through something that has already validated the claim shapes.

    ``guardian_run_id`` is the run *this process* was started for, from
    :class:`~guardian.app.config.GuardianConfig`, and it is published under its own key rather than
    merged with the request's. The distinction is load-bearing: ``request.run_id`` is
    attacker-settable under threat-model position P1 and ``capability.run_id`` is verified but may
    belong to another run, so a policy that wants to say "this action belongs to this run" needs a
    value neither the agent nor the token can move. It is nullable because
    :class:`~guardian.app.config.GuardianConfig` allows a Guardian to be started without pinning a
    run, which is a development posture rather than a campaign one.

    Construction is additive and every section is built from a closed tuple of field names, so a
    field added to a request model later reaches this document only if somebody adds it here. The
    finished document is then walked by :func:`assert_document_is_clean` before it is returned.
    """
    document: dict[str, Any] = {
        "schema_version": POLICY_INPUT_SCHEMA_VERSION,
        "guardian": {"run_id": guardian_run_id},
        "request": _project(request, POLICY_INPUT_REQUEST_FIELDS),
        "action": _action_section(request.action),
        "capability": _capability_section(claims),
    }
    assert_document_is_clean(document)
    return document


def _action_section(action: ActionSpec) -> dict[str, Any]:
    """Return the action as policy sees it: the four identifier fields, and, for a deployment write,
    a normalised replica count beside them.

    The four identifier fields are the same projection every other section is built with. The one
    addition is D4-A's (ADR-129): when the action is a deployment write -- one of
    :data:`POLICY_INPUT_REPLICA_CARVE_OUT` -- the section also carries
    :data:`POLICY_INPUT_REPLICAS_KEY`, the normalised replica count, so
    ``guardian/policies/scope.rego`` can refuse a scale to zero. The key is attached for no other
    ``(verb, resource)`` pair, so a rule that reads ``action.replicas`` is reading a field that is
    present exactly where a replica count means something and undefined everywhere else -- which is
    what makes "an action requesting zero replicas" a question the policy can ask without a special
    case for every other verb.

    The resource is folded to its bare form first, so ``deployments`` and ``deployments.apps`` are
    the one pair the request grammar allows them to be, exactly as the executor folds them.
    """
    section = _project(action, POLICY_INPUT_ACTION_FIELDS)
    if (action.verb, _bare_resource(action.resource)) in POLICY_INPUT_REPLICA_CARVE_OUT:
        section[POLICY_INPUT_REPLICAS_KEY] = _normalised_replica_count(action)
    return section


def _bare_resource(resource: str) -> str:
    """Return ``resource`` without any API-group suffix: ``deployments.apps`` -> ``deployments``.

    The request grammar admits an optional group suffix, so one kind reaches this builder under two
    spellings; folding here means the carve-out is one pair per kind rather than one per spelling,
    the same fold :func:`guardian.app.executor._bare_resource` performs so the two agree on what a
    deployment write is. Restated rather than imported for the reason :data:`REPLICAS_PARAM` is.
    """
    return resource.split(".", 1)[0]


def _normalised_replica_count(action: ActionSpec) -> int | None:
    """Return the requested replica count as a non-negative integer, or ``None``.

    The one scalar this module derives from ``params`` rather than withholds, and it is derived, not
    passed through: the raw value is read, its shape is checked, and only a non-negative integer
    count survives. ``"0"`` and ``"00"`` both normalise to ``0``, so a scale to zero cannot be
    spelled around the rule that refuses it. Everything that is not a non-negative integer count --
    a ``bool`` (``replicas: true``, refused before ``int`` because ``bool`` subclasses it), a
    ``float``, a non-decimal string, an absent key -- normalises to ``None``, which the rule reads
    as "not a zero scale"; those shapes are refused for their own reasons by the executor's stricter
    body builder on the vanishing chance a permit is ever produced for one.
    """
    raw = action.params.get(REPLICAS_PARAM)
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isascii() and raw.isdecimal():
        return int(raw)
    return None


def _project(model: BaseModel, fields: Iterable[str]) -> dict[str, Any]:
    """Return the named fields of ``model`` as a plain JSON-ready mapping.

    ``getattr`` on an explicit name list rather than a filtered ``model_dump``, because the two
    fail in opposite directions: a filtered dump silently gains whatever the model gains, while a
    name list raises ``AttributeError`` if a field it names is removed. The partition check at
    import means the name list is never silently incomplete either.
    """
    return {name: getattr(model, name) for name in fields}


def _capability_section(claims: CapabilityTokenClaims) -> dict[str, Any]:
    """Return the verified claim set as policy sees it, with ``allow`` expanded into plain lists.

    ``allow`` is nullable in the claim set, because a token carrying ``allow: null`` must parse in
    order to be denied for its scope rather than for its shape. A null reaches policy as a null:
    substituting three empty lists here would be this module quietly deciding a scope question, and
    the three empty lists it invented would be indistinguishable in the document from three empty
    lists a Supervisor actually issued.

    The lists are converted from tuples because a tuple is not a JSON type and an engine boundary
    is a serialisation boundary; order is preserved, since two tokens differing only in claim order
    are different tokens and normalising here would hide an issuer defect.
    """
    section = _project(
        claims, tuple(name for name in POLICY_INPUT_CAPABILITY_FIELDS if name != "allow")
    )
    section["allow"] = _allow_section(claims.allow)
    return section


def _allow_section(allow: AllowClaim | None) -> dict[str, list[str]] | None:
    """Return an allow claim as three plain lists, or ``None`` when the token carried none."""
    if allow is None:
        return None
    return {key: list(getattr(allow, key)) for key in ALLOW_CLAIM_KEYS}


def build_issuance_input(
    *,
    request: TokenIssueRequest,
    guardian_run_id: str | None,
    declared_phase: str | None = None,
) -> dict[str, Any]:
    """Build the OPA input document for one issue request, for the authority entrypoint.

    The counterpart of :func:`build_policy_input`, and deliberately the same shape of function: an
    additive construction from a closed field list, checked at import against the model it reads,
    walked by :func:`assert_document_is_clean` before it is returned. The module docstring argues
    why the check is kept even though :class:`~guardian.app.models.TokenIssueRequest` carries no
    free text -- in short, because "there is nothing to exclude today" is a statement about today.

    ``guardian_run_id`` is the run *this process* was started for and is published under its own key
    rather than merged into the issue section, for the same reason the action document keeps them
    apart: ``request.run_id`` is chosen by whoever sent the body, and ``POST /v1/tokens``
    authenticates nobody, so a rule that wants to say "this capability belongs to this run" needs a
    value the caller cannot move. It is nullable because
    :class:`~guardian.app.config.GuardianConfig` permits a Guardian that pins no run, which is a
    development posture; a null constrains nothing here, exactly as it constrains nothing in
    ``scope.rego``.

    ``declared_phase`` (ADR-128, V17) is the run's *actual* current phase, recorded by the runner
    through ``POST /v1/phase`` and read from :class:`~guardian.app.control_auth.PhaseState`. It is
    published under ``guardian`` rather than merged into the issue section for the same reason
    ``guardian_run_id`` is: ``request.phase`` is the caller's word, and ``POST /v1/tokens``
    authenticates the runner but not which phase the run is in, so a rule that wants to bound a mint
    to the phase the run is *actually* in needs a value the body cannot move. ``issuance.rego``'s
    ``deny_phase_not_current`` reads it. It is nullable because before any phase is declared -- a
    Guardian no runner has driven, the development posture :class:`PhaseState` documents -- there is
    no current phase to bound against, and a null constrains nothing, as a null ``run_id`` does.

    What this function deliberately does **not** do is decide anything. It does not compare the
    requested scope against the phase's authority, does not filter the allow-claim down to what is
    permitted, and does not clamp. Filtering in particular would be the issuance-side twin of the
    truncation ``guardian/token/issuer.py`` refuses for the TTL: a caller that asked for a wide
    capability and received a narrow one would be told it succeeded, and the record would not show
    that anything had been refused. The decision is the bundle's, and its answer is read by
    :func:`interpret_policy_result` -- the same interpreter, on the same three keys, because a
    second reading of "what the engine said" is a second place the engine and this module can
    disagree.
    """
    document: dict[str, Any] = {
        "schema_version": ISSUANCE_INPUT_SCHEMA_VERSION,
        "guardian": {"run_id": guardian_run_id, "declared_phase": declared_phase},
        "issue": _project(request, ISSUANCE_INPUT_REQUEST_FIELDS),
    }
    document["issue"]["allow"] = _allow_section(request.allow)
    assert_document_is_clean(document)
    return document


def assert_document_is_clean(document: Mapping[str, Any]) -> None:
    """Raise :class:`PolicyInputError` if any key anywhere names something policy must not see.

    The runtime half of the exclusion. Walks the whole document -- mappings, lists and tuples, to
    any depth -- and compares every key against :data:`FORBIDDEN_DOCUMENT_KEYS` in the normalised
    form :func:`guardian.app.models._normalise_field_name` produces, so ``guardian_mode``,
    ``guardianMode`` and ``guardian-mode`` are one entry rather than three.

    It runs on every call rather than only under test, and it cannot produce a false positive: the
    document's keys are all literals in this module, and the attacker's strings appear only as
    values. What it can catch is the edit that adds a section, forgets the partition, and would
    otherwise be found by a test somebody skipped.

    Public because M3-C10's test and ADR-023's isolation suite both need to call it on documents
    they built themselves, which is a stronger assertion than checking the one document the builder
    happened to produce.
    """
    _walk_keys(document, "")


def _walk_keys(node: object, path: str) -> None:
    """Recurse through ``node``, raising on the first forbidden key and naming where it was."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and _normalise_field_name(key) in FORBIDDEN_DOCUMENT_KEYS:
                raise PolicyInputError(
                    f"the OPA input document carries {here!r}. security-policy.md section 1.5 "
                    "requires LLM free text to be logged and never evaluated as policy "
                    "(plan conflict M3-C10), and ADR-023 requires policy to be mode-blind. Fix the "
                    "field partition in guardian/app/policy.py rather than this check"
                )
            _walk_keys(value, here)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            _walk_keys(value, f"{path}[{index}]")


def _assert_field_partition(
    model: type[BaseModel],
    included: tuple[str, ...],
    excluded: frozenset[str],
    *,
    why: str,
) -> None:
    """Raise ``TypeError`` unless every field of ``model`` is classified exactly once.

    Both directions are failures and both are checked. A field in neither tuple is a field whose
    fate nobody decided, and the default fate of an unclassified field must not be "silently
    reaches the policy engine" -- which is what a subtraction-based builder would give it. A field
    in both is a contradiction, and a contradiction resolved by whichever line runs last is not a
    decision.

    Raising at import is the whole point: the Guardian does not start and CI does not go green.
    ``why`` is quoted into the message because whoever trips this is by definition somebody who did
    not know the partition existed.
    """
    declared = set(model.model_fields)
    overlap = sorted(set(included) & excluded)
    if overlap:
        raise TypeError(f"{model.__name__}: field(s) both included and excluded: {overlap}: {why}")
    unclassified = sorted(declared - set(included) - excluded)
    if unclassified:
        raise TypeError(
            f"{model.__name__}: field(s) in neither the included nor the excluded set: "
            f"{unclassified}: {why}"
        )
    unknown = sorted((set(included) | excluded) - declared)
    if unknown:
        raise TypeError(
            f"{model.__name__}: classified field(s) the model does not declare: {unknown}: {why}"
        )


_PARTITION_REASON: Final = (
    "every field of a request model is either sent to the policy engine or deliberately withheld "
    "from it; an unclassified field would reach policy by default, which is how "
    "security-policy.md section 1.5's 'never evaluated as policy' stops being true without "
    "anybody deciding that it should"
)

_assert_field_partition(
    ActionRequest,
    POLICY_INPUT_REQUEST_FIELDS,
    POLICY_INPUT_EXCLUDED_REQUEST_FIELDS,
    why=_PARTITION_REASON,
)
_assert_field_partition(
    ActionSpec,
    POLICY_INPUT_ACTION_FIELDS,
    POLICY_INPUT_EXCLUDED_ACTION_FIELDS,
    why=_PARTITION_REASON,
)
_assert_field_partition(
    CapabilityTokenClaims,
    POLICY_INPUT_CAPABILITY_FIELDS,
    POLICY_INPUT_EXCLUDED_CAPABILITY_FIELDS,
    why=_PARTITION_REASON,
)
_assert_field_partition(
    TokenIssueRequest,
    ISSUANCE_INPUT_REQUEST_FIELDS,
    ISSUANCE_INPUT_EXCLUDED_REQUEST_FIELDS,
    why=(
        "every field of the issue contract is either shown to the authority policy or deliberately "
        "withheld from it; an unclassified field would reach the entrypoint that decides what may "
        "be minted, by default, which is how a bound on issuance stops meaning what it says "
        "without "
        "anybody deciding that it should"
    ),
)


# --------------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------------

# The three keys an entrypoint's result object must carry, and the whole contract T3.2's Rego is
# written against. Kept to three because every additional key is a way for the engine and this
# module to disagree, and a disagreement here is a decision nobody made.
RESULT_ALLOW_KEY: Final = "allow"
RESULT_RULE_ID_KEY: Final = "rule_id"
RESULT_EXPLICIT_DENY_KEY: Final = "explicit_deny"


class PolicyEngineUnavailable(RuntimeError):
    """The engine could not be reached, started, or asked. Denies under the matching reason code.

    Raised by an engine implementation, never by this module's own logic. Distinguished from a
    timeout because ``docs/plans/M3-implementation-plan.md``'s group E treats "unavailable" and
    "timing out" as two cases, and because an outage and a slow evaluation want different
    operational responses months later when a campaign is being explained.
    """


class PolicyEngineTimeout(PolicyEngineUnavailable):
    """The engine did not answer within the configured bound.

    A subclass of :class:`PolicyEngineUnavailable` so that an engine implementation which raises
    only the general type still fails closed with a sensible code, and so that a caller catching
    the general type cannot accidentally let a timeout through. The distinction is preserved in the
    reason code, which is where the evaluation reads it.
    """


@runtime_checkable
class PolicyEngine(Protocol):
    """The narrowest surface the Guardian needs from OPA: one question, one answer, one bound.

    Deliberately not "an OPA client". This module knows nothing about how the engine is reached --
    a subprocess running the pinned ``opa`` binary, a sidecar over HTTP, or an in-process
    evaluation -- and that ignorance is the point: T3.2 chooses the transport, and a transport
    choice must not be able to change what a denial means. The implementation owns its own timeout
    handling; :func:`evaluate_policy` checks the clock as well, because a bound the callee is
    trusted to honour is not a bound.

    An implementation raises :class:`PolicyEngineUnavailable` or :class:`PolicyEngineTimeout` when
    it cannot answer. It must not return a default: a value that means "I could not evaluate" and
    is shaped like a decision is the one thing that could turn an outage into a permit, and no
    amount of care at the call site can recover a lie told at this boundary.
    """

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Evaluate the bundle's entrypoint against ``document`` and return its result object."""
        ...


class UnavailablePolicyEngine:
    """An engine that always fails, so that an unconfigured Guardian denies loudly rather than well.

    This is **not a policy**, and it contains no permit path of any kind. It exists for two
    honest uses and no others. It is the engine a Guardian holds before T3.2's bundle has an
    evaluator wired to it, so that a half-assembled process refuses every action with
    :attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_UNAVAILABLE` rather than appearing to
    work; and it is the fixture the group E case "OPA unavailable fails closed" is driven with.

    Nothing that decides anything belongs in this file. A Python engine that could permit would be
    a second policy home alongside ``guardian/policies/``, evaluated by different code, tested by
    different tests, and divergent from the Rego in exactly the cases nobody wrote a test for --
    which is the defect ``.agents/rules/00-source-of-truth.md`` exists to prevent, arriving in the
    component least able to afford it.
    """

    def __init__(self, *, detail: str = "no policy engine has been wired to this Guardian") -> None:
        self._detail = detail

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Always raise :class:`PolicyEngineUnavailable`. The arguments are accepted and ignored."""
        del document, timeout_seconds
        raise PolicyEngineUnavailable(self._detail)


@dataclass(frozen=True)
class PolicyDecision:
    """What policy said: a verdict, the structured reason for it, and the rule that produced it.

    Frozen, and constructible only through :meth:`permit` and :meth:`deny`. The direct constructor
    is reachable in Python and is not defended against, because the defence that matters is that
    every *call site* in this repository goes through one of the two classmethods and each of them
    enforces one half of :class:`~guardian.app.models.ActionResult`'s invariant at the point the
    mistake would be made rather than at the point it would be caught.

    ``rule_id`` is nullable on a denial and required on a permit. A request refused before any rule
    matched -- the deny-default case, an engine outage, a malformed result -- has no rule to name,
    and inventing one would be a lie in the audit log. A permit that named no rule would be a
    permit nobody can trace to a policy, which is exactly what deny-by-default exists to prevent.
    """

    decision: Decision
    reason_code: ReasonCode
    rule_id: str | None

    @classmethod
    def permit(cls, rule_id: str) -> "PolicyDecision":
        """Return a permit naming ``rule_id``, or raise if it does not name a rule.

        The one construction path that produces a permit in this module, and it is guarded rather
        than trusting. ``rule_id`` must satisfy the audit record's identifier grammar, because it
        is written into :attr:`~guardian.app.models.AuditRecord.policy_rule_id`: a rule id that the
        record would reject must fail *here*, before a decision has been reached, and not at the
        append -- which is the one point in the pipeline where a Guardian must not fail.
        """
        if not _is_rule_id(rule_id):
            raise ValueError(
                f"a permit must name the policy rule that granted it, and {rule_id!r} is not a "
                "usable rule id. The audit record's identifier grammar is what it must satisfy, "
                "so that a permit can never be recorded with a rule id the chain would refuse"
            )
        return cls(
            decision=Decision.PERMIT, reason_code=ReasonCode.PERMIT_RULE_ALLOW, rule_id=rule_id
        )

    @classmethod
    def deny(cls, reason_code: ReasonCode, rule_id: str | None = None) -> "PolicyDecision":
        """Return a denial carrying ``reason_code``, and the rule that refused where there was one.

        A permit-group code is refused outright. There is exactly one code that may accompany a
        permit and it is reachable only through :meth:`permit`, so a denial carrying it would be a
        record whose decision and reason contradict each other -- which
        :class:`~guardian.app.models.AuditRecord` would reject at construction, again at the one
        moment failure is unaffordable.
        """
        if reason_code is ReasonCode.PERMIT_RULE_ALLOW:
            raise ValueError(
                f"{reason_code.value!r} is the permit vocabulary and cannot accompany a denial"
            )
        return cls(
            decision=Decision.DENY,
            reason_code=reason_code,
            rule_id=rule_id if _is_rule_id(rule_id) else None,
        )


def _is_rule_id(value: object) -> bool:
    """Return ``True`` if ``value`` is a string the audit record would accept as a rule id.

    Checked against :data:`~guardian.app.models.IDENTIFIER_PATTERN` and
    :data:`~guardian.app.models.IDENTIFIER_MAX_CHARS`, imported rather than restated, so that the
    grammar a permit is validated against and the grammar the record enforces cannot drift apart.
    The rule id arrives from the policy engine, which for this purpose is untrusted input like any
    other: a bundle can be edited, and a rule id long enough to be a payload must not reach the
    chain.

    **An obligation this places on T3.2, recorded here because that is where it will be tripped
    over.** :data:`~guardian.app.models.IDENTIFIER_PATTERN` admits letters, digits, ``_``, ``:``
    and ``-`` and deliberately admits **no** ``.`` -- models.py excludes the dot so that a compact
    JWS, which is three base64url segments joined by dots, cannot be smuggled through an
    identifier field. A Rego rule referred to by its natural dotted path, ``data.guardian.allow``,
    therefore does **not** satisfy this predicate, and a bundle that returned one would have its
    permit refused under
    :attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_MALFORMED_RESULT`. That is the correct
    failure -- a permit carrying a rule id the audit record would reject is a permit that could not
    be recorded -- and it means the entrypoint must emit rule ids in a dot-free form, for example
    ``guardian:containment:allow-delete-pod``. Widening the identifier grammar to admit the dot is
    not the alternative: it would reopen the hole models.py closed.
    """
    if not isinstance(value, str) or len(value) > IDENTIFIER_MAX_CHARS:
        return False
    return re.fullmatch(IDENTIFIER_PATTERN, value) is not None


def interpret_policy_result(result: Any) -> PolicyDecision:
    """Turn whatever the engine returned into a decision. Total, pure, and permits on one path only.

    ``result`` is typed ``Any`` because it is whatever crossed a process boundary: a mapping, a
    bare ``True``, ``None``, a list, a string of JSON that somebody forgot to parse. Every one of
    those is a case this function answers rather than raises on, because it is called from the
    enforcement path and an exception here would be a Guardian fault standing in for a policy
    outcome.

    The contract T3.2's entrypoint is written against is three keys::

        {"allow": <bool>, "rule_id": <string or null>, "explicit_deny": <bool>}

    and the readings are:

    *permit* -- ``allow`` is exactly ``True`` and ``rule_id`` names a rule. Both conditions, and
    ``allow`` compared identically to ``True`` rather than for truthiness, because ``"false"``,
    ``1`` and a non-empty list are all truthy and none of them is a policy saying yes.

    *explicit deny* -- ``allow`` is ``False`` and ``explicit_deny`` is ``True``. Distinguished from
    the default so that a policy which actively refuses something is visible in the audit log as
    more than an absence, which is what :attr:`~guardian.app.models.ReasonCode.POLICY_RULE_DENY`
    exists for.

    *deny by default* -- ``allow`` is ``False`` and nothing claimed a rule refused it. This is
    security-policy section 1.1's invariant expressed as an outcome and is the answer the Guardian
    gives most often.

    *malformed* -- anything else, including the dangerous shapes: a result that is not a mapping, an
    ``allow`` that is not a boolean, and a permit that names no rule. Each denies under
    :attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_MALFORMED_RESULT`, because a result this
    Guardian cannot read is not a result it may act on, and reading an unrecognised shape
    optimistically is the only way an outage becomes a permit.
    """
    if not isinstance(result, Mapping):
        return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_MALFORMED_RESULT)
    allow = result.get(RESULT_ALLOW_KEY)
    if not isinstance(allow, bool):
        return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_MALFORMED_RESULT)
    rule_id = result.get(RESULT_RULE_ID_KEY)
    if allow is True:
        if not _is_rule_id(rule_id):
            return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_MALFORMED_RESULT)
        return PolicyDecision.permit(str(rule_id))
    if result.get(RESULT_EXPLICIT_DENY_KEY) is True:
        return PolicyDecision.deny(
            ReasonCode.POLICY_RULE_DENY, rule_id if _is_rule_id(rule_id) else None
        )
    return PolicyDecision.deny(ReasonCode.POLICY_DENY_DEFAULT)


def evaluate_policy(
    engine: PolicyEngine,
    document: Mapping[str, Any],
    *,
    timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> PolicyDecision:
    """Ask ``engine`` about ``document``. Never raises, and never permits on an error path.

    This is the single most important function in the file, and its shape is the argument. There is
    no path from an exception, an overrun or an unrecognised answer to a permit, because the only
    expression in this module that produces a permit is inside :func:`interpret_policy_result` and
    it is reached only when the engine returned normally, in time, with a well-formed positive
    result naming a rule.

    The ``except`` clauses run from specific to general and the general one is ``Exception`` rather
    than a list of the failures an engine is expected to have. An engine that raises something this
    module has never heard of is an engine that failed, and there is no reading of an unrecognised
    failure that is safer than the reading of a recognised one. ``BaseException`` is deliberately
    *not* caught: a ``KeyboardInterrupt`` or a ``SystemExit`` is the process being shut down, and a
    reference monitor that answered a request while being killed would be worse than one that did
    not answer.

    The elapsed-time check after a successful return is not redundant with the argument passed in.
    ``timeout_seconds`` is a request to the engine; this is the Guardian measuring whether the
    request was honoured. An engine that ignored it -- because a subprocess timeout was not wired,
    because an HTTP client's default applied instead -- would otherwise turn a configured bound
    into a hope, and threat-model position P3 is unbounded request volume against exactly this
    surface.

    ``monotonic`` is injectable so that the timeout case is testable without a slow engine and
    without a sleep, which is what ``.agents/rules/20-parity-and-determinism.md`` asks of anything
    with time in it. It is monotonic rather than wall-clock because a clock adjustment mid-request
    must not be able to manufacture or hide an overrun.
    """
    started = monotonic()
    try:
        result = engine.evaluate(document, timeout_seconds=timeout_seconds)
    except PolicyEngineTimeout:
        return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_TIMEOUT)
    except PolicyEngineUnavailable:
        return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_UNAVAILABLE)
    except Exception:
        # Deliberately unselective, and deliberately without the exception in the reason: the
        # structured vocabulary is what the evaluation counts, and an engine's own message is
        # attacker-influenced text that has no business in a reason code. The detail belongs in the
        # Guardian's operational log, which is not this record.
        return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_UNAVAILABLE)
    if monotonic() - started > timeout_seconds:
        return PolicyDecision.deny(ReasonCode.POLICY_ENGINE_TIMEOUT)
    return interpret_policy_result(result)
