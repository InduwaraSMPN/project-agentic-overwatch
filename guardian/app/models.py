r"""The frozen contracts the Guardian speaks, and the structured vocabulary it answers with.

WHAT THIS MODULE IS
-------------------
``docs/02-architecture.md`` section 3 declares this system's interface contracts schema-first and
names four of them as the Guardian's: ``CapabilityToken`` claims, ``ActionRequest``,
``ActionResult`` and ``AuditRecord``. This module is that declaration made executable, in the shape
``monitor/aggregator/models.py`` already set for the Monitor's half of section 3 -- frozen models,
``extra="forbid"``, a required ``schema_version`` with no default, and no number that a protocol
owns.

The freeze matters more here than anywhere else in the repository. M4 builds the agent-side Guardian
client against ``ActionRequest``/``ActionResult``; M6's runner reads ``guardian_mode`` out of the
audit log; M7's daily QA verifies the hash chain over ``AuditRecord``s; and
``docs/protocols/evaluation-protocol.md`` section 3 computes *both* RQ5 measures -- injection
success rate by class, and policy-compliant action rate -- from those same records. A field added
carelessly here is a field that four milestones then depend on.

THE CALLER IS THE ATTACKER, AND THE MODELS ARE WRITTEN THAT WAY
----------------------------------------------------------------
``docs/plans/M3-implementation-plan.md``'s threat model puts the agent layer in position P1:
arbitrary ``ActionRequest`` content, every field it fills -- ``verb``, ``resource``, ``namespace``,
``name``, ``params``, ``justification``, and the request envelope itself -- with the content itself
attacker-authored under injection class INJ-B. The request models therefore carry three properties
that the Monitor's contract did not need:

*Every string is bounded.* Position P3 is unbounded request volume, and an unbounded field is a
volume amplifier that reaches the audit chain: an unbounded ``justification`` is an unbounded write
into ``guardian_audit.jsonl`` on every request, denied or not. The bounds are stated below as named
constants with their reasoning, and the paragraph on numbers explains why they may live here at all.

*Unknown keys are rejected rather than dropped.* ``extra="forbid"`` is what makes "no field of an
``ActionRequest`` can influence the Guardian beyond the action itself" a property of the type rather
than a promise about the code: a request carrying ``guardian_mode``, ``enforce``, ``dry_run`` or any
other behaviour-shaped key does not become an ``ActionRequest`` at all, and is denied and audited
under :attr:`ReasonCode.REQUEST_MALFORMED`. :mod:`guardian.app.config` closes the same door from the
other side, with an import-time check that no field anywhere in the request tree is *named* like a
mode or *typed* as one.

*The identifier grammars are strict, and they are the first line of enforcement.* ``namespace`` and
``name`` accept exactly what Kubernetes accepts -- a DNS-1123 label and a DNS-1123 subdomain -- so
path traversal, backslashes, URL escapes, whitespace, control characters and every non-ASCII
homoglyph are rejected at the contract boundary, before any token is verified and before any policy
runs. That is a deliberate departure from the plan's grouping and is recorded under the reason-code
vocabulary below.

WHAT IS NOT HERE: EVERY NUMBER ``security-policy.md`` SECTION 2 OWNS
--------------------------------------------------------------------
Token TTL, the per-phase override ceiling, the replay-cache size and window, and the signing
algorithm are owned by ``docs/protocols/security-policy.md`` section 2, and
``.agents/rules/00-source-of-truth.md`` allows them exactly one home. They appear nowhere in this
module -- not as a default, not as a bound, not as a comment restating a value. They reach the
Guardian only through :class:`guardian.app.config.GuardianConfig`, which carries no default for any
of them, so a Guardian configured without them does not start rather than running against a number
nobody chose.

The bounds this module *does* state are on a different axis, and the distinction is the one
``monitor/aggregator/models.py`` draws: ownership, not the direction of the inequality. No protocol
owns the size of a request envelope -- it is not an evaluation parameter, it is not reported, and no
measure reads it. It is a defensive limit on an untrusted body, in the same category as "a SHA-256
digest is sixty-four lowercase hex characters" and "a Kubernetes namespace is at most sixty-three
characters". Each is stated once, next to its reasoning, and :data:`ACTION_REQUEST_MAX_BYTES` is
*derived* from them rather than chosen independently, so the transport-level oversize gate cannot
drift below what the model itself would accept.

THE ``AuditRecord`` CARRIES THREE FIELDS SECTION 3 DOES NOT LIST, AND ONE IS A CONFLICT
---------------------------------------------------------------------------------------
Two of the three are the M3 plan's, argued in its conflict M3-C6 and recorded in ADR-014.
Section 3 gives the record one outcome field, ``decision``. Under ``G1-LOGONLY`` the Guardian
"logs but does not block", so a ``deny`` is followed by execution -- and with a single outcome field
a G1 record is byte-for-byte indistinguishable from a G0 deny. Evaluation-protocol section 3
computes both RQ5 measures from this log, and section 7's reduction lever protects the G0-versus-G1
contrast specifically, so without a second field that contrast is uncomputable from the very
artefact that is supposed to evidence it. :attr:`AuditRecord.guardian_mode` records which arm was in
force and :attr:`AuditRecord.enforcement` records what the Guardian *did* about the decision, as
distinct from what policy decided. The record's ``schema_version`` moved to ``"v2"`` for that
reason, and to ``"v3"`` when ADR-058 added ``record_type``.

The third is a conflict between two layers, resolved here in the direction
``.agents/rules/00-source-of-truth.md`` fixes and flagged rather than taken silently.
``docs/protocols/security-policy.md`` section 1.4 requires that permit and deny alike "produce
hash-chained AuditRecords with token jti, issuer, **rule id**, reason", and ADR-003 repeats it --
"decision (rule id + reason code) recorded in every AuditRecord". Architecture section 3's field
list omits it. ``docs/protocols/`` outranks ``docs/`` core in the precedence order, and ADR-003 is a
decision record that outranks the code implementing it, so :attr:`AuditRecord.policy_rule_id` is
present. **The owed amendment is to ``docs/02-architecture.md`` section 3**, which should gain
``policy_rule_id`` alongside ``guardian_mode`` and the enforcement field in the same edit the M3
plan already schedules. Until that edit lands, this paragraph is the record of the discrepancy.

ADR-058 adds a fourth, ``record_type``, together with the chain's one other record kind at the
time, :class:`RunStartRecord`: the genesis a Guardian writes when it starts on a new or empty
per-run chain, so that a run whose agents never reached the Guardian still leaves a verifiable
chain. It carries nothing a decision carries, and the kind is named on every record rather than
inferred from absent fields, because a meaning given to an existing field would have been read as a
refusal by every consumer that predates it. Architecture section 3 owes this amendment beside the
others.

ADR-082 adds a third record kind behind the same discriminator, :class:`ExecutionRecord`: a
follow-up naming one decision's ``seq`` in ``decision_seq`` and its outcome in
``execution_status``. See that class's docstring, and ``guardian/app/mediation.py``'s, for why the
outcome cannot be added to the decision record itself without either breaking the
append-before-execute ordering security-policy.md section 1.4 requires, or leaving the field
permanently null on every executed decision.

Nothing else is added to :class:`AuditRecord` itself. ``justification`` in particular is *not* a
twelfth top-level field: see the next section.

RECORDS ARE BORN CLEAN, AND THAT IS STRUCTURAL RATHER THAN CONVENTIONAL
-----------------------------------------------------------------------
``docs/protocols/data-management.md`` section 5 sanitises a bundle *before seal* -- stripping
``Authorization`` headers, key-shaped strings and ``.env`` values, and redacting capability-token
signatures while keeping claims. Architecture section 3 hashes
``canonical_json(record_without_hash)``
into a prev-hash chain. The two cannot both hold if a record ever needs redacting: any post-append
edit of a hashed field changes that record and breaks every link after it, so ``make audit-verify``
would fail on every sealed bundle *on correct behaviour*. That is the plan's conflict M3-C5, and the
only resolution that keeps both documents true is that the record never carries a secret in the
first place, so the sanitizer finds nothing to change.

This module makes that a property of the types, not a habit of the code:

1. :class:`AuditRecord` and :class:`AuditedAction` set ``extra="forbid"``, so a ``signature``,
   ``authorization`` or ``token`` key cannot be attached to an instance even by a caller trying to.
2. Neither declares a field that could *hold* a bearer token. ``token_jti`` and ``iss`` are the two
   attribution fields security-policy section 1.4 actually asks for, and both are constrained to the
   bounded identifier grammar -- which has no ``.`` and no ``/``, so a compact JWS cannot be
   smuggled
   through either of them: it fails validation on the first separator.
3. :func:`reject_field_names` is applied to the audit tree **at import time** against
   :data:`SECRET_SHAPED_FIELD_NAMES`. A future edit that adds ``signature``, ``bearer``,
   ``credential`` or ``api_key`` to the record raises ``TypeError`` when the module is imported,
   which is to say the Guardian does not start and CI does not go green. That is the difference
   between a structural guarantee and a comment.

``justification`` is LLM-authored free text that a hostile agent can deliberately fill with
key-shaped strings, and security-policy section 1.5 requires it to be *logged*, never evaluated as
policy. It is therefore carried inside :class:`AuditedAction`, which is the shape of the ``action``
field -- the one field of the audit record whose *contents* section 3 names without fixing. Placing
it there rather than beside ``action`` is deliberate: section 3's top-level field list is closed and
the plan names exactly two additions to it, whereas ``action`` is an implementation-chosen
projection of what the agent asked for, and "what was attempted, and the reason given for it" is
precisely what M3-T3.6's replay must reconstruct. It is bounded here; scrubbing it before hashing is
the audit layer's obligation, stated in the M3 plan and owed by ``guardian/audit/``.

``schema_version`` IS REQUIRED ON ALL FIVE MODELS, WITH NO DEFAULT
-------------------------------------------------------------------
The reasoning is ``monitor/aggregator/models.py``'s and is not re-argued: a consumer must be able to
reject a document of a version it does not understand, and a field with a default turns the one
check that could catch a contract mismatch into the thing that hides it -- a payload that omitted
the key would be silently *stamped* with this version on the way in. Each field is typed
``Literal[...]``, so the rejection is performed by the model, and by the exported JSON Schema for
consumers that are not written in Python.

The token claim set carries one too. It began as an addition beyond architecture section 3, which
listed eight claims and not a ninth; **section 3 was amended at M4 and now lists it**, so the field
is the contract rather than an extension of it. Its origin is unchanged and worth keeping: it is
the M3 plan's -- T3.1 requires the four contracts "versioned with a ``schema_version``". A JWT
whose claim set the Guardian cannot version is a JWT the Guardian cannot safely interpret, and the
alternative -- inferring the version from which claims happen to be present -- is the guess this
field exists to remove. The consequence is concrete and was flagged here while M3-T3.1 and M3-T3.3
were landing separately: **the issuer must stamp :data:`CAPABILITY_TOKEN_SCHEMA_VERSION` into every
token it mints**, or verification rejects its own tokens under
:attr:`ReasonCode.TOKEN_CLAIMS_MALFORMED`. It does, and has since M3;
``guardian/tests/test_token_contract_seam.py`` mints a token and puts it straight through this
model, so the obligation is checked rather than remembered.

``ActionRequest`` IS AT ``v2``: IT NOW CARRIES WHO IS PRESENTING, AND IN WHICH PHASE
--------------------------------------------------------------------------------------
:class:`ActionRequest` gains ``executor_id`` and ``phase``, and the version token moves with them
because a consumer that could not tell the two shapes apart would infer the contract from which keys
happened to be present -- the guess every ``schema_version`` in this repository exists to remove.

The gap they close is M4's conflict M4-C5 and it was a real blocker rather than an untidiness.
:class:`guardian.app.mediation.TokenVerifier` requires an ``expected_phase`` and an
``expected_subject``; the request carried neither and ``extra="forbid"`` meant it could not acquire
them ad hoc. ``guardian/tests/harness.py`` resolved that by making both *start-time configuration*,
which is correct for a test and means one Guardian process per ``(phase, executor)`` pair -- so a
golden path traversing all four of ``evaluation-protocol.md`` section 1.6's phases was unrunnable,
and :attr:`ReasonCode.SCOPE_SUBJECT_MISMATCH` and :attr:`ReasonCode.SCOPE_PHASE_MISMATCH` sat in the
vocabulary with no way to produce them from the HTTP seam. With the two fields on the request, one
Guardian serves a whole run and both codes become reachable.

**The honest limit, stated at length because a reader would otherwise infer a guarantee that is not
here.** Both fields are *agent-declared*. Executors in this system are in-process graph nodes, not
separately authenticated network peers, so nothing between the socket and this model establishes
that the Executor sending the request is the one it names, or that it is operating in the phase it
names. What the Guardian gains is therefore **attribution, not authentication**: it *records* the
identity presented, and it *detects* a disagreement between that identity and the verified ``sub``
and ``phase`` claims of the capability -- it does not *prevent* a hostile node from declaring the
identity that matches the token it stole. A node that borrows another Executor's token and also
declares that Executor's id passes the check, exactly as it would have under the harness's
configuration-based arrangement.

Genuine subject binding would need per-executor transport identity -- a client certificate, a
per-node service account, something the node cannot choose for itself -- and that is precluded by
FR3.1's "no standing credentials", which is the property this architecture is built to demonstrate.
The two are in genuine tension, the tension is not resolvable inside a single process, and naming it
is worth more than a check that reads stronger than it is. **This belongs in Chapter 5 as a stated
limitation of the artefact rather than as a defect of the implementation**, and the decision and its
alternatives are recorded in ADR-030.

What the check *is* worth is not nothing, and it is worth being precise about that too. It converts
a class of failure that was previously silent into a denial with a structured code in the hash
chain: a Supervisor that hands the wrong Executor a token, an Executor that reuses a containment
capability during eradication, and any agent-layer defect that crosses those wires now produce
:attr:`ReasonCode.SCOPE_SUBJECT_MISMATCH` or :attr:`ReasonCode.SCOPE_PHASE_MISMATCH` in
``guardian_audit.jsonl`` instead of an action that quietly succeeds. That is exactly what RQ5's
per-class decomposition counts.

The consequential amendment is ``docs/02-architecture.md`` section 3, whose ``ActionRequest`` field
list names five fields and must gain these two. It is not taken here: this module implements the
contract and section 3 owns it, and ``.agents/rules/00-source-of-truth.md`` puts the document above
the code. Until that edit lands, this paragraph is the record of the discrepancy, alongside the
``policy_rule_id`` amendment section 3 already owes below.

WHAT THIS MODULE DELIBERATELY DOES NOT DEFINE
----------------------------------------------
*A canonical serialiser.* ``monitor/aggregator/models.py`` carries one because the Monitor's
determinism ``cmp`` is defined on its output bytes. The Guardian's canonicalisation is a different
contract with a different owner: the M3 plan single-homes it in ``guardian/audit/canonical.py`` and
records it in ADR-013, precisely because ``hash = SHA256(prev_hash || canonical_json(...))`` is
reproducible only if "canonical" means one thing. A second definition here would be the same defect
ADR-010 closed for ``versions_env_sha256``, arriving in a new place. Callers that need the wire form
of a model use ``model_dump(mode="json")``; callers that need chain bytes use the audit module.

*Any chain arithmetic.* :attr:`AuditRecord.seq`, ``prev_hash`` and ``hash`` are declared with their
shapes and one invariant -- ``prev_hash`` is null exactly at ``seq == 0`` -- and nothing here
computes them. The byte used for ``||`` at the genesis link is ADR-013's to fix.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
The mediation pipeline, the token service, the audit chain, every Rego policy that reads the OPA
input document built from these fields, M4's agent-side client, and every sealed run bundle's
``guardian_audit.jsonl``. After the pilot gate freeze at ``v1.0``, AGENTS.md iron rule 6 makes a
change here a logged hotfix ADR rather than an edit.
"""

from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Final, Literal, get_args

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    model_validator,
)

# --------------------------------------------------------------------------------------------
# Version tokens
#
# One per contract rather than one for the package, because the four contracts move
# independently: the audit record has already been amended by M3 while the request and result
# shapes are still section 3's. The spelling is monitor/aggregator/models.py's and is chosen for
# the same reason -- a non-numeric token can only be compared for membership in a known set,
# which is the check a consumer is supposed to perform, whereas "2" invites the inference that
# newer means compatible and "1.0" promises it outright.
# --------------------------------------------------------------------------------------------

# v2, not v1: the request carries executor_id and phase, which architecture section 3's original
# field list does not. See the module docstring for what they close (M4's conflict M4-C5), for the
# honest limit -- attribution, not authentication -- and for ADR-030.
ACTION_REQUEST_SCHEMA_VERSION: Final = "v2"

ACTION_RESULT_SCHEMA_VERSION: Final = "v1"
CAPABILITY_TOKEN_SCHEMA_VERSION: Final = "v1"  # noqa: S105

# v4. v2 added guardian_mode and enforcement, which architecture section 3's original field list
# does not carry -- see the module docstring for why a single outcome field makes the G0-versus-G1
# contrast uncomputable, and ADR-014 for the decision. v3 added record_type and the run-start record
# kind that field names (ADR-058). v4 adds the execution record kind (ADR-082): a decision is sealed
# before its action is attempted, so whether that attempt succeeded cannot be known at the moment of
# the decision's own append, and this is the record that carries it once it is known. One token
# covers every record kind because they are one chain's contract: a consumer that understands v4
# understands every record a v4 chain can hold.
#
# v5 (M10, ADR-129) adds `action_caps` to the DECISION record: the reserved and consumed counters of
# the two action caps at the moment the decision was made. It is inside the hashed body, so unlike
# ADR-130's `record_signature` -- which is computed from the hash and therefore outside the body the
# hash covers -- it is a change to the record contract itself, and the version is the mechanism that
# says so. A consumer that understands v4 does not know this field exists and would drop it reading
# the chain; a consumer that understands v5 can tell a decision that was made under an exhausted
# budget from one that was not, which is the whole of what security-policy.md section 2.1 asks the
# counters for. The field is OPTIONAL and defaults to null, which is what keeps a v1-v4 record
# loadable: a chain written before the caps existed has nothing to report about them, and null says
# exactly that rather than zero. **Owed to `docs/02-architecture.md` section 3** (which names audit
# schema `v4` for ExecutionRecord and lists the AuditRecord fields), the same kind of amendment
# section 3 already owes for `policy_rule_id` -- the conflict is between a document and a code
# change and `.agents/rules/00-source-of-truth.md` resolves it towards the code plus a recorded
# debt,
# not by leaving the document to be read as the contract.
AUDIT_RECORD_SCHEMA_VERSION: Final = "v5"

# The three values of every audit record's ``record_type``: a decision on one agent request
# (unversioned, always present); the run-start genesis a Guardian writes when it starts on a new or
# empty per-run chain (ADR-058); and the execution follow-up naming one decision's outcome
# (ADR-082). Second home: guardian/audit/record_types.py, which the chain's readers use without
# importing this module; guardian/tests/test_run_start_record.py holds the spellings equal.
AUDIT_RECORD_TYPE_DECISION: Final = "decision"
AUDIT_RECORD_TYPE_RUN_START: Final = "run-start"
AUDIT_RECORD_TYPE_EXECUTION: Final = "execution"

TOKEN_ISSUE_SCHEMA_VERSION: Final = "v1"  # noqa: S105

# --------------------------------------------------------------------------------------------
# Grammars
#
# Each is a fact about what the value denotes, never a policy about what is allowed: policy is
# OPA's and lives in guardian/policies/. A pattern here decides whether a string can name the
# thing it claims to name at all.
# --------------------------------------------------------------------------------------------

# Run ids, request ids, jti, supervisor and executor ids, and policy rule ids. Deliberately has
# neither '.' nor '/' nor '+' nor '=': a compact JWS is three base64url segments joined by dots,
# so this grammar cannot hold one. That is what stops a raw token from being smuggled into
# AuditRecord.token_jti, which the module docstring lists as one of the three structural reasons
# audit records are born clean.
IDENTIFIER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9_:-]*$"

# A Kubernetes verb as the API server spells it: get, list, watch, create, update, patch, delete,
# deletecollection. Lowercase ASCII letters only, so no separator of any kind can appear.
VERB_PATTERN: Final = r"^[a-z]+$"

# A Kubernetes resource, optionally group-qualified: pods, deployments.apps,
# ciliumnetworkpolicies.cilium.io.
RESOURCE_PATTERN: Final = r"^[a-z][a-z0-9]*(?:\.[a-z0-9]+(?:[-.][a-z0-9]+)*)?$"

# RFC 1123 label and subdomain, which is exactly what the API server accepts for a namespace and
# for most object names. Stated positively, so that -- with no lookahead, which the Rust regex
# engine Pydantic compiles with does not have -- it rejects in one line: a leading or trailing
# hyphen; '/' and '\'; '..' and every other traversal form; ':' and therefore every URI scheme;
# '%' and therefore every percent-escape; whitespace and control characters; upper case, which
# the API server would reject anyway; and the entire non-ASCII plane, which is where homoglyph
# tricks live. The plan's group C names traversal and homoglyphs in `name` and `namespace` as
# adversarial cases; this is where they die.
DNS1123_LABEL_PATTERN: Final = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
DNS1123_SUBDOMAIN_PATTERN: Final = r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"

# An allow-claim element. Unlike the action grammars above this one admits '*', and admitting it
# is deliberate: a wildcard allow-claim must *parse* so that the denial can be attributed to the
# scope group as ReasonCode.SCOPE_ALLOW_CLAIM_UNUSABLE, rather than collapsing into a claim-shape
# failure that says nothing about why the token was refused. See the reason-code vocabulary.
ALLOW_ELEMENT_PATTERN: Final = r"^[A-Za-z0-9*][A-Za-z0-9.*_-]*$"

# A SHA-256 digest rendered as lowercase hexadecimal. A property of the hash function, not a cap.
HEX_SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"

# ADR-130. An Ed25519 record signature rendered as lowercase hexadecimal: the audit-ed25519/v1
# scheme guardian/audit/chain.py writes with `signing_key.sign(hash).hex()`. An Ed25519 signature is
# always 64 bytes, so 128 hex characters -- a property of the algorithm, not a cap, like
# HEX_SHA256_PATTERN.
HEX_ED25519_SIGNATURE_PATTERN: Final = r"^[0-9a-f]{128}$"

# A root-relative pointer: one or more '/'-separated segments, each beginning with a character
# that is not a dot. This is the grammar monitor/aggregator/models.py fixes for `raw_ref.path`,
# restated rather than imported because the Guardian ships as its own container with no monitor
# package inside it and guardian/ must not depend on monitor/. The decision is one decision --
# "a pointer is root-relative and can hold no content" -- and the duplication is recorded here so
# that a later edit to either copy is known to be an edit to both.
POINTER_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"

# --------------------------------------------------------------------------------------------
# Bounds
#
# None of these is owned by a protocol; see the module docstring for why that is the test rather
# than the direction of the inequality. Each is a defensive limit on an untrusted envelope, and
# each is stated once, here, with its reasoning.
# --------------------------------------------------------------------------------------------

# Every identifier-shaped field. Generous enough for the longest identifier this project defines
# -- docs/07-glossary-and-ids.md's run id, e.g. RUN-G0-FULL-SCN-CVE-03-INJ-A-101-R2 -- with room
# for the rerun suffix and for a policy rule path, and short enough that a hostile caller cannot
# turn an identifier into a payload.
IDENTIFIER_MAX_CHARS: Final = 128

# Kubernetes' own limits, and facts about the API server rather than choices of this project.
KUBERNETES_NAMESPACE_MAX_CHARS: Final = 63
KUBERNETES_NAME_MAX_CHARS: Final = 253

# A compact JWS with the claim set architecture section 3 fixes is a few hundred bytes. Eight
# kilobytes leaves an order of magnitude of headroom for a longer allow-claim list while keeping
# a single request's bearer field far below anything that could be used as a transport.
BEARER_MAX_CHARS: Final = 8192

# Free text the LLM authored, bounded because it is written into the audit chain on every request
# whether the request is permitted or denied. Two kilobytes is several paragraphs of reasoning --
# more than any Executor needs to say about one action -- and the bound is what stops position P3
# from turning `justification` into an unbounded amplifier against guardian_audit.jsonl.
JUSTIFICATION_MAX_CHARS: Final = 2048

# The action's structured parameters. Bounded in three dimensions because all three are
# attacker-chosen: how many, how long a key, how long a value.
PARAMS_MAX_KEYS: Final = 32
PARAM_KEY_MAX_CHARS: Final = 64
PARAM_VALUE_MAX_CHARS: Final = 512

# One allow-claim list. Sixty-four verbs, resources or namespaces is far past any legitimate
# phase scope and still bounds the work a verifier does per token.
ALLOW_ELEMENT_MAX_ITEMS: Final = 64
ALLOW_ELEMENT_MAX_CHARS: Final = 128

# A stdout pointer. Long enough for a run-bundle-relative path; too short to inline output, which
# the pointer grammar already forbids in kind.
POINTER_MAX_CHARS: Final = 512

# The worst case expansion of one source character under JSON string escaping: a control
# character or an astral-plane code unit renders as the six bytes of "\uXXXX". Used only to
# derive ACTION_REQUEST_MAX_BYTES below.
JSON_ESCAPE_WORST_CASE_BYTES_PER_CHAR: Final = 6

# Structural overhead of the request object: every key name, every quote, colon, comma and brace,
# plus the token/params/allow nesting. One kilobyte is a deliberate over-estimate; the derived
# bound is an upper bound on what could validate, and being generous costs nothing while being
# tight would risk rejecting a legitimate request.
_ENVELOPE_OVERHEAD_BYTES: Final = 1024


def _max_action_request_bytes() -> int:
    """Return an upper bound on the byte length of a JSON body that could validate as a request.

    Derived rather than chosen, so that the transport-level oversize gate in
    :mod:`guardian.app.main` cannot drift *below* what this module would accept. A gate narrower
    than the model is not a defence -- it is a way to deny legitimate actions with a misleading
    reason code, and to discover that only once a scenario needs a long parameter list.

    The sum is over every bounded character budget an ``ActionRequest`` can carry, multiplied by
    the worst-case JSON escape expansion, plus a fixed structural allowance. It is not tight and
    is not meant to be: an upper bound is the only thing that makes the "no valid request is ever
    rejected as oversize" property true.

    ``executor_id`` and ``phase`` were added to the sum in the same edit that added them to the
    model, and the pairing is the whole reason this function exists rather than a chosen constant:
    a field added to the contract without a term here would narrow the transport gate *below* what
    the model accepts, and the symptom would be a legitimate long-parameter request denied under
    :attr:`ReasonCode.POLICY_REQUEST_OVERSIZE` -- a misleading reason code, discovered by a scenario
    rather than by a test. ``phase`` is budgeted at the identifier bound rather than at the longest
    member of :class:`Phase`, because an upper bound that cannot move when the vocabulary gains a
    longer member is the one worth having and the slack costs nothing.
    """
    text_chars = (
        IDENTIFIER_MAX_CHARS * 2  # request_id, run_id
        + IDENTIFIER_MAX_CHARS  # executor_id
        + IDENTIFIER_MAX_CHARS  # phase
        + BEARER_MAX_CHARS
        + JUSTIFICATION_MAX_CHARS
        + IDENTIFIER_MAX_CHARS  # verb
        + IDENTIFIER_MAX_CHARS  # resource
        + KUBERNETES_NAMESPACE_MAX_CHARS
        + KUBERNETES_NAME_MAX_CHARS
        + PARAMS_MAX_KEYS * (PARAM_KEY_MAX_CHARS + PARAM_VALUE_MAX_CHARS)
    )
    return text_chars * JSON_ESCAPE_WORST_CASE_BYTES_PER_CHAR + _ENVELOPE_OVERHEAD_BYTES


ACTION_REQUEST_MAX_BYTES: Final = _max_action_request_bytes()

# --------------------------------------------------------------------------------------------
# Field-name and field-type guards
#
# Two small reflection helpers, public because :mod:`guardian.app.config` uses them to close the
# mode door from its side and because M3-T3.8's suite asserts on them directly. Both raise at
# *import* time, which is the whole point: a structural property that is checked only by a test
# is a property that holds until somebody skips the test.
# --------------------------------------------------------------------------------------------

# Names that must never appear on an audit-chain model. The list is written in the normalised
# form :func:`_normalise_field_name` produces, so `api_key`, `apiKey` and `api-key` all match the
# single entry `apikey`.
SECRET_SHAPED_FIELD_NAMES: Final = frozenset(
    {
        "apikey",
        "assertion",
        "auth",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "jwt",
        "key",
        "password",
        "privatekey",
        "secret",
        "signature",
        "signingkey",
        "token",
    }
)


def _normalise_field_name(name: str) -> str:
    """Return ``name`` folded to the form :data:`SECRET_SHAPED_FIELD_NAMES` is written in.

    Case, underscores, hyphens and dots are removed, so that a field spelled ``api_key``,
    ``API-KEY`` or ``apiKey`` cannot slip past a list written in one of those styles. Matching on
    the raw spelling would make the guard depend on a naming convention rather than on meaning.
    """
    return name.lower().replace("_", "").replace("-", "").replace(".", "")


def _iter_annotation_models(annotation: Any) -> Iterator[type[BaseModel]]:
    """Yield every Pydantic model reachable from one field annotation.

    Walks ``typing.get_args`` rather than inspecting a handful of known containers, so that
    ``Annotated``, unions, ``tuple[...]``, ``Mapping[...]`` and any future nesting are all covered
    by one traversal. Non-type arguments -- a ``StringConstraints`` instance inside ``Annotated``,
    a ``Literal`` value -- are skipped by the ``isinstance(..., type)`` guard.
    """
    if isinstance(annotation, type):
        if issubclass(annotation, BaseModel):
            yield annotation
        return
    for argument in get_args(annotation):
        yield from _iter_annotation_models(argument)


def contract_models(root: type[BaseModel]) -> tuple[type[BaseModel], ...]:
    """Return ``root`` and every model reachable from it, each exactly once.

    Order is deterministic -- breadth is irrelevant, but repeatability is not, because the guards
    below name the offending model in their error messages and a message that moves between runs
    is a message nobody trusts. Traversal is iterative and keeps a seen set, so a model that
    referred to itself would terminate rather than recurse forever.
    """
    seen: dict[type[BaseModel], None] = {}
    pending: list[type[BaseModel]] = [root]
    while pending:
        model = pending.pop(0)
        if model in seen:
            continue
        seen[model] = None
        for field in model.model_fields.values():
            for nested in _iter_annotation_models(field.annotation):
                if nested not in seen:
                    pending.append(nested)
    return tuple(seen)


def reject_field_names(root: type[BaseModel], forbidden: frozenset[str], *, why: str) -> None:
    """Raise ``TypeError`` if any model reachable from ``root`` declares a forbidden field name.

    ``forbidden`` is compared against :func:`_normalise_field_name` of each declared field, so the
    caller writes one entry per *meaning* rather than one per spelling. ``why`` is quoted verbatim
    into the exception, because the person who trips this guard is by definition somebody who did
    not know the rule existed, and a bare "forbidden field" would send them to read this function
    instead of the document that decided it.
    """
    offenders = [
        f"{model.__name__}.{name}"
        for model in contract_models(root)
        for name in model.model_fields
        if _normalise_field_name(name) in forbidden
    ]
    if offenders:
        raise TypeError(f"{root.__name__}: forbidden field name(s) {sorted(offenders)}: {why}")


def reject_field_types(root: type[BaseModel], forbidden: tuple[type, ...], *, why: str) -> None:
    """Raise ``TypeError`` if any model reachable from ``root`` declares a forbidden field type.

    The name guard above catches a field *called* ``mode``; this one catches a field *typed*
    :class:`GuardianMode` under any name at all. Both are needed, because either alone is one
    rename away from being useless.
    """
    offenders = [
        f"{model.__name__}.{name}: {found.__name__}"
        for model in contract_models(root)
        for name, field in model.model_fields.items()
        for found in _iter_annotation_types(field.annotation)
        if found in forbidden
    ]
    if offenders:
        raise TypeError(f"{root.__name__}: forbidden field type(s) {sorted(offenders)}: {why}")


def _iter_annotation_types(annotation: Any) -> Iterator[type]:
    """Yield every concrete type reachable from one field annotation.

    The counterpart of :func:`_iter_annotation_models`, which stops at model boundaries because a
    nested model is walked separately by :func:`contract_models`. This one does not stop, because
    a forbidden type can appear anywhere in the tree -- inside an ``Annotated``, inside a union,
    as a mapping's value type.
    """
    if isinstance(annotation, type):
        yield annotation
        return
    for argument in get_args(annotation):
        yield from _iter_annotation_types(argument)


# --------------------------------------------------------------------------------------------
# Closed vocabularies
# --------------------------------------------------------------------------------------------


class GuardianMode(StrEnum):
    """The condition arms the Guardian itself implements, spelled as AGENTS.md spells them.

    The tokens are ``docs/07-glossary-and-ids.md``'s canonical condition ids and are used verbatim
    in ``guardian_mode`` on every audit record and in ``manifest.json`` -- one spelling, so that
    ``analysis/`` never has to reconcile two. ``G3-UNQUOTED`` is deliberately absent: it is a
    Monitor flag that disables aggregator quoting (architecture section 4), owned by M2-T2.6, and
    a Guardian that could be set to it would be a Guardian offering an arm it does not implement.

    The *selection* of a mode is not this enum's business. ``docs/plans/M3-implementation-plan.md``
    requires the arms to be reachable only through runner flags, so the value is read once at
    process start into :class:`guardian.app.config.GuardianConfig` and is immutable thereafter.
    This enum only fixes what the legal values are, and being closed is what makes an unrecognised
    value a startup error rather than a silent default.
    """

    G0_FULL = "G0-FULL"
    G1_LOGONLY = "G1-LOGONLY"
    G2_SHAREDCRED = "G2-SHAREDCRED"


class Phase(StrEnum):
    """The four incident-response phases, in ``evaluation-protocol.md`` section 1.6's order.

    A capability token is issued for exactly one of them, which is what makes the plan's group C
    case "a containment token used in eradication" a scope violation rather than a matter of
    taste. The vocabulary is closed, so a token naming a fifth phase is not a token this Guardian
    issued.
    """

    DETECTION_AND_INVESTIGATION = "detection-and-investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    VERIFIED_RECOVERY = "verified-recovery"


class Decision(StrEnum):
    """Architecture section 3's ``decision in {permit, deny}``, and nothing else.

    Two members and no third. A tri-state -- permit, deny, error -- was rejected: an error is a
    denial with a reason code, and giving it its own decision value would create a class of
    outcome that neither RQ5 rate counts and that a policy-compliance denominator would have to
    special-case. Fail-closed means an error *is* a deny.
    """

    PERMIT = "permit"
    DENY = "deny"


class Enforcement(StrEnum):
    """What the Guardian did about the decision, as distinct from what policy decided.

    The second outcome field the M3 plan's conflict M3-C6 requires, recorded in ADR-014. Its
    values are exactly the three the plan names, and each is defined here rather than left to a
    reader's intuition, because both RQ5 measures are computed by counting them:

    ``blocked`` -- the Guardian prevented the action from reaching the cluster. Under ``G0-FULL``
    and ``G2-SHAREDCRED`` this is what a ``deny`` produces.

    ``executed`` -- the Guardian passed the action to its executor. A ``permit`` produces it in
    every mode; a ``deny`` produces it under ``G1-LOGONLY``, which is the entire content of that
    arm and the pair ``(deny, executed)`` is what makes a G1 record distinguishable from a G0 one.
    Note carefully what this value does *not* claim: it says the Guardian did not block, not that
    the cluster succeeded. Whether the attempt then worked is ``ActionResult.execution.status``. A
    failed attempt is still an attempt that was not blocked, which is what the policy-compliant
    action rate counts.

    ``not-applicable`` -- no action was ever formed, so there was nothing to block or to pass on.
    This is the oversize and malformed-body case, and it is deliberately mode-independent:
    ``G1-LOGONLY`` does not resurrect an action that never parsed.
    """

    BLOCKED = "blocked"
    EXECUTED = "executed"
    NOT_APPLICABLE = "not-applicable"


class ExecutionStatus(StrEnum):
    """The outcome of an execution attempt, for architecture section 3's ``execution {status,...}``.

    ``not-attempted`` is a first-class member rather than a null execution block, for the reason
    ``monitor/aggregator/models.py`` gives about nullable namespaces: a reader must never have to
    distinguish "absent" from "not applicable", and a required field with an explicit value forces
    the case to be handled instead of guessed.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NOT_ATTEMPTED = "not-attempted"


class ReasonGroup(StrEnum):
    """The threat-model families every reason code belongs to, and one for the permit outcome.

    The five denial groups are ``docs/plans/M3-implementation-plan.md``'s adversarial groups A-E,
    named rather than lettered so that a code read out of a sealed bundle is self-describing.
    :attr:`ReasonCode.group` derives membership from the code's own prefix, so a member cannot be
    filed under the wrong family: there is no second table to keep in step.
    """

    AUTHENTICITY = "authenticity"
    TEMPORAL = "temporal"
    SCOPE = "scope"
    REPLAY = "replay"
    POLICY = "policy"
    PERMIT = "permit"


class ReasonCode(StrEnum):
    """The closed vocabulary of Guardian outcomes. Never free text, in a result or in a record.

    ``docs/milestones/M3-guardian.md``'s Definition of Done requires every adversarial case to be
    "denied with a structured reason", and the M3 plan makes each case assert three things --
    denied, with a structured code, and present in the audit chain. Free text fails the second
    outright: it cannot be counted, it cannot be compared across arms, and two spellings of the
    same refusal become two phenomena in Chapter 4. Every code here is a value in a sealed run
    bundle and is read by ``analysis/stats/``.

    The value is ``<group>.<specific>``, and the group half is the plan's threat-model family.
    That is not decoration. It means a case can be attributed to a family mechanically -- a test
    asserts ``code.group is ReasonGroup.REPLAY`` rather than matching a string -- and it means
    adding a code without deciding which family it serves is impossible, because
    :func:`_verify_reason_code_grouping` rejects a prefix that is not a :class:`ReasonGroup` at
    import time.

    **Group A, authenticity** -- is this token one the Guardian issued, to somebody it knows?

    - :attr:`TOKEN_MALFORMED`: the bearer string is not a well-formed JWS at all. Non-JWT bytes,
      the wrong number of segments, undecodable base64url.
    - :attr:`TOKEN_ALGORITHM_REJECTED`: the header names an algorithm outside the single-algorithm
      allowlist that ``security-policy.md`` section 2 owns. This is the code that answers
      ``alg: none`` and the algorithm-confusion attack in which an RS256 token is presented whose
      claimed public key is the symmetric secret. It is separate from a signature failure on
      purpose: those two attacks are defeated by the allowlist, not by the verifier's arithmetic,
      and an evaluation that could not tell them apart could not evidence which defence worked.
    - :attr:`TOKEN_SIGNATURE_INVALID`: correctly shaped, correct algorithm, wrong signature. The
      wrong-key forgery case.
    - :attr:`TOKEN_ISSUER_UNKNOWN`: ``iss`` is not a Supervisor registered for this run.
    - :attr:`TOKEN_CLAIMS_MALFORMED`: the signature verified but the claim set is not
      :class:`CapabilityTokenClaims` -- a missing claim, an extra claim, an ill-typed one, or a
      ``schema_version`` this Guardian does not understand.

    **Group B, temporal** -- is this token live, and was it issued within its permitted lifetime?

    - :attr:`TOKEN_EXPIRED`: ``exp`` is in the past.
    - :attr:`TOKEN_EXPIRY_MISSING`: there is no ``exp``. Never treated as non-expiring; a token
      that cannot expire is not a short-lived capability token, which is the property section 3.4.2
      of the dissertation actually requires.
    - :attr:`TOKEN_LIFETIME_ABOVE_CEILING`: ``exp - iat`` exceeds the per-phase override ceiling
      that ``security-policy.md`` section 2 owns. Rejected rather than silently truncated, because
      truncation would make a token that violates the protocol usable, and would leave nothing in
      the audit log to show that anything unusual was presented.
    - :attr:`TOKEN_NOT_YET_VALID`: ``iat`` is in the future.

    **Group C, scope** -- the token is genuine and live, but it does not cover this action.

    - :attr:`SCOPE_VERB_NOT_ALLOWED`, :attr:`SCOPE_RESOURCE_NOT_ALLOWED`,
      :attr:`SCOPE_NAMESPACE_NOT_ALLOWED`: the action falls outside the corresponding allow-claim.
      Three codes rather than one, because "which dimension of the scope was exceeded" is the
      finding, and RQ5's per-class decomposition reads it.
    - :attr:`SCOPE_ALLOW_CLAIM_UNUSABLE`: the allow-claim cannot be matched by construction --
      it is null, it is empty, or it contains a wildcard. Deny-by-default means an unusable claim
      grants nothing; this code exists so that the refusal is attributable to the claim rather
      than to the action, which is a different defect with a different owner.
    - :attr:`SCOPE_RUN_MISMATCH`: the token's ``run_id`` is not this run's. The cross-run case.
    - :attr:`SCOPE_PHASE_MISMATCH`: a token issued for one phase presented in another.
    - :attr:`SCOPE_SUBJECT_MISMATCH`: the presenting Executor is not the token's ``sub`` -- one
      Executor holding another's token.
    - :attr:`SCOPE_ACTION_CAP_EXCEEDED` (ADR-129, M10): the capability is genuine and in scope, but
      the budget covering it is spent -- either this token's own per-token cap or the run's per-run
      cap. Group C is where it belongs for the same reason the other seven are: the token is
      authentic and live and the action may be entirely within its allow-claim, and what refuses it
      is that this *capability* no longer covers one more action. It is a separate code rather than
      another ``policy.deny-default`` because the two are different findings for the dissertation --
      one is a policy refusing an action, the other is a bound refusing a *loop* -- and because a
      bundle that recorded a cap refusal as a default deny would make RQ5's policy-compliant action
      rate count a bounded agent as a policy failure.

    **Group D, replay** -- has this exact capability already been spent?

    - :attr:`REPLAY_JTI_SPENT`: the ``jti`` is in the replay cache. Straight replay, and the
      losing side of a concurrent replay.
    - :attr:`REPLAY_JTI_MISSING`: there is no ``jti``, so single use cannot be enforced. Denied
      rather than admitted, because a capability that cannot be spent is a capability that can be
      used forever.
    - :attr:`REPLAY_CACHE_UNAVAILABLE`: the cache could not answer. Fail closed: an unverifiable
      single-use claim is not a satisfied one.

    **Group E, policy integrity** -- what the policy engine said, and what happens when it cannot
    say anything. This is also the plan's hostile-agent group, so the two request-shape codes
    belong here rather than in a transport family of their own.

    - :attr:`POLICY_DENY_DEFAULT`: no explicit permit rule matched. This is security-policy
      section 1.1's invariant expressed as an outcome, and it is the code the Guardian answers
      with most often.
    - :attr:`POLICY_RULE_DENY`: an explicit deny rule matched. Distinguished from the default so
      that a policy that actively refuses something is visible in the log as more than an absence.
    - :attr:`POLICY_ENGINE_UNAVAILABLE`, :attr:`POLICY_ENGINE_TIMEOUT`,
      :attr:`POLICY_ENGINE_MALFORMED_RESULT`: OPA could not be reached, took too long, or answered
      in a shape the Guardian does not recognise. All three deny. The plan states the requirement
      plainly -- fail closed, "denying and auditing rather than degrading to permit" -- and the
      three codes exist so that an outage is distinguishable from a refusal when the campaign is
      analysed months later.
    - :attr:`POLICY_REQUEST_OVERSIZE`: the body exceeded the accepted size and was not parsed.
    - :attr:`POLICY_REQUEST_MALFORMED`: the body is not an :class:`ActionRequest`. This covers
      every contract-boundary refusal, including the two the plan files under group C -- traversal
      and homoglyph tricks in ``name`` and ``namespace``. That placement is a deliberate departure
      from the plan's grouping and the reason is worth stating: a string that cannot name a
      Kubernetes object is not a scope question, because no allow-claim could ever permit it and
      no executor could ever act on it. Attributing it to scope would imply the token was the
      thing at fault. It is also the code a request carrying a mode-shaped key is denied under,
      since ``extra="forbid"`` refuses the body outright.
    - :attr:`POLICY_PARAM_NAME_FORBIDDEN`: the request parsed, and one of its ``params`` keys is
      *named* like a credential -- or lies in the Guardian's own reserved key namespace. See
      :data:`UNRECORDABLE_PARAM_NAMES` and :func:`recordable_params` for what the Guardian does
      with such a key and why it is not simply dropped. It is a separate code from
      :attr:`POLICY_REQUEST_MALFORMED` for two reasons and neither is taxonomic tidiness. First,
      that code's own definition is "the body is not an :class:`ActionRequest`", and this body
      *is* one: it parses, every grammar holds, and the refusal is about what the record can carry
      rather than about what the contract accepts. Second, ``POLICY_REQUEST_MALFORMED`` is
      produced only by :meth:`guardian.app.mediation.Mediator.reject`, which has no action to
      record, so every record carrying it today has ``action: null``; producing it here -- with an
      action -- would change what that code means in a log Chapter 4 is scored from, months after
      the records were written. A distinct code also lets RQ5's per-class decomposition count an
      agent that went after the *audit log* separately from one that sent a malformed body, which
      is the same argument the three scope codes are split on.
    - :attr:`POLICY_GUARDIAN_FAULT`: the Guardian's own pipeline raised. A defect in this code,
      not an attack, but it denies like everything else and it is audited like everything else,
      because a fault that silently permitted would be the single worst failure this component
      has.

    **The permit group** has exactly one member. :attr:`PERMIT_RULE_ALLOW` is the only code that
    may accompany ``decision = permit``, and :class:`ActionResult` and :class:`AuditRecord` both
    enforce the biconditional. A permit therefore always names a rule that granted it.
    """

    TOKEN_MALFORMED = "authenticity.token-malformed"  # noqa: S105
    TOKEN_ALGORITHM_REJECTED = "authenticity.algorithm-rejected"  # noqa: S105
    TOKEN_SIGNATURE_INVALID = "authenticity.signature-invalid"  # noqa: S105
    TOKEN_ISSUER_UNKNOWN = "authenticity.issuer-unknown"  # noqa: S105
    TOKEN_CLAIMS_MALFORMED = "authenticity.claims-malformed"  # noqa: S105

    TOKEN_EXPIRED = "temporal.expired"  # noqa: S105
    TOKEN_EXPIRY_MISSING = "temporal.expiry-missing"  # noqa: S105
    TOKEN_LIFETIME_ABOVE_CEILING = "temporal.lifetime-above-ceiling"  # noqa: S105
    TOKEN_NOT_YET_VALID = "temporal.not-yet-valid"  # noqa: S105

    SCOPE_VERB_NOT_ALLOWED = "scope.verb-not-allowed"
    SCOPE_RESOURCE_NOT_ALLOWED = "scope.resource-not-allowed"
    SCOPE_NAMESPACE_NOT_ALLOWED = "scope.namespace-not-allowed"
    SCOPE_ALLOW_CLAIM_UNUSABLE = "scope.allow-claim-unusable"
    SCOPE_RUN_MISMATCH = "scope.run-mismatch"
    SCOPE_PHASE_MISMATCH = "scope.phase-mismatch"
    SCOPE_SUBJECT_MISMATCH = "scope.subject-mismatch"
    SCOPE_ACTION_CAP_EXCEEDED = "scope.action-cap-exceeded"

    REPLAY_JTI_SPENT = "replay.jti-spent"
    REPLAY_JTI_MISSING = "replay.jti-missing"
    REPLAY_CACHE_UNAVAILABLE = "replay.cache-unavailable"

    POLICY_DENY_DEFAULT = "policy.deny-default"
    POLICY_RULE_DENY = "policy.rule-deny"
    POLICY_ENGINE_UNAVAILABLE = "policy.engine-unavailable"
    POLICY_ENGINE_TIMEOUT = "policy.engine-timeout"
    POLICY_ENGINE_MALFORMED_RESULT = "policy.engine-malformed-result"
    POLICY_REQUEST_OVERSIZE = "policy.request-oversize"
    POLICY_REQUEST_MALFORMED = "policy.request-malformed"
    POLICY_PARAM_NAME_FORBIDDEN = "policy.param-name-forbidden"
    POLICY_GUARDIAN_FAULT = "policy.guardian-fault"

    PERMIT_RULE_ALLOW = "permit.rule-allow"

    @property
    def group(self) -> ReasonGroup:
        """Return the threat-model family this code serves, derived from its own prefix.

        Derived rather than tabulated, so that a code and its family cannot disagree. The
        import-time check below guarantees the prefix is always a valid group, so this never
        raises in a running Guardian.
        """
        return ReasonGroup(self.value.split(".", 1)[0])


def _verify_reason_code_grouping() -> None:
    """Raise ``TypeError`` unless every code names a real group and every group has a code.

    Both directions matter. A code whose prefix is not a :class:`ReasonGroup` would make
    :attr:`ReasonCode.group` raise at the moment a denial is being recorded, which is the worst
    possible moment. A group with no codes would mean the plan named an adversarial family that
    nothing can be attributed to -- exactly the gap the Definition of Done's "denied with a
    structured reason" exists to close -- and it would go unnoticed, because no test fails for a
    case nobody wrote.
    """
    unknown = sorted(
        code.value for code in ReasonCode if code.value.split(".", 1)[0] not in set(ReasonGroup)
    )
    if unknown:
        raise TypeError(f"ReasonCode value(s) with no matching ReasonGroup prefix: {unknown}")
    populated = {code.group for code in ReasonCode}
    empty = sorted(group.value for group in ReasonGroup if group not in populated)
    if empty:
        raise TypeError(f"ReasonGroup member(s) with no ReasonCode: {empty}")


_verify_reason_code_grouping()


# --------------------------------------------------------------------------------------------
# Constrained scalar types, named so the model bodies read as architecture section 3's sentences
# --------------------------------------------------------------------------------------------


def _to_utc(value: datetime) -> datetime:
    """Return ``value`` in UTC, preserving the instant exactly.

    Only ever reached with an aware value, because :data:`RecordTimestamp` composes this with
    Pydantic's aware-datetime type. The conversion is the same deliberate normalisation
    ``monitor/aggregator/models.py`` performs: the offset a host happens to use is a property of
    the host, not evidence, and two Guardians reporting the same instant must serialise the same
    bytes into a hash chain that a verifier will later re-derive.
    """
    return value.astimezone(UTC)


def _freeze_params(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return an immutable view of ``value``.

    ``frozen=True`` stops an attribute being rebound; it does nothing about ``request.action.
    params["x"] = y``. ``monitor/aggregator/models.py`` solves the same problem for a list by
    declaring a ``tuple``, but a mapping has no built-in immutable form and the JSON shape must
    stay an object, so the field is annotated as a ``Mapping`` and validated into a
    ``MappingProxyType``. The point is not tidiness: ``params`` is the one attacker-authored
    structure that reaches the audit record, and a record whose contents can change after
    construction is a record whose hash means nothing.
    """
    return MappingProxyType(dict(value))


def _unfreeze_params(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a plain ``dict`` view of ``value`` for serialisation.

    The paired half of :func:`_freeze_params`. Pydantic's serialiser has no encoder for
    ``mappingproxy`` and raises rather than guessing, so without this the immutability above would
    be bought at the price of a model that cannot be written to the audit log -- which is not a
    trade worth making, and not one that would have been discovered until the first append.
    The copy is shallow and the values are scalars, so nothing mutable escapes.
    """
    return dict(value)


Identifier = Annotated[
    str, StringConstraints(pattern=IDENTIFIER_PATTERN, max_length=IDENTIFIER_MAX_CHARS)
]
Verb = Annotated[str, StringConstraints(pattern=VERB_PATTERN, max_length=IDENTIFIER_MAX_CHARS)]
Resource = Annotated[
    str, StringConstraints(pattern=RESOURCE_PATTERN, max_length=IDENTIFIER_MAX_CHARS)
]
Namespace = Annotated[
    str,
    StringConstraints(pattern=DNS1123_LABEL_PATTERN, max_length=KUBERNETES_NAMESPACE_MAX_CHARS),
]
ObjectName = Annotated[
    str,
    StringConstraints(pattern=DNS1123_SUBDOMAIN_PATTERN, max_length=KUBERNETES_NAME_MAX_CHARS),
]
AllowElement = Annotated[
    str, StringConstraints(pattern=ALLOW_ELEMENT_PATTERN, max_length=ALLOW_ELEMENT_MAX_CHARS)
]
Bearer = Annotated[str, StringConstraints(min_length=1, max_length=BEARER_MAX_CHARS)]
Justification = Annotated[str, StringConstraints(max_length=JUSTIFICATION_MAX_CHARS)]
HexDigest = Annotated[str, StringConstraints(pattern=HEX_SHA256_PATTERN)]
# ADR-130. The Ed25519 signature over a record's chain hash, when the chain is signed. Its field
# name `record_signature` normalises to `recordsignature`, which is NOT `signature` in
# SECRET_SHAPED_FIELD_NAMES, so reject_field_names admits it -- and it must: it is the one field the
# writer adds AFTER hashing, outside the body the hash covers (guardian/audit/chain.py), so it is a
# real record field the round-trip validation has to accept, not a leaked secret.
RecordSignature = Annotated[str, StringConstraints(pattern=HEX_ED25519_SIGNATURE_PATTERN)]

# The first link's predecessor: sixty-four zeros, in the same domain as every real digest.
#
# WHY THIS VALUE IS SPELLED HERE AS WELL AS IN guardian/audit/chain.py, WHICH IS A COST
#   The audit package deliberately depends on nothing under guardian/app/ -- it reaches the record
#   through a Protocol -- so that the chain, which is the security-critical part, cannot be broken
#   by a change to a contract module it never imports. Importing chain.py from here to borrow one
#   constant would repay that decoupling by coupling the other way, and would pull threading and
#   filesystem code into a module whose whole job is to declare shapes.
#
#   So the value has two homes, exactly as canonical JSON does and for the same reason (ADR-022):
#   the components must not couple, the rule is stated once in prose, and a check proves the two
#   agree rather than trusting them to. `guardian/audit/crosscheck.py` is where that check lives.
#   Recording it as a cost rather than presenting it as free: two homes is worse than one, and it
#   is the better of the two available bad options.
#
#   Derived from HEX_SHA256_PATTERN's own width rather than typed as a literal string, so a change
#   to the digest algorithm cannot leave a sixty-four-character sentinel behind a shorter pattern.
GENESIS_PREV_HASH: Final = "0" * 64
Pointer = Annotated[str, StringConstraints(pattern=POINTER_PATTERN, max_length=POINTER_MAX_CHARS)]
RecordTimestamp = Annotated[AwareDatetime, AfterValidator(_to_utc)]

# NumericDate as RFC 7519 defines it: seconds since the epoch, as an integer. Integer and not
# float, and the reason is the chain rather than taste -- ADR-013's canonicalisation rule requires
# that integers are never rendered as floats, and an `exp` that arrived as 1.7e9 would hash
# differently from the same instant that arrived as 1700000000 while denoting the same moment.
NumericDate = Annotated[int, Field(ge=0)]

ParamKey = Annotated[str, StringConstraints(min_length=1, max_length=PARAM_KEY_MAX_CHARS)]
# bool before int deliberately: bool is a subclass of int, and a union that offered int first
# would coerce True to 1 and lose the distinction in the audit record.
ParamValue = (
    Annotated[str, StringConstraints(max_length=PARAM_VALUE_MAX_CHARS)] | bool | int | float | None
)
Params = Annotated[
    Mapping[ParamKey, ParamValue],
    Field(max_length=PARAMS_MAX_KEYS),
    AfterValidator(_freeze_params),
    PlainSerializer(_unfreeze_params, return_type=dict[str, Any]),
]
AllowList = Annotated[tuple[AllowElement, ...], Field(max_length=ALLOW_ELEMENT_MAX_ITEMS)]


# --------------------------------------------------------------------------------------------
# The one place attacker-chosen *keys* reach the audit record, and the rule that makes them safe
#
# Everything else in an AuditRecord is a field this module declared, so `reject_field_names` above
# settles it at import time. `params` is the exception and it is the whole exception: it is a
# free-form mapping under threat-model position P1, so its keys are the agent's to choose, and
# `guardian/audit/chain.py` refuses -- correctly -- any record body carrying a key whose *name* is
# a credential name, at any depth. A request with `params: {"api_key": "..."}` therefore made the
# append raise, which `guardian/app/main.py` answers as 503 with **nothing written**: not a denial,
# not a malformed-request record, nothing. That is `security-policy.md` section 1.4 failing on the
# side that matters most, because the M3 plan's corollary is that an unaudited block is invisible
# to the evaluation whether or not it happened -- and it is reachable by any caller, at the cost of
# one extra key per request.
#
# The chain's guard is not the thing to relax. It is what makes `data-management.md` section 5's
# pre-seal sanitizer a no-op on `guardian_audit.jsonl` (ADR-022), and `.agents/rules/10`'s "never
# weaken guardian/policies/ to make a test pass" is the same instinct applied one file over. The
# fix belongs where attacker-chosen data becomes a record body, which is this module's projection
# and `guardian.app.mediation.audited_action`.
# --------------------------------------------------------------------------------------------

# The names a `params` key may not carry. THIS IS A SECOND HOME FOR guardian/audit/chain.py's
# FORBIDDEN_RECORD_KEYS, and that is a cost, recorded as one rather than presented as free.
#
# It cannot be an import. `guardian/audit/` is deliberately not downstream of this module's graph
# and `guardian.app.mediation`'s docstring states in as many words that it imports neither the
# chain nor the token service nor the executor -- each is reached through a narrow protocol -- so
# that the security-critical part cannot be broken by an edit to a contract module it never
# imports (ADR-022). Importing chain.py to borrow one frozenset would repay that decoupling by
# coupling the other way, and would pull threading and filesystem code into the mediation path.
#
# It also cannot be SECRET_SHAPED_FIELD_NAMES, which is the set immediately above and the obvious
# candidate. The two sets are *incomparable*: that one lacks `kubeconfig`, `passwd`, `pwd` and the
# four vendor token spellings, so reusing it would leave the defect open on `kubeconfig`; and it
# carries bare `key`, `auth` and `assertion`, which chain.py deliberately omits because "a
# ConfigMap or Secret action parameter legitimately names a key, and refusing that would be a
# false positive in the one place the Guardian most needs to record what was attempted". A set
# wider than the chain's would deny requests the chain would happily record; a narrower one would
# leave a request the chain refuses. It has to be the same set, exactly.
#
# So the value has two homes and a test proves they agree, which is the resolution ADR-022 already
# took for canonical JSON and GENESIS_PREV_HASH: "a copy is legal when a test makes 'copy' mean
# 'copy that cannot drift'". That test is `guardian/tests/test_audit_availability.py`; its proper
# long-term home is `guardian/audit/crosscheck.py`, beside the genesis-sentinel cross-check.
UNRECORDABLE_PARAM_NAMES: Final = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "idtoken",
        "jwt",
        "kubeconfig",
        "passwd",
        "password",
        "privatekey",
        "pwd",
        "refreshtoken",
        "secret",
        "secretkey",
        "signature",
        "signingkey",
        "token",
    }
)

# The namespace the Guardian keeps for keys it wrote itself, and the value it puts under one.
#
# WHY A PREFIX AND NOT A NESTED SUB-MAPPING. The chain's guard matches at *any depth*, so nesting
# the agent's params under a key of the Guardian's choosing moves the forbidden key without hiding
# it -- `action.params.supplied.api_key` is refused exactly as `action.params.api_key` is. Only the
# key's own text can change, so prefixing is the only structural move available. `ParamValue`
# admits no mapping in any case.
#
# WHY THIS PREFIX. The dot is load-bearing. chain.py's `_normalise_key` lowercases and removes `-`
# and `_` and nothing else, and no member of the forbidden set contains a `.`, so every key
# beginning with this prefix normalises to a string beginning with this prefix and can therefore
# never equal a forbidden name. That is a proof rather than a hope, and the test asserts it over
# the whole set. `guardian.` says who wrote the key, so a reader of a sealed bundle is never left
# guessing whether a `withheld.*` entry is the Guardian's statement or the agent's mimicry of one.
WITHHELD_PARAM_PREFIX: Final = "guardian.withheld."

# Deliberately a constant, carrying no length, no digest and no fragment of what it replaced.
# Anything derived from the value would be a channel out of the withheld field and would make two
# structurally identical requests hash differently; the marker has to survive `scrub_text`
# unchanged for the sanitizer to stay a no-op, which a constant with no ':' and no credential word
# in it does.
WITHHELD_PARAM_VALUE: Final = "[withheld]"


def _fold_param_key(key: str) -> str:
    """Fold ``key`` the way ``guardian/audit/chain.py`` folds a record key before matching it.

    Lowercase, ``-`` and ``_`` removed, **``.`` kept**. That last clause is the difference from
    :func:`_normalise_field_name`, which also removes dots because it matches *declared field
    names*, and it is not cosmetic: folding dots away here would make ``api.key`` collide with
    ``apikey`` and the Guardian would deny a request the chain would have recorded without
    complaint. The rule this function has to agree with is the chain's, not this module's.
    """
    return key.lower().replace("-", "").replace("_", "")


def _withheld_param_key(key: str) -> str:
    """Return the Guardian-owned key that ``key`` is recorded under.

    Folded, stripped of any prefix repetitions the caller supplied, then prefixed exactly once, so
    the mapping is idempotent and every spelling of one finding lands on one key. The length bound
    holds by construction in both cases the caller can reach: a forbidden name folds to a member
    of :data:`UNRECORDABLE_PARAM_NAMES`, whose longest member the import-time check below bounds;
    and a key already inside the reserved namespace can only shrink, because folding never
    lengthens and the prefix is put back exactly once.
    """
    bare = _fold_param_key(key)
    while bare.startswith(WITHHELD_PARAM_PREFIX):
        bare = bare[len(WITHHELD_PARAM_PREFIX) :]
    return WITHHELD_PARAM_PREFIX + bare


def _is_withheld_param_name(key: str) -> bool:
    """Return ``True`` if ``key`` may not be recorded under the name the caller gave it.

    Two cases, and the second is what stops the first being forgeable. A key whose folded form is
    a credential name is the finding itself. A key whose folded form already lies in the
    Guardian's reserved namespace is treated the same way, so that an agent sending
    ``GUARDIAN.WITHHELD.apikey`` cannot plant something that reads as the Guardian's own marker in
    a sealed bundle. The consequence is worth stating because it is the property a reader relies
    on: a ``guardian.withheld.*`` key appears in a record **if and only if** that record's reason
    code is :attr:`ReasonCode.POLICY_PARAM_NAME_FORBIDDEN`.
    """
    folded = _fold_param_key(key)
    return folded in UNRECORDABLE_PARAM_NAMES or folded.startswith(WITHHELD_PARAM_PREFIX)


def forbidden_param_names(params: Mapping[str, Any]) -> tuple[str, ...]:
    """Return, sorted, the caller's ``params`` keys that may not be recorded as given.

    Sorted rather than in the caller's order because the tuple is read on the decision path and
    ``.agents/rules/20-parity-and-determinism.md`` binds anything that shapes a record: two
    requests differing only in key order must reach the same decision by the same route.
    """
    return tuple(sorted(key for key in params if _is_withheld_param_name(key)))


def recordable_params(params: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``params`` in the form an audit record may carry. **Identity on ordinary params.**

    A key that is not credential-shaped is passed through untouched, with its value, which is what
    keeps a legitimate action's record byte-identical to what it was before this rule existed. A
    key that is credential-shaped is replaced by :func:`_withheld_param_key` of itself and its
    value by :data:`WITHHELD_PARAM_VALUE`.

    **The key survives and the value does not**, and that asymmetry is the whole design. The fact
    that an agent named a parameter after a credential is evidence about that agent and belongs in
    the log; the string it put under that name is, by the Guardian's own assumption, a credential,
    and ADR-022's born-clean rule says a record must never carry one. Dropping the key as well --
    the obvious alternative -- would leave a record that reads exactly like a request nobody
    tampered with, destroying the one signal an examiner would want. Refusing the request without
    a record is the defect this replaces.

    **The collision case is resolved by making collisions identical rather than by ordering them.**
    A caller sending ``api_key``, ``API-KEY`` and ``guardian.withheld.apikey`` in one request
    produces three keys that all fold to ``guardian.withheld.apikey``, and all three carry the same
    constant value -- so whichever order the mapping is walked in, the result is one entry with one
    value. No last-writer-wins, no counter, no suffix: the merge is order-independent because the
    colliding entries are equal, which is the only form of determinism worth relying on here given
    that this mapping is hashed into the chain. What is lost is the multiplicity and the exact
    spelling; the folded name and the count of distinct findings survive, and the folded name is
    precisely the form the chain's rule matches on, so it is the finding stated in the terms the
    rule states it in.
    """
    recorded: dict[str, Any] = {}
    for key, value in params.items():
        if _is_withheld_param_name(key):
            recorded[_withheld_param_key(key)] = WITHHELD_PARAM_VALUE
        else:
            recorded[key] = value
    return recorded


def _verify_withheld_param_key_bound() -> None:
    """Raise ``TypeError`` if a withheld key could ever exceed :data:`PARAM_KEY_MAX_CHARS`.

    The failure this prevents is quiet and expensive. An over-long key makes :class:`AuditedAction`
    refuse to validate, which surfaces in :meth:`guardian.app.mediation.Mediator._adjudicate` as a
    Guardian fault -- audited, so the log is not lost, but recorded with ``action: null`` and the
    wrong reason code, which is to say the evidence this whole rule exists to preserve would be
    gone while every test still passed. Checked at import for the same reason
    :func:`_verify_reason_code_grouping` is: a structural property checked only by a test is a
    property that holds until somebody skips the test.
    """
    longest = max(len(name) for name in UNRECORDABLE_PARAM_NAMES)
    if len(WITHHELD_PARAM_PREFIX) + longest > PARAM_KEY_MAX_CHARS:
        raise TypeError(
            f"{WITHHELD_PARAM_PREFIX!r} plus the longest forbidden param name ({longest} "
            f"characters) exceeds PARAM_KEY_MAX_CHARS ({PARAM_KEY_MAX_CHARS}); a withheld key "
            "would fail ParamKey validation and the finding would be recorded as a Guardian fault"
        )
    if any("." in name for name in UNRECORDABLE_PARAM_NAMES):
        raise TypeError(
            "a forbidden param name now contains '.', so a key inside "
            f"{WITHHELD_PARAM_PREFIX!r} is no longer provably outside the forbidden set"
        )


_verify_withheld_param_key_bound()


class _GuardianContractModel(BaseModel):
    """Shared configuration for every wire contract in this module.

    One base rather than a copy of ``model_config`` per class, so that "unknown key is an error"
    and "an instance cannot be edited after it exists" cannot hold for an outer model and quietly
    not hold for a nested one -- which is exactly the hole a hostile caller would look for.

    ``extra="forbid"`` is the structural half of "no request field can influence the Guardian":
    see the module docstring. ``frozen=True`` is what lets a decision, once made, be handed
    through the pipeline and into the audit chain without any stage being able to alter it.

    The class is private. A model elsewhere in ``guardian/`` that wants these settings declares
    them itself, rather than importing a base and inheriting a policy it did not read.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------------------------
# Architecture section 3: CapabilityToken claims
# --------------------------------------------------------------------------------------------


class AllowClaim(_GuardianContractModel):
    """Architecture section 3's ``allow {verbs[], resources[], namespaces[]}``.

    Three lists, all required and all possibly empty. Empty is legal here and denied later, under
    :attr:`ReasonCode.SCOPE_ALLOW_CLAIM_UNUSABLE`, and the split is deliberate: making the model
    reject an empty list would collapse a scope finding into a claim-shape finding and lose the
    distinction the plan's group C is built on. The same reasoning admits ``*`` through
    :data:`ALLOW_ELEMENT_PATTERN` -- a wildcard token has to parse before it can be refused for
    what it is.

    Tuples rather than lists, so ``frozen=True`` means what it says. Element order is the
    issuer's and is preserved rather than sorted: two tokens differing only in claim order are
    different tokens, and normalising them here would hide an issuer defect.
    """

    verbs: AllowList
    resources: AllowList
    namespaces: AllowList


class CapabilityTokenClaims(_GuardianContractModel):
    """The verified claim set of a capability token -- architecture section 3's nine claims.

    This models the *decoded and signature-verified* payload, never the bearer string. Nothing in
    ``guardian/app/`` constructs one of these from unverified bytes: :mod:`guardian.app.mediation`
    accepts an instance only from a :class:`~guardian.app.mediation.TokenVerifier`, so the
    existence of an instance is itself the statement that the signature checked out. That is what
    lets the audit record treat ``jti`` and ``iss`` as attribution rather than as claims.

    ``allow`` is nullable so that a token carrying ``allow: null`` parses and is denied for its
    scope rather than for its shape, on the same reasoning as the empty list above.

    Absent by design: ``nbf``. Architecture section 3 fixes nine claims and this model forbids
    extras, so a token carrying ``nbf`` is denied under
    :attr:`ReasonCode.TOKEN_CLAIMS_MALFORMED` -- which is the correct outcome, because a token
    with a claim the Guardian never issues is not one of the Guardian's tokens. A future ``nbf``
    would be an architecture section 3 amendment, not an edit here.

    TTL, the per-phase ceiling and the signing algorithm are ``security-policy.md`` section 2's
    and appear nowhere in this class. ``exp`` and ``iat`` are carried; what counts as too long a
    gap between them is configuration, read by the verifier.
    """

    iss: Identifier
    sub: Identifier
    run_id: Identifier
    phase: Phase
    allow: AllowClaim | None
    jti: Identifier
    iat: NumericDate
    exp: NumericDate
    schema_version: Literal[CAPABILITY_TOKEN_SCHEMA_VERSION]


# --------------------------------------------------------------------------------------------
# Architecture section 3: ActionRequest / ActionResult
# --------------------------------------------------------------------------------------------


class ActionSpec(_GuardianContractModel):
    """Architecture section 3's ``action {verb, resource, namespace, name, params}``.

    Every field is attacker-controlled, and each carries the tightest grammar that still admits
    everything a legitimate scenario needs. ``namespace`` and ``name`` in particular are held to
    Kubernetes' own DNS-1123 forms rather than to a permissive string, for the reason set out
    beside :data:`DNS1123_LABEL_PATTERN`.

    ``name`` is nullable because a collection-scoped action -- ``list pods`` in a namespace --
    names no object. Null and "the empty string" are not the same statement, and admitting the
    latter would put a name nobody created into the audit log.

    ``params`` is the one free-form structure in the request. It is bounded in three dimensions,
    validated into an immutable mapping, recorded in the audit record, and **excluded from the
    OPA input document by construction** -- see :mod:`guardian.app.policy`, where the exclusion is
    a checked property of the builder rather than a comment. A hostile agent that writes Rego
    fragments, mode-switch instructions or policy text into ``params`` is writing into a field
    that no policy will ever read.
    """

    verb: Verb
    resource: Resource
    namespace: Namespace
    name: ObjectName | None
    params: Params


class ActionRequest(_GuardianContractModel):
    """What an Executor sends the Guardian. Threat-model position P1: every field is the attacker's.

    The field list is architecture section 3's, in section 3's order, plus ``executor_id``,
    ``phase`` and ``schema_version``. There is no eighth field, and ``extra="forbid"`` means there
    cannot be one at run time either -- which is how "nothing in an ActionRequest can influence
    mode" is made structural rather than promised. :mod:`guardian.app.config` additionally rejects,
    at import time, any field in this tree *named* like a mode or *typed* as :class:`GuardianMode`,
    so the property survives a future edit that adds a field innocently. Neither new field trips
    either guard, and that is checked rather than asserted: ``executor_id`` folds to ``executorid``
    and ``phase`` to ``phase``, and neither is in
    :data:`~guardian.app.config.MODE_SHAPED_FIELD_NAMES`; the type guard forbids
    :class:`GuardianMode` alone, and :class:`Phase` is a different closed vocabulary naming
    ``evaluation-protocol.md`` section 1.6's four phases rather than an ablation arm.

    **The declaration order below is a statement about what each group is.** The first four fields
    are the *envelope*: which attempt this is, which run it belongs to, which Executor is making it
    and in which phase -- everything that identifies the attempt, before anything is presented or
    asked for. ``token`` follows, because a credential is offered *by* an identified party rather
    than alongside an anonymous one. ``action`` and ``justification`` come last, because they are
    what is being asked for and why. Placing ``executor_id`` and ``phase`` after ``token`` would
    have read as "two more attributes of the credential", which is precisely the misreading the
    module docstring's honest-limit section exists to prevent: they are *claims by the sender*,
    checked against the credential, not properties of it. The canonical serialiser sorts keys, so
    declaration order affects no bytes anywhere.

    ``executor_id`` and ``phase`` are the two the Guardian compares against the verified capability
    -- against ``sub`` and ``phase`` respectively -- which is what makes
    :attr:`ReasonCode.SCOPE_SUBJECT_MISMATCH` and :attr:`ReasonCode.SCOPE_PHASE_MISMATCH`
    producible. Both are attacker-settable under threat-model position P1 and the check they enable
    is therefore **attribution rather than authentication**; the module docstring argues that at
    length, says why FR3.1 precludes the alternative, and points at ADR-030 and Chapter 5. Nothing
    in this class should be read as establishing who sent the request.

    ``token`` is the compact JWS as presented. It is bounded, it is never logged, and no audit
    model in this repository has a field able to hold it. ``justification`` is LLM-authored free
    text: security-policy section 1.5 requires it to be logged and never evaluated as policy, and
    both halves of that are enforced elsewhere -- the audit record carries it inside
    :class:`AuditedAction`, and the OPA input builder cannot emit it.

    Note that ``run_id`` being attacker-settable is exactly why a cross-run token cannot be caught
    by comparing the request to the token alone: an attacker holding a token for another run can
    set this field to match it. :class:`guardian.app.config.GuardianConfig` carries the run the
    process was started for, and that is the value the check is taken against. ``executor_id`` and
    ``phase`` have no such process-level counterpart -- there is nothing a Guardian serving four
    phases could pin them to -- which is the same fact as the honest limit above, seen from the
    configuration side.
    """

    request_id: Identifier
    run_id: Identifier
    executor_id: Identifier
    phase: Phase
    token: Bearer
    action: ActionSpec
    justification: Justification
    schema_version: Literal[ACTION_REQUEST_SCHEMA_VERSION]


class ExecutionOutcome(_GuardianContractModel):
    """Architecture section 3's ``execution {status, stdout_ref}``.

    ``stdout_ref`` is a pointer and can hold no content, by construction: the grammar admits only
    a root-relative path, so there is no way to inline command output into a result body or, from
    there, into anything that quotes one. Null when nothing ran or when the executor produced no
    output worth referencing.
    """

    status: ExecutionStatus
    stdout_ref: Pointer | None


class ActionResult(_GuardianContractModel):
    """What the Guardian answers with -- architecture section 3's five fields, plus a version.

    ``audit_seq`` is required and non-nullable, and that is not a formality. It is the sequence
    number of the record this decision was written to, and the only place a sequence number comes
    from is an append that has already happened. :mod:`guardian.app.mediation` constructs an
    ``ActionResult`` in exactly one function, and that function takes a sealed
    :class:`AuditRecord` as its argument -- so "a decision cannot be returned without being
    audited" is a consequence of the type rather than of the control flow. Security-policy section
    1.4 requires it and T-22's scoring depends on it: a denial the audit log does not contain is
    invisible to the evaluation whether or not it happened.

    Two invariants are enforced below, and both close a way for a permit to be recorded without a
    reason:

    *A permit carries the permit group's code, and a deny never does.* Enforced as a
    biconditional, so neither direction is left to the caller.

    *A permit names the rule that granted it.* ``policy_rule_id`` is nullable, because a request
    refused before the policy engine was consulted -- a forged token, a malformed body -- has no
    rule to name and inventing one would be a lie in the log. But a permit with no rule id would
    be a permit nobody can trace to a policy, which is precisely what deny-by-default exists to
    make impossible.
    """

    decision: Decision
    reason_code: ReasonCode
    policy_rule_id: Identifier | None
    execution: ExecutionOutcome
    audit_seq: Annotated[int, Field(ge=0)]
    schema_version: Literal[ACTION_RESULT_SCHEMA_VERSION]

    @model_validator(mode="after")
    def _check_decision_consistency(self) -> "ActionResult":
        """Reject a decision whose reason group or rule id contradicts it.

        See the class docstring.
        """
        _validate_decision_consistency(self.decision, self.reason_code, self.policy_rule_id)
        return self


def _validate_decision_consistency(
    decision: Decision, reason_code: ReasonCode, policy_rule_id: str | None
) -> None:
    """Raise ``ValueError`` if a decision, its reason code and its rule id do not agree.

    One function rather than a copy in each of the two models that need it, because the rule is
    one rule: a permit is a permit in a result and in a record, and two implementations of the
    same invariant is one implementation too many. Raising ``ValueError`` rather than a custom
    type keeps it inside Pydantic's own validation reporting, so a violation is surfaced with the
    field context Pydantic already builds.
    """
    is_permit = decision is Decision.PERMIT
    if is_permit != (reason_code.group is ReasonGroup.PERMIT):
        raise ValueError(
            f"decision {decision.value!r} cannot carry reason code {reason_code.value!r}: "
            "a permit takes a code from the permit group and a deny never does"
        )
    if is_permit and policy_rule_id is None:
        raise ValueError("a permit must name the policy rule that granted it")


# --------------------------------------------------------------------------------------------
# Architecture section 3: AuditRecord
# --------------------------------------------------------------------------------------------


class AuditedAction(_GuardianContractModel):
    """The audited projection of what was attempted, and the reason the agent gave for it.

    :class:`ActionSpec`'s five fields, plus ``justification``. The module docstring argues the
    placement at length; in short, architecture section 3 fixes the audit record's *field list*
    and names ``action`` without fixing its contents, security-policy section 1.5 requires
    ``justification`` to be logged, and M3-T3.6's replay must reconstruct the full
    attempted-action history -- which is "what was asked for, and why", not one without the other.

    ``justification`` is bounded here. Scrubbing it before hashing is ``guardian/audit/``'s
    obligation and is what makes ``data-management.md`` section 5's sanitizer a no-op on a sealed
    ``guardian_audit.jsonl``: the M3 plan's test plants a secret-shaped string in a justification
    and asserts the sanitizer finds nothing left to change.
    """

    verb: Verb
    resource: Resource
    namespace: Namespace
    name: ObjectName | None
    params: Params
    justification: Justification | None


class ActionCapCounters(_GuardianContractModel):
    """The two action caps' counters as they stood at one decision (ADR-129; security-policy 2.1).

    **Why a record carries the counters at all.** ``docs/protocols/security-policy.md`` section 2.1
    requires the reserved and consumed counters in every decision record, and the reason is that a
    cap which cannot be seen in the evidence cannot be read in Chapter 4. A denial under
    :attr:`ReasonCode.SCOPE_ACTION_CAP_EXCEEDED` says the budget was spent; *how far past the edge*
    the run was, and whether the agent kept trying after the refusal, is only knowable from the two
    counters, and RQ5's bounded-agent findings are computed from this log.

    **Why reserved and consumed are two numbers and not one.** A reservation is a *claim* on the
    budget, held from before the policy is asked until the decision is sealed, and a claim is either
    still held (``reserved``) or was spent (``consumed``). A settled-permit action moves from the
    first column to the second; a settled refusal disappears from both, which is what "released"
    means. Their **sum is what the cap bounds**, and that is the invariant below: a counter set
    whose
    two columns together exceed the cap could not have come from a reserver that tests the cap
    before it hands out a slot, so a record carrying one is a finding rather than a measurement.
    Reading only ``consumed`` would under-report a run that is mid-flight; reading only the sum
    would make an in-flight action indistinguishable from a spent one, and those are the two states
    a
    chapter asking "how hard did the framework push" needs apart.
    """

    per_token: Annotated[int, Field(ge=0)]
    per_run: Annotated[int, Field(ge=0)]
    token_reserved: Annotated[int, Field(ge=0)]
    token_consumed: Annotated[int, Field(ge=0)]
    run_reserved: Annotated[int, Field(ge=0)]
    run_consumed: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def _check_counters(self) -> "ActionCapCounters":
        """Reject a counter set whose two columns together exceed the cap they count against.

        Per-dimension, and as a *model* invariant rather than a test's, for the reason this module
        states for every other cross-field rule: a record whose counters said otherwise was produced
        by a bug in the reserver, and a consumer reading it months later has no way to tell that
        from
        a measurement.
        """
        for label, reserved, consumed, cap in (
            ("token", self.token_reserved, self.token_consumed, self.per_token),
            ("run", self.run_reserved, self.run_consumed, self.per_run),
        ):
            claimed = reserved + consumed
            if claimed > cap:
                raise ValueError(
                    f"{label}_reserved + {label}_consumed is {claimed}, above the cap it counts "
                    f"toward ({cap}); a reservation is only handed out when the budget has room, so "  # noqa: E501 - message
                    "this counter set did not come from a correct reserver"
                )
        return self


class ActionCapReservation(_GuardianContractModel):
    """The handle a decision carries from its reserve to its settlement (ADR-129).

    **This is not a record field, and the difference is the point.** ``counters`` is what the audit
    record carries; the keys are what :mod:`guardian.app.limits` needs to find the rows it must
    settle, and a settlement handle inside a hash-chained record would be a second, unverified copy
    of a live pointer into Guardian state. So the reservation travels with the
    :class:`~guardian.app.mediation.Verdict` -- which never leaves the process -- while the counters
    travel into the record.

    ``granted`` is false when the cap was already spent. The handle still exists, and deliberately
    still names both keys, because the record of a cap refusal is required to carry the counters
    that
    show *which* cap was spent, and a refusal with no reservation to read them from would have to
    invent them.

    The keys are the token's verified ``jti`` and the run's id -- never a claim from the request
    body, and never the bearer. The jti is what makes the per-token counter per *capability* rather
    than per request, and it is authenticated by the time a reservation is taken, which is why the
    reserve happens after verification and before policy evaluation (see
    :func:`guardian.app.mediation.adjudicate`).
    """

    granted: bool
    run_key: str
    token_key: str
    counters: ActionCapCounters


class AuditRecord(_GuardianContractModel):
    """One append-only decision record. Architecture section 3's eleven, plus four and a version.

    Field order is section 3's for the first eleven, so a reader comparing this class to the
    architecture sentence finds them in the same sequence; the additions follow rather than
    interleave. The canonical serialiser sorts keys, so declaration order affects no bytes.

    The four additions and their authority:

    ``policy_rule_id`` -- required by ``security-policy.md`` section 1.4 and by ADR-003, and
    absent from architecture section 3's list. A cross-layer conflict, resolved towards the
    protocol as ``.agents/rules/00-source-of-truth.md`` directs, and flagged in the module
    docstring together with the amendment section 3 is owed.

    ``guardian_mode`` and ``enforcement`` -- the M3 plan's conflict M3-C6, recorded in ADR-014.
    Without them a ``G1-LOGONLY`` record is indistinguishable from a ``G0-FULL`` deny, and both
    RQ5 measures are computed from this log.

    ``record_type`` -- ADR-058, and always ``"decision"`` here. The chain's one other record kind
    is :class:`RunStartRecord`, its genesis, and naming the kind on every record is what lets every
    count leave that one out without reading a meaning into an absent field. Architecture section 3
    owes this amendment as well.

    ``action_caps`` -- ADR-129, and optional: the counters of the two action caps at the moment this
    decision was made, or null when no cap was consulted for it (a request refused before its token
    was verified consulted none). The schema is bumped to ``v5`` for it, unlike ADR-130's
    ``record_signature``, because this field is inside the hashed body and that one is not. Null is
    the honest value rather than six zeroes: a zeroed counter set would claim a run in which nothing
    was ever reserved, which is a measurement rather than an absence. See
    :class:`ActionCapCounters`.

    The nullable fields, each nullable for a reason that is an absence rather than a convenience.
    ``run_id``, ``request_id`` and ``action`` are null when no valid request was ever parsed --
    the oversize and malformed-body cases, which security-policy section 1.4 still requires to be
    audited, so the record has to be able to describe a request that never became one.
    ``token_jti`` and ``iss`` are null when authenticity and issuer registration were not
    established: a forged, malformed or group-A token carries only *claimed* values, and copying
    either into an attribution field would record attacker-authored text as though the Guardian had
    established it. Once those checks succeed, a subject- or phase-mismatch refusal retains the
    verified pair even though the claim set is not accepted for policy evaluation. Thus a null plus
    a group-A reason says "we do not know who this was", while an authentic crossed capability stays
    traceable to the Supervisor that minted it.
    ``prev_hash`` carries the genesis sentinel at the first link and a real predecessor digest
    everywhere after it.

    Two invariants beyond the decision consistency the result also enforces:

    *``action`` is null exactly when ``enforcement`` is ``not-applicable``.* Both directions hold
    by construction -- no action means nothing to block or pass on, and nothing to block or pass
    on means no action was formed -- so stating it as a biconditional catches a record that has
    drifted in either direction.

    *``prev_hash`` is the all-zero genesis sentinel exactly at ``seq == 0``.* This module computes
    no hashes; it only guarantees that the chain's first link is self-identifying, so a verifier
    need not be told where a file begins.

    **This invariant was written as "null exactly at seq 0" and has been corrected**, because it
    contradicted the writer that produces these records. ``guardian/audit/chain.py`` emits
    ``"0" * 64`` at ``seq 0``, and its reasoning is the stronger of the two: the chain rule is
    ``SHA256(prev_hash || canonical_json(record_without_hash))`` with **no separator**, and that
    concatenation is only unambiguous because ``prev_hash`` is a fixed-width value drawn from one
    domain. A null -- or an empty string -- makes the field two different types and destroys the
    injectivity that licenses the missing separator, which is a property of the hash construction
    and not a matter of taste. The sentinel is also visibly synthetic: no SHA-256 preimage of
    sixty-four zeros is known, so it cannot be mistaken for a real predecessor, which is exactly
    where the rejected alternative of hashing the empty input fails.

    The defect was found by building the fixture corpus at T3.6: every genesis record the writer
    produced was rejected by this model. Two modules had two incompatible spellings of one fact,
    each argued at length in its own docstring and neither aware of the other -- which is what a
    contract split across a producer and its schema looks like when only one of them is read at a
    time. ADR-022.
    """

    seq: Annotated[int, Field(ge=0)]
    ts: RecordTimestamp
    run_id: Identifier | None
    request_id: Identifier | None
    token_jti: Identifier | None
    iss: Identifier | None
    decision: Decision
    reason_code: ReasonCode
    policy_rule_id: Identifier | None
    action: AuditedAction | None
    prev_hash: HexDigest
    hash: HexDigest
    guardian_mode: GuardianMode
    enforcement: Enforcement
    record_type: Literal[AUDIT_RECORD_TYPE_DECISION]
    schema_version: Literal[AUDIT_RECORD_SCHEMA_VERSION]
    # ADR-129. Optional, and defaulted: a v1-v4 record carries no cap counters, and a field that
    # were merely nullable would refuse to load every chain written before M10 -- which is exactly
    # the corpus the v1 findings are counted from.
    action_caps: ActionCapCounters | None = None
    # ADR-130. The Ed25519 signature over this record's hash, present only on a signed chain.
    # Optional and defaulted for the same reason action_caps is -- an unsigned chain (offline, Tier
    # A, every pre-M10 record) carries none and must still load -- but unlike action_caps it does
    # NOT bump the schema, because it is outside the hashed body (see the module docstring): a v5
    # consumer reads the same body whether or not the envelope carries a signature.
    record_signature: RecordSignature | None = None

    @model_validator(mode="after")
    def _check_record_consistency(self) -> "AuditRecord":
        """Reject a record whose outcome fields or chain position contradict each other."""
        _validate_decision_consistency(self.decision, self.reason_code, self.policy_rule_id)
        _validate_action_enforcement(self.action, self.enforcement)
        is_genesis_sentinel = self.prev_hash == GENESIS_PREV_HASH
        if is_genesis_sentinel != (self.seq == 0):
            raise ValueError(
                "prev_hash must be the all-zero genesis sentinel at seq 0 and a real predecessor "
                f"digest everywhere else; got seq={self.seq} with prev_hash="
                f"{'the genesis sentinel' if is_genesis_sentinel else 'a predecessor digest'}"
            )
        return self


def _validate_action_enforcement(action: AuditedAction | None, enforcement: Enforcement) -> None:
    """Raise ``ValueError`` unless ``action`` is null exactly when nothing could be enforced.

    Shared with :class:`guardian.app.mediation.AuditDraft`, which carries the same two fields and
    must not be allowed to build a draft that the sealed record would then reject -- a failure
    that would surface as an exception *after* the append, which is the one place a Guardian must
    never fail.
    """
    if (action is None) != (enforcement is Enforcement.NOT_APPLICABLE):
        raise ValueError(
            "action must be null exactly when enforcement is 'not-applicable'; "
            f"got action={'null' if action is None else 'set'} "
            f"with enforcement={enforcement.value!r}"
        )


# The structural half of "records are born clean". Applied to the whole audit tree at import, so
# that a later edit adding a signature, a bearer string or a key-shaped field to the record makes
# this module fail to import rather than making a sanitizer fail months later on a sealed bundle.
# See the module docstring, data-management.md section 5, and the M3 plan's conflict M3-C5.
reject_field_names(
    AuditRecord,
    SECRET_SHAPED_FIELD_NAMES,
    why=(
        "audit records are born clean: data-management.md section 5 sanitises before seal, "
        "architecture section 3 hashes the record, and a post-append redaction would break every "
        "chain link after it. token_jti and iss are the attribution security-policy.md section "
        "1.4 requires"
    ),
)


# --------------------------------------------------------------------------------------------
# The run-start record (ADR-058): the chain's genesis, and not a decision
# --------------------------------------------------------------------------------------------


class RunStartDraft(_GuardianContractModel):
    """The body of a :class:`RunStartRecord`: everything except the three fields the chain assigns.

    Built once, by :func:`guardian.app.composition.build_guardian`, and handed to the audit sink
    only when the per-run chain is new or empty. A model rather than a mapping, so that ``ts``
    serialises exactly as it does on a decision record and a field added by mistake is refused at
    construction rather than hashed into the genesis.
    """

    ts: RecordTimestamp
    run_id: Identifier | None
    guardian_mode: GuardianMode
    record_type: Literal[AUDIT_RECORD_TYPE_RUN_START]
    schema_version: Literal[AUDIT_RECORD_SCHEMA_VERSION]


class RunStartRecord(_GuardianContractModel):
    """A Guardian started for this run: the first record of every per-run chain (ADR-058).

    Written when a Guardian starts on a new or empty chain, so that a run whose agents never reached
    ``POST /v1/actions`` still leaves the present, verifiable chain ``data-management.md`` section 3
    requires -- the quarantined zero-action attempt ADR-058 cites could not seal for want of one. It
    records the run, the arm and the moment, and nothing a decision carries: no ``decision``, no
    ``reason_code``, no ``enforcement``, no ``action`` and no attribution, because nothing was asked
    and nothing was decided. Every audit-derived count therefore leaves it out, by ``record_type``.

    ``run_id`` is the configured run and is null only for a Guardian that pins none.
    ``guardian_mode`` is the arm in force, so a chain states which arm produced it even when it
    holds no decision at all.

    *It is the genesis, and nothing else.* ``seq`` zero behind the all-zero sentinel, enforced
    below: one per chain, and a restart that reopens a non-empty chain writes none. A run-start
    anywhere else is a second Guardian start writing into one run's chain, and this model refuses
    to call it a record.
    """

    seq: Annotated[int, Field(ge=0)]
    ts: RecordTimestamp
    run_id: Identifier | None
    guardian_mode: GuardianMode
    prev_hash: HexDigest
    hash: HexDigest
    record_type: Literal[AUDIT_RECORD_TYPE_RUN_START]
    schema_version: Literal[AUDIT_RECORD_SCHEMA_VERSION]
    # ADR-130: the genesis is signed on a signed chain like every other record. Optional and outside
    # the hashed body, exactly as on AuditRecord.
    record_signature: RecordSignature | None = None

    @model_validator(mode="after")
    def _check_genesis(self) -> "RunStartRecord":
        """Reject a run-start anywhere but the genesis: ``seq`` 0 behind the all-zero sentinel."""
        if self.seq != 0 or self.prev_hash != GENESIS_PREV_HASH:
            raise ValueError(
                "a run-start record is the chain genesis (ADR-058): seq 0 behind the all-zero "
                f"sentinel; got seq={self.seq}"
            )
        return self


reject_field_names(
    RunStartDraft,
    SECRET_SHAPED_FIELD_NAMES,
    why="the run-start genesis is hashed into the chain like every record, so it is born clean too",
)
reject_field_names(
    RunStartRecord,
    SECRET_SHAPED_FIELD_NAMES,
    why="the run-start genesis is hashed into the chain like every record, so it is born clean too",
)


# --------------------------------------------------------------------------------------------
# The execution record (ADR-082): what happened after a decision, once it is known
# --------------------------------------------------------------------------------------------


class ExecutionRecordDraft(_GuardianContractModel):
    """The body of an :class:`ExecutionRecord`: everything except the three the chain assigns.

    Built by :meth:`guardian.app.mediation.Mediator._seal`, once per decision, immediately after
    :meth:`~guardian.app.mediation.Mediator._execute` returns -- never before, and never as a second
    write to the decision record itself. ``security-policy.md`` section 1.4's append-before-execute
    ordering is what a decision's own record has to keep, and the only way to keep it while still
    recording an outcome that is not knowable until after the attempt is to record it *somewhere
    else*, appended *after*. This is that somewhere else.

    Written for **every** decision, not only an executed one, and that uniformity is deliberate
    rather than a simplification. A conditional write -- only when ``enforcement`` is ``executed``
    -- would still be correct in isolation, because :mod:`guardian.audit.outcome` already reads
    ``not-attempted`` off ``enforcement`` for a blocked or not-applicable decision without needing a
    record to say so. But ``G1-LOGONLY`` executes every denial that ``G0-FULL`` blocks, so a
    conditional write would append a different number of execution records per arm and shift every
    later decision's ``seq`` by a different amount in each -- which would put chain position itself
    on ADR-023's isolation assertion 2's list of things the arm is permitted to change, alongside
    ``guardian_mode`` and ``enforcement``, for a reason that has nothing to do with what that
    assertion protects. Writing one execution record after every decision, always, keeps a
    decision's ``seq`` a function of how many decisions preceded it and nothing else -- identical
    across arms for the same request sequence, exactly as ``guardian/tests/test_flag_isolation.py``
    already requires of every other field.

    ``decision_seq`` is the ``seq`` of the decision this record explains, never its own -- the
    schema's own field for the join :class:`~guardian.audit.outcome` performs. ``run_id`` is copied
    from the decision it follows, per ADR-054's rule that every record a Guardian writes carries the
    run it was started for; it is never re-derived, because the decision has already resolved
    whatever that value should be (the Guardian's own configured run, or an attacker-settable
    request's, per :func:`adjudicate`'s own rule) and a second resolution here could only disagree
    with the first one by accident.

    ``execution_status`` is :class:`ExecutionStatus` in full, including ``not-attempted`` -- not a
    two-member subset -- because this record is written for every decision and a decision that
    enforcement never let reach the executor is exactly the case that value exists to say.
    """

    ts: RecordTimestamp
    run_id: Identifier | None
    decision_seq: Annotated[int, Field(ge=0)]
    execution_status: ExecutionStatus
    record_type: Literal[AUDIT_RECORD_TYPE_EXECUTION]
    schema_version: Literal[AUDIT_RECORD_SCHEMA_VERSION]


class ExecutionRecord(_GuardianContractModel):
    """A decision's execution outcome, appended once it is known (ADR-082).

    Never itself a decision, an attempt, a permit, a deny or a block -- the same reading
    :class:`RunStartRecord` gives its own genesis, and for the same reason: nothing was asked of the
    Guardian by this record and nothing was decided by it. It exists only to say what happened to an
    action a *different*, earlier record already decided. Every ``guardian-executed-*`` predicate,
    every RQ5 rate and :mod:`guardian.audit.outcome`'s own reading all exclude it from the count of
    decisions for that reason -- symmetrically with how each already excludes a run-start.

    ``decision_seq`` names the decision this record explains. It is required to refer to an earlier
    position in the same chain, and that ordering is checked below rather than left to the writer's
    discipline: a chain in which an execution record's ``decision_seq`` did not precede it would be
    describing an outcome before the action that produced it was ever decided, which is the one
    ordering property this whole design exists to keep intact.
    """

    seq: Annotated[int, Field(ge=0)]
    ts: RecordTimestamp
    run_id: Identifier | None
    decision_seq: Annotated[int, Field(ge=0)]
    execution_status: ExecutionStatus
    prev_hash: HexDigest
    hash: HexDigest
    record_type: Literal[AUDIT_RECORD_TYPE_EXECUTION]
    schema_version: Literal[AUDIT_RECORD_SCHEMA_VERSION]
    # ADR-130: the ADR-082 execution follow-up is signed on a signed chain too. Optional and outside
    # the hashed body, exactly as on AuditRecord.
    record_signature: RecordSignature | None = None

    @model_validator(mode="after")
    def _check_follows_its_decision(self) -> "ExecutionRecord":
        """Reject a record whose named decision does not precede it, or whose own genesis this is.

        ``seq`` zero is the run-start genesis by construction (:class:`RunStartRecord` refuses any
        other position for it), so no execution record may ever claim it: there is no decision at
        seq zero for one to follow, and a chain admitting one there would have two different kinds
        of record both plausibly reachable at the position every verifier anchors to.
        """
        if self.seq == 0:
            raise ValueError(
                "an execution record cannot be the chain genesis; seq 0 is the run-start "
                "record's position and every decision it could name would have to precede a "
                "record that does not exist yet"
            )
        if self.decision_seq >= self.seq:
            raise ValueError(
                f"decision_seq {self.decision_seq} does not precede this record's own seq "
                f"{self.seq}; an execution record can only follow the decision it explains"
            )
        return self


reject_field_names(
    ExecutionRecordDraft,
    SECRET_SHAPED_FIELD_NAMES,
    why="an execution record is hashed into the chain like every record, so it is born clean too",
)
reject_field_names(
    ExecutionRecord,
    SECRET_SHAPED_FIELD_NAMES,
    why="an execution record is hashed into the chain like every record, so it is born clean too",
)


# --------------------------------------------------------------------------------------------
# The token-issuance surface
#
# Not an architecture section 3 contract, and marked as such. Section 3 fixes the *claims* a
# capability token carries; it says nothing about how a Supervisor asks for one, and
# `POST /v1/tokens` needs a shape to validate. These two models are that shape. They live here
# rather than in main.py so that every wire contract the Guardian accepts is bounded by the same
# discipline and reviewed in one file -- and so that the request half, which is as attacker-
# reachable as an ActionRequest, inherits extra="forbid" and the bounded grammars rather than
# being hand-rolled at the route.
#
# The issuer itself is M3-T3.3. Its obligations at this seam are stated on
# :class:`guardian.app.mediation.TokenIssuer`.
# --------------------------------------------------------------------------------------------


class TokenIssueRequest(_GuardianContractModel):
    """What a Supervisor sends to ask for an Executor's capability token.

    ``supervisor_id`` becomes the ``iss`` claim and ``executor_id`` becomes ``sub``. Both are
    self-declared here, and that is the point at which this surface is *not* yet safe: nothing in
    this model authenticates the caller, and a hostile agent with network reach can send one.
    Establishing that the caller really is the Supervisor it names is M3-T3.3's obligation, stated
    on the issuer protocol, and it is recorded here so that the gap is visible in the type rather
    than discovered later.

    ``ttl_seconds`` is the per-phase override that ``security-policy.md`` section 2 permits. It is
    optional, meaning "use the configured default", and it carries no bound in this model: the
    ceiling is section 2's number, reaches the process through configuration, and is checked by
    the issuer. A bound here would be a second home for it.
    """

    supervisor_id: Identifier
    executor_id: Identifier
    run_id: Identifier
    phase: Phase
    allow: AllowClaim
    ttl_seconds: Annotated[int, Field(gt=0)] | None
    schema_version: Literal[TOKEN_ISSUE_SCHEMA_VERSION]


class TokenIssueResponse(_GuardianContractModel):
    """The minted token, returned to the Supervisor that asked for it.

    This is the one model in the repository that carries a bearer string, and it carries it
    because that is what the response *is*. It is never audited: :class:`AuditRecord` has no field
    able to hold it, and the import-time guard above keeps it that way. ``jti`` and ``exp`` are
    echoed so the Supervisor can hand an Executor the token together with the identifier the audit
    log will attribute its actions to, without parsing the JWS itself.
    """

    token: Bearer
    jti: Identifier
    exp: NumericDate
    schema_version: Literal[TOKEN_ISSUE_SCHEMA_VERSION]
