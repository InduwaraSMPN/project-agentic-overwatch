# issuance.rego -- may this capability be minted at all? Deny unless the authority declares it.
#
# WHAT THIS FILE IS
# -----------------
# The second entrypoint of this bundle. `guardian.rego` answers "may this action proceed"; this file
# answers "may this capability exist", and it is consulted before anything is signed. Point
# `GUARDIAN_ISSUANCE_ENTRYPOINT` at `data.guardian.issuance.decision`.
#
# It exists because of M4's conflict M4-C6. `guardian.rego`'s permit rule grants exactly what the
# presented token's allow-claim covers -- which is ADR-003's instruction, and right -- while
# `POST /v1/tokens` establishes no identity for whoever asked for that claim. Put together, a party
# with network reach to the issue surface writes its own allow-claim and the permit follows from it,
# and the mediated path is not mediated. `authority.rego` is the human-authored ceiling that closes
# the consequence; this file is the rule that reads it.
#
# THE ANSWER IS THE SAME THREE KEYS `guardian.rego` ANSWERS WITH
# ---------------------------------------------------------------
# `interpret_policy_result` in `guardian/app/policy.py` reads:
#
#     {"allow": <boolean>, "rule_id": <string|null>, "explicit_deny": <boolean>}
#
# and this file emits exactly that shape, deliberately reusing the reader rather than introducing a
# second one. A separate interpreter for issuance would be a second place the Guardian and its
# engine could disagree about what an answer means, in a component whose failures are silent. The
# strictness on the Python side is what makes "this bundle never emits anything else" a checked
# property rather than an intention: `allow` is compared to `true` by identity, and any shape the
# reader does not recognise denies.
#
# `rule_id` VALUES USE COLONS AND NEVER A DOT
# --------------------------------------------
# Every identifier below is written `guardian:issue:<what>`, for the reason `guardian.rego`'s header
# gives at length: a rule id can be written into the hash-chained record the Guardian appends, whose
# identifier grammar admits letters, digits, `_`, `:` and `-` and deliberately admits no `.` --
# because a compact JWS is three base64url segments joined by dots, and an identifier field able to
# hold one would be a place to smuggle a credential into a record that must be born clean. The
# natural Rego path, `data.guardian.issuance.decision`, does not satisfy that grammar, which is why
# the ids are constants here and every one of them is tested.
#
# The `issue:` middle segment separates these from `guardian.rego`'s `permit:` and `deny:` ids, so
# that a value read out of a sealed run months later says which question it answered.
#
# THE INPUT DOCUMENT, WHICH IS A CLOSED CONTRACT AND CARRIES NO FREE TEXT
# ------------------------------------------------------------------------
# `guardian/app/policy.py`'s `build_issuance_input` builds it from a field partition checked when
# that module is imported, so this is the whole of it:
#
#   {"schema_version": "v1",
#    "guardian": {"run_id": <string|null>},
#    "issue": {"supervisor_id": <string>, "executor_id": <string>, "run_id": <string>,
#              "phase": <string>, "ttl_seconds": <integer|null>,
#              "allow": {"verbs": [<string>], "resources": [<string>],
#                        "namespaces": [<string>]}}}
#
# Unlike the action document there is nothing withheld from it, because the issue contract carries
# no free text and no free-form map: every field is a bounded identifier, a closed vocabulary, a
# bounded list or an integer. The partition check is kept anyway, and the reason is stated in that
# module: "there is nothing to exclude today" is a statement about today.
#
# `ttl_seconds` is in the document and no rule below reads it. That is deliberate and is worth
# saying rather than leaving as an apparent omission: `docs/protocols/security-policy.md` section 2
# owns the lifetime and its ceiling, `guardian/token/issuer.py` applies them and refuses rather than
# truncating, and a clause here would be a second home for a number allowed exactly one. It is
# carried so that the declaration a person reads is the whole request, not a filtered view of it.
#
# WHAT THIS FILE DOES NOT CLOSE, STATED PLAINLY
# ----------------------------------------------
# **Caller identity is still not established.** Nothing here, and nothing anywhere between the
# socket and the signing key, checks that whoever sent an issue request is the Supervisor it names.
# A party reaching that surface can still name any `iss`, any `sub`, and any phase, and can still
# obtain a capability -- provided it is one the phase's declared authority already covers.
#
# So what changed is the *consequence* rather than the exposure. Before, a self-issued claim was
# unbounded and the permit followed from it. Now a self-issued claim can be no wider than what an
# authorised Supervisor for that phase could have obtained anyway, and it is confined to the target
# application's namespace. That is recorded rather than presented as a fix: the gap is named here,
# on `guardian.app.mediation.TokenIssuer`, in `guardian/app/composition.py`, and in
# `guardian/tests/test_token_issuance_exposure.py`, which is written as a demonstration of what
# remains open.
#
# ONLY ONE REFUSAL IS REPORTED, AND WHICH ONE IS FIXED
# ----------------------------------------------------
# `refusals` is a set and several members can hold at once; the answer carries a single `rule_id`,
# so one is chosen by sorting lexicographically rather than by whichever evaluated first. Rego set
# iteration order is not something to build a reported value on, and
# `.agents/rules/20-parity-and-determinism.md` forbids ordering that depends on it. Anything wanting
# every refusal reads `data.guardian.issuance.refusals` directly.
#
# THIS BUNDLE IS INDIFFERENT TO HOW THE GUARDIAN WAS STARTED
# -----------------------------------------------------------
# Nothing in this file reads, names or reacts to the Guardian's start-time settings, and nothing
# here can be reconfigured by an input document. ADR-023 requires that of every file in this bundle
# and gives the reason; two independent checks hold it, and both cover this file because it ships in
# the same directory. That co-location is also why the answer to M4-C6 was written as a second
# entrypoint here rather than as a second bundle: one directory is one sha256, and a separate bundle
# would have left half the policy outside the proof.

package guardian.issuance

import data.guardian.authority

# --------------------------------------------------------------------------------------------
# The version of the input document this entrypoint understands
# --------------------------------------------------------------------------------------------

input_schema_version := "v1"

# --------------------------------------------------------------------------------------------
# Rule identifiers
#
# Constants rather than strings written at each use, so the value tested is the value emitted.
# `issuance_test.rego` asserts that every one of them satisfies the record's identifier grammar and
# that no two are equal.
# --------------------------------------------------------------------------------------------

# The only permit this entrypoint can produce.
permit_within_authority := "guardian:issue:within-declared-authority"

# The input document is not a shape this entrypoint can read.
deny_document_unreadable := "guardian:issue:input-shape-unreadable"

# Readable, but stamped with a version this entrypoint does not know.
deny_schema_unknown := "guardian:issue:input-schema-unknown"

# The request names a phase `authority.rego` does not declare. A fifth phase, a misspelling, an
# absent key or a value that is not a string all land here.
deny_phase_not_declared := "guardian:issue:phase-not-declared"

# The requested scope is not three arrays, so there is nothing to compare against the declaration.
deny_claim_unusable := "guardian:issue:allow-claim-unusable"

# At least one requested element lies outside what the phase is declared to be able to carry. Three
# ids rather than one, because which dimension was exceeded is the finding.
deny_verb_outside := "guardian:issue:verb-outside-authority"

deny_resource_outside := "guardian:issue:resource-outside-authority"

deny_namespace_outside := "guardian:issue:namespace-outside-authority"

# The requested phase is not the phase the run is currently in. `guardian.declared_phase` is the
# runner's declaration of the run's actual phase (ADR-128, V17), recorded through `POST /v1/phase`;
# a mint for a phase the run has left, or has not yet entered, is refused, so a self-declared
# `issue.phase` cannot unlock a ceiling the run is not standing in. This is the phase-currency half
# of ADR-128: caller identity is authenticated at the route, and the phase is bounded here.
deny_phase_not_current := "guardian:issue:phase-not-current"

# --------------------------------------------------------------------------------------------
# Admissibility
#
# Every substantive rule is gated on this, so an unreadable or wrong-versioned document produces one
# refusal rather than six -- a finding computed from a document whose shape is unknown is a guess.
# --------------------------------------------------------------------------------------------

document_readable if {
	is_object(input)
	is_object(input.guardian)
	is_object(input.issue)
}

document_admissible if {
	document_readable
	input.schema_version == input_schema_version
}

# --------------------------------------------------------------------------------------------
# Is the requested scope one this entrypoint can compare at all?
# --------------------------------------------------------------------------------------------

claim_lists_present if {
	document_admissible
	is_object(input.issue.allow)
	is_array(input.issue.allow.verbs)
	is_array(input.issue.allow.resources)
	is_array(input.issue.allow.namespaces)
}

# Is every element of one requested dimension inside what the phase is declared to carry?
#
# Stated positively, so that a missing key, a phase that is not declared and an element of the wrong
# type all leave this undefined -- and the refusal rules below, which negate it, therefore fire. A
# negatively stated rule would be undefined in exactly those cases and would refuse nothing.
#
# `every` over an empty array holds vacuously, and that is the correct reading rather than an
# oversight: an empty list grants nothing, so a capability carrying one exceeds no ceiling. It is
# refused a step later, by the token service's own claim validation, which is where "a scope list
# has to have entries" already lives.
dimension_within_authority(dimension) if {
	claim_lists_present
	authority.phase_declared(input.issue.phase)
	every element in input.issue.allow[dimension] {
		element in authority.permitted(input.issue.phase, dimension)
	}
}

# --------------------------------------------------------------------------------------------
# Does this capability belong to the run this Guardian was started for?
#
# A requirement of the permit rather than a refusal of its own, exactly as `scope.rego` treats the
# same question on the action path, and for the same reason: the deny-by-default floor is the right
# answer to "nothing was wrong, and nothing matched". A null `guardian.run_id` constrains nothing --
# `guardian/app/config.py` permits a Guardian that pins no run, which is a development posture --
# and every process in a campaign sets it.
# --------------------------------------------------------------------------------------------

run_consistent if {
	document_admissible
	input.guardian.run_id == null
}

run_consistent if {
	document_admissible
	is_string(input.guardian.run_id)
	is_string(input.issue.run_id)
	input.guardian.run_id == input.issue.run_id
}

# --------------------------------------------------------------------------------------------
# Refusals
#
# Note the spelling of the version check: `not X == Y` rather than `X != Y`. They are not the same
# when the key is absent -- `X != Y` is undefined for a missing X and would refuse nothing, which is
# a document with no version passing the version check. The negated form holds.
# --------------------------------------------------------------------------------------------

refusals contains deny_document_unreadable if {
	not document_readable
}

refusals contains deny_schema_unknown if {
	document_readable
	not input.schema_version == input_schema_version
}

refusals contains deny_phase_not_declared if {
	document_admissible
	not authority.phase_declared(input.issue.phase)
}

refusals contains deny_claim_unusable if {
	document_admissible
	not claim_lists_present
}

refusals contains deny_verb_outside if {
	claim_lists_present
	authority.phase_declared(input.issue.phase)
	not dimension_within_authority("verbs")
}

refusals contains deny_resource_outside if {
	claim_lists_present
	authority.phase_declared(input.issue.phase)
	not dimension_within_authority("resources")
}

refusals contains deny_namespace_outside if {
	claim_lists_present
	authority.phase_declared(input.issue.phase)
	not dimension_within_authority("namespaces")
}

# ADR-128. `is_string` guards the null-and-absent case: before any phase is declared
# `guardian.declared_phase` is null (or absent), which constrains nothing -- the development posture
# a null `guardian.run_id` takes -- so the refusal fires only once a phase has been declared and the
# requested one is not it. `not X == Y` rather than `X != Y`, so an absent `issue.phase` is refused
# rather than slipping past an undefined comparison, the spelling every check in this bundle uses.
refusals contains deny_phase_not_current if {
	document_admissible
	is_string(input.guardian.declared_phase)
	not input.issue.phase == input.guardian.declared_phase
}

# Undefined when nothing was refused, which is what makes the explicit-deny rule and the permit rule
# below provably disjoint rather than merely unlikely to overlap.
first_refusal := identifier if {
	ordered := sort(refusals)
	count(ordered) > 0
	identifier := ordered[0]
}

# --------------------------------------------------------------------------------------------
# The verdict
#
# Three rules over one name, the `default` a literal that cannot fail to evaluate. The other two are
# disjoint: one requires at least one refusal, the other requires none. The floor is reachable --
# a request that was refused by nothing and whose run does not belong to this Guardian lands there,
# and is answered with a null `rule_id` because no rule turned it away and inventing one would be a
# falsehood in a value the Guardian may record.
# --------------------------------------------------------------------------------------------

default decision := {
	"allow": false,
	"rule_id": null,
	"explicit_deny": false,
}

decision := {
	"allow": false,
	"rule_id": identifier,
	"explicit_deny": true,
} if {
	identifier := first_refusal
}

decision := {
	"allow": true,
	"rule_id": permit_within_authority,
	"explicit_deny": false,
} if {
	count(refusals) == 0
	run_consistent
}
