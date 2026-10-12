# guardian.rego -- the entrypoint. Deny unless an explicit permit rule says otherwise.
#
# WHAT THIS FILE IS
# -----------------
# `docs/protocols/security-policy.md` section 1.1 states the invariant in one sentence: "absent an
# explicit permit rule, deny with a reason code". This file is that sentence made executable. It is
# the rule `guardian/app/policy.py` evaluates -- point `GUARDIAN_POLICY_ENTRYPOINT` at
# `data.guardian.decision` -- and it is the only file in this bundle that produces a verdict.
#
# THE ANSWER IS EXACTLY THREE KEYS
# --------------------------------
# `interpret_policy_result` in `guardian/app/policy.py` reads:
#
#     {"allow": <boolean>, "rule_id": <string|null>, "explicit_deny": <boolean>}
#
# and it reads them strictly. `allow` is compared to `true` by identity, so a string "true", a 1 or
# a non-empty list is not a policy saying yes -- each is a result the Guardian cannot read, and a
# result it cannot read is one it will not act on. Anything outside that shape denies. This bundle
# never emits anything else; the strictness on the other side is what makes that true rather than
# merely intended.
#
# WHY `rule_id` USES COLONS AND NEVER A DOT
# ------------------------------------------
# Every id below is written `guardian:<verdict>:<what>`. That is not a style choice. A permit's
# rule id is written into the hash-chained record the Guardian appends, whose identifier grammar
# admits letters, digits, `_`, `:` and `-` and deliberately admits no `.` -- because a compact JWS
# is three base64url segments joined by dots, and an identifier field that could hold one would be
# a place to smuggle a credential into a record that is supposed to be born clean.
#
# The consequence lands here rather than there. A rule referred to by its natural Rego path,
# `data.guardian.decision`, does NOT satisfy that grammar, so a bundle that returned one would have
# its permit refused as a malformed result. That is the correct failure -- a permit carrying an id
# the record would reject is a permit that could not be recorded -- but it is a silent one to debug
# from the outside, so the ids are constants in this file and every one of them is tested.
#
# THE THREE OUTCOMES, AND WHY TWO OF THEM ARE DENIALS THAT DIFFER
# ---------------------------------------------------------------
# *Permit.* Exactly one rule can produce one, it names itself, and it fires only when nothing was
# refused, the run identifiers agree, and the action is inside the capability's allow-claim.
#
# *Explicit deny.* Something was actively turned away: a document this bundle cannot read, a
# document at a version it does not know, an action identifier that could not name a Kubernetes
# object, or an allow-claim that cannot be matched at all. `explicit_deny: true` is what makes such
# a refusal visible downstream as more than an absence, which is the whole reason the Guardian's
# vocabulary carries a separate code for it.
#
# *Deny by default.* Nothing was refused and nothing matched. The document was fine, the claim was
# usable, and the action simply was not inside it -- an out-of-scope verb, resource or namespace,
# or a capability minted for a different run. `rule_id` is null, because no rule refused this and
# inventing one would be a falsehood in a record that is hashed and later replayed. This is the
# answer section 1.1 describes and it is the one given most often.
#
# ONLY ONE REFUSAL IS REPORTED, AND WHICH ONE IS FIXED
# ----------------------------------------------------
# `refusals` is a set and several members can fire at once. The result contract carries a single
# `rule_id`, so one has to be chosen, and it is chosen by sorting -- lexicographically first --
# rather than by whichever happened to evaluate first. Rego set iteration order is not something to
# build a reported value on: `.agents/rules/20-parity-and-determinism.md` forbids ordering that
# depends on set iteration, and a rule id that moved between runs would be a rule id nobody could
# match against a fixture. Anything that wants every refusal reads `data.guardian.refusals`
# directly; nothing is discarded, only the report is narrowed.
#
# HOW THE REFUSALS ARE LAYERED, AND WHY
# --------------------------------------
# A document that cannot be read produces exactly one refusal, not five. Every substantive rule is
# gated on `document_admissible`, so an unreadable or wrong-versioned document is settled before
# any rule tries to interpret its contents -- because a claim-shape finding computed from a
# document whose shape is unknown is not a finding, it is a guess.
#
# THIS BUNDLE IS INDIFFERENT TO HOW THE GUARDIAN WAS STARTED
# -----------------------------------------------------------
# Nothing under `guardian/policies/` reads, names or reacts to the Guardian's start-time
# configuration, and nothing here can be reconfigured by an input document. ADR-023 requires that
# and gives the reason: the guardrail ablation's causal claim is that each configuration removes
# exactly one property, which stops being true the moment a configuration is reachable by editing
# policy. Two independent checks hold it -- the sha256 of this loaded bundle is asserted equal
# across every configuration, and a separate script asserts that no file here so much as mentions
# one. The first would miss a token that is present but unreached; the second would miss a bundle
# that differs for a reason it has no pattern for. Both, or neither is evidence.

package guardian

import data.guardian.scope

# --------------------------------------------------------------------------------------------
# The version of the input document this bundle understands
#
# `guardian/app/policy.py` stamps it and this file checks it, which is the point of having it: a
# policy that could not tell which input shape it was reading would infer the shape from whichever
# keys happened to be present, and inferring a contract from field presence is the guess every
# `schema_version` in this repository exists to remove.
# --------------------------------------------------------------------------------------------

input_schema_version := "v1"

# --------------------------------------------------------------------------------------------
# Rule identifiers
#
# Constants rather than strings written at each use, so that the value tested is the value emitted.
# All are dot-free; all satisfy the record's identifier grammar; all are well under its 128-
# character budget. `guardian_test.rego` asserts both properties over every one of them rather than
# trusting the reader to have counted.
# --------------------------------------------------------------------------------------------

# The only permit this bundle can produce. One rule, one id, and the id is a constant rather than
# something derived from the request: a value taken from the input document could be steered by the
# caller, and a rule id is written into a hash-chained record.
#
# It is deliberately NOT one id per phase or per action, e.g. an id naming a phase and a specific
# verb-on-resource pair. That shape reads better in a record, and it would require this file to
# enumerate an action catalogue that no document in this repository has fixed -- M5 is the
# milestone that lands the scenarios such a catalogue would have to serve. Inventing one now would
# put content in policy that nothing authorises, and ADR-003's actual instruction is the opposite
# of enumerating: policies mirror the token's allow-claims. When the catalogue exists, adding named
# rules beside this one is additive and the tests below still hold.
permit_scope_match := "guardian:permit:capability-scope-match"

# The input document is not a shape this bundle can read: not an object, or missing one of the four
# sections, or carrying a section that is not an object.
deny_document_unreadable := "guardian:deny:input-shape-unreadable"

# The document is readable but stamped with a version this bundle does not know.
deny_schema_unknown := "guardian:deny:input-schema-unknown"

# A string in the action could not name the thing it claims to name. Traversal, a homoglyph, an
# escape, a control character, upper case, an over-long value, a wrong type, a missing key.
deny_action_malformed := "guardian:deny:action-identifier-malformed"

# The capability carried no allow-claim at all, or one that is not three arrays.
deny_claim_missing := "guardian:deny:allow-claim-missing"

# At least one of the three lists is empty. An allowlist of nothing grants nothing.
deny_claim_empty := "guardian:deny:allow-claim-empty"

# At least one element is or contains a wildcard. Deny-by-default does not expand one.
deny_claim_wildcard := "guardian:deny:allow-claim-wildcard"

# At least one element is not a usable identifier and is not a wildcard.
deny_claim_malformed := "guardian:deny:allow-claim-malformed"

# A deployment write asking for zero replicas, under a capability whose phase does not hold the
# scale-to-zero capability -- which is every capability this Guardian can mint (D4-A). Scaling a
# workload to zero is a capability apart from `patch deployments`, declared for no phase in
# `authority.rego`, so this is the action-side half of that decision.
deny_scale_to_zero := "guardian:deny:deployment-scale-to-zero"

# --------------------------------------------------------------------------------------------
# Admissibility
# --------------------------------------------------------------------------------------------

document_admissible if {
	scope.document_readable
	input.schema_version == input_schema_version
}

# --------------------------------------------------------------------------------------------
# Refusals
#
# Every negation in this bundle is here. Note the spelling of the version check: `not X == Y`
# rather than `X != Y`. They are not the same when the key is absent -- `X != Y` is undefined for a
# missing X and the refusal would not fire, which is a document with no version passing the version
# check. The negated form fires. Every refusal below is written so that a missing or ill-typed
# input reaches it as a refusal rather than as silence.
# --------------------------------------------------------------------------------------------

refusals contains deny_document_unreadable if {
	not scope.document_readable
}

refusals contains deny_schema_unknown if {
	scope.document_readable
	not input.schema_version == input_schema_version
}

refusals contains deny_action_malformed if {
	document_admissible
	not scope.action_wellformed
}

refusals contains deny_claim_missing if {
	document_admissible
	not scope.claim_lists_present
}

refusals contains deny_claim_empty if {
	document_admissible
	scope.claim_has_empty_list
}

refusals contains deny_claim_wildcard if {
	document_admissible
	scope.claim_has_wildcard
}

refusals contains deny_claim_malformed if {
	document_admissible
	scope.claim_has_malformed_element
}

# D4-A. A well-formed, in-scope zero scale is turned away here rather than permitted below: the
# action asks for zero replicas and the capability's phase does not hold the scale-to-zero
# capability. Gated on `document_admissible` alone, like the claim refusals above, so a zero scale
# that is also malformed adds this to the set and the lexicographically first id is still reported.
refusals contains deny_scale_to_zero if {
	document_admissible
	scope.action_requests_scale_to_zero
	not scope.capability_permits_scale_to_zero
}

# Undefined when nothing was refused, which is what makes the explicit-deny rule below and the
# permit rule mutually exclusive rather than merely unlikely to overlap.
first_refusal := identifier if {
	ordered := sort(refusals)
	count(ordered) > 0
	identifier := ordered[0]
}

# --------------------------------------------------------------------------------------------
# The verdict
#
# Three rules over one name. The `default` is the floor and it is a literal, so it cannot fail to
# evaluate; the other two are provably disjoint, one requiring at least one refusal and the other
# requiring none. Disjoint matters: two bodies of a complete rule that were both true with
# different values would be an evaluation error, and while that would still deny -- the Guardian
# treats an engine failure as a denial -- it would deny for a reason that says nothing about the
# request.
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
	"rule_id": permit_scope_match,
	"explicit_deny": false,
} if {
	count(refusals) == 0
	scope.run_consistent
	scope.action_covered_by_claim
}
