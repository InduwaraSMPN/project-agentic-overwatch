# scope.rego -- does the capability the caller presented actually cover the action it presented?
#
# WHAT THIS FILE IS
# -----------------
# guardian.rego is the entrypoint and owns the shape of the answer. This file owns the question
# underneath it: given the input document `guardian/app/policy.py` builds, is the requested action
# inside the allow-claim carried by the verified capability, and is every string involved a string
# that could name what it claims to name at all.
#
# Nothing here returns a decision. Every rule below is a predicate, and every predicate is written
# so that it is true only on the safe reading. guardian.rego is the one file that negates them.
#
# THE ONE REGO PROPERTY EVERYTHING BELOW IS SHAPED BY
# ---------------------------------------------------
# A reference to a key a document does not carry is *undefined*, not false. So `not p` is TRUE when
# p is undefined, and a body that reads a missing key is undefined and therefore contributes
# nothing. Those two facts pull in opposite directions, and the direction they pull decides whether
# a missing key opens a hole or closes one:
#
#   permit if { input.action.verb == "get" }     -- missing verb => undefined => NO permit. Safe.
#   refuse if { input.action.verb != "get" }     -- missing verb => undefined => NO refusal. Unsafe.
#   refuse if { not permit }                     -- missing verb => permit undefined => refuses. Safe.
#
# Hence the discipline: this file states only positive properties -- "this is a well-formed verb",
# "this claim is usable", "this action is inside that claim" -- and guardian.rego turns the absence
# of one into a refusal. A predicate here that fails for any reason at all, including a reason
# nobody anticipated, fails towards denial rather than away from it.
#
# THE INPUT DOCUMENT, WHICH IS A CLOSED CONTRACT
# ----------------------------------------------
# `guardian/app/policy.py` builds it from a closed field partition that is checked when the module
# is imported, so this is the whole of it and there is no other key to read:
#
#   {"schema_version": "v1",
#    "guardian":   {"run_id": <string|null>},
#    "request":    {"request_id": <string>, "run_id": <string>},
#    "action":     {"verb": <string>, "resource": <string>,
#                   "namespace": <string>, "name": <string|null>},
#    "capability": {"iss": <string>, "sub": <string>, "run_id": <string>, "phase": <string>,
#                   "allow": {"verbs": [<string>], "resources": [<string>],
#                             "namespaces": [<string>]} | null}}
#
# Two fields of the request are deliberately NOT in it: the free text the calling agent wrote, and
# the free-form parameter map it filled. `security-policy.md` section 1.5 requires agent-supplied
# free text to be recorded and never evaluated as policy, and policy.py makes that structural by
# building the document additively rather than by subtracting two names. No rule in this bundle
# references either, and a rule that did would be reading a key that does not exist -- which, by
# the property above, either never matches or always fires. Both are defects; neither is a policy.
#
# The token itself is likewise absent. Policy is handed the *verified claim set*, never the bearer
# string, so there is no path by which an unchecked credential could be evaluated as though it had
# been checked, and none by which a live credential could reach an evaluator's own diagnostics.
#
# WHY THE GRAMMARS BELOW ARE RESTATED RATHER THAN TRUSTED
# -------------------------------------------------------
# The Guardian's frozen request contract already holds `namespace` to a DNS-1123 label and `name`
# to a DNS-1123 subdomain, and a body that fails those is refused at the contract boundary before
# any of this runs. Restating them here is therefore duplication, and it is deliberate duplication
# for a reason worth stating plainly: this bundle is a separately loadable, separately testable
# artefact, and "the caller already checked" is not a property a reference monitor may assume about
# its own input. `opa eval` against a hand-written document, a future second caller, or a defect in
# the builder all reach these rules with something the contract never saw.
#
# The plan's group C names the two attacks this closes -- traversal and homoglyph tricks in `name`
# and `namespace`. Both die on the same line, and they die because the grammars are stated
# POSITIVELY. A blocklist would need an entry per trick and would be wrong the first time somebody
# invented a new one; `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` admits thirty-seven characters and refuses
# the rest of Unicode, which is where every homoglyph lives, along with `/`, `\`, `%`, `:`, spaces,
# control characters and the whole of upper case.
#
# One place this file is deliberately STRICTER than the request contract, and it can only ever deny
# more: `object_name_wellformed` additionally refuses a name containing `..`. A DNS-1123 subdomain
# admits dots, so `a..b` satisfies the grammar; it is not a name Kubernetes would ever accept, and
# a dot-dot sequence is the one traversal shape a subdomain grammar tolerates. Refusing it costs
# nothing legitimate.
#
# WHAT THIS FILE DOES NOT RE-DERIVE, AND WHERE THE LINE IS
# --------------------------------------------------------
# It re-derives what an identifier may LOOK LIKE, because that is what defeats the attacks named
# above. It does not re-derive HOW MANY of them a claim may carry: list cardinality is the request
# contract's bound, it has no bearing on whether this action is inside this claim, and restating it
# would put a second home under a third file for a limit that is already stated once.
#
# It also does not re-decide anything the token verifier owns. Signature, issuer, expiry, single
# use, subject and phase are settled before an input document is built at all, and a rule here that
# re-checked one of them would be a second implementation of a decision that already has an owner
# -- divergent in exactly the cases nobody wrote a test for.

package guardian.scope

import data.guardian.authority

# --------------------------------------------------------------------------------------------
# Grammars
#
# Raw strings, so a backslash is a backslash and the regex sees what is written. Anchored with ^
# and $, which in RE2 -- with no (?m) flag, and there is none -- match the start and the end of the
# whole text rather than of a line. That is load-bearing: under a line-oriented reading,
# "kube-system\nrm -rf" would match a pattern meant to admit only "kube-system".
# --------------------------------------------------------------------------------------------

# A Kubernetes verb as the API server spells it: get, list, watch, create, update, patch, delete,
# deletecollection. Lower-case ASCII letters and nothing else, so no separator of any kind fits.
verb_pattern := `^[a-z]+$`

# A resource, optionally group-qualified: pods, deployments.apps, ciliumnetworkpolicies.cilium.io.
resource_pattern := `^[a-z][a-z0-9]*(?:\.[a-z0-9]+(?:[-.][a-z0-9]+)*)?$`

# RFC 1123 label. A namespace. No dots, so the dot-dot sequence cannot arise here at all.
namespace_pattern := `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`

# RFC 1123 subdomain. An object name. Dots are legal, which is why the extra dot-dot clause exists.
object_name_pattern := `^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`

# One element of an allow-claim list, as this bundle is willing to USE it.
#
# Narrower than the grammar the request contract parses, and the difference is the whole point. The
# contract admits `*` so that a wildcard claim parses and can then be refused for what it is,
# rather than collapsing into a claim-shape failure that says nothing about why the token was
# turned away. This pattern refuses it, because a wildcard is not something a deny-by-default
# policy may expand.
claim_element_pattern := `^[A-Za-z0-9][A-Za-z0-9._-]*$`

# Character budgets, mirroring the request contract's. A string longer than its budget is refused
# before the regex runs -- cheaper, and it keeps an over-long value from being carried further.
verb_max_chars := 128

resource_max_chars := 128

namespace_max_chars := 63

object_name_max_chars := 253

claim_element_max_chars := 128

# The three dimensions of an allow-claim, in the order the architecture's contract lists them.
claim_dimension_keys := ["verbs", "resources", "namespaces"]

# --------------------------------------------------------------------------------------------
# Is this document one this bundle can read at all?
#
# Checked before anything else touches it. `is_object(input)` comes first so that an input which
# is a string, a number or an array is settled here rather than by a reference into a non-object
# further down. The four sections are required to be present and to be objects; their contents are
# checked by the rules that use them.
# --------------------------------------------------------------------------------------------

document_readable if {
	is_object(input)
	is_object(input.guardian)
	is_object(input.request)
	is_object(input.action)
	is_object(input.capability)
}

# --------------------------------------------------------------------------------------------
# Is every string in the action a string that could name what it claims to name?
# --------------------------------------------------------------------------------------------

action_wellformed if {
	document_readable
	verb_wellformed
	resource_wellformed
	namespace_wellformed
	object_name_wellformed
}

verb_wellformed if {
	value := input.action.verb
	is_string(value)
	count(value) <= verb_max_chars
	regex.match(verb_pattern, value)
}

resource_wellformed if {
	value := input.action.resource
	is_string(value)
	count(value) <= resource_max_chars
	regex.match(resource_pattern, value)
}

namespace_wellformed if {
	value := input.action.namespace
	is_string(value)
	count(value) <= namespace_max_chars
	regex.match(namespace_pattern, value)
}

# `name` is null for a collection-scoped action -- listing pods in a namespace names no object --
# so a null is well-formed and the two readings are given two bodies rather than one disjunction.
# Null and the empty string are not the same statement, and the empty string fails the grammar.
object_name_wellformed if {
	input.action.name == null
}

object_name_wellformed if {
	value := input.action.name
	is_string(value)
	count(value) <= object_name_max_chars
	regex.match(object_name_pattern, value)

	# The one clause stricter than the request contract. See the file header.
	indexof(value, "..") == -1
}

# --------------------------------------------------------------------------------------------
# Is the allow-claim one this bundle can match an action against?
#
# Three ways a claim fails to be usable, kept as three separate predicates so that guardian.rego
# can attribute a refusal to the right one. The Guardian's own vocabulary already draws this
# distinction for the token verifier's half of it -- a claim that cannot be matched by construction
# is a defect in the claim rather than in the action, which is a different defect with a different
# owner -- and the same reasoning applies here.
#
# EMPTY MEANS NOTHING IS GRANTED. This is the only safe reading and it is worth being explicit
# about, because the opposite reading is the classic bug: an empty allowlist treated as "no
# restriction stated, therefore everything" turns the most restrictive claim a Supervisor can issue
# into the most permissive one. Under deny-by-default an allowlist grants exactly what it lists,
# and a list of nothing grants nothing. Note that this would already hold from membership alone --
# nothing is a member of an empty array -- so the rule below adds no safety by itself. What it adds
# is attribution: without it, a token carrying three empty lists would be turned away silently by
# the absence of a match, and the record would not distinguish it from an ordinary out-of-scope
# request.
# --------------------------------------------------------------------------------------------

claim_lists_present if {
	document_readable
	is_object(input.capability.allow)
	is_array(input.capability.allow.verbs)
	is_array(input.capability.allow.resources)
	is_array(input.capability.allow.namespaces)
}

claim_has_empty_list if {
	claim_lists_present
	some key in claim_dimension_keys
	count(input.capability.allow[key]) == 0
}

claim_has_wildcard if {
	claim_lists_present
	some key in claim_dimension_keys
	some element in input.capability.allow[key]
	element_wildcard(element)
}

# Disjoint from the wildcard case on purpose. A wildcard element also fails `element_usable`, so
# without the second clause both predicates would be true for the same token and the refusal
# reported for it would be the less specific of the two.
claim_has_malformed_element if {
	claim_lists_present
	some key in claim_dimension_keys
	some element in input.capability.allow[key]
	not element_usable(element)
	not element_wildcard(element)
}

element_wildcard(element) if {
	is_string(element)
	indexof(element, "*") != -1
}

element_usable(element) if {
	is_string(element)
	count(element) > 0
	count(element) <= claim_element_max_chars
	regex.match(claim_element_pattern, element)
}

claim_usable if {
	claim_lists_present
	not claim_has_empty_list
	not claim_has_wildcard
	not claim_has_malformed_element
}

# --------------------------------------------------------------------------------------------
# Does the claim cover the action?
#
# Membership in all three dimensions. Exact string equality, never a prefix and never a pattern:
# the elements have been through `element_usable` and carry no metacharacter, so there is nothing
# here for a crafted claim to expand into.
# --------------------------------------------------------------------------------------------

action_covered_by_claim if {
	claim_usable
	action_wellformed
	input.action.verb in input.capability.allow.verbs
	input.action.resource in input.capability.allow.resources
	input.action.namespace in input.capability.allow.namespaces
}

# --------------------------------------------------------------------------------------------
# Does this action scale a workload to zero, and may the capability's phase do that?
#
# D4-A. `guardian/app/policy.py` attaches a normalised integer `replicas` to the action for a
# deployment write and for nothing else, so `input.action.replicas` is defined exactly where a
# replica count means something and undefined everywhere else. The first predicate is therefore true
# only for a deployment write asking for zero -- `"0"` and `"00"` became the one integer `0` on the
# Python side, so no spelling of zero escapes it. The second asks `authority.rego` whether the phase
# the capability was minted for holds the scale-to-zero capability at all; no phase does, so it is
# false for every capability this Guardian can mint. `guardian.rego` requires the first and negates
# the second, turning "a zero scale under a capability that does not hold the zero-scale capability"
# into a refusal.
#
# Both are positive predicates, on the discipline this whole file is written to: a missing key or an
# ill-typed value leaves them undefined, and the entrypoint's `not` fires towards denial rather than
# away from it. A zero scale therefore reaches a refusal even from a document where `capability.phase`
# is absent -- there is no phase to hold the capability, so there is nothing to permit it.
# --------------------------------------------------------------------------------------------

action_requests_scale_to_zero if {
	input.action.replicas == 0
}

capability_permits_scale_to_zero if {
	authority.phase_permits_scale_to_zero(input.capability.phase)
}

# --------------------------------------------------------------------------------------------
# Does this action belong to the run this capability was minted for?
#
# A requirement of a permit rather than a refusal of its own, and the distinction is deliberate.
# The token verifier owns the cross-run finding and answers it with its own structured reason; a
# refusal rule here would be a second owner for one question. What this bundle may do without
# taking that ownership is decline to grant a permit it is not certain about, which is what this
# predicate expresses: fail it and no permit rule matches, so the answer is the deny-by-default
# answer rather than a competing verdict.
#
# `guardian.run_id` is the run the Guardian PROCESS was started for and is the only one of the
# three run identifiers in the document that neither the calling agent nor the token can move --
# `request.run_id` is agent-supplied, and `capability.run_id` is verified but may have been minted
# for some other run. It is nullable because a Guardian may be started without pinning a run, which
# is a development posture rather than a campaign one; a null therefore constrains nothing here,
# and every campaign process sets it.
# --------------------------------------------------------------------------------------------

run_consistent if {
	document_readable
	is_string(input.request.run_id)
	is_string(input.capability.run_id)
	input.request.run_id == input.capability.run_id
	guardian_run_consistent
}

guardian_run_consistent if {
	input.guardian.run_id == null
}

guardian_run_consistent if {
	is_string(input.guardian.run_id)
	input.guardian.run_id == input.capability.run_id
}
