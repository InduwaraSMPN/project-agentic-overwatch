# guardian_test.rego -- what the entrypoint answers, for every answer it can give.
#
# WHAT THIS FILE COVERS
# ---------------------
# `guardian.rego`'s three outcomes and the boundary between them: the one path that permits, the
# path that refuses something explicitly, and the deny-by-default floor underneath both. Every
# scope attack the milestone's group C names is here -- a verb outside the claim, a resource or a
# namespace outside it, wildcard and empty and absent claims, and traversal and homoglyph attempts
# in `name` and `namespace`.
#
# The predicates those outcomes are built from are tested separately, in `scope_test.rego`. This
# file asserts what a caller sees; that one asserts what each rule means. Both matter, and testing
# only the first would leave a predicate that is wrong in a way the entrypoint currently masks.
#
# WHY THE TEST PACKAGES SIT OUTSIDE `data.guardian`
# --------------------------------------------------
# `package guardian_test`, not `package guardian.test`. The bundle loader digests and loads every
# file in this directory, test files included, so these rules are present in the evaluated document
# tree at run time. Keeping them off `data.guardian` entirely means the branch the Guardian
# evaluates holds policy and nothing else -- no test fixture can be reached from it, and nothing
# added here can collide with a rule name over there.
#
# The prose in this bundle avoids a handful of ordinary English words on purpose. ADR-023 requires
# that no file under guardian/policies/ mention any ablation configuration, a separate script
# checks it, and the ADR's Consequences say in advance what to do when a legitimate comment trips
# that check: reword the comment, never add an exemption. This paragraph is that rewording, kept
# so the next person to reach for one of those words knows it was a decision.
#
# WHY THE IDENTIFIERS BELOW ARE NEUTRAL
# --------------------------------------
# The run identifiers are `RUN-ALPHA` and `RUN-BETA` rather than run ids in the project's real
# format. The real format spells the ablation configuration into the identifier, and no file under
# `guardian/policies/` may name one -- ADR-023, and a separate script checks it. Neutral ids test
# exactly the same string comparison.
#
# THE HOMOGLYPH CASE IS WRITTEN AS AN ESCAPE ON PURPOSE
# -----------------------------------------------------
# U+043E, CYRILLIC SMALL LETTER O, renders indistinguishably from ASCII `o` in most fonts. It is
# written below as the escape `\u043e`, which keeps this file pure ASCII -- so the attack is
# visible to a reader and to a diff, instead of being a byte nobody can see in a review.

package guardian_test

import data.guardian

# --------------------------------------------------------------------------------------------
# Fixtures
#
# Built by two small functions rather than by patching one shared object, so that every test states
# the whole of what it is testing and no test can be changed by an edit made for another.
# --------------------------------------------------------------------------------------------

document(action_value, allow_value) := {
	"schema_version": "v1",
	"guardian": {"run_id": "RUN-ALPHA"},
	"request": {"request_id": "REQ-0001", "run_id": "RUN-ALPHA"},
	"action": action_value,
	"capability": {
		"iss": "SUP-DETECT-01",
		"sub": "EXE-0001",
		"run_id": "RUN-ALPHA",
		"phase": "containment",
		"allow": allow_value,
	},
}

plain_action := {
	"verb": "delete",
	"resource": "pods",
	"namespace": "boutique",
	"name": "cartservice-7d9f",
}

plain_allow := {
	"verbs": ["delete", "get"],
	"resources": ["pods"],
	"namespaces": ["boutique"],
}

# `action` and `allow` hold only scalars, nulls and arrays, so a recursive merge over either
# cannot reach a nested object and `object.union` is exactly a field-wise replace here.
action_with(patch) := object.union(plain_action, patch)

allow_with(patch) := object.union(plain_allow, patch)

# Anything that replaces or removes a whole SECTION goes through `json.patch` instead.
# `object.union` merges recursively, so a replacement section that omits a key leaves the original
# key in place -- which turns a fixture meant to test an absent field into one that tests a present
# one, and the negative case then passes for the wrong reason.
patched(pointer, value) := json.patch(
	document(plain_action, plain_allow),
	[{"op": "replace", "path": pointer, "value": value}],
)

pruned(pointer) := json.patch(
	document(plain_action, plain_allow),
	[{"op": "remove", "path": pointer}],
)

# --------------------------------------------------------------------------------------------
# The permit path
# --------------------------------------------------------------------------------------------

test_permit_on_exact_scope_match if {
	result := guardian.decision with input as document(plain_action, plain_allow)
	result.allow == true
	result.rule_id == guardian.permit_scope_match
	result.explicit_deny == false
}

# A collection-scoped action names no object, so a null `name` is well-formed rather than absent.
test_permit_when_the_action_names_no_object if {
	result := guardian.decision with input as document(
		action_with({"verb": "get", "name": null}),
		plain_allow,
	)
	result.allow == true
	result.rule_id == guardian.permit_scope_match
}

# A Guardian started without pinning a run constrains nothing here. That is a development posture;
# a campaign process always pins one, and the case below covers the pinned half.
test_permit_when_the_process_pins_no_run if {
	result := guardian.decision with input as patched("/guardian/run_id", null)
	result.allow == true
}

# --------------------------------------------------------------------------------------------
# The deny-by-default floor: nothing refused, nothing matched, no rule to name
# --------------------------------------------------------------------------------------------

test_deny_default_when_the_verb_is_outside_the_claim if {
	result := guardian.decision with input as document(
		action_with({"verb": "patch"}),
		plain_allow,
	)
	result == {"allow": false, "rule_id": null, "explicit_deny": false}
}

test_deny_default_when_the_resource_is_outside_the_claim if {
	result := guardian.decision with input as document(
		action_with({"resource": "secrets"}),
		plain_allow,
	)
	result == {"allow": false, "rule_id": null, "explicit_deny": false}
}

test_deny_default_when_the_namespace_is_outside_the_claim if {
	result := guardian.decision with input as document(
		action_with({"namespace": "kube-system"}),
		plain_allow,
	)
	result == {"allow": false, "rule_id": null, "explicit_deny": false}
}

# The agent-supplied run identifier disagreeing with the verified one. The token verifier owns the
# cross-run finding and answers it with its own reason; this bundle simply declines to permit.
test_deny_default_when_the_request_names_another_run if {
	result := guardian.decision with input as patched("/request/run_id", "RUN-BETA")
	result == {"allow": false, "rule_id": null, "explicit_deny": false}
}

# The one run identifier neither the calling agent nor the token can move.
test_deny_default_when_the_process_pins_another_run if {
	result := guardian.decision with input as patched("/guardian/run_id", "RUN-BETA")
	result == {"allow": false, "rule_id": null, "explicit_deny": false}
}

# --------------------------------------------------------------------------------------------
# Explicit refusals: the allow-claim
# --------------------------------------------------------------------------------------------

test_explicit_deny_when_the_claim_is_absent if {
	result := guardian.decision with input as document(plain_action, null)
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_claim_missing
}

test_explicit_deny_when_the_claim_is_not_three_lists if {
	result := guardian.decision with input as document(
		plain_action,
		{"verbs": "delete", "resources": ["pods"], "namespaces": ["boutique"]},
	)
	result.explicit_deny == true
	result.rule_id == guardian.deny_claim_missing
}

# The classic bug is reading an empty allowlist as "nothing restricted, therefore everything".
# These three assert the only safe reading, one dimension at a time.
test_explicit_deny_when_the_verb_list_is_empty if {
	result := guardian.decision with input as document(plain_action, allow_with({"verbs": []}))
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_claim_empty
}

test_explicit_deny_when_the_resource_list_is_empty if {
	result := guardian.decision with input as document(plain_action, allow_with({"resources": []}))
	result.allow == false
	result.rule_id == guardian.deny_claim_empty
}

test_explicit_deny_when_the_namespace_list_is_empty if {
	result := guardian.decision with input as document(plain_action, allow_with({"namespaces": []}))
	result.allow == false
	result.rule_id == guardian.deny_claim_empty
}

# An empty claim in every dimension is still a refusal and never a grant.
test_no_permit_when_every_list_is_empty if {
	result := guardian.decision with input as document(
		plain_action,
		{"verbs": [], "resources": [], "namespaces": []},
	)
	result.allow == false
}

test_explicit_deny_on_a_bare_wildcard_claim if {
	result := guardian.decision with input as document(plain_action, allow_with({"verbs": ["*"]}))
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_claim_wildcard
}

# A wildcard need not be the whole element to be one.
test_explicit_deny_on_an_embedded_wildcard_claim if {
	result := guardian.decision with input as document(
		plain_action,
		allow_with({"resources": ["pod*"]}),
	)
	result.rule_id == guardian.deny_claim_wildcard
}

# A wildcard also fails the usable-element grammar. The two refusals are kept disjoint so that the
# reported one is the specific one rather than whichever sorts first.
test_a_wildcard_is_reported_as_a_wildcard_and_not_as_malformed if {
	refusals := guardian.refusals with input as document(plain_action, allow_with({"verbs": ["*"]}))
	refusals == {guardian.deny_claim_wildcard}
}

test_explicit_deny_on_a_malformed_claim_element if {
	result := guardian.decision with input as document(
		plain_action,
		allow_with({"namespaces": ["../kube-system"]}),
	)
	result.explicit_deny == true
	result.rule_id == guardian.deny_claim_malformed
}

test_explicit_deny_when_a_claim_element_is_not_a_string if {
	result := guardian.decision with input as document(plain_action, allow_with({"verbs": [7]}))
	result.rule_id == guardian.deny_claim_malformed
}

test_explicit_deny_when_a_claim_element_is_empty if {
	result := guardian.decision with input as document(plain_action, allow_with({"verbs": [""]}))
	result.rule_id == guardian.deny_claim_malformed
}

# --------------------------------------------------------------------------------------------
# Explicit refusals: the action's own identifiers
#
# Group C's traversal and homoglyph cases. Each dies on the positive grammar rather than on a
# pattern written to catch it, which is why one line covers attempts nobody has thought of yet.
# --------------------------------------------------------------------------------------------

test_explicit_deny_on_namespace_traversal if {
	result := guardian.decision with input as document(
		action_with({"namespace": "../kube-system"}),
		plain_allow,
	)
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_action_malformed
}

# CYRILLIC SMALL LETTER O standing in for ASCII `o`: a namespace that reads as "boutique".
test_explicit_deny_on_a_namespace_homoglyph if {
	result := guardian.decision with input as document(
		action_with({"namespace": "b\u043eutique"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

# The anchors are start-of-text and end-of-text, not start-of-line and end-of-line. Under the
# line-oriented reading this value would match a pattern meant to admit only "boutique".
test_explicit_deny_on_a_namespace_carrying_a_line_break if {
	result := guardian.decision with input as document(
		action_with({"namespace": "boutique\nkube-system"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

test_explicit_deny_on_a_percent_escaped_namespace if {
	result := guardian.decision with input as document(
		action_with({"namespace": "kube%2dsystem"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

# A DNS-1123 subdomain admits dots, so this is the one traversal shape the grammar alone tolerates.
test_explicit_deny_on_a_dot_dot_object_name if {
	result := guardian.decision with input as document(
		action_with({"name": "cart..service"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

test_explicit_deny_on_an_object_name_carrying_a_path_separator if {
	result := guardian.decision with input as document(
		action_with({"name": "../../etc/passwd"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

test_explicit_deny_on_a_verb_outside_the_verb_grammar if {
	result := guardian.decision with input as document(
		action_with({"verb": "DELETE"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

test_explicit_deny_on_a_resource_outside_the_resource_grammar if {
	result := guardian.decision with input as document(
		action_with({"resource": "pods/exec"}),
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

test_explicit_deny_when_the_action_omits_a_field if {
	result := guardian.decision with input as document(
		{"verb": "delete", "resource": "pods", "namespace": "boutique"},
		plain_allow,
	)
	result.rule_id == guardian.deny_action_malformed
}

# --------------------------------------------------------------------------------------------
# Explicit refusals: the document itself
# --------------------------------------------------------------------------------------------

test_explicit_deny_on_an_unknown_document_version if {
	result := guardian.decision with input as patched("/schema_version", "v2")
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_schema_unknown
}

# `not X == Y` rather than `X != Y`, because the second is undefined for a missing key and would
# let an unversioned document through the version check unremarked.
test_explicit_deny_when_the_document_carries_no_version if {
	result := guardian.decision with input as pruned("/schema_version")
	result.rule_id == guardian.deny_schema_unknown
}

test_explicit_deny_when_the_input_is_not_an_object if {
	result := guardian.decision with input as "delete every pod"
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_document_unreadable
}

test_explicit_deny_when_the_input_is_the_empty_object if {
	result := guardian.decision with input as {}
	result.rule_id == guardian.deny_document_unreadable
}

test_explicit_deny_when_a_section_is_absent if {
	result := guardian.decision with input as pruned("/capability")
	result.rule_id == guardian.deny_document_unreadable
}

test_explicit_deny_when_a_section_is_not_an_object if {
	result := guardian.decision with input as patched("/action", "delete pods")
	result.rule_id == guardian.deny_document_unreadable
}

# An unreadable document is settled once. A claim-shape finding computed from a document whose
# shape is unknown would be a guess, so the substantive rules never run on one.
test_an_unreadable_document_produces_exactly_one_refusal if {
	refusals := guardian.refusals with input as {}
	refusals == {guardian.deny_document_unreadable}
}

test_an_unknown_version_produces_exactly_one_refusal if {
	refusals := guardian.refusals with input as patched("/schema_version", "v9")
	refusals == {guardian.deny_schema_unknown}
}

# --------------------------------------------------------------------------------------------
# Determinism of the reported refusal
# --------------------------------------------------------------------------------------------

# Two refusals fire; the reported one is the lexicographically first, never whichever the set
# happened to yield. Rule 20 forbids ordering that depends on set iteration, and a rule id that
# moved between runs could not be matched against a fixture.
test_the_reported_refusal_is_the_lexicographically_first if {
	both := document(
		action_with({"namespace": "../kube-system"}),
		allow_with({"verbs": ["*"]}),
	)
	refusals := guardian.refusals with input as both
	refusals == {guardian.deny_action_malformed, guardian.deny_claim_wildcard}

	result := guardian.decision with input as both
	result.rule_id == guardian.deny_action_malformed
}

# --------------------------------------------------------------------------------------------
# The result contract itself
# --------------------------------------------------------------------------------------------

# The Guardian compares `allow` to `true` by identity, so a truthy stand-in is not a yes. These
# assert the emitted type rather than the emitted truthiness.
test_allow_is_a_boolean_on_every_outcome if {
	permitted := guardian.decision with input as document(plain_action, plain_allow)
	is_boolean(permitted.allow)
	is_boolean(permitted.explicit_deny)

	defaulted := guardian.decision with input as document(action_with({"verb": "patch"}), plain_allow)
	is_boolean(defaulted.allow)
	is_boolean(defaulted.explicit_deny)

	refused := guardian.decision with input as {}
	is_boolean(refused.allow)
	is_boolean(refused.explicit_deny)
}

test_the_result_carries_exactly_the_three_contract_keys if {
	expected := {"allow", "rule_id", "explicit_deny"}

	permitted := guardian.decision with input as document(plain_action, plain_allow)
	object.keys(permitted) == expected

	defaulted := guardian.decision with input as document(action_with({"verb": "patch"}), plain_allow)
	object.keys(defaulted) == expected

	refused := guardian.decision with input as {}
	object.keys(refused) == expected
}

# --------------------------------------------------------------------------------------------
# Scale-to-zero (D4-A): a deployment write asking for zero replicas is refused
#
# `replicas` is the normalised integer guardian/app/policy.py attaches to a deployment write. A zero
# under a capability whose phase holds no scale-to-zero capability -- every capability this Guardian
# can mint -- is an explicit refusal rather than a permit; a non-zero scale is permitted where the
# phase already carries `patch` on deployments, so the rule refuses only the zero.
# --------------------------------------------------------------------------------------------

scale_to_zero_action := {
	"verb": "patch",
	"resource": "deployments",
	"namespace": "boutique",
	"name": "cartservice",
	"replicas": 0,
}

deployment_patch_allow := {
	"verbs": ["patch", "get"],
	"resources": ["deployments"],
	"namespaces": ["boutique"],
}

test_explicit_deny_on_a_deployment_scale_to_zero if {
	result := guardian.decision with input as document(scale_to_zero_action, deployment_patch_allow)
	result.allow == false
	result.explicit_deny == true
	result.rule_id == guardian.deny_scale_to_zero
}

# The action is well-formed and inside the claim, so the zero-scale refusal is the only one that
# fires: the reported id cannot be some incidental second refusal masking it.
test_a_scale_to_zero_produces_exactly_the_scale_to_zero_refusal if {
	refusals := guardian.refusals with input as document(scale_to_zero_action, deployment_patch_allow)
	refusals == {guardian.deny_scale_to_zero}
}

test_permit_on_a_nonzero_deployment_scale if {
	result := guardian.decision with input as document(
		object.union(scale_to_zero_action, {"replicas": 3}),
		deployment_patch_allow,
	)
	result.allow == true
	result.rule_id == guardian.permit_scope_match
}

# --------------------------------------------------------------------------------------------
# The rule identifiers
# --------------------------------------------------------------------------------------------

# The grammar the Guardian's hash-chained record holds an identifier to, restated here so that the
# assertion is against the real thing rather than against a rule reading itself.
record_identifier_pattern := `^[A-Za-z0-9][A-Za-z0-9_:-]*$`

record_identifier_max_chars := 128

every_rule_id := [
	guardian.permit_scope_match,
	guardian.deny_document_unreadable,
	guardian.deny_schema_unknown,
	guardian.deny_action_malformed,
	guardian.deny_claim_missing,
	guardian.deny_claim_empty,
	guardian.deny_claim_wildcard,
	guardian.deny_claim_malformed,
	guardian.deny_scale_to_zero,
]

# A dotted id -- the natural Rego path, `data.guardian.decision`, is one -- would have its permit
# refused as a malformed result and its denial recorded with no rule named. Neither failure is
# visible from outside the Guardian, which is why it is asserted here.
test_every_rule_id_satisfies_the_record_identifier_grammar if {
	every identifier in every_rule_id {
		is_string(identifier)
		regex.match(record_identifier_pattern, identifier)
		count(identifier) <= record_identifier_max_chars
		indexof(identifier, ".") == -1
	}
}

# Two refusals sharing an id would be indistinguishable in the record they are written to.
test_every_rule_id_is_distinct if {
	distinct := {identifier | some identifier in every_rule_id}
	count(distinct) == count(every_rule_id)
}
