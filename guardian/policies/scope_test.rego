# scope_test.rego -- each predicate on its own, on the smallest input that exercises it.
#
# WHAT THIS FILE COVERS AND WHY IT IS SEPARATE FROM guardian_test.rego
# ---------------------------------------------------------------------
# `guardian_test.rego` asserts what a caller of the entrypoint sees. This file asserts what each
# rule underneath it means. The two are not the same assertion and the difference is the reason
# both exist: a predicate can be wrong in a way the entrypoint currently masks -- too permissive on
# a case no end-to-end test happens to send, or accidentally undefined where it should be false --
# and an entrypoint test would stay green through all of it right up until some later edit stopped
# masking it.
#
# THE INPUTS ARE MINIMAL ON PURPOSE
# ----------------------------------
# Most tests below pass an input document carrying only the keys the predicate under test reads.
# That is the assertion, not a shortcut: a rule that quietly grew a dependency on some other part
# of the document would stop being defined on these inputs, and the test would fail. A shared
# fixture carrying every key would hide exactly that.
#
# Note also that none of these documents carries `schema_version`. `scope.rego` does not check it
# and must not: version admissibility belongs to the entrypoint, and a predicate here that read the
# version would be a second place that decides which documents are readable.
#
# NEGATIVE TESTS ARE WRITTEN WITH `not`
# --------------------------------------
# Every predicate in `scope.rego` is partial, so "false" means "undefined". `not scope.p` is the
# spelling that covers both, and it is also the spelling `guardian.rego` uses, so a negative test
# here asserts the thing the entrypoint actually relies on rather than something adjacent to it.

package guardian_scope_test

import data.guardian.scope

# --------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------

# A document that satisfies `document_readable` and permits a delete of one pod in `boutique`.
readable_document := {
	"guardian": {"run_id": "RUN-ALPHA"},
	"request": {"request_id": "REQ-0001", "run_id": "RUN-ALPHA"},
	"action": {
		"verb": "delete",
		"resource": "pods",
		"namespace": "boutique",
		"name": "cartservice-7d9f",
	},
	"capability": {
		"iss": "SUP-DETECT-01",
		"sub": "EXE-0001",
		"run_id": "RUN-ALPHA",
		"phase": "containment",
		"allow": {
			"verbs": ["delete", "get"],
			"resources": ["pods"],
			"namespaces": ["boutique"],
		},
	},
}

# `json.patch` rather than `object.union` for anything nested, and that is a correction rather than
# a preference. `object.union` merges recursively, so replacing a section with one that OMITS a key
# leaves the original key in place -- which means a fixture meant to test an absent field silently
# tests a present one, and the negative case passes for the wrong reason. Two tests in this file
# were green that way before the helpers were rewritten. `json.patch` replaces and removes exactly
# what it is pointed at.
#
# The two helpers below still use `object.union` for the innermost merge, where every value is a
# scalar, a null or an array and the recursive case therefore cannot arise.
with_action(patch) := json.patch(
	readable_document,
	[{"op": "replace", "path": "/action", "value": object.union(readable_document.action, patch)}],
)

with_allow(allow_value) := json.patch(
	readable_document,
	[{"op": "replace", "path": "/capability/allow", "value": allow_value}],
)

without(pointer) := json.patch(readable_document, [{"op": "remove", "path": pointer}])

replacing(pointer, value) := json.patch(readable_document, [{"op": "replace", "path": pointer, "value": value}])

# Long values for the character budgets. Built rather than typed, so the number in the test is the
# number being tested instead of a string somebody has to count.
repeated(character, times) := concat("", [character | some _index in numbers.range(1, times)])

# --------------------------------------------------------------------------------------------
# document_readable
# --------------------------------------------------------------------------------------------

test_document_readable_on_the_four_sections if {
	scope.document_readable with input as readable_document
}

test_document_not_readable_when_it_is_a_string if {
	not scope.document_readable with input as "delete every pod"
}

test_document_not_readable_when_it_is_an_array if {
	not scope.document_readable with input as ["delete", "pods"]
}

test_document_not_readable_when_a_section_is_absent if {
	not scope.document_readable with input as without("/guardian")
}

test_document_not_readable_when_a_section_is_a_scalar if {
	not scope.document_readable with input as replacing("/request", 7)
}

# --------------------------------------------------------------------------------------------
# The action grammars
# --------------------------------------------------------------------------------------------

test_verb_grammar_accepts_the_api_server_spelling if {
	every verb in ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"] {
		scope.verb_wellformed with input as {"action": {"verb": verb}}
	}
}

test_verb_grammar_refuses_case_separators_and_wrong_types if {
	every verb in ["DELETE", "delete-collection", "delete pods", "delete;rm", "", 7, null] {
		not scope.verb_wellformed with input as {"action": {"verb": verb}}
	}
}

test_verb_grammar_refuses_an_absent_verb if {
	not scope.verb_wellformed with input as {"action": {}}
}

test_verb_grammar_refuses_a_value_over_its_budget if {
	oversize := repeated("a", scope.verb_max_chars + 1)
	not scope.verb_wellformed with input as {"action": {"verb": oversize}}
}

test_resource_grammar_accepts_plain_and_group_qualified if {
	every resource in ["pods", "deployments.apps", "ciliumnetworkpolicies.cilium.io", "networkpolicies.networking.k8s.io"] {
		scope.resource_wellformed with input as {"action": {"resource": resource}}
	}
}

test_resource_grammar_refuses_subresources_case_and_leading_digits if {
	every resource in ["pods/exec", "Pods", "1pods", ".pods", "pods.", "pods exec", 7] {
		not scope.resource_wellformed with input as {"action": {"resource": resource}}
	}
}

test_namespace_grammar_accepts_a_dns_1123_label if {
	every namespace in ["boutique", "kube-system", "a", "ns-01"] {
		scope.namespace_wellformed with input as {"action": {"namespace": namespace}}
	}
}

# Traversal, escapes, control characters, case and the whole non-ASCII plane, refused by one
# positive pattern rather than by an entry per trick. The escape below is U+043E, CYRILLIC
# SMALL LETTER O, which is why this file stays pure ASCII.
test_namespace_grammar_refuses_the_group_c_attacks if {
	every namespace in [
		"../kube-system",
		"..",
		"kube/system",
		"kube\\system",
		"kube%2dsystem",
		"kube:system",
		"kube system",
		"boutique\nkube-system",
		"b\u043eutique",
		"Boutique",
		"boutique.internal",
		"-boutique",
		"boutique-",
		"",
	] {
		not scope.namespace_wellformed with input as {"action": {"namespace": namespace}}
	}
}

test_namespace_grammar_refuses_a_value_over_the_kubernetes_limit if {
	oversize := repeated("a", scope.namespace_max_chars + 1)
	not scope.namespace_wellformed with input as {"action": {"namespace": oversize}}

	# One character shorter is the limit itself, and it is accepted.
	at_limit := repeated("a", scope.namespace_max_chars)
	scope.namespace_wellformed with input as {"action": {"namespace": at_limit}}
}

test_object_name_is_wellformed_when_it_is_null if {
	scope.object_name_wellformed with input as {"action": {"name": null}}
}

test_object_name_accepts_a_dns_1123_subdomain if {
	every name in ["cartservice-7d9f", "svc.default.local", "a", "a1.b2"] {
		scope.object_name_wellformed with input as {"action": {"name": name}}
	}
}

# The dot-dot clause is the one place this bundle is stricter than the request contract, because a
# subdomain grammar admits dots and therefore admits `a..b`. It is not a name Kubernetes accepts.
test_object_name_refuses_a_dot_dot_sequence if {
	every name in ["cart..service", "..", "a..", "..b"] {
		not scope.object_name_wellformed with input as {"action": {"name": name}}
	}
}

test_object_name_refuses_separators_case_and_wrong_types if {
	every name in ["../../etc/passwd", "cart/service", "Cart", "cart service", "", 7] {
		not scope.object_name_wellformed with input as {"action": {"name": name}}
	}
}

test_object_name_refuses_an_absent_name if {
	not scope.object_name_wellformed with input as {"action": {}}
}

test_object_name_refuses_a_value_over_the_kubernetes_limit if {
	oversize := repeated("a", scope.object_name_max_chars + 1)
	not scope.object_name_wellformed with input as {"action": {"name": oversize}}
}

# --------------------------------------------------------------------------------------------
# action_wellformed
# --------------------------------------------------------------------------------------------

test_action_wellformed_on_a_readable_document if {
	scope.action_wellformed with input as readable_document
}

test_action_wellformed_requires_a_readable_document if {
	not scope.action_wellformed with input as {"action": readable_document.action}
}

test_action_wellformed_fails_if_any_one_field_fails if {
	every patch in [
		{"verb": "DELETE"},
		{"resource": "pods/exec"},
		{"namespace": "../kube-system"},
		{"name": "cart..service"},
	] {
		not scope.action_wellformed with input as with_action(patch)
	}
}

# --------------------------------------------------------------------------------------------
# Allow-claim elements
# --------------------------------------------------------------------------------------------

test_element_usable_on_plain_identifiers if {
	every element in ["pods", "delete", "kube-system", "deployments.apps", "a_b", "A1"] {
		scope.element_usable(element)
	}
}

test_element_usable_refuses_empty_wrong_type_and_metacharacters if {
	every element in ["", "*", "pod*", "-pods", ".pods", "kube/system", "kube system", 7, null, ["pods"]] {
		not scope.element_usable(element)
	}
}

test_element_usable_refuses_a_value_over_its_budget if {
	not scope.element_usable(repeated("a", scope.claim_element_max_chars + 1))
	scope.element_usable(repeated("a", scope.claim_element_max_chars))
}

# The deliberate divergence from the request contract: that grammar admits `*` so a wildcard claim
# can parse and then be turned away for what it is. This one refuses it, because deny-by-default
# does not expand a wildcard.
test_the_usable_element_grammar_refuses_the_wildcard_the_contract_admits if {
	not regex.match(scope.claim_element_pattern, "*")
	not regex.match(scope.claim_element_pattern, "pods*")
}

test_element_wildcard_detects_bare_and_embedded_stars if {
	scope.element_wildcard("*")
	scope.element_wildcard("pod*")
	scope.element_wildcard("*.apps")
	not scope.element_wildcard("pods")
	not scope.element_wildcard(7)
}

# --------------------------------------------------------------------------------------------
# Allow-claim shape
# --------------------------------------------------------------------------------------------

test_claim_lists_present_on_three_arrays if {
	scope.claim_lists_present with input as readable_document
}

test_claim_lists_absent_when_the_claim_is_null if {
	not scope.claim_lists_present with input as with_allow(null)
}

test_claim_lists_absent_when_a_dimension_is_not_an_array if {
	every claim_value in [
		{"verbs": "delete", "resources": ["pods"], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": {"a": 1}, "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": ["pods"]},
	] {
		not scope.claim_lists_present with input as with_allow(claim_value)
	}
}

# An allowlist of nothing grants nothing. Asserted one dimension at a time, because a rule that
# only looked at `verbs` would pass a test that only sent an empty `verbs`.
test_claim_has_empty_list_in_each_dimension_separately if {
	every claim_value in [
		{"verbs": [], "resources": ["pods"], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": [], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": ["pods"], "namespaces": []},
	] {
		scope.claim_has_empty_list with input as with_allow(claim_value)
	}
}

test_claim_has_no_empty_list_when_every_dimension_is_populated if {
	not scope.claim_has_empty_list with input as readable_document
}

test_claim_has_wildcard_in_each_dimension_separately if {
	every claim_value in [
		{"verbs": ["*"], "resources": ["pods"], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": ["pod*"], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": ["pods"], "namespaces": ["*"]},
	] {
		scope.claim_has_wildcard with input as with_allow(claim_value)
	}
}

test_claim_has_no_wildcard_on_a_plain_claim if {
	not scope.claim_has_wildcard with input as readable_document
}

test_claim_has_malformed_element_for_bad_shapes if {
	every claim_value in [
		{"verbs": [""], "resources": ["pods"], "namespaces": ["boutique"]},
		{"verbs": [7], "resources": ["pods"], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": ["pods/exec"], "namespaces": ["boutique"]},
		{"verbs": ["delete"], "resources": ["pods"], "namespaces": ["../kube-system"]},
	] {
		scope.claim_has_malformed_element with input as with_allow(claim_value)
	}
}

# Disjoint from the wildcard case, so that a wildcard is reported as a wildcard.
test_a_wildcard_element_is_not_also_reported_as_malformed if {
	not scope.claim_has_malformed_element with input as with_allow({
		"verbs": ["*"],
		"resources": ["pods"],
		"namespaces": ["boutique"],
	})
}

test_claim_usable_on_a_plain_claim if {
	scope.claim_usable with input as readable_document
}

test_claim_not_usable_when_absent_empty_wildcarded_or_malformed if {
	not scope.claim_usable with input as with_allow(null)
	not scope.claim_usable with input as with_allow({"verbs": [], "resources": ["pods"], "namespaces": ["boutique"]})
	not scope.claim_usable with input as with_allow({"verbs": ["*"], "resources": ["pods"], "namespaces": ["boutique"]})
	not scope.claim_usable with input as with_allow({"verbs": [""], "resources": ["pods"], "namespaces": ["boutique"]})
}

# --------------------------------------------------------------------------------------------
# action_covered_by_claim
# --------------------------------------------------------------------------------------------

test_action_covered_when_all_three_dimensions_match if {
	scope.action_covered_by_claim with input as readable_document
}

test_action_not_covered_when_any_one_dimension_misses if {
	every patch in [{"verb": "patch"}, {"resource": "secrets"}, {"namespace": "kube-system"}] {
		not scope.action_covered_by_claim with input as with_action(patch)
	}
}

# Matching is exact string equality, so a claim listing `pod` does not reach `pods` and a claim
# listing `pods` does not reach `podsecuritypolicies`.
test_action_coverage_is_exact_and_never_a_prefix if {
	not scope.action_covered_by_claim with input as with_allow({
		"verbs": ["delete"],
		"resources": ["pod"],
		"namespaces": ["boutique"],
	})
	not scope.action_covered_by_claim with input as with_action({"resource": "podsecuritypolicies"})
}

test_action_not_covered_when_the_claim_is_unusable if {
	not scope.action_covered_by_claim with input as with_allow(null)
}

# --------------------------------------------------------------------------------------------
# run_consistent
# --------------------------------------------------------------------------------------------

test_run_consistent_when_all_three_agree if {
	scope.run_consistent with input as readable_document
}

# A Guardian started without pinning a run constrains nothing. A development posture, never a
# campaign one.
test_run_consistent_when_the_process_pins_no_run if {
	scope.run_consistent with input as replacing("/guardian/run_id", null)
}

test_run_not_consistent_when_the_request_names_another_run if {
	not scope.run_consistent with input as replacing("/request/run_id", "RUN-BETA")
}

test_run_not_consistent_when_the_process_pins_another_run if {
	not scope.run_consistent with input as replacing("/guardian/run_id", "RUN-BETA")
}

test_run_not_consistent_when_a_run_identifier_is_absent_or_ill_typed if {
	not scope.run_consistent with input as without("/request/run_id")
	not scope.run_consistent with input as replacing("/guardian/run_id", 7)
}

# --------------------------------------------------------------------------------------------
# Scale-to-zero (D4-A)
#
# `guardian/app/policy.py` attaches a normalised integer `replicas` to a deployment write, so the
# predicate reads a zero it can trust. `readable_document`'s capability is minted for `containment`,
# and no phase holds the scale-to-zero capability, so `capability_permits_scale_to_zero` is false for
# it -- as it is for every capability this Guardian can mint.
# --------------------------------------------------------------------------------------------

test_action_requests_scale_to_zero_on_a_normalised_zero if {
	scope.action_requests_scale_to_zero with input as with_action({"replicas": 0})
}

test_action_does_not_request_scale_to_zero_on_a_nonzero_or_absent_count if {
	not scope.action_requests_scale_to_zero with input as with_action({"replicas": 3})
	not scope.action_requests_scale_to_zero with input as readable_document
}

test_no_capability_this_guardian_mints_permits_scale_to_zero if {
	not scope.capability_permits_scale_to_zero with input as readable_document
}

# Not accidentally always-false: a capability whose phase IS granted the scale-to-zero capability
# permits it. The real declaration grants no phase (the test above and issuance_test.rego), so this
# overrides the declaration to prove the mechanism rather than the policy. `readable_document`'s
# capability is minted for `containment`.
test_capability_permits_scale_to_zero_when_its_phase_holds_it if {
	scope.capability_permits_scale_to_zero with input as readable_document with data.guardian.authority.phases_permitted_to_scale_to_zero as ["containment"]
}
