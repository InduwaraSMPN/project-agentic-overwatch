# issuance_test.rego -- what the authority entrypoint answers, for every answer it can give.
#
# WHAT THIS FILE COVERS
# ---------------------
# `issuance.rego`'s three outcomes and the boundary between them: the one path that permits, every
# path that refuses something explicitly, and the deny-by-default floor underneath both. All four
# declarations in `authority.rego` are exercised, because a declaration nothing evaluates is a
# declaration nobody has checked -- and the whole value of a human-authored ceiling is that somebody
# can read it and see it hold.
#
# WHY THE TEST PACKAGE SITS OUTSIDE `data.guardian`
# --------------------------------------------------
# `package guardian_issuance_test`, not `package guardian.issuance.test`. The bundle loader digests
# and loads every file in this directory, test files included, so these rules are present in the
# evaluated document tree at run time. Keeping them off `data.guardian` entirely means the branch
# the Guardian evaluates holds policy and nothing else -- nothing added here can be reached from it,
# and nothing added here can collide with a rule name over there. `guardian_test.rego` states the
# same choice for the same reason.
#
# WHY THE IDENTIFIERS ARE NEUTRAL
# --------------------------------
# The run identifiers are `RUN-ALPHA` and `RUN-BETA` rather than ids in the project's real format.
# The real format spells the ablation setting into the identifier, and no file in this directory may
# name one -- ADR-023, and a separate script checks it. Neutral ids exercise exactly the same string
# comparison.
#
# THE PROSE HERE AVOIDS A HANDFUL OF ORDINARY ENGLISH WORDS
# ----------------------------------------------------------
# Deliberately, and `guardian_test.rego` records why: ADR-023's Consequences say in advance what to
# do when a legitimate comment trips the purity check -- reword the comment, never add an exemption.

package guardian_issuance_test

import data.guardian.authority
import data.guardian.issuance

# --------------------------------------------------------------------------------------------
# Fixtures
#
# Built by two small functions rather than by patching one shared object, so that every test states
# the whole of what it is testing and no test can be changed by an edit made for another.
# --------------------------------------------------------------------------------------------

document(issue_value) := {
	"schema_version": "v1",
	"guardian": {"run_id": "RUN-ALPHA"},
	"issue": issue_value,
}

issue(phase_value, allow_value) := {
	"supervisor_id": "SUP-0001",
	"executor_id": "EXE-0001",
	"run_id": "RUN-ALPHA",
	"phase": phase_value,
	"ttl_seconds": null,
	"allow": allow_value,
}

allow(verbs_value, resources_value, namespaces_value) := {
	"verbs": verbs_value,
	"resources": resources_value,
	"namespaces": namespaces_value,
}

# The narrowest claim any phase can carry: one read verb, one kind, the target namespace.
read_only_claim := allow(["get"], ["pods"], ["boutique"])

# A document that also carries the run's declared current phase (ADR-128), for the phase-currency
# rule. The plain `document` helper omits `declared_phase`, so its permits stand for the development
# posture in which no phase has been declared and nothing is bounded.
document_declaring(declared_phase, issue_value) := {
	"schema_version": "v1",
	"guardian": {"run_id": "RUN-ALPHA", "declared_phase": declared_phase},
	"issue": issue_value,
}

# --------------------------------------------------------------------------------------------
# The permit, once per declared phase
#
# Four separate tests rather than one loop, so that a declaration which stopped covering its own
# phase's work fails by name. Each asks for something that phase is actually for.
# --------------------------------------------------------------------------------------------

test_detection_may_be_granted_a_read_capability if {
	answer := issuance.decision with input as document(issue(
		"detection-and-investigation",
		read_only_claim,
	))
	answer.allow == true
	answer.rule_id == issuance.permit_within_authority
	answer.explicit_deny == false
}

test_containment_may_be_granted_scale_label_and_policy_creation if {
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(
			["get", "list", "patch", "create"],
			["deployments", "pods", "networkpolicies"],
			["boutique"],
		),
	))
	answer.allow == true
	answer.rule_id == issuance.permit_within_authority
}

test_eradication_may_be_granted_delete_and_replace if {
	answer := issuance.decision with input as document(issue(
		"eradication",
		allow(["get", "delete", "update"], ["pods", "deployments.apps"], ["boutique"]),
	))
	answer.allow == true
}

# ADR-083 (supervisor ruling §3.1 items 2-3): the RoleBinding revocation and removal capabilities.

test_containment_may_be_granted_a_rolebinding_patch_to_revoke_a_subject if {
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(["get", "patch"], ["rolebindings"], ["boutique"]),
	))
	answer.allow == true
	answer.rule_id == issuance.permit_within_authority
}

test_containment_may_be_granted_the_group_qualified_rolebinding_spelling if {
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(["patch"], ["rolebindings.rbac.authorization.k8s.io"], ["boutique"]),
	))
	answer.allow == true
}

test_eradication_may_be_granted_a_rolebinding_delete if {
	answer := issuance.decision with input as document(issue(
		"eradication",
		allow(["get", "delete"], ["rolebindings"], ["boutique"]),
	))
	answer.allow == true
}

test_a_rolebinding_capability_is_refused_outside_containment_and_eradication if {
	# Each request pairs "rolebindings" with a verb the phase already carries for something else
	# (detection-and-investigation's own "get", verified-recovery's own "patch"), so the refusal
	# below is provably about the resource dimension and not a verb this phase never has at all --
	# the same isolation `test_a_resource_outside_the_declaration_is_refused` uses.
	detection := issuance.decision with input as document(issue(
		"detection-and-investigation",
		allow(["get"], ["rolebindings"], ["boutique"]),
	))
	detection.allow == false
	detection.rule_id == issuance.deny_resource_outside

	recovery := issuance.decision with input as document(issue(
		"verified-recovery",
		allow(["patch"], ["rolebindings"], ["boutique"]),
	))
	recovery.allow == false
	recovery.rule_id == issuance.deny_resource_outside
}

test_rolebinding_delete_is_refused_for_containment if {
	# Containment gains `patch` on rolebindings, never `delete`: containment still never deletes.
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(["get", "delete"], ["rolebindings"], ["boutique"]),
	))
	answer.allow == false
	answer.rule_id == issuance.deny_verb_outside
}

test_verified_recovery_may_be_granted_reads_and_the_scale_write if {
	answer := issuance.decision with input as document(issue(
		"verified-recovery",
		allow(["get", "list", "watch", "patch"], ["deployments", "replicasets"], ["boutique"]),
	))
	answer.allow == true
}

test_a_guardian_pinned_to_no_run_still_mints_within_the_declaration if {
	unpinned := {
		"schema_version": "v1",
		"guardian": {"run_id": null},
		"issue": issue("containment", read_only_claim),
	}
	answer := issuance.decision with input as unpinned
	answer.allow == true
}

# --------------------------------------------------------------------------------------------
# The refusals
# --------------------------------------------------------------------------------------------

test_a_document_that_is_not_an_object_is_refused if {
	answer := issuance.decision with input as "not a document"
	answer.allow == false
	answer.explicit_deny == true
	answer.rule_id == issuance.deny_document_unreadable
}

test_a_document_missing_a_section_is_refused if {
	answer := issuance.decision with input as {"schema_version": "v1", "guardian": {"run_id": null}}
	answer.rule_id == issuance.deny_document_unreadable
}

test_a_document_at_an_unknown_version_is_refused if {
	unknown := {
		"schema_version": "v99",
		"guardian": {"run_id": "RUN-ALPHA"},
		"issue": issue("containment", read_only_claim),
	}
	answer := issuance.decision with input as unknown
	answer.rule_id == issuance.deny_schema_unknown
}

test_a_document_with_no_version_at_all_is_refused if {
	versionless := {
		"guardian": {"run_id": "RUN-ALPHA"},
		"issue": issue("containment", read_only_claim),
	}
	answer := issuance.decision with input as versionless
	answer.rule_id == issuance.deny_schema_unknown
}

test_a_phase_the_declaration_does_not_name_is_refused if {
	answer := issuance.decision with input as document(issue("cleanup", read_only_claim))
	answer.allow == false
	answer.rule_id == issuance.deny_phase_not_declared
}

test_a_phase_that_is_not_a_string_is_refused if {
	answer := issuance.decision with input as document(issue(7, read_only_claim))
	answer.rule_id == issuance.deny_phase_not_declared
}

test_a_null_scope_is_refused_as_unusable if {
	answer := issuance.decision with input as document(issue("containment", null))
	answer.rule_id == issuance.deny_claim_unusable
}

test_a_scope_whose_dimension_is_not_an_array_is_refused_as_unusable if {
	answer := issuance.decision with input as document(issue(
		"containment",
		allow("get", ["pods"], ["boutique"]),
	))
	answer.rule_id == issuance.deny_claim_unusable
}

test_a_verb_outside_the_declaration_is_refused if {
	# `delete` belongs to eradication. Asking for it under containment is the case the split
	# between those two declarations exists to catch.
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(["get", "delete"], ["pods"], ["boutique"]),
	))
	answer.allow == false
	answer.explicit_deny == true
	answer.rule_id == issuance.deny_verb_outside
}

test_a_write_verb_under_detection_is_refused if {
	answer := issuance.decision with input as document(issue(
		"detection-and-investigation",
		allow(["get", "patch"], ["pods"], ["boutique"]),
	))
	answer.rule_id == issuance.deny_verb_outside
}

test_a_resource_outside_the_declaration_is_refused if {
	# Secrets are absent from every declaration in authority.rego, in every phase.
	answer := issuance.decision with input as document(issue(
		"eradication",
		allow(["get"], ["secrets"], ["boutique"]),
	))
	answer.rule_id == issuance.deny_resource_outside
}

test_a_namespace_outside_the_target_application_is_refused if {
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(["get"], ["pods"], ["kube-system"]),
	))
	answer.rule_id == issuance.deny_namespace_outside
}

test_a_wildcard_element_is_not_expanded if {
	# Deny-by-default read literally. `*` is a string like any other here and is a member of no
	# declared list, so it is refused for being outside the ceiling rather than expanded into it.
	answer := issuance.decision with input as document(issue(
		"containment",
		allow(["*"], ["pods"], ["boutique"]),
	))
	answer.allow == false
	answer.rule_id == issuance.deny_verb_outside
}

test_the_lexicographically_first_refusal_is_the_one_reported if {
	# Three dimensions exceeded at once. The reported id must be the first in sort order rather
	# than whichever the set happened to yield first, or a fixture could not name it.
	answer := issuance.decision with input as document(issue(
		"detection-and-investigation",
		allow(["delete"], ["secrets"], ["kube-system"]),
	))
	answer.rule_id == issuance.deny_namespace_outside
	count(issuance.refusals) == 3 with input as document(issue(
		"detection-and-investigation",
		allow(["delete"], ["secrets"], ["kube-system"]),
	))
}

# --------------------------------------------------------------------------------------------
# The deny-by-default floor
# --------------------------------------------------------------------------------------------

test_a_capability_for_another_run_falls_to_the_floor if {
	other := {
		"schema_version": "v1",
		"guardian": {"run_id": "RUN-ALPHA"},
		"issue": object.union(issue("containment", read_only_claim), {"run_id": "RUN-BETA"}),
	}
	answer := issuance.decision with input as other
	answer.allow == false
	answer.rule_id == null
	answer.explicit_deny == false
}

test_a_run_identifier_that_is_not_a_string_falls_to_the_floor if {
	other := {
		"schema_version": "v1",
		"guardian": {"run_id": "RUN-ALPHA"},
		"issue": object.union(issue("containment", read_only_claim), {"run_id": 7}),
	}
	answer := issuance.decision with input as other
	answer.allow == false
	answer.rule_id == null
}

# --------------------------------------------------------------------------------------------
# Phase currency (ADR-128, V17)
#
# The declared phase is the run's actual phase, recorded by the runner. A mint for another phase is
# refused, so a self-declared `issue.phase` cannot unlock a ceiling the run is not standing in; a mint
# for the declared phase, within that phase's authority, still succeeds.
# --------------------------------------------------------------------------------------------

test_phase_not_current_is_refused if {
	# The claim is within containment's authority, so phase currency is the only thing wrong.
	answer := issuance.decision with input as document_declaring(
		"detection-and-investigation",
		issue(
			"containment",
			allow(["get", "patch", "create"], ["deployments", "networkpolicies"], ["boutique"]),
		),
	)
	answer.allow == false
	answer.explicit_deny == true
	answer.rule_id == issuance.deny_phase_not_current
}

test_an_in_phase_mint_is_permitted if {
	answer := issuance.decision with input as document_declaring(
		"containment",
		issue("containment", read_only_claim),
	)
	answer.allow == true
	answer.rule_id == issuance.permit_within_authority
}

# --------------------------------------------------------------------------------------------
# The declaration itself
# --------------------------------------------------------------------------------------------

test_every_declared_phase_is_one_of_the_four if {
	declared := {phase | some phase, _ in authority.phase_authority}
	declared == {
		"detection-and-investigation",
		"containment",
		"eradication",
		"verified-recovery",
	}
}

test_no_phase_may_ever_reach_outside_the_target_application if {
	every _, declaration in authority.phase_authority {
		declaration.namespaces == authority.target_namespaces
	}
}

test_detection_carries_no_write_verb if {
	every verb in authority.permitted("detection-and-investigation", "verbs") {
		verb in authority.read_verbs
	}
}

test_delete_is_declared_for_eradication_alone if {
	"delete" in authority.permitted("eradication", "verbs")
	not "delete" in authority.permitted("containment", "verbs")
	not "delete" in authority.permitted("verified-recovery", "verbs")
	not "delete" in authority.permitted("detection-and-investigation", "verbs")
}

# ADR-083: rolebindings is a resource only containment and eradication ever declare, and only
# containment (never having gained `delete`) can be granted `patch` on it -- eradication's own
# `patch` combinatorially reaching rolebindings too is the accepted, documented ceiling-versus-
# implementation gap the module comment above and executor.py's OPERATIONS table both name.

test_rolebindings_are_declared_for_containment_and_eradication_only if {
	"rolebindings" in authority.permitted("containment", "resources")
	"rolebindings.rbac.authorization.k8s.io" in authority.permitted("containment", "resources")
	"rolebindings" in authority.permitted("eradication", "resources")
	"rolebindings.rbac.authorization.k8s.io" in authority.permitted("eradication", "resources")
	not "rolebindings" in authority.permitted("detection-and-investigation", "resources")
	not "rolebindings" in authority.permitted("verified-recovery", "resources")
}

test_containment_can_never_be_granted_delete_on_anything if {
	# The invariant supervisor ruling §3.1 restates explicitly for this extension: containment
	# never deletes. Checked over every resource this phase can ever be granted, not only
	# rolebindings, so a future resource added to containment's list inherits the same proof.
	not "delete" in authority.permitted("containment", "verbs")
}

test_no_phase_may_ever_be_granted_a_secret_or_a_config_map if {
	every _, declaration in authority.phase_authority {
		not "secrets" in declaration.resources
		not "configmaps" in declaration.resources
	}
}

# D4-A: scaling a workload to zero is a capability apart from `patch deployments`, declared for no
# phase. The empty list is the decision; `scope.rego` reads `phase_permits_scale_to_zero` to refuse a
# zero-replica action under any capability, because no phase holds it.
test_no_phase_may_scale_a_workload_to_zero if {
	authority.phases_permitted_to_scale_to_zero == []
	every phase in [
		"detection-and-investigation",
		"containment",
		"eradication",
		"verified-recovery",
	] {
		not authority.phase_permits_scale_to_zero(phase)
	}
}

# The predicate is not accidentally always-false: were a phase listed, it would be granted, and only
# that phase. The real list is empty (the test above), so this overrides the declaration to prove the
# mechanism holds rather than changing the policy -- exactly the "undefined where it should be false"
# risk scope_test.rego names.
test_phase_permits_scale_to_zero_exactly_for_a_listed_phase if {
	granted := ["containment"]
	authority.phase_permits_scale_to_zero("containment") with data.guardian.authority.phases_permitted_to_scale_to_zero as granted
	not authority.phase_permits_scale_to_zero("eradication") with data.guardian.authority.phases_permitted_to_scale_to_zero as granted
}

# --------------------------------------------------------------------------------------------
# The rule identifiers
# --------------------------------------------------------------------------------------------

# The grammar the Guardian's hash-chained record holds an identifier to, restated here so that the
# assertion is against the real thing rather than against a rule reading itself.
record_identifier_pattern := `^[A-Za-z0-9][A-Za-z0-9_:-]*$`

record_identifier_max_chars := 128

every_rule_id := [
	issuance.permit_within_authority,
	issuance.deny_document_unreadable,
	issuance.deny_schema_unknown,
	issuance.deny_phase_not_declared,
	issuance.deny_claim_unusable,
	issuance.deny_verb_outside,
	issuance.deny_resource_outside,
	issuance.deny_namespace_outside,
	issuance.deny_phase_not_current,
]

# A dotted id -- the natural Rego path, `data.guardian.issuance.decision`, is one -- would have its
# permit refused as an unreadable result and its denial recorded with no rule named. Neither failure
# is visible from outside the Guardian, which is why it is asserted here.
test_every_issuance_rule_id_satisfies_the_record_identifier_grammar if {
	every identifier in every_rule_id {
		is_string(identifier)
		regex.match(record_identifier_pattern, identifier)
		count(identifier) <= record_identifier_max_chars
		indexof(identifier, ".") == -1
	}
}

test_every_issuance_rule_id_is_distinct if {
	distinct := {identifier | some identifier in every_rule_id}
	count(distinct) == count(every_rule_id)
}

# The two entrypoints write into the same record field, so an id shared between them would be
# ambiguous in a sealed run: a reader could not tell which question it answered.
test_no_issuance_rule_id_collides_with_an_action_rule_id if {
	every identifier in every_rule_id {
		startswith(identifier, "guardian:issue:")
	}
}
