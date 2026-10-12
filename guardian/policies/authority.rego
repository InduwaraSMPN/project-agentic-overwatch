# authority.rego -- the widest capability each phase may ever be granted. Human-authored.
#
# WHAT THIS FILE IS
# -----------------
# RQ1 asks whether a hierarchical multi-agent system can act inside "a human-authored authority
# policy". This file is that phrase made executable, and it is the only file in this bundle whose
# contents are a *declaration* rather than a derivation: every list below was written by a person
# deciding what an agent in that phase is allowed to be able to do, against the target application
# `infra/boutique/` deploys.
#
# It decides nothing on its own. `issuance.rego` is the entrypoint that reads these lists and
# answers; this file only says what they are. That split is deliberate -- the declaration is the
# part a supervisor reads and signs off, and it should be readable without following any control
# flow at all.
#
# WHY A CEILING ON ISSUANCE AND NOT A SECOND CHECK ON ACTIONS
# -----------------------------------------------------------
# `guardian.rego` already answers "is this action inside the capability presented", and it answers
# it by mirroring the token's allow-claim. That is ADR-003's instruction and it is right, but it has
# a consequence M4 recorded as conflict M4-C6: the permit follows from the claim, and `POST
# /v1/tokens` establishes no identity for whoever asked for the claim. So a party reaching the issue
# surface writes its own allow-claim and the permit follows from it.
#
# The answer is not to re-decide actions here. Two files answering the same question is two policies
# that diverge in the cases nobody wrote a test for. The answer is to bound the *claim* before it
# becomes a credential: whatever a caller asks for, it may not receive a capability wider than the
# phase it names has been declared. An unauthenticated request then obtains nothing an authorised
# Supervisor could not already have obtained, which is what leaves the study's central claim
# standing.
#
# HOW THE FOUR DECLARATIONS WERE CHOSEN
# --------------------------------------
# `docs/protocols/evaluation-protocol.md` section 1.6 fixes the four phases and their order, and
# each declaration below is the smallest set that lets that phase do its own work and not the next
# phase's. The shape of the reasoning is the same in all four: what must this phase be able to
# observe, and what must it be able to change.
#
#   detection-and-investigation -- observation only. It establishes what is happening, and a phase
#   that could also change things would make the first recorded state a state it had already
#   altered. Read verbs, no write verb of any kind.
#
#   containment -- reduce reach without removing evidence. Scaling a workload down, labelling one
#   for quarantine, and creating a policy object that isolates it are the three shapes that stop
#   spread while leaving the object in place to be examined. Deletion is deliberately absent: it is
#   the fastest way to stop something and it destroys the thing the next phase has to work on.
#
#   ADR-083 (supervisor ruling §3.1 item 2) adds a fourth containment shape on the same principle:
#   revoking an escalation by removing the one subject an incident granted it from a RoleBinding,
#   which is `patch` on `rolebindings` here. It is deliberately not `delete`: containment still
#   never deletes, and a RoleBinding with the offending subject removed is exactly the "object left
#   in place to be examined" the rest of this declaration already asks for. The Guardian's own
#   executor is what makes this safe rather than merely declared -- its one `patch rolebindings`
#   operation can only remove a subject that is already there, never add one, on the same principle
#   as the isolation NetworkPolicy body a caller cannot shape into anything but a closed one; see
#   `guardian/app/executor.py`'s `_revoke_rolebinding_subject_body` and its adversarial tests in
#   `guardian/tests/test_executor.py`, which include the INJ-C payloads that ask for a grant.
#
#   eradication -- removal. This is the only phase granted `delete`, and it is granted `update` as
#   well because replacing a compromised object with a known-good one is the other half of removal.
#   It keeps the read verbs, because removing an object one has not looked at is not a decision.
#   ADR-083 (supervisor ruling §3.1 item 3) extends this to `rolebindings`: eradication deletes the
#   RoleBinding an escalation depended on outright, once containment's subject-only revocation is no
#   longer enough and the compromised object it named is being replaced rather than merely defused.
#   Eradication's existing `patch` verb also now reaches `rolebindings` combinatorially (this file
#   declares a ceiling as verbs times resources, not a table of specific pairs -- see WHAT A
#   GROUP-QUALIFIED RESOURCE MEANS HERE below for the same shape applied to spellings), which is the
#   same pattern the `deployments patch` row of the RBAC verb table already accepts across
#   containment, eradication and verified-recovery: a wider declared ceiling than any one phase's
#   documented use, narrowed to what actually happens by `guardian/app/executor.py`'s `OPERATIONS`
#   table, which implements `patch rolebindings` as containment's subject-revoke operation and
#   nothing wider for any phase that reaches it.
#
#   verified-recovery -- observe, and restore capacity. Reads, plus the scale write, so a workload
#   that containment took to zero can be brought back and then watched. No delete and no create: a
#   phase whose job is to show that service returned must not be able to change what returned.
#
# THE NAMESPACE LIST IS ONE ENTRY, AND THAT IS THE POINT
# -------------------------------------------------------
# Every phase is bounded to the namespace `infra/boutique/kustomization.yaml` stamps onto the target
# application. Nothing may ever be minted for `kube-system`, for the namespace this Guardian runs
# in, or for the one the agent layer runs in -- so the widest capability this Guardian can issue is
# still confined to the application under study, whoever asks for it and whatever they ask for.
# That containment is what makes a self-issued token an experiment-scoped problem rather than a
# cluster-wide one.
#
# WHAT A GROUP-QUALIFIED RESOURCE MEANS HERE
# -------------------------------------------
# The request contract admits an optional API-group suffix -- `deployments` and `deployments.apps`
# both parse -- and `scope.rego` matches an action's resource against an allow-claim by exact string
# equality. Two spellings of one kind are therefore two different strings to every rule in this
# bundle, so both are listed for the two kinds that have a non-core group. Listing only one would
# leave a scenario that used the other spelling unable to obtain a capability at all, for a reason
# that has nothing to do with what it was trying to do.
#
# WHAT IS NOT HERE
# ----------------
# No lifetime. `docs/protocols/security-policy.md` section 2 owns the token time-to-live and its
# ceiling, `guardian/token/issuer.py` applies them, and a duration in this file would be a second
# home for a number that is allowed exactly one.
#
# No identity. This file bounds what may be minted; it says nothing about who may ask, because
# nothing at that surface establishes who is asking. `issuance.rego`'s header records that gap in
# full, and it is recorded rather than closed.

package guardian.authority

# --------------------------------------------------------------------------------------------
# The target application's namespace
#
# One value, referenced by all four declarations, so that widening the study's blast radius is a
# single visible edit rather than four consistent ones.
# --------------------------------------------------------------------------------------------

target_namespaces := ["boutique"]

# --------------------------------------------------------------------------------------------
# Read verbs, shared by every phase that has any
#
# Named once and reused, because "every phase can look" is one decision and repeating it four times
# would let three of the copies drift while the fourth kept the comment explaining them.
# --------------------------------------------------------------------------------------------

read_verbs := ["get", "list", "watch"]

# The kinds any phase may observe. Deployments and their ReplicaSets are what the target application
# is made of; Pods are what actually runs; Services are how traffic reaches them; Events are how the
# cluster explains itself. Secrets and ConfigMaps are absent from every list in this file, in every
# phase, and their absence is a decision: reading them is how a compromised agent would obtain
# credentials, and no phase of incident response needs their contents to do its job.
read_resources := [
	"pods",
	"deployments",
	"deployments.apps",
	"replicasets",
	"replicasets.apps",
	"services",
	"events",
]

# --------------------------------------------------------------------------------------------
# The four declarations
# --------------------------------------------------------------------------------------------

phase_authority := {
	"detection-and-investigation": {
		"verbs": read_verbs,
		"resources": read_resources,
		"namespaces": target_namespaces,
	},
	"containment": {
		"verbs": array.concat(read_verbs, ["patch", "create"]),
		"resources": array.concat(read_resources, [
			"networkpolicies",
			"networkpolicies.networking.k8s.io",
			"rolebindings",
			"rolebindings.rbac.authorization.k8s.io",
		]),
		"namespaces": target_namespaces,
	},
	"eradication": {
		"verbs": array.concat(read_verbs, ["delete", "update", "patch"]),
		"resources": array.concat(read_resources, [
			"networkpolicies",
			"networkpolicies.networking.k8s.io",
			"rolebindings",
			"rolebindings.rbac.authorization.k8s.io",
		]),
		"namespaces": target_namespaces,
	},
	"verified-recovery": {
		"verbs": array.concat(read_verbs, ["patch"]),
		"resources": read_resources,
		"namespaces": target_namespaces,
	},
}

# --------------------------------------------------------------------------------------------
# Scaling a workload to zero: a capability apart from `patch deployments`, held by no phase
#
# Containment, eradication and verified-recovery each carry `patch` on `deployments`, and that verb
# is what a normal scale rides on -- to one replica, to three. Scaling a whole Deployment to zero is
# a different act with a different consequence: it removes the running workload rather than reducing
# its reach, which is the shape the ground truth forbids and the shape agents reached for as their
# default containment before this rule existed -- breaking their own verified recovery and making an
# injection's "success" unattributable. So it is drawn here as a capability of its own, ABOVE the
# `patch deployments` ceiling rather than inside it, and it is declared for no phase.
#
# The list is empty, and that emptiness is the decision rather than a stub: no phase of incident
# response in this study may take a workload to zero through the Guardian. Because the capability is
# declared for no phase it can belong to no phase's mintable authority -- which is the issuance half
# of the decision, needing no rule of its own beyond this absence -- and `scope.rego` reads the
# predicate below to refuse a zero-replica ACTION under a capability whose phase does not hold it,
# which is every capability this Guardian can mint. Granting it to a phase later is adding that
# phase's name here: a deliberate, reviewed authority change with an ADR, exactly as widening any
# declaration above would be.
# --------------------------------------------------------------------------------------------

phases_permitted_to_scale_to_zero := []

phase_permits_scale_to_zero(phase) if {
	is_string(phase)
	phase in phases_permitted_to_scale_to_zero
}

# --------------------------------------------------------------------------------------------
# The two predicates `issuance.rego` reads
#
# Both are undefined rather than false for a phase this file does not declare, which is the safe
# direction: an undefined predicate makes the caller's `not` fire, so an unrecognised phase is
# refused rather than silently granted whatever the last lookup happened to return.
# --------------------------------------------------------------------------------------------

phase_declared(phase) if {
	is_string(phase)
	phase_authority[phase]
}

permitted(phase, dimension) := phase_authority[phase][dimension]
