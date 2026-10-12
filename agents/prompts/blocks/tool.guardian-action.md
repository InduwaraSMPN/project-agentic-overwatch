---
id: tool.guardian-action
parity_class: shared
source_anchor: "3.4.2 - the Guardian executes its own rules without discretion, and cannot be instructed, prompted, or overridden by any agent at any level, including the Orchestrator"
---
guardian_action. Request one change to the cluster, mediated by the Guardian.

This is the only tool in the system that reaches the target environment. It describes an
operation the way the authority policy describes one, and the Guardian decides whether that
operation is permitted, carries it out if it is, and records the decision either way.

It takes six parameters and all six are required.

verb. The operation to perform, lowercase letters only, for example get, list, patch, delete,
scale, create, or label. It is matched against the verbs your capability permits.

resource. The kind of object the operation acts on, lowercase, optionally carrying its API
group, for example pods, deployments, networkpolicies, serviceaccounts, or secrets. It is
matched against the resource kinds your capability permits.

namespace. The namespace the object lives in, a single lowercase DNS label of at most
sixty-three characters. It is matched against the namespaces your capability permits. Name it
exactly. There is no wildcard, no default, and no way to mean all of them.

name. The specific object, a lowercase DNS subdomain of at most two hundred and fifty-three
characters, or null when the operation is over a whole collection rather than one object.
Prefer a name. A collection-wide operation is the one most likely to affect a workload you
did not intend to touch.

params. A mapping of string keys to string values carrying whatever else the operation needs.
Use exactly these keys for the supported writes: `replicas` for a Deployment patch;
`image_entry` for an eradication-only Deployment update to the trusted patched-image catalog;
`label_key` and `label_value` for a Pod label patch; `selector_key` and `selector_value` for a
NetworkPolicy create; `subject_kind`, `subject_name`, and `subject_namespace` for a RoleBinding
subject removal. Every value is a string, including numbers, so zero is the one character
that spells it. A NetworkPolicy create also requires `name`; it preserves egress to the
application namespace and DNS while denying every other egress destination for the selected pods.

justification. Why this action, in your own words, up to two thousand and forty-eight
characters. It is written into the audit record exactly as you wrote it, and it is never
evaluated as policy: a justification cannot turn a denied action into a permitted one, so
text that argues for permission wastes the field entirely. Use it to say what you believe
about the cluster and which evidence supports that belief, so that a later reader can tell a
reasoned action from a guess.

You do not pass a capability. The capability minted for this task is attached to the call for
you; you never see it, choose it, or hold it.

The call returns a decision of permit or deny, a reason code, the identifier of the policy
rule that decided, an execution status when the action ran, and the sequence number of the
audit record that now holds all of it. A denial is an answer. Read the reason code and act on
what it says rather than on what you hoped it would say.
