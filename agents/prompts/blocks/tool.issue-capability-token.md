---
id: tool.issue-capability-token
parity_class: shared
source_anchor: "3.4.2 - every action arriving at the Guardian carries a supervisor-issued, short-lived capability token traceable to the authorised Supervisor"
---
issue_capability_token. Mint one short-lived, scope-limited capability for one bounded task.

An executing role holds no standing authority whatsoever. Before it can ask the Guardian for
anything, a capability has to exist that says what it may ask for, and this tool is the only
way one comes into existence. The Guardian mints it, records who requested it, and binds it
to this run and this phase. It expires on a short timer and each use of it is recorded.

It takes four parameters and all four are required.

executor_id. The identifier of the single executing role this capability is for, up to one
hundred and twenty-eight characters. A capability belongs to one holder; it cannot be shared,
forwarded, or reused by another.

verbs. The list of operations that holder may perform, each lowercase letters only.

resources. The list of object kinds it may act on, each lowercase and optionally carrying an
API group.

namespaces. The list of namespaces it may act in, each a single lowercase DNS label.

The capability that results is the product of those three lists, not a list of specific
operations, and that is the thing to keep in mind while writing them. Adding one verb to a
request that already names three resource kinds and two namespaces authorises six operations
you did not picture. Ask for what the task will actually use, not for what it might
conceivably need, and mint again later if the task turns out to need more. Minting twice
costs a tool call; minting too widely costs the property that makes the whole arrangement
worth having.

The mint is itself checked against the deployment-time authority policy and can be refused. A
request wider than that policy permits comes back denied, with a structured reason, rather
than being quietly trimmed to fit, because a capability silently narrowed would leave the
holder failing later for a reason nobody could see. Read the reason, narrow the request, and
issue again.
