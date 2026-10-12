"""Package marker for the Guardian's mediation service: the system's sole enforcement path.

WHAT THIS PACKAGE IS
--------------------
``docs/02-architecture.md`` section 1 types the Guardian ``deterministic``, ``trusted; sole
credential holder``, and gives it one job in section 2's data flow: an Executor's ``ActionRequest``
arrives, its capability token is verified, an OPA policy decides, the action is executed through the
Guardian's own ServiceAccount, and an ``AuditRecord`` is appended. This package is the code that
performs that sequence. Every mutation the agent layer ever causes in the target environment passes
through here, which is why the boundary this package sits on is enforced rather than merely
documented.

There is no second path and no development shortcut. ``.agents/rules/10-guardian-first.md`` forbids
any code under ``agents/`` from importing a Kubernetes client, shelling out to ``kubectl`` or
opening a connection to the cluster API, and ``scripts/grep_guard.sh`` greps for exactly that with
no exemption mechanism. ``docs/protocols/security-policy.md`` section 3 extends the same rule to
local experiments: "There is no 'dev shortcut' direct client." The agent layer reaches the cluster
by asking this package, or it does not reach the cluster.

THE CREDENTIAL BOUNDARY IS THIS DIRECTORY, AND IT IS NOT NEGOTIABLE
-------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 1.2 states it as an invariant: only ``guardian/``
holds a kubeconfig or ServiceAccount able to mutate the cluster, and its own RBAC is least
privilege. Section 2 adds the token signing key to the same boundary -- "signing key in
``guardian/`` only, provided via env/Secret". Rule 10 states the consequence directly: that
ServiceAccount token, that kubeconfig and that signing key are never copied anywhere else, not into
tests and not into ``.env``.

:mod:`guardian.app.config` is where the signing key enters the process, and it enters as a
``SecretStr`` that is required rather than defaulted, so a Guardian with no key does not start.
Nothing else in this package accepts a key, and nothing in it writes one out.

THE ADVERSARY IS THE CALLER
---------------------------
``docs/plans/M3-implementation-plan.md``'s threat model is explicit that the agent layer -- the
Orchestrator, the Supervisors and the Executors -- is assumed fully hostile, and that under the four
injection classes it is also the channel through which attacker-authored content arrives. Every
module here is written against a caller that controls the whole request body, arbitrary token bytes,
request volume and ordering, and network reach to this surface. Two consequences shape the code:

*Fail closed, everywhere and in both directions.* An unrecognised Guardian mode is a startup error
rather than a silent default; a policy engine that is unavailable or slow denies rather than
degrading to permit; a malformed body is a denial with a reason code rather than a stack trace; and
an audit sink that cannot append means no decision is returned at all.

*Every denial is audited, not merely returned.* Security policy section 1.4 requires permit and deny
alike to produce hash-chained records, and the RQ5 measures in
``docs/protocols/evaluation-protocol.md`` section 3 are computed from that log -- so a block that
the log does not contain is invisible to the evaluation whether or not it happened.
:mod:`guardian.app.mediation` makes that structural: the only construction site of an
``ActionResult`` takes an already-appended ``AuditRecord`` as its input.

WHAT LIVES HERE
---------------
:mod:`guardian.app.models` holds the frozen wire contracts and the structured reason-code
vocabulary. :mod:`guardian.app.config` holds the start-time, immutable ``GuardianConfig``, including
the condition-arm mode that only the runner may set. :mod:`guardian.app.policy` holds the OPA seam
-- the bundle loader with its digest, and the input-document builder that excludes
LLM-authored free text by construction. :mod:`guardian.app.mediation` holds the one pipeline.
:mod:`guardian.app.main` holds the FastAPI surface.

What deliberately does not live here: the capability-token issuer and verifier
(``guardian/token/``, M3-T3.3), the canonical-JSON hash chain and its verifier
(``guardian/audit/``, M3-T3.6), the Rego policy bundle itself (``guardian/policies/``, M3-T3.2), and
the real cluster executor (Tier B). Each is reached through a narrow protocol defined in
:mod:`guardian.app.mediation` or :mod:`guardian.app.policy`, so this package is complete and
drivable before any of them exists -- and so that none of them can be replaced by something weaker
without the substitution being visible at the seam.

The marker itself is what makes these modules importable as ``guardian.app.<module>`` from the
repository root. ``pyproject.toml`` already names ``guardian`` in ruff's ``src`` list, so the
tooling side of that was settled at M0; this file is the interpreter side of it.
"""
