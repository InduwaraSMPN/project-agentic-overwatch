"""Capability-token issue, verify and single-use ``jti`` replay -- the Guardian's authenticity half.

WHAT THIS PACKAGE IS
--------------------
``docs/02-architecture.md`` section 3 names ``CapabilityToken`` as the Supervisor-to-Guardian
credential and fixes its claim set: ``iss`` (supervisor id), ``sub`` (executor id), ``run_id``,
``phase``, ``allow {verbs[], resources[], namespaces[]}``, ``jti`` (single-use), ``iat`` and
``exp``. ``docs/adr/ADR-004-capability-tokens-jwt.md`` decides the carrier and records the
obligations that follow from it. This package is those two documents made executable, and nothing
else: it mints tokens, it decides whether a presented token is authentic and in-scope for the
request in hand, and it remembers which ``jti`` values have been spent. It performs no policy
evaluation -- deciding whether an *authentic* token's scope permits a *particular* action is
OPA's job under ``guardian/policies/`` -- and it writes no audit record, because
``guardian/audit/`` owns the chain. What it produces is a structured verdict for those two to
consume.

THE SIGNING KEY LIVES IN ``guardian/`` AND NOWHERE ELSE
-------------------------------------------------------
``docs/protocols/security-policy.md`` section 1.2 makes the Guardian the sole holder of anything
that can act on the cluster, and section 2 places the token signing key "in ``guardian/`` only,
provided via env/Secret, rotated on demand". ``.agents/rules/10-guardian-first.md`` states the
same invariant from the other side: the key is never copied into tests, into ``.env``, or into any
module under ``agents/``. Two consequences are visible in the code here rather than left to
discipline. First, no module in this package contains a key, a secret, a token value or any
example of one -- not in code, not in a docstring, not as a fixture. Second, neither the issuer
nor the verifier stores key material as an attribute; each holds a *provider callable* supplied by
the composition root, calls it at the moment it is needed, and lets the value go out of scope
immediately. That is what makes "rotated on demand" a configuration change rather than a restart,
and it keeps key bytes out of every object ``repr`` and therefore out of every traceback.

EVERY PARAMETER HERE IS PROTOCOL-OWNED, AND NONE OF THEM IS A LITERAL IN THIS PACKAGE
-------------------------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 2 is the single source of truth for the token
lifetime, the per-phase override ceiling, the replay cache's size and window, and the signing
algorithm. ``.agents/rules/00-source-of-truth.md`` allows those values to be stated exactly once.
They are therefore not stated here at all: :class:`guardian.token.verifier.TokenParameters` and
:class:`guardian.token.replay.ReplayCache` take them as required constructor arguments with no
defaults and no fallbacks, and the composition root under ``guardian/app/`` is what reads them
from configuration seeded by section 2. A grep of this package for any section 2 value finds
nothing, which is the machine-checkable form of the claim. The practical effect is that a
deployment which fails to supply one of them cannot start rather than quietly running on a number
nobody chose -- the same fail-closed posture ``monitor/aggregator/limits.py`` takes toward
uncalibrated protocol values.

The clock is treated the same way. No module here imports :mod:`time` or :mod:`datetime`, and no
module reads a clock. Every temporal decision -- expiry, issued-in-the-future, replay-cache
eviction -- is taken against an injected ``clock`` callable returning integer epoch seconds, so
the adversarial suite can advance time exactly and the eviction test that
``docs/plans/M3-implementation-plan.md`` calls ADR-004's explicit obligation is deterministic
rather than slept-through.

WHERE THE PIECES SIT
--------------------
:mod:`guardian.token.verifier` owns the shared contract -- the parameter carrier, the claim
dataclasses, the strict claim validators, the closed set of denial reason codes, and the verifier
itself. :mod:`guardian.token.issuer` depends on it, deliberately in that direction: the checker
defines what a valid token is and the minter conforms, so the issuer cannot mint a token shape the
verifier would reject. :mod:`guardian.token.replay` depends on neither and is imported by neither;
it satisfies the verifier's ``JtiClaimant`` protocol structurally, which keeps the single-use
store swappable without giving the verifier a hard dependency on one implementation of it.
"""
