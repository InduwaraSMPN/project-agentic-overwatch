"""The Guardian's hash-chained audit log: canonicalisation, chain, verification and replay.

``docs/02-architecture.md`` section 3 names ``AuditRecord`` as the Guardian's append-only output and
fixes one rule over it::

    hash = SHA256(prev_hash || canonical_json(record_without_hash))

This package is that rule made executable, in three modules with three separate jobs:

``canonical`` — the byte contract. The single stated definition of what ``canonical_json`` means
for the audit chain, standard library only, because a dependency here is a dependency the chain's
reproducibility rests on. Read its docstring first; it is the authority, and the other two modules
implement against it rather than restating it.

``chain`` — append-only construction. Assigns ``seq``, ``prev_hash`` and ``hash``, refuses a body
that was not born clean, and bounds and scrubs the one free-text field a hostile agent controls,
*before* the record is hashed. That ordering is what makes ``docs/protocols/data-management.md``
section 5's pre-seal sanitizer a no-op on this file instead of a chain-breaking edit (M3-C5).

``verify`` — verification and replay. Detects field mutation, record deletion, record insertion and
reordering, each reported at the ``seq`` where it happened; detects tail truncation and whole-chain
rewrite only when given the head anchor ``data-management.md`` section 1 puts in ``seal.json``, and
says so rather than claiming a property an unsigned hash chain does not have. Replay reconstructs
the full attempted-action history, denials included, which is traceability row T-12's evidence.

``record_types`` — the record-type vocabulary. Every record a chain holds from audit schema ``v3``
says whether it is a ``decision`` or the ``run-start`` genesis ADR-058 adds, and this module is the
one spelling the chain's readers -- the verifier's replay, the runner, analysis -- use to leave the
genesis out of every attempt count. Standard library only.

``crosscheck`` — conformance, not runtime. Compares this package's canonicalisation against a
frozen fixture and against the Monitor's independent implementation of the same rule. Nothing in
the enforcement path imports it, and the Guardian container never runs it.

``fixtures`` — the committed corpus: one clean chain, one file per tamper class, and the frozen
canonicalisation vectors whose expected digests are literals, so a change to the rule fails a
comparison rather than silently redefining itself.

Nothing here imports ``guardian.app``, ``guardian.token``, ``monitor`` or any third-party package
from the modules on the hash path. The audit chain is the last thing that should acquire a
dependency, because every digest in every sealed bundle is a claim about what this code did.
"""
