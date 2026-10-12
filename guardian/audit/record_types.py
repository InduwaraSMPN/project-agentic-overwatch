r"""The audit chain's record-type vocabulary: which records are decisions, and the two that are not.

WHY A CHAIN RECORD CAN BE SOMETHING OTHER THAN A DECISION (ADR-058, ADR-082)
--------------------------------------------------------------------------------
Until ADR-058 every record in ``guardian_audit.jsonl`` was a decision on an agent request, and the
Guardian created the per-run chain ADR-054 gives it only on its first append. A run whose agents
never reached ``POST /v1/actions`` therefore left no chain at all, extraction found no file, and
``docs/protocols/data-management.md`` section 3 -- ``guardian_audit.jsonl`` present, non-empty and
verified -- made the run unsealable. The quarantined attempt ADR-058 cites is that case: a framework
failure of exactly the kind the evaluation has to count, removed from the data because nothing was
decided.

So the Guardian now opens every new or empty per-run chain with one **run-start** record at
``seq`` zero. It is hash-chained like every other record, and it is **not a decision**: no agent
attempted it, no policy permitted or denied it, and nothing was blocked or executed because of it.
Every consumer that counts attempts, permits, denials or blocks must leave it out, and this module
is the one spelling of how a consumer recognises it.

ADR-082 adds a second non-decision kind for the opposite reason: a decision is sealed *before* its
action is attempted (mediation.py's write-ahead ordering), so what actually happened to the cluster
-- ``succeeded``, ``failed`` or ``not-attempted`` -- cannot be known at the moment the decision is
appended, and a hash-chained record cannot be edited afterwards to add it. The Guardian therefore
appends one **execution** record immediately after every decision, naming the decision's ``seq`` in
``decision_seq`` and carrying the outcome in ``execution_status``. It is never itself a decision, an
attempt, a permit, a deny or a block, for the same reason a run-start is not one: nothing was asked
of the Guardian and nothing was decided by it. See ``guardian/audit/outcome.py`` for how a reader
resolves the status this record (or, for a pre-v4 bundle, a joined ``results.json``) carries.

THE DISCRIMINATOR IS A FIELD OF ITS OWN, NOT A MEANING GIVEN TO AN EXISTING ONE
---------------------------------------------------------------------------------
``record_type`` names what a record is. The alternative -- a run-start spelled as
``decision: null``, or as ``enforcement: not-applicable`` with no action -- would have made the new
record look, to any consumer that predates it, like one of the refusals that value already
describes. A consumer counting ``not-applicable`` records as malformed bodies would then count
every Guardian start as an attack, silently and forever. A new field cannot be mistaken for an old
one. The same argument is why an execution record is not spelled as a fourth ``enforcement`` value:
``enforcement`` already has a closed, tested meaning ("what the Guardian did about the decision"),
and overloading it would make every existing reader of that field silently wrong rather than loudly
unable to parse an unrecognised one.

Records written before the field existed carry no ``record_type``; the audit record schema was
``v2`` then and every record was a decision. :func:`is_run_start` and :func:`is_execution` therefore
answer ``False`` for them, which is correct rather than lenient: those chains contain no run-start
and no execution record to exclude -- an execution record does not exist before schema v4 at all.

WHY THIS MODULE AND NOT ``guardian/app/models.py``
----------------------------------------------------
``guardian/app/models.py`` owns the record *contracts* and types ``record_type`` on them, but
``guardian/audit/`` must not import ``guardian/app/`` (ADR-022) and the runner and analysis read
chain files without the Guardian's contract layer. So the vocabulary has two homes, exactly as
``GENESIS_PREV_HASH`` does, and ``guardian/tests/test_run_start_record.py`` proves the two agree.
Standard library only, like every module on the chain's path.

``guardian/audit/outcome.py`` re-exports :data:`EXECUTION_RECORD_TYPE` from here rather than
defining its own copy, which is a change from how that module was first written: it originally held
an independent literal with the same value, and a third home for one string is a third place for it
to drift. It is imported rather than duplicated for the same reason it already imported
:func:`is_run_start` from here instead of restating ADR-058's discriminator.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

__all__ = [
    "DECISION_RECORD_TYPE",
    "EXECUTION_RECORD_TYPE",
    "RECORD_TYPES",
    "RECORD_TYPE_FIELD",
    "RUN_START_RECORD_TYPE",
    "is_execution",
    "is_run_start",
]

# The discriminator's key, carried by every record the Guardian writes from audit schema v3 onward.
RECORD_TYPE_FIELD: Final = "record_type"

# A decision on one agent request -- permit or deny, blocked, executed or not-applicable. The only
# record type the chain carried before ADR-058, and the only one any RQ5 count reads.
DECISION_RECORD_TYPE: Final = "decision"

# The chain's genesis: a Guardian started for this run (ADR-058). Never an attempt, a permit, a
# denial or a block.
RUN_START_RECORD_TYPE: Final = "run-start"

# A follow-up naming one decision's execution outcome (ADR-082). Never itself an attempt.
EXECUTION_RECORD_TYPE: Final = "execution"

# The closed set, so a consumer can refuse a type it does not know rather than guess at one.
RECORD_TYPES: Final = frozenset(
    {DECISION_RECORD_TYPE, RUN_START_RECORD_TYPE, EXECUTION_RECORD_TYPE}
)


def is_run_start(record: object) -> bool:
    """True when ``record`` is the Guardian's run-start record, and for nothing else.

    Accepts any value, because consumers call it on whatever one JSON line decoded to: a non-mapping
    is not a run-start record, and answering ``False`` leaves the consumer's own shape check to
    reject it the way it always did.
    """
    return isinstance(record, Mapping) and record.get(RECORD_TYPE_FIELD) == RUN_START_RECORD_TYPE


def is_execution(record: object) -> bool:
    """True when ``record`` is a follow-up execution-outcome record (ADR-082), and for nothing else.

    Accepts any value for the same reason :func:`is_run_start` does. A consumer that walks a chain
    counting decisions, attempts or attributed run ids must exclude this record exactly as it
    already excludes a run-start: nothing was asked of the Guardian by it, and it is never a
    decision on an agent request.
    """
    return isinstance(record, Mapping) and record.get(RECORD_TYPE_FIELD) == EXECUTION_RECORD_TYPE
