r"""The action caps: an atomic reserve taken before evaluation, settled when the decision is known.

WHAT THIS MODULE IS
-------------------
``docs/plans/M10-implementation-plan.md`` WS-4 gives this file a row of its own, and the defect
behind it is in ADR-129's context: **there was no cap on actions per token or per run.** V6 measured
a Guardian whose authority policy was barely exercised, and V5/V11 measured why that was partly the
policy's own doing -- agents scaling whole Deployments to zero as a routine containment, which the
ground truth forbids, so a *bounded* agent and a *looping* agent produced the same kind of evidence.
A cap is the answer to the second problem, and it is a control the Guardian owns rather than one the
prompts ask for.

The two values live in ``docs/protocols/security-policy.md`` section 2.1 and are mirrored here as
:data:`ACTION_CAP_PER_TOKEN` and :data:`ACTION_CAP_PER_RUN`, checked against the protocol by
``guardian/tests/test_adversarial_c_scope.py`` on the ADR-016 pattern
``analysis/stats/gate.py`` and ``monitor/aggregator/limits.py`` follow. Why a mirror and not the
token parameters' route into configuration (what ``guardian/app/config.py`` does for the TTL, the
ceiling and the replay bounds) is worth stating, because the two are deliberately different: those
five are *tunable* and a runner reads section 2 to supply them, while these two are a number a
Guardian applies to itself and an operator has no legitimate reason to set per deployment -- a
Guardian whose cap is whatever its environment said would be a Guardian whose blast radius is
configuration. So the protocol is read once, here, and the value that reached the process is the one
the protocol names. The cost of that choice is that a deployment cannot raise the cap, and
``docs/protocols/security-policy.md`` section 2.1 is where somebody who needs that goes; the
alternative -- an environment variable with no protocol value behind it -- is the defect ADR-016
exists to prevent.

WHY THE COUNTERS ARE IN SQLITE AND NOT IN A LOCK AROUND A DICT
---------------------------------------------------------------
Because the property being defended is **atomicity under concurrency**, and the two halves of it
fail
differently. A counter behind a ``threading.Lock`` is correct for the threaded worker the Guardian
runs today and wrong the moment the pipeline becomes asynchronous, which is the change this design
has to survive: a reserve that reads "31 of 32 used", then awaits the policy engine, then writes,
admits 33 -- and the plan names that future explicitly ("so the caps hold under any worker count or
asynchronous evaluation"). The reserve is therefore a single ``BEGIN IMMEDIATE`` transaction that
tests both caps and increments both counters before committing, which is the
:meth:`guardian.token.persistent_replay.SQLiteReplayStore.claim` pattern the replay cache already
uses for exactly the same reason (two processes must not both accept one ``jti``). SQLite is in the
standard library, needs no server, and gives the write reservation the transaction needs.

``BEGIN IMMEDIATE`` is the whole mechanism and is worth being explicit about: the default
``BEGIN``/``BEGIN DEFERRED`` takes no lock until the first write, so two transactions can both read
the counter, both find room, and both write -- the classic lost update. ``IMMEDIATE`` takes the
database write lock at the statement, which is what makes "test the cap and take the slot" one
indivisible step. Every connection is opened with ``isolation_level=None`` so this module, and not
``sqlite3``'s implicit transaction handling, decides where a transaction begins.

WHY THE RESERVE IS TAKEN AFTER VERIFICATION AND BEFORE EVALUATION
-----------------------------------------------------------------
Two different placements, and each is forced by something.

*After* verification, because the per-token counter is keyed on the capability's ``jti`` and the
only ``jti`` worth counting is one whose signature the Guardian checked. A counter keyed on a
*claimed*
``jti`` would be an attacker-controlled key: presenting a fresh forged ``jti`` per request would
  mint
a fresh bucket each time and the per-token cap would bound nothing. The same argument in the other
direction is why a group-A refusal records ``action_caps: null`` rather than a zeroed counter set --
no verified capability, no counter to report, and zero would be a measurement.

*Before* evaluation, so the budget is held while the engine is asked. The alternative -- check the
cap after the policy answers -- leaves a window in which N concurrent requests have all been
permitted by policy and none of them has yet found out that the budget was gone; every one of them
then has to be un-permitted, and the number that reaches the executor is a property of how the
scheduler happened to interleave them. A reserve held across the evaluation is what makes the cap a
property of the run rather than of the timing.

RELEASE IS NOT REFUSAL, AND SETTLEMENT IS MODE-BLIND
-----------------------------------------------------
A reservation that is not spent is released, so the plan's phrase "released when the decision is not
permit-and-executed" is implemented as :meth:`ActionCapReserver.settle(..., consumed=...)` with
``consumed`` true for exactly one case: the decision was a permit. Both halves of that are argued
where they are decided rather than here -- why it keys on the *decision* and not on the enforcement
(the G0/G1 isolation assertion) is :meth:`guardian.app.mediation.Mediator._settle_caps`, and why the
release exists at all is that a run's 32 slots would otherwise be spent by its *refusals*, which is
the failure mode a cap must not have: a Guardian that refuses everything under a cap is a Guardian
that stops mediating, and the refusals it then issues are indistinguishable from enforcement.

WHAT THE TWO COLUMNS ADD UP TO, AND WHY THE CAP IS ON THE SUM
------------------------------------------------------------
``reserved`` is a *claim* and ``consumed`` is a *spend*, and the cap bounds their sum. That is what
makes the release above a release rather than a refund of the wrong thing: a settled permit moves
from the first column to the second and keeps its claim on the budget, while a settled refusal
leaves
both columns. Reading only ``consumed`` would under-report a run mid-flight; reading only the sum
would make a request being evaluated indistinguishable from an action that already happened, and
that is the difference between "the cap stopped a loop" and "the cap arrived just in time".

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every run's action count. Raise :data:`ACTION_CAP_PER_RUN` below the observed envelope and
legitimate
runs start being denied for a reason no agent could do anything about; the protocol's own recount
(median 12 decisions, p99 18) is what the 32 was chosen against. Lower :data:`ACTION_CAP_PER_TOKEN`
to
1 and the per-token cap collides with the single-use ``jti`` -- every capability may be spent
exactly
once anyway, so a per-token cap of 1 would be a second, redundant replay check rather than a bound.
After the ``v2.0`` freeze, AGENTS.md iron rule 6 makes a change here a logged hotfix ADR.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from guardian.app.models import ActionCapCounters, ActionCapReservation

__all__ = [
    "ACTION_CAP_PER_RUN",
    "ACTION_CAP_PER_TOKEN",
    "MIRRORED_KEYS",
    "PROTOCOL_ANCHOR_PATTERN",
    "PROTOCOL_RELATIVE_PATH",
    "PROTOCOL_SECTION_HEADING",
    "ActionCapReserver",
    "SQLiteActionCapReserver",
    "as_protocol_mapping",
]

# ------------------------------------------------------------------------------------------------
# THE VALUES, mirrored from docs/protocols/security-policy.md section 2.1 (ADR-129; D4-A).
# ------------------------------------------------------------------------------------------------

# How many actions one capability may hold a claim on at once (security-policy section 2.1:
# `action_cap_per_token = 8`). Above one, so that it is a bound on a capability's blast radius
# rather
# than a second copy of the single-use `jti` check the replay cache already performs -- a jti is
# spent
# once, so a per-token cap of 1 would duplicate `replay.jti-spent` under a different reason code and
# make two refusals for one event.
ACTION_CAP_PER_TOKEN: Final[int] = 8

# How many actions one run may hold a claim on at once (`action_cap_per_run = 32`). The protocol
# states why this number and not a smaller one: the v1 corpus's median was 12 Guardian decisions per
# run and its p99 was 18 (recount 2026-09-26), so 32 clears the observed envelope with room for the
# runs that acted hardest while still bounding a runaway loop. The recount belongs to the protocol;
# restating the 12 and the 18 here would be a second home for two numbers nothing in this module
# uses.
ACTION_CAP_PER_RUN: Final[int] = 32

# Where the mirrored values are checked against, and how the mirror test finds them. The anchor is
# the section heading rather than a line number, for the reason `scripts/security_params.py` gives
# for
# its own extraction: a heading is prose and gets retitled, while the section's content is what
# changed, and a pattern that stops matching is a loud failure rather than a stale number.
PROTOCOL_SECTION_HEADING: Final = "### 2.1 M10 remediation parameters (single source of truth)"
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/security-policy.md"

# One pattern per mirrored value, matching the backticked assignment the protocol writes
# (`action_cap_per_token = 8`). Anchored on the key rather than on a position, so a reworded
# sentence
# around it does not break the mirror and a changed *value* cannot be read by accident.
PROTOCOL_ANCHOR_PATTERN: Final = r"`action_cap_{key} = (\d+)`"

# The keys this module mirrors, in the order the mirror test reports them.
MIRRORED_KEYS: Final[tuple[str, ...]] = ("per_token", "per_run")


def as_protocol_mapping() -> dict[str, int]:
    """Return the mirrored cap values keyed as the protocol names them.

    The comparison surface the mirror test uses. A fresh dict per call, so no caller can mutate the
    mirror for everyone else.
    """
    return {
        "per_token": ACTION_CAP_PER_TOKEN,
        "per_run": ACTION_CAP_PER_RUN,
    }


# ------------------------------------------------------------------------------------------------
# The store
# ------------------------------------------------------------------------------------------------

# One row per (scope, key). `scope` is the string form of the dimension -- "token" or "run" --
# rather
# than a boolean, so a row in this table is readable on its own by whoever reads the file, and so
# the
# two dimensions cannot be told apart by a future edit that reverses a flag. The CHECK is what makes
# the column total rather than merely constrained by convention.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_cap_counters (
    scope TEXT NOT NULL CHECK (scope IN ('token', 'run')),
    cap_key TEXT NOT NULL,
    reserved INTEGER NOT NULL DEFAULT 0,
    consumed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, cap_key)
);
"""

_SCOPE_TOKEN: Final = "token"  # noqa: S105 - scope constant, not a credential
_SCOPE_RUN: Final = "run"

# How long SQLite waits for the write reservation before raising. Generous, because the holders are
# microseconds long (one transaction, two rows) and the alternative -- failing a reserve because
# thirty other requests arrived at once -- would deny a request for a reason that has nothing to do
# with the cap.
_BUSY_TIMEOUT_SECONDS: Final = 30.0


def _is_plain_int(value: object) -> bool:
    """``True`` for a genuine ``int``; ``bool`` is excluded because ``True`` is not a cap."""
    return isinstance(value, int) and not isinstance(value, bool)


@runtime_checkable
class ActionCapReserver(Protocol):
    """The one method :func:`guardian.app.mediation.adjudicate` needs from the caps.

    A protocol rather than the concrete class, for the reason every other collaborator seam in
    ``guardian/app/mediation.py`` is one: the pipeline names what it needs, and a test can supply
    something else without the pipeline learning what the real store is made of.

    ``reserve`` **always** returns a handle, including when the cap is spent. A refusal still has to
    be audited, and the record of a refusal is required to carry the counters that show which cap
    was spent -- so the caller reads ``granted`` and the counters off one object rather than
    re-deriving either.
    """

    def reserve(self, *, run_key: str, token_key: str) -> ActionCapReservation:
        """Take one slot against both caps, or return a handle that says it was not granted."""
        ...


class SQLiteActionCapReserver:
    """Per-token and per-run action caps, reserved atomically in one SQLite transaction.

    The database path and both caps are injected, and the caps default to the protocol's values
    rather than being required: a test that wants to drive a cap boundary in one assertion rather
    than
    thirty-two may, and a test that wants the real boundary (as
    ``guardian/tests/test_adversarial_c_scope.py`` does) gets the shipped numbers because it named
      no
    caps of its own. Nothing else is configurable, deliberately: the *where* is a path like the
    replay
    store's, and the *how much* is security-policy section 2.1's.

    Each operation opens its own connection and closes it before returning, on the pattern
    :class:`guardian.token.persistent_replay.SQLiteReplayStore` sets. Sharing one connection across
    threads would need a lock around it, and a lock around a connection that is already inside a
    transaction is how a reserve ends up holding the write reservation across somebody else's work.
    """

    def __init__(
        self,
        path: Path,
        *,
        per_token_cap: int = ACTION_CAP_PER_TOKEN,
        per_run_cap: int = ACTION_CAP_PER_RUN,
    ) -> None:
        for label, cap in (("per_token_cap", per_token_cap), ("per_run_cap", per_run_cap)):
            if not _is_plain_int(cap) or cap < 1:
                raise ValueError(
                    f"{label} must be a positive integer; security-policy.md section 2.1 owns the "
                    f"values and guardian/app/limits.py mirrors them"
                )
        self.path = Path(path)
        self.per_token_cap = per_token_cap
        self.per_run_cap = per_run_cap
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # `closing`, not a bare `with`: sqlite3's context manager commits or rolls back a
        # transaction
        # and does NOT close the connection, so a `with` here would leave the handle open until the
        # garbage collector got round to it -- and on Windows an open handle keeps the file locked,
        # which is how a test's temporary directory ends up undeletable.
        with contextlib.closing(self._connect()) as connection:
            connection.executescript(_SCHEMA)
        # Cap state is security-sensitive even though it holds no credential material: the counters
        # bound a capability's blast radius, so an operator who could read and edit them could widen
        # it. Restrict it on POSIX; Windows ACLs are inherited from the containing directory, which
        # is the same position the replay store takes and the same limitation.
        if os.name == "posix":
            self.path.chmod(0o600)

    def reserve(self, *, run_key: str, token_key: str) -> ActionCapReservation:
        """Take one slot against both caps, atomically, or take none and say so.

        The transaction tests **both** caps before incrementing **either** counter. Testing one and
        incrementing the other is the same lost-update shape as a check-then-act pair, one level
        down:
        a request that passes the run cap and fails the token cap would have consumed a run slot it
        never used, and since the run cap is the one a whole campaign shares, the damage would be
        spread across every other capability in the run rather than confined to the one that
        presented it.

        The test is on the **sum** of the two columns and not on ``reserved`` alone, which is the
        whole of the model invariant :class:`~guardian.app.models.ActionCapCounters` states: a
        reserved count alone would admit an unbounded number of actions after that many had been
        settled into ``consumed``, and a cap whose budget resets every time a request finishes is
        not
        a cap.
        """
        if not run_key or not token_key:
            # A cap keyed on an empty string would make every run and every capability share one
            # bucket, which is not stricter -- it is a single global cap with a misleading name.
            raise ValueError("run_key and token_key must both be non-empty")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            token = self._read(connection, _SCOPE_TOKEN, token_key)
            run = self._read(connection, _SCOPE_RUN, run_key)
            granted = (
                token["reserved"] + token["consumed"] < self.per_token_cap
                and run["reserved"] + run["consumed"] < self.per_run_cap
            )
            if granted:
                self._write(
                    connection, _SCOPE_TOKEN, token_key, token["reserved"] + 1, token["consumed"]
                )
                self._write(connection, _SCOPE_RUN, run_key, run["reserved"] + 1, run["consumed"])
                token = {**token, "reserved": token["reserved"] + 1}
                run = {**run, "reserved": run["reserved"] + 1}
            connection.commit()
            return ActionCapReservation(
                granted=granted,
                run_key=run_key,
                token_key=token_key,
                counters=ActionCapCounters(
                    per_token=self.per_token_cap,
                    per_run=self.per_run_cap,
                    token_reserved=token["reserved"],
                    token_consumed=token["consumed"],
                    run_reserved=run["reserved"],
                    run_consumed=run["consumed"],
                ),
            )
        except BaseException:
            # Roll the write reservation back rather than unwinding with it held: a raised exception
            # inside a transaction that has taken the lock leaves every other thread in the process
            # waiting on `timeout` for a reservation this one is never going to release.
            connection.rollback()
            raise
        finally:
            connection.close()

    def settle(self, reservation: ActionCapReservation, *, consumed: bool) -> ActionCapCounters:
        """Finish ``reservation``: spend the slot, or give it back. Never raises for a non-grant.

        ``consumed=True`` moves one from ``reserved`` to ``consumed``; ``consumed=False`` returns it
        to ``reserved``'s absence. A reservation that was never granted is a no-op, and a refusal
        whose budget is already spent has nothing to give back.

        The counters returned are the **post**-settlement values, which is what makes the store
        self-checking: a caller (or a test) that reserved and settled a refused action can read
        ``run_reserved`` here and see the slot returned. The values recorded in the *record* are the
        reservation's own, which is a different pair of numbers for a different question -- what the
        budget looked like when the decision was made.
        """
        if not reservation.granted:
            return reservation.counters
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            token = self._read(connection, _SCOPE_TOKEN, reservation.token_key)
            run = self._read(connection, _SCOPE_RUN, reservation.run_key)
            token_reserved = max(0, token["reserved"] - 1)
            run_reserved = max(0, run["reserved"] - 1)
            self._write(
                connection,
                _SCOPE_TOKEN,
                reservation.token_key,
                token_reserved,
                token["consumed"] + 1 if consumed else token["consumed"],
            )
            self._write(
                connection,
                _SCOPE_RUN,
                reservation.run_key,
                run_reserved,
                run["consumed"] + 1 if consumed else run["consumed"],
            )
            connection.commit()
            return ActionCapCounters(
                per_token=self.per_token_cap,
                per_run=self.per_run_cap,
                token_reserved=token_reserved,
                token_consumed=token["consumed"] + 1 if consumed else token["consumed"],
                run_reserved=run_reserved,
                run_consumed=run["consumed"] + 1 if consumed else run["consumed"],
            )
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def counters(self, *, run_key: str, token_key: str) -> ActionCapCounters:
        """Read both counters without reserving. Observational only; never gate admission on it.

        Exists so that a test can ask what a run's budget looks like *after* a sequence of decisions
        without inferring it from the last record, and so that an operator debugging a bounded run
        has
        one read that does not change what it reads.
        """
        with contextlib.closing(self._connect()) as connection:
            token = self._read(connection, _SCOPE_TOKEN, token_key)
            run = self._read(connection, _SCOPE_RUN, run_key)
        return ActionCapCounters(
            per_token=self.per_token_cap,
            per_run=self.per_run_cap,
            token_reserved=token["reserved"],
            token_consumed=token["consumed"],
            run_reserved=run["reserved"],
            run_consumed=run["consumed"],
        )

    def _connect(self) -> sqlite3.Connection:
        """Open one connection in explicit-transaction mode. See the module docstring on the why."""
        connection = sqlite3.connect(
            self.path,
            timeout=_BUSY_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {int(_BUSY_TIMEOUT_SECONDS * 1000)}")
        return connection

    @staticmethod
    def _read(connection: sqlite3.Connection, scope: str, cap_key: str) -> dict[str, int]:
        """Return one counter row, or zeroes when the row does not exist yet.

        Zeroes rather than a row: an absent row is a capability that has reserved nothing, and
        inserting one to say that would put a write in the read path of a transaction whose whole
        point is that it takes the write lock once.
        """
        row = connection.execute(
            "SELECT reserved, consumed FROM action_cap_counters WHERE scope = ? AND cap_key = ?",
            (scope, cap_key),
        ).fetchone()
        if row is None:
            return {"reserved": 0, "consumed": 0}
        return {"reserved": int(row[0]), "consumed": int(row[1])}

    @staticmethod
    def _write(
        connection: sqlite3.Connection, scope: str, cap_key: str, reserved: int, consumed: int
    ) -> None:
        """Upsert one counter row.

        ``INSERT ... ON CONFLICT DO UPDATE`` rather than a select-then-choose, so the row is written
        in one statement and there is no second place in this module where the two counters could be
        updated inconsistently. The ``WHERE`` clause on the update is a guard rather than a filter:
        if
        a counter were ever about to go negative it stays at what it is instead, and the clamp in
        :meth:`settle` is what is actually relied upon.
        """
        connection.execute(
            "INSERT INTO action_cap_counters(scope, cap_key, reserved, consumed) VALUES (?, ?, ?, ?) "  # noqa: E501 - sql
            "ON CONFLICT(scope, cap_key) DO UPDATE SET "
            "reserved = MAX(0, excluded.reserved), consumed = MAX(0, excluded.consumed)",
            (scope, cap_key, reserved, consumed),
        )
