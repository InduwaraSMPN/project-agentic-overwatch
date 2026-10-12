r"""The single-use ``jti`` store: the difference between a capability and a reusable password.

WHAT THIS MODULE IS
-------------------
``docs/02-architecture.md`` section 3 marks one claim of the capability token ``jti (single-use)``,
and ``docs/adr/ADR-004-capability-tokens-jwt.md`` records the obligation that follows -- "jti replay
cache eviction tested". This module is the store that makes "single-use" true. It answers one
question, and it answers it destructively: *has this ``jti`` been spent, and if not, is it now?*

Without it, a capability token is a bearer password with an expiry date. Position P3 of
``docs/plans/M3-implementation-plan.md``'s threat model gives the attacker "unbounded request
volume and ordering -- replay, flood, interleave, race", and every one of those four words names a
way to attack this file specifically. The rest of the verification path can be perfect and the
Guardian still fails its purpose if a captured token can be presented twice.

EVERY PROTOCOL PARAMETER ARRIVES BY CONFIGURATION; NONE IS A LITERAL HERE
-------------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 2 owns both bounds -- the number of entries and the
length of the window -- and ``.agents/rules/00-source-of-truth.md`` allows them to be stated
exactly once, there. :class:`ReplayCache` therefore requires ``min_entries`` and ``window_seconds``
as constructor arguments with no defaults and no environment lookup, and the composition root under
``guardian/app/`` supplies them from configuration seeded by section 2. A grep of
``guardian/token/`` for either value finds nothing. The clock is injected on the same principle:
this module never imports :mod:`time`, so the eviction behaviour the adversarial suite has to prove
is exercised by advancing a test clock rather than by sleeping, and it is exact rather than
approximately timed.

This module depends on nothing else in the package and production composition does not import it.
It remains the deterministic in-memory implementation injected by focused tests. Production uses
:class:`guardian.token.persistent_replay.SQLiteReplayStore` (ADR-045); both satisfy
:class:`guardian.token.verifier.JtiClaimant` structurally, so the verifier does not change. The one
cost of that independence is a three-line integer predicate repeated here rather than imported;
that is a Python type test, not a protocol value, so no second decision exists to drift.

CLAIM-OR-REJECT IS ONE INDIVISIBLE STEP
----------------------------------------
The adversarial table's group D requires that two requests in flight with the same ``jti`` produce
"exactly one winning, which proves the cache is not read-then-write racy". The naive shape --
``if jti in cache: deny`` followed by ``cache.add(jti)`` -- is exactly that racy read-then-write:
two threads can both evaluate the membership test before either performs the insert, and both are
admitted. An attacker holding one captured token and a thread pool does not need any other flaw.

There is therefore no membership predicate on the admission path at all. :meth:`ReplayCache.claim`
is the *only* way to consult the store for a decision, and it performs eviction, the membership
test and the insert inside a single :class:`threading.Lock` critical section, so no other thread
can observe or modify the store between the test and the write. It returns ``True`` to the first
caller and ``False`` to every subsequent one, and "first" is decided by the lock rather than by
timing.

Two alternatives were considered and rejected. Relying on ``dict.setdefault`` being atomic under
CPython is true today and is still wrong: it is a property of the GIL and of keys whose ``__hash__``
and ``__eq__`` cannot re-enter the interpreter, so it is a correctness argument that rests on an
implementation detail of one interpreter, and it would not cover the eviction pass that has to
happen in the same critical section anyway -- an eviction interleaved between two claims can delete
the entry a concurrent claim just wrote. A lock-free compare-and-set over an immutable mapping
would work but replaces a four-line critical section with a retry loop, for a component whose
contention is a few hundred requests per run.

:meth:`ReplayCache.is_spent` exists for tests and for operational inspection and is documented as
observational only. It is inherently stale the moment it returns, and using it to gate an admission
would reintroduce precisely the race :meth:`claim` exists to close.

"WHICHEVER LARGER" IS IMPLEMENTED LITERALLY, AND THAT IS THE WHOLE POINT
-------------------------------------------------------------------------
Section 2 bounds the cache at "the last ``N`` jti **or** the window, whichever larger". The word
"or" is load-bearing and the plan says so: the eviction-replay case is "the only test that proves
the 'whichever larger' clause is implemented rather than merely written down".

A size-only cache -- keep the most recent ``N``, drop the rest -- is the obvious implementation and
is broken in a way that is invisible until someone attacks it. The attacker captures a token,
floods the Guardian with ``N`` further requests carrying fresh ``jti`` values, and pushes the
captured entry off the end of the store. It then replays the captured token, which is *still inside
its TTL* and therefore still passes every other check in
:mod:`guardian.token.verifier`. The store has forgotten it, so it is admitted. The single-use
property is defeated by nothing more sophisticated than volume, which position P3 grants for free.

The retained set is therefore the *union* of the two bounds, never the intersection: an entry may
be evicted only when it is both outside the window and outside the most recent ``N``. In
:meth:`ReplayCache._evict` the ``while`` guard is the size half -- the store never shrinks below
``min_entries`` -- and the ``break`` is the window half -- an entry still inside its retention
horizon stops the pass regardless of how far the size bound has been exceeded. Neither can override
the other, which is what "whichever larger" means. Under flood the store grows past ``min_entries``
and stays there until the window expires, which is the correct and intended behaviour: memory is
bounded by the window, not by the size floor.

RETENTION IS A RUNNING MAXIMUM, SO THE QUEUE IS SORTED BY CONSTRUCTION
-----------------------------------------------------------------------
Each entry records the time until which it must be remembered:
``max(now + window_seconds, expires_at, the previous maximum)``.

The first term is the section 2 window. The second is the presented token's own ``exp``, and it
covers the case where a deployment configures a window shorter than the TTL ceiling -- without it,
a token could outlive the memory of its own ``jti``, which is the eviction-replay hole reopened
through configuration rather than through code. The third term makes the stored values
non-decreasing in insertion order, so the oldest entry always has the smallest horizon and eviction
can stop at the first entry still inside it instead of scanning the whole store on every request.
That is what keeps admission amortised constant-time under exactly the flood the attack uses.

Forcing monotonicity can only ever retain an entry *longer* than strictly required, never shorter,
and the excess is bounded by the difference between the window and the TTL ceiling. Over-retention
is the safe direction: a remembered ``jti`` denies a replay, a forgotten one admits it.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
:meth:`claim` is called last in :meth:`guardian.token.verifier.TokenVerifier.verify`, after every
other check has passed, so that a token denied for some other reason does not burn its ``jti`` --
see that module for why the ordering matters. A ``claim`` that raises rather than returning is
caught there and turned into a fail-closed denial with its own reason code, so a store fault denies
and is audited rather than surfacing as an unhandled error.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable


def _is_plain_int(value: object) -> bool:
    """Return whether ``value`` is an ``int`` that is not a ``bool``.

    ``bool`` subclasses ``int``, so ``True`` would otherwise satisfy every integer check and
    compare equal to 1 -- an expiry one second after the epoch, in a store whose whole job is to
    get expiry right.
    """
    return isinstance(value, int) and not isinstance(value, bool)


class ReplayCache:
    """A single-use ``jti`` store bounded by size and window together, safe for concurrent claims.

    Construction takes both bounds and the clock, and defaults none of them:

    ``min_entries``
        The number of most-recent ``jti`` values that are retained regardless of age. Owned by
        ``docs/protocols/security-policy.md`` section 2.
    ``window_seconds``
        The age below which a ``jti`` is retained regardless of how many newer ones have arrived.
        Owned by the same section.
    ``clock``
        A zero-argument callable returning integer epoch seconds. The only source of time here.

    The instance is safe to share across threads. It is deliberately process-local and is retained
    as the injectable deterministic test implementation. Production composition uses the persistent,
    cross-process store from :mod:`guardian.token.persistent_replay` (ADR-045).
    """

    def __init__(
        self,
        *,
        min_entries: int,
        window_seconds: int,
        clock: Callable[[], int],
    ) -> None:
        if not _is_plain_int(min_entries) or min_entries < 0:
            raise ValueError("min_entries must be a non-negative integer")
        if not _is_plain_int(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be a positive integer number of seconds")
        self._min_entries = min_entries
        self._window_seconds = window_seconds
        self._clock = clock
        # Insertion-ordered, so the oldest entry is always the first item and eviction never has to
        # sort or scan for a minimum.
        self._entries: OrderedDict[str, int] = OrderedDict()
        self._retention_high_water = 0
        self._lock = threading.Lock()

    @property
    def min_entries(self) -> int:
        """The configured size half of the bound."""
        return self._min_entries

    @property
    def window_seconds(self) -> int:
        """The configured window half of the bound."""
        return self._window_seconds

    def __len__(self) -> int:
        """The number of ``jti`` values currently retained.

        Observational, like :meth:`is_spent`: it reflects the store at the instant the lock was
        held and may be stale by the time it is read.
        """
        with self._lock:
            return len(self._entries)

    def claim(self, jti: str, *, expires_at: int) -> bool:
        """Record ``jti`` as spent and return ``True``, or return ``False`` if it already was.

        The only admission path. Eviction, the membership test and the insert all happen inside one
        lock, so concurrent callers presenting the same ``jti`` produce exactly one ``True``.

        ``expires_at`` is the presented token's ``exp``. It only ever extends retention -- see the
        module docstring on why the store must not forget a ``jti`` while a token bearing it can
        still be used.

        Raises :class:`ValueError` on a malformed ``jti`` or ``expires_at``. That is a precondition
        violation rather than an attack: :class:`guardian.token.verifier.TokenVerifier` validates
        both before it ever reaches this method, so the path is unreachable from the network and a
        raise here is a caller bug worth surfacing loudly.
        """
        if not isinstance(jti, str) or not jti:
            raise ValueError("jti must be a non-empty string")
        if not _is_plain_int(expires_at) or expires_at < 0:
            raise ValueError("expires_at must be a non-negative integer number of epoch seconds")

        with self._lock:
            now = self._clock()
            if not _is_plain_int(now):
                raise TypeError("clock must return an integer number of epoch seconds")
            self._evict(now)
            if jti in self._entries:
                return False
            retain_until = max(now + self._window_seconds, expires_at, self._retention_high_water)
            self._retention_high_water = retain_until
            self._entries[jti] = retain_until
            return True

    def is_spent(self, jti: str) -> bool:
        """Return whether ``jti`` is currently retained. Observational only -- never gate on this.

        Reading this value and then acting on it is the read-then-write race :meth:`claim` exists
        to eliminate: another thread can claim the same ``jti`` between the two steps. It is here
        for tests and for operational inspection, and for nothing else.
        """
        if not isinstance(jti, str) or not jti:
            raise ValueError("jti must be a non-empty string")
        with self._lock:
            return jti in self._entries

    def _evict(self, now: int) -> None:
        """Drop entries that both bounds agree may go. Caller must already hold the lock.

        The two lines below are the "whichever larger" clause of ``security-policy.md`` section 2,
        and they are meant to be read as a pair. The ``while`` condition is the size half: the store
        is never reduced below ``min_entries``, so the most recent ``N`` are always present. The
        ``break`` is the window half: the oldest entry still inside its retention horizon ends the
        pass, and because horizons are non-decreasing in insertion order every newer entry is
        inside its own horizon too. An entry is removed only when it fails both tests, which is the
        union of the two bounds and not their intersection.

        Do not "optimise" this into a size-only trim. Doing so reopens the eviction-replay attack
        the module docstring describes, and it will pass every test that does not deliberately
        flood the store first.
        """
        while len(self._entries) > self._min_entries:
            oldest_jti, retain_until = next(iter(self._entries.items()))
            if retain_until > now:
                break
            del self._entries[oldest_jti]
