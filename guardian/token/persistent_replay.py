"""SQLite-backed production replay protection owned by Guardian.

The store implements the same claim contract and retention rule as :class:`ReplayCache`, but keeps
state across Guardian restarts and serialises claims across threads and processes. SQLite is part of
the Python runtime, requires no database server, and provides the unique-key and transaction
primitives needed to make claim-or-reject indivisible.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS replay_entries (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT NOT NULL UNIQUE,
    retain_until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS replay_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    retention_high_water INTEGER NOT NULL
);
INSERT OR IGNORE INTO replay_state(singleton, retention_high_water) VALUES (1, 0);
"""


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class SQLiteReplayStore:
    """Persistent, process-safe single-use ``jti`` store.

    Each operation opens its own SQLite connection. ``BEGIN IMMEDIATE`` obtains the database write
    reservation before eviction, membership testing, and insertion, so two processes cannot both
    accept one ``jti``. The database path, both retention bounds, and the clock are injected; tests
    can use a temporary file and a frozen clock without sleeping.
    """

    def __init__(
        self,
        path: Path,
        *,
        min_entries: int,
        window_seconds: int,
        clock: Callable[[], int],
    ) -> None:
        if not _is_plain_int(min_entries) or min_entries < 0:
            raise ValueError("min_entries must be a non-negative integer")
        if not _is_plain_int(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be a positive integer number of seconds")
        self.path = Path(path)
        self._min_entries = min_entries
        self._window_seconds = window_seconds
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
        # Replay state is security-sensitive even though it contains no credential material.
        # Restrict it on POSIX; Windows ACLs are inherited from the containing directory.
        if os.name == "posix":
            self.path.chmod(0o600)

    @property
    def min_entries(self) -> int:
        return self._min_entries

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def __len__(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM replay_entries").fetchone()
        if row is None:
            raise RuntimeError("replay store count returned no row")
        return int(row[0])

    def claim(self, jti: str, *, expires_at: int) -> bool:
        """Atomically claim ``jti`` once, retaining it under the configured union of bounds."""
        if not isinstance(jti, str) or not jti:
            raise ValueError("jti must be a non-empty string")
        if not _is_plain_int(expires_at) or expires_at < 0:
            raise ValueError("expires_at must be a non-negative integer number of epoch seconds")
        now = self._clock()
        if not _is_plain_int(now):
            raise TypeError("clock must return an integer number of epoch seconds")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._evict(connection, now)
            row = connection.execute(
                "SELECT retention_high_water FROM replay_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("replay store state row is missing")
            retain_until = max(now + self._window_seconds, expires_at, int(row[0]))
            try:
                connection.execute(
                    "INSERT INTO replay_entries(jti, retain_until) VALUES (?, ?)",
                    (jti, retain_until),
                )
            except sqlite3.IntegrityError:
                # The schema's only insert-time conflict is UNIQUE(jti). Commit the eviction pass
                # that preceded the membership decision, matching ReplayCache's claim semantics.
                connection.commit()
                return False
            connection.execute(
                "UPDATE replay_state SET retention_high_water = ? WHERE singleton = 1",
                (retain_until,),
            )
            connection.commit()
            return True
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def is_spent(self, jti: str) -> bool:
        """Return whether ``jti`` is retained. Observational only; never gate admission on it."""
        if not isinstance(jti, str) or not jti:
            raise ValueError("jti must be a non-empty string")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM replay_entries WHERE jti = ?",
                (jti,),
            ).fetchone()
        return row is not None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _evict(self, connection: sqlite3.Connection, now: int) -> None:
        row = connection.execute("SELECT COUNT(*) FROM replay_entries").fetchone()
        if row is None:
            raise RuntimeError("replay store count returned no row")
        excess = int(row[0]) - self._min_entries
        while excess > 0:
            oldest = connection.execute(
                "SELECT sequence, retain_until FROM replay_entries ORDER BY sequence LIMIT 1"
            ).fetchone()
            if oldest is None or int(oldest[1]) > now:
                break
            connection.execute("DELETE FROM replay_entries WHERE sequence = ?", (oldest[0],))
            excess -= 1
