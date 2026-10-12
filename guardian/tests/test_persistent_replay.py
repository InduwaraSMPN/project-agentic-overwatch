"""Restart, atomicity, retention, and injection tests for Guardian's production replay store."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from guardian.token.persistent_replay import SQLiteReplayStore


class FrozenClock:
    def __init__(self, epoch: int) -> None:
        self.epoch = epoch

    def __call__(self) -> int:
        return self.epoch

    def advance(self, seconds: int) -> None:
        self.epoch += seconds


def _store(path: Path, clock: FrozenClock, *, min_entries: int = 2) -> SQLiteReplayStore:
    return SQLiteReplayStore(path, min_entries=min_entries, window_seconds=10, clock=clock)


def test_spent_jti_survives_store_reconstruction(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    clock = FrozenClock(100)
    assert _store(path, clock).claim("spent-before-restart", expires_at=105)

    restarted = _store(path, clock)
    assert not restarted.claim("spent-before-restart", expires_at=105)
    assert restarted.is_spent("spent-before-restart")


def test_two_store_instances_racing_one_jti_produce_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    clock = FrozenClock(100)
    stores = [_store(path, clock), _store(path, clock)]
    barrier = threading.Barrier(2)

    def claim(store: SQLiteReplayStore) -> bool:
        barrier.wait()
        return store.claim("same-jti", expires_at=105)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(claim, stores))
    assert sorted(outcomes) == [False, True]


def test_window_prevents_size_only_eviction_and_expired_excess_is_trimmed(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    clock = FrozenClock(100)
    store = _store(path, clock)
    assert store.claim("target", expires_at=105)
    for index in range(5):
        assert store.claim(f"flood-{index}", expires_at=105)

    assert len(store) == 6
    assert not store.claim("target", expires_at=105)

    clock.advance(11)
    # Claim triggers eviction. The two most recent old entries remain as the configured size floor,
    # and the new entry is added after that pass.
    assert store.claim("after-window", expires_at=120)
    assert len(store) == 3
    assert not store.is_spent("target")


def test_replayed_claim_still_performs_the_eviction_pass(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    clock = FrozenClock(100)
    store = _store(path, clock, min_entries=1)
    assert store.claim("old", expires_at=101)
    assert store.claim("retained", expires_at=101)

    clock.advance(11)
    assert not store.claim("retained", expires_at=101)
    assert not store.is_spent("old")
    assert len(store) == 1


def test_injected_path_and_clock_make_state_deterministic(tmp_path: Path) -> None:
    clock = FrozenClock(7)
    first_path = tmp_path / "first.sqlite3"
    second_path = tmp_path / "second.sqlite3"
    first = _store(first_path, clock)
    second = _store(second_path, clock)

    assert first.claim("isolated", expires_at=8)
    assert second.claim("isolated", expires_at=8)
    assert first_path.is_file()
    assert second_path.is_file()
