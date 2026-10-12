"""Regression: :func:`runner.fidelity.agents._last_runtime_task` must terminate.

The scan walks a model context looking for ``"capability_scope"``, and the nearest ``{`` before an
occurrence does not always ENCLOSE it: a prompt that names the field in prose, or a mention after an
unrelated object, puts the key outside any object, so the matching ``}`` lands before the key. The
function used to resume from that ``}`` -- ``search_from = closed_at + 1`` -- which re-finds the
same occurrence, re-scans the same braces and re-parses the same object for ever.

That is not a theoretical hang. The v1 bundle ``RUN-G1-LOGONLY-SCN-SIM-02-INJ-D-101`` carries such
a context, and it stalled the known-bad replay over the v1 corpus for hours where the per-bundle
cost is otherwise about 0.1s (measured: one bundle timed out at 60s; the full corpus, linear, takes
under two minutes). A check that does not terminate is a check that cannot report, so the defect was
invisible in the verdict and visible only as a replay that never finished.

Every case here runs under a deadline, in a daemon thread, so that a REGRESSION FAILS THE TEST
instead of hanging CI. A test that can only fail by hanging is a test that stops the suite rather
than reporting, which is the failure mode this file exists to prevent.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from runner.fidelity.agents import _last_runtime_task

#: Generous enough that a loaded CI runner does not report a false failure, short enough that a
#: regression costs the suite seconds rather than the whole job.
DEADLINE_SECONDS = 10.0


def _call_with_deadline(function: Callable[[str], Any], argument: str) -> tuple[bool, Any]:
    """Run ``function(argument)`` on a daemon thread; return ``(finished, result)``.

    A daemon thread cannot be killed, so a hung call is left behind rather than joined -- which is
    safe here precisely because the process exits when the suite does, and because the assertion
    that reads ``finished`` fails the test in the meantime.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        box["result"] = function(argument)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(DEADLINE_SECONDS)
    if thread.is_alive():
        return False, None
    return True, box.get("result")


def test_the_field_named_in_prose_after_an_object_terminates() -> None:
    """The regression. The key follows a complete object that does not contain it."""
    finished, result = _call_with_deadline(
        _last_runtime_task,
        '{"other": 1} then the field "capability_scope" is named',
    )
    assert finished, "the scan did not terminate: the infinite loop is back"
    assert result is None, "no object encloses the key, so no frame should be reported"


def test_the_field_named_in_prose_before_any_object_terminates() -> None:
    finished, result = _call_with_deadline(
        _last_runtime_task,
        'the field "capability_scope" is named, then {"other": 1}',
    )
    assert finished, "the scan did not terminate"
    assert result is None


def test_a_frame_is_still_found_after_an_unrelated_object() -> None:
    """The fix must not stop the scan early: a later, real frame is still reached."""
    finished, result = _call_with_deadline(
        _last_runtime_task,
        '{"a": 1} and "capability_scope" in prose, then {"capability_scope": {"scope": "x"}}',
    )
    assert finished, "the scan did not terminate"
    assert result == {"capability_scope": {"scope": "x"}}


def test_an_enclosing_frame_is_returned() -> None:
    finished, result = _call_with_deadline(_last_runtime_task, '{"capability_scope": null}')
    assert finished
    assert result == {"capability_scope": None}


def test_the_newest_frame_wins() -> None:
    """A context carrying two frames reports the last one, which is what "newest" means here."""
    finished, result = _call_with_deadline(
        _last_runtime_task,
        '{"capability_scope": {"n": 1}} {"capability_scope": {"n": 2}}',
    )
    assert finished
    assert result == {"capability_scope": {"n": 2}}


def test_an_unbalanced_frame_terminates() -> None:
    """A truncated context has no matching brace; the scan must return rather than run on."""
    finished, result = _call_with_deadline(_last_runtime_task, '{"capability_scope": {"a": 1')
    assert finished, "the scan did not terminate on an unbalanced frame"
    assert result is None


def test_a_non_string_context_is_refused() -> None:
    assert _last_runtime_task(None) is None
    assert _last_runtime_task(17) is None
