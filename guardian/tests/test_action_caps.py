r"""The two action caps: the values are the protocol's, and the per-token bound holds at the store.

WHY A MIRROR TEST EXISTS AT ALL
-------------------------------
``docs/plans/M10-implementation-plan.md`` §2 principle P3 and
  ``.agents/rules/00-source-of-truth.md``
allow a number to appear in exactly one place plus a *checked* copy, and the check is the whole of
what makes the copy legal. :mod:`guardian.app.limits` carries ``ACTION_CAP_PER_TOKEN`` and
``ACTION_CAP_PER_RUN`` as a checked copy of ``docs/protocols/security-policy.md`` §2.1, and this
  file
is that check -- the same arrangement ``monitor/tests/test_limits_match_protocol.py`` and
``analysis/tests/test_gate_constants_match_protocol.py`` use for their blocks. The mirror is
deliberately **not** configuration, the way the token TTL and the replay bounds are
(``guardian/app/config.py``): those five are tunable and a runner reads §2 to supply them, while a
Guardian's own blast radius is not something a deployment should be able to set. The reasoning is
argued at length in :mod:`guardian.app.limits`; what matters here is that the two numbers are
compared against the protocol on every CI run rather than trusted.

WHY THE PER-TOKEN CAP IS PROVED HERE AND NOT IN THE ADVERSARIAL SUITE
---------------------------------------------------------------------
Because it is **unreachable through ``POST /v1/actions``**, and a case that cannot make a decision
does not belong in a file whose every case must assert one --
``guardian/tests/test_suite_integrity.py``
enforces that, and enforcing it is right. The reason is structural rather than incidental: a ``jti``
is single-use, so the second presentation of a capability is refused by the replay cache as
``replay.jti-spent`` before the caps are consulted, and the per-token bound of 8 can only be reached
by reserving one capability nine times. It is a *second line* behind single use, and this is the
case
that says the second line is real rather than decorative: a reserver that ignored the per-token cap
would pass every case in the adversarial suite, because nothing there can drive it.

NOTHING HERE NEEDS A CLUSTER, A CLOCK, OR A RUN
-----------------------------------------------
The store is SQLite in a temporary file, opened with the same ``BEGIN IMMEDIATE`` discipline
production uses, and a "capability" here is a string. No policy engine, no token issuer and no audit
chain are involved, so none of the two cases can be made to pass by an unrelated part of the
Guardian
answering differently.
"""

import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.limits import (  # noqa: E402
    ACTION_CAP_PER_RUN,
    ACTION_CAP_PER_TOKEN,
    MIRRORED_KEYS,
    PROTOCOL_ANCHOR_PATTERN,
    PROTOCOL_RELATIVE_PATH,
    PROTOCOL_SECTION_HEADING,
    SQLiteActionCapReserver,
    as_protocol_mapping,
)

# The run key, spelled once. It is a plain string here: the store keys on whatever it is handed, and
# `guardian/app/mediation.py` is where a run id becomes the key (its own configured run id whenever
# it pinned one, which is what keeps an attacker-settable request field out of the cap arithmetic).
RUN_KEY = "RUN-G0-FULL-SCN01-INJA-S07"
# Two capabilities, so a case can show that the per-token bound is per capability and not global.
OTHER_TOKEN_KEY = "jti-suite-0002"  # noqa: S105 - fake test token, not a real credential


def _protocol_section() -> str:
    """Return security-policy.md §2.1's body, whitespace-normalised, or fail loudly.

    The heading is an anchor rather than a line number for the reason ``scripts/security_params.py``
    gives for its own extraction of §2: prose gets reflowed and retitled, and a pattern that stops
    matching is a loud failure rather than a stale number being enforced.
    """
    text = (REPO_ROOT / PROTOCOL_RELATIVE_PATH).read_text(encoding="utf-8")
    start = text.find(PROTOCOL_SECTION_HEADING)
    assert start >= 0, (
        f"{PROTOCOL_RELATIVE_PATH} has no section headed {PROTOCOL_SECTION_HEADING!r}. The two caps "  # noqa: E501 - message
        "are mirrored from that section, so an extraction that cannot find it must fail rather than "  # noqa: E501 - message
        "fall back to the copy"
    )
    end = text.find("\n## ", start + len(PROTOCOL_SECTION_HEADING))
    return " ".join(text[start : end if end > 0 else len(text)].split())


def test_the_caps_are_the_ones_security_policy_section_2_1_names() -> None:
    """The mirror holds, key by key, against the section that owns the numbers.

    Both directions matter. A protocol edit that does not reach this module leaves the Guardian
    enforcing a bound no document describes; a module edit that does not reach the protocol leaves
    the
    Guardian enforcing something the study never declared. Either is a finding about the artefact,
    and
    the protocol is what is right when the two disagree.
    """
    section = _protocol_section()
    mirrored = as_protocol_mapping()
    assert set(mirrored) == set(MIRRORED_KEYS), (
        f"as_protocol_mapping() publishes {sorted(mirrored)}, MIRRORED_KEYS names {sorted(MIRRORED_KEYS)}"  # noqa: E501 - message
    )
    for key in MIRRORED_KEYS:
        match = re.search(PROTOCOL_ANCHOR_PATTERN.format(key=key), section)
        assert match is not None, (
            f"cannot read action_cap_{key} from {PROTOCOL_RELATIVE_PATH} §2.1. The value is owned "
            "there and is mirrored, never invented; re-anchor PROTOCOL_ANCHOR_PATTERN in "
            "guardian/app/limits.py against the current wording"
        )
        assert int(match.group(1)) == mirrored[key], (
            f"action_cap_{key} is {mirrored[key]} in guardian/app/limits.py and "
            f"{match.group(1)} in {PROTOCOL_RELATIVE_PATH} §2.1. The protocol owns the value; the "
            "mirror follows it, and after the v2.0 freeze changing it here is a logged hotfix ADR"
        )


def test_a_cap_refused_because_of_the_run_reports_a_full_run_and_an_untouched_capability() -> None:
    """A refusal is attributable to *which* budget ran out, from the counters alone.

    The two dimensions are separate rows rather than one counter for a reason a reader of a sealed
    bundle needs: "this agent was bounded by the run's budget" and "this capability was bounded by
    its own" are different findings about different agents, and a single number could not tell them
    apart. So this case spends the run's cap entirely, confirms the refusal says so, and confirms
    the
    refused capability's own counters stayed at zero -- which is the all-or-nothing reserve, and the
    property that a request refused for someone else's budget is not itself charged for it.
    """
    with tempfile.TemporaryDirectory() as directory:
        caps = SQLiteActionCapReserver(Path(directory) / "caps.sqlite3")
        for index in range(ACTION_CAP_PER_RUN):
            reservation = caps.reserve(run_key=RUN_KEY, token_key=f"jti-{index:04d}")
            assert reservation.granted, index
            caps.settle(reservation, consumed=True)

        refused = caps.reserve(run_key=RUN_KEY, token_key="jti-over")  # noqa: S106 - fake test token, not a real credential
        assert refused.granted is False
        assert refused.counters.run_reserved + refused.counters.run_consumed == ACTION_CAP_PER_RUN
        assert refused.counters.token_reserved == 0
        assert refused.counters.token_consumed == 0
        # A refusal is not a settlement: the store must not have moved, or the next request would be
        # refused by a budget this one had already spent.
        assert caps.counters(run_key=RUN_KEY, token_key="jti-over") == refused.counters  # noqa: S106 - fake test token, not a real credential


def test_one_capability_cannot_reserve_more_than_the_per_token_cap() -> None:
    """The per-token bound, at the one place it is reachable.

    **Why this is not in the adversarial suite.** Every case in ``test_adversarial_*.py`` must
    assert
    a decision, and a ninth reservation of one ``jti`` never reaches a decision: the replay cache
    refuses the second presentation of a capability as ``replay.jti-spent`` long before the caps are
    consulted. So the bound that ``docs/protocols/security-policy.md`` §2.1 puts on "one
    capability's
    blast radius" would otherwise be enforced by code with no case behind it, and a reserver that
    ignored it entirely would pass the whole suite.

    The count is the protocol's, and the control is the point: the other capability is unaffected,
    so
    what is being bounded is one capability rather than the run.
    """
    with tempfile.TemporaryDirectory() as directory:
        caps = SQLiteActionCapReserver(Path(directory) / "caps.sqlite3")
        for index in range(ACTION_CAP_PER_TOKEN):
            reservation = caps.reserve(run_key=RUN_KEY, token_key="jti-suite-0001")  # noqa: S106 - fake test token, not a real credential
            assert reservation.granted is True, (
                f"reservation {index + 1} of {ACTION_CAP_PER_TOKEN} was refused, so the per-token cap "  # noqa: E501 - message
                "is not the protocol's value or is being tested against the wrong column"
            )

        over = caps.reserve(run_key=RUN_KEY, token_key="jti-suite-0001")  # noqa: S106 - fake test token, not a real credential
        assert over.granted is False, (
            "one capability reserved more slots than the per-token cap allows. A cap the pipeline "
            "cannot reach is a cap with no evidence behind it, and this is the only case that drives it"  # noqa: E501 - message
        )
        assert over.counters.token_reserved == ACTION_CAP_PER_TOKEN
        assert over.counters.run_reserved == ACTION_CAP_PER_TOKEN, (
            "the per-token refusal took a run slot as well. The reserve is all-or-nothing across both "  # noqa: E501 - message
            f"dimensions: run_reserved is {over.counters.run_reserved}"
        )
        # The control: a different capability, in the same run, is not affected by the first's cap.
        other = caps.reserve(run_key=RUN_KEY, token_key=OTHER_TOKEN_KEY)
        assert other.granted is True, (
            "one capability exhausting its own cap refused a second, unrelated capability, so the "
            "per-token bound is being applied to the run as well"
        )
        assert other.counters.run_reserved + other.counters.run_consumed == ACTION_CAP_PER_TOKEN + 1
