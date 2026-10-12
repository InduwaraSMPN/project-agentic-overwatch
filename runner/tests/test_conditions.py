r"""The condition-flag matrix: each arm one property from the shared arm, G2 the named exception.

This is the T-13 obligation extended to all six arms (ADR-040): the flags are set from the arm token
and nowhere else, each arm removes exactly one property from the shared full-architecture arm, and
the G2 two-difference case is encoded by name so any *other* second difference fails.
"""

import sys
from dataclasses import fields
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from runner.conditions import CONDITION_FLAGS, G2_EXCEPTION, flags_for  # noqa: E402
from runner.ids import CANONICAL_ARMS  # noqa: E402


def test_the_table_covers_exactly_the_six_canonical_arms() -> None:
    assert set(CONDITION_FLAGS) == set(CANONICAL_ARMS)


def test_each_arm_differs_from_the_shared_arm_in_exactly_one_property_except_g2() -> None:
    """§3.5.4's 'each configuration removes exactly one property', as an assertion over the table.

    G2-SHAREDCRED is the documented two-difference exception (guardian_mode AND the netpol overlay),
    the non-orthogonality ADR-024 records. The test names it; any OTHER arm with two differences
    fails, which is the defect this test exists for.
    """
    shared = CONDITION_FLAGS["G0-FULL"]
    columns = [f.name for f in fields(shared)]
    for arm, flags in CONDITION_FLAGS.items():
        if arm == "G0-FULL":
            continue
        differences = [c for c in columns if getattr(flags, c) != getattr(shared, c)]
        if arm == G2_EXCEPTION:
            assert len(differences) == 2, (
                f"{arm} should differ in two columns, differs in {differences}"
            )
            assert set(differences) == {"guardian_mode", "netpol_overlay"}
        else:
            assert len(differences) == 1, (
                f"{arm} must remove exactly one property; differs in {differences}"
            )


def test_g3_routes_to_the_monitor_not_the_guardian() -> None:
    """G3 removes a Monitor property, so it runs under full mediation with quoting off."""
    g3 = flags_for("G3-UNQUOTED")
    assert g3.guardian_mode == "G0-FULL"  # NOT G3-UNQUOTED; config.py rejects that
    assert g3.aggregator_quoting is False


def test_only_g2_opens_the_netpol_overlay() -> None:
    for arm, flags in CONDITION_FLAGS.items():
        assert flags.netpol_overlay == ("opened" if arm == "G2-SHAREDCRED" else "default-deny")


def test_flags_for_rejects_a_non_canonical_arm() -> None:
    with pytest.raises(KeyError):
        flags_for("S1-HIER")  # an alias, not a separate arm
    with pytest.raises(KeyError):
        flags_for("BOGUS")
