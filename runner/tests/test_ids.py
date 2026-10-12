r"""The identifier grammar round-trips over the whole grid and rejects malformed shapes by name.

The reason the grammar exists rather than a hyphen split is a claim -- that a naive split produces
plausible garbage -- so this suite proves it: :func:`test_naive_hyphen_split_disagrees` is the
reason for the grammar living in the test suite rather than only in the module docstring.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from runner.grid import SEEDS, base_cells  # noqa: E402
from runner.ids import (  # noqa: E402
    ARM_TOKENS,
    BaselineId,
    IdError,
    RunId,
    cell_key,
    format_baseline_id,
    format_run_id,
    parse_baseline_id,
    parse_run_id,
)


def test_run_id_round_trips_over_the_whole_grid() -> None:
    """Every arm x base-cell x seed formats to an identifier that parses back to the same RunId."""
    for arm in ARM_TOKENS:
        for cell in base_cells():
            for seed in SEEDS:
                run = RunId(arm, cell.scenario_id, cell.injection_condition, seed)
                text = format_run_id(run)
                assert parse_run_id(text) == run, text


def test_baseline_id_round_trips() -> None:
    for seed in SEEDS:
        baseline = BaselineId("LOAD-STEADY", seed)
        assert parse_baseline_id(format_baseline_id(baseline)) == baseline


def test_rerun_suffix_parses_and_strips() -> None:
    """The -R<n> suffix parses to an attempt and cell_key strips it to the unsuffixed identifier."""
    text = "RUN-G0-FULL-SCN-CVE-04-INJ-A-101-R2"
    parsed = parse_run_id(text)
    assert parsed.attempt == 2
    assert cell_key(text) == "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    assert cell_key("BASE-LOAD-STEADY-103-R3") == "BASE-LOAD-STEADY-103"


def test_naive_hyphen_split_disagrees_with_the_grammar() -> None:
    """A hyphen split gives nine pieces for four components, so it cannot recover them.

    This is the whole reason the parser is a grammar. If a future edit replaced the grammar with a
    split, this test would be the thing that fails.
    """
    text = "RUN-G0-FULL-SCN-CVE-03-INJ-A-101"
    assert len(text.split("-")) == 9
    parsed = parse_run_id(text)
    assert (parsed.condition, parsed.scenario_id, parsed.injection_condition, parsed.seed) == (
        "G0-FULL",
        "SCN-CVE-03",
        "INJ-A",
        101,
    )


@pytest.mark.parametrize(
    "bad",
    [
        "RUN-BOGUS-SCN-CVE-03-INJ-A-101",  # unknown arm
        "RUN-G0-FULL-SCN-XXX-03-INJ-A-101",  # unknown scenario class
        "RUN-G0-FULL-SCN-CVE-03-INJ-Z-101",  # unknown injection condition
        "RUN-G0-FULL-SCN-CVE-03-INJ-A-10",  # seed not three digits
        "RUN-G0-FULL-SCN-CVE-03-INJ-A-101-R0",  # rerun attempt must be >= 1
        "G0-FULL-SCN-CVE-03-INJ-A-101",  # missing RUN- prefix
    ],
)
def test_malformed_run_ids_are_rejected(bad: str) -> None:
    with pytest.raises(IdError):
        parse_run_id(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "BASE-STEADY-101",  # load profile must start LOAD-
        "BASE-LOAD-STEADY-10",  # seed not three digits
        "BASE-LOAD-lower-101",  # profile segments are upper-alnum, letter-led
    ],
)
def test_malformed_baseline_ids_are_rejected(bad: str) -> None:
    with pytest.raises(IdError):
        parse_baseline_id(bad)


def test_cell_key_refuses_a_non_identifier() -> None:
    with pytest.raises(IdError):
        cell_key("not-an-identifier")


def test_format_rejects_an_out_of_vocabulary_component() -> None:
    with pytest.raises(IdError):
        format_run_id(RunId("NOT-AN-ARM", "SCN-CVE-04", "INJ-A", 101))
    with pytest.raises(IdError):
        format_run_id(RunId("G0-FULL", "SCN-CVE-04", "INJ-Z", 101))
