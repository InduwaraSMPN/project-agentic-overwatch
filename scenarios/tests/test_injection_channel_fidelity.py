r"""Every payload of every class survives its own delivery channel, byte for byte (M10 WS-2).

WHAT THIS PROVES, AND WHY IT IS OFFLINE
    Three of the four classes are delivered by writing the payload's exact bytes to a file the
    runner
    reads before the response starts; the fourth rides a shell's command line. Both are byte-moving
    paths, and a byte that does not arrive is an injection that was never delivered -- which is the
    v1 campaign's INJ-B result (0 of 150 bundles carried a payload in evidence; defect V3) and the
    reason the class's surface was rewritten to name the channel it actually uses.

    So this suite is the offline half of F-SC-04's payload-coverage check for INJ-A, INJ-C and
    INJ-D: for every pool-02 instance, the bytes the registry holds are the bytes the applier
    writes and the response reads. It needs no cluster, because `_deliver_runner_input` writes to a
    path the runner owns; that is the whole reason the class was moved onto this channel. INJ-B's
    half is a bound rather than a round trip, because its delivery runs a debug container in a live
    replica and cannot be exercised without one -- which is why its bound is stated as a proposed
    value to be VERIFIED in the P0-live stage, not asserted here as a measurement.

WHAT BREAKS IF THE CHANNELS CHANGE
    The round trip is the only thing standing between the registry text and the model's context, so
    a channel rewrite that re-encodes, normalises or truncates shows up here rather than as a
    silently undelivered payload in a sealed bundle. A payload that grows past the INJ-B bound is
    the same failure in the other direction: a command line the kernel, the Falco output field or
    the aggregator's excerpt cap could truncate.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from scenarios.attackers import content as content_registry  # noqa: E402
from scenarios.attackers import plan as planner  # noqa: E402
from scenarios.attackers.apply import (  # noqa: E402
    DirectoryInjectionChannels,
    KubectlClusterAdapter,
    OfflineAdapter,
    ingested_log_argv,
    ingested_log_cmdline,
)
from scenarios.attackers.marker import mark_payload, payload_marker  # noqa: E402

# The pool generation the v2 campaign draws from (D8). The v1 pools are exercised by the same tests
# for the same reason the v1 corpus is kept: a channel that cannot carry an old payload would make
# the known-bad replay's corpus unreadable.
POOL_GENERATIONS = ("01", "02")

# The classes delivered through the runner's file channels, and the pool-02 generation each must
# cover. INJ-B is the exception and is handled below.
RUNNER_INPUT_CLASSES = ("INJ-A", "INJ-C", "INJ-D")

# PROPOSED bound on the length of an INJ-B command line, in bytes (M10 WS-2, F-SC-04).
#
# Not a protocol constant and deliberately not one: it is a property of the delivery, not of the
# experiment, exactly as `STEP_MS`/`JITTER_MS` are the scenario's own rather than
# evaluation-protocol section 4's. It is set an order of magnitude above the longest command
# line the corpus can currently build (194 bytes for INJ-B-pool-02-001) and far below every
# bound in the
# delivery path that could truncate one: the kernel's 128 KiB per-argument limit, the aggregator's
# evidence-excerpt cap (evaluation-protocol section 4, 2904 characters), and the Kubernetes event
# and annotation limits. P0-live is where the real measurement belongs -- it reads the observed
# `proc.cmdline` Falco actually recorded for each pool-02 INJ-B payload (D5, ADR-119) and confirms
# the delivered length against this bound -- and this suite only proves the corpus fits inside it
# offline, which is what makes the P0-live number a check rather than a discovery.
MAX_CMDLINE_BYTES = 1024

SCENARIO_ID = "SCN-SIM-01"
SEED = 101
RUN_ID = "RUN-G0-FULL-SCN-SIM-01-INJ-A-101"


class _ContextRunner:
    """Answers the one command the delivery path issues: the kubeconfig context guard.

    `_deliver_runner_input` writes a file and stamps labels; it shells out only through `begin()`'s
    context check, which is the guard the applier refuses to proceed without. Answering it here
    keeps the round trip honest -- the same code path a live run takes, with the cluster call it
    does not need stubbed out.
    """

    def __init__(self, context: str = "kind-overwatch") -> None:
        self.context = context
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self, argv: tuple[str, ...], input_text: str | None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(tuple(argv), 0, self.context + "\n", "")


def _adapter(
    tmp_path: Path, run_id: str = RUN_ID
) -> tuple[KubectlClusterAdapter, DirectoryInjectionChannels]:
    config = tmp_path / "config"
    config.write_text("apiVersion: v1\n", encoding="utf-8")
    channel_dir = tmp_path / "channels"
    channel_dir.mkdir()
    channels = DirectoryInjectionChannels(
        prompt_input=channel_dir / "prompt-input.txt",
        role_manipulation=channel_dir / "role-manipulation.txt",
        parameter_manipulation=channel_dir / "parameter-manipulation.txt",
    )
    adapter = KubectlClusterAdapter(
        kubeconfig=config,
        context="kind-overwatch",
        cluster_cli="cluster-cli-test",
        runner=_ContextRunner(),
        injection_channels=channels,
    )
    adapter.begin(run_id)
    return adapter, channels


def _injection_event(injection_class: str, payload_id: str) -> dict:
    """A planned injection event re-pointed at ``payload_id``.

    Taken from a real plan rather than hand-built, so `detail.content_pool` -- the field that names
    the registry the payload came from, and the one the channel metadata and the M10 attribution
    both read -- is the manifest's own.
    """
    events = planner.plan_cell(SCENARIO_ID, injection_class, 101)
    event = next(item for item in events if item["kind"] == "injection")
    return {**event, "payload_id": payload_id}


@pytest.mark.parametrize("generation", POOL_GENERATIONS)
@pytest.mark.parametrize("injection_class", RUNNER_INPUT_CLASSES)
def test_every_pool_payload_round_trips_byte_exact_through_the_runner_channel(
    tmp_path: Path, injection_class: str, generation: str
) -> None:
    """The registry's bytes are the file's bytes, for every instance of the class's pool.

    ``_deliver_runner_input`` appends this cell's F-SC-01 marker on its own line, so the expectation
    is the registry text plus that marker -- and the assertion is still byte-exact, because the
    marker is the only thing the channel adds and it must add exactly that.
    """
    adapter, channels = _adapter(
        tmp_path, run_id=f"RUN-G0-FULL-{SCENARIO_ID}-{injection_class}-{SEED}"
    )
    pool = content_registry.load_pool(f"{injection_class}-pool-{generation}")
    path = channels.path_for(injection_class)
    marker = payload_marker(SCENARIO_ID, injection_class, SEED)
    for instance in pool.instances:
        event = _injection_event(injection_class, instance.payload_id)
        detail = adapter._deliver_runner_input(event, instance.text)

        delivered = path.read_bytes()
        expected = mark_payload(instance.text, marker)
        assert delivered == expected.encode("utf-8"), (
            f"{instance.payload_id}: the delivered bytes are not the registry text plus this "
            f"cell's marker ({len(delivered)} delivered, "
            f"{len(expected.encode('utf-8'))} expected)"
        )
        # The adjacent metadata is how the runner and the M10 attribution know WHICH payload
        # this is; a delivery whose bytes arrived without it would be unattributable.
        metadata = json.loads(path.with_suffix(path.suffix + ".json").read_text(encoding="utf-8"))
        assert metadata["payload_id"] == instance.payload_id
        assert metadata["injection_class"] == injection_class
        assert metadata["schema_version"] == "v1"
        assert instance.payload_id in detail


@pytest.mark.parametrize("injection_class", RUNNER_INPUT_CLASSES)
def test_every_class_draws_from_its_pool_02_generation(injection_class: str) -> None:
    """The manifests name pool-02, and every payload the grid can draw resolves in that pool.

    Coverage of the *class* is what the round trip above proves; this is the join that says the two
    are about the same material -- a manifest still naming pool-01 would leave the pool-02 payloads
    the v2 experiment needs sitting in the registry undelivered by any run, which is the defect
    (V25) the rotation was introduced to close.
    """
    pool_id = planner.load_manifest(SCENARIO_ID)["injection_points"][injection_class][
        "content_pool"
    ]
    assert pool_id == f"{injection_class}-pool-02", (
        f"{injection_class}: the manifest still names {pool_id}; the v2 campaign draws from the "
        "pool-02 generation (D8), and the v1 pools are kept only for the v1 corpus"
    )
    pool = content_registry.load_pool(pool_id)
    drawn = {
        event["payload_id"]
        for seed in planner.CANONICAL_SEEDS
        for event in planner.plan_cell(SCENARIO_ID, injection_class, seed)
        if event["kind"] == "injection"
    }
    assert drawn <= {instance.payload_id for instance in pool.instances}
    assert len(drawn) == len(planner.CANONICAL_SEEDS), (
        f"{injection_class}: the five seeds of the cell drew {len(drawn)} distinct payload(s)"
    )


@pytest.mark.parametrize("generation", POOL_GENERATIONS)
def test_every_inj_b_command_line_stays_under_the_proposed_bound(generation: str) -> None:
    """INJ-B's payload rides a command line, so the bound is a length check on the rendered line.

    The rendering is Falco's own: the process name, then every argument after argv[0] joined by
    single spaces, an empty argument included -- so each NUL in the payload becomes one space, which
    is why the bound is measured on the RENDERED line rather than on the payload text. Both pool
    generations are checked because the v1 payloads carry the control characters, the bidirectional
    overrides and the NUL padding the aggregator's normaliser families exist to handle, and those
    are the ones a truncation would silently mangle.
    """
    pool = content_registry.load_pool(f"INJ-B-pool-{generation}")
    marker = payload_marker(SCENARIO_ID, "INJ-B", SEED)
    for instance in pool.instances:
        rendered = ingested_log_cmdline(mark_payload(instance.text, marker))
        size = len(rendered.encode("utf-8"))
        assert size < MAX_CMDLINE_BYTES, (
            f"{instance.payload_id}: its command line is {size} bytes, at or over the proposed "
            f"{MAX_CMDLINE_BYTES}-byte bound. P0-live measures the delivered length; if the real "
            "one is over the bound, the payload has to be shortened rather than the bound raised, "
            "because a truncated command line is a partially delivered injection (defect V3)."
        )
        # The line is the payload plus the shell it rides behind plus the F-SC-01 marker, so the
        # bound has to hold for the WHOLE thing rather than for the payload alone.
        assert rendered == " ".join(ingested_log_argv(mark_payload(instance.text, marker)))
        assert instance.text.replace("\x00", " ") in rendered or "\x00" not in instance.text
        assert marker in rendered


def test_the_inj_b_bound_leaves_headroom_over_the_corpus() -> None:
    """The bound is a bound, not a number copied from today's longest payload.

    Asserted as a ratio rather than as an absolute so it cannot rot into "the bound equals the
    largest instance": a pool that grew by a factor would still fit a bound that had been set from
    the old maximum, and the check that is supposed to catch an un-deliverable payload would pass.
    Measured over INJ-B alone, which is the only class that reaches `ingested_log_cmdline`: the
    other three are delivered as file bytes and have no command line to bound.
    """
    longest = max(
        len(
            ingested_log_cmdline(
                mark_payload(instance.text, payload_marker(SCENARIO_ID, "INJ-B", SEED))
            ).encode("utf-8")
        )
        for generation in POOL_GENERATIONS
        for instance in content_registry.load_pool(f"INJ-B-pool-{generation}").instances
    )
    assert longest * 4 < MAX_CMDLINE_BYTES, (
        f"the longest INJ-B command line in the corpus is {longest} bytes, so the "
        f"{MAX_CMDLINE_BYTES}-byte bound is under 4x headroom; a bound that tight turns an"
        " ordinary payload edit into a delivery failure"
    )


def test_the_offline_adapter_is_not_a_delivery() -> None:
    """``OfflineAdapter`` writes nothing, so it is never mistaken for a covered channel.

    Stated as a test because the round-trip suite's value depends on `_deliver_runner_input` being
    the only writer it trusts: an adapter that recorded `applied` without writing a byte is the v1
    INJ-B failure exactly (ADR-105: the delivery was logged applied while no source ever saw the
    payload).
    """
    adapter = OfflineAdapter()
    assert adapter.apply_event({"injection_class": "INJ-A"}, "payload") == (
        "offline: no cluster command executed"
    )
