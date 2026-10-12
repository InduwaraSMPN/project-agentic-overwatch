r"""The ``manifest.json`` schema of ``data-management.md`` §2, as a typed record with one null-set.

WHAT THIS MODULE OWNS
-----------------------
``data-management.md`` §2 lists every field a run manifest carries and states two rules a validator
must enforce over them: the **twelve-field null set** a framework-off baseline blanks, and the
**two-directional** check that reads it -- a baseline carrying a non-null value in any of the twelve
is rejected, and a framework-on run carrying a null in any of the eleven that are not
``baseline_run_id`` is rejected too. This module carries the field list and that null set as single
literals, so the sealer and the three validator entry points read one definition rather than three
that can drift.

THE M10 FIELDS, AND WHY EVERY ONE OF THEM DEFAULTS
--------------------------------------------------
``data-management.md`` §2's M10 subsection adds nine more fields (ADRs 120, 123, 131, 135, 136):
``freeze_tag``, ``instrument_digest``, ``answered_model``, ``system_fingerprints``,
``fidelity_summary``, ``guardian_restarted``, ``environment_lock_sha256`` and the two token
expiries.
Every one of them **defaults**, and that is forced rather than convenient.

A manifest is read by three readers that arrive at different times: the sealer that wrote it, the
validators that ran over a corpus months later, and ``analysis/render.py`` re-reading it to build
the
dissertation's tables. ``runs/CAMP-20260914-campaign/`` holds 755 sealed bundles whose manifests
have
none of these keys, and the v1 corpus is kept read-only as evidence (D9). A strict field set would
make every one of those bundles unreadable, which is a far worse outcome than a v1 bundle reading
``None`` for a field that did not exist when it was written. So: optional on the way IN, always
emitted on the way OUT -- the same asymmetry ``runner/campaign.py`` uses for the campaign manifest's
``freeze_tag``, and for the same reason (a tracked manifest cannot carry its own commit's hash, and
a
field that appears only when some code version happened to set it makes the schema depend on the
writer).

The fields are NOT in :data:`BASELINE_NULL_FIELDS`. A baseline blanks the twelve §2 names; these
nine
are instrumentation of a run's provenance, and the provenance facts that do not apply to a baseline
(there is no model, no freeze tag binding a baseline, no token) are already ``None`` by their own
defaults. Adding them to the null set would make the two-directional check reject a framework-on run
for a missing ``g2_token_expiry`` in a non-G2 arm, which is not a defect: no G2 credential was
minted,
so there is no expiry to record.

THE RQ4 PREDICATE IS ONE NAMED FUNCTION (conflict M6-C2)
----------------------------------------------------------
``baseline_run_id`` keeps a narrower rule than the other eleven: null on a baseline, and non-null on
a framework-on **RQ4** run only. But "a framework-on RQ4 run" is not a decidable predicate anywhere
in the protocol -- §2 justifies the exclusion by enumerating the five ablated arms whose runs would
"name a baseline nothing ever reads", and the complement of that enumeration is the shared
full-architecture arm. So the intended predicate is ``condition == G0-FULL``, and the validator must
decide it 750 times. This module implements it as :func:`requires_baseline_pairing`, one line behind
one name, so that if the supervisor rules otherwise exactly one line changes. Conflict M6-C2 records
that this is the plan's proposal, owed to a protocol amendment at T6.3, not a settled rule.

SERIALISATION IS DETERMINISTIC
--------------------------------
The manifest is hashed into ``seal.json``, so its bytes must be a function of its content alone.
:func:`to_canonical_bytes` uses the repository's canonical JSON -- ``sort_keys=True``,
``separators=(",", ":")``, ``ensure_ascii=True``, ``allow_nan=False`` -- the same four arguments
``monitor/aggregator/models.py``, ``guardian/audit/canonical.py`` and ``agents/registry/digest.py``
use, so the manifest hash is reproducible on any machine.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The seal (T-15) and every validator entry point (T-23). A field added to §2 without a line here is a
field the sealer does not write; a line here without a §2 field is a manifest the validator rejects.
ADR-039.
"""

import json
from dataclasses import dataclass, fields
from typing import Any, Final

from runner.ids import INJECTION_CONDITIONS

__all__ = (
    "BASELINE_NULL_FIELDS",
    "FRAMEWORK_ON_REQUIRED_NON_NULL",
    "HOST_FIELDS",
    "MANIFEST_FIELDS",
    "M10_FIELDS",
    "SCHEMA_VERSION",
    "ManifestError",
    "RunManifest",
    "requires_baseline_pairing",
    "to_canonical_bytes",
)

SCHEMA_VERSION: Final = "v1"

# The manifest field set, data-management.md §2, in the order §2 lists them. `host` is a nested
# object with its own three keys; `<STUDY>` is absent, dropped at M0 closeout with the identifier
# component (ADR-008).
MANIFEST_FIELDS: Final[tuple[str, ...]] = (
    "run_id",
    "campaign_id",
    "condition",
    "scenario_id",
    "injection_condition",
    "seed",
    "rerun_of",
    "is_baseline",
    "baseline_run_id",
    "load_profile_id",
    "started_at",
    "ended_at",
    "git_commit",
    "versions_env_sha256",
    "litellm_config_sha256",
    "model_alias",
    "model_provider_string",
    "prompt_registry_sha256",
    "tool_registry_sha256",
    "graph_id",
    "guardian_mode",
    "aggregator_quoting",
    "netpol_overlay",
    "shared_credential_exercised",
    "host",
    "schema_version",
)

# The M10 fields, data-management.md §2's M10 subsection (ADRs 120, 123, 131, 135, 136). Appended to
# :data:`MANIFEST_FIELDS` below rather than spliced into it, because they are a different generation
# of
# the schema: the twenty-six above are what v1 wrote and what the v1 corpus holds, and the nine
# below are what v2 adds. Keeping the two lists separate is what makes "which of these did v1 know
# about?" a question this file can answer, which is the question the defaults below exist for.
M10_FIELDS: Final[tuple[str, ...]] = (
    # The freeze tag NAME, never a commit hash (ADR-136): this file is committed in the very commit
    # the tag names, so a hash written into it would name the previous one.
    "freeze_tag",
    # The P6 instrument digest at HEAD, which is what F-RN-02 compares across a corpus.
    "instrument_digest",
    # The provider-returned model, which is NOT the alias: a gateway that echoes the requested name
    # returns the alias by construction (V20), so recording only the alias records the one string
    # that
    # cannot go stale (D10).
    "answered_model",
    # The distinct system_fingerprints seen, sorted. Advisory under D10 (the field is deprecated
    # upstream), and possibly empty: a provider that sends none is a fact, not a failure.
    "system_fingerprints",
    # A copy of fidelity.json's `summary`, so a reader of the manifest alone can see the per-class
    # verdict without opening the sealed report.
    "fidelity_summary",
    # Whether the Guardian workload restarted inside the window (ADR-132). A bool with no default in
    # spirit: `False` is asserted by the runner that read resources.csv, and `None` would be the
    # honest "not measured", which the runner never leaves for a live run.
    "guardian_restarted",
    # The environment lock digest, so a corpus can be tied to one reproducible dependency set
    # (ADR-135). None until WS-7 lands the hashed lock.
    "environment_lock_sha256",
    # The two per-run credential expiries (ADR-128 for the control plane, ADR-131 for G2), ISO-8601
    # UTC. Both None in arms where no such credential was minted, which is why they are not in the
    # baseline null set and not in the framework-on non-null set.
    "control_plane_token_expiry",
    "g2_token_expiry",
)

# The full set this module writes, in §2's order with the M10 fields appended: the schema_version
# stays last because it is the last §2 name, and appending after it would put a v2 field outside the
# group §2 enumerates. `schema_version` is itself unchanged at "v1" -- the nine fields are all
# optional, so no reader has to branch on it, and bumping it would make every v1 bundle look
# structurally invalid for the sake of an additive change.
_ALL_FIELDS: Final[tuple[str, ...]] = (*MANIFEST_FIELDS, *M10_FIELDS)

HOST_FIELDS: Final[tuple[str, ...]] = ("os", "wsl_kernel", "docker")

# The twelve fields a framework-off baseline blanks (data-management.md §2, "the baseline null-field
# set ... this is the whole list"). A baseline carrying a non-null value in any of these is
# rejected.
BASELINE_NULL_FIELDS: Final[tuple[str, ...]] = (
    "condition",
    "scenario_id",
    "injection_condition",
    "graph_id",
    "guardian_mode",
    "aggregator_quoting",
    "netpol_overlay",
    "shared_credential_exercised",
    "prompt_registry_sha256",
    "tool_registry_sha256",
    "model_alias",
    "model_provider_string",
    "litellm_config_sha256",
    "baseline_run_id",
)

# The other direction: a framework-on run must carry a non-null value in each of the twelve EXCEPT
# baseline_run_id, which keeps its own narrower rule (null unless the run is an RQ4 pairing run).
# The
# asymmetry is the whole of why the positive fixture the DoD demands -- a framework-on run on an
# ablated arm with a null baseline_run_id -- must be accepted rather than caught by a naive
# symmetric
# check.
FRAMEWORK_ON_REQUIRED_NON_NULL: Final[tuple[str, ...]] = tuple(
    field for field in BASELINE_NULL_FIELDS if field != "baseline_run_id"
)

# The canonical shared full-architecture arm. A framework-on run on this arm is the RQ4 pairing run;
# every other (ablated) arm's run legitimately carries a null baseline_run_id.
_RQ4_ARM: Final = "G0-FULL"


class ManifestError(Exception):
    """A manifest is structurally malformed (a *rule* violation belongs to validate.py)."""


@dataclass(frozen=True)
class RunManifest:
    """A run manifest. Every §2 field is present; a framework-off baseline blanks the twelve.

    This is the structural record. The *rules* over it -- the two-directional null check, the
    identifier-versus-field comparison, the pairing coverage -- live in runner/validate.py, so a
    malformed record and an invalid campaign are two different failures with two different owners.

    The nine M10 fields default, so a v1 bundle's manifest -- which has none of the keys -- is
    exactly
    this dataclass with seven ``None``s, a ``False`` and one empty tuple. That is the whole of why
    they are optional: see the module docstring.
    """

    run_id: str
    campaign_id: str
    condition: str | None
    scenario_id: str | None
    injection_condition: str | None
    seed: int
    rerun_of: str | None
    is_baseline: bool
    baseline_run_id: str | None
    load_profile_id: str
    started_at: str
    ended_at: str
    git_commit: str
    versions_env_sha256: str
    litellm_config_sha256: str | None
    model_alias: str | None
    model_provider_string: str | None
    prompt_registry_sha256: str | None
    tool_registry_sha256: str | None
    graph_id: str | None
    guardian_mode: str | None
    aggregator_quoting: bool | None
    netpol_overlay: str | None
    shared_credential_exercised: bool | None
    host: dict[str, str]
    schema_version: str = SCHEMA_VERSION
    # --- the M10 fields (data-management §2, ADRs 120/123/131/135/136)
    # -----------------------------
    freeze_tag: str | None = None
    instrument_digest: str | None = None
    answered_model: str | None = None
    system_fingerprints: tuple[str, ...] = ()
    fidelity_summary: dict[str, dict[str, int]] | None = None
    guardian_restarted: bool = False
    environment_lock_sha256: str | None = None
    control_plane_token_expiry: str | None = None
    g2_token_expiry: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """A plain dict in §2 field order, for serialisation.

        ``system_fingerprints`` is emitted as a sorted LIST, not as the tuple it is held as: the
        canonical-JSON writer would turn a tuple into a list anyway, and doing it here means the
        value
        in the sealed bytes and the value in memory agree -- so a byte-compare of two manifests is a
        comparison of their content rather than of Python's container choices. Sorted because the
        field is a SET of distinct fingerprints and the manifest's bytes must be a function of its
        content alone.
        """
        payload: dict[str, Any] = {}
        for field_ in fields(self):
            value = getattr(self, field_.name)
            if field_.name == "system_fingerprints":
                payload[field_.name] = sorted(value)
            else:
                payload[field_.name] = value
        return payload


def requires_baseline_pairing(condition: str | None) -> bool:
    """Whether a framework-on run on this arm must carry a non-null ``baseline_run_id``.

    The M6-C2 predicate, behind one name: the shared full-architecture arm G0-FULL is the RQ4
    pairing arm, and every ablated arm's run legitimately names no baseline. If the supervisor rules
    the predicate differently at T6.3, this one line changes and nothing else does.
    """
    return condition == _RQ4_ARM


def to_canonical_bytes(manifest: RunManifest) -> bytes:
    """Serialise a manifest to the repository's canonical JSON, for hashing into seal.json."""
    return json.dumps(
        manifest.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def from_dict(payload: dict[str, Any]) -> RunManifest:
    """Build a RunManifest from a parsed manifest.json, checking only that the field set is exact.

    Structural check only -- an unknown key or a missing one is a malformed manifest. Everything
    about whether the *values* are consistent (the null set, the identifier match) is validate.py's.

    The M10 fields are the one exception to "exact", and the exception is documented in the module
    docstring: each of the nine is **optional on read** and **always written**. A missing one takes
    its
    default; an unknown one is still a malformed manifest, because "I do not recognise this key" is
    a
    different failure from "this key is old" and the two must not be confused -- a v2 reader that
    silently ignored an unknown field would read a manifest written by a v3 runner as if it were
    complete.
    """
    keys = set(payload)
    expected = set(_ALL_FIELDS)
    unexpected = keys - expected
    if unexpected:
        raise ManifestError(
            f"manifest carries unknown field(s) {sorted(unexpected)}; the §2 schema is "
            f"{sorted(MANIFEST_FIELDS)} plus the M10 fields {sorted(M10_FIELDS)}"
        )
    missing = set(MANIFEST_FIELDS) - keys
    if missing:
        raise ManifestError(
            f"manifest is missing required §2 field(s) {sorted(missing)}; every §2 field is "
            "required "
            "and only the M10 fields default"
        )
    if not isinstance(payload["host"], dict) or set(payload["host"]) != set(HOST_FIELDS):
        raise ManifestError(f"host must carry exactly {HOST_FIELDS}")
    if payload["injection_condition"] is not None and (
        payload["injection_condition"] not in INJECTION_CONDITIONS
    ):
        raise ManifestError(
            f"injection_condition {payload['injection_condition']!r} is not one of "
            f"{INJECTION_CONDITIONS}"
        )
    fingerprints = payload.get("system_fingerprints")
    if fingerprints is None:
        fingerprints = ()
    elif isinstance(fingerprints, list) and all(isinstance(item, str) for item in fingerprints):
        fingerprints = tuple(fingerprints)
    else:
        raise ManifestError(
            "system_fingerprints must be a list of strings (possibly empty); the distinct "
            "system_fingerprint values this run saw (D10, ADR-123)"
        )
    return RunManifest(**{**payload, "system_fingerprints": fingerprints})


def same_model_provider(recorded: str | None, pinned: str | None) -> bool:
    """Whether a recorded per-call provider string names the same model as the pinned one.

    The pin is `MODEL_PROVIDER_STRING` (`infra/versions.env`), e.g.
    ``custom_openai/gpt-5.6-terra``: a LiteLLM provider prefix and a model id. A gateway that
    fans one logical model out over several upstream sources may answer some calls with the
    upstream vendor's own namespace inserted between the two -- ``custom_openai/openai/
    gpt-5.6-terra`` -- for the same model, the same weights and the same price. Exact string
    equality reads that as a changed instrument and refuses the bundle, which is a false
    positive: the label moved, the model did not (ADR-106).

    Equivalence is therefore the LiteLLM provider prefix AND the terminal model id, with any
    intermediate vendor namespace ignored. Nothing weaker: a different model id or a different
    provider prefix still fails, so the check keeps doing the job ADR-100 gave it -- catching a
    run whose model actually changed -- and stops doing the one it was never meant to do.
    """
    if recorded is None or pinned is None:
        return recorded == pinned
    if recorded == pinned:
        return True
    recorded_parts = recorded.split("/")
    pinned_parts = pinned.split("/")
    if len(recorded_parts) < 2 or len(pinned_parts) < 2:
        return False
    return recorded_parts[0] == pinned_parts[0] and recorded_parts[-1] == pinned_parts[-1]
