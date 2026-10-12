r"""The campaign manifest format: the planned grid, frozen, that the validator reads.

WHAT A CAMPAIGN MANIFEST IS
-----------------------------
``07-glossary-and-ids.md`` §Run & campaign IDs says a campaign manifest "freezes grid, order,
versions hash"; the format itself is unspecified in the protocol and is T6.3's to define, so it is
kit engineering (``origin: engineering``). A campaign manifest is the planned grid before any run
exists: a ``campaign_id`` on the ``CAMP-<yyyymmdd>-<slug>`` form, the seed set and load profiles it
covers, and one **planned run** per cell -- a run's four grid coordinates plus its ``is_baseline``,
``baseline_run_id`` and ``load_profile_id``, which is exactly the subset of the §2 manifest the
validator can check before a bundle carries the rest.

A planned run is deliberately NOT a full ``manifest.json``: at plan time there is no
``started_at``, no ``git_commit``, no registry digest, because nothing has run. The full manifest is
sealed per bundle (``runner/manifest.py``); this is what ``make campaign`` validates before it
starts.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
``validate_campaign_manifest`` (T-23) and the synthetic generator's campaign output (T-25). ADR-039.
"""

import json
from dataclasses import dataclass, fields
from typing import Any, Final

__all__ = (
    "CAMPAIGN_ID_PATTERN",
    "SYNTHETIC_SLUG",
    "CampaignError",
    "CampaignManifest",
    "PlannedRun",
    "from_dict",
    "to_canonical_bytes",
)

import re

# CAMP-<yyyymmdd>-<slug>. The synthetic corpus uses the reserved slug so a figure produced from it
# says so on its face (ADR-042).
CAMPAIGN_ID_PATTERN: Final = re.compile(r"^CAMP-[0-9]{8}-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_SLUG: Final = "synthetic"


class CampaignError(Exception):
    """A campaign manifest is structurally malformed (a *rule* violation belongs to validate.py)."""


@dataclass(frozen=True)
class PlannedRun:
    """One planned cell: the four grid coordinates plus the fields the validator checks pre-run.

    For a grid run, ``is_baseline`` is false and the four coordinates are set. For a baseline,
    ``is_baseline`` is true, ``condition``/``scenario_id``/``injection_condition`` are null (§2's
    null set), and ``load_profile_id`` and ``seed`` are the pairing key.
    """

    run_id: str
    condition: str | None
    scenario_id: str | None
    injection_condition: str | None
    seed: int
    is_baseline: bool
    baseline_run_id: str | None
    load_profile_id: str

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True)
class CampaignManifest:
    """A campaign whose grid, generated order, order seed, versions hash and freeze tag are frozen.

    ``freeze_tag`` is the ANNOTATED TAG NAME, not a commit hash, and that is forced rather than
    preferred (ADR-136): this document is committed in the very commit ``v2.0`` names, so a commit
    hash written into it would name the PREVIOUS commit, and no self-consistent value exists. The
    resolved commit lives in the runtime sidecar ``runs/<CAMP>/frozen_commit.txt``, written on first
    execution and cross-checked on every later one (``runner/freeze.py``). ``None`` is the honest
    value for a campaign that has not been frozen yet -- every v1 manifest, and any pilot, which
    runs long before ``v2.0`` exists.
    """

    campaign_id: str
    seeds: tuple[int, ...]
    load_profiles: tuple[str, ...]
    runs: tuple[PlannedRun, ...]
    campaign_seed: int
    generated_order: tuple[str, ...]
    versions_env_sha256: str
    freeze_tag: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "seeds": list(self.seeds),
            "load_profiles": list(self.load_profiles),
            "runs": [run.to_dict() for run in self.runs],
            "campaign_seed": self.campaign_seed,
            "generated_order": list(self.generated_order),
            "versions_env_sha256": self.versions_env_sha256,
            "freeze_tag": self.freeze_tag,
        }


def to_canonical_bytes(manifest: CampaignManifest) -> bytes:
    """Canonical JSON, so a campaign manifest hashes reproducibly."""
    return json.dumps(
        manifest.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


_PLANNED_RUN_FIELDS: Final = frozenset(f.name for f in fields(PlannedRun))

# The manifest's own keys. `freeze_tag` is OPTIONAL on the way in and mandatory on the way out: a v1
# manifest predates the field and must still load (it is a sealed campaign with 755 bundles behind
# it), while every manifest this module WRITES carries the key, present-but-null when there is no
# freeze. That asymmetry is deliberate in both directions -- tolerating its absence on read is what
# keeps the four tracked `runner/CAMP-*.json` files loadable without editing them, and emitting it
# always is what stops a v2 manifest's field set depending on which code version wrote it. The exact
# set check below therefore compares against this tuple rather than hard-coding the names twice.
_MANIFEST_FIELDS: Final = tuple(f.name for f in fields(CampaignManifest))
_OPTIONAL_ON_READ: Final = frozenset({"freeze_tag"})


def from_dict(payload: dict[str, Any]) -> CampaignManifest:
    """Parse a campaign manifest, checking only structure. Rules are validate.py's."""
    keys = set(payload)
    expected = set(_MANIFEST_FIELDS)
    if keys - expected or (expected - keys) - _OPTIONAL_ON_READ:
        raise CampaignError(
            f"campaign manifest keys {sorted(payload)} do not match {sorted(expected)}"
            f" (optional on read: {sorted(_OPTIONAL_ON_READ)})"
        )
    if CAMPAIGN_ID_PATTERN.match(payload["campaign_id"]) is None:
        raise CampaignError(f"campaign_id {payload['campaign_id']!r} is not CAMP-<yyyymmdd>-<slug>")
    runs: list[PlannedRun] = []
    for index, raw in enumerate(payload["runs"]):
        if set(raw) != _PLANNED_RUN_FIELDS:
            raise CampaignError(
                f"run {index}: fields {sorted(raw)} do not match {sorted(_PLANNED_RUN_FIELDS)}"
            )
        runs.append(PlannedRun(**raw))
    return CampaignManifest(
        campaign_id=payload["campaign_id"],
        seeds=tuple(payload["seeds"]),
        load_profiles=tuple(payload["load_profiles"]),
        runs=tuple(runs),
        campaign_seed=payload["campaign_seed"],
        generated_order=tuple(payload["generated_order"]),
        versions_env_sha256=payload["versions_env_sha256"],
        freeze_tag=payload.get("freeze_tag"),
    )
