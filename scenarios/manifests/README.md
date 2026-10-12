# scenarios/manifests — the scenario manifest format

One file per scenario, `SCN-<CLASS>-<nn>.yaml`, validated against
`../schemas/scenario_manifest.v1.json`. The manifest is what a scenario **is**: what fires, where,
in what order, and where each injection class reaches it. What a *correct response* to it looks like
is `../groundtruth/<scenario_id>.yaml`, and the two are separate files so the sha256 a run bundle
pins over the labels does not move when a teardown step is reworded.

`origin: engineering`. §3.5.6 of the submitted chapters fixes the scenario count and the
phase-coverage constraint and names no individual scenario; "ground truth" has zero occurrences in
the chapters. The scenario identities, the CVE/SIM split and this format are kit engineering
(conflict M5-C2, ADR-034), not dissertation-derived, and the schema pins `origin: engineering` so a
manifest cannot claim otherwise.

## Fields

Every field is defined in `../schemas/scenario_manifest.v1.json`, which is the authority; this is the
reading guide.

- `scenario_id`, `class ∈ {CVE, SIM}`, `schema_version`, `title`, `summary`.
- `namespace` — the Kubernetes namespace the scenario acts in, and the outer bound the ground
  truth's `blast_radius` is read inside.
- `load_profile_id` — resolves against `infra/locust/profiles.yaml` (ADR-015); the registry owns the
  values, the manifest only names one.
- `first_signal_source ∈ {falco, prometheus, k8s_audit, trivy}` — which of FR1.1's four Monitor
  sources carries this scenario's **first** evidence. Each of the four is the first signal for at
  least one scenario (§D12), so the campaign exercises Prometheus and Trivy as detection surfaces
  rather than only as ingestion paths.
- `groundtruth_ref` — the label file, resolved by test rather than by convention.
- `phase_coverage` — all four phases `evaluation-protocol.md` §3 fixes
  (`detection-and-investigation`, `containment`, `eradication`, `verified-recovery`), each declared.
  A scenario declaring three makes `full-lifecycle proportion` undefined on a fifth of the grid.
- `injection_points` — where each of `INJ-A…D` reaches this scenario. `INJ-NONE` takes no entry,
  which is the whole of what distinguishes it from the four classes.
- `incident_primitives` — the Chaos Mesh CRDs, CVE images and attacker steps that make up the
  **incident**, which fires under every injection condition including `INJ-NONE`. One planned event
  per entry, in order.
- `teardown` — ordered steps returning the environment to its pre-scenario state; authored at M5,
  applied at Tier B.

## The planned event count is a property of the manifest

The seeded planner (`../attackers/plan.py`) emits **one event per `incident_primitives` entry**,
plus **one delivery** under each of `INJ-A…D`. So the event count for a cell is
`len(incident_primitives)` under `INJ-NONE`, and `len(incident_primitives) + 1` under each class —
and it does **not** vary with the seed. `data-management.md` §3 refuses to seal a framework-on
bundle whose `injection.log.jsonl` does not match the scenario's ground-truth event count, and that
count is one number per `(scenario, injection_condition)`. A seed that changed the count would make
four fifths of the seeds unsealable; the seed varies timing, selection order, payload instance and
target replica, never how many events fire. `../groundtruth/<id>.yaml`'s
`conditions.<inj>.expected_event_count` declares this number, and `scenarios/tests/` asserts it
equals the planner's across the whole seed set.

## `INJ-NONE` is a grid coordinate, not an absence

> On an `INJ-NONE` run the scenario's incident fires exactly as it does under `INJ-A`…`INJ-D`; what
> is absent is adversarial content directed at the agent layer. The plan is therefore **non-empty**
> — it holds the incident events and no injection-class event — which is what
> `data-management.md` §3's framework-on completeness profile requires of every
> `injection.log.jsonl`, and what lets `evaluation-protocol.md` §3 read these runs as "the no-attack
> baseline the classes are read against". The planner refuses an empty `INJ-NONE` plan, naming it as
> an error.
>
> A framework-**off** `BASE-<LOAD>-<SEED>` run is a different artefact entirely: no scenario, no
> incident, no arm, and `injection.log.jsonl` asserted **absent** by the baseline completeness
> profile. `INJ-NONE` is a cell of the grid; `BASE-<LOAD>-<SEED>` is not a grid cell at all
> (`07-glossary-and-ids.md` §Run & campaign IDs). Reading the two as the same thing would leave a
> fifth of the grid with nothing to respond to and RQ2's per-phase correctness undefined on it,
> which is conflict M5-C4.

This statement is written **here, once**, and referenced from the glossary and from the schema
descriptions rather than restated, per `.agents/rules/00-source-of-truth.md`.
