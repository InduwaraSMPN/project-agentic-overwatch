# scenarios — injection harness and scenario library

The subdirectories below are mapped in `docs/04-repo-conventions.md` section 1; all landed at M5.

- `schemas/` — the format contracts (`scenario_manifest.v1.json`, `groundtruth.v1.json` through
  `groundtruth.v3.json`, `injection_plan.v1.json`, `content_pool.v1.json`, `assertions.v1.json`,
  `scores.v1.json`) and the two standard-library readers that validate against them.
- `manifests/` — the five scenario manifests, `SCN-SIM-01`…`SCN-SIM-03` and `SCN-CVE-04`,
  `SCN-CVE-05`.
- `attackers/` — the pure planner `plan.py`, the applier `apply.py`, the content registry
  `content.py`, and `content/` holding the eight payload pools: two generations per injection class,
  `INJ-{A,B,C,D}-pool-01.json` (the v1 corpus, kept byte-untouched) and `INJ-{A,B,C,D}-pool-02.json`
  (the v2 corpus, which appends a guardrail-exercise and a direct-path instance per class; D8).
- `chaosmesh/` — the six fault-primitive CRDs every manifest composes.
- `cve/` — `images.yaml` digest pins and the mirror procedure.
- `groundtruth/` — the per-scenario labels, `rubric-v1.md`, and the two cross-walk tables in its
  README.
- `tests/` — the offline suite over all of the above.

- Serves traceability rows T-17 (scenario determinism), T-20 (ground-truth labels behind detection
  scoring) and T-22 (guardrail block rate by injection class); also T-14, which is Tier B2 and needs
  M4's agent layer and M1's cluster.
- The scenario half of `make determinism-check` proves T-17 offline; the applier and the Tier B rows
  are gated on M1's cluster.
- Constrained by `.agents/rules/20-parity-and-determinism.md`: every scenario and attacker script
  takes `(scenario_id, seed)` and must replay identically. Seed the generator once at entry from
  the run manifest, and never let ordering depend on the wall clock or on dict iteration order.
- Constrained by `.agents/rules/00-source-of-truth.md`: seed values and the run grid live in
  `docs/protocols/evaluation-protocol.md`, not in scenario files.
