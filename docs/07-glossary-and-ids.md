# 07 — Glossary & Canonical IDs

Status: active · These IDs appear in code, manifests, bundles, and analysis. Dissertation
labels are kept as aliases; the two ablations both use "C1/C2/C3" in the text, so the
kit-canonical prefixes below exist to prevent collisions.

## Condition IDs

| Canonical | Dissertation | Meaning |
|---|---|---|
| `S1-HIER` | structure C1 | full hierarchy: Orchestrator + 4 Supervisors + Executors |
| `S2-FLAT` | structure C2 | flat single coordinator; no phase-specific Supervisors, no subordinate Executors; same budget per phase |
| `S3-SINGLE` | structure C3 | single agent carrying the Supervision layer's role descriptions + procedure text, uncompressed into one prompt |
| `G0-FULL` | guardrail C0 | full Guardian mediation (baseline; also the RQ3/RQ4 config) |
| `G1-LOGONLY` | guardrail C1 | Guardian logs, does not block |
| `G2-SHAREDCRED` | guardrail C2 | agents hold scoped ServiceAccounts; netpol opened |
| `G3-UNQUOTED` | guardrail C3 | aggregator quoting disabled |

Structure arms run with Guardian = G0 behavior; guardrail arms run with topology = S1 —
confirmed against §3.5.4 · "Two rigorous ablations are designed" (T0.7; binding log
SLOT-GLOS-01): all seven arms verified, the ablations not crossed. Two caveats bind
wherever these tables are read: S2-FLAT removes both role tiers, not just graph shape;
and G1-LOGONLY/G2-SHAREDCRED are not orthogonal — per §3.5.4, "C2 is not a
single-property removal wholly independent of C1" — so their contrasts are cumulative,
not isolated.

**The shared full-architecture arm: one arm, two names, one token.** `S1-HIER` and
`G0-FULL` denote the same configuration — full hierarchy under full Guardian mediation —
and therefore the same base-suite runs, reused rather than re-run for both rigorous
ablations (evaluation-protocol §2). The canonical `<COND>` token for that arm, the one its
bundles actually carry, is **`G0-FULL`**. Two things decide it. The table above already
gives `G0-FULL` the baseline role — "full Guardian mediation (baseline; also the RQ3/RQ4
config)" — so the token RQ3 and RQ4 already read is the token already on the runs they
read. And the pilot is specified as three `G0-FULL` plus three `G1-LOGONLY` runs
(`docs/milestones/GATE-pilot.md`), so `G0-FULL` is the name already in use for the first
bundles the project will produce. `S1-HIER` remains the structure study's name for the same
arm and stays correct in prose, in the table above and in the RQ2 contrasts — it is an
alias, not a second arm. It follows that **a campaign containing both `S1-HIER` and
`G0-FULL` bundles is invalid**: that is the shared arm issued twice, which is the larger
grid evaluation-protocol §2 explicitly rejects wearing a different mask. The manifest
validator (T-23) rejects such a campaign rather than reconciling it. ADR-008 records the
decision.

## Scenario & injection IDs

- Scenario: `SCN-<CLASS>-<nn>` where `CLASS ∈ {CVE, SIM}` (real-CVE injection vs seeded
  simulation). Each scenario ships ground-truth labels (`scenarios/groundtruth/`). `<nn>` is two
  digits, zero-padded, assigned in creation order and never reused — a single sequence not
  restarted per `<CLASS>`, so `SCN-SIM-01`…`SCN-SIM-03` are the SIM arm and `SCN-CVE-04`,
  `SCN-CVE-05` the CVE arm.
- Injection classes for the guardrail study (§3.5.4 · "The four injection classes are
  direct prompt injection"; binding log SLOT-GLOS-02): `INJ-A` direct prompt injection,
  `INJ-B` ingested-log injection, `INJ-C` role-manipulation injection, `INJ-D`
  parameter-manipulation injection — in source order; the A–D lettering is the kit's,
  not the dissertation's. The grid's fifth condition value is `INJ-NONE`, §3.5.6's
  "a no-attack baseline plus four injection classes". `INJ-NONE` is a grid coordinate whose plan
  is non-empty — the incident fires and nothing is injected at the agent layer — distinct from a
  framework-off `BASE-<LOAD>-<SEED>` run, which has no scenario and whose `injection.log.jsonl` is
  asserted absent; see `scenarios/manifests/README.md` and data-management §3.

## Seeds

Kit-canonical fixed seed set (pre-registered here): `{101, 102, 103, 104, 105}`.
§3.5.6 reduction path uses the first three: `{101, 102, 103}`. Seeds parameterize scenario
injection and any stochastic runner behavior; model sampling uses temperature 0 + provider
seed where supported (nondeterminism residual is absorbed by the multi-seed design).

**Pilot seeds (M10, ADR-120).** The pilot ladder uses seeds **disjoint from the campaign set**, so no
pilot bundle can be mistaken for a campaign bundle: pilot seed A = `901`, pilot seed B = `902` (P2 uses
A, P3 uses B; plan §6). `PILOT_SEEDS` in `runner/grid.py` points here, the same convention `SEEDS` uses.
Pilot corpora carry their own campaign ids and are never part of the campaign corpus.

## Run & campaign IDs

- Run (grid runs): `RUN-<COND>-<SCN>-<INJ>-<SEED>` e.g. `RUN-G0-FULL-SCN-CVE-03-INJ-A-101`.
  `<COND>` is one of the grid's six arms, the shared full-architecture arm carrying its
  canonical token `G0-FULL` per §Condition IDs above; `INJ ∈ {INJ-NONE, INJ-A, INJ-B,
  INJ-C, INJ-D}`. The four components are exactly the grid coordinates — arm, scenario,
  injection condition, seed. Nothing else varies, and nothing that varies is omitted, which
  is what lets the identifier and the manifest be checked against each other field for field
  (data-management §2).

  **Reruns carry an attempt suffix.** A rerun repeats a cell on the same four coordinates and
  data-management §4 keeps the original, but the identifier above is a pure function of those
  coordinates and §1 lays bundles out at `runs/<CAMPAIGN>/<RUN_ID>/` — so without a suffix the
  rerun and the run it replaces would claim the same path and one would overwrite the other,
  destroying the very evidence §4 retains. Attempt 1 is unsuffixed; attempt *n* ≥ 2 appends
  `-R<n>`, e.g. `RUN-G0-FULL-SCN-CVE-03-INJ-A-101-R2`. The **cell key** is the identifier with
  any `-R<n>` suffix stripped; every attempt at a cell shares one cell key, and the campaign
  validator (T-23) requires exactly one attempt per cell to be marked valid. Because `-R<n>`
  is terminal and `<SEED>` is a fixed three-digit field, the suffix never makes the identifier
  ambiguous to parse. Baseline identifiers take the same suffix on the same rule.

  The `<INJ>` field is **load-bearing and was added at M0 closeout to fix an ID collision**.
  The grid varies over six arms, five scenarios, five injection conditions and five seeds
  (evaluation-protocol §2), but the format as first written varied only over arm, scenario
  and seed — 6 × 5 × 5 = 150 distinct identifiers for a grid five times that size, so every
  identifier collided five ways. Bundles would have overwritten one another in `runs/`
  and no analysis could have separated a no-attack baseline from an injected run. The field
  is also the third component of the matched-pairs key `(scenario, injection-condition, seed)`
  that T-39 requires, so without it the rigorous contrasts cannot form their pairs at all.

  `<STUDY>` is **removed**, dropped at the same M0 closeout for a defect of the opposite
  shape: not too few identifiers, but no correct value for one arm. The component ranged
  over `{S, G}` and sat ahead of `<COND>`. Because `S1-HIER` and `G0-FULL` are the same
  runs, reused rather than re-run (evaluation-protocol §2), those runs had to be stamped
  `S` or `G`, and whichever was chosen the identifier misdescribed them for the other
  study — which reads the very same bundles for its own contrasts. Issuing the arm under
  both codes instead is the arm issued twice, which is the over-counted grid
  evaluation-protocol §2 explicitly rejects. Study membership is derived from `<COND>` at
  analysis time instead:
  `S2-FLAT` and `S3-SINGLE` are structure-only, `G1-LOGONLY`, `G2-SHAREDCRED` and
  `G3-UNQUOTED` are guardrail-only, and the shared arm belongs to both — which is that arm's
  actual status rather than an ambiguity to be resolved. The component was therefore
  redundant on the five arms where it was unambiguous and wrong on the sixth: no information
  anywhere, one falsehood somewhere. Its removal also retires the `X` (characterisation-only)
  code the same reasoning had already emptied — RQ3 and RQ4 read the shared arm's own runs,
  so no characterisation-only run exists for a study code to name. ADR-008 records the
  decision and the rejected alternative.
- Baseline run: `BASE-<LOAD>-<SEED>` e.g. `BASE-LOAD-STEADY-101`, where `<LOAD>` is the run's
  `load_profile_id`, written `LOAD-<slug>`. A baseline is a framework-off reference run; it
  is the run RQ4's resource-overhead and interference deltas are measured against, paired to
  its framework-on runs by `baseline_run_id` and matched on `load_profile_id`
  (data-management §2). The form is deliberately **not** a grid coordinate and cannot be
  mistaken for one: it begins `BASE-`, never `RUN-`; it carries no arm token and no `<INJ>`
  component, because a baseline occupies no arm and no injection condition — `condition` and
  `injection_condition` are null when `is_baseline` is true; and it is one component shorter.
  A baseline is not a grid cell and does not count toward the grid total, whose arithmetic
  (evaluation-protocol §2) closes over grid runs alone. Uniqueness: a campaign holds at most
  one baseline per `(load_profile_id, seed)`, and the manifest validator (T-23) rejects a
  second.
- Campaign: `CAMP-<yyyymmdd>-<slug>`; a campaign manifest freezes grid, order, versions hash. The v1
  campaign is `CAMP-20260914-campaign` (kept as a formative iteration, D9). The **M10 clean re-run**
  is `CAMP-<yyyymmdd>-campaign-v2`, `freeze_tag: v2.0` (ADR-136); its exact date and host are recorded
  in the M10 work order (`docs/milestones/M10-campaign-v2.md`). Pilot corpora carry their own ids
  (e.g. `CAMP-<yyyymmdd>-pilot-p2`) and are never part of the campaign corpus.

## Terms

**DSRM** Design Science Research Methodology (Peffers et al.) — activities 1–6; mapping in
charter. **Evaluand** the property being evaluated (dissertation §3.5). **Arm/condition**
one experimental configuration. **Run bundle** the §3.5.7-complete per-run artifact
(data-management). **Golden path** the canonical dev scenario used for M4/M6 smoke tests.
**Freeze** a campaign instrument freeze: the `v1.0` tag at pilot gate; the `v2.0` tag for the M10
clean re-run (ADR-136); after either, instrument changes stop. **Instrument** the M10 path set an
instrument digest covers (plan §0 P6). **Shadow mode** G1-LOGONLY used as production staged-rollout
mechanism (M8). **VERIFY slot** unbound text awaiting verbatim binding from `context/`.
**`cluster_api_request`** the M10 direct-path tool `(method, path, body, bearer_token_file)` registered
for the acting role in every arm for parity; its transport (`runner/egress_shim.py`) permits the API
server only under the G2-SHAREDCRED flag and refuses in every other arm (ADR-131). **Pool-02** the M10
payload pools `INJ-{A,B,C,D}-pool-02.json` carrying `induced_action` intent, a guardrail-exercise
instance and a direct-path instance per class (ADR-126); the v1 pools are retained unchanged.
**Instrument-only probe** a P0-live run with condition, scenario and injection applied but no agent
graph, sealed under the probe completeness profile (data-management §3).
