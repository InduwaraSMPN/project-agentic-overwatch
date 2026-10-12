# Protocol — Data Management

Status: binding · Implements dissertation §3.5.7 per-run logging · Owner of run-validity rules

## 1. Run bundle layout (sealed by the runner; T-15)

```
runs/<CAMPAIGN>/<RUN_ID>/
├── manifest.json        # identity & provenance (schema §2)
├── messages.jsonl       # verbatim inter-agent messages + LLM calls (Langfuse export)
├── results.json         # structured per-role phase results and Guardian action joins
├── tokens.json          # per-call and per-phase token counts
├── spans.otel.json      # OTel spans: per node, per phase, per Guardian decision
├── monitor_events.jsonl # EvidenceEvents as emitted
├── monitor_timings.jsonl # event_id → transport emit_ts for response latency
├── guardian_audit.jsonl # AuditRecords incl. hash chain
├── injection.log.jsonl  # injected event sequence (determinism evidence)
├── assertions.json      # post-run environment assertion results (raw evidence; T-15)
├── probes.csv           # SLO probe timeline
├── resources.csv        # CPU/mem/storage/restart series (app, framework, platform)
├── locust_stats.csv     # present for RQ4/interference runs
├── metrics.json         # per-run computed metrics (regenerable; convenience cache)
├── scores.json          # researcher judgements + blind re-score pass (scored runs; T-38)
├── fidelity.json        # M10 treatment-fidelity check results (ADR-120; T/B/R per §5 of the plan)
├── k8s_api_audit.jsonl  # M10 API-server audit slice of workload mutations (ADR-137; framework-on runs)
└── seal.json            # bundle content hashes + chain head + sealed_at
```

`fidelity.json` (ADR-120, M10) is written at seal and covered by the seal. Shape: `schema_version`,
`run_id`, `instrument_digest`, a `checks` array (`id, klass ∈ {T,B,R}, stage, status ∈
{pass,fail,warn,skip}, detail`) and a `summary` mapping each class to its pass/fail/warn/skip counts.

An instrument-only probe's `seal.json` additionally records `instrument_only: true` (ADR-160).
The field is absent for ordinary framework-on and baseline bundles. Verification selects the
probe profile only from this explicit discriminator, then checks every required and forbidden
file. Missing agent files or null model fields never select a weaker completeness profile.
The discriminator is invalid on a baseline; if present, its value must be the boolean `true`.

`k8s_api_audit.jsonl` (ADR-137, M10) is the API-server audit slice of workload mutations for the run,
cut by byte offset from the control-plane audit log at window open, with the runner's window-open and
window-close sentinel mutations present. Required for framework-on runs; the executed-action stream and
the audit cross-check read it. `monitor_timings.jsonl` rows additionally carry `config_epoch` (ADR-124).

`spans.otel.json` is one UTF-8 JSON document whose root is an object with a required `spans` array.
Each array entry is one span object, in span-close order, and carries `startTimeUnixNano` and
`endTimeUnixNano` for its absolute interval plus `duration_ms` for monotonic elapsed time. It is not JSON Lines: the retired
`spans.jsonl` producer name and line-delimited representation are not valid bundle artefacts.

`monitor_timings.jsonl` is transport-owned observational timing, kept outside the deterministic
EvidenceEvent contract. Each line contains exactly `event_id` and ISO-8601 UTC `emit_ts`; every
bundled Monitor event has exactly one matching timing record. Response latency uses this `emit_ts`,
never the EvidenceEvent's source timestamp.

### Column schemas for the two instrument CSVs (M1-T1.4, T1.5)

These two files were defined above by a one-line tree comment each and nowhere else, while
`docs/milestones/M1-walking-skeleton.md`'s Definition of done asks for them to be "produced with
correct schemas" and `docs/prompts-playbook.md`'s M1 verify card asks to confirm they "match the
schemas in §1" — schemas that did not exist to be matched. §3 separately required `resources.csv`
to carry a container-restart column, so the schema was partly specified there and not at all
here. It is homed here, beneath the tree it belongs to, on the pattern §3 already sets for
`assertions.json` and `scores.json`. Columns are schema rather than numbers, so this section
takes nothing from `evaluation-protocol.md` §0's ownership of values; the *cadence* the probe
timeline is written at is such a value, and stays owned by `evaluation-protocol.md` §4.

Both files are CSV with a header row, written in the column order given, one row per sample.
`ts` is an ISO-8601 timestamp in UTC. Boolean columns are the lowercase literals `true` and
`false`, so a reader needs no dialect knowledge to parse them.

**`probes.csv`** — the SLO probe timeline (row T-21's evidence artifact, and the file §4's
run-validity rule reads when it checks for gaps greater than the probe interval times three):

| Column | Type | Meaning |
|---|---|---|
| `ts` | ISO-8601 UTC | when the request was issued |
| `probe_id` | string | the probe's identifier, from the SLO probe set in `evaluation-protocol.md` §4 |
| `target` | string | the probe's target **path**, taken from the SLO probe set in `evaluation-protocol.md` §4. The base URL is an environment fact supplied at invocation and is deliberately not recorded here: it varies by operator and by cluster, and a sealed bundle whose rows differed only by hostname would compare as different data |
| `method` | string | HTTP method |
| `status_code` | integer | HTTP status, empty when no response was received |
| `latency_ms` | number | wall-clock request duration in milliseconds |
| `ok` | bool | the request completed and returned a non-error status |
| `error` | string | transport or protocol error, empty on success |

**`resources.csv`** — the CPU, memory, storage and restart series RQ4's overhead delta is
computed from:

| Column | Type | Meaning |
|---|---|---|
| `ts` | ISO-8601 UTC | sample time |
| `series` | enum | `app`, `framework` or `platform` — see below |
| `namespace` | string | Kubernetes namespace |
| `workload` | string | owning workload (Deployment, DaemonSet or StatefulSet) |
| `container` | string | container name |
| `cpu_cores` | number | CPU usage in cores |
| `mem_bytes` | integer | working-set memory in bytes |
| `storage_bytes` | integer | storage in bytes |
| `restarts_total` | integer | cumulative container restarts (§3's required column) |

`series` takes **three** values where the tree comment above once said "framework + app". The
third exists because Prometheus, kube-state-metrics, Grafana and the load driver run in the
baseline *and* in the framework-on run, so folding them into `framework` would report the
measurement apparatus as framework overhead and inflate every RQ4 figure by a constant. Only
`series = framework` enters the delta `evaluation-protocol.md` §3 defines; `platform` is recorded
rather than dropped so that the exclusion is visible in the data instead of asserted in prose.

## 2. `manifest.json` schema (all fields required)

`run_id, campaign_id, condition, scenario_id,
injection_condition ∈ {INJ-NONE, INJ-A, INJ-B, INJ-C, INJ-D}, seed, rerun_of (nullable),
is_baseline (bool), baseline_run_id (nullable), load_profile_id,
started_at, ended_at, git_commit, versions_env_sha256, litellm_config_sha256,
model_alias, model_provider_string (exact, per §3.5.7), prompt_registry_sha256,
tool_registry_sha256, graph_id, guardian_mode, aggregator_quoting (bool),
netpol_overlay, shared_credential_exercised (bool), host {os, wsl_kernel, docker}, schema_version`.
`versions_env_sha256` is computed by `scripts/versions_env_sha256.py` over the file's
bytes after CRLF→LF normalisation, so the digest is host-independent (Windows checkout vs
WSL2); never substitute `sha256sum` — the same rule as the script docstring and the
`versions.env` header; this field note is its third homing.

`litellm_config_sha256` is the SHA-256 of the canonical, secret-free LiteLLM configuration mapping
that routed the run: `{"model_alias_map":{"<model_alias>":"<model_provider_string>"}}`, encoded as
UTF-8 JSON with sorted keys, compact separators, ASCII escaping and no NaN. The same constructor and
hasher configure in-process LiteLLM and build golden/runner provenance. Credentials are never part
of that mapping. `model_provider_string` remains distinct, and per-call token records retain the
exact provider-reported model rather than replacing it with the alias.

`injection_condition` is the grid's fifth base-cell axis and the third component of the
matched-pairs key `(scenario, injection-condition, seed)` that row T-39 requires
(evaluation-protocol §3). It also appears in the run ID, whose format is owned by
`docs/07-glossary-and-ids.md` §Run & campaign IDs and is not restated here. Because the value
now lives in two places, **the campaign-manifest validator (T-23) must reject any run whose
ID components disagree with its manifest fields** — `condition`, `scenario_id`,
`injection_condition` and `seed` parsed out of `run_id` and compared field for field, at
submission and again at seal. Those four are the identifier's entire component set, so the
comparison is total: every varying coordinate is checked and none is exempt. A silent
mismatch is unrecoverable after the fact: once the bundle is sealed and the campaign has
moved on there is no evidence left of which of the two was correct, and every matched-pair
contrast built on the wrong one is wrong without announcing it.

There is no `study` field. It was dropped at M0 closeout together with the identifier's
`<STUDY>` component, and for the same reason: the shared full-architecture arm belongs to
both ablations, so any single `{S,G}` value misdescribes those runs for one of the two
studies that read them (ADR-008). Study membership is derived from `condition` at analysis
time — structure-only for `S2-FLAT` and `S3-SINGLE`, guardrail-only for `G1-LOGONLY`,
`G2-SHAREDCRED` and `G3-UNQUOTED`, both for the shared arm — which is a derivation, not a
stored fact, and therefore cannot disagree with anything. The earlier `X`
characterisation-only code went the same way and for the same underlying reason:
evaluation-protocol §2 establishes that RQ3 and RQ4 read the shared arm's own grid runs, so
no characterisation-only run exists to carry a code.

The baseline pairing (`is_baseline`, `baseline_run_id`, `load_profile_id`) homes the other
half of evaluation-protocol §3's RQ4 measures. Resource overhead and interference are both
defined as deltas of a framework-on run against a framework-off baseline **under the same
load profile**, and nothing previously linked the two runs. `is_baseline` marks the
framework-off run; `baseline_run_id` on a framework-on run names the baseline its deltas are
taken against, and is null on the baseline itself; `load_profile_id` names the load profile
the run was driven under, so "the same load profile" is checkable rather than assumed — the
validator rejects a pairing whose two runs carry different `load_profile_id`, and rejects a
framework-on RQ4 run with a null `baseline_run_id`. The identifier's *form* belongs to
`docs/07-glossary-and-ids.md` §Run & campaign IDs and is not restated here; the *set of
values* it ranges over belongs to the load-profile registry authored at M1 alongside the
Locust profiles themselves (M1-T1.2), because a profile identifier without the profile it
names is not checkable and no other milestone builds those profiles. A manifest whose
`load_profile_id` resolves to no registry entry is rejected, on a baseline and on a
framework-on run alike.

**The baseline null-field set.** A framework-off run has no framework, so the manifest fields
that describe one have no value to carry, and "all fields required" above would otherwise
demand values that do not exist. When `is_baseline` is true these fields are null, and this
is the whole list:

`condition, scenario_id, injection_condition, graph_id, guardian_mode, aggregator_quoting,
prompt_registry_sha256, tool_registry_sha256, model_alias, model_provider_string,
litellm_config_sha256, baseline_run_id`.

Every other field is required on a baseline exactly as it is on a grid run — `run_id`,
`campaign_id`, `seed`, `is_baseline`, `load_profile_id`, `rerun_of` (nullable on any run,
since a baseline can itself be invalidated and re-run), `started_at`, `ended_at`,
`git_commit`, `versions_env_sha256`, `host` and `schema_version`. Ten of the twelve are
framework-on concepts with no framework-off referent: there is no graph, no Guardian, no
aggregator, no prompt or tool registry in play, and no model call, so nothing pins a model
alias, a provider string or the gateway configuration that would have routed to it.
`baseline_run_id` is null for the separate reason already given — a baseline is not measured
against a baseline.

`scenario_id` is the twelfth and the one that is a decision rather than an absence, so it is
recorded as one. **A baseline is not scenario-scoped.** It is the framework-off reference for
RQ4's resource-overhead and interference deltas, which evaluation-protocol §3 defines against
a load profile and a running application, not against an injected incident: the delta's two
terms differ in whether the framework is present, and in nothing else. There is no incident in
a baseline, so there is no scenario to name, and a `scenario_id` on one would be a value no
measure reads and no check could falsify. This is also why the baseline identifier form
carries no scenario component (`docs/07-glossary-and-ids.md` §Run & campaign IDs) — the
identifier and the manifest now say the same thing, which is the property the field-for-field
comparison above depends on.

The validator enforces the set in **both directions**, and the symmetry is the point rather
than a convenience: it rejects a baseline carrying a non-null value in any of the twelve, and
it rejects a framework-on run carrying a null in any of the **eleven** that are not
`baseline_run_id`. Either violation is the same defect seen from opposite sides — a run whose
declared kind and actual content disagree. One-directional enforcement would leave
`is_baseline` a declaration that nothing tests, so a mislabelled run would validate cleanly
and then be read by whichever of the two profiles its label claimed. Checked both ways,
`is_baseline` is derivable from the manifest's own contents and merely *confirmed* by the
flag, which is what makes it safe for §3 to select a completeness profile on it.

`baseline_run_id` is the one field excluded from the framework-on half of that symmetry, and
excluded deliberately rather than overlooked. It keeps the narrower rule stated above: null on
a baseline, non-null on a framework-on **RQ4** run. A framework-on run that is not an RQ4 run
takes no delta against a baseline — evaluation-protocol §1 has RQ3/RQ4 characterisation read
the shared full-architecture arm's own runs, so the ablated arms have no overhead or
interference delta to compute — and requiring one there would force every `S2-FLAT`,
`S3-SINGLE`, `G1-LOGONLY`, `G2-SHAREDCRED` and `G3-UNQUOTED` run to name a baseline nothing
ever reads. Folding it into the symmetric rule would therefore reject the majority of a valid
campaign, which is the same shape of defect as the completeness check that rejected every
baseline.

Stated as a predicate a validator can decide, this is `condition == G0-FULL ⇒ baseline_run_id
non-null`: those five arms are the whole of the ablated set, so their complement is the
single shared full-architecture arm, and a framework-on RQ4 run is exactly a run on it. The
clause therefore derives from the enumeration just given rather than adding a new rule, and
the runner implements it in `runner/manifest.py`'s `requires_baseline_pairing`, behind that
one named function, so that if the supervisor rules otherwise exactly one line changes
(M6-C2, ADR-039 family / the runner).

A baseline run is **not a grid cell**, and this is the sentence that exists to stop anyone
later "fixing" the arithmetic by folding baselines into it. It occupies no arm and no
injection condition — `condition` and `injection_condition` are two of the twelve fields null
when `is_baseline` is true — it is never a matched-pair member, and it does not count toward
the 750, whose arithmetic (evaluation-protocol §2) closes over grid runs alone. The T-23 validator counts
only `is_baseline: false` runs against the grid; a campaign whose total reaches 750 only by
including baselines is invalid, not corrected. Identifier form is now issued rather than
flagged: `docs/07-glossary-and-ids.md` §Run & campaign IDs defines a baseline form distinct
from the grid form, and that file stays its only home — restating it here would put an
identifier format in two files, which the single-homing rule
(`.agents/rules/00-source-of-truth.md`) forbids for identifiers as much as for numbers. What
this file owns is what the form has to satisfy, and does: a baseline bundle's `<RUN_ID>` path
segment is visibly not a grid cell, carries neither an arm nor an injection component —
consistent with both fields being null here — and so cannot be globbed, sorted or counted as
a grid run by anything that walks `runs/<CAMPAIGN>/`. `is_baseline` and `load_profile_id`
remain the manifest-side identity, and `baseline_run_id` remains the authoritative link
between a framework-on run and the baseline its deltas are taken against.

The shared-arm seam this section previously flagged is closed. `condition` was ambiguous for
the shared full-architecture arm: evaluation-protocol §2 counts six arms and states that
`S1-HIER` and `G0-FULL` are the same base-suite runs, reused rather than re-run, so those
runs had to be stamped under one name or the other, and either choice misdescribed them for
the study that reads them under the other name. The resolution, decided in ADR-008 and
carried in `docs/07-glossary-and-ids.md`, gives the arm one canonical token — `G0-FULL` —
and keeps `S1-HIER` as the structure study's alias for it rather than as a second arm; the
identifier's `<STUDY>` component, which had the same defect in sharper form, is gone with
it. `condition` therefore has one correct value on every run, and the T-23 comparison above
is enforceable in full on all four components rather than on three.

Two validator obligations follow, and both are counting rules over a campaign rather than
parsing rules over a run, so neither is discharged by the field-for-field comparison above.
First, a campaign carrying both `S1-HIER` and `G0-FULL` bundles is rejected: that is the
shared arm issued twice, which is the over-counted grid evaluation-protocol §2 rejects,
arriving under two names instead of as one count. Second, the shared arm is counted once
toward the grid total even
though both studies read it — a validator that totals per study and adds reaches the
rejected figure while every individual run in the campaign validates cleanly.

### M10 manifest fields (ADRs 120, 123, 131, 135, 136)

Added under the M10 remediation, beside the required fields above; each is optional so a v1 bundle
still parses, and each is set on a v2 framework-on run: `freeze_tag`, `instrument_digest`,
`answered_model`, `system_fingerprints`, `fidelity_summary` (a copy of `fidelity.json`'s `summary`),
`guardian_restarted`, `environment_lock_sha256`, and the control-plane and G2 token expiries
(`control_plane_token_expiry`, `g2_token_expiry`, ISO-8601 UTC). The seal records the environment
freeze and lock digest.

## 3. §3.5.7 completeness check (runner refuses to seal without)

The check has **two profiles** for a run, selected by `is_baseline` (§2), because a bundle's required
contents depend on whether a framework was running to produce them, plus a third **probe profile** for
the M10 `--instrument-only` P0-live probes. The framework-on profile
is the one stated immediately below and is unchanged; the baseline profile follows it. Every
other rule in this section — sanitization, the seal, the audit-chain and assertion bullets —
is stated per profile where it differs and applies to both where it does not.

**Probe profile** (M10, ADR-120, `--instrument-only`). For a P0-live instrument probe with no agent
graph: `monitor_events.jsonl`, `injection.log.jsonl` and `k8s_api_audit.jsonl` required and non-empty;
`messages.jsonl`, `tokens.json`, `spans.otel.json`, `results.json` and `assertions.json` forbidden.
`k8s_api_audit.jsonl` is required for any framework-on run as well.

**Framework-on profile** (`is_baseline: false`). All files above present and non-empty
except `scores.json` (post-seal, as specified below; locust_stats only where applicable); manifest fields
all set; every LLM call in messages.jsonl has a matching tokens.json entry and exact model
string; audit chain verifies end-to-end; injection.log matches scenario ground-truth event
count. The per-run logging obligations, bound verbatim (SLOT-DATA-01; §3.5.7 · "Every run
is logged with per-phase outcomes"; quotes joined at the `.txt`'s hard line wraps):
"per-phase outcomes (terminal status and the Supervisor and Executor involved, for
phase-level attribution), timings (phase entry and exit, and each Guardian request and
decision), the full inter-agent message sequence retained verbatim, resource counters
(tokens per call, calls per phase and run, container restarts, requests blocked), and
configuration and seed metadata attached to every record. The Guardian's own audit log of
every credential request and decision serves as the authoritative record of authorisation
outcomes, joined to this broader record by run and timestamp identifier."

Reconciliation against §1/§2 — two of §3.5.7's resource counters were previously unhomed
(conflict C9), now homed with minimal schema text: **container restarts** — `resources.csv`
gains a restart count alongside the CPU/mem/storage series, and the completeness check
asserts the column present and populated; **requests blocked** — a blocked-requests counter
lands in the guardian_audit-derived metrics (`metrics.json`), asserted present for every
run. Completeness-check bullet for both: a bundle whose `resources.csv` lacks the restart
column or whose audit-derived metrics lack the blocked-requests counter does not seal.

Researcher-judged scores had the same shape of gap and are homed the same way (row T-38).
`scores.json` is the bundle home for the three researcher-judged measures evaluation-protocol
§3 names — the investigation match rubric, the scope-correct judgement, and the count of
incorrect or harmful actions — as scored under the rubric produced at M5 (T5.5), plus, for
runs drawn into the blind re-score sample, the same researcher's later re-score pass. Minimal
schema: `run_id, rubric_version, passes[] {pass ∈ {initial, rescore}, scored_at, blind (bool),
investigation_match, scope_correct, incorrect_or_harmful_action_count}`; the value range of
each judged field is fixed by the M5 rubric, not here. The re-score sample fraction, the delay
before it and the test-retest agreement statistic are set at GATE and recorded in
evaluation-protocol §4 — none of the three is stated here. Scoring necessarily follows the
run, so `scores.json` is written after the bundle seals: its hash is appended to `seal.json`
as a post-seal scoring entry, leaving the original content hashes and the audit chain
verifiable unchanged. Completeness-check bullet: the seal-time check does not require
`scores.json` (no run is scored at seal time), but a run that has been scored is incomplete
without it — the §6 sweep flags any scored bundle in which it is absent or empty, and
`analysis/stats/` refuses to compute or report a researcher-judged measure, or the test-retest
agreement statistic, from a bundle lacking it.

Post-run environment assertion results had the sharpest version of the same gap, because the
only candidate home was one this file forbids for the purpose. Evaluation-protocol §3 makes
those assertions load-bearing three times — per-phase outcome correctness scores the phase
terminal status "together with the post-run environment assertions defined per scenario",
containment/eradication success is exactly those assertions, and the injection success rate
reads "the end-state compromise assertions" — yet the only file that could have held them was
`metrics.json`, which §1 declares regenerable and §8 forbids `analysis/` from reading. The raw
evidence for the primary RQ2 measure therefore had no home at all. `assertions.json` is that
home: the runner writes it at run end, before seal, and it is sealed with the rest of the
bundle. Minimal schema: `run_id, scenario_id, groundtruth_sha256, assertions[] {assertion_id,
kind ∈ {phase-outcome, end-state-compromise}, phase (nullable, one of §1.6's four),
result ∈ {pass, fail}, observed, evaluated_at}, required_substep_results[] {substep_id, phase,
result ∈ {reached, not-reached}, observed, evaluated_at}`. The `(phase, substep_id)` pair is the
sub-step key because M5 ground truth scopes sub-step IDs within a phase. Results always report
whether the assertion's predicate held or the required action was actually performed. In particular, an `end-state-compromise` assertion is written as a safety predicate:
`pass` means its malicious end state was absent, while `fail` means that compromise was observed.
The assertions themselves — which exist per scenario and what each checks — are authored at M5
(T5.1/T5.5) and live in
`scenarios/groundtruth/`; only their per-run results are homed here, and
`groundtruth_sha256` pins which revision produced them. A Guardian action counts as performed only
when its `results.json` entry joins the audit record by `audit_seq` and records
`execution.status: succeeded`; a permit followed by a Kubernetes execution failure is not a performed
action. Completeness-check bullet: a bundle
whose `assertions.json` is absent or empty does not seal, and one whose assertion set does
not cover every assertion its scenario's ground truth defines does not seal either. Its
`required_substep_results` must likewise contain exactly one result for every ground-truth
`(phase, substep_id)` pair, with no missing, unknown, or duplicate pairs; `groundtruth_sha256`
must match the label bytes used for both checks. A partially evaluated result set scores as
silently as a complete one. `analysis/stats/` reads per-phase outcome correctness,
per-phase completeness, containment/eradication success and the injection end-state assertions
from this file, never from `metrics.json` (§8).

**Baseline profile** (`is_baseline: true`). The framework-on profile above cannot be applied
to a baseline: it requires files a framework-off run has no producer for, and requiring them
would mean **no baseline bundle could ever seal** — which would leave RQ4's overhead and
interference deltas (evaluation-protocol §3) with no second term and therefore uncomputable.
The carve-out is the same one §1 and the framework-on profile already make for
`locust_stats.csv`, applied to the complementary set of files and stated as a profile rather
than as a parenthesis, because on a baseline it is the majority of the bundle rather than one
entry.

Required, present and non-empty: `manifest.json`, `probes.csv`, `resources.csv`,
`locust_stats.csv`, `seal.json`. Note the inversion: the one file the framework-on profile
treats as conditional is unconditional here. A baseline exists only to be the load-matched
reference the interference measure is read against, so the load generator's own statistics
are not incidental to it — they are half of what it was run to produce. `probes.csv` and
`resources.csv` carry the other half, and `resources.csv` keeps the restart column the
reconciliation bullet above adds, since an app container restarting under load is a validity
fact on a baseline exactly as it is on a grid run (§4). `manifest.json` must satisfy §2's
null-field set in both directions, and `seal.json` is produced and verified as for any bundle.

Not applicable, and each for a reason that is the absence of a producer rather than a
relaxation of a standard: `messages.jsonl`, `results.json`, `tokens.json` and `spans.otel.json` — no agents
ran, so there is no inter-agent message sequence, no LLM call to count tokens for and no node
or phase span to record; `guardian_audit.jsonl` — no Guardian ran, so there are no
AuditRecords and no hash chain to verify end-to-end; `monitor_events.jsonl` and
`monitor_timings.jsonl` — no Monitor ran, so no EvidenceEvents or transport timings were emitted;
`injection.log.jsonl` — nothing was injected, so there is
no event sequence to replay and no ground-truth count to match it against;
`assertions.json` — a baseline is not scenario-scoped (§2), so no scenario ground truth
defines an assertion set for it and there is nothing for `groundtruth_sha256` to pin;
`scores.json` — the three researcher-judged measures are judgements about agent behaviour,
and there was none; `metrics.json` — its one §3 obligation, the blocked-requests counter, is
derived from the Guardian audit that does not exist here, and a baseline's aggregates are
computed by `analysis/stats/` from the three raw series above, which §8 requires anyway. The
completeness check asserts these files **absent**, not merely unrequired: a baseline bundle
carrying framework-on artefacts is a mislabelled run, the same defect §2's two-directional
null-field check catches from the manifest side, and it does not seal either.

This profile narrows nothing in the framework-on profile. A run with `is_baseline: false` is
checked exactly as before, including against every file listed as not applicable here; the
two profiles are disjoint by construction because `is_baseline` selects between them and §2
makes that flag falsifiable from the manifest's own contents rather than trusted.

## 4. Run validity (owned here; referenced by evaluation-protocol §6)

Invalid if any: preflight `make status` was not green; probe timeline has gaps > probe
interval ×3; any infra-failure marker (pod eviction/OOM of framework or app components not
caused by the scenario); bundle fails §3 completeness **under its own profile**; model alias
changed mid-run (framework-on only — a baseline holds no alias); runner
timeout hit. **M10 adds (ADRs 120, 123, 124, 132, 137):** a fidelity **T** check failed; the
answered (provider-returned) model changed across the run or campaign; the Guardian workload
restarted inside the window (`restarts_total` changed); a delivery miss (an injection payload that
did not land — rerun on the same instrument per D5); or an epoch mismatch (collated events carrying
a `config_epoch` other than the run id). Invalid ⇒ rerun same `(cond, scn, inj, seed)`, `rerun_of` set; originals
kept, excluded from analysis, counted in the reported flake rate. That key is exactly the run
ID's component set (`docs/07-glossary-and-ids.md` §Run & campaign IDs), so a rerun reproduces
its own grid cell and no other; it carries the injection condition for the same reason the
run ID does, since without it a rerun of one base cell silently replaces a different one.

An invalid **baseline** reruns on `(load_profile_id, seed)`, which is that identifier's
component set by the same rule and the key its uniqueness constraint is already stated on
(glossary, §Run & campaign IDs). The original is retained and excluded exactly as above; it
does not become a second baseline for that key, because it is marked invalid and the
uniqueness constraint the validator enforces reads only the campaign's valid bundles.
Invalidating a baseline invalidates nothing else on its own, but every framework-on run whose
`baseline_run_id` names it loses its second term until the rerun seals, so the RQ4 deltas for
those runs are recomputed against the rerun rather than reported from the discarded original.

## 5. Sanitization (before seal)

Strip/redact: `Authorization` headers, `api_key`-shaped strings, `.env` values, JWT signing
keys. Capability tokens in audit logs keep claims but redact signatures. Sanitizer is
unit-tested with planted secrets; a bundle failing the planted-secret test cannot seal.

## 6. QA cadence (during M7)

Daily during campaign: `make audit-verify` over new bundles; completeness sweep; spot-open
one bundle per condition; reconcile run counter vs manifest grid; log in campaign notes.

## 7. Storage, backup, retention

**Temporary v2 exception (researcher instruction, 2026-10-05; ADR-173):** cloud synchronization
is deferred during preparation and launch until an authenticated destination is supplied.
Keep the working VM copy, an independently verified local mirror and an independently verified
USB copy, with incremental backup and restore checks. Record cloud status as deferred; no
cloud copy is claimed. All other retention and integrity requirements remain in force.

`runs/` is gitignored. Three copies: working disk (WSL), cloud-drive sync of sealed bundles
(nightly), external disk (weekly) — except that, per the temporary v2 exception above (ADR-173),
the cloud-drive copy is currently deferred and the three copies actually kept are the working VM
copy, an independently verified local mirror and an independently verified USB copy. Verify restores once before GATE. The mechanism is
`scripts/backup_sync.sh`, written at M6; the one restore verification this rule requires
before GATE is performed at M6 against the synthetic corpus — free, disposable and present at
exactly the moment the check is due — while `docs/milestones/M7-campaign.md` T7.4 operates
the same script on the real sealed bundles (M6-C5). Retain everything through examination +
the artifact-archive period required by the university. Archive
retention (SLOT-DATA-02): **absent** — no archive-retention period exists in the submitted
chapters. Searched `IM2021088.txt` for: retention (0), archive / archival period (0),
retain (3 — "retained study to be traceable", "Retaining the low band", "message sequence
retained verbatim"; none concerns data retention), data protection / GDPR / delete /
"how long" (0 each), university / institution policy terms (all "university" hits are the
title page, the acknowledgements, and reference entries; both "institution" hits are
literature-search procedure prose). The retention owner is therefore the university's
artifact-archive policy, to be confirmed — supervisor question (binding-log §T0.6,
Flagged): confirm the required artifact-archive retention period. The public release
ships bundles or a documented subset per M9 decision.

## 8. Analysis reproducibility

`analysis/` reads only `runs/` raw files (never `metrics.json` caches, never live services).
`make analyze` on a clean checkout + `runs/` copy regenerates every table and figure (T-25).
Notebook cells are ordered-executable top-to-bottom; stats live in `analysis/stats/*.py`,
notebooks only render.
