# 04 — Repository Conventions & Environment

Status: active

## 1. Folder map (current tree, annotated; ★ = to create when first needed)

The convention is load-bearing in both directions: an unstarred entry exists in the working
tree **today**, a starred one does not yet and arrives with the milestone that needs it, and
an entry absent from the map is a defect in the map. `scripts/check_hygiene.sh` block (d)
asserts every unstarred top-level directory drawn below, so this map is executable rather
than decorative — it fails CI when it stops matching the tree.

```
agentic-overwatch/
├── AGENTS.md                 # AI-assistant context; carries the iron rules inline
├── CLAUDE.md                 # shorter alias of the same contract — no rules directory
├── Makefile                  # single entry point — §3; every recipe delegates to scripts/
├── pyproject.toml            # Python metadata + the repo's only ruff configuration (§3 `lint`)
├── .gitattributes            # line-ending normalisation (eol=lf), binding for every clone — §5
├── .gitignore                # the ignore rules §5 enumerates
├── .github/workflows/        # ci.yml, env-bringup.yml, self-scan.yml (§4)
├── scripts/                  # every gate's logic, runnable without make — see below
│   ├── lint.sh               # ruff check + ruff format --check        (make lint)
│   ├── verify_slots.sh       # unbound-marker gate + exemption cap     (make verify-slots)
│   ├── grep_guard.sh         # rule 10: no kubectl / k8s client under agents/
│   ├── check_hygiene.sh      # §1 and §5 as an executable check
│   ├── versions_env_sha256.py # LF-normalised sha256 of versions.env  (make versions-sha)
│   ├── install_cluster_tools.sh # kind/kubectl/helm/kustomize/cilium at the versions.env pins
│   ├── install_runtime_deps.sh # Python runtime dependencies at the versions.env pins
│   ├── monitor_guard.sh      # rule 40: no LLM call surface under monitor/; determinism tripwire
│   ├── monitor_replay.sh     # replay every fixture, or F=<id>          (make monitor-replay)
│   ├── monitor_determinism.sh # replay twice and diff bytes             (make determinism-check)
│   ├── monitor_render.sh     # offline Helm/Kustomize render of M2 Phase B surfaces
│   ├── monitor_image.sh      # build and kind-load the pinned aggregator image
│   ├── guardian_test.sh      # opa test plus the adversarial suite      (make guardian-test)
│   ├── audit_verify.sh       # hash-chain integrity over a path         (make audit-verify)
│   ├── policy_purity_grep.sh # rule: no arm or mode token under guardian/policies/
│   ├── prompt_purity_grep.sh # rule 20: no prompt text in agents/ code; registry reachability
│   ├── parity_check.sh       # prompt and tool parity gate             (make parity-check)
│   ├── agents_golden.sh      # golden path, S1-HIER × G0-FULL          (make agents-golden)
│   ├── scenario_determinism.sh # scenario half: plan twice, diff bytes (make determinism-check)
│   ├── scenario_guard.sh     # rule: no clock/cluster in planner; no agents/↔scenarios/ edge
│   ├── cve_mirror.sh         # CVE tarball mirror verify/save/load procedure
│   ├── blind_view.py         # strip arm tokens from a bundle for blind re-scoring
│   ├── score_bundle.py       # render worksheet + record human scores post-seal
│   ├── run.sh                # one grid run to a sealed bundle         (make run)
│   ├── baseline.sh           # one framework-off baseline to a bundle  (make baseline)
│   ├── campaign.sh           # validate, order and gate the grid       (make campaign)
│   ├── analyze.sh            # regenerate tables and figures from bundles (make analyze)
│   ├── backup_sync.sh        # three-copy sync + restore verify (R-09)
│   ├── preflight.sh          # host and pin readiness, before anything mutates
│   ├── up.sh                 # full bring-up, layer by layer           (make up)
│   ├── down.sh               # teardown leaving volumes intact         (make down)
│   ├── nuke.sh               # teardown including volumes              (make nuke)
│   ├── status.sh             # health over infra/status/components.yaml (make status)
│   └── netpol_proof.sh       # attributable NetworkPolicy denial       (make netpol-proof)
├── context/                  # README.md + dissertation chapters — read-only ground truth
├── docs/                     # canonical documentation; README.md is its entry point and map
│   ├── adr/                  # decision records, numbered, never renumbered
│   ├── milestones/           # work orders M0–M9 + GATE, one `active` at a time
│   ├── plans/                # execution plans, one per milestone, written when it goes active
│   └── protocols/            # binding methodology-as-checks documents
├── infra/                    # README.md, versions.env, kind-config.yaml, cilium/,
│                             # boutique/ (kustomize), locust/, observability/, audit/, netpol/,
│                             # probes/, collectors/, status/, tests/
├── monitor/                  # README.md, rules/ (falco), deploy/, trivy/, http_service.py,
│                             # aggregator/, fixtures/, tests/ — all landed at M2
├── guardian/                 # README.md, app/, policies/ (rego), token/, audit/, deploy/,
│                             # tests/ — all landed at M3
├── agents/                   # README.md; graphs/ ★, prompts/ ★, tools/ ★,
│                             # registry/ ★ (composer + parity logic), tests/ ★
├── scenarios/                # README.md; chaosmesh/, cve/, attackers/, groundtruth/,
│                             # manifests/, schemas/ — all landed at M5
├── runner/                   # README.md; ids/grid/manifest/validate/order/bundle/sanitize/
│                             # synthetic/conditions/run/baseline/campaign CLIs, tests/ — landed M6
├── analysis/                 # README.md; stats/, render.py, notebooks/, tests/ — landed at M6
└── runs/ ★                   # run bundles — gitignored, backed up per data-management
```

Every component directory carries a `README.md` naming what it will hold and the milestone
that fills it, so a directory standing empty before its milestone still explains itself.
Component tests live inside each component (`<component>/tests/`), runnable standalone.

`docs/` is the only editable documentation source. The Starlight site (ADR-047) has been
removed from the repository along with its build workflow: authors never maintain a copied,
generated, synchronized or symlinked Markdown tree, because there is nowhere to mirror it.

`scripts/` holds the logic behind every implemented gate. The Makefile (§3) is a table of
one-line delegators, and `ci.yml` (§4) invokes the same scripts directly rather than through
`make`, so each gate is defined once and runs identically from `make` in WSL2, from Git Bash
on the Windows host — which has no `make` at all — and on the CI runner. Adding a gate means
adding a script here plus a one-line target there; never logic inside a recipe or a workflow
step.

One gate qualifies that rule, and it is named here so this section and the parity protocol do
not contradict each other. The prompt-parity check's logic lives in `agents/registry/` rather
than in `scripts/`, because the check must count exactly the bytes a graph sends: a checker with
its own rendering path would measure a prompt no run ever used, so the composer is agent-layer
code shared by the gate and the runtime. What this section requires is still satisfied —
`scripts/parity_check.sh` is the one-line entry point, `make parity-check` and `ci.yml` both
reach the gate through it, and no check logic sits in a recipe or a workflow step.
`protocols/prompt-parity-policy.md` §3 owns the decision and its reasoning; conflict M4-C2,
ADR-027.

### Operator scripts (not gates)

Five files under `scripts/` are operated by a human before and after a live run rather than
invoked as a gate, so none of them has a Makefile target: §3's table is the contract for the
gates, and an operator convenience that appeared there would claim a status it does not have.
They are listed here instead, and each carries its own header block explaining why it exists.

| Script | What it does |
|---|---|
| `scripts/live_env.sh` | **Sourced**, not executed. Composes the full environment `runner/live_run.py`'s `dependencies_from_environment()` fails closed without — cluster coordinates, the four port-forwarded URLs, the three evidence paths, and the five Guardian capability-token settings, which it reads from `protocols/security-policy.md` §2 through `scripts/security_params.py` rather than restating |
| `scripts/security_params.py` | Extracts those five settings from `protocols/security-policy.md` §2 and prints them as shell assignments. Has no defaults and fails loudly when an anchor stops matching, so a reworded §2 produces a diagnostic rather than a stale number |
| `scripts/port_forward.sh` | `up` / `status` / `down` over the four endpoints a live run reaches (Guardian, boutique frontend, Prometheus, Locust). Pid-file tracked, so `down` stops only the forwarders it started |
| `scripts/run_quarantine.sh` | Moves an **unsealed** crashed attempt to `runs/.quarantine/` so its grid cell can be re-run. It never touches a sealed bundle: `protocols/data-management.md` §4 retains an invalid run and records the invalidity in its manifest, and the runner's refusal to reuse a bundle directory is a safety property this script routes around rather than weakens |
| `scripts/score_bundle.py` | Renders the rubric, scenario ground truth and blind evidence into a worksheet outside the sealed bundle, then records only explicitly supplied human judgements in schema-validated `scores.json` and appends its hash through `runner.bundle.append_scoring_entry` |

Not drawn above, and deliberately so: `.ruff_cache/` and `.venv/` exist on the development
host but hold nothing tracked. They are local tool state, not repository structure.

## 2. Development environment (Windows host)

All cluster tooling runs in **WSL2 Ubuntu** — Falco (modern eBPF, kernel ≥5.8) and Cilium
need a real Linux kernel; the WSL2 kernel qualifies. Setup once:

1. Docker Desktop with WSL2 backend enabled for the Ubuntu distro.
2. In WSL2: `kind`, `kubectl`, `helm`, `kustomize`, `cilium` CLI, `opa`, `python3.12`, `make`.
3. **Filesystem**: `C:\agentic-overwatch` is reachable at `/mnt/c/agentic-overwatch`, but
   cross-boundary I/O is slow and can break file-watchers. Recommended: clone the repo inside
   WSL2 (`~/agentic-overwatch`) and treat the Windows path as the editor's view (VS Code
   Remote-WSL / opencode inside WSL). If you keep it on `C:\`, run `make` from WSL anyway, and
   **export `OVERWATCH_EVIDENCE_DIR` to a WSL ext4 path before `make up`** (e.g.
   `export OVERWATCH_EVIDENCE_DIR=$HOME/overwatch-evidence`). The Monitor evidence directory is a
   kind hostPath that every ingested request writes into; through the 9p bridge one small write
   measured ~115 ms from inside a node against ~5 ms on ext4, enough for the aggregator to fall
   behind its ingestion rate and be liveness-killed under run load. `up.sh` warns when the
   directory is under `/mnt/`, records what the cluster mounted in `runs/.cluster-evidence-dir`,
   and `scripts/live_env.sh` reads that record. The mount is fixed at cluster creation (ADR-057).
4. Known friction (ADR-001): bump `fs.inotify` sysctls for kind+Cilium; mount bpffs if Falco
   modern_ebpf complains. Record fixes in ADR-001's log as encountered.
5. Host memory, via `%USERPROFILE%` + `\.wslconfig`. With no such file present the WSL2 utility
   VM defaults to half of host RAM, and that VM is *shared* by the Ubuntu distro and by
   `docker-desktop`, which is where kind's node containers actually run. On the development host
   that measured 7 GB total, against an M1 steady state -- kind, Cilium, eleven Boutique
   services, Prometheus, kube-state-metrics, Grafana and Locust -- of roughly 3.5-4.5 GB, before
   M2 adds Falco. The setting below caps the whole utility VM, so one number covers both distros:

   ```ini
   [wsl2]
   memory=10GB
   processors=8
   swap=4GB
   autoMemoryReclaim=gradual
   ```

   Ten rather than twelve: twelve would leave a 15.6 GB host about 3.6 GB for Windows 11, Docker
   Desktop and an editor, which Windows alone idles close to. Apply it with `wsl --shutdown`,
   which restarts the utility VM. The file lives outside the repository and therefore cannot be
   committed -- it is documented here and logged in ADR-001 instead, the same treatment step 1's
   Docker Desktop toggle gets and for the same reason.

Step 2's tool list is executable rather than advisory: `sh scripts/install_cluster_tools.sh`
installs every one of those tools at the versions `infra/versions.env` pins, and
`.github/workflows/env-bringup.yml` runs that same script on a clean runner -- so the developer
setup path and the evidence path cannot drift apart. `opa` is deliberately not in that script:
it belongs to the Guardian and arrives with M3.

Node is not required for cluster, experiment or analysis work, and no Node package enters
`infra/versions.env`.

## 3. Makefile target spec (implemented in M0–M6; behavior is the contract)

| Target | Contract |
|---|---|
| `make help` | list every target with its one-line description — the default goal, so bare `make` prints it |
| `make up` / `make down` / `make nuke` | full env from `infra/versions.env` on clean machine / teardown / destroy incl. volumes. `up` reads `UP_PROFILE` (`full`, the default, or `substrate`) and brings up only the components whose `required_in` in `infra/status/components.yaml` admits it — `substrate` omits the Guardian (ADR-148). Nuke requires interactive confirmation or `FORCE=1` and explicitly removes only the repo-owned Langfuse Postgres, ClickHouse, Redis and MinIO bind-mount directories in addition to kind and its labelled Docker residue; it rejects symlinked state ancestors and never removes `runs/` or other repository content |
| `make status` | health summary over the component set declared in `infra/status/components.yaml` -- one line per component; each row has an explicit `landed` deployment state, and the same change that authors its deployable workload must flip that state to `true` and complete its health-check coordinates. `status` reads the same `UP_PROFILE` as `up` and reports a component the profile omits as `not-required` (not `absent`), naming the profile on its summary line. A landed unhealthy component fails; an unlanded later component reports `not-deployed` and does not. Milestone workflow status (`active`, `gated`, `done`) is deliberately not deployment state, because partial M2/M3 work must not make an M1 bring-up fail. The declared set is what keeps the summary **total**: `protocols/evaluation-protocol.md` §5 rule 1 makes a green `status` the preflight gate for every run, so a summary that silently omitted an absent component would still pass at M7 with the Guardian down (ADR-044) |
| `make netpol-proof` | the attributable NetworkPolicy denial, same-node and cross-node -- Cilium is the only CNI, a positive control, a denial whose failure *mode* is asserted, a `Policy denied` drop attributed to the policy engine, then reversal (ADR-014). Needs a running cluster, so it is neither part of `make up` nor a `ci.yml` check |
| `make monitor-replay [F=<fixture>]` | replay the fixture corpus through the aggregator and assert schema-valid `EvidenceEvent`s within the §4 latency budget. **`F` is optional**, and that is a correction, not a convenience: the row previously read `F=<fixture>` as though it were required, while `M2-monitor.md`'s Definition of done asks for a replay "over all fixtures" and the playbook's verify card for one "against every fixture" — so no invocation satisfied the DoD as the contract was written (M2 plan conflict M2-C2). With no `F` it replays every fixture; with `F=<id>` it replays that one, which is what a developer iterating on a single normaliser wants |
| `make guardian-test` | `opa test` over `guardian/policies/` — **pass rate and a coverage floor, both printed** (M3 plan conflict M3-C9; "100%" alone conflates two different claims) — plus the adversarial suite, in which every case asserts three things: denied, with a structured reason code, and present in the audit chain. Both halves are mandatory: an absent or unrunnable adversarial suite fails the target. The script acquires the pinned `opa` binary with a checksum check; callers must provide pytest and the Guardian's pinned runtime dependencies (ADR-025 follow-up). |
| `make agents-golden` | golden-path scenario end-to-end on dev model tier |
| `make run COND=<id> SCN=<id> INJ=<id> SEED=<n>` | one grid run → sealed bundle in `runs/`; the four parameters are exactly the four grid coordinates the run ID carries |
| `make baseline LOAD=<id> SEED=<n>` | one framework-off baseline run → sealed bundle in `runs/`; a separate target because a baseline occupies no arm, scenario or injection condition |
| `make campaign M=<manifest> SAMPLES=<n>` | interleaved grid per evaluation-protocol; a live campaign takes exactly one of `SAMPLES=<n>` or `DURATION=<s>`, as `make run` does |
| `make analyze` | regenerate all metrics/figures from raw bundles only |
| `make parity-check` | prompt/tool parity per prompt-parity-policy (CI-blocking) |
| `make determinism-check` | replay twice and diff the bytes. **The target has two halves, both now landed**: the Monitor half at M2 — every fixture replayed twice, emitted streams compared with `cmp`, which is what `.agents/rules/20-parity-and-determinism.md` and NFR2 require of the aggregator — and the scenario half at M5, each scenario planned twice per seed, the injected sequences diffed with `cmp` and failing closed on an empty corpus (conflict M5-C1). Running the target executes whichever halves exist; each half reports itself by name, so a green result never conceals a half that was skipped. The nightly CI step stays armed on the five `scenarios/` content directories alone (§4), because M2's coverage rides the `monitor/tests/**` pytest step, which arms on its own |
| `make verify-slots` | fail if any unexempted `⟦VERIFY-DISSERTATION` marker remains in any tracked file <!-- verify-slots:ignore --> |
| `make versions-sha` | print the sha256 of `infra/versions.env`, CRLF normalised to LF before hashing |
| `make lint` | `ruff check` plus `ruff format --check` over the repository (CI-blocking) |
| `make audit-verify [P=<path>] [HEAD=<sha256>]` | Guardian hash-chain integrity. **`P` is optional and defaults to `runs/`**, which is a correction rather than a convenience: the row previously named `runs/` alone, but that directory is gitignored and stays empty until M6 seals the first bundle — while M3's Definition of done requires this target to pass, and the playbook's verify card already assumes a file-level invocation ("tamper with one line in a `guardian_audit.jsonl`"). As specified, no invocation satisfied both (M3 plan conflict M3-C4). `HEAD` is the expected chain head from `seal.json`: an unsigned hash chain detects mutation, deletion, insertion and reordering on its own, but **not** tail truncation or a whole-chain rewrite, because an attacker who can write the file recomputes every hash forward from the cut. The anchor is what closes that, and the tamper tests show truncation caught with it and missed without it (ADR-022) |

## 4. CI (`.github/workflows/`)

Three workflows have distinct contracts. `ci.yml` is the **per-change check list** every pull
request runs; `env-bringup.yml` is the **fresh-clone environment proof**, added at M1-T1.7; and
`self-scan.yml` is the supply-chain self-scan (ADR-115, `scripts/self_scan.sh`). The four-job
rule below is a rule about `ci.yml` specifically — it governs
what appears on every pull request, which is what makes a permanently-skipped entry noise. A
separate workflow is not a fifth entry in that list: when its paths filter does not match it is
absent rather than skipped.

### 4.1 `ci.yml` — the per-change check list

Triggers: every pull request; every push to `main`; `workflow_dispatch`, so a check that went
red for an environmental reason can be re-run without manufacturing a commit; and a nightly
`schedule`, deliberately off the hour, which is what arms the determinism check below.
Permissions are `contents: read` — nothing in the workflow writes to the repository.
Concurrency is per-ref with `cancel-in-progress`, so a rapid push stream cancels its own
superseded runs. Only first-party actions are used: `actions/checkout` in every job and `actions/setup-python` in lint and (guarded) hygiene (d7cac79 — PEP 668 isolation; interpreter version read from PYTHON_VERSION in `infra/versions.env`, packages remain pinned in their existing single homes). Every other tool is installed by `python -m pip`, pinned literally in the workflow (`ruff`, `pytest`) or read from `infra/versions.env` via `scripts/install_runtime_deps.sh`. Hygiene's guarded pytest/Guardian-runtime installs are the ADR-025 follow-up (2026-08-27) exception to toolchain grouping; OPA remains self-acquired with checksum by `scripts/guardian_test.sh`, so no third-party code runs with the
repository token.

Four named jobs, so a red check names the failure instead of burying it in one mega-job. Every
job delegates to a script in `scripts/`; no check logic lives in the workflow file, so a red
check reproduces locally with one command and does not depend on `make` (§1).

| Job | Always runs | Guarded steps, and what arms each |
|---|---|---|
| `lint` | `sh scripts/lint.sh` — `ruff check` plus `ruff format --check` (§3 `lint`) | per-component `pytest`, one step each for `infra/`, `monitor/`, `guardian/`, `agents/`, `runner/`, `analysis/`, armed by `hashFiles('<component>/tests/**')`; `sh scripts/install_runtime_deps.sh`, armed by `hashFiles()` over the test directories of the components that **have** a runtime dependency (`monitor/`, `guardian/`, `analysis/` — deliberately not the six-way union above, since `infra/`'s tests need nothing beyond the standard library, and, unlike `analysis/`, neither does `scenarios/`'s determinism corpus), and invoked with no argument so it installs every component whose code is present rather than from a list somebody must remember to extend; it installs the **runtime** dependencies of the evaluated artefact from `infra/versions.env` — as opposed to the `ruff` and `pytest` *tool* pins above, which ADR-011 keeps as literals because they are not part of it (ADR-021) — `analysis/` being M6's turn at that same one-commit procedure, its `pandas`, `statsmodels` and `matplotlib` pins, the installer line and this arming landing together (M6-C4, ADR-043); and the nightly `make determinism-check`, armed by the `schedule` event **and** `hashFiles()` over the five content directories §1 draws under `scenarios/` (`chaosmesh`, `cve`, `attackers`, `groundtruth`, `manifests`) — deliberately not `scenarios/**`, which `scenarios/README.md` already satisfies |
| `slots` | `sh scripts/verify_slots.sh` — **blocking** | `continue-on-error` re-arms only while a file exists at `docs/.slots-advisory`; none does, so a slot regression fails the build rather than logging an annotation |
| `guardrail-grep` | four always-runs guards, one per enforceable boundary. `Rule 10 grep guard` — `sh scripts/grep_guard.sh`, no kubectl or Kubernetes-client import under `agents/`; `Rule 40 monitor guard` — `sh scripts/monitor_guard.sh`, no LLM call surface under `monitor/`, plus a determinism tripwire over `monitor/aggregator/`; `Prompt purity grep` — `sh scripts/prompt_purity_grep.sh`, added at M4 for rule 20's boundary: no prompt-shaped literal under `agents/graphs/` or `agents/tools/`, no registry block that no composition manifest reaches, and no tool whose documentation block is absent; and `Scenario boundary guard` — `sh scripts/scenario_guard.sh`, added at M5: (a) no clock or unseeded draw in the planner, (b) the plan/apply split with cluster access only in the applier, and (c) no import edge between `agents/` and `scenarios/`. All four handle their own pre-milestone vacuous pass, so none carries a `hashFiles()` guard that could go stale, and none should: a boundary is enforced from before the first line of code it governs exists — and a guarded purity check would be armed by the very files it polices, which is the wrong way round | `Prompt parity check` — `make parity-check`, armed by `hashFiles('agents/prompts/**')`. **Armed at M4**, this being the milestone that puts the first file under that path, and the target it reaches is a real delegator to `scripts/parity_check.sh` rather than the stub that would have failed the job. It can pass inside a job that installs nothing because the checker under `agents/registry/` is standard-library only — conflict M4-C1, answered by needing nothing rather than by acquiring it (ADR-028) |
| `hygiene` | `sh scripts/check_hygiene.sh` — §1 and §5 as an executable check | `make guardian-test` — `opa test` plus the mandatory adversarial suite (§3) — armed by `hashFiles('guardian/policies/**/*.rego')`. The guarded path installs pinned pytest plus the Guardian runtime dependencies so the adversarial half cannot be skipped as unrunnable; `scripts/guardian_test.sh` still acquires and checksum-verifies OPA itself, keeping that evaluated binary on the same path locally and in CI (ADR-025 follow-up). |

A gated check is always a step, never a job: a job whose `if` is false still appears on the
pull request as a skipped entry, and the four-job shape exists precisely to keep that list
free of permanent noise.

Guarded steps are the deliberate pattern — the contract is written down once, now, and
self-activates the moment its input first exists, with no future "turn it on" edit to forget.
Each guard therefore also places an obligation on the milestone that first satisfies it, and
until then only the always-runs column can fail a pull request:

- **Per-component unit tests** — inert steps that activate as each component's tests land:
  infra M1, monitor M2, guardian M3, agents M4, runner M6, analysis M6.
- **`make parity-check`** (M4) — the glob matches *any* tracked file under `agents/prompts/`,
  including a placeholder, so M4 must implement the target in the same commit that puts the
  first file there. **Discharged at M4**, along with the second obligation this step carries and
  the four-job shape creates: it runs in a job with no dependency install, so the checker it
  reaches has to be standard-library only (conflict M4-C1). That is the same
  install-in-a-job-that-has-none pressure ADR-025 answered for `opa`, met here in the stronger
  form — not "acquire it yourself" but "need nothing".
- **`make determinism-check`** (M5) — same shape, but the guard is scoped: the first tracked file
  under any of the five content directories §1 draws beneath `scenarios/` arms the nightly run, so
  the target must be implemented in that commit. It is deliberately NOT armed by
  `hashFiles('scenarios/**')`, which `scenarios/README.md` already satisfies — that glob would
  have fired the stub on the first scheduled run. A guard must test for the corpus, not for the
  directory that will hold it, because the README announcing a directory always lands first.
- **`make guardian-test`** (M3) — scoped to `*.rego`, so it arms with the first real policy. Its
  adversarial half is mandatory; the guarded CI path installs pytest and the Guardian runtime set
  before invoking it, and an unavailable suite is a failure rather than a partial success.
- **Runtime dependencies** (M2 onward) — `scripts/install_runtime_deps.sh` reads `infra/versions.env`, so the
  milestone that introduces a component's first runtime dependency adds the key there and the line in that
  script together, and widens this step's guard in the same commit. M2 armed it for `monitor/`; M3 added
  `guardian/`. **Both M3 guards trip in one commit and originally failed for a dependency reason
  rather than a code reason.** The lint job installs the Guardian runtime set before
  `pytest guardian/tests`; the hygiene job now installs pytest and that same runtime set before the
  combined gate, while the gate itself acquires checksum-verified OPA. Implementing the target and
  making both invocation environments runnable therefore belong to the same arming change
  (ADR-025 and its follow-up).

### 4.2 `env-bringup.yml` — the fresh-clone environment proof (M1-T1.7)

Triggers: `pull_request` **with a paths filter** on `infra/**`, `scripts/**`, `Makefile` and the
workflow itself, so it runs exactly when the bring-up surface changes and is absent from the
check list otherwise; `workflow_dispatch`, for on-demand proof from any branch, which is how the
first evidence run is produced before a branch has a pull request; and a weekly `schedule`, off
the hour, which catches upstream rot no commit of ours causes — a yanked chart version, a digest
that stops resolving, a withdrawn release asset.

| Runs | What it establishes |
|---|---|
| `sh scripts/install_cluster_tools.sh` | the tooling installs **from `infra/versions.env`**, not from literal pins |
| `sh scripts/preflight.sh`, then `make up`, `make status` — all under `UP_PROFILE=substrate` | traceability row T-16 — the environment reconstructs on a machine that has never seen this repository |
| `sh scripts/netpol_proof.sh` | M1's NetworkPolicy Definition-of-done item, which supports row T-11 |
| a smoke drive of the SLO probe and the resource collector | the two writers produce their `protocols/data-management.md` §1 schemas against a real cluster, which unit tests over fixtures cannot reach |
| `make down`, `make up`, `make status`, then `FORCE=1 make nuke` — the round trip under `UP_PROFILE=substrate` too | the teardown/bring-up round trip converges, and teardown works even after a failure |

Two rules bind this workflow specifically:

- **The tool pins come from `infra/versions.env`, deliberately breaking ADR-011's literal-pin
  rule.** ADR-011 keeps `ruff` and `pytest` as literals because a linter and a test runner are
  not part of the evaluated artefact. `kind`, `kubectl`, `helm`, `kustomize` and the `cilium` CLI
  *are* part of it — NFR1 asserts the environment reproduces from a clean machine — so reading
  their versions from the pins file is not a convenience but the claim under test. ADR-017.
- **It must never be a required status check in branch protection.** A required check belonging
  to a path-filtered workflow reports as permanently pending on every pull request the filter
  does not match, and a pending required check blocks the merge — so requiring it would block
  every documentation change, and the failure would read as a stuck queue rather than as a
  misconfiguration. `ci.yml`'s four jobs are the required set.

This workflow runs the **substrate profile** (`UP_PROFILE=substrate`, ADR-148). That profile
brings up layers 1–9 and 11–12 — kind, Cilium, Boutique, the chaos tooling, Locust, the
observability trio and Falco — and deliberately skips layer 10, the Guardian, because the
Guardian cannot come up on a hosted runner: `scripts/guardian_deploy.sh` refuses without
`guardian-signing-key`, and ADR-114 forbids every repository path — chart value, ExternalSecret,
installer — from creating that key. Bending ADR-114 to satisfy CI was rejected; stating the
profile honestly was chosen instead. Under this profile `make up` skips the Guardian layer with
a `progress` line naming the skip, and `make status` counts the Guardian `not-required` rather
than `absent` (its `required_in: full` in `infra/status/components.yaml` excludes it). The
Guardian stays proven on the VM and in P0-live, which is where a live Guardian is actually
needed. The three profile-sensitive steps — `make up`, `make status`, and the round trip — set
the same `UP_PROFILE` and must change together; a `make status` under a different profile than
its `make up` would assert over a component set this workflow never built.

### 4.3 Documentation site — removed (ADR-047)

The read-only documentation validation this section used to describe is gone with the site
it validated. What stood here — the preparatory workflow, its path filters, its Node setup,
its npm install / loader tests / Astro checks / production build / output verification
through `scripts/docs_build.sh`, and the `make docs-build` target — was deleted from the
repository rather than left to fail. To resurrect it, restore the tree, the script, the
workflow and the target from git history.

Like `env-bringup.yml`, a path-filtered workflow must not be a required branch-protection check:
an unmatched path filter otherwise leaves a required check permanently pending. The four jobs in
`ci.yml` remain the required per-change set. The documentation site that a third workflow once
validated (ADR-047) has been removed, so §4 has no third workflow to describe; the two sections
that named it survive in git history with the site itself.

## 5. Git hygiene

`.gitignore` must include: `.env`, `runs/`, `**/__pycache__/`,
`.venv/`, `*.key`, Langfuse volumes. Node tooling is gone with the site, so there is no
longer a `node_modules/` rule to keep. Decide before any public push whether `context/` (dissertation
chapters) is included. Decision taken at M0 (risk R-13): `context/` stays **tracked** and
the repository stays private until submission; re-decide at M9-T9.4 before any public
push. Kit references remain valid whether the folder is tracked or ignored.

Branches: `main` protected; feature branches `m<N>/<slug>`. Commits: Conventional Commits
(`feat(guardian): …`). Every merged decision references its ADR. Tags: `v1.0-rc` at M6,
`v1.0` at pilot-gate freeze, `v1.x` hotfixes only.

## 6. Config strategy

Static config per component in-tree (YAML), values only from `infra/versions.env` +
run manifests. Secrets: `.env` (dev) / K8s Secrets (in-cluster) — never in YAML, never
in prompts, never echoed into run bundles (bundle sanitizer strips `Authorization` and
key-shaped strings; see data-management §5).
