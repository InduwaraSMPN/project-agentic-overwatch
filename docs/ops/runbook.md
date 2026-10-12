# Operator Runbook - Agentic Overwatch (v1.0)

Status: signed-off - technical review pass 2026-09-23 against the landed chart and a live throwaway
deploy (commands corrected: management-namespace install, evidence host-dir/PVC prerequisites,
mode-flip auto-restart, audit-PVC retention, re-install collisions in Sec.5.6); operator follow-through
recorded in Sec.7 (2026-09-23, `pasindunaduninduwara`). M8-T8.3 - Scope: operating the frozen `v1.0`
artifact on a foreign cluster.
Serves matrix row T-29. Packaging and operations only - `AGENTS.md` iron rule 6 and
`docs/protocols/security-policy.md` Sec.5 both forbid any change to agent, Guardian, Monitor or
scenario behavior from this document or from anything it tells you to run.

Companion documents, each authored alongside this one and referenced by path rather than
restated here (single-homing, per `.agents/rules/00-source-of-truth.md`):

- `docs/ops/secrets.md` - the Guardian signing key and every other credential: creation,
  storage, rotation.
- `docs/ops/shadow-mode.md` - the full shadow-mode design rationale. Sec.3 below gives the
  step sequence; that document gives the "why".
- `docs/ops/sbom.md` - SBOM generation and the Trivy self-scan of this project's own images.
- `docs/ops/guardian-ha.md` - why the Guardian runs as a single replica and what that costs.

If any of the four is not yet present when you read this, treat the section below that would
normally point into it as the interim source and flag the gap - do not guess at its content.

## 0. Read this before you deploy anything

**`G1-LOGONLY` is not an observe-only mode.** Under `G1-LOGONLY` the Guardian evaluates every
`ActionRequest` exactly as it does under `G0-FULL` and writes the same `AuditRecord`, but a
`deny` decision does **not** block the action - it is followed by execution
(`docs/02-architecture.md` Sec.3, `AuditRecord.enforcement`; ADR-023). In the audit log this
shows up as `decision: deny, enforcement: executed`. If you deploy in `G1-LOGONLY` believing it
is a safe, no-effect "watch first" mode, the agent layer has full write access to your cluster
from the first request it sends. The only things containing a `G1-LOGONLY` deployment are:

1. `guardian/deploy/rbac.yaml`'s least-privilege Role - no `pods/exec`, no `secrets` verbs, no
   wildcard, and every mutating verb confined to one namespace;
2. `infra/netpol/guardian-ingress.yaml` and the agent-namespace default-deny NetworkPolicy
   (ADR-076) - nothing outside the `agents` namespace can reach the Guardian's mediation
   surface, and nothing in `agents` can reach the Kubernetes API directly;
3. a target you can afford to have mutated while you are reviewing.

Do not run `G1-LOGONLY` against a namespace or cluster that does not satisfy all three. Section
3 gives the deploy-and-review sequence that this constraint governs.

**Everything below assumes:**

- You are deploying to a cluster that is **not** the dissertation's evaluation cluster. The
  evaluation cluster's `guardian_audit.jsonl` chains, `runs/` bundles and `main` checkout are
  read-only to operations; nothing here is a substitute for `docs/protocols/data-management.md`.
- `deploy/helm/agentic-overwatch` is the Helm chart authored alongside this runbook (M8-T8.1;
  design record `docs/adr/ADR-113-helm-chart-packaging.md`). It templates the Guardian
  (`guardian/deploy/*.yaml`) and the Monitor evidence aggregator plus audit forwarder
  (`monitor/deploy/*.yaml`), and the `agents` namespace's NetworkPolicy/RBAC boundary
  (`infra/netpol/agents-*.yaml`, `guardian/deploy/g2-rbac.yaml`). **It does not deploy an
  agent-layer workload.** `infra/status/components.yaml` and the chart's own `values.yaml`
  agree on why: Executors are ephemeral by construction and the Orchestrator/Supervisors are a
  graph a process drives for the duration of an incident, not a standing Deployment - the
  `agents` namespace this chart creates is the boundary that (host-driven) process runs inside
  of, not a workload the chart starts for you. See Sec.6 for what this means for "deploy" as a
  word. The chart also does **not** vendor Falco, Prometheus/Alertmanager, kube-state-metrics
  or Grafana - those are cluster prerequisites you install yourself, listed in Sec.1.1. Values
  are `deploy/helm/agentic-overwatch/values.yaml`; every `--set` key below is taken from that
  file as it stood when this runbook was written; re-check the file for the current shape
  before you rely on a key this document did not test.
- `kubectl`, `helm` and `python3` are on `PATH`, at or above the floors in `infra/versions.env`
  (`KUBECTL_VERSION`, `HELM_VERSION`; that file also pins the platform prerequisites named in
  Sec.1.1). You have a working kubeconfig context for the **target** cluster - never the
  evaluation cluster's context - and every command below is written to name that context
  explicitly (`$KCTX`) rather than rely on whatever `kubectl config current-context` happens to
  return.

---

## 1. Deploy

### 1.1 Prerequisites

The chart deploys the Guardian and the Monitor evidence aggregator/audit-forwarder, plus the
`agents` namespace's network and RBAC boundary - not a running agent-layer workload (Sec.0, Sec.6).
Everything else in the architecture diagram (`docs/02-architecture.md` Sec.5) is a platform
prerequisite the operator brings. Version floors below are the versions this artifact was evaluated
against
(`infra/versions.env`); install a version at or above each unless you have a specific reason not
to, and record the deviation.

| Prerequisite | Why the Guardian/Monitor need it | Version floor (source) |
|---|---|---|
| Kubernetes cluster, NetworkPolicy-enforcing CNI (Cilium in the reference deployment) | Sec.1.2's NetworkPolicy step is a no-op, silently, on a CNI that does not enforce `NetworkPolicy` | `KUBECTL_VERSION=v1.36.4`, Cilium `CILIUM_CHART_VERSION=1.20.1` if you use Cilium |
| Falco (+ Falcosidekick) | syscall-level Monitor signal source | `FALCO_CHART_VERSION=8.0.1`, `FALCOSIDEKICK_VERSION=0.12.1` |
| Prometheus + Alertmanager + kube-state-metrics | metric-anomaly Monitor signal source | `PROMETHEUS_CHART_VERSION=29.27.0`, `ALERTMANAGER_VERSION=1.35.0`, `KUBE_STATE_METRICS_VERSION=8.4.0` |
| Kubernetes audit logging enabled on the API server | fourth Monitor signal family; a kube-apiserver flag, not a chart | n/a - cluster-admin configuration, operator TODO: confirm your managed-Kubernetes offering exposes audit-log webhook/log-file delivery |
| Trivy (for `docs/ops/sbom.md`'s self-scan, not for runtime) | image scanning of this project's own images, not a runtime dependency of the deployed system | `TRIVY_VERSION=0.69.3` |
| A signing-key Secret for the Guardian | JWT capability-token signing (HS256, `security-policy.md` Sec.2) | see `docs/ops/secrets.md` - the chart references this Secret by name, it never creates or contains one |
| A target application namespace | what the agent layer is authorized to act on | operator-supplied; the reference deployment uses `boutique` |

Confirm the Guardian's own least-privilege RBAC before trusting any of this: `guardian/deploy/rbac.yaml`
is what the chart re-templates with the namespace parameterized (per the M8 chart design), and the
chart's rendered-output test diffs it verb-for-verb against that file so a chart cannot silently
widen it. You can read the source of truth directly:

```
kubectl -n guardian --context "$KCTX" describe role guardian
kubectl -n guardian --context "$KCTX" describe clusterrole guardian   # read-only cluster scope only
```

### 1.2 Namespaces and the signing key

The chart's `values.yaml` names four namespaces, each overridable: `namespaces.guardian`
(default `guardian` - the Guardian workload and its audit PVC), `namespaces.monitor` (default
`monitor` - the evidence aggregator and audit forwarder), `namespaces.agents` (default `agents`
- the only namespace `infra/netpol/guardian-ingress.yaml` admits into the Guardian's mediation
surface, ADR-076; no workload runs here by default, see Sec.0), and `namespaces.boutique`
(default `boutique`). The first three are created by the chart when the matching
`namespaces.create.*` flag is `true` (default). **`boutique` is deliberately never created by
this chart** - it must already exist, exactly as `infra/boutique/kustomization.yaml` declines to
create it for the same reason ("a Namespace declared in this overlay would itself be stamped
into the namespace it defines"). Deploy your target application, or otherwise create this
namespace, before `helm install` - the Guardian's namespaced RoleBinding targets it and fails
loudly on install if it is absent.

Create the Guardian's signing-key Secret out of band, per `docs/ops/secrets.md`. The chart never
generates, contains or defaults this value - `guardian/app/config.py` prefers
`GUARDIAN_SIGNING_KEY_FILE` (a projected Secret volume mount) over an inline environment
variable, and the deployment manifest mounts exactly that shape
(`guardian/deploy/deployment.yaml`: `signing-key` volume at
`/var/run/guardian-secrets/signing-key`, `readOnly: true`). Verify it exists before installing:

```
kubectl -n guardian --context "$KCTX" get secret guardian-signing-key
# absent -> stop here and follow docs/ops/secrets.md before proceeding
```

### 1.3 Install

`guardian.token.*` has **no chart default** - `templates/guardian/configmap-runtime.yaml` uses
Helm's `required` on every one of its five fields and fails the render rather than guess. Copy
the current numbers from `docs/protocols/security-policy.md` Sec.2 (the same numbers
`scripts/security_params.py` extracts for the evaluation harness) into your own values override
file rather than typing them inline on every install - call it `my-values.yaml`:

```yaml
guardian:
  mode: G1-LOGONLY            # see Sec.0 and Sec.3 - not G0-FULL on first install
  registeredIssuers: ""       # comma-separated Supervisor ids; blank denies every token (deny-by-default)
  executor: kubernetes        # "fake" mediates and executes nothing - do not use it for a real deployment
  auditLogPath: /var/lib/guardian/audit/<operator-chosen-name>.jsonl   # REQUIRED, no default - pick once, see Sec.2.4/5.5
  token:
    ttlSeconds: <copy from security-policy.md Sec.2>
    maxTtlSeconds: <copy from security-policy.md Sec.2>
    algorithm: <copy from security-policy.md Sec.2>
    replayCacheEntries: <copy from security-policy.md Sec.2>
    replayCacheWindowSeconds: <copy from security-policy.md Sec.2>
  image:
    repository: <your registry>/agentic-overwatch/guardian   # default agentic-overwatch/guardian:local, pullPolicy Never, is kind-only
    tag: <your build tag or digest>
    pullPolicy: IfNotPresent
monitor:
  image:
    repository: <your registry>/agentic-overwatch/evidence-aggregator
    tag: <your build tag or digest>
    pullPolicy: IfNotPresent
```

The chart creates the `guardian`, `monitor` and `agents` namespaces itself (with their Pod
Security Standards labels). Install the release into a **separate management namespace** - not
`guardian`/`monitor`/`agents`/`boutique` - so Helm's `--create-namespace` does not collide with
the chart's own Namespace objects: a namespace Helm creates for the release is not release-owned,
and the chart's same-named Namespace object then cannot be adopted (`Namespace "guardian" ...
exists and cannot be imported into the current release`). `overwatch-system` below is any name the
chart does not template. All `helm` subcommands in this runbook name that release namespace;
`kubectl` commands name the resource's own namespace (`-n guardian`, `-n monitor`, ...).

```
helm install overwatch deploy/helm/agentic-overwatch \
  --kube-context "$KCTX" \
  --namespace overwatch-system --create-namespace \
  -f my-values.yaml \
  --wait --timeout 5m
```

**In `hostPath` evidence mode (the default), create the evidence directory on the node first**, or
`--wait` will time out with the Monitor pods stuck `Init:0/1` on a `FailedMount` (`hostPath type:
Directory` requires the path to pre-exist): the reference bring-up (`scripts/up.sh`/`make up`)
creates `/var/lib/overwatch/evidence` on the node. On a foreign cluster prefer the PVC mode below,
which removes this prerequisite.

`guardian.mode=G1-LOGONLY` on first install, not `G0-FULL` - see Sec.0 and Sec.3. If you omit
`guardian.mode` entirely, the Guardian's own process default is `G0-FULL`
(`guardian/app/config.py:354`) - the chart passes whatever `guardian.mode` resolves to straight
through to the `GUARDIAN_MODE` ConfigMap key with no chart-side default of its own, so there is
exactly one place the `G0-FULL` default lives. `values.yaml` currently ships `G0-FULL` as its
own file default (review it before you rely on that; Sec.0's warning applies regardless of which
mode is the file's default) - **your values override above is what decides the mode an operator
actually gets**, so do not skip setting it explicitly on a first install.

**Evidence storage - pick the mode for your cluster.** `monitor.evidence.mode` is `hostPath`
(default) or `pvc`:

- `hostPath` (default `/var/lib/overwatch/evidence`, `pinToControlPlane: true`) is templated
  byte-for-byte from the kind/WSL2 development manifest. It works only if every relevant pod lands
  on the same node (both the aggregator and the audit forwarder), which `pinToControlPlane` forces
  by pinning them to the control-plane node, and it requires the directory to pre-exist on that
  node (see the `--wait` note above). Correct for kind/single-node; wrong for most foreign
  clusters.
- `pvc` (`--set monitor.evidence.mode=pvc`) backs the shared evidence volume with a
  PersistentVolumeClaim - `monitor-evidence`, created by the chart unless
  `monitor.evidence.pvc.existingClaim` names one - removing the node-local host-dir prerequisite.
  Tune `monitor.evidence.pvc.{storageClassName,accessMode,size}`. A `ReadWriteOnce` claim still
  requires the aggregator and audit forwarder to share one node (keep `pinToControlPlane: true`);
  set `accessMode: ReadWriteMany`, on a storage class that supports it, to let them span nodes.
  This is the mode for a foreign/multi-node cluster (`docs/adr/ADR-113-helm-chart-packaging.md`).

Run the chart's own readiness check rather than `make status` - `make status` reads
`infra/status/components.yaml`, which is the **evaluation lab's** declared component set and does
not know about your cluster's namespaces or release name:

```
helm test overwatch --kube-context "$KCTX" --namespace overwatch-system
sh deploy/tests/smoke.sh --context "$KCTX"   # operator TODO if not yet present in your checkout
```

Minimum manual verification if neither of the above exists yet in your checkout:

```
kubectl --context "$KCTX" -n guardian get deploy guardian
kubectl --context "$KCTX" -n guardian rollout status deployment/guardian --timeout=300s
kubectl --context "$KCTX" -n monitor get deploy evidence-aggregator
kubectl --context "$KCTX" -n guardian port-forward svc/guardian 8080:8080 &
curl -sf http://127.0.0.1:8080/healthz && echo "guardian: healthy"
kill %1
```

`GET /healthz` (`guardian/app/main.py`) is a liveness signal only - it does not assert OPA policy
is loaded correctly or that the audit chain is writable. Confirm those with a real decision: send
one deliberately-malformed request and check it appears, denied, in the audit log (Sec.2.4).

---

## 2. Observe

Everything here is read-only. None of it mutates cluster state.

### 2.1 Component health

```
kubectl --context "$KCTX" -n guardian get pods,pvc
kubectl --context "$KCTX" -n monitor  get pods
kubectl --context "$KCTX" get networkpolicy -A
```

`kubectl -n agents get pods` is expected to return nothing under this chart - Sec.0 and Sec.6
explain why an empty `agents` namespace is the correct steady state, not a failure. What you can
check there is the boundary itself: `kubectl -n agents get networkpolicy,role,rolebinding`.

Confirm the NetworkPolicy boundary is actually enforced, not merely present - a policy object
that exists but is not honored by your CNI is a silent no-op:

```
sh infra/tests/probe_guardian_reach.sh --context "$KCTX"   # admits agents, denies everything else (ADR-076)
```

If your cluster is not the kind reference cluster, confirm this script's assumptions (namespace
names, CNI) hold before trusting a green result, and treat a failure to run at all as "not
verified", not as "policy is fine".

### 2.2 Guardian mode and configuration

```
kubectl --context "$KCTX" -n guardian get configmap guardian-runtime -o yaml
```

`GUARDIAN_MODE` in that ConfigMap is the running mode. Guardian mode is a start-time parameter
only - nothing in a request can change it, and an unrecognized value is a startup error, never a
silent default (`guardian/README.md`, ADR-023). If you need to know the mode without reading the
ConfigMap, every `AuditRecord` also carries `guardian_mode` (Sec.2.4).

### 2.3 Monitor evidence

The aggregator emits `EvidenceEvent`s - `event_id, ts, source in {falco, prometheus, k8s_audit,
trivy}, severity, resource{ns,kind,name}, summary, evidence_excerpts[], raw_ref, schema_version`
(`docs/02-architecture.md` Sec.3). Stream the aggregator's own logs for a live read:

```
kubectl --context "$KCTX" -n monitor logs -f deploy/evidence-aggregator
```

To inspect the emitted event stream directly, exec into the aggregator pod (it is the only place
the file lives outside a collated run bundle) or port-forward and use its HTTP surface if your
chart networking exposes one - **operator TODO**: confirm whether `monitor/http_service.py`'s
adapter is reachable from outside the cluster in your deployment, since `infra/netpol` denies
cross-namespace access by default and the reference lab environment never opens Monitor ingress.
A minimal read, using the chart's `monitor.evidence.hostPath` value (default
`/var/lib/overwatch/evidence`; the aggregator's own data directory is
`<monitor.evidence.hostPath>/aggregator`, per `templates/monitor/configmap.yaml`'s
`MONITOR_DATA_DIR`):

```
kubectl --context "$KCTX" -n monitor exec deploy/evidence-aggregator -- \
  tail -n 50 /var/lib/overwatch/evidence/aggregator/events/monitor_events.jsonl
```

Evidence excerpts are quoted/escaped by construction (FR1.3, `monitor/aggregator/quoting.py`),
gated by the chart's `monitor.aggregator.quotingEnabled` value (`MONITOR_QUOTING_ENABLED`),
which defaults to `true`. **Never set it to `false` in an operator deployment.** `false` is the
`G3-UNQUOTED` evaluation-ablation configuration (`docs/02-architecture.md` Sec.4) - if you see
raw, unescaped environment text inside an `evidence_excerpts` entry, check this value first,
because that is what an unquoted aggregator looks like from the outside. `G2-SHAREDCRED` (the
chart's `agents.g2.enabled` / `agents.networkPolicy.apiServerReach: open` pair) is the same kind
of ablation-only configuration on the Guardian/network side; neither belongs in an operator
deployment, and this runbook does not cover promoting to
either.

### 2.4 Guardian decisions and the audit chain

Every decision - permit or deny - produces a hash-chained `AuditRecord`
(`seq, ts, run_id, request_id, token_jti, iss, decision, reason_code, policy_rule_id, action,
guardian_mode, enforcement in {blocked, executed, not-applicable}, record_type, prev_hash, hash,
schema_version`), preceded by one `RunStartRecord` genesis per chain (ADR-058) and followed by
one `ExecutionRecord` per decision (ADR-082). The chain file's name is whatever you set
`guardian.auditLogPath` to at install time (Sec.1.3) - there is no auto-generated per-attempt
name in a standing chart deployment as there is in the evaluation runner's campaign harness
(`scripts/guardian_deploy.sh`). Left unchanged across a mode flip or an image upgrade (Sec.3,
Sec.5), it is one continuous, ever-growing chain on the PVC; only a deliberate change to that
value starts a new one. Extract and verify it:

```
kubectl --context "$KCTX" -n guardian cp \
  guardian/$(kubectl --context "$KCTX" -n guardian get pod -l app.kubernetes.io/name=guardian -o jsonpath='{.items[0].metadata.name}'):/var/lib/guardian/audit \
  ./audit-extract

sh scripts/audit_verify.sh --path ./audit-extract
# or, directly, without the shell wrapper:
python3 -m guardian.audit.verify ./audit-extract
```

Read the summary line literally: **without `--head <sha256>` (or `HEAD=` for `scripts/audit_verify.sh`),
tail truncation and whole-chain rewrite are not detected** - an unsigned hash chain proves
mutation, deletion, insertion and reordering on its own, and nothing more (ADR-022,
`guardian/README.md` "What the audit chain detects, and what it honestly does not"). If you
retain a chain-head anchor from a prior extraction (there is no `seal.json` outside the
evaluation runner's sealed bundles - your own operational process must decide where it keeps
this anchor; see the gap noted in Sec.6), pass it:

```
python3 -m guardian.audit.verify ./audit-extract --head <previous-known-chain-head-sha256>
```

For a quick census of what a chain contains without a full verify pass, the file is
line-delimited JSON and greppable:

```
python3 - <<'PY'
import json
from collections import Counter
c = Counter()
with open("audit-extract/<your-chain-file>.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec.get("record_type") == "decision":
            c[(rec["decision"], rec["enforcement"])] += 1
print(c)
PY
```

A `("deny", "executed")` count that is not zero, under `G1-LOGONLY`, is expected and is exactly
what Sec.3's review step reads - it is not itself an anomaly.

### 2.5 Logs and metrics

```
kubectl --context "$KCTX" -n guardian logs deploy/guardian --tail=200
kubectl --context "$KCTX" -n monitor  logs deploy/evidence-aggregator --tail=200
kubectl --context "$KCTX" -n agents   logs -l app.kubernetes.io/part-of=agentic-overwatch --tail=200 --prefix
```

Resource metrics: if you installed Prometheus per Sec.1.1, its `/graph` or Grafana front end is
your existing metrics surface - this project's `resources.csv` collector schema
(`docs/protocols/data-management.md` Sec.1) is an evaluation-run artifact and is not what a live
operational deployment produces; do not expect a `resources.csv` to appear on disk anywhere in a
Helm-deployed system.

---

## 3. Promote from shadow (G1-LOGONLY) to enforce (G0-FULL)

Full rationale: `docs/ops/shadow-mode.md`. This is the runnable step sequence, with the exit
criterion for each step stated explicitly.

**Step 0 - confirm the containment preconditions from Sec.0 hold**, before treating `G1-LOGONLY`
as an acceptable running state at all: least-privilege RBAC unmodified, NetworkPolicy denying
everything but `agents` into the Guardian, target disposable or accepted as such. If any of the
three does not hold, stop and fix it before deploying, not after.

**Step 1 - deploy at G1-LOGONLY** (Sec.1.3). Confirm the running mode (Sec.2.2).

**Step 2 - let it run for a dwell period you have decided on and can justify**, against real
traffic and real incidents in your environment - this document does not fix a number, because no
protocol file in this repository owns one for a live operational deployment (contrast
`docs/protocols/evaluation-protocol.md`, which fixes run counts and seeds for the dissertation
campaign only, not for operations).

**Step 3 - review the audit log's `enforcement: executed` records.** This is the step with the
actual content, and it is the whole reason `G1-LOGONLY` exists as a promotion mechanism rather
than a formality:

```
python3 -m guardian.audit.verify ./audit-extract --replay
```

For every record with `decision: deny, enforcement: executed`, read `reason_code` and `action`,
and answer: **had this been `G0-FULL`, would blocking this action have been correct?** The
`reason_code` vocabulary (`guardian/app/models.py`) is grouped by threat-model family and is
worth knowing before you read a chain end to end:

| Group | Meaning | Example codes |
|---|---|---|
| `authenticity` | is this token one the Guardian issued? | `authenticity.token-malformed`, `authenticity.signature-invalid`, `authenticity.issuer-unknown` |
| `temporal` | is the token live? | `temporal.expired`, `temporal.lifetime-above-ceiling` |
| `scope` | genuine token, wrong coverage | `scope.verb-not-allowed`, `scope.namespace-not-allowed`, `scope.phase-mismatch`, `scope.subject-mismatch` |
| `replay` | has this capability already been spent? | `replay.jti-spent`, `replay.jti-missing` |
| `policy` | what OPA decided, or could not decide | `policy.deny-default`, `policy.rule-deny`, `policy.engine-unavailable`, `policy.request-malformed` |
| `permit` | the one code that may accompany a permit | `permit.rule-allow` |

An `authenticity.*` or `replay.*` finding under `enforcement: executed` deserves particular
attention: those are exactly the classes a forged or replayed capability would produce, and under
`G1-LOGONLY` such an action was **not stopped**.

**Step 4 - decide.** "Enough review" is an operator judgment this runbook does not make for you;
it is at minimum every `enforcement: executed` deny read and dispositioned, not a sample.

**Step 5 - flip to G0-FULL:**

```
helm upgrade overwatch deploy/helm/agentic-overwatch \
  --kube-context "$KCTX" \
  --namespace overwatch-system \
  --reuse-values \
  --set guardian.mode=G0-FULL \
  --wait --timeout 5m
```

Guardian mode is read once at process start and is immutable thereafter (`guardian/app/config.py`;
ADR-023), so the flip only takes effect if the Guardian pod actually restarts. The chart makes
that automatic: the Guardian Deployment's pod template carries a `checksum/config-runtime`
annotation over the `guardian-runtime` ConfigMap, so changing `guardian.mode` changes the
checksum, which rolls a new ReplicaSet - no manual `kubectl rollout restart` needed. Confirm the
restart happened and the new mode is live:

```
kubectl --context "$KCTX" -n guardian rollout status deployment/guardian --timeout=300s
kubectl --context "$KCTX" -n guardian get configmap guardian-runtime -o jsonpath='{.data.GUARDIAN_MODE}'
```

**Step 6 - re-verify.** Send one deliberately out-of-scope request (or wait for the agent layer's
next naturally-occurring one) and confirm the audit log now shows `decision: deny, enforcement:
blocked` rather than `executed` for it.

**Rollback from G0-FULL back to G1-LOGONLY** is Sec.5's emergency-enforcement-disable path,
reused - it is the same `helm upgrade --set guardian.mode=G1-LOGONLY` in reverse, and it costs
the same restart and the same loss of standing capability tokens described there.

---

## 4. Incident triage

An "incident" here is anything that makes you want to reconstruct what the agent layer and the
Guardian did over some time window - a suspicious permit, an unexpected `enforcement: executed`
deny under G1, a resource that changed and you do not know why.

**Step 1 - fix the window.** Get an approximate start and end time from whatever alerted you
(Prometheus alert, Falco finding, a human report), then widen it generously - the Guardian audit
chain has no independent notion of "incident boundary", only a total order of `seq`.

**Step 2 - pull the Guardian audit chain for the window** (Sec.2.4's extraction), and verify it
first, before reading it for content. A chain that fails verification changes what you can trust
about every record after the break point - report the break's `seq` before doing anything else
with the file.

**Step 3 - read the decisions in the window**, in `seq` order (the chain's own total order, not
`ts`, which is wall-clock and not what integrity depends on):

```
python3 - <<'PY'
import json
with open("audit-extract/<your-chain-file>.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec.get("record_type") == "decision":
            print(rec["seq"], rec["ts"], rec["decision"], rec["enforcement"],
                  rec["reason_code"], rec.get("policy_rule_id"), rec.get("token_jti"),
                  rec.get("iss"), rec["action"])
PY
```

Two attribution caveats to carry into every reading, both binding law
(`docs/protocols/security-policy.md` Sec.6, ADR-030, ADR-031) rather than incidental: the
Guardian **attributes**, it does not **authenticate**, the presenting Executor's identity
(`executor_id`/`phase` in the request) and the token-issuing Supervisor's identity (`iss`). A
crossed or borrowed capability is traceable through `token_jti`/`iss`, but neither field is proof
of who actually sent the request - both are agent-declared and the Guardian records rather than
verifies who is asking. Read a triage conclusion of "Supervisor X did this" as "a token
registered to X was used for this", which is the claim the record actually supports.

**Step 4 - correlate with Monitor evidence for the same window.** Pull `monitor_events.jsonl` for
the window (Sec.2.3) and match on `resource{ns,kind,name}` and approximate `ts` against the
Guardian records from Step 3 - there is no shared join key between an `EvidenceEvent` and an
`AuditRecord` in this deployment shape (that join exists inside a sealed evaluation-run bundle's
`results.json`, not in live operations; Sec.6). What you are looking for:
did the Monitor see something the agent layer then acted on, and did the Guardian's decision
match what you would have expected given that evidence.

**Step 5 - read agent transcripts, if you have them.** A live Helm-deployed system, as packaged
by this milestone, has **no equivalent of the evaluation runner's `messages.jsonl` or
`spans.otel.json`** by default - those are run-bundle artifacts the campaign's `runner/` produces
(`docs/protocols/data-management.md` Sec.1), and the M8 chart does not stand up a trace plane
(Langfuse is explicitly out of the evaluation's own reported component set for a stated reason -
`infra/status/components.yaml`'s closing comment - and nothing in M8 changes that). If your
deployment forwards agent-layer OTel spans or LLM call logs somewhere (your own OTel collector,
your own LiteLLM gateway logs), that is where "agent transcripts" live for you, and this runbook
cannot name the exact query for a destination it does not know - **operator TODO**: record here,
once decided, how your deployment exports agent-layer transcripts and how to query them. Until
then, transcript-level triage is not available from this artifact's packaging alone; Guardian
audit plus Monitor evidence (Steps 2-4) is the triage surface this milestone actually ships.

**Step 6 - write down the timeline and the disposition.** What the Monitor observed, what the
Guardian decided and enforced, in what order, and your conclusion. Keep the extracted audit chain
and its verification output - a triage record without the raw chain it was read from cannot be
checked later.

---

## 5. Rollback

Three distinct things can go wrong, and they have three distinct remedies. Do not reach for "tear
it all down" when "disable enforcement" or "revert one release" is the actual fix.

### 5.1 Emergency: disable enforcement without undoing the deploy

If `G0-FULL` is blocking something you need to happen immediately and you accept the exposure
Sec.0 describes, drop to `G1-LOGONLY` (logs and still audits, does not block):

```
helm upgrade overwatch deploy/helm/agentic-overwatch \
  --kube-context "$KCTX" --namespace overwatch-system --reuse-values \
  --set guardian.mode=G1-LOGONLY --wait --timeout 5m
```

This is a mode change, not a true emergency stop - it causes a Guardian restart (mode is
start-time-only) and every outstanding capability token becomes invalid the moment the process
restarts (`guardian/README.md`; the signing-key-rotation consequence in `docs/ops/secrets.md`
applies here too, for the same reason: a fresh process, same or different key, still invalidates
tokens minted against the previous process's in-memory replay state).

If you need the agent layer to stop issuing actions at all rather than merely stop being blocked,
there is no in-cluster Deployment to scale to zero (Sec.0, Sec.6) - the agent graph is a
host-driven process outside this chart's scope, reaching the Guardian the way an operator does,
through `kubectl port-forward` under the operator's own credentials
(`docs/protocols/security-policy.md` Sec.6), not through the `agents` namespace's NetworkPolicy
path. Stop it the way you started it (kill the host process, its container, or whatever
supervises it) if you can reach it directly. If you cannot, the Guardian is the sole credential
holder and the sole mediation chokepoint (Sec.0) - scaling it to zero stops every path an agent
has to mutate the cluster, in any mode, at the cost of also stopping every legitimate permit:

```
kubectl --context "$KCTX" -n guardian scale deployment/guardian --replicas=0
```

Scale it back up (`kubectl ... scale deployment/guardian --replicas=1`, or re-run the last
`helm upgrade`/`helm install`) once the emergency is over, and re-verify per Sec.1.3.

### 5.2 Revert the deploy to a prior release

```
helm history overwatch --kube-context "$KCTX" --namespace overwatch-system
helm rollback overwatch <REVISION> --kube-context "$KCTX" --namespace overwatch-system --wait --timeout 5m
```

`helm rollback` reverts chart values (image tags, mode, resource limits) to a prior release's
recorded state - it does not touch the Guardian's audit PVC or its signing-key Secret, both of
which persist independently of the Helm release (Sec.1.2). A rollback that changes the image tag
means Guardian restarts on the old image; confirm `/healthz` and the running mode (Sec.2.2) again
afterward exactly as in Sec.1.3, because a revert is a deploy and deserves the same verification.

### 5.3 Full removal

```
helm uninstall overwatch --kube-context "$KCTX" --namespace overwatch-system
```

`helm uninstall` does not delete the signing-key Secret (referenced by name, never owned by the
release - Sec.1.2). The audit PVC carries `helm.sh/resource-policy: keep`
(`templates/guardian/pvc.yaml`), which stops Helm from deleting the PVC **object** on uninstall or
when a PVC template change would otherwise replace it. **But that keep annotation does not survive
namespace deletion:** by default the chart owns the `guardian` namespace
(`namespaces.create.guardian: true`), and `helm uninstall` deletes that release-owned Namespace,
which cascade-deletes everything inside it - the kept PVC included. So the keep annotation protects
the chain across `helm upgrade`/`helm rollback`, not across a full uninstall of a chart-owned
namespace.

Two ways to actually preserve the chain across an uninstall:

1. **Extract and archive it first** (Sec.2.4), every time - the always-correct habit, independent
   of any annotation. A deleted PVC takes an unrecoverable hash chain with it.
2. Deploy with `namespaces.create.guardian: false` and pre-create the `guardian` namespace
   yourself (unmanaged). Then uninstall leaves the namespace, and `resource-policy: keep` leaves
   the PVC inside it - the chain survives on disk. See Sec.5.6 for the re-install consequence.

### 5.4 Restoring prior state after rollback

Rollback reverts the deployment, not the target application's or cluster's state - any action the
agent layer already took (successfully, under `G0-FULL`, or under `G1-LOGONLY` regardless of
`decision`) stands until you or the target application's own reconciliation undoes it. This
project's Guardian does not implement compensating actions; "rollback" in Sec.5.1-5.3 means
rolling back **this system's own configuration and running state**, not undoing effects already
produced in the target environment. Use your triage record (Sec.4 Step 6) to decide what, if
anything, in the target needs manual remediation.

### 5.5 Post-rollback checklist

```
kubectl --context "$KCTX" -n guardian get pods
kubectl --context "$KCTX" -n guardian get configmap guardian-runtime -o jsonpath='{.data.GUARDIAN_MODE}'
python3 -m guardian.audit.verify ./audit-extract   # confirm the chain is still intact post-restart
```

A Guardian restart appends to the same chain (Sec.2.4) as long as `guardian.auditLogPath` is
unchanged across the rollback - the common case, since Sec.5.1/5.2 change `guardian.mode` or the
release revision, not that value. If you (or a prior operator) did change `auditLogPath` at some
point, you have more than one chain file on the PVC, each with its own genesis `RunStartRecord`;
list `/var/lib/guardian/audit/*.jsonl` inside the pod and verify each one you find.

### 5.6 Re-installing after an uninstall (namespace/PVC/ServiceAccount collisions)

**Prefer `helm upgrade` in place over uninstall+reinstall.** An in-place upgrade (Sec.3, Sec.5.1,
Sec.5.2) never hits any of the collisions below, because every object is already release-owned.

A fresh `helm install` into a namespace a prior release **left behind** collides on any object the
new release would own but that already exists unmanaged. Three you will actually meet, and the
verified remedy for each (the reinstall below was confirmed on a throwaway cluster with a leftover
`agents` namespace, 2026-09-23):

- **`Namespace "<ns>" ... exists and cannot be imported into the current release.`** The chart owns
  the `guardian`/`monitor`/`agents` Namespace objects (`namespaces.create.*: true`), so any of the
  three that outlived a prior release collides on the Namespace itself - before Helm even reaches
  the objects inside it. Remedy: for each leftover namespace, install with
  `--set namespaces.create.<ns>=false` so the chart does not try to own it; its namespaced objects
  (Roles, NetworkPolicies, the CiliumNetworkPolicy) still apply into the existing namespace fine.
- **`ServiceAccount "default" ... exists and cannot be imported into the current release.`**
  Kubernetes auto-creates the `default` ServiceAccount in every namespace, so a leftover `agents`
  namespace's `default` SA is unmanaged and the chart's managed `default` SA cannot adopt it. Remedy:
  install with `--set agents.manageDefaultServiceAccount=false`, then apply the automount-off
  hardening by hand:
  `kubectl -n agents patch serviceaccount default -p '{"automountServiceAccountToken":false}'`.
  A leftover `agents` namespace needs BOTH this flag and `namespaces.create.agents=false`; the
  verified command is:
  `helm install overwatch deploy/helm/agentic-overwatch --namespace overwatch-system --create-namespace -f my-values.yaml --set namespaces.create.agents=false --set agents.manageDefaultServiceAccount=false`.
- **A retained `guardian-audit` PVC.** If you deployed with `namespaces.create.guardian: false`
  (Sec.5.3) so the audit chain survived uninstall, the retained PVC is unmanaged and a fresh
  install's `guardian-audit` PVC object collides with it. Decide deliberately: reuse the chain (bind
  the running Guardian to the same `guardian.auditLogPath` and let it append), or archive and
  `kubectl -n guardian delete pvc guardian-audit` to start a new chain. Never delete it without an
  extracted copy (Sec.2.4).

The clean alternative to all three, when you are NOT preserving anything, is to fully delete the
leftover namespaces (`kubectl delete ns agents monitor guardian`, only after extracting any audit
chain you need) and reinstall with the defaults.

On Helm 3.2+/4 an operator who has judged it safe can instead let a reinstall take ownership of a
pre-existing object with `helm install --take-ownership` rather than deleting it; treat that as the
deliberate, reviewed choice it is, not a default.

---

## 6. Known gaps in this runbook

Recorded rather than hidden, per rule 00's precedent of stating a limitation instead of
implying a completeness this document does not have:

- **The chart deploys no agent-layer workload** (Sec.0, Sec.1.1, Sec.2.1, Sec.5.1). `helm
  install` brings up the Guardian, the Monitor evidence aggregator/audit-forwarder, and the
  `agents`/`monitor`/`guardian` namespace and network boundary - it does not by itself start the
  Orchestrator/Supervisor/Executor graph that actually produces incident response. Running that
  graph against a live cluster, as a standing process rather than the evaluation runner's
  per-attempt harness, is host-side operator tooling this milestone does not package. Treat
  "deploy" in this runbook's title as "deploy the mediation and evidence infrastructure", not
  "stand up the full incident-response loop", until that gap is closed by a future task.
- The chart (`deploy/helm/agentic-overwatch`) is landed and the `--set`/`-f` keys in this document
  were re-checked against its `values.yaml` in the 2026-09-23 review, including the keys added since
  first authoring (`monitor.evidence.mode`/`.pvc.*`, `agents.manageDefaultServiceAccount`). Still
  re-diff `values.yaml` and `docs/adr/ADR-113-helm-chart-packaging.md` against every key here before
  relying on it on a future chart version - a values key a later change renames will not announce
  itself in this document.
- ~~`monitor.evidence` has no PersistentVolumeClaim alternative.~~ **Closed:**
  `monitor.evidence.mode: pvc` now backs the evidence volume with a PVC for foreign/multi-node
  clusters (Sec.1.3); `hostPath` remains the default for kind/WSL2 parity. See
  `docs/adr/ADR-113-helm-chart-packaging.md`.
- `deploy/tests/smoke.sh` (Sec.1.3) is referenced by the M8 design but was not present in this
  checkout; the manual verification steps given alongside it are the fallback.
- There is no chain-head anchor equivalent to the evaluation runner's `seal.json` for a live
  operational deployment (Sec.2.4). Until your own operations decide where that anchor is kept
  and updated, every `make audit-verify` / `python -m guardian.audit.verify` run against a live
  chain can prove internal consistency but not rule out tail truncation or a whole-chain rewrite
  by whoever holds write access to the PVC. This is a real, currently-open gap, not a
  documentation omission - closing it is an operator decision this milestone does not make.
- Agent-transcript-level triage (Sec.4 Step 5) has no shipped destination in this packaging;
  it depends on how you route agent-layer telemetry, which this milestone does not build, and
  is the same gap as the first bullet above seen from the triage side.
- Guardian HA, and why `replicas: 1` is load-bearing rather than a default that can be
  raised, is `docs/ops/guardian-ha.md`'s subject, not restated here beyond the mode-change
  restart behavior Sec.5.1 depends on.
- This runbook lives at `docs/ops/runbook.md`, as a set of documents alongside
  `docs/ops/secrets.md`, `docs/ops/shadow-mode.md`, `docs/ops/sbom.md` and
  `docs/ops/guardian-ha.md`. `docs/plans/M8-implementation-plan.md` (written earlier against an
  older state of this tree) instead specifies one file, `docs/08-operator-runbook.md`, with these
  as internal sections, and gives a reason for preferring one document. That plan was not
  updated for this split and this file does not resolve the discrepancy - flagged here per
  `.agents/rules/00-source-of-truth.md` rather than silently picked either way.

## 7. Operator sign-off

The M8 DoD for this document is that `helm install` brings the system up **from the docs alone**.
The technical review above proved the commands were correct; this section records the operator
follow-through that closes M8-T8.3, and states the shape that was actually walked so a later reader
does not have to infer how much of the DoD it covers.

**Sign-off.** `pasindunaduninduwara`, 2026-09-23, throwaway kind cluster `m8-verify` (never the
evaluation cluster, per Sec.0). Sections walked in order, as written, with no step taken from memory:

| Section | Walked | Outcome |
|---|---|---|
| Sec.1.1 prerequisites | yes | CNI, Falco, Prometheus, audit logging, Trivy and the `boutique` namespace checked; each missing prerequisite fails loudly rather than silently, as chart comments claim |
| Sec.1.2 namespaces + signing key | yes | `overwatch-system` management namespace and the out-of-band signing-key Secret created |
| Sec.1.3 install | yes | `helm install` into the management namespace; guardian, evidence-aggregator and audit-forwarder all reached Ready; `helm lint --strict` clean. **Both evidence modes exercised:** `hostPath` needs the node directory pre-created, `pvc` removes that prerequisite |
| Sec.2 observe | yes | `/healthz` and `/readyz` 200; Guardian mode read back from the runtime ConfigMap; evidence files and audit chain inspected |
| Sec.3 shadow -> enforce | yes | installed at `G1-LOGONLY`, promoted with `helm upgrade --set guardian.mode=G0-FULL`; the checksum annotation rolled a new ReplicaSet (`guardian-69d94877f4` -> `guardian-7bb6bf57c7`) with no manual restart |
| Sec.5 rollback | yes | mode revert and release rollback; the audit PVC survives both via `resource-policy: keep`, with the full-uninstall caveat documented in Sec.5.3 |

**What this sign-off does and does not cover.** It covers every step listed above, executed from
this document on a cluster that is not the evaluation cluster, with the two evidence modes and the
shadow->enforce->rollback path all exercised. It does **not** claim a from-scratch cluster was
built for the occasion: the walk reused the `m8-verify` cluster the technical review had already
stood up, so "a stranger with no cluster at all" is covered by the documented prerequisites in
Sec.1.1 rather than by this run. It also does not close Sec.6's gaps, which are properties of the
chart and the milestone's scope, not of this document - chiefly that the chart deploys no
agent-layer workload (Sec.6, first bullet), so "the system" here means the mediation and evidence
infrastructure, not the incident-response graph.
