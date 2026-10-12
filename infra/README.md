# infra — cluster and application substrate

Everything the experiment runs *on*, and the two instruments that measure what it costs. Populated
by M1 (walking skeleton); `netpol/` gains the agent-namespace default-deny in M3.

## What is here

| Path | Holds | Landed |
|---|---|---|
| `versions.env` | every pinned tool version, chart version and image digest (`docs/03-tech-stack.md` §5) | M0, cluster/app/observability groups filled at M1 |
| `kind-config.yaml` | the 2-node kind cluster: 1 control-plane, 1 worker, `disableDefaultCNI: true`, kube-proxy kept | M1-T1.1 |
| `cilium/` | Helm values and the install script for Cilium as the **sole** CNI | M1-T1.1 |
| `netpol/probe/` | the throwaway fixtures `scripts/netpol_proof.sh` uses to prove enforcement | M1-T1.1 |
| `boutique/` | the Kustomize overlay deploying Online Boutique at pinned digests, with the bundled load generator removed | M1-T1.2 |
| `locust/` | the load driver, the **load-profile registry** (`profiles.yaml`) and its resolver | M1-T1.2 |
| `observability/` | Prometheus, kube-state-metrics and Grafana from M1; representative rules and separately pinned Alertmanager from M2 | M1-T1.3, M2-T2.3 |
| `audit/` | kube-apiserver audit policy and the mounted audit-log ingestion surface | M2-T2.4 |
| `probes/` | the SLO probe and the constants module mirroring `evaluation-protocol.md` §4 | M1-T1.4 |
| `collectors/` | the resource collector that labels the `app`, `framework` and `platform` series | M1-T1.5 |
| `status/` | `components.yaml`, the declared component set `make status` reports over | M1-T1.6 |
| `tests/` | unit tests for everything above — **fixtures only, never a cluster** | M1 |

The two node images are not the only pins that matter: `boutique/images.yaml` carries one
`sha256:` digest per Boutique service, applied by Kustomize's `images:` transformer. A tag is not
a pin, and NFR1's clean-machine reproduction is exactly the claim a tag would quietly break.

## Rules that bind this directory

- **`versions.env` carries pinned versions and digests only.** Seeds, run counts, budgets and
  thresholds belong to `docs/protocols/evaluation-protocol.md` and must never be restated here —
  `.agents/rules/00-source-of-truth.md`, and `versions.env`'s own header rule 4.
- **The SLO constants are protocol-owned.** `probes/constants.py` is a *checked copy* of
  `evaluation-protocol.md` §4, not an independent source; `tests/test_constants_match_protocol.py`
  parses §4 and fails CI on any divergence. Edit the protocol first; the module follows (ADR-016).
- **Nothing under `tests/` may require a cluster, a network or Docker.** The first tracked file
  under `infra/tests/` arms `ci.yml`'s `Unit tests -- infra` step, which runs on `ubuntu-latest`
  where none of those exist. Cluster-dependent verification belongs to
  `.github/workflows/env-bringup.yml`, which builds one.
- **Tests use only dependencies installed by the repository CI path.** Most infra tests remain
  standard-library-only; deployment-manifest tests use PyYAML, which is already a transitive runtime
  dependency on the current guarded test path. If that dependency ceases to be installed, those
  tests must gain an explicit tool install or return to a standard-library parser rather than pass
  only in a developer environment.
- **The NetworkPolicies under `netpol/` are the network half of the Guardian-only enforcement
  path** required by `.agents/rules/10-guardian-first.md`. M1's are a throwaway probe namespace
  proving the mechanism; M3-T3.5 adds the agent-namespace default-deny that closes row T-11.

## Traceability

Serves rows T-16 (clean-machine bring-up) and T-21 (restoration-time probes), and supplies the
collectors and probes that T-18 and T-19 measure against at M7. Row status and the reason none of
the four is `closed` at M1 are recorded at the foot of `docs/05-traceability-matrix.md`.

## Entry points

```bash
sh scripts/install_cluster_tools.sh   # kind, kubectl, helm, kustomize, cilium — at the pins above
make up                               # preflight, cluster, Cilium, Boutique, Locust, observability
make status                           # one line per declared component
make netpol-proof                     # the attributable denial, same-node and cross-node
make down                             # teardown, volumes intact
make nuke                             # teardown, volumes destroyed (FORCE=1 to skip the prompt)
```
