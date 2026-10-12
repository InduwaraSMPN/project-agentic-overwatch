# M2 Phase B source deployment

This directory contains the build-controlled source deployment side of the Monitor. Runtime and
normalisation code remains under `monitor/`; cluster composition remains under `infra/`, alongside
`infra/cilium/` and `infra/observability/`. The aggregator service and central version pins live at
their established repository surfaces. Live fixture capture and protocol calibration remain
absent until a cluster study exists.

Every chart, image, and driver choice is read by `install.sh` from `infra/versions.env`; values and
manifests do not carry a second operational version pin. Version numbers below identify the chart
schemas against which the files were authored and verified.

## Surfaces

- `falco-values.yaml`: Falco chart 8.0.1 / app 0.43.0, `modern_ebpf`, project rules, and the bundled
  Falcosidekick webhook to `http://evidence-aggregator.monitor.svc.cluster.local:8080/v1/falco`.
- `falcosidekick-values.yaml`: independently renderable chart 0.12.1 / app 2.31.1 values used to
  validate the dependency keys and application image pin.
- `alertmanager-values.yaml`: standalone Alertmanager chart 1.35.0 / app v0.32.0 and its webhook to
  `/v1/alertmanager`.
- `trivy-kubernetes-job.yaml`: an ephemeral scan of an explicit digest-pinned image; the report is
  posted unchanged to `/v1/trivy` by the aggregator image's stdlib uploader.
- `install.sh`: guarded, idempotent Helm/apply surface reading every version from `versions.env`.

Prometheus rules and the standalone Alertmanager target are in
`infra/observability/prometheus-values.yaml`. The API audit policy is in
`infra/audit/audit-policy.yaml`; `infra/kind-config.yaml` mounts that policy and the shared evidence
path into the control-plane node and kube-apiserver.

Run from the repository root inside WSL2 after the kind cluster exists:

```sh
sh infra/monitor/install.sh
```

The URLs are the routes exported by `monitor/http_service.py`; DNS includes the namespace so the
source and sink need not share a namespace. No authentication material is stored in these files.

Static and Helm-render checks prove authored shape and chart-key compatibility only. They are not
claims of modern-eBPF kernel compatibility, live delivery, captured-fixture provenance, alert noise,
or calibrated caps/latency; those require the M2 live cluster study.
