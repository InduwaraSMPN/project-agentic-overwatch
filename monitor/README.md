# monitor — programmatic detection and evidence aggregation

The deterministic half of the system. Four engineering ingestion paths are implemented: the
mapping onto the three telemetry families named by the submitted chapters remains provisional, and
Prometheus/Alertmanager metric anomalies are carried as `origin: engineering` pending T-41.
Bounded, schema-valid, quoted `EvidenceEvent`s flow out. This is not presented as a settled
four-family requirement. No model is ever called here, and that is enforced rather than asserted —
see "The non-LLM boundary" below.

## What is here

| Path | Holds | Landed |
|---|---|---|
| `aggregator/models.py` | the frozen `EvidenceEvent` v1 contract — architecture §3's nine fields, no more | M2-T2.1 |
| `aggregator/schema/` | the exported JSON Schema, regenerated in test and compared to the tracked copy | M2-T2.1 |
| `aggregator/sources/` | one normaliser per family: Falco, Prometheus/Alertmanager, Kubernetes audit, Trivy | M2-T2.5 |
| `aggregator/normalize.py` | the ordered source registry and the dispatch over it | M2-T2.5 |
| `aggregator/caps.py` | count and length caps, applied to **pre-quoting** source text | M2-T2.5 |
| `aggregator/limits.py` | the mirror of `evaluation-protocol.md` §4's `m2-monitor-limits` block | M2-T2.5 |
| `aggregator/quoting.py` | reversible quoting of untrusted environment text, and the single G3 branch | M2-T2.6 |
| `aggregator/emit.py` | deterministic emission to `monitor_events.jsonl`, latency to `latency.json` | M2-T2.5 |
| `aggregator/cli.py` | the entry point replay drives, carrying `--quoting/--no-quoting` | M2-T2.5 |
| `http_service.py` | the build-controlled HTTP adapter dispatching live payloads into the existing normalisers | M2-T2.2–T2.4 |
| `deploy/` | aggregator container and Kubernetes deployment surface | M2 Phase B |
| `rules/` and `infra/monitor/falco-values.yaml` | modern-eBPF configuration, Falcosidekick route and baseline rules | M2-T2.2 |
| `trivy/` | pinned, ephemeral scan Job renderer and Trivy ingestion path | M2-T2.4 |
| `fixtures/` | one directory per fixture: provenance, raw inputs, and the golden event stream | M2-T2.7 |
| `tests/` | unit tests — **fixtures only, never a cluster, never a network, never a model** | M2 |

## The non-LLM boundary

`docs/02-architecture.md` §1 types this component `deterministic, non-LLM` and FR1.4 requires the
property end to end. Before M2 that was a claim in four documents and a check in none. It is now
three checks, because each catches what the one before it misses:

1. **`scripts/monitor_guard.sh` block (a)** — a static scan of every tracked file here for
   constructs that *execute*: SDK imports, aliased-import access, inference endpoints, provider
   credentials, model pins, call shapes, process-launch APIs and provider CLI commands.
2. **The socket-denial replay** — a test that makes every socket constructor raise, then replays the
   whole corpus. A green replay under socket denial is positive evidence that no call went out, and
   it catches a dynamically imported client that no grep can see.
3. **The dependency-surface assertion** — the pinned runtime dependency set contains no inference
   client, so the guarantee cannot be eroded by an addition nobody reads.

`.agents/rules/40-monitor-non-llm.md` is what those three answer to, and there is **no exemption
mechanism**, on rule 10's precedent. ADR-020 records the design, including the one property the
whole thing turns on: the guard deliberately does **not** match the bare words in this heading.
Scoping the patterns to constructs that execute is what lets this file say plainly what it says.

## Rules that bind this directory

- **Determinism is a `cmp`, not a judgement.** Replaying a fixture twice must produce byte-identical
  output (`.agents/rules/20-parity-and-determinism.md`, NFR2). That is why `ts` comes from the
  source record, `event_id` is a hash over a canonical projection rather than a fresh identifier,
  serialisation is canonical, emission order is an explicit total order over a fixed registry, and
  `raw_ref` is repo-relative — an absolute path encodes the host and breaks the diff across machines
  while passing on one. `monitor_guard.sh` block (b) is the tripwire for those; the byte diff is the
  proof. ADR-019.
- **Latency figures never enter the event stream.** They are wall-clock and machine-dependent, and
  one such field in `monitor_events.jsonl` would make the twice-and-diff unpassable forever. They go
  to `latency.json`, which is not diffed.
- **Caps are counted before quoting, and the order is load-bearing.** Quoting lengthens text, so a
  cap applied after it would leave the unquoted arm carrying more source content than the quoted
  arm — and the G3 flag would then change how much evidence reaches the Orchestrator as well as how
  it is escaped. §3.5.4 requires each configuration to remove exactly one property, so the other
  ordering makes G3 an invalid arm rather than a failing test.
- **The cap and budget values are protocol-owned.** `evaluation-protocol.md` §4 is the authority;
  `aggregator/limits.py` is a checked copy, and `tests/test_limits_match_protocol.py` fails CI on
  drift. The aggregator carries **no default** and fails closed with a named error on an unset
  limit, so a corpus cannot go green against numbers nobody has measured (ADR-016, ADR-019).
- **The G3-UNQUOTED toggle is configuration.** It reaches the aggregator as a flag and is branched
  on in exactly one function; M6 drives it from the runner's condition flags. Never a code path
  selected by editing this directory.
- **Nothing under `tests/` may require a cluster, a network, or a third-party package beyond the
  pinned runtime set.** The first tracked file here armed `ci.yml`'s `Unit tests -- monitor` step,
  which runs on `ubuntu-latest` with `pytest` and whatever `scripts/install_runtime_deps.sh`
  installs from `infra/versions.env` — and nothing else.

## Signal families — an open question, not a settled map

The submitted chapters name **three** telemetry families; FR1.1 and this component name **four**.
The mapping between them is proposed in ADR-018 and recorded in `docs/binding-log.md` §M2, and it is
**provisional**: metric anomalies are labelled `origin: engineering` pending the supervisor's answer,
and whether "network traffic" is satisfied by syscall-level network events or needs a flow-log source
is one of the two questions put to them. Matrix row T-41 tracks the resolution. Do not read the four
normalisers here as a settled reading of the requirement.

## Traceability

Serves T-01 (four-source ingestion), T-02 (bounded events and latency), T-03 (quoting with the G3
toggle isolated), T-04 (determinism), plus M2's proposed T-42 (non-LLM enforced by check) and T-43
(caps and budget derived from captured fixtures). Row status and the reason none closed at the
offline phase are recorded at the foot of `docs/05-traceability-matrix.md`.

## Entry points

```bash
sh scripts/monitor_guard.sh        # rule 40, plus the determinism tripwire
sh scripts/monitor_render.sh       # Helm/Kustomize render only; no live claim
sh scripts/monitor_image.sh        # build and load the pinned image into kind
make monitor-replay                # every fixture; F=<id> for one
make determinism-check             # replay twice, diff the bytes
```
