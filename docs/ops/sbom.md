# SBOM and self-scan — format, location, CI wiring and residual findings

Status: active · Milestone: M8 hardening (T8.4) · Scope: packaging/ops only, zero behavior change

This file exists because `docs/milestones/M8-hardening.md` T8.4 asks for "SBOM generation; Trivy
scans of our own images in CI; document residual findings," and `docs/protocols/security-policy.md`
section 5 names the same pair — "image signing + SBOM; Trivy scans of our own images" — as an M8
production-hardening delta that must not alter frozen `v1.0` behavior (AGENTS.md iron rule 6). The
mechanism lives in `scripts/self_scan.sh`; the CI wiring is `.github/workflows/self-scan.yml`; the
tool-choice and design decisions are recorded in `docs/adr/ADR-115-sbom-and-self-scan.md`. This
document is the operator- and reviewer-facing read: what is produced, where, how to read it, and how
an accepted residual finding is documented and reviewed.

**This is a docs-only reading guide.** It reproduces no scan output and no vulnerability data; every
example below is illustrative, not a real finding.

## 1. What gets scanned

Every container image this repository actually builds today, per `scripts/self_scan.sh`'s own
header:

| Short name | Image ref (pin) | Dockerfile | Role |
|---|---|---|---|
| `monitor` | `infra/versions.env`'s `MONITOR_IMAGE` (`agentic-overwatch/evidence-aggregator:local`) | `monitor/Dockerfile` | Evaluated artefact — the evidence aggregator ADR-007/ADR-018 pin |
| `guardian` | `infra/versions.env`'s `GUARDIAN_IMAGE` (`agentic-overwatch/guardian:local`) | `guardian/deploy/Dockerfile` | Evaluated artefact — the reference monitor and sole credential holder |
| `slo-probe` | `agentic-overwatch/slo-probe:local` (override: `SLO_PROBE_IMAGE`; not a `versions.env` pin — see that Dockerfile's own header) | `infra/probes/deploy/Dockerfile` | Measurement apparatus, not evaluated artefact — scanned anyway because it is still an image this repository builds and ships |

**`agents/` ships no container image**, so there is nothing to scan there. ADR-113 records why: the
agent layer is a host-side graph the runner drives for the duration of a run, not a standing cluster
workload, and no Dockerfile for it exists in the tree. When one lands, `scripts/self_scan.sh`'s own
header names exactly where to add a fourth `build_agents()` function and `scan_image` call.

## 2. SBOM: format, tool and where it lands

**Format: CycloneDX JSON**, produced by `trivy image --format cyclonedx --output <file> <image>`.
ADR-115 records why Trivy generates the SBOM rather than a separate tool (Syft, etc.): one binary
already pinned and reasoned about in this repository (`TRIVY_VERSION` in `infra/versions.env`, the
same key ADR-007/ADR-018 pin the Monitor's own CVE signal source at) produces both the SBOM and the
vulnerability scan, so T8.4 adds no second scanner dependency to install, cache or keep current.

Each run writes one file per image to the output directory (default `self-scan-out/`, override
`SELF_SCAN_OUTPUT_DIR`):

```
self-scan-out/
  monitor.cyclonedx.json       # SBOM
  monitor.trivy-full.json      # full vulnerability report, every severity, never suppressed
  guardian.cyclonedx.json
  guardian.trivy-full.json
  slo-probe.cyclonedx.json
  slo-probe.trivy-full.json
  <name>.trivy-gate.txt        # human-readable table from the CI gate pass, per image
  summary.txt                  # one line per image: PASS/FAIL plus severity counts
```

**Reading an SBOM.** A CycloneDX document's `components` array is the package inventory: each entry
carries a `purl` (package URL — e.g. `pkg:pypi/pydantic@2.13.4`), a `type`, and licence information
where Trivy could resolve it. To list every component of the Guardian image, for example:

```sh
python3 -c "
import json
data = json.load(open('self-scan-out/guardian.cyclonedx.json'))
for c in data.get('components', []):
    print(c.get('purl', c.get('name')))
"
```

The SBOM is written **regardless of the scan gate's outcome** and regardless of any residual-finding
suppression (section 6) — it is a complete package inventory, not a filtered one.

## 3. Vulnerability scan: a full report and a separate gate

Two Trivy passes run per image, deliberately kept apart:

1. **Full report** (`<name>.trivy-full.json`) — every severity (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`,
   `CRITICAL`; the same five-level Trivy vocabulary `docs/adr/ADR-019-evidence-event-schema-and-
   determinism.md` already documents for the Monitor's own Trivy signal source), `--exit-code 0`, so
   this call never fails the build and **no ignore-file entry is ever applied to it.** This is the
   complete, honest record: an accepted residual finding still appears here.
2. **Gate** (`<name>.trivy-gate.txt`) — only `SELF_SCAN_FAIL_SEVERITY` and above (default
   `CRITICAL`), `--exit-code 1`, with the configured ignore file (section 6) applied if one is
   set. This is the pass/fail decision that fails the CI job.

`summary.txt` reports each image's PASS/FAIL alongside a per-severity count **read from the full,
unsuppressed report**, so a gate that passes because of an accepted entry still shows the true count
rather than a number an ignore file quietly reduced.

**Exit-code policy.** The script's own exit code is `0` only when every image's gate passed. A single
image with an unignored finding at or above `SELF_SCAN_FAIL_SEVERITY` fails the whole run — every
image is still scanned first, so a red run's log and uploaded reports cover all three, not just the
first failure.

## 4. Running it locally

```sh
sh scripts/self_scan.sh
```

Requires Docker and network access (Trivy downloads its vulnerability database, and the script
downloads and checksum-verifies its own pinned Trivy binary on first use — see `scripts/
self_scan.sh`'s header for what that verification does and does not guarantee). Images already
present locally under their pinned tag are reused rather than rebuilt; set `SELF_SCAN_FORCE_BUILD=1`
to force a rebuild. `sh scripts/self_scan.sh -h` lists every environment variable, including
`SELF_SCAN_OUTPUT_DIR`, `SELF_SCAN_FAIL_SEVERITY`, `SELF_SCAN_TRIVYIGNORE` and `TRIVY_BIN`.

The output directory is a local/CI working artifact, not tracked — it is listed in `.gitignore`
(see section 7's closed follow-up); remove it by hand after a local run
(`rm -rf self-scan-out`) if you do not want it on disk.

## 5. CI wiring

`.github/workflows/self-scan.yml` runs `sh scripts/self_scan.sh` with no logic of its own (per
`docs/04-repo-conventions.md` section 1, every gate's logic lives in `scripts/`) and uploads
`self-scan-out/` as a build artifact (`self-scan-reports`, 90-day retention) whether the gate passed
or failed, so a red run still leaves every SBOM and report attached for inspection.

Triggers: `pull_request` path-filtered to the three Dockerfiles, the source trees each one `COPY`s,
`infra/versions.env` and the script/workflow themselves; `workflow_dispatch` for an on-demand run;
and a weekly `schedule`, because an unchanged image can still acquire a new CVE with no commit of
ours responsible — the same argument `env-bringup.yml` already makes for its own weekly run.

**First real CI run: green, 2026-09-23.**
[actions/runs/35876009662](https://github.com/InduwaraSMPN/agentic-overwatch/actions/runs/35876009662)
(`workflow_dispatch` on `main`, commit `8faef58`) built all three images, fetched and
checksum-verified Trivy 0.69.3, wrote a CycloneDX SBOM plus both reports per image, and passed the
gate:

```
self-scan: monitor    PASS  [CRITICAL=5 HIGH=58 MEDIUM=112 LOW=103 UNKNOWN=3]
self-scan: guardian   PASS  [CRITICAL=5 HIGH=61 MEDIUM=115 LOW=107 UNKNOWN=4]
self-scan: slo-probe  PASS  [CRITICAL=5 HIGH=55 MEDIUM=109 LOW=103 UNKNOWN=1]
self-scan: PASS — SBOM + scan reports for 3 image(s) written to self-scan-out
```

The gate decision is only meaningful against the unsuppressed report, and the two agree: the
downloaded `self-scan-reports` artifact's full reports name exactly the five accepted ids —
`CVE-2025-7458` (libsqlite3-0), `CVE-2026-8376` / `CVE-2026-42496` / `CVE-2026-13221` (perl-base),
`CVE-2023-45853` (zlib1g) — each with `FixedVersion` empty, at CRITICAL, in all three images. Five
CRITICALs accepted and five suppressed-and-passing means no finding rode through unexamined: a sixth
would have failed the step. Note the run was fast (1m18s) because the runner reused the base layers;
the three `docker build` invocations, the SBOMs and the scans are all present in the log, so this is
a cache-warm pass, not a skipped one.

**This workflow must never be a required branch-protection status check.** It is path-filtered, so a
required check on it would sit permanently pending on every pull request that does not touch an
image surface, which blocks the merge and reads as a stuck queue rather than as what it is — the same
operational warning `env-bringup.yml` already carries for itself. `ci.yml`'s
four jobs remain the required set (`docs/04-repo-conventions.md` section 4).

## 6. Residual findings: the ignore-file mechanism

Some findings are real, in code this project does not own, with no fix available at any version —
recording "known, unfixable, accepted, reviewed" is the honest outcome, not a hole in the gate. This
is a different situation from rules 10 and 40 (`.agents/rules/10-guardian-first.md`, `.agents/rules/
40-monitor-non-llm.md`), which refuse any exemption mechanism because they police **our own code**,
where a finding is always ours to fix. A CVE scanner reporting on upstream base-image layers is
reporting facts about code nobody here wrote; suppression there, done individually and reviewed, is
not the same act as punching a hole in a boundary over our own source.

**The ignore file is committed at `.trivyignore.yaml` (repository root), reviewed and signed off
2026-09-23.** It accepts the five base-layer CRITICALs the self-scan found in all three images — all
from the shared debian-12-bookworm base, none with an upstream fix at any version (`CVE-2025-7458`
libsqlite3-0, `CVE-2026-8376`/`CVE-2026-42496`/`CVE-2026-13221` perl-base, `CVE-2023-45853`
zlib1g). It is wired into CI: `.github/workflows/self-scan.yml` sets `SELF_SCAN_TRIVYIGNORE:
.trivyignore.yaml` on the scan step. The acceptance is the researcher's decision, recorded in the
commit that carries the file with the owner it names — `pasindunaduninduwara`, accountable for
revisiting each entry. If the disposition is instead a base-image bump, delete the entries rather
than renewing them. The full unsuppressed report still lists every one of these findings; the ignore
file affects the gate decision only, and each entry's `expires` (2026-12-22) makes Trivy re-fail it
after that date.

Fail-closed remains the default *shape*: `SELF_SCAN_TRIVYIGNORE` unset means **no suppression at
all**, a file named but missing is a hard error (the script refuses to scan with suppressions
silently dropped), and every finding at or above the gate severity fails the build unless an entry
accepts it.

**When a further finding needs accepting**, add an entry to `.trivyignore.yaml` (Trivy's YAML
ignore-file form, supported natively by `--ignorefile`; the `expires` field needs no project-side
code). It lives at the repository root because no `deploy/security/` convention exists yet in this
tree; relocate it (and update this section plus the workflow's `SELF_SCAN_TRIVYIGNORE`) if a later
change under `deploy/` establishes one. Entry shape:

```yaml
vulnerabilities:
  - id: CVE-2024-XXXXX
    statement: >
      No fix published for this base-image package at any available version as of the date below.
      Not reachable from this image's own entrypoint (python -m guardian.app); tracked for the next
      base-image bump. Reviewed 2026-09-23 by <owner>.
    expires: 2026-12-23T00:00:00Z
```

Every entry must carry, at minimum:

- **The CVE (or GHSA) id**, exact — a bare package-name suppression is not accepted.
- **A reason** (`statement`) stating why it is not fixed and, where relevant, why it is not
  reachable or exploitable in this image's actual use.
- **An owner** — a name or role, in the `statement`, accountable for revisiting the entry.
- **An `expires` date.** This is Trivy's own native field, not a wrapper this project maintains: once
  the date passes, Trivy stops honoring the entry and the finding reappears at the gate — "an expired
  entry fails the scan" is enforced by the scanner itself, not by a second piece of logic here that
  could itself drift or be forgotten.

**Review.** The ignore file is an ordinary tracked file once it exists, so adding or renewing an entry
goes through the same pull-request review as any other change — there is no separate approval
mechanism to build or maintain. Section 3's full, unsuppressed report is what a reviewer checks an
entry against: it must still show the finding, at the correct severity, so "accepted" is never
confused with "no longer present."

## 7. Known limitations and follow-up (stated rather than hidden)

- **Trivy's own acquisition is checksum-verified against the release's own checksums manifest,
  fetched over TLS at run time — not against a literal digest a reviewer read and committed**, the
  stronger shape `scripts/guardian_test.sh` already gives OPA (ADR-025: a digest fetched from the
  same server, at the same moment, as the thing it verifies "detects a corrupted transfer and
  nothing else"). Tightening this to a committed, reviewer-sourced literal is real follow-up work,
  not assumed done here. See ADR-115's Consequences.
- **`guardian/deploy/Dockerfile`'s `OPA_LINUX_AMD64_SHA256` build-arg is duplicated** in
  `scripts/self_scan.sh` from its one existing home, `scripts/guardian_image.sh`, because self-scan
  must build without a running `kind` cluster (see `scripts/self_scan.sh`'s own header) and so cannot
  simply invoke that script. If `scripts/guardian_image.sh`'s literal ever changes, this one must
  move with it; there is no test enforcing that today.
- **~~`self-scan-out/` is not yet in `.gitignore`.~~ Closed:** `self-scan-out/` is ignored
  (`.gitignore`, under the M8-T8.4 supply-chain comment heading). Re-checked 2026-09-23 against the
  tree; the previous note in this section was stale.
- **Image signing is out of scope.** `docs/protocols/security-policy.md` section 5 names it beside
  SBOM as an M8 delta; it needs a signing key, a keyless-OIDC decision and a verification policy,
  none of which this task's brief or `docs/milestones/M8-hardening.md`'s T8.4 line asks for. Future
  work, with the SBOM this file describes as its prerequisite.
- **Scope is vulnerabilities only** (`--scanners vuln`). Trivy can also scan for embedded secrets and
  misconfigurations; neither is wired in here, since `docs/milestones/M8-hardening.md` T8.4 and this
  task's brief both say "Trivy vulnerability scan," not a broader posture scan.
- **`docs/plans/M8-implementation-plan.md`'s own T8.4 sketch** (`scripts/sbom.sh` +
  `scripts/image_scan.sh` as two scripts, `.github/workflows/supply-chain.yml`, `deploy/security/
  residual-findings.md` + `deploy/security/.trivyignore`) predates the current tree and is superseded
  here, the same way ADR-113 and ADR-114 each recorded for their own tasks: that plan's own text
  requires re-verifying it against the tree of the day before treating any of its shape as binding,
  and `deploy/security/` does not exist in this tree. This document, `scripts/self_scan.sh`,
  `.github/workflows/self-scan.yml` and ADR-115 are the corrected, current shape for T8.4.

## 8. Verification performed and deferred

**This section is closed as of 2026-09-23 by two real runs, the second one in CI.**

While authoring the change, no image was built and no live Trivy scan was run;
`scripts/self_scan.sh` was checked with `bash -n` and `sh -n` only (both clean). That first gap was
closed on the VM: `sh scripts/self_scan.sh` fetched and checksum-verified Trivy 0.69.3, generated a
CycloneDX SBOM per image, and ran the gate — which **FAILed by design**, all three images carrying
the same five unfixable debian-12 base-layer CRITICALs. That is the fail-closed behavior working, and
it is what motivated the reviewed acceptance in section 6.

The second gap — the first `self-scan.yml` execution — is closed by
[actions/runs/35876009662](https://github.com/InduwaraSMPN/agentic-overwatch/actions/runs/35876009662)
(`workflow_dispatch` on `main`, commit `8faef58`), which passed the gate at `CRITICAL=5` for each of
the three images in 1m18s. Log, `self-scan-reports` artifact and the accepted-id check against the
unsuppressed reports are quoted in section 5. Note the run was cache-warm, so treat the elapsed time
as a lower bound on a cold runner, not as the workflow's expected duration against its
`timeout-minutes: 30`.

Still not verified here, and stated rather than implied: the weekly `schedule` trigger has never
fired (it cannot be forced), and the `pull_request` path filter has not been exercised by a real
image-touching pull request. Both are configurations this run does not cover.
