# `scenarios/cve/` — the CVE arm: real vulnerabilities, pinned, mirrored and seeded

This directory holds the digest pins for the known-vulnerable container images the CVE scenarios
admit into the `boutique` namespace (`images.yaml`), the procedure for mirroring those images
locally, and nothing else. The mirror tarballs themselves are gitignored; see
[The mirror procedure](#the-mirror-procedure) for why, and `scripts/cve_mirror.sh` for the check.

## What the CVE arm is for, and what it is not for

§3.5.6 of the dissertation states the design as two mechanisms combined for two different purposes.
The CVE arm carries the first: **"real-CVE injection … for the demonstration area's ecological
grounding"**. The SIM arm carries the second: **"controlled, repeatable manipulation the rigorous
ablations require"**. Both fragments are from the same sentence, and the pairing is the point —
neither mechanism is a degraded version of the other.

What follows from that split, and what does not:

- The CVE arm's job is **ecological grounding**. A result obtained only against faults the
  researcher wrote is a result about the researcher's imagination; a result obtained against a real,
  published, independently-catalogued vulnerability is evidence about the class of thing that
  actually happens to clusters. That is what RQ3's demonstration area needs and what a simulated
  incident cannot supply at any level of fidelity.
- The SIM arm's job is **manipulability**. The ablations need a perturbation whose every parameter
  can be held constant across arms and varied on purpose, which a real CVE, whose behaviour is
  whatever the vulnerable software does, is a poor instrument for.
- The split is about **provenance, not grid position**. All five scenarios run in all six arms under
  all five injection conditions, per `docs/protocols/evaluation-protocol.md` §2. A CVE scenario is
  not a special case of the grid; it is an ordinary cell whose incident happens to be real.
- The CVE/SIM split, the scenario slate and the two-CVE count are **kit engineering**, not
  dissertation-derived. §3.5.6 fixes the count of scenarios and the phase-coverage constraint and
  names no individual scenario (conflict M5-C2). ADR-034 records the composition and its rejected
  alternatives.

## What the seed varies on a CVE scenario (M5-C6)

Conflict **M5-C6** is that the CVE arm's determinism claim is vacuous unless this is written down.
`evaluation-protocol.md` §2 runs every scenario through every injection condition at every seed in
every arm, so a CVE scenario is seeded exactly like a SIM one — but if the seed reached nothing on a
CVE scenario, then "same seed twice → identical injected sequence" would be true because there was
nothing for the seed to vary, and `make determinism-check` would pass over it while asserting
nothing. A gate that cannot fail is not a gate.

The statement below is `docs/plans/M5-implementation-plan.md` §D13, verbatim. It is reproduced here
rather than referenced because this is the file a reader of the CVE arm reaches first, and it is
restated in each CVE scenario's manifest for the same reason:

> On a CVE scenario the vulnerable image and the vulnerability are fixed — that is what makes the
> scenario a CVE scenario. The seed varies the *approach*: the timing offsets of the exploitation
> steps, the selection order within the attacker's action set, the payload instances drawn from the
> class's content pool, and the target replica among identical ones. Two runs of one CVE scenario
> at different seeds face the same vulnerability reached differently; two runs at the same seed are
> byte-identical plans. Without this stated, `(scenario_id, seed)` determinism on the CVE arm is
> trivially true and the check passes over nothing.

Two consequences worth making explicit:

1. **The image is not a seeded quantity.** `images.yaml` is a pin, and a pin that varied by seed
   would not be a pin. Everything the seed touches is in the plan the attacker module emits, not in
   the image the scenario admits.
2. **The determinism gate compares plans, not outcomes.** Per §D1, the planner is pure and offline
   and the applier is what meets the cluster; the `cmp` covers the injected sequence and never the
   vulnerable software's response to it. A CVE whose exploitation succeeded on one run and failed on
   the next is a measurement, and measurements are what the campaign's repetitions are for.

## The two CVE scenarios

ADR-091 (2026-09-13) supersedes ADR-079. ADR-079 admitted a Log4Shell-vulnerable Apache Solr image
as a fixed-name `cve-lab` sidecar beside an unrelated Boutique service's real server, its command
overridden so it never actually ran — the supervisor rejected that design outright ("An image that
cannot serve its host service's protocol is not an admissible design", ruling B1), and its own
consequences section already admitted SCN-CVE-05's exploit reached only the co-located sidecar, not
a real Boutique call edge. Both scenarios now admit a vulnerable build of **adservice itself** — the
only Java service this Boutique deployment runs, and the one workload whose own dependency graph can
honestly carry `log4j-core` without inventing a vulnerability the service's own build does not have.

| Scenario | First signal | What happens | Image entry | Source |
|---|---|---|---|---|
| `SCN-CVE-04` | `trivy` | The vulnerable adservice build is admitted into `boutique` and the scanner reports a critical CVE **before** any exploitation | `CVE-SCN-04-adservice` | engineering build (this project's own recipe) |
| `SCN-CVE-05` | `falco` | The identical vulnerable adservice build is exploited over its own gRPC edge at runtime; Falco sees a sensitive-file read | `CVE-SCN-05-adservice` | engineering build (this project's own recipe) |

Both entries pin the **same** vulnerable image — adservice's own source at the pinned upstream ref
(`v0.10.6`, `infra/versions.env`'s `BOUTIQUE_MANIFEST_REF`), rebuilt with `log4j-core` forced to the
Log4Shell-unpatched `2.14.1` — swapped directly onto adservice's own `server` container, not onto a
sidecar beside it (researcher/supervisor decision, 2026-09-13: the pair may share one image,
differing in scenario *stage* rather than in target). What the scanner and the runtime detector
report is a property of the admitted image, and holding it identical across the pair keeps the
contrast about the **detection surface** alone: `SCN-CVE-04` stops before exploitation and its first
evidence is the scan; `SCN-CVE-05` reaches the vulnerable library over adservice's own `GetAds` gRPC
edge — the same edge the frontend's home and product pages call — before the scan lands, so its
first evidence is a syscall. `images.yaml`'s own header carries the rest of the argument, including
why the patched half is a checked mirror of `infra/boutique/images.yaml`'s own adservice pin rather
than a separately-built image.

### Building the vulnerable image

The vulnerable build does not exist until an operator produces it — unlike ADR-079's Solr entries,
there is no public tag to pull. `scenarios/cve/adservice/build_and_pin.sh` fetches adservice's own
pinned source, patches exactly one dependency version and builds it locally; it never pushes and
never resolves a digest itself, on the same "print the command, let the operator run it" discipline
`scripts/cve_mirror.sh` already keeps for the mirror. Run `sh
scenarios/cve/adservice/build_and_pin.sh --vulnerable`, read its printed next steps, push the result
to a registry you control, and continue with the mirror procedure below exactly as written — that
script's own header carries the full argument for why the build is shaped the way it is, and why the
"patched" pin is recommended to stay a mirror of the fleet's own image rather than a second build.

### Preload and admission preflight

`scripts/up.sh` loads a pinned CVE mirror tarball into every kind node as its own layer (after
Guardian), and then runs `scripts/cve_admission_preflight.sh <scenario_id>` for each scenario
whose image it just loaded — confirming the image is present in every node's containerd store and
the target Deployment is fully Ready on its own current image, before any run's injection t0. Both
are non-fatal to bring-up while the CVE arm is still unpinned at Tier A: the three SIM scenarios need
neither. This closes supervisor ruling B1's second sentence ("Preload every scenario image into the
kind nodes at bring-up; admission preflight ... before injection t0"), motivated by an observed
4m58s uncached pull inside a timed run (2026-09-13) that would otherwise contaminate every latency
and wall-clock figure the run measures.

## The mirror procedure

### Why there is a mirror at all

A digest pin buys **immutability**, not **availability**. If the registry drops the manifest, the
digest resolves to nothing — more finally than a deleted tag would, because there is not even a
moved pointer to follow. `docs/milestones/M5-scenarios.md`'s Risks line describes these digests as
pinned "so they survive upstream deletion"; that is conflict **M5-C5**, and it is wrong. The mirror
is the mechanism that survives deletion, and known-vulnerable images are precisely the images a
registry has a standing incentive to withdraw.

The tarballs are hundreds of megabytes of container image apiece, so git cannot hold them. The
repository therefore carries a **verifiable recipe** for the mirror rather than the mirror: the
commands below, and one `tarball_sha256` per entry in `images.yaml`. The checksum is what makes it
verifiable rather than merely written down — a tarball recovered from a backup or a colleague's disk
is the image that ran only if its hash matches.

### Where the tarballs go

`scenarios/cve/tarballs/`, which is gitignored, anchored to that full path. `.gitignore`'s own
comment block carries the argument. Create it on first use:

```sh
mkdir -p scenarios/cve/tarballs
```

### Saving an image to a tarball

Everything below is **Tier B**: it needs a network and, for the last step, a running kind cluster.
Run it once per entry in `images.yaml`, substituting that entry's `repository`, `digest` and
`tarball`. Building the vulnerable image itself comes first — see
[Building the vulnerable image](#building-the-vulnerable-image) above — because, unlike ADR-079's
Solr entries, there is no public tag here to pull directly; `repository`/`digest` below are the
values you push to and resolve from your own registry after that build.
`sh scripts/cve_mirror.sh --save` prints these lines for every pinned entry, so the procedure can be
read off the corpus instead of transcribed by hand.

```sh
docker pull <your-registry>/<your-namespace>/adservice-log4shell@sha256:<digest>
docker save --output scenarios/cve/tarballs/cve-scn-04-adservice.tar \
    <your-registry>/<your-namespace>/adservice-log4shell@sha256:<digest>
```

Pull **by digest**, not by tag. Pulling by tag and saving the result is how a mirror ends up
holding bytes the pin does not describe: the tag may already have moved, and nothing downstream
would say so. Repeat for `cve-scn-05-adservice.tar`: by researcher/supervisor decision the two
entries pin the identical image, so the same pulled bytes are saved twice, once per entry, exactly
as `scripts/cve_mirror.sh --save` emits one `docker save` line per entry regardless of whether two
entries happen to name the same digest.

### Recording the checksum back into `images.yaml`

```sh
sha256sum scenarios/cve/tarballs/cve-scn-04-adservice.tar
```

On a host without GNU coreutils, `shasum -a 256 <file>` and `openssl dgst -sha256 <file>` produce
the same digest; `scripts/cve_mirror.sh` accepts whichever of the three it finds. Paste the 64 hex
characters — and nothing else — into that entry's `tarball_sha256` field, and the resolved image
digest into its `digest` field, in the same change, for **both** `CVE-SCN-04-adservice` and
`CVE-SCN-05-adservice`. Doing one without the other leaves the mirror holding one image while the
pin claims another, and `--verify` will not catch it: a tarball whose recorded checksum matches is a
tarball this repository believes.

### Loading a tarball into the cluster

```sh
kind load image-archive --name kind scenarios/cve/tarballs/cve-scn-04-adservice.tar
```

`--name kind` is the cluster name `scripts/up.sh` creates by default; if `KIND_CLUSTER_NAME` was
set when the cluster was created, pass that instead. `sh scripts/cve_mirror.sh --load` prints these
lines for every pinned entry, and `scripts/up.sh` now runs this step itself at bring-up once the
entries are pinned (see [Preload and admission preflight](#preload-and-admission-preflight) above).

`kind load image-archive` copies the image into every node's containerd store, so a pod scheduled
anywhere can start it without reaching a registry. That is the whole of the availability mechanism:
after this step the scenario runs with the registry unreachable or the tag withdrawn.

### Verifying the mirror

```sh
sh scripts/cve_mirror.sh --verify
```

Per entry it reports the tarball present or absent and, when present, whether its sha256 matches
the recorded `tarball_sha256`. **An entry with an empty `digest` or an empty `tarball_sha256` is
reported `unpinned` and fails.** It is not skipped, and that is deliberate: an unpinned entry
passing silently is exactly the vacuous pass this repository refuses everywhere else, and it is the
failure mode that would let a run proceed against an image nobody had pinned.

Both entries' vulnerable half is unpinned today (empty `digest` and `tarball_sha256`), so **`--verify`
exits 1 today**, and that is the correct state before Tier B — the same way `make parity-check` and
`scripts/monitor_determinism.sh` fail closed rather than reporting green over a corpus that is not
there. The script's header says so in its own words. The patched half is already pinned (a checked
mirror of `infra/boutique/images.yaml`'s own adservice pin — `images.yaml`'s own header explains
why that half needs no Tier B of its own), which is why `--verify`'s failure here is specifically
`unpinned` on the vulnerable digest, not a malformed-file error.

## What is Tier A and what is Tier B

| Step | Tier | Needs |
|---|---|---|
| `images.yaml` authored, entries and fields complete | A | nothing |
| `scripts/cve_mirror.sh` authored and failing closed | A | nothing |
| `CVE_IMAGE_DIGESTS_FILE` set in `infra/versions.env` | A | nothing |
| `patched_repository` / `patched_digest`, mirrored from `infra/boutique/images.yaml` | A | nothing (already resolved elsewhere) |
| Building the vulnerable adservice image (`scenarios/cve/adservice/build_and_pin.sh --vulnerable`) | **B** | network, Docker, git |
| Pushing it and resolving its `digest` against your registry | **B** | network |
| Producing each tarball and recording its `tarball_sha256` | **B** | network, Docker |
| `kind load image-archive` (now run by `scripts/up.sh` once pinned) and confirming presence in-cluster | **B** | M1's cluster |
| Running `SCN-CVE-04` / `SCN-CVE-05` end to end | **B** | M1's cluster, M2's Falco and Trivy |

## Files

| Path | What it is |
|---|---|
| `images.yaml` | the digest pins and mirror record; named by `CVE_IMAGE_DIGESTS_FILE` |
| `README.md` | this file |
| `adservice/build_and_pin.sh` | builds the vulnerable (and, optionally, a reference-patched) adservice image from its own pinned upstream source |
| `trivy-scan-job.template.yaml` | per-run Trivy scan Job template the `cve` mechanism applies against the admitted image (ADR-091, Integration) |
| `../../scripts/cve_admission_preflight.sh` | image-present + rollout-Ready check before a run's injection t0; lives under `scripts/` (not here) because `scripts/scenario_guard.sh` refuses a second cluster-touching file under `scenarios/`; run by `scripts/up.sh` and available for a runner-side per-run check |
| `tarballs/` | the mirror; gitignored, created on first use, never tracked |
| `../../scripts/cve_mirror.sh` | `--verify` the mirror, `--save` and `--load` print the procedure |

## Related

- ADR-091 — supersedes ADR-079: adservice replaces the `cve-lab` sidecar; the build recipe, the
  Trivy per-run trigger and the admission preflight this directory now carries.
- ADR-079 — the sidecar-and-allowlisted-remediation design ADR-091 supersedes; kept for the record
  of what did not work and why.
- `docs/plans/M5-implementation-plan.md` §D9 (three mechanisms), §D13 (what the seed varies),
  conflicts M5-C5 and M5-C6.
- ADR-038 — CVE image availability: pin is identity, mirror is availability. (The plan's §ADRs
  section proposes this as ADR-031; 027–033 were taken by M4 before M5 began, so M5's ADRs land at
  034 and up and this one is 038.) Written against the original productcatalogservice/paymentservice
  sidecar corpus; its pin-versus-mirror argument holds unchanged under ADR-091, its worked example
  does not.
- ADR-034 — scenario suite composition and the CVE/SIM split. Its Log carries the earlier
  productcatalogservice/paymentservice-versus-adservice naming drift this same redesign now resolves
  in adservice's favour, for the reason ADR-091 gives.
- `docs/06-risk-register.md` R-06 and its neighbourhood, where CVE image availability is the risk
  this directory's mirror is the mitigation for.
