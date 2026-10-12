# `monitor/fixtures/` — the replay corpus

One directory per fixture. Each holds a `fixture.yaml` manifest, the raw per-source input files it
declares, and `expected/monitor_events.jsonl` — the golden output the aggregator produces from
those inputs. Landed at M2-T2.7a.

```
monitor/fixtures/<fixture-id>/
├── fixture.yaml                  # provenance and replay parameters (format below)
├── falco.jsonl                   # present only for a declared source
├── prometheus.json               #   "
├── k8s_audit.jsonl               #   "
├── trivy.json                    #   "
└── expected/
    └── monitor_events.jsonl      # golden output, G0-FULL arm, committed
```

The four input filenames are not free. Each is declared on its source's row of the registry in
`monitor/aggregator/normalize.py` and derived mechanically from the `EvidenceSource` value, so a
fixture author never has to look one up. A directory holding none of the four is an error rather
than an empty replay.

## Two halves: six synthesised fixtures and four captured ones

The six fixtures landed at T2.7a were written **from published schemas and documentation**. None of
them was captured from a running Falco, Alertmanager, API server or Trivy, every identifier in them
is invented, and each manifest's `synthesised_from` names the document its record shape was read
from so a reviewer can check the shape without a cluster.

The four `*-live-capture` fixtures landed at **T2.7b** are the other half: each is a payload
recorded byte-for-byte from the corresponding live source on the kind cluster, and each names the
commit that captured it and the version of the tool that produced it.

That is not a caveat, it is the point. `docs/protocols/evaluation-protocol.md` §4 owns the evidence
caps and the Monitor latency budget; those values freeze at `v1.0`, govern every run, and are quoted
in Chapter 4. Derived from fixtures written by hand they would describe the fixtures rather than the
system — a number that survived the freeze without ever having met real telemetry. M1 set the
precedent for its own constants: they are *measured, not chosen*. T2.7b has now captured fixtures from all four live sources, so the §4 row waits only on
**T2.5b**, the study that derives the caps and the budget from them. That study needs a derivation
rule -- which statistic, how much headroom -- that no document in this repository yet states, and
choosing one is not a capture decision. What this corpus proves is emission ordering, quoting, cap
*semantics* and byte-level determinism, and now also what a real payload from each source looks
like. What it still does not prove is cap calibration.

`provenance: captured` is the value T2.7b's fixtures carry. The reader enforces the difference:
a `synthesised` fixture must name what it was synthesised from and must leave `capture_commit` and
`source_tool_version` empty; a `captured` one must fill both. Both keys are present and empty in the
synthesised half so that a capture fills a line rather than adding one.
`monitor/tests/test_determinism.py` checks both shapes, and separately requires that every one of
the four source families is represented by at least one captured fixture -- a corpus that had
captured three families out of four would let T2.5b be run over a source whose real payload had
never been seen.

## The `corpus_cap_*` values are NOT the caps `evaluation-protocol.md` §4 owns

`monitor/aggregator/limits.py` mirrors §4 and **fails closed**: while §4's caps still read
`PENDING-M2-FIXTURE-STUDY`, the aggregator refuses to run rather than bounding evidence by a number
nobody has measured. That is deliberate (ADR-019), and it means this corpus cannot replay at all
unless each fixture supplies cap values of its own. Those values are **fixture-corpus test
parameters**. Five things keep them from ever being mistaken for protocol values:

1. **They live inside the corpus, one set per fixture.** There is no corpus-wide constant and no
   default in any module, so nothing here is shaped like *the* cap value.
2. **The key names are disjoint from §4's.** `corpus_cap_excerpt_count_max` is not
   `evidence_excerpt_count_max`. A `git grep` for a §4 key finds §4 and `limits.py` and nothing
   under this directory, which is the form the milestone's Definition of done uses to check that a
   value is single-homed.
3. **Every manifest carries a refusable sentinel.** `corpus_cap_status` must read
   `FIXTURE-CORPUS-TEST-PARAMETER` or the fixture does not load. Promoting one of these numbers
   into §4 means first deleting a line that says, in the file, that it is not a §4 number.
4. **The values disagree between fixtures on purpose.** `falco-shell-in-container` caps tight so
   truncation and excerpt selection are exercised; `adversarial-quoting-shapes` caps loose so every
   injection shape survives into the golden output. A corpus with several disagreeing values offers
   no candidate to promote.
5. **Both gates print the disclaimer on every run**, so it appears in the log of every replay
   rather than only in this file.

`monitor/tests/test_determinism.py` asserts 2 and 3 mechanically.

## `fixture.yaml`

A flat `key: value` file — **no nesting, no lists, no indentation**. This is a format decision, not
a simplification: `scripts/monitor_replay.sh` and `scripts/monitor_determinism.sh` read it with
`awk` (there is no `jq` in the toolchain) and `monitor/tests/replay_harness.py` reads it with the
standard library, and neither may need PyYAML. Lines are `key: value`, or a bare `key:` for a value
that is deliberately empty; `#` begins a comment; keys are lower case with underscores; a duplicate
key is an error rather than last-one-wins.

The key set is **exact**. A missing key and an unexpected key are both errors, in the same spirit as
ADR-016's mirror tests — a reader that only checked for the keys it needed could not catch one
silently deleted or misspelt.

| Key | Meaning |
|---|---|
| `fixture_id` | must equal the directory name; it is what every gate prints |
| `source` | comma-separated `EvidenceSource` values, **in source-registry order** — the order events are emitted in. Must match exactly the input files present |
| `provenance` | `synthesised` or `captured`. See above |
| `synthesised_from` | the schema or documentation the record shape was read from. Required when `provenance: synthesised`, and the reason a reviewer can check the shape without a cluster |
| `capture_commit` | the commit that captured the fixture. Empty while synthesised; T2.7b fills it |
| `source_tool_version` | the version of the source tool that produced it. Empty while synthesised |
| `seed` | the seed a generated fixture replays from. Present and empty throughout this corpus: nothing in it is produced by a seeded process, and a key that only appears when it applies is a key an `awk` reader has to special-case |
| `golden_arm` | `G0-FULL` — the arm `expected/monitor_events.jsonl` was emitted under, spelled with the canonical condition ID from `AGENTS.md`. The `G3-UNQUOTED` arm is compared against the quoted one in `monitor/tests/test_g3_isolation.py` and is never itself a golden file |
| `audit_severity` | the severity assigned to every `k8s_audit` record in this fixture. Required exactly when the fixture declares that source, and forbidden otherwise. The audit stream carries no severity and its `level` field is a verbosity setting, not a ranking; the per-rule assignment is authored at **T2.4**, so until then the fixture states it explicitly. There is deliberately no default |
| `corpus_cap_status` | must read `FIXTURE-CORPUS-TEST-PARAMETER`. See above |
| `corpus_cap_excerpt_count_max` | how many excerpts one event of this fixture may carry |
| `corpus_cap_excerpt_length_max_chars` | length bound on one excerpt, in **source characters before quoting** |
| `corpus_cap_summary_length_max_chars` | length bound on the summary, same unit |
| `description` | what this fixture covers and why it exists |

## The corpus today

| Fixture | Sources | Covers |
|---|---|---|
| `adversarial-quoting-shapes` | falco, k8s_audit | every injection shape `quoting.py` defends against, in fields an attacker can set |
| `falco-shell-in-container` | falco | the priority ladder, the subject ladder, out-of-order timestamps, both caps binding |
| `four-source-incident` | all four | the ordered registry *across* sources; every component of the total order |
| `k8s-audit-anonymous-exec` | k8s_audit | exec subresource, a forbidden request, a non-resource URL |
| `prometheus-alertmanager-webhook` | prometheus | one grouped webhook body, three severities, the annotation preference order |
| `trivy-image-report` | trivy | the two-level group walk, document and group context, an empty result |
| `falco-live-capture` | falco | **captured** — six real alerts from the live Falco DaemonSet, three rules, three priorities |
| `k8s-audit-live-capture` | k8s_audit | **captured** — six real records from the kind control-plane audit log, including a `RequestResponse` body |
| `prometheus-live-capture` | prometheus | **captured** — one real grouped webhook body off the wire from the live Alertmanager |
| `trivy-live-capture` | trivy | **captured** — one unmodified real `trivy image` report, twenty real findings plus an empty result |

## Running the corpus

```sh
sh scripts/monitor_replay.sh                       # every fixture, diffed against golden
sh scripts/monitor_replay.sh F=falco-shell-in-container   # one fixture
sh scripts/monitor_determinism.sh                  # every fixture twice, byte-compared
make monitor-replay                                # the same, through the target contract
```

Emitted output goes to `monitor/.replay/`, which is gitignored: a committed copy of it would be a
second answer to "what does this fixture produce", and the first time the two disagreed the
repository would hold a golden file that no longer describes the aggregator.

## Regenerating golden output

```sh
python -m monitor.tests.replay_harness --out-root monitor/.replay/update --update-golden
```

This is a **reviewed diff, never a way to make a failing gate green**. Every golden file is the
aggregator's output byte for byte, so a diff here means the aggregator's behaviour changed and the
change is what needs reviewing. After the `v1.0` freeze, iron rule 6 makes it a logged hotfix ADR.
Update mode always emits the `G0-FULL` arm, so `--no-quoting` cannot rewrite the corpus as the
ablation arm.

## Adding a fixture

1. Create `monitor/fixtures/<id>/` and write the raw inputs, in **binary with LF terminators** — a
   text-mode write on Windows puts CRLF into the input and every `raw_ref` byte offset then
   describes a file no other machine would produce.
2. Write `fixture.yaml` with the exact key set above.
3. Generate the golden output with the command above and read the diff.
4. Run `sh scripts/monitor_replay.sh` and `sh scripts/monitor_determinism.sh`.

Keep every input file ASCII where the source content allows it, and express a dangerous character as
a JSON `\uXXXX` escape rather than as a literal. A raw control byte in a fixture is not valid JSON,
and a raw NUL would make `grep -I` treat the file as binary — which would silently drop it from
`scripts/monitor_guard.sh`'s scan. `adversarial-quoting-shapes` carries the full escape alphabet and
is pure ASCII on disk.
