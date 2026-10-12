r"""Format contracts for the M5 scenario library, plus the two standard-library readers that apply
them.

This directory is deliberately NOT one of the five content directories `.github/workflows/ci.yml`
arms the nightly determinism run on -- `chaosmesh/`, `cve/`, `attackers/`, `groundtruth/` and
`manifests/` are those five. Schemas can therefore land ahead of the corpus without arming a check
whose corpus does not exist yet, which is what conflict M5-C1 is about.

Six schemas, each the single definition of its format:

* ``scenario_manifest.v1.json`` -- what a scenario IS.
* ``groundtruth.v1.json`` / ``groundtruth.v2.json`` / ``groundtruth.v3.json`` -- what a correct
  response to one looks like. v2 (ADR-088) makes a required substep's ``check`` mandatory instead
  of optional, so that per-phase completeness is read off a predicate rather than off a shared
  file's presence. v3 (M10 WS-2; D1-A, SEAM 5) adds ``cluster-executed-any``/``-none`` over the
  unified executed-action stream, which is what every end-state-compromise check now reads. v1 and
  v2 stay on disk as the record of what shipped before each ruling -- existing sealed bundles pin
  their own ``groundtruth_sha256`` over the bytes they were scored against -- while the live corpus
  (every file under ``scenarios/groundtruth/``) is v3, and ``scenarios/tests/test_corpus.py`` checks
  it against v3 only.
* ``injection_plan.v1.json`` -- one event of an injected sequence, in a plan and in a bundle's
  ``injection.log.jsonl`` alike.
* ``content_pool.v1.json`` -- one injection class's payload registry, validated before
  ``scenarios/attackers/content.py::load_pool`` applies its positional-contiguity check (ADR-117:
  schema first). It carries its OWN copy of the ground-truth ``check`` shape in ``$defs``, because
  ``validate.py`` resolves only same-document references; ``test_schemas.py`` pins the copy equal to
  ``groundtruth.v3``'s, which is what makes an instance's ``induced_action`` a ground-truth check by
  construction rather than by resemblance.
* ``scores.v1.json`` -- the researcher's judgements, with the value ranges
  ``docs/protocols/data-management.md`` section 3 says the M5 rubric fixes.
* ``assertions.v1.json`` -- a run bundle's scored result set.

The schemas are the definition and the code holds no second copy of them, which is why nothing here
can drift from them the way a hand-written model beside a hand-written schema would.
"""
