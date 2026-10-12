"""Unit tests for the load-profile registry and the two pins that must not drift away from it.

WHAT THESE TESTS ARE PROTECTING
    The load-profile registry is the file that gives the run-manifest field `load_profile_id` a set
    of values to range over (docs/protocols/data-management.md section 2). Three separate documents
    already depend on it in ways that no compiler checks: the glossary uses one of its identifiers
    in a worked example, data-management makes "same load profile" a validator rule, and the M1
    Definition of Done requires an identifier from outside the set to resolve to nothing. Each of
    those is an assertion about this repository's own files, so each can be a unit test, and the
    ones below are exactly those.

    Two of the tests are not about the registry at all. They hold the Online Boutique release ref
    and the Locust image digest -- values that infra/versions.env owns and that a Kubernetes or
    Kustomize file has to repeat as a literal, because neither format can read an environment
    variable -- equal to the copies in those files. That mirror-and-test arrangement is the M1
    plan's answer to a value that must exist in two places, and the test is the half that makes it
    legal: drift fails a check rather than surviving quietly into a sealed bundle whose
    versions_env_sha256 then describes a stack that was never deployed.

NO CLUSTER, NO NETWORK, NO YAML LIBRARY
    docs/04-repo-conventions.md section 4 gives infra/ its own pytest step in CI, and that step runs
    on ubuntu-latest with pytest installed and nothing else -- no kind, no kubectl, no Locust, no
    PyYAML. Everything below therefore reads files from this checkout and nothing else, and reads
    the registry through the standard-library subset parser in infra/locust/registry.py rather than
    through a YAML library that is not there. A test here that needed a running cluster would fail
    on every pull request for a reason unrelated to the change under review.

PATHS COME FROM __file__, NEVER FROM THE WORKING DIRECTORY
    `python -m pytest infra/tests` from the repository root and `pytest` from inside infra/tests
    have different working directories and must produce the same result, so every path below is
    derived from this file's own location.

REACHING FOR A PRIVATE NAME
    One test calls `registry._read_registry` on a file it writes for the occasion. That is
    deliberate: the parser's promise is that it refuses what its documentation says it refuses, and
    the only way to test a refusal is to hand it something refusable. The underscore marks the name
    as outside the contract the runner imports, not as untestable.
"""

import re
import sys
from dataclasses import fields
from pathlib import Path

import pytest

# parents[2] is the repository root: this file is infra/tests/test_load_profiles.py.
REPO_ROOT = Path(__file__).resolve().parents[2]
VERSIONS_ENV = REPO_ROOT / "infra" / "versions.env"
BOUTIQUE_KUSTOMIZATION = REPO_ROOT / "infra" / "boutique" / "kustomization.yaml"
LOCUST_DEPLOYMENT = REPO_ROOT / "infra" / "locust" / "deployment.yaml"
LOCUSTFILE = REPO_ROOT / "infra" / "locust" / "locustfile.py"
PROFILES_FILE = REPO_ROOT / "infra" / "locust" / "profiles.yaml"

# Importable whether pytest was invoked as `python -m pytest` from the root, which puts the root on
# sys.path, or as a bare `pytest` from somewhere else, which does not.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.locust import registry  # noqa: E402

# The identifier form docs/07-glossary-and-ids.md fixes for a load profile, written out here rather
# than imported from the module under test. Importing it would make this test assert that the module
# agrees with itself, which is true of any regular expression the module happens to hold.
GLOSSARY_PROFILE_ID_FORM = re.compile(r"LOAD-[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*")

# The keys the deliberate omission of a run duration has to survive. profiles.yaml's header and
# infra/locust/registry.py both explain why there is no such field; this list is what stops one
# reappearing under a synonym.
DURATION_LIKE = ("duration", "run_time", "runtime", "run_seconds", "time_limit", "seconds")

REQUIRED_FIELDS = ("id", "locustfile", "users", "spawn_rate", "host", "description")

# A digest as it appears in an image reference, and a git ref as it appears in a Kustomize remote
# resource URL.
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# Stops at an ampersand: the resource URL carries Kustomize's own timeout and submodules
# parameters alongside the ref, and only the ref is the pin under test.
KUSTOMIZE_REF = re.compile(r"\?ref=([^\s&]+)")


def _uncommented_lines(path: Path) -> list[str]:
    """Return the lines of a file that are neither blank nor whole-line comments.

    Every file this module inspects carries a long prose header that quotes the very literals being
    checked -- the ref, the digest, the word duration. Searching the raw text would match the
    explanation as readily as the value, so the explanation is removed first.
    """
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _versions_env() -> dict[str, str]:
    """Parse infra/versions.env into a plain mapping.

    The file's own contract (its header, rule 1) is that every line is a plain key and value pair
    with no shell expansion, so a split on the first equals sign is the whole parser.
    """
    values: dict[str, str] = {}
    for line in _uncommented_lines(VERSIONS_ENV):
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _embedded_locustfile() -> str:
    """Return the load script as infra/locust/deployment.yaml embeds it, de-indented.

    The ConfigMap carries the script in a literal block scalar indented by four spaces. Blank lines
    inside the block are genuinely empty rather than four spaces of whitespace, which is both what
    the repository's line-ending and trailing-whitespace hygiene requires and what YAML produces.
    """
    marker = "  locustfile.py: |"
    lines = LOCUST_DEPLOYMENT.read_text(encoding="utf-8").split("\n")
    assert marker in lines, f"{LOCUST_DEPLOYMENT} no longer embeds the load script under {marker!r}"

    body: list[str] = []
    for line in lines[lines.index(marker) + 1 :]:
        if line == "":
            body.append("")
        elif line.startswith("    "):
            body.append(line[4:])
        else:
            break
    return "\n".join(body) + "\n"


def test_both_registry_entries_resolve() -> None:
    """Every identifier the registry declares resolves to a profile, and there are two of them.

    Two is the point rather than an incidental count. With one entry `load_profile_id` would be a
    constant, and data-management section 2's rule that a pairing whose two runs carry different
    load profile identifiers is rejected would be a rule no data could ever violate.
    """
    profiles = registry.list_profiles()
    assert [profile.id for profile in profiles] == ["LOAD-STEADY", "LOAD-LIGHT"]

    for profile in profiles:
        assert registry.resolve(profile.id) == profile

    # The second entry is the lower-concurrency one, so the two are genuinely different operating
    # points and not the same load written twice.
    steady = registry.resolve("LOAD-STEADY")
    light = registry.resolve("LOAD-LIGHT")
    assert light.users < steady.users


def test_load_steady_exists_because_the_glossary_uses_it() -> None:
    """LOAD-STEADY specifically must be in the registry.

    docs/07-glossary-and-ids.md gives BASE-LOAD-STEADY-101 as its worked example of a baseline run
    identifier, where the middle component is a load profile identifier. If this entry were renamed,
    the canonical example in the file that owns the identifier's form would name a profile that does
    not exist, and data-management section 2 would reject any run carrying it. That is why this
    assertion is separate from the one above: the general property is that every declared entry
    resolves, and this specific string is a commitment to another document.
    """
    profile = registry.resolve("LOAD-STEADY")
    assert profile.id == "LOAD-STEADY"
    assert profile.users >= 1
    assert profile.spawn_rate >= 1
    assert profile.host
    assert profile.locustfile_path.is_file()


def test_an_identifier_outside_the_registry_resolves_to_nothing() -> None:
    """An unknown identifier raises, and the command line exits non-zero.

    This is the M1 Definition of Done item "an outside ID resolves to nothing, demonstrated once",
    and it is checked at both layers because both are used: the runner imports resolve(), while the
    Definition of Done's own command is the module's command line.
    """
    with pytest.raises(registry.UnknownLoadProfile):
        registry.resolve("LOAD-NOPE")

    # Case matters, and so does the prefix. Neither near miss may quietly succeed.
    for near_miss in ("load-steady", "STEADY", "LOAD-STEADY ", "BASE-LOAD-STEADY-101"):
        with pytest.raises(registry.UnknownLoadProfile):
            registry.resolve(near_miss)

    assert registry.main(["--resolve", "LOAD-NOPE"]) != 0
    assert registry.main(["--resolve", "LOAD-STEADY"]) == 0
    assert registry.main(["--list"]) == 0


def test_every_entry_carries_every_field_and_no_duration() -> None:
    """The schema is complete, and the field that is deliberately missing stays missing.

    A profile is a load shape. How long a measurement window runs is a property of a run, and no
    file in docs/protocols/ owns that number, so putting one here would create a quantitative
    parameter with no owner -- which .agents/rules/00-source-of-truth.md forbids. The omission is
    guarded from four directions, because it is the kind of gap a later contributor fills in good
    faith: the dataclass carries exactly six fields, each resolved profile has a usable value for
    each of them, the registry file itself mentions no duration key outside its prose, and the
    parser refuses one outright.
    """
    assert tuple(field.name for field in fields(registry.Profile)) == REQUIRED_FIELDS

    for profile in registry.list_profiles():
        assert isinstance(profile.users, int) and profile.users >= 1
        assert isinstance(profile.spawn_rate, int) and profile.spawn_rate >= 1
        for name in ("id", "locustfile", "host", "description"):
            value = getattr(profile, name)
            assert isinstance(value, str) and value.strip(), f"{profile.id}: {name} is empty"

    for line in _uncommented_lines(PROFILES_FILE):
        key = line.lstrip(" -").partition(":")[0].strip()
        assert key.lower() not in DURATION_LIKE, f"a duration-like key reappeared: {line!r}"


def test_the_parser_refuses_a_duration_key(tmp_path: Path) -> None:
    """Handing the parser a duration field fails loudly, and the message says why.

    The previous test proves the registry has no duration today. This one proves that adding one
    cannot succeed tomorrow, which is the difference between a convention and a guard.
    """
    candidate = tmp_path / "profiles.yaml"
    candidate.write_text(
        "profiles:\n"
        "  - id: LOAD-STEADY\n"
        "    locustfile: locustfile.py\n"
        "    users: 10\n"
        "    spawn_rate: 1\n"
        "    host: http://frontend.boutique.svc.cluster.local\n"
        "    description: a profile that tries to carry a duration\n"
        "    duration: 600\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(registry.ProfilesFormatError) as failure:
        registry._read_registry(candidate)
    assert "duration" in str(failure.value)


def test_every_identifier_matches_the_glossary_form() -> None:
    """Every registry id is of the LOAD-SLUG form docs/07-glossary-and-ids.md fixes.

    The form matters beyond tidiness. A baseline run identifier is BASE-<LOAD>-<SEED> with a fixed
    three-digit seed at the end, so a profile identifier whose last hyphen-separated component were
    all digits would make BASE-LOAD-STEADY-101 ambiguous about where the profile stops. Requiring
    every component to start with a letter is what removes that ambiguity.
    """
    for profile in registry.list_profiles():
        assert GLOSSARY_PROFILE_ID_FORM.fullmatch(profile.id), profile.id
        assert profile.id == profile.id.upper()


def test_boutique_manifest_ref_matches_versions_env() -> None:
    """The release ref in the Kustomize overlay equals BOUTIQUE_MANIFEST_REF.

    Kustomize cannot read an environment variable, so infra/boutique/kustomization.yaml carries the
    upstream release ref as a literal in its remote resource URL while infra/versions.env stays the
    pin of record -- it is one of the values every run manifest's versions_env_sha256 closes over.
    Two homes for one value is a defect unless something holds them equal; this is that something.
    """
    declared = _versions_env().get("BOUTIQUE_MANIFEST_REF", "")
    if not declared:
        pytest.skip(
            "BOUTIQUE_MANIFEST_REF is empty in infra/versions.env. Empty values are correct before "
            "the task that populates the application group (that file's header, rule 2), so there "
            "is nothing to compare yet rather than a disagreement to report."
        )

    refs = [
        match.group(1)
        for line in _uncommented_lines(BOUTIQUE_KUSTOMIZATION)
        for match in [KUSTOMIZE_REF.search(line)]
        if match
    ]
    assert len(refs) == 1, (
        f"expected exactly one pinned ref in {BOUTIQUE_KUSTOMIZATION}, got {refs}"
    )
    assert refs[0] == declared, (
        f"{BOUTIQUE_KUSTOMIZATION} pins {refs[0]!r} while infra/versions.env declares "
        f"BOUTIQUE_MANIFEST_REF={declared!r}. Change both in one commit."
    )


def test_locust_image_digest_matches_versions_env() -> None:
    """The image digest in the Locust manifest equals LOCUST_IMAGE_DIGEST.

    Same arrangement, same reason, for a Kubernetes manifest instead of a Kustomize one. The
    comparison is made on digests rather than on whole strings because infra/versions.env may
    reasonably spell its value either as a bare sha256 digest or as a full image reference carrying
    one, and both mean the same pin.
    """
    declared = _versions_env().get("LOCUST_IMAGE_DIGEST", "")
    if not declared:
        pytest.skip(
            "LOCUST_IMAGE_DIGEST is empty in infra/versions.env. Empty values are correct before "
            "the task that populates the application group (that file's header, rule 2), so there "
            "is nothing to compare yet rather than a disagreement to report."
        )

    declared_digest = DIGEST.search(declared)
    assert declared_digest, (
        f"LOCUST_IMAGE_DIGEST={declared!r} carries no sha256 digest; a tag is not a pin."
    )

    found = {
        match for line in _uncommented_lines(LOCUST_DEPLOYMENT) for match in DIGEST.findall(line)
    }
    assert len(found) == 1, f"expected exactly one image digest in {LOCUST_DEPLOYMENT}, got {found}"
    assert found.pop() == declared_digest.group(), (
        f"{LOCUST_DEPLOYMENT} and infra/versions.env pin different Locust images. "
        "Change both in one commit."
    )


def test_the_embedded_locustfile_is_the_locustfile() -> None:
    """The ConfigMap in the Locust manifest carries infra/locust/locustfile.py byte for byte.

    The manifest is applied as one file with no build step, so the load script has to travel inside
    it. That is a second copy of a source file, and a second copy without a check is how two
    artefacts start pretending to be one: the linted, reviewed script on disk and the different
    script that is actually driving the application under measurement.
    """
    assert _embedded_locustfile() == LOCUSTFILE.read_text(encoding="utf-8"), (
        f"the block in {LOCUST_DEPLOYMENT} no longer matches {LOCUSTFILE}. Re-indent the script by "
        "four spaces and replace the block, in the same commit as the edit to the script."
    )
