"""Resolution contract for the load-profile registry in infra/locust/profiles.yaml.

WHAT THIS MODULE IS FOR
    docs/protocols/data-management.md section 2 makes `load_profile_id` a required field of every
    run manifest and states that a manifest whose value resolves to no registry entry is rejected.
    Something has to do the resolving, and it has to be importable: the runner needs it when it
    seals a bundle, the campaign validator needs it when it checks a matched pair, and a human
    needs it from a shell when a manifest is under suspicion. That is this module, and the whole of
    its contract is three names -- `resolve`, `list_profiles` and `UnknownLoadProfile`.

WHY IT PARSES YAML ITSELF INSTEAD OF IMPORTING A YAML LIBRARY
    The unit tests for infra/ run on ubuntu-latest in a CI step that installs pytest and nothing
    else, so PyYAML is not there. That constraint could have been removed by adding a dependency,
    and was not, for a reason that outlives the CI configuration: this module sits between a sealed
    run bundle and the registry its `load_profile_id` is checked against, and every dependency on
    that path is a way for the check to become unavailable exactly when it is needed -- on a machine
    that is reproducing a two-year-old result from a clean checkout.

    The cost is that this file must not pretend to parse YAML. It parses a subset, it says exactly
    which subset, and it fails loudly on anything else rather than guessing. The failure mode a
    home-grown parser must never have is silent disagreement with a real one -- a file that PyYAML
    reads as a boolean and this reads as the text of one -- so every construct where the two could
    differ is rejected rather than interpreted.

THE ACCEPTED SUBSET, IN FULL
    Structure
        Exactly one top-level key, `profiles:`, at column zero with no value on its line, followed
        by a block sequence. Each sequence entry begins with a dash and one space at exactly two
        spaces of indent and carries its first key on that line; the entry's remaining keys sit at
        exactly four spaces. Any other indentation is an error, not a reinterpretation. Entries are
        flat: a value is always a scalar, never a nested mapping or sequence.
    Keys
        Lowercase ASCII, digits and underscores, starting with a letter. A key may appear once per
        entry.
    Scalars
        An integer is an optionally signed run of ASCII digits. A quoted scalar is wrapped in
        matching single or double quotes and contains no quote of that kind and no escape sequences.
        Anything else is a plain string, taken verbatim after the single space that follows the
        colon.
    Comments and blank lines
        A line whose first non-space character is a hash is a comment. Blank lines are ignored.
        There are no trailing comments: a plain scalar containing a space followed by a hash is
        rejected, because YAML would strip it and this parser would not.
    Rejected outright, each because a real parser would read it differently or read it at all
        Tabs anywhere. Trailing whitespace on any line. A plain scalar that is empty, or that starts
        with any of the YAML indicator characters, or that contains a colon followed by a space, or
        that ends with a colon, or that spells a YAML boolean or null in any case. Anchors, aliases,
        tags, flow collections, block scalars, multi-line plain scalars, multiple documents, and any
        key the registry schema does not define.

    Write ordinary YAML inside those lines and PyYAML and this module agree. Step outside them and
    you get a message naming the file and the line, which is the outcome this design is chosen for.

SCHEMA, AND THE FIELD THAT IS NOT THERE
    Every entry carries exactly `id`, `locustfile`, `users`, `spawn_rate`, `host` and `description`.
    `users` and `spawn_rate` are integers of at least one; the rest are non-empty strings; `id`
    matches the LOAD-SLUG form docs/07-glossary-and-ids.md fixes, with every hyphen-separated
    component starting with a letter so that a baseline identifier such as BASE-LOAD-STEADY-101 can
    never be ambiguous about where the profile ends and the three-digit seed begins.

    There is no duration field, deliberately; profiles.yaml's header gives the reasoning. This
    module enforces the absence instead of relying on it: the obvious spellings of a duration key
    are rejected by name, with a message pointing at that header, so the decision survives a
    contributor who has not read it.

NO CACHING
    Each call re-reads and re-parses profiles.yaml. The file is a few dozen lines and the callers
    are a runner sealing a bundle and a human at a prompt, so the saving would be unmeasurable,
    while a module-level cache would introduce a second answer to "what is in the registry" that
    depends on when the process started. Determinism is worth more here than microseconds.

WHAT BREAKS IF THIS MODULE CHANGES
    Loosening the subset makes profiles.yaml a file whose meaning depends on which parser reads it.
    Widening the schema without widening the registry's own contract lets a run record a profile
    property that no bundle reader knows about. Making `resolve` return a default instead of raising
    turns the "rejected if it resolves to nothing" rule in data-management section 2 into a rule
    that cannot fire, which is the single most consequential thing anyone could do to this file.

A NOTE ON THE UNDERSCORED NAMES
    `_read_registry` and the parsing helpers below are not part of the contract the runner imports.
    infra/tests/test_load_profiles.py reaches for `_read_registry` deliberately, to hand the parser
    a file written for the occasion and prove it rejects what this docstring says it rejects; that
    is a test seam, and it is the reason those helpers take a path rather than closing over one.
"""

import argparse
import re
import sys
from dataclasses import dataclass, fields
from pathlib import Path

# Resolved from this file's own location, never from the working directory, so that the registry a
# caller gets is a property of the checkout rather than of where the caller happened to be standing.
REGISTRY_DIR = Path(__file__).resolve().parent
PROFILES_PATH = REGISTRY_DIR / "profiles.yaml"

# The one top-level key profiles.yaml may carry. Hardcoded rather than inferred so that a typo in
# the registry produces a message naming the expected key instead of an empty result.
TOP_LEVEL_KEY = "profiles"

# The entry schema. The tuple order is also the print order of the command line output, so a reader
# and a caller see the fields in the same sequence.
REQUIRED_FIELDS = ("id", "locustfile", "users", "spawn_rate", "host", "description")
INTEGER_FIELDS = frozenset({"users", "spawn_rate"})

# Rejected by name so that the deliberate absence of a run duration cannot be undone quietly. See
# the DURATION section of the header of infra/locust/profiles.yaml.
DURATION_LIKE_KEYS = frozenset(
    {
        "duration",
        "duration_s",
        "duration_seconds",
        "run_time",
        "run_seconds",
        "runtime",
        "seconds",
        "time_limit",
    }
)

# LOAD-SLUG, uppercase, hyphen separated, every component starting with a letter. The last clause is
# what keeps a baseline identifier unambiguous: no profile component can be mistaken for the seed.
PROFILE_ID_PATTERN = re.compile(r"LOAD-[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*")

_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
_INTEGER_PATTERN = re.compile(r"[+-]?[0-9]+")

# Characters that begin something other than a plain scalar in YAML: flow collections, anchors,
# aliases, tags, block scalars, directives, comments, complex keys and sequence entries. The
# backtick and the at sign are reserved indicators that YAML sets aside rather than defines, so they
# are refused for the same reason as the rest -- a future YAML could give them a meaning this parser
# does not have.
_INDICATOR_CHARACTERS = "[]{}&*!>|%@" + chr(96) + "#,?-"

# YAML resolves these to booleans or null. A plain-string parser would hand back the text, so they
# are the sharpest available example of silent disagreement and are refused outright.
_AMBIGUOUS_SCALARS = frozenset({"true", "false", "yes", "no", "on", "off", "null", "~"})

_SEQUENCE_INDENT = 2
_ENTRY_INDENT = 4


class ProfileRegistryError(Exception):
    """Base class for every failure this module raises, so a caller can catch one name."""


class UnknownLoadProfile(ProfileRegistryError):
    """Raised when an identifier does not name an entry of the registry.

    This is the exception the manifest validator turns into "rejected":
    docs/protocols/data-management.md section 2 requires a run whose `load_profile_id` resolves to
    no entry to be refused, on a baseline and on a framework-on run alike.
    """


class ProfilesFormatError(ProfileRegistryError):
    """Raised when profiles.yaml is unreadable, outside the accepted subset, or off schema.

    Distinct from :class:`UnknownLoadProfile` because the two mean opposite things about who is at
    fault. An unknown identifier is a bad question asked of a good registry; this is a broken
    registry, and every question asked of it is unanswerable until it is fixed.
    """


@dataclass(frozen=True, slots=True)
class Profile:
    """One load profile, exactly as the registry carries it.

    Frozen because a profile is a record of what a run was driven under. A caller that could edit
    the object it resolved could report a load the cluster never saw, and nothing downstream would
    be able to tell.
    """

    id: str
    locustfile: str
    users: int
    spawn_rate: int
    host: str
    description: str

    @property
    def locustfile_path(self) -> Path:
        """Absolute path of this profile's load script.

        Derived, not a seventh field -- ``dataclasses.fields(Profile)`` still returns exactly the
        six keys the registry file carries. It exists so that resolving a relative `locustfile`
        value against the registry directory happens once, here, rather than once in the runner and
        again in whatever else needs the script.
        """
        return REGISTRY_DIR / self.locustfile


def _fail(source: Path, line_number: int, message: str) -> ProfilesFormatError:
    """Build a format error that names the file and the line, ready to be raised."""
    return ProfilesFormatError(f"{source}:{line_number}: {message}")


def _parse_scalar(text: str, source: Path, line_number: int) -> str | int:
    """Return the value of one scalar, or raise if it is outside the accepted subset."""
    if not text:
        raise _fail(source, line_number, "empty value; every key must carry a scalar")
    if text[0] in "\"'":
        quote = text[0]
        if len(text) < 2 or text[-1] != quote or quote in text[1:-1]:
            raise _fail(
                source,
                line_number,
                f"malformed quoted scalar; it must open and close with {quote} and contain no "
                f"other {quote} and no escape sequences",
            )
        return text[1:-1]
    if _INTEGER_PATTERN.fullmatch(text):
        return int(text)
    if text[0] in _INDICATOR_CHARACTERS:
        raise _fail(
            source,
            line_number,
            f"a plain scalar may not start with {text[0]!r}; that character opens a YAML construct "
            "this parser does not accept. Quote the value if it is meant literally",
        )
    if " #" in text:
        raise _fail(
            source,
            line_number,
            "a plain scalar may not contain a space followed by a hash; YAML would read the rest "
            "of the line as a comment and this parser would not, so the two would disagree",
        )
    if ": " in text or text.endswith(":"):
        raise _fail(
            source,
            line_number,
            "a plain scalar may not contain a colon followed by a space, or end with a colon; "
            "YAML reads that as a nested mapping. Quote the value if it is meant literally",
        )
    if text.lower() in _AMBIGUOUS_SCALARS:
        raise _fail(
            source,
            line_number,
            f"{text!r} is a YAML boolean or null and would not survive the round trip as text; "
            "quote it if a string is meant, or write an integer if a number is",
        )
    return text


def _parse_pair(fragment: str, source: Path, line_number: int) -> tuple[str, str | int]:
    """Split one key and value fragment and return the key with its parsed scalar."""
    key, separator, value = fragment.partition(": ")
    if not separator:
        raise _fail(
            source,
            line_number,
            "expected a key and a value separated by a colon and exactly one space",
        )
    if not _KEY_PATTERN.fullmatch(key):
        raise _fail(
            source,
            line_number,
            f"{key!r} is not an accepted key; keys are lowercase ASCII letters, digits and "
            "underscores, starting with a letter",
        )
    return key, _parse_scalar(value, source, line_number)


def _record_pair(
    entry: dict[str, str | int],
    key: str,
    value: str | int,
    source: Path,
    line_number: int,
) -> None:
    """Add one key to the entry under construction, refusing duplicates and unknown keys."""
    if key in DURATION_LIKE_KEYS:
        raise _fail(
            source,
            line_number,
            f"{key!r} is refused on purpose: a profile is a load shape, and the length of a "
            "measurement window is a property of a run that no protocol file owns yet. See the "
            "DURATION section of the header of the registry file",
        )
    if key not in REQUIRED_FIELDS:
        raise _fail(
            source,
            line_number,
            f"unknown key {key!r}; a registry entry carries exactly {', '.join(REQUIRED_FIELDS)}",
        )
    if key in entry:
        raise _fail(source, line_number, f"duplicate key {key!r} in one entry")
    entry[key] = value


def _parse_document(text: str, source: Path) -> list[tuple[int, dict[str, str | int]]]:
    """Parse the registry text into entries, each paired with the line it started on."""
    entries: list[tuple[int, dict[str, str | int]]] = []
    current: dict[str, str | int] | None = None
    seen_top_level_key = False
    lines = text.split("\n")

    for line_number, line in enumerate(lines, start=1):
        if "\t" in line:
            raise _fail(source, line_number, "tab character; this file is indented with spaces")
        if not line.strip():
            continue
        if line.rstrip() != line:
            raise _fail(source, line_number, "trailing whitespace")
        body = line.lstrip(" ")
        if body.startswith("#"):
            continue
        indent = len(line) - len(body)

        if indent == 0:
            if seen_top_level_key:
                raise _fail(
                    source,
                    line_number,
                    f"a second top-level key; this file carries only {TOP_LEVEL_KEY!r}",
                )
            if body != f"{TOP_LEVEL_KEY}:":
                raise _fail(
                    source,
                    line_number,
                    f"expected the top-level key {TOP_LEVEL_KEY!r} alone on its own line, "
                    "followed by a colon",
                )
            seen_top_level_key = True
            continue

        if not seen_top_level_key:
            raise _fail(source, line_number, f"indented content before the {TOP_LEVEL_KEY!r} key")

        if indent == _SEQUENCE_INDENT:
            if not body.startswith("- "):
                raise _fail(
                    source,
                    line_number,
                    f"expected a sequence entry, a dash and one space, at {_SEQUENCE_INDENT} "
                    "spaces of indent",
                )
            current = {}
            entries.append((line_number, current))
            key, value = _parse_pair(body[2:], source, line_number)
            _record_pair(current, key, value, source, line_number)
        elif indent == _ENTRY_INDENT:
            if current is None:
                raise _fail(source, line_number, "entry key before any sequence entry")
            key, value = _parse_pair(body, source, line_number)
            _record_pair(current, key, value, source, line_number)
        else:
            raise _fail(
                source,
                line_number,
                f"indentation of {indent} spaces; this file uses exactly {_SEQUENCE_INDENT} for a "
                f"sequence entry and {_ENTRY_INDENT} for its keys",
            )

    if not seen_top_level_key:
        raise _fail(source, len(lines), f"no {TOP_LEVEL_KEY!r} key found")
    return entries


def _build_profiles(
    entries: list[tuple[int, dict[str, str | int]]], source: Path
) -> dict[str, Profile]:
    """Validate parsed entries against the schema and return them keyed by identifier."""
    if not entries:
        raise _fail(source, 1, "the registry is empty; at least one profile must be defined")

    profiles: dict[str, Profile] = {}
    for line_number, entry in entries:
        missing = [name for name in REQUIRED_FIELDS if name not in entry]
        if missing:
            raise _fail(source, line_number, f"entry is missing {', '.join(missing)}")

        for name in REQUIRED_FIELDS:
            value = entry[name]
            if name in INTEGER_FIELDS:
                if not isinstance(value, int):
                    raise _fail(source, line_number, f"{name} must be an integer, not {value!r}")
                if value < 1:
                    raise _fail(source, line_number, f"{name} must be at least 1, not {value}")
            elif not isinstance(value, str) or not value:
                raise _fail(source, line_number, f"{name} must be a non-empty string")

        identifier = str(entry["id"])
        if not PROFILE_ID_PATTERN.fullmatch(identifier):
            raise _fail(
                source,
                line_number,
                f"{identifier!r} is not of the LOAD-SLUG form that docs/07-glossary-and-ids.md "
                "fixes for a load profile identifier",
            )
        if identifier in profiles:
            raise _fail(source, line_number, f"duplicate profile id {identifier!r}")
        profiles[identifier] = Profile(
            id=identifier,
            locustfile=str(entry["locustfile"]),
            users=int(entry["users"]),
            spawn_rate=int(entry["spawn_rate"]),
            host=str(entry["host"]),
            description=str(entry["description"]),
        )

    return profiles


def _read_registry(path: Path = PROFILES_PATH) -> dict[str, Profile]:
    """Read, parse and validate a registry file, returning its profiles in file order."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ProfilesFormatError(f"{path}: cannot be read: {error}") from error
    return _build_profiles(_parse_document(text, path), path)


def list_profiles(path: Path = PROFILES_PATH) -> list[Profile]:
    """Return every profile in the registry, in the order the file declares them.

    File order rather than sorted order, so that a caller iterating the registry -- the M1
    Definition of Done drives every entry end to end -- does so in an order a reader of
    profiles.yaml can predict.
    """
    return list(_read_registry(path).values())


def resolve(load_profile_id: str, path: Path = PROFILES_PATH) -> Profile:
    """Return the profile named by the identifier, or raise :class:`UnknownLoadProfile`.

    Raising rather than returning None is the whole point of the function. A None is a value a
    caller can forget to check, and the check it would be forgetting is the one
    docs/protocols/data-management.md section 2 requires before a run bundle is accepted.
    """
    profiles = _read_registry(path)
    try:
        return profiles[load_profile_id]
    except KeyError:
        known = ", ".join(profiles) or "none"
        raise UnknownLoadProfile(
            f"{load_profile_id!r} is not a load profile in {path}; known profiles: {known}"
        ) from None


def _format_profile(profile: Profile) -> str:
    """Render one profile as aligned field and value lines, one field per line."""
    width = max(len(field.name) for field in fields(Profile)) + 2
    return "\n".join(f"{name:<{width}}{getattr(profile, name)}" for name in REQUIRED_FIELDS)


def main(argv: list[str] | None = None) -> int:
    """List or resolve registry entries. Return the process exit code."""
    parser = argparse.ArgumentParser(
        prog="python -m infra.locust.registry",
        description=(
            "Inspect the load-profile registry that infra/locust/profiles.yaml defines. Exits 0 on "
            "success, 1 when an identifier does not resolve or the registry is malformed, and 2 "
            "when the command line itself is wrong."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="Print every profile in the registry.")
    mode.add_argument(
        "--resolve",
        metavar="LOAD_PROFILE_ID",
        help="Print the profile with this identifier, or fail if there is no such profile.",
    )
    arguments = parser.parse_args(argv)

    # An ordinary print, unlike scripts/versions_env_sha256.py, which writes through the binary
    # buffer so that a Windows text-mode stdout cannot append a CR to a digest captured in a command
    # substitution. This output is read by people and by grep and is never compared byte for byte,
    # so the distinction that matters there does not arise here.
    try:
        if arguments.list:
            print("\n\n".join(_format_profile(profile) for profile in list_profiles()))
        else:
            print(_format_profile(resolve(arguments.resolve)))
    except ProfileRegistryError as error:
        print(f"registry: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
