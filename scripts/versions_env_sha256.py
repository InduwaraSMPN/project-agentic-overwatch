"""SHA-256 digest of infra/versions.env under a fixed line-ending normalisation.

Why this is a Python module and not a shell function
----------------------------------------------------
``sha256sum`` is absent on macOS and on minimal Git Bash installs, so a shell
implementation would not run on every host this project is developed, examined
and reproduced on. More importantly, a shell function cannot be imported: M6's
bundle sealer needs exactly this digest for the ``versions_env_sha256`` field of
every run manifest (docs/protocols/data-management.md section 2). Writing the
digest twice, once in shell for the Makefile and once in Python for the sealer,
would create the second source of truth that the source-of-truth iron rule (AGENTS.md 1)
forbids, and the two copies would eventually disagree without anything failing.
The sealer therefore imports :func:`versions_env_sha256` from this module, and
the command line entry point below is that same function with a print.

The CRLF normalisation contract
-------------------------------
The digest is taken over the file's bytes after every CRLF pair and every bare
CR has been rewritten to LF. Without that step, the same infra/versions.env
hashed inside WSL2 and on the Windows checkout yields two different digests,
because the Windows host runs with core.autocrlf enabled and materialises the
file with CRLF endings. The manifest field would then record which host sealed
the bundle rather than which stack produced it, which defeats the clean-machine
reproducibility requirement NFR1 and the sealed-bundle provenance row T-15.
Normalising inside the hasher, rather than trusting .gitattributes to have
already normalised the working tree, keeps the digest stable even for a copy of
the file that arrived by download, archive extraction or copy and paste.

Output is a bare 64-character lowercase hexadecimal digest on stdout, terminated
by a single LF on every host and followed by nothing else, so the script is
substitutable inside ``$(...)`` in a Makefile recipe or a shell script.
"""

import argparse
import hashlib
import sys
from pathlib import Path

DEFAULT_RELATIVE_PATH = Path("infra") / "versions.env"


def default_path() -> Path:
    """Return infra/versions.env resolved against the repository root.

    The root is derived from this file's own location rather than from the
    current working directory, so the default target is the same whether the
    script is invoked from the repository root, from a Makefile recipe or from
    another directory entirely.
    """
    return Path(__file__).resolve().parent.parent / DEFAULT_RELATIVE_PATH


def normalise_line_endings(data: bytes) -> bytes:
    """Return ``data`` with CRLF pairs and bare CR characters rewritten to LF."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def versions_env_sha256(path: str | Path | None = None) -> str:
    """Return the lowercase hexadecimal sha256 of ``path`` after normalisation.

    ``path`` defaults to infra/versions.env under the repository root. The file
    is read as bytes and never decoded, so the digest does not depend on the
    caller's locale or default encoding.
    """
    target = default_path() if path is None else Path(path)
    return hashlib.sha256(normalise_line_endings(target.read_bytes())).hexdigest()


def main(argv: list[str] | None = None) -> int:
    """Print the digest of the requested file. Return the process exit code."""
    parser = argparse.ArgumentParser(
        description=(
            "Print the sha256 of a versions file, computed over its bytes after "
            "CRLF line endings have been normalised to LF."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="File to digest. Defaults to infra/versions.env under the repository root.",
    )
    args = parser.parse_args(argv)

    target = default_path() if args.path is None else Path(args.path)
    if not target.is_file():
        print(f"versions_env_sha256: no such file: {target}", file=sys.stderr)
        return 1

    # Written through the binary buffer, and not with print, because Windows opens a text-mode
    # stdout that translates the terminating LF into CRLF. Shell command substitution strips a
    # trailing LF but keeps the CR, so on a Windows host `$(...)` would capture 65 characters
    # instead of 64 and every comparison against the digest would fail.
    sys.stdout.buffer.write(versions_env_sha256(target).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
