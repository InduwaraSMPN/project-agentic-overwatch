#!/bin/sh
# cve_mirror.sh — verify the local mirror of the CVE arm's vulnerable images, and print the
# procedure that produces it.
#
# WHAT THIS SCRIPT IS
# The check behind `docs/plans/M5-implementation-plan.md` §T5.3's verification line, and the
# executable half of the argument §D9 makes: a digest pin buys immutability, a local `docker save`
# tarball buys availability, and only the second survives upstream deleting the manifest. The pins
# live in scenarios/cve/images.yaml, tracked; the tarballs live in scenarios/cve/tarballs/,
# gitignored, because they are hundreds of megabytes of container image apiece and git cannot hold
# them. What the repository carries is therefore a verifiable RECIPE for the mirror rather than the
# mirror, and this script is what makes "verifiable" mean something: --verify re-hashes each tarball
# against the sha256 recorded on its entry, and --save and --load print the commands that produce
# and install one.
#
# WHY --verify FAILS TODAY AND THAT IS CORRECT
# Every entry in scenarios/cve/images.yaml carries an empty `digest` and an empty `tarball_sha256`,
# so every entry is reported `unpinned` and this script exits 1 today. That is the intended state
# before Tier B, not a defect to be worked around, and the reasoning is worth stating rather than
# leaving to be inferred.
#
# Resolving a registry digest needs a network request; Tier A of M5 is offline by construction. The
# alternative to an empty field is not omission, it is invention — and an invented digest would sit
# inside versions_env_sha256, which every sealed run bundle carries, where nothing in this
# repository could ever detect it. An empty field is visible and is refused; a plausible wrong one
# is invisible and is believed. infra/versions.env rule 2 already settles the principle one level up
# ("every key stays present even when its value is empty"), and this is the same shape one level
# down.
#
# So an unpinned entry is a FAILURE and never a skip. A gate that quietly passed over the entries it
# could not check would be byte-identical, in a log, to a gate that checked them all — the vacuous
# pass `make parity-check`, scripts/monitor_determinism.sh and scripts/status.sh each refuse in their
# own words. This one refuses it in these.
#
# WHY IT NEVER REACHES A REGISTRY ITSELF
# --save and --load PRINT commands; they never run one. Nothing in this file invokes docker, kind,
# curl or a registry client, and that is a property worth keeping rather than a limitation to
# apologise for:
#
#   * The gate stays runnable on a machine with no Docker, no cluster and no network, which is what
#     CI is and what a reviewer's laptop may be. A check that needs the thing it is checking to be
#     installed is a check that gets skipped.
#   * Pulling an image is a side effect on the host, and pulling a KNOWN-VULNERABLE image is a side
#     effect with a security consequence. The operator decides when a vulnerable Solr lands on their
#     disk, from a command they read first. That decision does not belong to a verification script.
#   * The emitted procedure goes to stderr rather than stdout, deliberately. stdout is the verdict
#     channel every gate in scripts/ uses, and a procedure printed on stdout invites `| sh` — which
#     would hand back, through a pipe, exactly the property this script is built not to have. To
#     capture the commands: `sh scripts/cve_mirror.sh --save 2>commands.sh >/dev/null`, then read
#     commands.sh before running it.
#
# SCOPE AND EXIT CODES
#   --verify   a GATE. Exit 0 only when every entry is pinned (a `sha256:`-prefixed 64-hex digest
#              and a 64-hex tarball checksum), its tarball is present under scenarios/cve/tarballs/,
#              and the tarball re-hashes to the recorded value. Every other outcome — unpinned,
#              malformed, absent, mismatched, or a corpus with no entries at all — is exit 1 with
#              the entry named.
#   --save     an EMITTER. Prints the `docker pull` and `docker save` lines for each entry.
#   --load     an EMITTER. Prints the `kind load image-archive` line for each entry.
#              Both emitters exit 0 only when a runnable command was produced for EVERY entry, and 1
#              otherwise: an entry whose digest is unresolved yields a `#` comment naming it instead
#              of a command, and a procedure printed with holes in it is not a procedure. Today,
#              therefore, all three modes exit 1.
#   no mode    usage on stderr, exit 1. There is no default mode: --verify is a gate and the two
#              emitters are not, and guessing which one an unqualified invocation meant would make
#              the exit status mean two different things.
#
# What this script does NOT assert: that a digest is the one the registry currently serves, that a
# tarball contains the image its entry names, or that either exists upstream at all. It checks the
# mirror against the record. The record is checked against the registry at Tier B, and
# scenarios/cve/README.md is where that procedure lives.
#
# STREAMS
#   stdout: exactly one summary line, in scripts/check_hygiene.sh's shape, so a caller can capture
#   the verdict without parsing the report. stderr: one line per entry, the emitted procedure in the
#   two emitter modes, and the remediation.
#
# ENVIRONMENT
#   CVE_IMAGES_FILE   the digest file to read, default scenarios/cve/images.yaml. It exists so a
#                     test can drive this script over a fixture corpus without editing the real one.
#   CVE_TARBALL_DIR   where tarballs are looked for, default scenarios/cve/tarballs.
#   KIND_CLUSTER_NAME the cluster name --load emits, default `kind`, matching scripts/up.sh's own
#                     default and its stated reasoning.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options, no jq, and no YAML library. Runs under dash in
# WSL2 Ubuntu, under Git Bash on Windows, and on ubuntu-latest. The sha256 tool is whichever of
# sha256sum, shasum -a 256 or openssl dgst -sha256 is on PATH; its absence is reported rather than
# silently turning a checksum comparison into a no-op.

set -eu

# Byte-exact matching and byte-stable tool output whatever the ambient locale.
LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

IMAGES_FILE=${CVE_IMAGES_FILE:-scenarios/cve/images.yaml}
TARBALL_DIR=${CVE_TARBALL_DIR:-scenarios/cve/tarballs}
CLUSTER_NAME=${KIND_CLUSTER_NAME:-kind}

usage() {
    echo "usage: sh scripts/cve_mirror.sh --verify | --save | --load"
    echo "       --verify  re-hash each mirrored tarball against $IMAGES_FILE and report"
    echo "                 present/absent per entry; an entry with an empty digest or an empty"
    echo "                 tarball_sha256 is reported unpinned and FAILS, it is not skipped"
    echo "       --save    print the docker pull/save commands that build the mirror"
    echo "       --load    print the kind load image-archive commands that install it"
    echo "       the emitted procedure goes to stderr, never stdout, and is never executed here;"
    echo "       see WHY IT NEVER REACHES A REGISTRY ITSELF in this script's header"
}

mode=""

while [ $# -gt 0 ]; do
    case "$1" in
        --verify|--save|--load)
            if [ -n "$mode" ] && [ "$mode" != "$1" ]; then
                printf 'cve-mirror: %s and %s are separate invocations: one is a gate and the\n' \
                    "$mode" "$1" >&2
                echo "other is not, so a single exit status could not report both." >&2
                printf 'cve-mirror: FAIL — %s and %s cannot be combined\n' "$mode" "$1"
                exit 1
            fi
            mode=$1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'cve-mirror: unknown argument %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [ -z "$mode" ]; then
    usage >&2
    printf 'cve-mirror: FAIL — no mode given\n'
    exit 1
fi

if [ ! -f "$IMAGES_FILE" ]; then
    printf 'cve-mirror: FAIL — digest file not found at %s\n' "$IMAGES_FILE" >&2
    echo "infra/versions.env's CVE_IMAGE_DIGESTS_FILE names it; M5-T5.3 owns it." >&2
    printf 'cve-mirror: FAIL — %s not found\n' "$IMAGES_FILE"
    exit 1
fi

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM
rows="$work/rows"
problems="$work/problems"
: > "$problems"

problem() {
    printf '%s\n' "$1" >> "$problems"
}

report() {
    printf 'cve-mirror: %-22s %-10s %s\n' "$1" "$2" "$3" >&2
}

# --- read the digest file -------------------------------------------------------------------
#
# The parser scripts/status.sh carries for infra/status/components.yaml, with one addition forced by
# this corpus: it is COLUMN-ANCHORED. A record opens on a line whose body begins exactly `- `, and
# that dash fixes the column its own fields sit at — the dash's indent plus two, which is where the
# first key physically starts. A `key: value` line is a field of the open record only when its
# indent equals that column. Everything else is ignored.
#
# The addition earns its keep on one field. `notes` is a folded block scalar, so its continuation
# lines are prose indented deeper than the fields, and prose contains colons. Without the column
# anchor a sentence like "one consequence: the mirror is the answer" would parse as a field named
# `one consequence`; with it, the line is at the wrong column and is dropped before its content is
# ever considered. Fields this script does not use — cve_id, component, source, reference, notes —
# fall through the assignment chain and are discarded, so the file may carry them freely.
#
# Fields are emitted pipe-separated because no field may contain a pipe: ids, scenario ids,
# repository paths, tags, digests and filenames cannot.
awk '
    function emit() {
        if (id == "") return
        printf "%s|%s|%s|%s|%s|%s|%s\n", id, scenario_id, repository, tag, digest, tarball, sha
    }
    {
        line = $0
        sub(/\r$/, "", line)
        indent = line
        sub(/[^ ].*$/, "", indent)
        col = length(indent)
        body = substr(line, col + 1)
        if (body == "" || substr(body, 1, 1) == "#") next
        isnew = 0
        if (substr(body, 1, 2) == "- ") {
            isnew = 1
            body = substr(body, 3)
            col = col + 2
        }
        ci = index(body, ":")
        if (ci == 0) next
        k = substr(body, 1, ci - 1)
        if (k !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next
        if (isnew) {
            emit()
            field_col = col
            id = ""; scenario_id = ""; repository = ""
            tag = ""; digest = ""; tarball = ""; sha = ""
        } else {
            if (id == "") next
            if (col != field_col) next
        }
        v = substr(body, ci + 1)
        sub(/^ +/, "", v)
        sub(/ +$/, "", v)
        sub(/^"/, "", v)
        sub(/"$/, "", v)
        if (k == "id") id = v
        else if (k == "scenario_id") scenario_id = v
        else if (k == "repository") repository = v
        else if (k == "tag") tag = v
        else if (k == "digest") digest = v
        else if (k == "tarball") tarball = v
        else if (k == "tarball_sha256") sha = v
    }
    END { emit() }
' "$IMAGES_FILE" > "$rows"

# A record whose first key is not `id` is dropped by the parser above, silently, which would take an
# image out of the check without saying so. Count what the file declares and what the parser
# produced, and refuse to report at all if the two disagree — scripts/status.sh's own guard, for the
# same reason.
declared=$(awk '{ line = $0; sub(/\r$/, "", line); sub(/^ +/, "", line) }
                line ~ /^- id:/ { n++ }
                END { print n + 0 }' "$IMAGES_FILE")
openers=$(awk '{ line = $0; sub(/\r$/, "", line); sub(/^ +/, "", line) }
               line ~ /^- / { n++ }
               END { print n + 0 }' "$IMAGES_FILE")
parsed=$(awk 'END { print NR }' "$rows")

# A record that opens on some other key leaves declared and parsed both at zero, which would fall
# through to the empty-corpus message below and tell an operator the file declares nothing when it
# plainly declares something. The opener count separates the two so the diagnosis names the actual
# defect.
if [ "$openers" -gt 0 ] && [ "$declared" -eq 0 ]; then
    {
        printf 'cve-mirror: FAIL — %s opens %s record(s), none of them with an id key.\n' \
            "$IMAGES_FILE" "$openers"
        echo "Every record must begin with its 'id' key on the dash line. See THE FORMAT IS"
        echo "DELIBERATELY SMALLER THAN YAML in that file's header."
    } >&2
    printf 'cve-mirror: FAIL — %s is malformed\n' "$IMAGES_FILE"
    exit 1
fi

if [ "$declared" -ne "$parsed" ]; then
    {
        printf 'cve-mirror: FAIL — %s declares %s image record(s) but %s parsed.\n' \
            "$IMAGES_FILE" "$declared" "$parsed"
        echo "Every record must begin with its 'id' key, at two spaces past the dash, and every"
        echo "field of that record must sit at the same column. See THE FORMAT IS DELIBERATELY"
        echo "SMALLER THAN YAML in that file's header."
    } >&2
    printf 'cve-mirror: FAIL — %s is malformed\n' "$IMAGES_FILE"
    exit 1
fi

if [ "$parsed" -eq 0 ]; then
    {
        printf 'cve-mirror: FAIL — %s declares no images at all.\n' "$IMAGES_FILE"
        echo "Checking an empty corpus produces no findings, and no findings over nothing reads"
        echo "in a log exactly like no findings over everything. The CVE arm needs one entry per"
        echo "CVE scenario; scenarios/cve/README.md lists which."
    } >&2
    printf 'cve-mirror: FAIL — %s declares no images\n' "$IMAGES_FILE"
    exit 1
fi

# --- sha256, from whichever tool is present -------------------------------------------------

sha_tool=""
if command -v sha256sum >/dev/null 2>&1; then
    sha_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    sha_tool=shasum
elif command -v openssl >/dev/null 2>&1; then
    sha_tool=openssl
fi

# The file is fed on STDIN rather than named as an argument, which is not a stylistic preference.
# GNU coreutils' sha256sum escapes a filename containing a backslash or a newline and marks the
# escaped line with a leading `\`, so hashing by name would sometimes return a 65-character string
# that compares unequal to a perfectly correct 64-hex record. Reading from stdin puts no filename in
# the output at all, and the failure mode disappears rather than being trimmed off afterwards.
sha256_of() {
    case "$sha_tool" in
        sha256sum) sha256sum < "$1" | awk '{ print $1; exit }' ;;
        shasum)    shasum -a 256 < "$1" | awk '{ print $1; exit }' ;;
        openssl)   openssl dgst -sha256 < "$1" | awk '{ print $NF; exit }' ;;
        *)         printf '' ;;
    esac
}

is_digest() {
    printf '%s' "$1" | awk '/^sha256:[0-9a-f]{64}$/ { found = 1 } END { exit found ? 0 : 1 }'
}

is_hex64() {
    printf '%s' "$1" | awk '/^[0-9a-f]{64}$/ { found = 1 } END { exit found ? 0 : 1 }'
}

total=0
verified=0
unpinned=0
emitted=0

# --- one pass over the entries ---------------------------------------------------------------

while IFS='|' read -r e_id e_scn e_repo e_tag e_digest e_tar e_sha; do
    [ -n "$e_id" ] || continue
    total=$((total + 1))

    # Structural fields first. An entry missing a repository or a tarball filename is malformed
    # rather than unpinned: no value at Tier B would repair it, because the file never said what
    # image the entry is about.
    if [ -z "$e_repo" ] || [ -z "$e_tar" ]; then
        report "$e_id" "malformed" "repository or tarball missing in $IMAGES_FILE"
        problem "$e_id: repository or tarball field is missing"
        continue
    fi

    tar_path="$TARBALL_DIR/$e_tar"

    case "$mode" in
        --save)
            if is_digest "$e_digest"; then
                {
                    printf 'docker pull %s@%s\n' "$e_repo" "$e_digest"
                    printf 'docker save --output %s %s@%s\n' "$tar_path" "$e_repo" "$e_digest"
                } >&2
                emitted=$((emitted + 1))
            else
                printf '# %s (%s): digest unresolved, so no runnable pull exists yet — Tier B\n' \
                    "$e_id" "$e_scn" >&2
                unpinned=$((unpinned + 1))
                problem "$e_id: digest is empty or malformed, so --save could emit no command"
            fi
            continue
            ;;
        --load)
            if is_digest "$e_digest"; then
                printf 'kind load image-archive --name %s %s\n' "$CLUSTER_NAME" "$tar_path" >&2
                printf 'for node in $(kind get nodes --name %s); do docker exec "$node" ctr -n k8s.io images tag %s:%s %s@%s; done\n' \
                    "$CLUSTER_NAME" "$e_repo" "$e_tag" "$e_repo" "$e_digest" >&2
                emitted=$((emitted + 1))
            else
                printf '# %s (%s): digest unresolved, so the tarball it names is not built — Tier B\n' \
                    "$e_id" "$e_scn" >&2
                unpinned=$((unpinned + 1))
                problem "$e_id: digest is empty or malformed, so --load could emit no command"
            fi
            continue
            ;;
        *)
            ;;
    esac

    # --verify from here down.
    if [ -z "$e_digest" ] || [ -z "$e_sha" ]; then
        unpinned=$((unpinned + 1))
        if [ -z "$e_digest" ] && [ -z "$e_sha" ]; then
            missing="digest and tarball_sha256 are both empty"
        elif [ -z "$e_digest" ]; then
            missing="digest is empty"
        else
            missing="tarball_sha256 is empty"
        fi
        report "$e_id" "unpinned" "$missing"
        problem "$e_id ($e_scn): $missing — filled at Tier B, and unpinned is a failure, not a skip"
        continue
    fi

    if ! is_digest "$e_digest"; then
        report "$e_id" "malformed" "digest is not sha256: followed by 64 lowercase hex"
        problem "$e_id: digest '$e_digest' is not a sha256 manifest digest"
        continue
    fi

    if ! is_hex64 "$e_sha"; then
        report "$e_id" "malformed" "tarball_sha256 is not 64 lowercase hex characters"
        problem "$e_id: tarball_sha256 '$e_sha' is not a sha256 hex digest"
        continue
    fi

    if [ ! -f "$tar_path" ]; then
        report "$e_id" "absent" "$tar_path not present"
        problem "$e_id ($e_scn): $tar_path is absent — rebuild it with 'sh scripts/cve_mirror.sh --save'"
        continue
    fi

    if [ -z "$sha_tool" ]; then
        report "$e_id" "unchecked" "no sha256 tool on PATH, so $tar_path was not hashed"
        problem "$e_id: no sha256sum, shasum or openssl on PATH; the checksum was not verified"
        continue
    fi

    observed=$(sha256_of "$tar_path")
    if [ "$observed" = "$e_sha" ]; then
        verified=$((verified + 1))
        report "$e_id" "ok" "$tar_path matches its recorded sha256"
    else
        report "$e_id" "MISMATCH" "recorded $e_sha, observed $observed"
        problem "$e_id ($e_scn): $tar_path does not hash to the value recorded in $IMAGES_FILE"
    fi
done < "$rows"

# --- report ------------------------------------------------------------------------------------

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        echo
        echo "cve-mirror: FAIL — $problem_count problem(s):"
        echo
        cat "$problems"
        echo
        if [ "$unpinned" -gt 0 ]; then
            echo "An unpinned entry is a FAILURE and not a skip. Every entry carries an empty"
            echo "digest and an empty tarball_sha256 today, because resolving a registry digest"
            echo "needs a network request and Tier A of M5 is offline; inventing one would put an"
            echo "unverifiable value inside versions_env_sha256, where nothing would detect it."
            echo "So this gate fails closed until Tier B fills them, exactly as make parity-check"
            echo "fails rather than passing vacuously. scenarios/cve/README.md carries the"
            echo "procedure and images.yaml's header carries the argument."
        fi
    } >&2
fi

case "$mode" in
    --verify)
        if [ "$problem_count" -gt 0 ]; then
            printf 'cve-mirror: FAIL — %s problem(s); %s of %s entry(ies) verified, %s unpinned\n' \
                "$problem_count" "$verified" "$total" "$unpinned"
            exit 1
        fi
        printf 'cve-mirror: PASS — %s/%s entry(ies) mirrored and matching their recorded sha256\n' \
            "$verified" "$total"
        exit 0
        ;;
    --save|--load)
        if [ "$problem_count" -gt 0 ]; then
            printf 'cve-mirror: FAIL — %s of %s entry(ies) emitted; %s unpinned, so the printed procedure has holes\n' \
                "$emitted" "$total" "$unpinned"
            exit 1
        fi
        printf 'cve-mirror: PASS — procedure printed for %s/%s entry(ies) on stderr\n' \
            "$emitted" "$total"
        exit 0
        ;;
esac
