#!/bin/sh
# Offline smoke test for scripts/nuke.sh. No Docker daemon, network, or real cluster required.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=${TMPDIR:-/tmp}/agentic-overwatch-nuke-test.$$
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

sandbox=$tmp/repo
mkdir -p "$sandbox/scripts" "$tmp/bin"
cp "$repo_root/scripts/nuke.sh" "$sandbox/scripts/nuke.sh"
cat >"$tmp/bin/kind" <<'EOF'
#!/bin/sh
[ "${1:-}" = get ] && [ "${2:-}" = clusters ] && exit 0
[ "${1:-}" = delete ] && exit 0
exit 2
EOF
chmod +x "$tmp/bin/kind"

volumes=$sandbox/infra/observability/langfuse/volumes
for datastore in postgres clickhouse redis minio; do
    mkdir -p "$volumes/$datastore"
    printf '%s\n' "$datastore" >"$volumes/$datastore/state"
done
mkdir -p "$volumes/operator-notes" "$sandbox/runs"
printf 'keep\n' >"$volumes/operator-notes/keep"
printf 'keep\n' >"$sandbox/runs/keep"

PATH="$tmp/bin:$PATH" FORCE=1 sh "$sandbox/scripts/nuke.sh" >/dev/null
for datastore in postgres clickhouse redis minio; do
    [ ! -e "$volumes/$datastore" ] || {
        echo "test_nuke: FAIL — $datastore state survived" >&2
        exit 1
    }
done
[ -f "$volumes/operator-notes/keep" ]
[ -f "$sandbox/runs/keep" ]

outside=$tmp/outside
mkdir -p "$outside" "$sandbox/infra/observability/langfuse/volumes"
printf 'keep\n' >"$outside/sentinel"
ln -s "$outside" "$sandbox/infra/observability/langfuse/volumes/postgres"
PATH="$tmp/bin:$PATH" FORCE=1 sh "$sandbox/scripts/nuke.sh" >/dev/null
[ ! -e "$sandbox/infra/observability/langfuse/volumes/postgres" ]
[ "$(cat "$outside/sentinel")" = keep ]

rm -rf "$sandbox/infra/observability/langfuse"
ln -s "$outside" "$sandbox/infra/observability/langfuse"
if PATH="$tmp/bin:$PATH" FORCE=1 sh "$sandbox/scripts/nuke.sh" >/dev/null 2>&1; then
    echo 'test_nuke: FAIL — accepted symlinked Langfuse ancestor' >&2
    exit 1
fi
[ "$(cat "$outside/sentinel")" = keep ]

printf 'test_nuke: PASS — fixed datastore deletion and repository confinement proved\n'
