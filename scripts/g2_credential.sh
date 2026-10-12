#!/bin/sh
# Runner-owned G2 credential lifecycle. The bearer is written only to a caller-selected private file
# and never printed, logged, placed in a Secret, or copied under agents/.
set -eu
LC_ALL=C
export LC_ALL
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

action=${1:-}
token_file=${G2_TOKEN_FILE:-}
bound_secret="g2-run-$(printf '%s' "$token_file" | sha256sum | cut -c1-32)"

case "$action" in
  issue)
    [ -n "$token_file" ] || { echo "g2-credential: G2_TOKEN_FILE is required" >&2; exit 1; }
    kubectl apply -f guardian/deploy/g2-rbac.yaml >/dev/null
    kubectl apply -f infra/netpol/agents-g2-open.yaml >/dev/null
    tmp="${token_file}.tmp.$$"
    trap 'rm -f "$tmp"; kubectl -n agents delete secret "$bound_secret" --ignore-not-found >/dev/null' EXIT HUP INT TERM
    # 3600s, NOT the TokenRequest API's 600s floor (ADR-157, amending ADR-103). The bearer is minted
    # at condition-apply time, before the measurement window opens, and must still be valid when the
    # window CLOSES: F-GD-05 requires the recorded expiry to be after the run's end, and a credential
    # that lapses mid-run silently closes the direct path the C2 ablation is measuring. The API floor
    # was set in ADR-103 on the assumption that the run fits in ten minutes; measured against the
    # corpus it does not (n=1687 framework-on runs: p50 670s, p99 894s, max 1578s). 3600s covers the
    # observed maximum with a 2.3x margin and matches the control-plane bearer's TTL, so both
    # credentials in a G2 run share one exposure window. Revocation, not expiry, still ends the
    # credential at run end -- ADR-103's own reasoning, unchanged.
    kubectl -n agents delete secret "$bound_secret" --ignore-not-found >/dev/null
    kubectl -n agents create secret generic "$bound_secret" >/dev/null
    kubectl -n agents create token g2-executor --duration=3600s \
      --bound-object-kind=Secret --bound-object-name="$bound_secret" > "$tmp"
    [ -s "$tmp" ] || { echo "g2-credential: TokenRequest returned an empty bearer" >&2; exit 1; }
    mv "$tmp" "$token_file"
    trap - EXIT HUP INT TERM
    printf 'g2-credential: PASS — scoped TokenRequest bearer written to the runner-owned file\n'
    ;;
  revoke)
    [ -n "$token_file" ] || { echo "g2-credential: G2_TOKEN_FILE is required" >&2; exit 1; }
    [ -z "$token_file" ] || rm -f "$token_file"
    kubectl -n agents delete secret "$bound_secret" --ignore-not-found >/dev/null
    kubectl delete -f guardian/deploy/g2-rbac.yaml --ignore-not-found >/dev/null
    kubectl apply -f infra/netpol/agents-default-deny.yaml >/dev/null
    printf 'g2-credential: PASS — scoped identity removed and default-deny restored\n'
    ;;
  *)
    echo "usage: G2_TOKEN_FILE=<private-path> $0 issue|revoke" >&2
    exit 2
    ;;
esac
