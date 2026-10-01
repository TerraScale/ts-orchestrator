#!/usr/bin/env bash
# Start image.yml for the revision this ci.yml run is checking. Called as the
# first ci.yml step on main, so the image job prepares its tools meanwhile;
# it waits for this run to retain the release and skips itself if the run
# fails or is cancelled.
set -euo pipefail

: "${FORGEJO_TOKEN:?Forgejo Actions token is required}"
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'Forgejo source SHA is required' >&2; exit 1; }
[[ ${GITHUB_REF:-} == refs/heads/main ]] || { echo 'only main revisions are imaged automatically' >&2; exit 1; }

umask 077
header=$(mktemp)
trap 'rm -f -- "$header"' EXIT
printf 'Authorization: token %s\n' "$FORGEJO_TOKEN" > "$header"
unset FORGEJO_TOKEN GITHUB_TOKEN
body=$(jq -cn --arg source "$GITHUB_SHA" '{ref:"main", inputs:{source_revision:$source, trigger:"ci"}}')
status=$(curl --silent --show-error --output /dev/stderr --write-out '%{http_code}' --max-time 30 \
	-X POST -H "@$header" -H 'Content-Type: application/json' --data "$body" \
	"$FORGEJO_SERVER_URL/api/v1/repos/TerraScale/ts-orchestrator/actions/workflows/image.yml/dispatches")
[[ $status == 204 || $status == 201 ]] || { echo "image.yml dispatch returned HTTP $status" >&2; exit 1; }
echo "image.yml dispatched for $GITHUB_SHA"
