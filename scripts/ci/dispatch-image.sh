#!/usr/bin/env bash
# Start WORKFLOW (default image.yml, or deploy.yml) for the revision this
# ci.yml run is checking. Called as the last ci.yml steps on main, after the
# release is retained, so the dispatched job never holds a builder slot while
# the checks run; it still confirms this run succeeded and skips itself if
# the run fails or is cancelled.
set -euo pipefail

workflow=${1:-image.yml}
[[ $workflow == image.yml || $workflow == deploy.yml ]] || { echo "usage: $0 [image.yml|deploy.yml]" >&2; exit 2; }

: "${FORGEJO_TOKEN:?Forgejo Actions token is required}"
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'Forgejo source SHA is required' >&2; exit 1; }
[[ ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]{0,17}$ && ${GITHUB_RUN_NUMBER:-} =~ ^[1-9][0-9]{0,17}$ ]] || { echo 'Forgejo CI run identity is required' >&2; exit 1; }
[[ ${GITHUB_REF:-} == refs/heads/main ]] || { echo "only main revisions start $workflow automatically" >&2; exit 1; }

umask 077
header=$(mktemp)
trap 'rm -f -- "$header"' EXIT
printf 'Authorization: token %s\n' "$FORGEJO_TOKEN" > "$header"
unset FORGEJO_TOKEN GITHUB_TOKEN
body=$(jq -cn --arg source "$GITHUB_SHA" --arg run_id "$GITHUB_RUN_ID" --arg run_number "$GITHUB_RUN_NUMBER" \
	'{ref:"main", inputs:{source_revision:$source, source_ci_run_id:$run_id, source_ci_run_number:$run_number, trigger:"ci"}}')
status=$(curl --silent --show-error --output /dev/stderr --write-out '%{http_code}' --max-time 30 \
	-X POST -H "@$header" -H 'Content-Type: application/json' --data "$body" \
	"$FORGEJO_SERVER_URL/api/v1/repos/TerraScale/ts-orchestrator/actions/workflows/$workflow/dispatches")
[[ $status == 204 || $status == 201 ]] || { echo "$workflow dispatch returned HTTP $status" >&2; exit 1; }
echo "$workflow dispatched for $GITHUB_SHA"
