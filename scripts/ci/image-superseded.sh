#!/usr/bin/env bash
# Report whether an automatic image build for SOURCE_SHA is superseded: a
# newer main revision has already passed ci.yml, so its own image build is
# queued behind this one. Writes superseded=true|false to GITHUB_OUTPUT.
#
# usage: image-superseded.sh SOURCE_SHA
#
# Automatic image runs queue instead of cancelling each other, so a build in
# progress always finishes; a queued build that a newer qualified revision
# has overtaken skips itself. A revision whose successor is still in ci.yml
# is built, because that successor may yet fail.
set -euo pipefail

source_sha=${1:-}
[[ $source_sha =~ ^[0-9a-f]{40}$ && $# == 1 ]] || { echo "usage: $0 SOURCE_SHA" >&2; exit 2; }
[[ -r ${FORGEJO_READ_TOKEN_FILE:-} ]] || { echo 'FORGEJO_READ_TOKEN_FILE must name a readable token file' >&2; exit 2; }
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

header=$(mktemp)
trap 'rm -f -- "$header"' EXIT
printf 'Authorization: token %s\n' "$(<"$FORGEJO_READ_TOKEN_FILE")" > "$header"
runs=$(curl --fail --silent --show-error --max-time 30 -H "@$header" \
	"$FORGEJO_SERVER_URL/api/v1/repos/TerraScale/ts-orchestrator/actions/runs?workflow_id=ci.yml&status=success&limit=50&page=1")
latest=$(jq -c '[.workflow_runs[] | select(.prettyref == "main")] | max_by(.id) // {}' <<< "$runs")
own=$(jq -c --arg source "$source_sha" \
	'[.workflow_runs[] | select(.prettyref == "main" and .commit_sha == $source)] | max_by(.id) // {}' <<< "$runs")
latest_id=$(jq -r '.id // 0' <<< "$latest")
own_id=$(jq -r '.id // 0' <<< "$own")
if ((own_id > 0 && latest_id > own_id)) && [[ $(jq -r .commit_sha <<< "$latest") != "$source_sha" ]]; then
	echo "superseded=true" >> "$GITHUB_OUTPUT"
	echo "image for $source_sha skipped: $(jq -r .commit_sha <<< "$latest") passed ci.yml later (run $latest_id) and is imaged next"
else
	echo "superseded=false" >> "$GITHUB_OUTPUT"
	echo "image for $source_sha is the newest qualified main revision"
fi
