#!/usr/bin/env bash
# Wait for SOURCE_SHA's ci.yml run on main to end, then report whether its
# automatic image build should skip. Writes skip=true|false to GITHUB_OUTPUT.
#
# usage: image-superseded.sh SOURCE_SHA [WAIT_SECONDS]
#
# ci.yml dispatches the image build as it starts, so the image job prepares
# its tools while the checks run. A revision whose ci.yml run fails or is
# cancelled (a newer push to main supersedes it) is skipped, not failed.
# Automatic image runs queue instead of cancelling each other, so a build in
# progress always finishes; a queued build that a newer qualified revision
# has overtaken skips itself. A revision whose successor is still in ci.yml
# is built, because that successor may yet fail.
set -euo pipefail

source_sha=${1:-}
wait_seconds=${2:-1800}
[[ $source_sha =~ ^[0-9a-f]{40}$ && $wait_seconds =~ ^[0-9]+$ && $# -le 2 ]] || {
	echo "usage: $0 SOURCE_SHA [WAIT_SECONDS]" >&2
	exit 2
}
[[ -r ${FORGEJO_READ_TOKEN_FILE:-} ]] || { echo 'FORGEJO_READ_TOKEN_FILE must name a readable token file' >&2; exit 2; }
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

header=$(mktemp)
trap 'rm -f -- "$header"' EXIT
printf 'Authorization: token %s\n' "$(<"$FORGEJO_READ_TOKEN_FILE")" > "$header"
api_get() {
	curl --fail --silent --show-error --max-time 30 -H "@$header" \
		"$FORGEJO_SERVER_URL/api/v1/repos/TerraScale/ts-orchestrator/actions/runs?$1"
}

deadline=$((SECONDS + wait_seconds))
while :; do
	status=$(api_get "workflow_id=ci.yml&head_sha=$source_sha&limit=50" |
		jq -r '[.workflow_runs[] | select(.prettyref == "main")] | max_by(.id) | .status // "absent"')
	case $status in
		success) break ;;
		failure|cancelled|skipped|blocked)
			echo "skip=true" >> "$GITHUB_OUTPUT"
			echo "image for $source_sha skipped: its ci.yml run ended $status"
			exit 0 ;;
	esac
	((SECONDS < deadline)) || { echo "no finished ci.yml run on main for $source_sha (status $status)" >&2; exit 1; }
	sleep 10
done

runs=$(api_get "workflow_id=ci.yml&status=success&limit=50&page=1")
latest=$(jq -c '[.workflow_runs[] | select(.prettyref == "main")] | max_by(.id) // {}' <<< "$runs")
own=$(jq -c --arg source "$source_sha" \
	'[.workflow_runs[] | select(.prettyref == "main" and .commit_sha == $source)] | max_by(.id) // {}' <<< "$runs")
latest_id=$(jq -r '.id // 0' <<< "$latest")
own_id=$(jq -r '.id // 0' <<< "$own")
if ((own_id > 0 && latest_id > own_id)) && [[ $(jq -r .commit_sha <<< "$latest") != "$source_sha" ]]; then
	echo "skip=true" >> "$GITHUB_OUTPUT"
	echo "image for $source_sha skipped: $(jq -r .commit_sha <<< "$latest") passed ci.yml later (run $latest_id) and is imaged next"
else
	echo "skip=false" >> "$GITHUB_OUTPUT"
	echo "image for $source_sha is the newest qualified main revision"
fi
