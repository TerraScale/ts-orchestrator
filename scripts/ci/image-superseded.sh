#!/usr/bin/env bash
# Wait for the dispatching ci.yml run on main to end, then report whether its
# automatic image build should skip. Writes skip=true|false to GITHUB_OUTPUT.
#
# usage: image-superseded.sh SOURCE_SHA CI_RUN_ID CI_RUN_NUMBER [WAIT_SECONDS]
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
ci_run_id=${2:-}
ci_run_number=${3:-}
wait_seconds=${4:-6000}
[[ $source_sha =~ ^[0-9a-f]{40}$ && $ci_run_id =~ ^[1-9][0-9]{0,17}$ &&
	$ci_run_number =~ ^[1-9][0-9]{0,17}$ && $wait_seconds =~ ^(0|[1-9][0-9]{0,5})$ && $# -le 4 ]] || {
	echo "usage: $0 SOURCE_SHA CI_RUN_ID CI_RUN_NUMBER [WAIT_SECONDS]" >&2
	exit 2
}
[[ -r ${FORGEJO_READ_TOKEN_FILE:-} ]] || { echo 'FORGEJO_READ_TOKEN_FILE must name a readable token file' >&2; exit 2; }
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

umask 077
header=$(mktemp)
trap 'rm -f -- "$header"' EXIT
printf 'Authorization: token %s\n' "$(<"$FORGEJO_READ_TOKEN_FILE")" > "$header"
deadline=$((SECONDS + wait_seconds))
api_get() {
	local remaining=$((deadline - SECONDS))
	((remaining > 0)) || return 1
	((remaining <= 30)) || remaining=30
	curl --fail --silent --show-error --max-time "$remaining" -H "@$header" \
		"$FORGEJO_SERVER_URL/api/v1/repos/TerraScale/ts-orchestrator/actions/runs?$1"
}
wait_again() {
	local remaining=$((deadline - SECONDS))
	((remaining > 0)) || {
		echo "CI image gate timed out for $source_sha (run $ci_run_id, status $status); dispatch image.yml manually after ci.yml succeeds" >&2
		exit 1
	}
	((remaining <= 10)) || remaining=10
	sleep "$remaining"
}

while :; do
	if ! status=$(api_get "workflow_id=ci.yml&run_number=$ci_run_number&limit=50" |
		jq -r --arg id "$ci_run_id" --arg source "$source_sha" \
		'[(.workflow_runs // [])[] | select((.id | tostring) == $id and
		  .workflow_id == "ci.yml" and .prettyref == "main" and .commit_sha == $source)] |
		  first | .status // "absent"'); then
		status=poll-failed
		echo "actions run poll failed; retrying run $ci_run_id" >&2
	fi
	case $status in
		success) break ;;
		failure|cancelled)
			echo "skip=true" >> "$GITHUB_OUTPUT"
			echo "image for $source_sha skipped: dispatching ci.yml run $ci_run_id ended $status"
			exit 0 ;;
		blocked|skipped)
			echo "dispatching ci.yml run $ci_run_id is $status; dispatch image.yml manually after ci.yml succeeds" >&2
			exit 1 ;;
	esac
	wait_again
done

# A repeated run of this SHA cannot replace the dispatching run's identity.
# Retry supersession reads within the same budget instead of losing a
# qualified image on a transient Actions API failure.
while :; do
	if latest=$(api_get "workflow_id=ci.yml&status=success&limit=50&page=1" |
		jq -c '[(.workflow_runs // [])[] | select(.workflow_id == "ci.yml" and
		  .prettyref == "main" and .status == "success")] | max_by(.id) // {}'); then
		break
	fi
	status=supersession-poll-failed
	echo "qualified run poll failed; retrying" >&2
	wait_again
done
latest_id=$(jq -r '.id // 0' <<< "$latest")
if ((latest_id > ci_run_id)) && [[ $(jq -r .commit_sha <<< "$latest") != "$source_sha" ]]; then
	echo "skip=true" >> "$GITHUB_OUTPUT"
	echo "image for $source_sha skipped: $(jq -r .commit_sha <<< "$latest") passed ci.yml later (run $latest_id) and is imaged next"
else
	echo "skip=false" >> "$GITHUB_OUTPUT"
	echo "image for $source_sha qualified by dispatching ci.yml run $ci_run_id"
fi
