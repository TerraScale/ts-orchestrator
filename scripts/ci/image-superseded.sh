#!/usr/bin/env bash
# Wait for the dispatching ci.yml run on main to end, then report whether its
# automatic image build (or, with GATE_WORKFLOW=deploy.yml, its fleet
# deployment) should skip. Writes skip=true|false to GITHUB_OUTPUT.
#
# usage: image-superseded.sh SOURCE_SHA CI_RUN_ID CI_RUN_NUMBER [WAIT_SECONDS]
#
# ci.yml dispatches the image build as its last step, after the release is
# retained, so the run is normally about to end when this starts. A revision
# whose ci.yml run fails or is cancelled (a newer push to main supersedes it)
# is skipped, not failed.
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
	$ci_run_number =~ ^[1-9][0-9]{0,17}$ && $wait_seconds =~ ^[1-9][0-9]{0,5}$ && $# -le 4 ]] || {
	echo "usage: $0 SOURCE_SHA CI_RUN_ID CI_RUN_NUMBER [WAIT_SECONDS]" >&2
	exit 2
}
export GH_TOKEN=${GH_TOKEN:-${GH_READ_TOKEN:-}}
: "${GH_TOKEN:?GitHub read token is required}"
export GH_HOST=github.com
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
workflow=${GATE_WORKFLOW:-image.yml}

deadline=$((SECONDS + wait_seconds))
api_get() {
	local remaining=$((deadline - SECONDS))
	((remaining > 0)) || return 1
	((remaining <= 30)) || remaining=30
	timeout "$remaining" gh api "$@"
}
wait_again() {
	local remaining=$((deadline - SECONDS))
	((remaining > 0)) || {
		echo "CI gate timed out for $source_sha (run $ci_run_id, status $status); dispatch $workflow manually after ci.yml succeeds" >&2
		exit 1
	}
	((remaining <= 10)) || remaining=10
	sleep "$remaining"
}

while :; do
	if ! status=$(api_get "repos/TerraScale/ts-orchestrator/actions/runs/$ci_run_id" |
		jq -r --arg id "$ci_run_id" --arg number "$ci_run_number" --arg source "$source_sha" '
		  if (.id | tostring) == $id and (.run_number | tostring) == $number and
		    .path == ".github/workflows/ci.yml" and .head_branch == "main" and .head_sha == $source then
		    if .status == "completed" then .conclusion else .status end
		  else "absent" end'); then
		status=poll-failed
		echo "actions run poll failed; retrying run $ci_run_id" >&2
	fi
	case $status in
		success) break ;;
		failure|cancelled)
			echo "skip=true" >> "$GITHUB_OUTPUT"
			echo "$workflow for $source_sha skipped: dispatching ci.yml run $ci_run_id ended $status"
			exit 0 ;;
		action_required|skipped|timed_out|neutral|stale|startup_failure)
			echo "dispatching ci.yml run $ci_run_id is $status; dispatch $workflow manually after ci.yml succeeds" >&2
			exit 1 ;;
	esac
	wait_again
done

# A repeated run of this SHA cannot replace the dispatching run's identity.
# Retry supersession reads within the same budget instead of losing a
# qualified image on a transient Actions API failure.
while :; do
	if candidates=$(api_get --paginate --slurp "repos/TerraScale/ts-orchestrator/actions/workflows/ci.yml/runs?branch=main&status=success&per_page=100" |
		jq -c '[.[].workflow_runs[] | select(.path == ".github/workflows/ci.yml" and
		  .head_branch == "main" and .event != "pull_request" and .status == "completed" and
		  .conclusion == "success")] | sort_by(.id) | reverse | .[]'); then
		break
	fi
	status=supersession-poll-failed
	echo "qualified run poll failed; retrying" >&2
	wait_again
done
latest='{}'
# A successful docs-only check has no retained runtime candidate and cannot
# supersede the older executable/image candidate still waiting for delivery.
while IFS= read -r candidate; do
	[[ -n $candidate ]] || continue
	latest_id=$(jq -r .id <<< "$candidate")
	((latest_id > ci_run_id)) || break
	latest_source=$(jq -er '.head_sha | select(test("^[0-9a-f]{40}$"))' <<< "$candidate")
	tag=ci-$latest_source-run-$latest_id
	if release=$(api_get "repos/TerraScale/ts-orchestrator/releases/tags/$tag") &&
		jq -e --arg tag "$tag" '(.assets | map(.name)) as $assets |
		  .tag_name == $tag and .draft == false and .prerelease == true and
		  all(["qualification.json", "terrascale-orchestrator-linux-amd64",
		    "terrascale-orchestrator-linux-arm64"][]; . as $name |
		    [$assets[] | select(. == $name)] | length == 1)' <<< "$release" >/dev/null; then
		latest=$candidate
		break
	fi
done <<< "$candidates"
latest_id=$(jq -r '.id // 0' <<< "$latest")
if ((latest_id > ci_run_id)) && [[ $(jq -r .head_sha <<< "$latest") != "$source_sha" ]]; then
	echo "skip=true" >> "$GITHUB_OUTPUT"
	echo "$workflow for $source_sha skipped: $(jq -r .head_sha <<< "$latest") passed ci.yml later (run $latest_id) and runs next"
else
	echo "skip=false" >> "$GITHUB_OUTPUT"
	echo "$workflow for $source_sha qualified by dispatching ci.yml run $ci_run_id"
fi
