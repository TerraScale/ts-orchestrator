#!/usr/bin/env bash
# Start WORKFLOW (default image.yml, or deploy.yml) for the revision this
# ci.yml run is checking. Called as the last ci.yml steps on main, after the
# release is retained, so the dispatched job never holds a builder slot while
# the checks run; it still confirms this run succeeded and skips itself if
# the run fails or is cancelled.
set -euo pipefail

workflow=${1:-image.yml}
[[ $workflow == image.yml || $workflow == deploy.yml ]] || { echo "usage: $0 [image.yml|deploy.yml]" >&2; exit 2; }

: "${GH_TOKEN:?GitHub Actions token is required}"
export GH_HOST=github.com
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'GitHub source SHA is required' >&2; exit 1; }
[[ ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]{0,17}$ && ${GITHUB_RUN_NUMBER:-} =~ ^[1-9][0-9]{0,17}$ ]] || { echo 'GitHub CI run identity is required' >&2; exit 1; }
[[ ${GITHUB_REF:-} == refs/heads/main ]] || { echo "only main revisions start $workflow automatically" >&2; exit 1; }

# An image is rebuilt only when its inputs change, and weekly (the schedule)
# so base and package updates still land.
if [[ $workflow == image.yml && ${GITHUB_EVENT_NAME:-} != schedule ]]; then
	status=0
	bash "$(dirname -- "$0")/image-inputs-changed.sh" || status=$?
	if ((status == 3)); then
		echo "image.yml not dispatched for $GITHUB_SHA"
		exit 0
	fi
fi

gh api --method POST "repos/TerraScale/ts-orchestrator/actions/workflows/$workflow/dispatches" \
	-f ref=main -f "inputs[source_revision]=$GITHUB_SHA" \
	-f "inputs[source_ci_run_id]=$GITHUB_RUN_ID" -f "inputs[source_ci_run_number]=$GITHUB_RUN_NUMBER" \
	-f 'inputs[trigger]=ci'
echo "$workflow dispatched for $GITHUB_SHA"
