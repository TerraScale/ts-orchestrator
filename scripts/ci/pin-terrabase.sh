#!/usr/bin/env bash
# Pin a published TerraBase release in deploy/image/image-inputs.json and
# queue the data-only change for main, which qualifies and images it.
#
# usage: pin-terrabase.sh TERRABASE_RELEASE_TAG
#
# Run from a clean ts-orchestrator checkout of main with an authenticated GitHub CLI (gh) that can push branches and open pull requests. TerraBase's
# publish job calls it for every release it publishes; run it by hand to pin
# an older release. The release's Fast job must have succeeded; the image
# build later requires the whole TerraBase run to have succeeded.
set -euo pipefail

tag=${1:-}
[[ $tag =~ ^ci-([0-9a-f]{40})-run-([1-9][0-9]*)$ && $# == 1 ]] || {
	echo "usage: $0 ci-<terrabase sha>-run-<run id>" >&2
	exit 2
}
terrabase_sha=${BASH_REMATCH[1]}
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || { echo 'checkout is not clean' >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# Keep the tool outside the checkout, which moves to origin/main.
if [[ -n ${TS_ORCH_BIN:-} ]]; then
	cp -- "$(realpath -e -- "$TS_ORCH_BIN")" "$work/ts-orch"
else
	go build -trimpath -buildvcs=true -o "$work/ts-orch" ./cmd/terrascale-orchestrator
fi
pin_tool="$work/ts-orch"
gh release download "$tag" --repo TerraScale/TerraBase --pattern qualification.json --output "$work/qualification.json" >/dev/null
gh release download "$tag" --repo TerraScale/TerraBase --pattern tb-server-linux-arm64 --output "$work/tb-server-linux-arm64" >/dev/null
run_number=$(jq -er .verification.run_number "$work/qualification.json")
"$pin_tool" release run-detail --repository TerraScale/TerraBase --run-id "$(jq -er .verification.run_id "$work/qualification.json")" > "$work/run-detail.json"
jq -e --arg sha "$(sha256sum "$work/tb-server-linux-arm64" | cut -d ' ' -f 1)" \
	'[.artifacts[] | select(.name == "tb-server-linux-arm64" and .sha256 == $sha)] | length == 1' \
	"$work/qualification.json" >/dev/null || { echo "tb-server-linux-arm64 of $tag differs from its qualification" >&2; exit 1; }

git fetch --quiet origin main
git checkout --quiet --detach origin/main
"$pin_tool" image inputs pin-terrabase \
	--qualification "$work/qualification.json" --run-detail "$work/run-detail.json"
if git diff --quiet -- deploy/image/image-inputs.json; then
	echo "TerraBase $terrabase_sha is already pinned"
	exit 0
fi
title="Pin TerraBase ${terrabase_sha:0:12} (Fast run $run_number) in image inputs"
git -c user.name=github-actions -c 'user.email=41898282+github-actions[bot]@users.noreply.github.com' \
	commit --quiet -m "$title

Data-only pin bump from TerraBase release $tag." -- deploy/image/image-inputs.json
# main accepts changes only through the merge queue, which tests the pin on
# the latest main and merges it.
branch=pin/terrabase-${terrabase_sha:0:12}
git push --quiet --force origin "HEAD:refs/heads/$branch"
gh pr view "$branch" --repo TerraScale/ts-orchestrator --json number >/dev/null 2>&1 ||
	gh pr create --repo TerraScale/ts-orchestrator --base main --head "$branch" \
		--title "$title" --body "Data-only pin bump from TerraBase release $tag." >/dev/null
gh pr merge "$branch" --repo TerraScale/ts-orchestrator --auto --squash
echo "queued TerraBase $tag as $(git rev-parse HEAD) on $branch"
