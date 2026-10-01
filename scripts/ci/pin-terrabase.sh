#!/usr/bin/env bash
# Pin a published TerraBase release in deploy/image/image-inputs.json and
# push the data-only change to main, which qualifies and images it.
#
# usage: pin-terrabase.sh TERRABASE_RELEASE_TAG
#
# Run from a clean ts-orchestrator checkout of main with an authenticated fj
# that has `actions run-detail`, and git push access to origin. TerraBase's
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
# Keep the tool outside the checkout while the retry loop advances main.
if [[ -n ${TS_ORCH_BIN:-} ]]; then
	pin_tool=$(realpath -e -- "$TS_ORCH_BIN")
else
	go build -trimpath -buildvcs=true -o "$work/ts-orch" ./cmd/terrascale-orchestrator
	pin_tool="$work/ts-orch"
fi
fj release asset download -r TerraScale/TerraBase "$tag" qualification.json -o "$work/qualification.json" >/dev/null
fj release asset download -r TerraScale/TerraBase "$tag" tb-server-linux-arm64 -o "$work/tb-server-linux-arm64" >/dev/null
run_number=$(jq -er .verification.run_number "$work/qualification.json")
fj actions run-detail "$run_number" -r TerraScale/TerraBase > "$work/run-detail.json"
jq -e --arg sha "$(sha256sum "$work/tb-server-linux-arm64" | cut -d ' ' -f 1)" \
	'[.artifacts[] | select(.name == "tb-server-linux-arm64" and .sha256 == $sha)] | length == 1' \
	"$work/qualification.json" >/dev/null || { echo "tb-server-linux-arm64 of $tag differs from its qualification" >&2; exit 1; }

for attempt in 1 2 3 4 5; do
	git fetch --quiet origin main
	git checkout --quiet --detach origin/main
	"$pin_tool" image inputs pin-terrabase \
		--qualification "$work/qualification.json" --run-detail "$work/run-detail.json"
	if git diff --quiet -- deploy/image/image-inputs.json; then
		echo "TerraBase $terrabase_sha is already pinned"
		exit 0
	fi
	git -c user.name=terrascale-bot -c user.email=terrascale-bot@noreply.git.terrascale.tech \
		commit --quiet -m "Pin TerraBase ${terrabase_sha:0:12} (Fast run $run_number) in image inputs

Data-only pin bump from TerraBase release $tag." -- deploy/image/image-inputs.json
	if git push --quiet origin HEAD:main; then
		echo "pinned TerraBase $tag as $(git rev-parse HEAD)"
		exit 0
	fi
	echo "main moved; retrying the pin bump (attempt $attempt)" >&2
	sleep $((attempt * 2))
done
echo 'could not push the pin bump to main' >&2
exit 1
