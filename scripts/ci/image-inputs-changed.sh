#!/usr/bin/env bash
# Decide whether GITHUB_SHA needs a new host image. Exit 3 when every image
# input is unchanged since the source of the newest image release. Any other
# status builds: a changed input, no image release, a failed comparison or a
# failure of this script itself. Orchestrator code alone never needs an image: running nodes
# take new binaries through self-update, and a new node updates after its
# first boot.
#
# The base is the newest image release, not this push's parent: a newer
# push cancels a running ci.yml check, and a change the cancelled run carried
# must still produce an image.
set -euo pipefail
unchanged=3

# Everything an image bakes in besides the binary: the pinned base and
# inputs, the units and udev rules it installs, and the code that builds it.
inputs=(deploy/image deploy/systemd deploy/udev internal/image internal/netbird/client .github/workflows/image.yml)

: "${GH_TOKEN:?GitHub Actions token is required}"
export GH_HOST=github.com
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'GitHub source SHA is required' >&2; exit 0; }
repository=TerraScale/ts-orchestrator

# Releases list newest first; ci-<sha> releases outnumber image releases.
base=
page_size=50
for page in {1..10}; do
	if ! releases=$(timeout 30 gh api "repos/$repository/releases?per_page=$page_size&page=$page"); then
		echo 'image releases are unreadable; building the image' >&2
		exit 0
	fi
	base=$(jq -r 'first(.[].tag_name | capture("^image-(?<sha>[0-9a-f]{40})-run-").sha) // empty' <<< "$releases" 2>/dev/null) || base=
	[[ -n $base ]] && break
	[[ $(jq -r 'length' <<< "$releases" 2>/dev/null) == "$page_size" ]] || break
done
[[ -n $base ]] || { echo 'no image release found; building the image'; exit 0; }

# Both trees are fetched one level deep; diffing two trees needs no history.
auth=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w 0)
if ! GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraHeader GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $auth" \
	timeout 120 git fetch --quiet --no-tags --depth=1 origin "$base"; then
	echo "image release source $base is unreadable; building the image" >&2
	exit 0
fi
status=0
git diff --quiet "$base" "$GITHUB_SHA" -- "${inputs[@]}" || status=$?
case $status in
	0) echo "image inputs are unchanged since the image of $base"; exit "$unchanged" ;;
	1) echo "image inputs changed since the image of $base:"
	   git diff --name-only "$base" "$GITHUB_SHA" -- "${inputs[@]}" || true ;;
	*) echo "comparing with the image of $base failed; building the image" >&2 ;;
esac
