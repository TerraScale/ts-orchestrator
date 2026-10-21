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
inputs=(deploy/image deploy/systemd deploy/udev internal/image internal/netbird/client .github/workflows/image.yml
	go.mod go.sum scripts/ci/image-inputs-changed.sh)

# Follow the image tool's imports, including helpers that render baked files.
# Package source globs retain deleted, generated and other-platform inputs;
# embed prefixes retain removed files that no longer appear in EmbedFiles.
root=$(git rev-parse --show-toplevel)
graph=
for architecture in amd64 arm64; do
	if ! platform_graph=$(GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOOS=linux GOARCH=$architecture \
		go list -mod=readonly -deps -json ./internal/image ./internal/netbird/client); then
		echo 'image tool dependencies are unreadable; building the image' >&2
		exit 0
	fi
	graph+=$'\n'"$platform_graph"
done
if ! dependencies=$(jq -rs --arg root "$root/" '
	[.[] | select(.Dir | startswith($root)) |
	 (.Dir | ltrimstr($root)) as $dir |
	 (["go", "s", "S", "h", "c", "cc", "cpp", "m", "mm", "syso"][] |
	   ":(glob)" + $dir + "/*." + .),
	 ((.EmbedPatterns // [])[] | sub("^all:"; "") | sub("[*?\\[].*$"; "") |
	   sub("/+$"; "") | ":(literal)" + $dir + "/" + .),
	 (.Module.GoMod // empty | select(startswith($root)) |
	   ltrimstr($root) | ":(literal)" + .)] |
	if length == 0 or any(test("[\\r\\n]")) then error("invalid image dependencies") else .[] end
' <<< "$graph"); then
	echo 'image tool dependency paths are unreadable; building the image' >&2
	exit 0
fi
while IFS= read -r dependency; do inputs+=("$dependency"); done <<< "$dependencies"
inputs+=(':(exclude,glob)**/*_test.go')

if ! pins=$(jq -er '
	[.. | objects | .path? | strings] |
	if length == 0 or any(. == "" or startswith("/") or
	   test("(^|/)\\.\\.(/|$)|[\\r\\n]")) then error("invalid image file pins") else .[] end
' deploy/image/image-inputs.json); then
	echo 'image file pins are unreadable; building the image' >&2
	exit 0
fi
while IFS= read -r pin; do inputs+=(":(literal)$pin"); done <<< "$pins"

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
	base=$(jq -r 'first(.[] | select(.draft == false and
		any(.assets[]?; .name == "image-qualification.json")) |
		.tag_name | capture("^image-(?<sha>[0-9a-f]{40})-run-").sha) // empty' <<< "$releases" 2>/dev/null) || base=
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
