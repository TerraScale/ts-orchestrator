#!/usr/bin/env bash
# Build the host image for SOURCE on this machine from the same retained CI
# release and pinned inputs, without an Actions image workflow.
#
# usage: build-image-local.sh SOURCE_SHA [OUTPUT_DIRECTORY]
#
# SOURCE_SHA must have a successful ci.yml run on main. The output directory
# (default /tmp/ts-image-SOURCE) receives the QCOW2, guest kernel,
# image-qualification.json (builder.kind "local") and SHA256SUMS; promote it
# with ts-orch image promote --image-dir. The build runs at low
# priority in a temporary worktree of this repository at SOURCE.
#
# Authenticate gh for github.com before running this command.
set -euo pipefail

source_sha=${1:-}
[[ $source_sha =~ ^[0-9a-f]{40}$ && $# -le 2 ]] || { sed -n '2,17s/^# \{0,1\}//p' "$0" >&2; exit 2; }
output=${2:-/tmp/ts-image-$source_sha}
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
export GH_HOST=github.com
gh auth status --hostname github.com >/dev/null

umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/ts-image-local.XXXXXXXX")
cleanup() {
	git -C "$repository_root" worktree remove --force "$scratch/source" 2>/dev/null || true
	rm -rf -- "$scratch"
}
trap cleanup EXIT

git -C "$repository_root" fetch --quiet origin main
git -C "$repository_root" worktree add --quiet --detach "$scratch/source" "$source_sha"
cd "$scratch/source"
TMPDIR="$scratch" \
	TS_NETBIRD_CLIENT_CACHE="${TS_NETBIRD_CLIENT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/terrascale/netbird-client}" nice -n 19 \
	bash deploy/image/tools.sh bash deploy/image/build-image.sh --source "$source_sha" --out "$output"
echo "local image ready in $output"
