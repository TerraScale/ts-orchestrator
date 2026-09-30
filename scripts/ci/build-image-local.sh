#!/usr/bin/env bash
# Build the host image for SOURCE on this machine from the same retained CI
# release and pinned inputs image.yml uses, without waiting for the runner.
#
# usage: build-image-local.sh SOURCE_SHA [OUTPUT_DIRECTORY]
#
# SOURCE_SHA must have a successful ci.yml run on main. The output directory
# (default /tmp/ts-image-SOURCE) receives the QCOW2, guest kernel,
# image-qualification.json (builder.kind "local") and SHA256SUMS; promote it
# with deploy/image/promote-image.py --image-dir. The build runs at low
# priority in a temporary worktree of this repository at SOURCE.
#
# fj must be the pinned build with `actions run-detail` and `actions logs`:
# TS_FJ names it (default: the admission build under
# ~/.local/share/terrascale-controller-bootstrap-20260927). Reads use that
# fj's stored login; FORGEJO_READ_TOKEN_FILE (default: a copy of the stored
# token) authenticates Actions API lookups.
set -euo pipefail

source_sha=${1:-}
[[ $source_sha =~ ^[0-9a-f]{40}$ && $# -le 2 ]] || { sed -n '2,17s/^# \{0,1\}//p' "$0" >&2; exit 2; }
output=${2:-/tmp/ts-image-$source_sha}
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
fj_binary=${TS_FJ:-$HOME/.local/share/terrascale-controller-bootstrap-20260927/fj-admission-pinned-7f44ff1a/bin/fj}
[[ -x $fj_binary ]] || { echo "pinned fj not found: $fj_binary (set TS_FJ)" >&2; exit 1; }
if ! "$fj_binary" actions run-detail --help >/dev/null || ! "$fj_binary" actions logs --help >/dev/null; then
	echo "$fj_binary lacks the actions run-detail/logs extension" >&2
	exit 1
fi

umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/ts-image-local.XXXXXXXX")
cleanup() {
	git -C "$repository_root" worktree remove --force "$scratch/source" 2>/dev/null || true
	rm -rf -- "$scratch"
}
trap cleanup EXIT
mkdir -m 0700 "$scratch/bin"
ln -s "$fj_binary" "$scratch/bin/fj"
if [[ -z ${FORGEJO_READ_TOKEN_FILE:-} ]]; then
	jq -er '.hosts["git.terrascale.tech"].token' "${XDG_DATA_HOME:-$HOME/.local/share}/forgejo-cli/keys.json" \
		> "$scratch/read-token" || { echo 'no stored fj login for git.terrascale.tech' >&2; exit 1; }
	export FORGEJO_READ_TOKEN_FILE="$scratch/read-token"
fi

git -C "$repository_root" fetch --quiet origin main
git -C "$repository_root" worktree add --quiet --detach "$scratch/source" "$source_sha"
cd "$scratch/source"
PATH="$scratch/bin:$PATH" TMPDIR="$scratch" nice -n 19 \
	bash deploy/image/tools.sh bash deploy/image/build-image.sh --source "$source_sha" --out "$output"
echo "local image ready in $output"
