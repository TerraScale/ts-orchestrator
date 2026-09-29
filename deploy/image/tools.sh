#!/usr/bin/env bash
# Run COMMAND with the pinned image tools on PATH: qemu, libguestfs with its
# appliance, guestfs-tools, host systemd (offline systemctl/sysusers) and
# gnupg, all from one nixpkgs revision.
#
# usage: tools.sh COMMAND [ARG...]
#
# TS_IMAGE_TOOL_CACHE names an extra Nix binary cache (CI: file:///cache/nix
# on the runner's shared volume). The closure is substituted from it and
# copied back after a build, so only the first run on a runner builds
# libguestfs. TS_IMAGE_TOOLS_ID is exported with the pinned revision.
set -euo pipefail

(($#)) || { sed -n '2,12s/^# \{0,1\}//p' "$0" >&2; exit 2; }
nixpkgs_revision=e554fab72f81915600f3f449b786fd9af40439a5
nixpkgs_nar_hash=sha256-ZKhUe/2IJUq1JhKxKMu8rbkgSGmPP2ZCqlIPn40aGCM=
nixpkgs=github:NixOS/nixpkgs/$nixpkgs_revision
installables=()
for package in qemu libguestfs-with-appliance guestfs-tools systemd gnupg; do
	installables+=("$nixpkgs#$package")
done

[[ $(nix flake metadata --json "$nixpkgs" | jq -r .locked.narHash) == "$nixpkgs_nar_hash" ]] || {
	echo 'image tool nixpkgs source differs from its pinned NAR hash' >&2
	exit 1
}
substituters=()
if [[ -n ${TS_IMAGE_TOOL_CACHE:-} ]]; then
	# Ahead of cache.nixos.org, so the whole closure comes from local disk.
	substituters=(--extra-substituters "$TS_IMAGE_TOOL_CACHE?trusted=1&priority=10")
fi
started=$SECONDS
nix build --no-link "${substituters[@]}" "${installables[@]}"
if [[ -n ${TS_IMAGE_TOOL_CACHE:-} ]]; then
	nix copy --to "$TS_IMAGE_TOOL_CACHE?compression=zstd&parallel-compression=true" "${installables[@]}"
fi
echo "image tools ready nixpkgs=$nixpkgs_revision seconds=$((SECONDS - started))"
export TS_IMAGE_TOOLS_ID="nixpkgs=$nixpkgs_revision nar_hash=$nixpkgs_nar_hash"
exec nix shell "${installables[@]}" --command "$@"
