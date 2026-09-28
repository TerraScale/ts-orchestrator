#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi

repo=$(cd "$(dirname "$0")/../.." && pwd)
output_dir=$1
upstream_revision=7f44ff1a1587a406b627ac45f0a2485b970c6379
upstream_lock_sha256=4de42ee153468f31e6f0f0062777fa684cc519a122e5e7139020428a9da72651
extension_patch_sha256=95cffe7416774e3740c11bb604c1a0a98909a3af717146b2ea65ce3ce1d92f05
nixpkgs_flake=github:NixOS/nixpkgs/e554fab72f81915600f3f449b786fd9af40439a5
nixpkgs_nar_hash=sha256-ZKhUe/2IJUq1JhKxKMu8rbkgSGmPP2ZCqlIPn40aGCM=
patch="$repo/scripts/ci/fj-run-detail.patch"

for tool in fj git nix jq rustup sha256sum python3; do
    command -v "$tool" >/dev/null || { echo "$tool is required to prepare fj admission" >&2; exit 1; }
done
[[ $(sha256sum "$patch" | awk '{print $1}') == "$extension_patch_sha256" ]] || {
    echo 'fj admission patch digest differs from the pinned digest' >&2
    exit 1
}
[[ $(nix flake metadata --json "$nixpkgs_flake" | jq -r .locked.narHash) == "$nixpkgs_nar_hash" ]] || {
    echo 'fj admission build toolchain differs from the pinned nixpkgs source' >&2
    exit 1
}
openssl_dev=$(nix eval --raw "${nixpkgs_flake}#legacyPackages.x86_64-linux.openssl.dev.outPath")

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/fj-admission.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
fj repo clone -H https://codeberg.org forgejo-contrib/forgejo-cli "$work/source"
git -C "$work/source" checkout --detach "$upstream_revision"
[[ $(git -C "$work/source" rev-parse HEAD) == "$upstream_revision" ]] || {
    echo 'fj upstream checkout differs from the pinned revision' >&2
    exit 1
}
[[ $(sha256sum "$work/source/Cargo.lock" | awk '{print $1}') == "$upstream_lock_sha256" ]] || {
    echo 'fj upstream lockfile differs from the pinned digest' >&2
    exit 1
}
git -C "$work/source" apply --check "$patch"
git -C "$work/source" apply "$patch"

# The tool is built at normal CI priority from pinned source and dependencies.
rustup toolchain install 1.98.1 --profile minimal
export CARGO_TARGET_DIR="$work/target"
nix shell --no-write-lock-file \
    "${nixpkgs_flake}#pkg-config" \
    "${nixpkgs_flake}#openssl.dev" \
    --command env \
    "CARGO_PROFILE_RELEASE_LTO=false" \
    "PKG_CONFIG_PATH=${openssl_dev}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
    bash -c 'cd "$1" && rustup run 1.98.1 cargo build --locked --release --bin fj -j 4' \
    bash "$work/source"
mkdir -p "$output_dir"
install -m 0755 "$CARGO_TARGET_DIR/release/fj" "$output_dir/fj"
"$output_dir/fj" actions run-detail --help >/dev/null
"$output_dir/fj" actions logs --help >/dev/null
"$output_dir/fj" actions job-logs --help >/dev/null
python3 "$repo/scripts/ci/test-fj-attachment-probe.py" "$output_dir/fj"
printf 'fj admission upstream=%s lock_sha256=%s patch_sha256=%s binary_sha256=%s\n' \
    "$upstream_revision" "$upstream_lock_sha256" "$extension_patch_sha256" \
    "$(sha256sum "$output_dir/fj" | awk '{print $1}')"
