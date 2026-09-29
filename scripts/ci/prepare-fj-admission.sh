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
expected_binary_sha256=2f6f4c0392ec8ad8a46ca1b96b856abf9b8a5583f044044e9776989eec51c4e4
rust_toolchain=1.98.1
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

[[ ! -L "$output_dir" ]] || { echo 'fj admission output directory is a symlink' >&2; exit 1; }
install -d -m 0700 "$output_dir"
chmod 0700 "$output_dir"
rm -f -- "$output_dir/fj"

binary_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

verify_binary() {
    [[ $(binary_sha256 "$output_dir/fj") == "$expected_binary_sha256" ]] || return 1
    "$output_dir/fj" actions run-detail --help >/dev/null &&
        "$output_dir/fj" actions logs --help >/dev/null &&
        "$output_dir/fj" actions job-logs --help >/dev/null &&
        python3 "$repo/scripts/ci/test-fj-attachment-probe.py" "$output_dir/fj"
}

# The shared cache is untrusted. Its key is an identity filter; the fixed digest
# on the copied private binary is the execution gate.
cache_dir=${TS_FJ_ADMISSION_CACHE_DIR:-}
cache_entry=
cache_key=
if [[ -n $cache_dir && $cache_dir = /* && ! -L $cache_dir ]]; then
    platform="$(uname -s)-$(uname -m)"
    cache_key=$(printf '%s\n' "$upstream_revision" "$upstream_lock_sha256" \
        "$extension_patch_sha256" "$rust_toolchain" "$nixpkgs_flake" \
        "$nixpkgs_nar_hash" "$platform" | sha256sum | awk '{print $1}')
    cache_entry="$cache_dir/$cache_key/fj"
    if [[ -f $cache_entry && ! -L $cache_entry ]] &&
        install -m 0755 "$cache_entry" "$output_dir/fj"; then
        if verify_binary; then
            printf 'fj admission upstream=%s lock_sha256=%s patch_sha256=%s binary_sha256=%s cache=hit key=%s\n' \
                "$upstream_revision" "$upstream_lock_sha256" "$extension_patch_sha256" \
                "$expected_binary_sha256" "$cache_key"
            exit 0
        fi
        rm -f -- "$output_dir/fj"
        echo 'fj admission cache entry failed verification; rebuilding pinned source' >&2
    fi
fi

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
openssl_dev=$(nix eval --raw "${nixpkgs_flake}#legacyPackages.x86_64-linux.openssl.dev.outPath")
rustup toolchain install "$rust_toolchain" --profile minimal
export CARGO_TARGET_DIR="$work/target"
nix shell --no-write-lock-file \
    "${nixpkgs_flake}#pkg-config" \
    "${nixpkgs_flake}#openssl.dev" \
    --command env \
    "CARGO_PROFILE_RELEASE_LTO=false" \
    "PKG_CONFIG_PATH=${openssl_dev}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
    bash -c 'cd "$1" && rustup run "$2" cargo build --locked --release --bin fj -j 4' \
    bash "$work/source" "$rust_toolchain"
install -m 0755 "$CARGO_TARGET_DIR/release/fj" "$output_dir/fj"
verify_binary || { echo 'fj admission built binary failed fixed digest or fixture checks' >&2; exit 1; }

if [[ -n $cache_entry ]]; then
    cache_slot=${cache_entry%/fj}
    if [[ ! -L $cache_slot ]] && install -d -m 0700 "$cache_slot" &&
        [[ $(stat -c %u "$cache_slot") == "$(id -u)" ]]; then
        if cache_temp=$(mktemp "$cache_slot/.fj.XXXXXXXX"); then
            if install -m 0755 "$output_dir/fj" "$cache_temp" &&
                [[ $(binary_sha256 "$cache_temp") == "$expected_binary_sha256" ]]; then
                mv -fT "$cache_temp" "$cache_entry" || true
            fi
            rm -f -- "$cache_temp"
        fi
    fi
fi
printf 'fj admission upstream=%s lock_sha256=%s patch_sha256=%s binary_sha256=%s cache=build key=%s\n' \
    "$upstream_revision" "$upstream_lock_sha256" "$extension_patch_sha256" \
    "$expected_binary_sha256" "${cache_key:-none}"
