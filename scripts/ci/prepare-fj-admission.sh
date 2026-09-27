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
extension_patch_sha256=bf905cf4f9cdc6f2d7168450b2a51cb24228a702a47d5f8bdf67ffeb772525e0
patch="$repo/scripts/ci/fj-run-detail.patch"

for tool in fj git rustup sha256sum; do
    command -v "$tool" >/dev/null || { echo "$tool is required to prepare fj admission" >&2; exit 1; }
done
[[ $(sha256sum "$patch" | awk '{print $1}') == "$extension_patch_sha256" ]] || {
    echo 'fj admission patch digest differs from the pinned digest' >&2
    exit 1
}

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
(cd "$work/source" && rustup run 1.98.1 cargo build --locked --release --bin fj -j 4)
mkdir -p "$output_dir"
install -m 0755 "$CARGO_TARGET_DIR/release/fj" "$output_dir/fj"
"$output_dir/fj" actions run-detail --help >/dev/null
"$output_dir/fj" actions logs --help >/dev/null
printf 'fj admission upstream=%s lock_sha256=%s patch_sha256=%s binary_sha256=%s\n' \
    "$upstream_revision" "$upstream_lock_sha256" "$extension_patch_sha256" \
    "$(sha256sum "$output_dir/fj" | awk '{print $1}')"
