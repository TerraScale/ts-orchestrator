#!/usr/bin/env bash
# Transport only: final-image admission belongs to release verify-image-production.
set -euo pipefail
[[ $# == 5 && $1 =~ ^ci-[0-9a-f]{40}-run-[1-9][0-9]{0,17}$ &&
    $2 =~ ^[0-9a-f]{64}$ && $3 =~ ^[A-Z]{3}$ && ($4 == arm64 || $4 == amd64) ]] || {
    echo "usage: $0 ci-SHA-run-ID IMAGE_SHA256 CELL ARCH EVIDENCE_DIR" >&2; exit 2;
}
tag=$1
image_sha256=$2
cell=$3
architecture=$4
directory=$5
mkdir -p "$directory/$cell/$architecture" "$directory/objects"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
gh release view "$tag" --repo TerraScale/ts-orchestrator --json assets > "$work/assets.json"
fetch() {
    local name=$1 output=$2 limit=$3
    jq -e --arg name "$name" --argjson limit "$limit" \
        '[.assets[] | select(.name == $name)] | length == 1 and all(.size > 0 and .size <= $limit)' \
        "$work/assets.json" >/dev/null || { echo "retained image evidence unavailable: $name" >&2; return 1; }
    gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern "$name" --output "$output" >/dev/null
    [[ -f $output && ! -L $output && $(stat -c '%s' "$output") -le $limit ]]
}
prefix=image-production-$image_sha256-$cell-$architecture
target=$directory/$cell/$architecture
fetch "$prefix.json" "$target/production.json" 1064960
if jq -e --arg name "$prefix-delegation.json" 'any(.assets[]; .name == $name)' "$work/assets.json" >/dev/null; then
    fetch "$prefix-delegation.json" "$target/delegation.json" 1064960
fi
jq -er '.payload.evidence | select(length == 2) | .[] |
    select((.sha256 | test("^[0-9a-f]{64}$")) and (.bytes > 0 and .bytes <= 67108864)) |
    [.sha256, (.bytes | tostring)] | @tsv' "$target/production.json" > "$work/objects"
[[ $(wc -l < "$work/objects") == 2 ]] || { echo 'image record must retain both gate objects' >&2; exit 1; }
while IFS=$'\t' read -r digest bytes; do
    [[ $digest =~ ^[0-9a-f]{64}$ && $bytes =~ ^[1-9][0-9]*$ ]] || exit 2
    if [[ ! -f $directory/objects/$digest ]]; then
        fetch "image-production-evidence-$digest" "$directory/objects/$digest" "$bytes"
    fi
done < "$work/objects"
