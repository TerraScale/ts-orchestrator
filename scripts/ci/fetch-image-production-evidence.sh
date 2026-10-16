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
fetch "$prefix.json" "$work/production.json" 1064960
if jq -e --arg name "$prefix-delegation.json" 'any(.assets[]; .name == $name)' "$work/assets.json" >/dev/null; then
    fetch "$prefix-delegation.json" "$work/delegation.json" 1064960
fi
jq -er '.payload.evidence | select(length == 2) | .[] |
    select((.sha256 | test("^[0-9a-f]{64}$")) and (.bytes > 0 and .bytes <= 67108864)) |
    [.sha256, (.bytes | tostring)] | @tsv' "$work/production.json" > "$work/objects"
[[ $(wc -l < "$work/objects") == 2 ]] || { echo 'image record must retain both gate objects' >&2; exit 1; }
while IFS=$'\t' read -r digest bytes; do
    [[ $digest =~ ^[0-9a-f]{64}$ && $bytes =~ ^[1-9][0-9]*$ ]] || exit 2
    object=$directory/objects/$digest
    if [[ -f $object && ! -L $object && $(stat -c '%s' "$object") == "$bytes" &&
        $(sha256sum "$object" | awk '{print $1}') == "$digest" ]]; then
        continue
    fi
    fetch "image-production-evidence-$digest" "$work/$digest" "$bytes"
    [[ $(stat -c '%s' "$work/$digest") == "$bytes" &&
        $(sha256sum "$work/$digest" | awk '{print $1}') == "$digest" ]] || {
        echo "retained image evidence bytes differ: $digest" >&2; exit 1;
    }
    mv -f -- "$work/$digest" "$object"
done < "$work/objects"
if [[ -f $work/delegation.json ]]; then
    mv -f -- "$work/delegation.json" "$target/delegation.json"
else
    rm -f -- "$target/delegation.json"
fi
# Consumers use this completion marker to resume without another provider call.
mv -f -- "$work/production.json" "$target/production.json"
