#!/usr/bin/env bash
# Fetch retained evidence; only release verify-production grants admission.
set -euo pipefail
[[ $# == 2 && $1 =~ ^ci-[0-9a-f]{40}-run-[1-9][0-9]{0,17}$ ]] || {
    echo "usage: $0 ci-SHA-run-ID candidate-directory" >&2; exit 2;
}
tag=$1
directory=$2/production
mkdir -p "$directory/objects"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
gh release view "$tag" --repo TerraScale/ts-orchestrator --json assets > "$work/assets.json"
# Never construct a path from unvalidated release metadata or envelope fields.
fetch() {
    local name=$1 output=$2 limit=$3
    jq -e --arg name "$name" --argjson limit "$limit" \
        '[.assets[] | select(.name == $name)] | length == 1 and all(.size > 0 and .size <= $limit)' \
        "$work/assets.json" >/dev/null || return 1
    gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern "$name" --output "$output" >/dev/null || return 1
    [[ -f $output && ! -L $output && $(stat -c '%s' "$output") -le $limit ]]
}
jq -r '.assets[].name | select(test("^production-[A-Z]{3}-(amd64|arm64)\\.json$"))' \
    "$work/assets.json" > "$work/records"
while IFS= read -r name; do
    [[ $name =~ ^production-([A-Z]{3})-(amd64|arm64)\.json$ ]] || exit 2
    cell=${BASH_REMATCH[1]}
    architecture=${BASH_REMATCH[2]}
    target=$directory/$cell/$architecture
    mkdir -p "$target"
    if ! fetch "$name" "$target/production.json" 1064960; then
        echo "$cell $architecture: retained production record unavailable" >&2
        continue
    fi
    delegation=production-$cell-$architecture-delegation.json
    if jq -e --arg name "$delegation" 'any(.assets[]; .name == $name)' "$work/assets.json" >/dev/null; then
        if ! fetch "$delegation" "$target/delegation.json" 1064960; then
            # An advertised but unavailable delegation must never become root-signed admission.
            printf '{}\n' > "$target/delegation.json"
        fi
    fi
    if ! jq -er '.payload.evidence | select(length == 2) | .[] |
        select((.sha256 | test("^[0-9a-f]{64}$")) and (.bytes > 0 and .bytes <= 67108864)) |
        [.sha256, (.bytes | tostring)] | @tsv' "$target/production.json" > "$work/objects"; then
        echo "$cell $architecture: malformed retained evidence references" >&2
        continue
    fi
    while IFS=$'\t' read -r digest bytes; do
        [[ $digest =~ ^[0-9a-f]{64}$ && $bytes =~ ^[1-9][0-9]*$ ]] || continue
        object=$directory/objects/$digest
        if [[ ! -f $object ]]; then
            if ! fetch "production-evidence-$digest" "$object" "$bytes"; then
                rm -f -- "$object"
                echo "$cell $architecture: retained evidence $digest unavailable" >&2
            fi
        fi
    done < "$work/objects"
done < "$work/records"
