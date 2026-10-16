#!/usr/bin/env bash
# Retain already signed qualification from an authorized disposable-target run.
# This command never creates a qualification statement or loads a signing key.
set -euo pipefail
[[ $# -ge 3 ]] || { echo "usage: $0 candidate-directory root-public-key CELL [CELL ...]" >&2; exit 2; }
directory=$1
root=$2
shift 2
source_revision=$(jq -er '.source_revision' "$directory/qualification.json")
run_id=$(jq -er '.verification.run_id' "$directory/qualification.json")
[[ $source_revision =~ ^[0-9a-f]{40}$ && $run_id =~ ^[1-9][0-9]{0,17}$ ]] || exit 2
tag=ci-$source_revision-run-$run_id
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
arguments=()
for cell in "$@"; do
    [[ $cell =~ ^[A-Z]{3}$ ]] || exit 2
    arguments+=(--cell "$cell")
done
# Admission binds both exact binary digests, build manifest, scope and evidence.
dist/ts-orch release verify-production --dir "$directory" --root-key "$root" "${arguments[@]}"
gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern qualification.json --output "$work/qualification.json" >/dev/null
cmp -- "$directory/qualification.json" "$work/qualification.json"
gh release view "$tag" --repo TerraScale/ts-orchestrator --json assets > "$work/assets.json"
retain() {
    local name=$1 path=$2
    if [[ ! -e $work/$name ]] && ! jq -e --arg name "$name" 'any(.assets[]; .name == $name)' "$work/assets.json" >/dev/null; then
        cp -- "$path" "$work/$name"
        gh release upload "$tag" "$work/$name" --repo TerraScale/ts-orchestrator
    fi
    gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern "$name" --output "$work/readback" >/dev/null
    cmp -- "$path" "$work/readback"
    rm -- "$work/readback"
}
for cell in "$@"; do
    for architecture in amd64 arm64; do
        record=$directory/production/$cell/$architecture/production.json
        jq -er '.payload.evidence[].sha256 | select(test("^[0-9a-f]{64}$"))' "$record" > "$work/digests"
        while IFS= read -r digest; do
            retain "production-evidence-$digest" "$directory/production/objects/$digest"
        done < "$work/digests"
        delegation=$directory/production/$cell/$architecture/delegation.json
        if [[ -f $delegation ]]; then
            retain "production-$cell-$architecture-delegation.json" "$delegation"
        fi
        # Signed records are completion markers, after evidence object readback.
        retain "production-$cell-$architecture.json" "$record"
    done
done
