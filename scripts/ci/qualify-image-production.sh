#!/usr/bin/env bash
# Admit the final unsigned QCOW2 before release publication or cloud promotion.
set -euo pipefail
[[ $# == 1 && -d $1 ]] || { echo "usage: $0 IMAGE_DIRECTORY" >&2; exit 2; }
directory=$1
admission=$directory/image-production-admission.jsonl
stage=validate-candidate
finish() {
    local result=$? state=refused error
    error="$stage failed (exit $result); see workflow log"
    if [[ $result == 0 ]]; then state=qualified; error=; fi
    jq -cn --arg source "${SOURCE_SHA:-}" --arg digest "${image_sha256:-}" --arg cell "${cell:-}" \
        --arg state "$state" --arg error "$error" \
        '{schema:"terrascale.release.image-production-admission.v1",source_revision:$source,
          image_sha256:$digest,cell:$cell,architecture:"arm64",environment:"production",state:$state,error:$error}' \
        > "$admission"
    cat "$admission"
}
trap finish EXIT
[[ ${SOURCE_SHA:-} =~ ^[0-9a-f]{40}$ && $(git rev-parse HEAD) == "$SOURCE_SHA" ]] || {
    echo 'image qualification requires the exact checked-out source' >&2; exit 2;
}
export GH_HOST=github.com
manifest=$directory/image-qualification.json
image=$directory/terrascale-gru-arm64.qcow2
image_sha256=$(sha256sum "$image" | awk '{print $1}')
image_bytes=$(stat -c '%s' "$image")
cell=$(jq -er '.region | select(test("^[A-Z]{3}$"))' deploy/image/image-inputs.json)
root=$(jq -er '.trust_roots[0].path' deploy/image/image-inputs.json)
run_id=$(jq -er '.go_candidate.run_id' "$manifest")
run_number=$(jq -er '.go_candidate.run_number' "$manifest")
[[ $run_id =~ ^[1-9][0-9]{0,17}$ && $run_number =~ ^[1-9][0-9]{0,17}$ ]] || exit 2
[[ -z ${SOURCE_CI_RUN_ID:-} || $SOURCE_CI_RUN_ID == "$run_id" ]] || { echo 'image used another binary CI run' >&2; exit 1; }
[[ -z ${SOURCE_CI_RUN_NUMBER:-} || $SOURCE_CI_RUN_NUMBER == "$run_number" ]] || { echo 'image used another binary CI run number' >&2; exit 1; }
jq -e --arg source "$SOURCE_SHA" --arg digest "$image_sha256" --argjson bytes "$image_bytes" --arg cell "$cell" '
    .schema == "terrascale.image.qualification.v2" and .source_revision == $source and
    .image.name == "terrascale-gru-arm64.qcow2" and .image.architecture == "arm64" and
    .image.sha256 == $digest and .image.bytes == $bytes and .inputs.manifest.region == $cell' \
    "$manifest" >/dev/null || { echo 'image candidate differs from its final bytes or target' >&2; exit 1; }
umask 077
work=$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is required}/image-production.XXXXXXXX")
# Preserve evidence and diagnostics for workflow retention and the qualifier.
evidence=$work/image-production
stage=retrieve-binary-qualification
tag=ci-$SOURCE_SHA-run-$run_id
gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern qualification.json \
    --output "$work/qualification.json" >/dev/null
[[ $(sha256sum "$work/qualification.json" | awk '{print $1}') == \
    "$(jq -er '.go_candidate.qualification_sha256' "$manifest")" ]] || {
    echo 'retained binary qualification differs from image build provenance' >&2; exit 1;
}
jq -e --arg source "$SOURCE_SHA" --argjson id "$run_id" --argjson number "$run_number" \
    '.source_revision == $source and .verification.run_id == $id and .verification.run_number == $number' \
    "$work/qualification.json" >/dev/null || { echo 'retained binary qualification names another source or run' >&2; exit 1; }
stage=retrieve-final-image-proof
bash scripts/ci/fetch-image-production-evidence.sh "$tag" "$image_sha256" "$cell" arm64 "$evidence"
stage=build-verifier
go build -trimpath -buildvcs=true -o "$work/ts-orch" ./cmd/terrascale-orchestrator
stage=verify-final-image-proof
"$work/ts-orch" release verify-image-production --image-file "$image" --qualification "$work/qualification.json" \
    --root-key "$root" --cell "$cell" --environment production --arch arm64 \
    --production-evidence-dir "$evidence"
