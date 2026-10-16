#!/usr/bin/env bash
# Admission runs without OCI credentials. The deploy stage rechecks signed evidence.
# usage: deploy-fleet.sh qualify|deploy
set -euo pipefail
export GH_HOST=github.com
[[ $# == 1 && ($1 == qualify || $1 == deploy) ]] || { echo "usage: $0 qualify|deploy" >&2; exit 2; }
[[ ${SOURCE_SHA:-} =~ ^[0-9a-f]{40}$ && ${SOURCE_CI_RUN_ID:-} =~ ^[1-9][0-9]{0,17}$ ]] || {
    echo 'SOURCE_SHA and SOURCE_CI_RUN_ID must name the qualified run' >&2; exit 2;
}
[[ $(git rev-parse HEAD) == "$SOURCE_SHA" ]] || { echo 'checked-out source differs from the deployed revision' >&2; exit 1; }
umask 077
work=${RUNNER_TEMP:?RUNNER_TEMP is required}/production-$SOURCE_SHA-run-$SOURCE_CI_RUN_ID
root_key=$(jq -er '.trust_roots[0].path' deploy/image/image-inputs.json)
if [[ $1 == qualify ]]; then
    # A fresh admission directory cannot inherit previously qualified cells.
    [[ ! -e $work ]] || { echo 'admission directory already exists' >&2; exit 1; }
    mkdir -m 0700 "$work"
    mkdir "$work/release"
    tag=ci-$SOURCE_SHA-run-$SOURCE_CI_RUN_ID
    gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern qualification.json \
        --output "$work/release/qualification.json" >/dev/null
    for architecture in amd64 arm64; do
        asset=terrascale-orchestrator-linux-$architecture
        gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern "$asset" \
            --output "$work/release/$asset" >/dev/null
    done
    bash scripts/ci/fetch-production-evidence.sh "$tag" "$work/release"
    make build GO=go
    # verify-production emits every serving region even when one is refused.
    admission_status=0
    dist/ts-orch release verify-production --dir "$work/release" --root-key "$root_key" \
        > "$work/production-admission.jsonl" || admission_status=$?
    cat "$work/production-admission.jsonl"
    jq -ers --arg source "$SOURCE_SHA" 'length > 0 and all(
        .schema == "terrascale.release.production-admission.v1" and .source_revision == $source and
        (.cell | test("^[A-Z]{3}$")) and (.state == "qualified" or .state == "refused")) and
        any(.state == "qualified")' "$work/production-admission.jsonl" >/dev/null || {
        echo "no serving region has exact retained production qualification (verifier exit $admission_status)" >&2; exit 1;
    }
    sha256sum "$work/release/qualification.json" > "$work/qualification.sha256"
    exit 0
fi

[[ -f $work/qualification.sha256 && ! -L $work/qualification.sha256 ]] || { echo 'credential-free admission must complete first' >&2; exit 1; }
sha256sum --check --status "$work/qualification.sha256"
mapfile -t cells < <(jq -er 'select(.state == "qualified") | .cell' "$work/production-admission.jsonl")
((${#cells[@]})) || { echo 'no admitted regions' >&2; exit 1; }
arguments=()
for cell in "${cells[@]}"; do
    [[ $cell =~ ^[A-Z]{3}$ ]] || exit 2
    arguments+=(--cell "$cell")
done
# Recheck immediately before reading deployment credentials; deploy also checks
# the evidence for the complete rollout deadline before loading signing keys.
dist/ts-orch release verify-production --dir "$work/release" --root-key "$root_key" "${arguments[@]}"
for variable in TS_OBJECT_NAMESPACE TS_RELEASE_VAULT_ID TS_RELEASE_LEAF_SECRET TS_DEPLOY_OCI_USER \
    TS_DEPLOY_OCI_TENANCY TS_DEPLOY_OCI_FINGERPRINT TS_DEPLOY_OCI_KEY; do
    [[ -n ${!variable:-} ]] || { echo "$variable is required" >&2; exit 2; }
done
mkdir -m 0700 "$work/oci"
trap 'rm -rf -- "$work/oci"' EXIT
printf '%s\n' "$TS_DEPLOY_OCI_KEY" > "$work/oci/key.pem"
unset TS_DEPLOY_OCI_KEY
printf '[DEFAULT]\nuser=%s\nfingerprint=%s\ntenancy=%s\nregion=sa-saopaulo-1\nkey_file=%s\n' \
    "$TS_DEPLOY_OCI_USER" "$TS_DEPLOY_OCI_FINGERPRINT" "$TS_DEPLOY_OCI_TENANCY" "$work/oci/key.pem" > "$work/oci/config"
export OCI_CONFIG_FILE=$work/oci/config
gh auth setup-git --hostname github.com
deploy_status=0
dist/ts-orch release deploy --dir "$work/release" --source-revision "$SOURCE_SHA" \
    --update-delegation-secret release-delegation --root-key "$root_key" \
    --signing-key-secret "$TS_RELEASE_LEAF_SECRET" --vault-id "$TS_RELEASE_VAULT_ID" \
    --source-checkout . --namespace "$TS_OBJECT_NAMESPACE" --poll 5s "${arguments[@]}" || deploy_status=$?
if jq -es 'any(.state == "refused")' "$work/production-admission.jsonl" >/dev/null; then
    echo 'fleet incomplete: qualified regions finished; refused regions were not deployed' >&2
    exit 1
fi
exit "$deploy_status"
