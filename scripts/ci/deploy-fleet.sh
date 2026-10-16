#!/usr/bin/env bash
# Deploy one CI-qualified main revision to every serving region, the
# concurrently, with ts-orch release deploy (docs/deploy-pipeline.md).
#
# usage: deploy-fleet.sh
#
# Inputs:
#   SOURCE_SHA, SOURCE_CI_RUN_ID   the revision and its successful ci.yml run
#   TS_OBJECT_NAMESPACE            Object Storage namespace of the head buckets
#   TS_RELEASE_VAULT_ID            OCI Vault holding the update leaf key and the
#                                  root-signed release delegation (release-delegation)
#   TS_RELEASE_LEAF_SECRET         the leaf key's secret name
#   TS_DEPLOY_OCI_USER, TS_DEPLOY_OCI_TENANCY, TS_DEPLOY_OCI_FINGERPRINT and
#   TS_DEPLOY_OCI_KEY              the deployment's scoped OCI API key
set -euo pipefail

export GH_HOST=github.com
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
[[ ${SOURCE_SHA:-} =~ ^[0-9a-f]{40}$ && ${SOURCE_CI_RUN_ID:-} =~ ^[1-9][0-9]{0,17}$ ]] || {
	echo 'SOURCE_SHA and SOURCE_CI_RUN_ID must name the qualified run' >&2
	exit 2
}
for variable in TS_OBJECT_NAMESPACE TS_RELEASE_VAULT_ID TS_RELEASE_LEAF_SECRET TS_DEPLOY_OCI_USER TS_DEPLOY_OCI_TENANCY TS_DEPLOY_OCI_FINGERPRINT \
	TS_DEPLOY_OCI_KEY; do
	[[ -n ${!variable:-} ]] || { echo "$variable is required" >&2; exit 2; }
done
[[ $(git rev-parse HEAD) == "$SOURCE_SHA" ]] || { echo 'checked-out source differs from the deployed revision' >&2; exit 1; }
umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/deploy-fleet.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/release" "$work/oci"

# The key's group may only read the leaf and release-delegation secrets and
# write releases/orchestrator/* in every *-head bucket; the region of each
# call is set by ts-orch.
printf '%s\n' "$TS_DEPLOY_OCI_KEY" > "$work/oci/key.pem"
unset TS_DEPLOY_OCI_KEY
printf '[DEFAULT]\nuser=%s\nfingerprint=%s\ntenancy=%s\nregion=sa-saopaulo-1\nkey_file=%s\n' \
	"$TS_DEPLOY_OCI_USER" "$TS_DEPLOY_OCI_FINGERPRINT" "$TS_DEPLOY_OCI_TENANCY" "$work/oci/key.pem" > "$work/oci/config"
export OCI_CONFIG_FILE=$work/oci/config

tag="ci-${SOURCE_SHA}-run-${SOURCE_CI_RUN_ID}"
gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern qualification.json \
	--output "$work/release/qualification.json" >/dev/null
assets=$(jq -er '.artifacts[].name' "$work/release/qualification.json")
while IFS= read -r asset; do
	[[ $asset =~ ^terrascale-orchestrator-linux-(amd64|arm64)$ ]] || { echo 'invalid qualified binary name' >&2; exit 2; }
	gh release download "$tag" --repo TerraScale/ts-orchestrator --pattern "$asset" \
		--output "$work/release/$asset" >/dev/null
done <<< "$assets"
root_key=$(jq -er '.trust_roots[0].path' deploy/image/image-inputs.json)

make build GO=go
# GitHub CLI supplies credentials to git without writing token files.
gh auth setup-git --hostname github.com
# The root re-signs the release-delegation Vault secret at least every 31 days.
dist/ts-orch release deploy --dir "$work/release" --source-revision "$SOURCE_SHA" \
	--update-delegation-secret release-delegation --root-key "$root_key" \
	--signing-key-secret "$TS_RELEASE_LEAF_SECRET" --vault-id "$TS_RELEASE_VAULT_ID" \
	--source-checkout . \
	--namespace "$TS_OBJECT_NAMESPACE" --poll 5s
