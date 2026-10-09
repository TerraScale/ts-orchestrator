#!/usr/bin/env bash
# Deploy one CI-qualified main revision to every serving region, the
# concurrently, with ts-orch release deploy (docs/deploy-pipeline.md).
#
# usage: deploy-fleet.sh FORGEJO_PROFILES
#
# FORGEJO_PROFILES is the directory configure-fj-profiles.sh created. Inputs:
#   SOURCE_SHA, SOURCE_CI_RUN_ID   the revision and its successful ci.yml run
#   TS_OBJECT_NAMESPACE            Object Storage namespace of the head buckets
#   TS_RELEASE_VAULT_ID            OCI Vault holding the update leaf key
#   TS_RELEASE_LEAF_SECRET         the leaf key's secret name
#   TS_RELEASE_UPDATE_DELEGATION   the root-signed binary update delegation
#   TS_DEPLOY_OCI_USER, TS_DEPLOY_OCI_TENANCY, TS_DEPLOY_OCI_FINGERPRINT and
#   TS_DEPLOY_OCI_KEY              the deployment's scoped OCI API key
set -euo pipefail

profiles=${1:-}
[[ -d $profiles && $# == 1 ]] || { echo "usage: $0 FORGEJO_PROFILES" >&2; exit 2; }
[[ ${SOURCE_SHA:-} =~ ^[0-9a-f]{40}$ && ${SOURCE_CI_RUN_ID:-} =~ ^[1-9][0-9]{0,17}$ ]] || {
	echo 'SOURCE_SHA and SOURCE_CI_RUN_ID must name the qualified run' >&2
	exit 2
}
for variable in TS_OBJECT_NAMESPACE TS_RELEASE_VAULT_ID TS_RELEASE_LEAF_SECRET \
	TS_RELEASE_UPDATE_DELEGATION TS_DEPLOY_OCI_USER TS_DEPLOY_OCI_TENANCY TS_DEPLOY_OCI_FINGERPRINT \
	TS_DEPLOY_OCI_KEY FORGEJO_SERVER_URL; do
	[[ -n ${!variable:-} ]] || { echo "$variable is required" >&2; exit 2; }
done
[[ $(git rev-parse HEAD) == "$SOURCE_SHA" ]] || { echo 'checked-out source differs from the deployed revision' >&2; exit 1; }
# Verified serving inventory: both cells use ARM64 and the canary trust scope.
# Region discovery will replace these constants in the shared TS-768 contract.
cells=(GRU SFO)
architectures=(arm64)

umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/deploy-fleet.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/release" "$work/oci"

# The key's group may only read the leaf secret and write releases/* in
# the head buckets; the region of each call is set by ts-orch.
printf '%s\n' "$TS_DEPLOY_OCI_KEY" > "$work/oci/key.pem"
unset TS_DEPLOY_OCI_KEY
printf '[DEFAULT]\nuser=%s\nfingerprint=%s\ntenancy=%s\nregion=sa-saopaulo-1\nkey_file=%s\n' \
	"$TS_DEPLOY_OCI_USER" "$TS_DEPLOY_OCI_FINGERPRINT" "$TS_DEPLOY_OCI_TENANCY" "$work/oci/key.pem" > "$work/oci/config"
export OCI_CONFIG_FILE=$work/oci/config
# The delegation is a canonical trust envelope: write its exact bytes.
printf '%s' "$TS_RELEASE_UPDATE_DELEGATION" > "$work/update-delegation.json"

tag="ci-${SOURCE_SHA}-run-${SOURCE_CI_RUN_ID}"
args=()
for asset in qualification.json "${architectures[@]/#/terrascale-orchestrator-linux-}"; do
	XDG_DATA_HOME="$profiles/read" fj release asset download -r TerraScale/ts-orchestrator "$tag" "$asset" \
		-o "$work/release/$asset" >/dev/null
done
for architecture in "${architectures[@]}"; do args+=(--arch "$architecture"); done
for cell in "${cells[@]}"; do args+=(--cell "$cell"); done
root_key=$(jq -er '.trust_roots[0].path' deploy/image/image-inputs.json)

make build GO=go
# The lineage proof fetches main with the read token for this process only;
# nothing is written to .git/config.
read_token=$(<"$profiles/read-token")
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="http.$FORGEJO_SERVER_URL/.extraheader" \
	GIT_CONFIG_VALUE_0="Authorization: token $read_token"
XDG_DATA_HOME="$profiles/read" dist/ts-orch release deploy --dir "$work/release" --source-revision "$SOURCE_SHA" \
	--update-delegation "$work/update-delegation.json" --root-key "$root_key" \
	--signing-key-secret "$TS_RELEASE_LEAF_SECRET" --vault-id "$TS_RELEASE_VAULT_ID" \
	--environment canary --source-checkout . \
	--namespace "$TS_OBJECT_NAMESPACE" --region-timeout 30m --poll 5s "${args[@]}"
