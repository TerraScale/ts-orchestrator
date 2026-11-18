#!/usr/bin/env bash
set -euo pipefail
: "${DOCKER_CONFIG:?}" "${REPOSITORY:?}" "${DIGEST:?}" "${BUILD_BUNDLE:?}" "${SBOM_BUNDLE:?}"
media=application/vnd.dev.sigstore.bundle.v0.3+json
cp "$BUILD_BUNDLE" "$RUNNER_TEMP/build.sigstore.json"
cp "$SBOM_BUNDLE" "$RUNNER_TEMP/sbom.sigstore.json"
cd "$RUNNER_TEMP"
for region do
  repo="$region.ocir.io/$REPOSITORY"
  printf 'Copy scope: %s (pull,push)\n' "$repo"
  oras cp --from-oci-layout "$RUNNER_TEMP/app-canary-layout:arm64" "$repo@$DIGEST"
  test "$(oras resolve "$repo@$DIGEST")" = "$DIGEST"
  for bundle in build.sigstore.json selection.sigstore.json sbom.sigstore.json; do
    oras attach --distribution-spec v1.1-referrers-tag --artifact-type "$media" "$repo@$DIGEST" "$bundle:$media"
  done
  oras discover --distribution-spec v1.1-referrers-tag --artifact-type "$media" --format json "$repo@$DIGEST" |
    jq -e '.referrers | length >= 3'
  "$GITHUB_WORKSPACE/dist/terrascale-orchestrator-linux-amd64" release verify-provenance \
    --image "$repo@$DIGEST" \
    --workflow TerraScale/ts-orchestrator/.github/workflows/app-canary.yml@refs/heads/main \
    --revision "$GITHUB_SHA"
done
