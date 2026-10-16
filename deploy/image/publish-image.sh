#!/usr/bin/env bash
# Retain an image built by build-image.sh in CI as the GitHub prerelease
# image-<source>-run-<run id>-attempt-<attempt>.
#
# usage: publish-image.sh DIRECTORY
#
# Uses GH_TOKEN for release publication and readback. The QCOW2, kernel
# and SHA256SUMS are uploaded and read back first; image-qualification.json
# is the completion marker and goes last. The job then logs one
# TS_IMAGE_QUALIFICATION_V1 marker that ts-orch image promote matches after the run
# has succeeded.
set -euo pipefail

directory=${1:-}
[[ -d $directory && $# == 1 ]] || { echo "usage: $0 DIRECTORY" >&2; exit 2; }
repository=TerraScale/ts-orchestrator
manifest="$directory/image-qualification.json"
: "${GH_TOKEN:?GitHub Actions token is required}"
export GH_HOST=github.com
(cd "$directory" && sha256sum --check --strict --quiet SHA256SUMS)

source_sha=$(jq -r .source_revision "$manifest")
jq -e --arg source "$(git rev-parse HEAD)" --argjson run_id "${GITHUB_RUN_ID:?}" \
	--argjson run_number "${GITHUB_RUN_NUMBER:?}" --argjson attempt "${GITHUB_RUN_ATTEMPT:?}" '
	.source_revision == $source and .builder.kind == "ci" and .builder.run_id == $run_id and
	.builder.run_number == $run_number and .builder.run_attempt == $attempt and
	.builder.workflow == "image.yml" and .builder.job == "build/qualified-gru-arm64-image" and
	(.builder.job_id | type == "number" and . > 0)' \
	"$manifest" >/dev/null || { echo 'image manifest was not built by this CI run' >&2; exit 1; }
attempt=$(jq -r .builder.run_attempt "$manifest")
tag="image-${source_sha}-run-${GITHUB_RUN_ID}-attempt-${attempt}"

umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/ts-image-publish.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT

if ! gh release view "$tag" --repo "$repository" --json tagName,assets > "$work/view.json" 2>/dev/null; then
	gh release create "$tag" --repo "$repository" --target "$source_sha" --prerelease --title "$tag" --notes '' >/dev/null
	gh release view "$tag" --repo "$repository" --json tagName,assets > "$work/view.json"
fi
jq -e --arg tag "$tag" '.tagName == $tag' "$work/view.json" >/dev/null || {
	echo 'image release readback differs from its tag' >&2; exit 1;
}
jq -e '.assets | all(.name == "terrascale-gru-arm64.qcow2" or .name == "guest-kernel" or
	.name == "SHA256SUMS" or .name == "image-qualification.json")' "$work/view.json" >/dev/null || {
	echo 'image release contains unexpected asset' >&2; exit 1;
}

retain() {
	local name=$1
	if ! jq -e --arg name "$name" 'any(.assets[]; .name == $name)' "$work/view.json" >/dev/null; then
		gh release upload "$tag" "$directory/$name" --repo "$repository" >/dev/null
	fi
	gh release download "$tag" --repo "$repository" --pattern "$name" --output "$work/$name" >/dev/null
	cmp -s -- "$directory/$name" "$work/$name" || {
		echo "retained image asset differs from this run: $name" >&2
		return 1
	}
	echo "retained $name sha256=$(sha256sum -- "$work/$name" | cut -d ' ' -f 1)"
}
retain terrascale-gru-arm64.qcow2
retain guest-kernel
retain SHA256SUMS
retain image-qualification.json
printf 'TS_IMAGE_QUALIFICATION_V1 source_sha=%s run_id=%s run_number=%s job_id=%s attempt=%s image_sha256=%s kernel_sha256=%s provenance_sha256=%s tag=%s\n' \
	"$source_sha" "$GITHUB_RUN_ID" "$(jq -r .builder.run_number "$manifest")" \
	"$(jq -r .builder.job_id "$manifest")" "$attempt" "$(jq -r .image.sha256 "$manifest")" \
	"$(jq -r .kernel.sha256 "$manifest")" "$(sha256sum -- "$manifest" | cut -d ' ' -f 1)" "$tag"
