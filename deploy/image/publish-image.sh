#!/usr/bin/env bash
# Retain an image built by build-image.sh in CI as the Forgejo prerelease
# image-<source>-run-<run id>-attempt-<attempt>.
#
# usage: publish-image.sh DIRECTORY
#
# Uses fj with write authentication for the release and a separate read
# profile (XDG_DATA_HOME of FJ_READ_PROFILE) for readback. The QCOW2, kernel
# and SHA256SUMS are uploaded and read back first; image-qualification.json
# is the completion marker and goes last. The job then logs one
# TS_IMAGE_QUALIFICATION_V1 marker that ts-orch image promote matches after the run
# has succeeded.
set -euo pipefail

directory=${1:-}
[[ -d $directory && $# == 1 ]] || { echo "usage: $0 DIRECTORY" >&2; exit 2; }
repository=TerraScale/ts-orchestrator
manifest="$directory/image-qualification.json"
[[ -d ${FJ_READ_PROFILE:-} ]] || { echo 'FJ_READ_PROFILE must name the read-only fj profile' >&2; exit 2; }
(cd "$directory" && sha256sum --check --strict --quiet SHA256SUMS)

source_sha=$(jq -r .source_revision "$manifest")
jq -e --argjson run_id "${GITHUB_RUN_ID:?}" '.builder.kind == "ci" and .builder.run_id == $run_id' \
	"$manifest" >/dev/null || { echo 'image manifest was not built by this CI run' >&2; exit 1; }
attempt=$(jq -r .builder.run_attempt "$manifest")
tag="image-${source_sha}-run-${GITHUB_RUN_ID}-attempt-${attempt}"

umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/ts-image-publish.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
fj_read() { XDG_DATA_HOME="$FJ_READ_PROFILE" fj "$@"; }

if ! fj_read release view --repo "$repository" --by-tag "$tag" > "$work/view.txt" 2>/dev/null; then
	fj release create -r "$repository" "$tag" --create-tag="$tag" --branch "$source_sha" --prerelease >/dev/null
	fj_read release view --repo "$repository" --by-tag "$tag" > "$work/view.txt"
fi
grep -Fq "$tag" "$work/view.txt" || { echo 'image release readback differs from its tag' >&2; exit 1; }
while IFS= read -r listed; do
	case $listed in
		'- terrascale-gru-arm64.qcow2'|'- guest-kernel'|'- SHA256SUMS'|'- image-qualification.json'|'- source.zip'|'- source.tar.gz') ;;
		*) echo "image release contains unexpected asset: $listed" >&2; exit 1 ;;
	esac
done < <(grep '^- ' "$work/view.txt" || true)

retain() {
	local name=$1
	if ! grep -Fqx -- "- $name" "$work/view.txt"; then
		fj release asset create -r "$repository" "$tag" "$directory/$name" >/dev/null
	fi
	fj_read release asset download -r "$repository" "$tag" "$name" -o "$work/$name" >/dev/null
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
