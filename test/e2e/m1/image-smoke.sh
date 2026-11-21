#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
out=$RUNNER_TEMP/host-image-smoke
image_dir=$IMAGE_DIRECTORY
mkdir -p "$out" "$image_dir"
git -C "$repo" diff --stat "$IMAGE_SOURCE" HEAD -- deploy/image/debian deploy/m1/ts-orch.service 'deploy/m1/services/*.service' > "$out/input-changes.txt"
if [[ ! -e $image_dir/ts-host-debian13-amd64.qcow2 || ! -e $image_dir/ts-host-debian13-amd64.qcow2.sha256 ]]; then
	gh release download "$IMAGE_TAG" --repo "$GITHUB_REPOSITORY" --pattern 'ts-host-debian13-amd64.qcow2*' --dir "$image_dir"
fi
(cd "$image_dir" && sha256sum -c ts-host-debian13-amd64.qcow2.sha256)
python3 "$repo/test/e2e/m1/host-image/run.py" amd64 "$image_dir/ts-host-debian13-amd64.qcow2" "$out/boot"
{
	printf '\nPre-built main image: %s (%s), source %s.\n\n' "$IMAGE_TAG" "$IMAGE_URL" "$IMAGE_SOURCE"
	printf 'Provisioning changes since that image (candidate images are qualified by host-image CI):\n\n'
	cat "$out/input-changes.txt"
} >> "$GITHUB_STEP_SUMMARY"
