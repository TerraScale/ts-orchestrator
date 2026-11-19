#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
out=${RUNNER_TEMP:?}/host-image-smoke
mkdir -p "$out/image"
record=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/host-image.yml/runs?branch=main&status=success&event=push&per_page=1" \
	--jq '.workflow_runs[0] | [.id, .head_sha, .html_url] | @tsv')
read -r run source url <<< "$record"
[[ $run =~ ^[0-9]+$ && $source =~ ^[0-9a-f]{40}$ ]]
git -C "$repo" diff --stat "$source" HEAD -- deploy/image/debian deploy/m1/ts-orch.service 'deploy/m1/services/*.service' > "$out/input-changes.txt"
releases=$(gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
	--jq ".[] | select(.target_commitish == \"$source\" and (.tag_name | startswith(\"host-image-\"))) | .tag_name")
read -r tag <<< "$releases"
[[ $tag == host-image-* ]]
gh release download "$tag" --repo "$GITHUB_REPOSITORY" --pattern 'ts-host-debian13-amd64.qcow2*' --dir "$out/image"
(cd "$out/image" && sha256sum -c ts-host-debian13-amd64.qcow2.sha256)
python3 "$repo/test/e2e/m1/host-image/run.py" amd64 "$out/image/ts-host-debian13-amd64.qcow2" "$out/boot"
{
	printf '\nPre-built main image: %s (%s), source %s.\n\n' "$tag" "$url" "$source"
	printf 'Provisioning changes since that image (candidate images are qualified by host-image CI):\n\n'
	cat "$out/input-changes.txt"
} >> "$GITHUB_STEP_SUMMARY"
