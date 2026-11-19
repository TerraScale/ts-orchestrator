#!/usr/bin/env bash
set -euo pipefail

repo=$GITHUB_REPOSITORY
tag=$(gh api "repos/$repo/releases?per_page=100" --jq '
  [.[] | select(.draft == false)
   | select(.tag_name | test("^ci-[0-9a-f]{40}-run-[1-9][0-9]*$"))
   | select(any(.assets[]; .name == "terrascale-orchestrator-linux-amd64"))
   | select(any(.assets[]; .name == "terrascale-orchestrator-linux-arm64"))
   | select(any(.assets[]; .name == "provenance.sigstore.json"))][0].tag_name // empty')
[[ -n $tag ]] || { echo 'No published CI release has both binaries and signed provenance' >&2; exit 1; }
source=${tag#ci-}
source=${source%-run-*}
minimum=$(gh api "repos/$repo/pulls/477" --jq 'select(.merged == true) | .merge_commit_sha')
[[ $minimum =~ ^[0-9a-f]{40}$ ]] || { echo 'PR #477 must merge before building host images with its image-release marker contract' >&2; exit 1; }
[[ $(gh api "repos/$repo/commits/$tag" --jq .sha) == "$source" ]] || { echo 'CI release tag does not match its source revision' >&2; exit 1; }
git fetch origin "$source" "$minimum"
git merge-base --is-ancestor "$minimum" "$source" || { echo 'The selected CI release does not include PR #477' >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$tag" --repo "$repo" --dir "$work" \
	--pattern terrascale-orchestrator-linux-amd64 \
	--pattern terrascale-orchestrator-linux-arm64 \
	--pattern provenance.sigstore.json
for arch in amd64 arm64; do
	binary="$work/terrascale-orchestrator-linux-$arch"
	gh attestation verify "$binary" --repo "$repo" \
		--bundle "$work/provenance.sigstore.json" \
		--signer-workflow "$repo/.github/workflows/ci.yml" \
		--source-ref refs/heads/main --source-digest "$source" \
		--deny-self-hosted-runners --format json > "$work/$arch.attestation.json"
	jq -e 'type == "array" and length > 0' "$work/$arch.attestation.json" >/dev/null
	printf '%s=%s\n' "$arch" "$(sha256sum "$binary" | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
done
printf 'tag=%s\n' "$tag" >> "$GITHUB_OUTPUT"
