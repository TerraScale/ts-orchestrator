#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"

for tool in gh jq sha256sum stat; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
[[ ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ ]] || { echo 'GitHub run ID is required' >&2; exit 1; }
[[ ${GITHUB_RUN_NUMBER:-} =~ ^[0-9]+$ ]] || { echo 'GitHub run number is required' >&2; exit 1; }
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'GitHub source SHA is required' >&2; exit 1; }
: "${GH_TOKEN:?GitHub Actions token is required}"
export GH_HOST=github.com
repository=TerraScale/ts-orchestrator
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]] || { echo 'checked-out source differs from the run' >&2; exit 1; }

source_tree=$(git rev-parse 'HEAD^{tree}')
go_version=$(go env GOVERSION)
go_mod_sha256=$(sha256sum go.mod | awk '{print $1}')
go_sum_sha256=$(sha256sum go.sum | awk '{print $1}')
probe_name=terrascale-d15-qualify
probe_source=dist/terrascale-orchestrator-linux-arm64
probe_path="dist/$probe_name"
[[ -s $probe_source && ! -L $probe_source ]] || { echo 'D15 probe source is missing or unsafe' >&2; exit 1; }
cp -- "$probe_source" "$probe_path"
chmod 0644 "$probe_path"
cmp -- "$probe_source" "$probe_path"
probe_bytes=$(stat -c '%s' "$probe_path")
probe_sha256=$(sha256sum "$probe_path" | awk '{print $1}')
[[ $probe_bytes -gt 0 && $probe_bytes -le 536870912 ]] || { echo 'D15 probe exceeds its bound' >&2; exit 1; }
artifacts='[]'
for architecture in amd64 arm64; do
    name="terrascale-orchestrator-linux-${architecture}"
    path="dist/${name}"
    [[ -s $path ]] || { echo "missing artifact: $path" >&2; exit 1; }
    bytes=$(stat -c '%s' "$path")
    sha256=$(sha256sum "$path" | awk '{print $1}')
    artifacts=$(jq -cnS --argjson previous "$artifacts" --arg architecture "$architecture" \
        --arg name "$name" --argjson bytes "$bytes" --arg sha256 "$sha256" \
        '$previous + [{architecture:$architecture,name:$name,bytes:$bytes,sha256:$sha256}]')
done

jq -cnS \
    --arg schema 'terrascale.d15.probe-publication/v1' \
    --arg repository 'TerraScale/ts-orchestrator' \
    --arg source_revision "$GITHUB_SHA" --arg source_tree "$source_tree" \
    --argjson run_id "$GITHUB_RUN_ID" --argjson run_number "$GITHUB_RUN_NUMBER" \
    --arg name "$probe_name" --argjson bytes "$probe_bytes" --arg sha256 "$probe_sha256" \
    '{schema:$schema,repository:$repository,source_revision:$source_revision,
      source_tree:$source_tree,
      verification:{workflow:"ci.yml",job:"verify/go + artifact/linux-amd64-arm64",
        run_id:$run_id,run_number:$run_number},
      probe:{name:$name,bytes:$bytes,sha256:$sha256}}' \
    > dist/terrascale-d15-probe.json

jq -cnS \
    --arg schema 'terrascale.release.qualification.v1' \
    --arg repository 'TerraScale/ts-orchestrator' \
    --arg source_revision "$GITHUB_SHA" --arg source_tree "$source_tree" \
    --arg go_version "$go_version" --arg go_mod_sha256 "$go_mod_sha256" \
    --arg go_sum_sha256 "$go_sum_sha256" \
    --argjson run_id "$GITHUB_RUN_ID" --argjson run_number "$GITHUB_RUN_NUMBER" \
    --argjson artifacts "$artifacts" \
    '{schema:$schema,repository:$repository,source_revision:$source_revision,
      source_tree:$source_tree,go_version:$go_version,go_mod_sha256:$go_mod_sha256,
      go_sum_sha256:$go_sum_sha256,
      verification:{workflow:"ci.yml",job:"verify/go + artifact/linux-amd64-arm64",
        run_id:$run_id,run_number:$run_number,conclusion:"success"},artifacts:$artifacts}' \
    > dist/qualification.json

umask 077
work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT

tag="ci-${GITHUB_SHA}-run-${GITHUB_RUN_ID}"
if ! gh release view "$tag" --repo "$repository" --json tagName,isDraft,isPrerelease,assets > "$work/view.json" 2>/dev/null; then
    gh release create "$tag" --repo "$repository" --target "$GITHUB_SHA" --prerelease \
        --title "$tag" --notes ''
    gh release view "$tag" --repo "$repository" --json tagName,isDraft,isPrerelease,assets > "$work/view.json"
fi
jq -e --arg tag "$tag" '.tagName == $tag and .isDraft == false and .isPrerelease == true and
    (.assets | all(.name == "terrascale-orchestrator-linux-amd64" or
      .name == "terrascale-orchestrator-linux-arm64" or .name == "terrascale-d15-qualify" or
      .name == "terrascale-d15-probe.json" or .name == "qualification.json" or
      (.name | test("^production-[A-Z]{3}-(amd64|arm64)(-delegation)?\\.json$")) or
      (.name | test("^production-evidence-[0-9a-f]{64}$"))))' "$work/view.json" >/dev/null || {
    echo 'retained release has an unexpected tag, state or asset' >&2; exit 1;
}
[[ $(gh api "repos/$repository/commits/$tag" --jq .sha) == "$GITHUB_SHA" ]] || {
    echo 'retained release tag points to a different source revision' >&2; exit 1;
}
mkdir -m 0700 "$work/readback"
retain() {
    local name=$1 delay matched attempt readback
    if ! jq -e --arg name "$name" 'any(.assets[]; .name == $name)' "$work/view.json" >/dev/null; then
        gh release upload "$tag" "dist/$name" --repo "$repository"
    fi
    delay=1
    matched=false
    for attempt in 1 2 3 4 5 6; do
        readback="$work/readback/$name.$attempt"
        if gh release download "$tag" --repo "$repository" --pattern "$name" --output "$readback" &&
            cmp -- "dist/$name" "$readback"; then
            matched=true
            break
        fi
        if [[ -f $readback ]]; then
            printf 'D15 release asset readback mismatch name=%s attempt=%s bytes=%s sha256=%s\n' \
                "$name" "$attempt" "$(stat -c '%s' "$readback")" \
                "$(sha256sum "$readback" | awk '{print $1}')" >&2
        fi
        if [[ $attempt == 6 ]]; then
            break
        fi
        sleep "$delay"
        delay=$((delay * 2))
    done
    [[ $matched == true ]] || { echo "D15 release asset readback never matched: $name" >&2; exit 1; }
}
retain terrascale-orchestrator-linux-amd64
retain terrascale-orchestrator-linux-arm64
retain "$probe_name"
retain terrascale-d15-probe.json
# The manifest is the completion marker. A partial upload cannot be admitted.
retain qualification.json
printf 'TS_D15_PROBE_PUBLICATION_V1 source_sha=%s run_id=%s run_number=%s probe_sha256=%s descriptor_sha256=%s\n' \
    "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_NUMBER" "$probe_sha256" \
    "$(sha256sum dist/terrascale-d15-probe.json | awk '{print $1}')"
printf 'TS_RELEASE_QUALIFICATION_V1 source_sha=%s run_id=%s run_number=%s manifest_sha256=%s\n' \
    "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_NUMBER" \
    "$(sha256sum dist/qualification.json | awk '{print $1}')"
