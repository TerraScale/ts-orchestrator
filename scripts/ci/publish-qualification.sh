#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"

for tool in fj jq sha256sum stat; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
[[ ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ ]] || { echo 'Forgejo run ID is required' >&2; exit 1; }
[[ ${GITHUB_RUN_NUMBER:-} =~ ^[0-9]+$ ]] || { echo 'Forgejo run number is required' >&2; exit 1; }
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'Forgejo source SHA is required' >&2; exit 1; }
: "${FORGEJO_TOKEN:?Forgejo Actions token is required}"
: "${FORGEJO_SERVER_URL:?Forgejo server URL is required}"
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]] || { echo 'checked-out source differs from the run' >&2; exit 1; }

source_tree=$(git rev-parse 'HEAD^{tree}')
go_version=$(go env GOVERSION)
go_mod_sha256=$(sha256sum go.mod | awk '{print $1}')
go_sum_sha256=$(sha256sum go.sum | awk '{print $1}')
probe_name=terrascale-d15-qualify.py
probe_source=tests/runtime_priority/qualify.py
probe_path="dist/$probe_name"
[[ -s $probe_source && ! -L $probe_source ]] || { echo 'D15 probe source is missing or unsafe' >&2; exit 1; }
cp -- "$probe_source" "$probe_path"
chmod 0644 "$probe_path"
cmp -- "$probe_source" "$probe_path"
probe_bytes=$(stat -c '%s' "$probe_path")
probe_sha256=$(sha256sum "$probe_path" | awk '{print $1}')
[[ $probe_bytes -gt 0 && $probe_bytes -le 262144 ]] || { echo 'D15 probe exceeds its bound' >&2; exit 1; }
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

auth_home=$(mktemp -d)
chmod 700 "$auth_home"
trap 'find "$auth_home" -depth -delete' EXIT
export XDG_DATA_HOME="$auth_home"
printf '%s\n' "$FORGEJO_TOKEN" | fj auth add-token --host "$FORGEJO_SERVER_URL" >/dev/null
unset FORGEJO_TOKEN GITHUB_TOKEN

tag="ci-${GITHUB_SHA}-run-${GITHUB_RUN_ID}"
fj release create "$tag" --create-tag="$tag" --branch "$GITHUB_SHA" --prerelease \
    --attach=dist/terrascale-orchestrator-linux-amd64 \
    --attach=dist/terrascale-orchestrator-linux-arm64 \
    --attach="dist/$probe_name" \
    --attach=dist/terrascale-d15-probe.json
mkdir -m 0700 "$auth_home/readback"
for name in "$probe_name" terrascale-d15-probe.json; do
    fj release asset download "$tag" "$name" -o "$auth_home/readback/$name"
    cmp -- "dist/$name" "$auth_home/readback/$name"
done
# The manifest is the completion marker. A partial upload cannot be admitted.
fj release asset create "$tag" dist/qualification.json
printf 'TS_D15_PROBE_PUBLICATION_V1 source_sha=%s run_id=%s run_number=%s probe_sha256=%s descriptor_sha256=%s\n' \
    "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_NUMBER" "$probe_sha256" \
    "$(sha256sum dist/terrascale-d15-probe.json | awk '{print $1}')"
printf 'TS_RELEASE_QUALIFICATION_V1 source_sha=%s run_id=%s run_number=%s manifest_sha256=%s\n' \
    "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_NUMBER" \
    "$(sha256sum dist/qualification.json | awk '{print $1}')"
