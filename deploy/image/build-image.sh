#!/usr/bin/env bash
# Build the qualified GRU ARM64 host image for one source revision.
#
# usage: build-image.sh --source SHA --out DIRECTORY [--wait-for-ci SECONDS]
#
# Run from a clean checkout of SOURCE with the pinned image tools on PATH
# (deploy/image/tools.sh) and an fj that has `actions run-detail` and
# `actions logs`, authenticated for reads. FORGEJO_READ_TOKEN_FILE names a
# file holding a read token for the Actions API.
#
# Every input is found from data, never copied by hand:
#   - deploy/image/image-inputs.json pins the base image release, trust
#     roots, timesyncd config, priority profile, and TerraBase artifact;
#   - the orchestrator binary is the retained release of the successful
#     ci.yml run on main for SOURCE, found through the Actions API. With
#     --wait-for-ci, a still-running ci.yml run is awaited.
# Writes terrascale-gru-arm64.qcow2, guest-kernel, image-qualification.json
# and SHA256SUMS to DIRECTORY. Publishing is publish-image.sh's job.
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"
repository=TerraScale/ts-orchestrator
server=${FORGEJO_SERVER_URL:-https://git.terrascale.tech}
ci_job='verify/go + artifact/linux-amd64-arm64'
image_job='build/qualified-gru-arm64-image'

source_sha=
output=
wait_seconds=0
while (($#)); do
	case $1 in
		--source) source_sha=${2:?}; shift 2 ;;
		--out) output=${2:?}; shift 2 ;;
		--wait-for-ci) wait_seconds=${2:?}; shift 2 ;;
		*) sed -n '2,19s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
	esac
done
[[ $source_sha =~ ^[0-9a-f]{40}$ && -n $output && $wait_seconds =~ ^[0-9]+$ ]] || {
	echo 'build-image.sh needs --source FULL_SHA and --out DIRECTORY' >&2
	exit 2
}
[[ $(git rev-parse HEAD) == "$source_sha" && -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
	echo "checkout is not a clean tree at $source_sha" >&2
	exit 1
}
[[ -r ${FORGEJO_READ_TOKEN_FILE:-} ]] || { echo 'FORGEJO_READ_TOKEN_FILE must name a readable token file' >&2; exit 2; }
test "$(go env GOVERSION)" = go1.27.1
for tool in curl fj jq sha256sum stat gpgv qemu-img guestfish systemctl systemd-sysusers python3; do
	command -v "$tool" >/dev/null || { echo "missing image build tool: $tool" >&2; exit 1; }
done
fj actions run-detail --help >/dev/null 2>&1 && fj actions logs --help >/dev/null 2>&1 || {
	echo 'fj lacks the pinned actions run-detail/logs extension' >&2
	exit 1
}

mkdir -p -- "$output"
output=$(realpath -e -- "$output")
[[ -z $(ls -A -- "$output") ]] || { echo "output directory is not empty: $output" >&2; exit 1; }
umask 077
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ts-image.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -m 0700 "$work/base" "$work/go" "$work/terrabase" "$work/tools"
source_tree=$(git rev-parse 'HEAD^{tree}')
inputs=deploy/image/image-inputs.json
python3 deploy/image/image-inputs.py check
input_json() { jq -r "$1" "$inputs"; }

sha256() { sha256sum -- "$1" | cut -d ' ' -f 1; }
verify_file() {
	local path=$1 expected_sha256=$2 expected_bytes=$3
	[[ $(stat -c '%s' -- "$path") == "$expected_bytes" && $(sha256 "$path") == "$expected_sha256" ]] || {
		echo "downloaded bytes differ from their pin: ${path##*/}" >&2
		return 1
	}
}
api_get() {
	curl --fail --silent --show-error --location --max-time 30 \
		-H "@$work/api-header" "$server/api/v1/repos/$repository$1"
}
printf 'Authorization: token %s\n' "$(<"$FORGEJO_READ_TOKEN_FILE")" > "$work/api-header"

# Base image: retained once as a release, pinned by digest, and proven to be
# the Ubuntu image signed by the pinned key.
base_tag=$(input_json .base.release_tag)
for asset in base-image.qcow2 ubuntu-SHA256SUMS ubuntu-SHA256SUMS.gpg ubuntu-cloud-image-keyring.gpg; do
	fj release asset download -r "$repository" "$base_tag" "$asset" -o "$work/base/$asset" >/dev/null
	verify_file "$work/base/$asset" "$(input_json ".base.assets[\"$asset\"].sha256")" \
		"$(input_json ".base.assets[\"$asset\"].bytes")"
done
gpgv --status-fd 1 --keyring "$work/base/ubuntu-cloud-image-keyring.gpg" \
	"$work/base/ubuntu-SHA256SUMS.gpg" "$work/base/ubuntu-SHA256SUMS" > "$work/gpgv-status" 2>/dev/null || {
	echo 'Ubuntu base checksum signature verification failed' >&2
	exit 1
}
grep -Fq "[GNUPG:] VALIDSIG $(input_json .base.signer_fingerprint) " "$work/gpgv-status" || {
	echo 'Ubuntu base checksum signer differs from the pinned fingerprint' >&2
	exit 1
}
signed_base_sha256=$(awk -v name="$(input_json .base.checksum_name)" \
	'{ file = $2; sub(/^\*/, "", file); sub(/^\.\//, "", file); if (file == name) print $1 }' \
	"$work/base/ubuntu-SHA256SUMS")
[[ $signed_base_sha256 == "$(input_json '.base.assets["base-image.qcow2"].sha256')" ]] || {
	echo 'base QCOW2 differs from the signed Ubuntu checksum' >&2
	exit 1
}
echo "base image verified tag=$base_tag sha256=$signed_base_sha256"

# TerraBase native verifier: the pinned Fast-qualified release artifact.
terrabase_sha=$(input_json .terrabase.source_revision)
terrabase_run_id=$(input_json .terrabase.run_id)
terrabase_run_number=$(input_json .terrabase.run_number)
terrabase_tag="ci-${terrabase_sha}-run-${terrabase_run_id}"
for asset in qualification.json tb-server-linux-arm64; do
	fj release asset download -r TerraScale/TerraBase "$terrabase_tag" "$asset" -o "$work/terrabase/$asset" >/dev/null
done
[[ $(sha256 "$work/terrabase/qualification.json") == "$(input_json .terrabase.qualification_sha256)" &&
	$(sha256 "$work/terrabase/tb-server-linux-arm64") == "$(input_json .terrabase.binary_sha256)" ]] || {
	echo "TerraBase release $terrabase_tag differs from the pinned digests" >&2
	exit 1
}
fj actions run-detail "$terrabase_run_number" -r TerraScale/TerraBase > "$work/terrabase/run-detail.json"
cp -- "$inputs" "$work/terrabase/inputs-check.json"
python3 deploy/image/image-inputs.py --file "$work/terrabase/inputs-check.json" pin-terrabase \
	--qualification "$work/terrabase/qualification.json" --run-detail "$work/terrabase/run-detail.json" >/dev/null
cmp -s -- "$inputs" "$work/terrabase/inputs-check.json" || {
	echo "TerraBase release $terrabase_tag does not reproduce the pinned inputs" >&2
	exit 1
}
echo "terrabase verified tag=$terrabase_tag binary_sha256=$(input_json .terrabase.binary_sha256)"

# Orchestrator candidate: the successful ci.yml run on main for this revision.
deadline=$((SECONDS + wait_seconds))
while :; do
	api_get "/actions/runs?workflow_id=ci.yml&head_sha=$source_sha&limit=50" > "$work/go/runs.json"
	run=$(jq -c '[.workflow_runs[] | select(.prettyref == "main")] | max_by(.id) // empty' "$work/go/runs.json")
	status=$(jq -r '.status // "absent"' <<< "${run:-null}")
	case $status in
		success) break ;;
		failure|cancelled|skipped|blocked)
			echo "ci.yml run $(jq -r .id <<< "$run") for $source_sha ended $status; no image" >&2
			exit 1 ;;
	esac
	((SECONDS < deadline)) || { echo "no successful ci.yml run on main for $source_sha (status $status)" >&2; exit 1; }
	echo "waiting for ci.yml on $source_sha (status $status)"
	sleep 15
done
go_run_id=$(jq -r .id <<< "$run")
go_run_number=$(jq -r .index_in_repo <<< "$run")
go_tag="ci-${source_sha}-run-${go_run_id}"
for asset in qualification.json terrascale-orchestrator-linux-arm64; do
	fj release asset download -r "$repository" "$go_tag" "$asset" -o "$work/go/$asset" >/dev/null
done
qualification="$work/go/qualification.json"
go_binary="$work/go/terrascale-orchestrator-linux-arm64"
jq -e --arg source "$source_sha" --arg tree "$source_tree" --arg job "$ci_job" \
	--arg binary "$(sha256 "$go_binary")" --argjson bytes "$(stat -c '%s' -- "$go_binary")" \
	--argjson run_id "$go_run_id" --argjson run_number "$go_run_number" '
  .schema == "terrascale.release.qualification.v1" and
  .repository == "TerraScale/ts-orchestrator" and .source_revision == $source and
  .source_tree == $tree and .verification.workflow == "ci.yml" and .verification.job == $job and
  .verification.run_id == $run_id and .verification.run_number == $run_number and
  .verification.conclusion == "success" and
  ([.artifacts[] | select(.name == "terrascale-orchestrator-linux-arm64" and .architecture == "arm64" and
    .sha256 == $binary and .bytes == $bytes)] | length) == 1
' "$qualification" >/dev/null || { echo "CI qualification of $go_tag does not match $source_sha" >&2; exit 1; }
[[ $(jq -r .go_mod_sha256 "$qualification") == $(sha256 go.mod) &&
	$(jq -r .go_sum_sha256 "$qualification") == $(sha256 go.sum) ]] || {
	echo 'CI qualification module digests differ from the checkout' >&2
	exit 1
}
fj actions run-detail "$go_run_number" -r "$repository" > "$work/go/run-detail.json"
jq -e --arg source "$source_sha" --arg job "$ci_job" --argjson run_id "$go_run_id" \
	--argjson run_number "$go_run_number" '
  .run_id == $run_id and .run_number == $run_number and .head_sha == $source and
  .workflow == "ci.yml" and .status == "success" and
  ([.jobs[] | select(.run_id == $run_id and .name == $job and .status == "success")] | length) == 1
' "$work/go/run-detail.json" >/dev/null || { echo "ci.yml run $go_run_id did not qualify $source_sha" >&2; exit 1; }
# The CI job log binds the retained manifest bytes to the successful job.
fj actions logs "$go_run_number" -r "$repository" | tr -d '\r' > "$work/go/logs.txt"
marker="TS_RELEASE_QUALIFICATION_V1 source_sha=$source_sha run_id=$go_run_id run_number=$go_run_number manifest_sha256=$(sha256 "$qualification")"
[[ $(grep -c -E "^[0-9TZ:.-]+ ${marker}\$" "$work/go/logs.txt") == 1 ]] || {
	echo "ci.yml job log lacks one exact qualification marker for $go_tag" >&2
	exit 1
}
echo "orchestrator candidate verified tag=$go_tag binary_sha256=$(sha256 "$go_binary")"

go build -trimpath -buildvcs=true -o "$work/tools/ts-release" ./cmd/ts-release
build_info=$(go version -m "$work/tools/ts-release")
grep -Fq "vcs.revision=$source_sha" <<< "$build_info" && grep -Fq 'vcs.modified=false' <<< "$build_info"

kernel_release=$(input_json .base.kernel_release)
roots=()
while IFS= read -r root; do roots+=(--bootstrap-root "$root"); done < <(input_json '.trust_roots[].path')
deploy/image/build-offline.sh \
	--base "$work/base/base-image.qcow2" \
	--kernel-release "$kernel_release" \
	--binary "$go_binary" \
	--qualification "$qualification" \
	--source-revision "$source_sha" \
	--native-verifier-binary "$work/terrabase/tb-server-linux-arm64" \
	--native-verifier-sha256 "$(input_json .terrabase.binary_sha256)" \
	--release-tool "$work/tools/ts-release" \
	"${roots[@]}" \
	--timesyncd-config "$(input_json .timesyncd_config.path)" \
	--runtime-priority-profile-id "$(input_json .priority.profile_id)" \
	--runtime-priority-system-reserve-bytes "$(input_json .priority.system_reserve_bytes)" \
	--host-memory-min-bytes "$(input_json .priority.host_memory_min_bytes)" \
	--host-memory-low-bytes "$(input_json .priority.host_memory_low_bytes)" \
	--controller-memory-min-bytes "$(input_json .priority.controller_memory_min_bytes)" \
	--controller-memory-low-bytes "$(input_json .priority.controller_memory_low_bytes)" \
	--system-slice-memory-min-bytes "$(input_json .priority.system_slice_memory_min_bytes)" \
	--system-slice-memory-low-bytes "$(input_json .priority.system_slice_memory_low_bytes)" \
	--out "$output/terrascale-gru-arm64.qcow2" \
	--kernel-out "$output/guest-kernel"
chmod 0644 "$output/terrascale-gru-arm64.qcow2" "$output/guest-kernel"

# Who built it: the image.yml job in CI, or a named local builder.
if [[ -n ${GITHUB_RUN_ID:-} ]]; then
	fj actions run-detail "${GITHUB_RUN_NUMBER:?}" -r "$repository" > "$work/image-run-detail.json"
	builder=$(jq -c --arg job "$image_job" --argjson run_id "$GITHUB_RUN_ID" '
	  . as $run | [.jobs[] | select(.run_id == $run_id and .name == $job)] |
	  if length == 1 and ($run.workflow == "image.yml") and ($run.run_id == $run_id) then
	    {kind:"ci", workflow:"image.yml", job:$job, run_id:$run.run_id, run_number:$run.run_number,
	     job_id:.[0].id, run_attempt:.[0].attempt, required_final_status:"success"}
	  else error("image run detail does not identify this job") end' "$work/image-run-detail.json")
else
	builder=$(jq -cn --arg user "$(id -un)" --arg host "$(hostname)" '{kind:"local", user:$user, host:$host}')
fi

jq -n --slurpfile inputs "$inputs" --argjson builder "$builder" \
	--arg source "$source_sha" --arg tree "$source_tree" \
	--arg inputs_sha256 "$(sha256 "$inputs")" \
	--arg go_tag "$go_tag" --argjson go_run_id "$go_run_id" --argjson go_run_number "$go_run_number" \
	--arg go_qualification "$(sha256 "$qualification")" --arg go_binary "$(sha256 "$go_binary")" \
	--argjson go_bytes "$(stat -c '%s' -- "$go_binary")" \
	--arg terrabase_tag "$terrabase_tag" \
	--arg go_version "$(go env GOVERSION)" --arg ts_release "$(sha256 "$work/tools/ts-release")" \
	--arg qemu_img "$(qemu-img --version | head -n 1)" --arg guestfish "$(guestfish --version)" \
	--arg gpgv "$(gpgv --version | head -n 1)" --arg tools "${TS_IMAGE_TOOLS_ID:-unrecorded}" \
	--arg kernel_release "$kernel_release" --arg kernel "$(sha256 "$output/guest-kernel")" \
	--argjson kernel_bytes "$(stat -c '%s' -- "$output/guest-kernel")" \
	--arg image "$(sha256 "$output/terrascale-gru-arm64.qcow2")" \
	--argjson image_bytes "$(stat -c '%s' -- "$output/terrascale-gru-arm64.qcow2")" '
  {schema:"terrascale.image.qualification.v2", source_revision:$source, source_tree:$tree,
   builder:$builder,
   inputs:{path:"deploy/image/image-inputs.json", sha256:$inputs_sha256, manifest:$inputs[0]},
   go_candidate:{release_tag:$go_tag, run_id:$go_run_id, run_number:$go_run_number,
     qualification_sha256:$go_qualification, binary_sha256:$go_binary, binary_bytes:$go_bytes},
   terrabase_release_tag:$terrabase_tag,
   toolchain:{go_version:$go_version, ts_release_sha256:$ts_release, qemu_img_version:$qemu_img,
     guestfish_version:$guestfish, gpgv_version:$gpgv, tools:$tools},
   kernel:{name:"guest-kernel", guest_path:("/boot/vmlinuz-" + $kernel_release), release:$kernel_release,
     architecture:"arm64", bytes:$kernel_bytes, sha256:$kernel},
   image:{name:"terrascale-gru-arm64.qcow2", format:"qcow2", architecture:"arm64",
     bytes:$image_bytes, sha256:$image},
   image_receipt_status:"requires OCI import and signing (deploy/image/promote-image.py)"}' \
	> "$output/image-qualification.json"
chmod 0644 "$output/image-qualification.json"
(cd "$output" && sha256sum terrascale-gru-arm64.qcow2 guest-kernel image-qualification.json > SHA256SUMS)
chmod 0644 "$output/SHA256SUMS"
printf 'image built source=%s image_sha256=%s kernel_sha256=%s qualification_sha256=%s\n' \
	"$source_sha" "$(sha256 "$output/terrascale-gru-arm64.qcow2")" "$(sha256 "$output/guest-kernel")" \
	"$(sha256 "$output/image-qualification.json")"
