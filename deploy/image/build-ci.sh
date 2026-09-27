#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"

for name in SOURCE_SHA SOURCE_REF CANDIDATE_RUN_ID CANDIDATE_RUN_NUMBER IMAGE_INPUT_TAG \
	IMAGE_INPUT_MANIFEST_SHA256 GITHUB_RUN_ID GITHUB_RUN_NUMBER FORGEJO_TOKEN FORGEJO_SERVER_URL; do
	[[ -n ${!name:-} ]] || { echo "missing CI input: $name" >&2; exit 2; }
done
[[ $SOURCE_SHA =~ ^[0-9a-f]{40}$ && $SOURCE_REF == refs/heads/main &&
	$CANDIDATE_RUN_ID =~ ^[1-9][0-9]*$ && $CANDIDATE_RUN_NUMBER =~ ^[1-9][0-9]*$ &&
	$GITHUB_RUN_ID =~ ^[1-9][0-9]*$ && $GITHUB_RUN_NUMBER =~ ^[1-9][0-9]*$ &&
	$IMAGE_INPUT_TAG =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
	$IMAGE_INPUT_MANIFEST_SHA256 =~ ^[0-9a-f]{64}$ ]] || {
	echo 'invalid source, run, tag, or public manifest pin' >&2
	exit 2
}
[[ $(git rev-parse HEAD) == "$SOURCE_SHA" && -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
	echo 'checked-out source differs from the image event' >&2
	exit 1
}
test "$(go env GOVERSION)" = go1.27.1
test "$(command -v fj)" = "${RUNNER_TEMP}/fj-admission-bin/fj"
for tool in jq sha256sum stat qemu-img virt-cat virt-ls readelf guestfish systemctl systemd-sysusers gpgv; do
	command -v "$tool" >/dev/null || { echo "missing image build tool: $tool" >&2; exit 1; }
done

umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/ts-image-ci.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
export XDG_DATA_HOME="$work/fj-auth"
mkdir -m 0700 "$XDG_DATA_HOME"
printf '%s\n' "$FORGEJO_TOKEN" | fj auth add-token --host "$FORGEJO_SERVER_URL" >/dev/null
unset FORGEJO_TOKEN GITHUB_TOKEN

inputs="$work/inputs"
go_release="$work/go-release"
terrabase="$work/terrabase"
mkdir -m 0700 "$inputs" "$go_release" "$terrabase"
manifest="$inputs/image-inputs.json"
fj release asset download "$IMAGE_INPUT_TAG" image-inputs.json -o "$manifest"
[[ $(stat -c '%s' "$manifest") -le 65536 ]] || {
	echo 'public image input manifest exceeds 64 KiB' >&2
	exit 1
}
printf '%s  %s\n' "$IMAGE_INPUT_MANIFEST_SHA256" "$manifest" | sha256sum --check --status

source_tree=$(git rev-parse 'HEAD^{tree}')
jq -e --arg source "$SOURCE_SHA" --arg tree "$source_tree" \
	--arg tag "$IMAGE_INPUT_TAG" --argjson run_id "$CANDIDATE_RUN_ID" \
	--argjson run_number "$CANDIDATE_RUN_NUMBER" '
  (keys == ["assets", "base_image_ocid", "base_provenance", "environment", "go_candidate",
    "input_release_tag", "kernel_release", "priority", "region", "schema",
    "source_revision", "source_tree", "terrabase"]) and
  .schema == "terrascale.image.inputs.v1" and
  .source_revision == $source and .source_tree == $tree and
  .input_release_tag == $tag and .environment == "canary" and .region == "GRU" and
  (.base_image_ocid | type == "string" and startswith("ocid1.image.oc1.sa-saopaulo-1.")) and
  .base_provenance == {
    source_url:"https://cloud-images.ubuntu.com/noble/20260926/noble-server-cloudimg-arm64.img",
    checksum_name:"noble-server-cloudimg-arm64.img",
    signer_fingerprint:"D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
  } and
  (.kernel_release | type == "string" and test("^[0-9][A-Za-z0-9._+-]{0,127}$")) and
  .go_candidate.run_id == $run_id and .go_candidate.run_number == $run_number and
  (.go_candidate | keys) == ["binary_sha256", "delegation_sha256",
    "qualification_sha256", "receipt_sha256", "root_key_sha256", "run_id", "run_number"] and
  .go_candidate.root_key_sha256 == "bbdab8425dac0382d641cdf9de7c5a6685f0355a63f6b1131c64241873d418bc" and
  .terrabase == {
    source_revision:"77dbd680504012fcee1ebf489d4813da5104912d",
    source_tree:"11df45ce68dab8208c5976c3ad930ef90fad33af",
    run_id:11534, run_number:988,
    qualification_sha256:"e7fbfe2840f8af69fd0baa504845a0f15707dc18bc3a10d4f94adab24353cbaf",
    binary_sha256:"d703c54ae4a7a9136fa1e7a1a1b6d22d6c180387de0aa2322de26871f852a1d7"
  } and
  .priority == {
    profile_id:"gru-a1-1ocpu-6gib-v1", system_reserve_bytes:1073741824,
    host_memory_min_bytes:268435456, host_memory_low_bytes:536870912,
    controller_memory_min_bytes:268435456, controller_memory_low_bytes:536870912,
    system_slice_memory_min_bytes:536870912, system_slice_memory_low_bytes:1073741824
  } and
  (.assets | keys) == [
    "base-image.qcow2", "bootstrap-anchor.json", "bootstrap-identity.json",
    "bootstrap-root-001.pem", "host-enrollment-public.json", "timesyncd-gru.conf",
    "ubuntu-SHA256SUMS", "ubuntu-SHA256SUMS.gpg", "ubuntu-cloud-image-keyring.gpg"
  ] and
  .assets["bootstrap-root-001.pem"].sha256 == "bbdab8425dac0382d641cdf9de7c5a6685f0355a63f6b1131c64241873d418bc" and
  all(.assets[]; (keys == ["bytes", "sha256"])) and
  all(.assets[]; .sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  all(.assets[]; .bytes | type == "number" and . > 0) and
  all([.go_candidate.qualification_sha256, .go_candidate.binary_sha256,
       .go_candidate.receipt_sha256, .go_candidate.delegation_sha256,
       .go_candidate.root_key_sha256][]; type == "string" and test("^[0-9a-f]{64}$"))
' "$manifest" >/dev/null

verify_file() {
	local path=$1 expected_hash=$2 expected_bytes=$3
	[[ $expected_hash =~ ^[0-9a-f]{64}$ && $expected_bytes =~ ^[1-9][0-9]*$ ]] || {
		echo "invalid public asset pin for $(basename -- "$path")" >&2
		return 1
	}
	[[ $(stat -c '%s' "$path") == "$expected_bytes" ]] || {
		echo "public asset size differs: $(basename -- "$path")" >&2
		return 1
	}
	printf '%s  %s\n' "$expected_hash" "$path" | sha256sum --check --status
}

for asset in base-image.qcow2 bootstrap-anchor.json bootstrap-identity.json \
	bootstrap-root-001.pem timesyncd-gru.conf host-enrollment-public.json \
	ubuntu-cloud-image-keyring.gpg ubuntu-SHA256SUMS ubuntu-SHA256SUMS.gpg; do
	fj release asset download "$IMAGE_INPUT_TAG" "$asset" -o "$inputs/$asset"
	verify_file "$inputs/$asset" \
		"$(jq -r --arg asset "$asset" '.assets[$asset].sha256' "$manifest")" \
		"$(jq -r --arg asset "$asset" '.assets[$asset].bytes' "$manifest")"
done

signature_status=$(gpgv --status-fd 1 --keyring "$inputs/ubuntu-cloud-image-keyring.gpg" \
	"$inputs/ubuntu-SHA256SUMS.gpg" "$inputs/ubuntu-SHA256SUMS" 2> "$work/gpgv-stderr") || {
	echo 'Ubuntu base checksum signature verification failed' >&2
	exit 1
}
grep -Fq '[GNUPG:] VALIDSIG D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81 ' <<< "$signature_status" || {
	echo 'Ubuntu base checksum signer differs from the pinned fingerprint' >&2
	exit 1
}
base_hash=$(jq -r '.assets["base-image.qcow2"].sha256' "$manifest")
signed_base_hash=$(awk '{ name = $2; sub(/^\*/, "", name); sub(/^\.\//, "", name); if (name == "noble-server-cloudimg-arm64.img") print $1 }' \
	"$inputs/ubuntu-SHA256SUMS")
[[ $signed_base_hash == "$base_hash" ]] || {
	echo 'base QCOW2 differs from the signed Ubuntu checksum' >&2
	exit 1
}

kernel_release=$(jq -r .kernel_release "$manifest")
kernel_guest_path="/boot/vmlinuz-${kernel_release}"
virt-ls -lR --csv -a "$inputs/base-image.qcow2" /boot > "$work/boot-listing.csv"
python3 - "$work/boot-listing.csv" "$kernel_guest_path" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8") as listing:
    kernels = [row for row in csv.reader(listing)
               if len(row) >= 4 and row[3].startswith("/boot/vmlinuz-")]
if len(kernels) != 1 or len(kernels[0]) != 4 or kernels[0][0] != "-" or kernels[0][3] != sys.argv[2]:
    raise SystemExit("base image has an absent, ambiguous, or nonregular boot kernel")
PY
virt-ls -a "$inputs/base-image.qcow2" "/lib/modules/${kernel_release}" > /dev/null || {
	echo 'selected guest kernel has no matching base-image modules directory' >&2
	exit 1
}
mkdir -m 0700 "$work/kernel"
virt-cat -a "$inputs/base-image.qcow2" "$kernel_guest_path" > "$work/kernel/guest-kernel"
python3 - "$work/kernel/guest-kernel" <<'PY'
import gzip
import os
import sys

path = sys.argv[1]
size = os.stat(path).st_size
if not 0 < size <= 128 * 1024 * 1024:
    raise SystemExit("base guest kernel must be between 1 byte and 128 MiB")
with open(path, "rb") as source:
    prefix = source.read(2)
    source.seek(0)
    if prefix == b"\x1f\x8b":
        with gzip.open(source) as decompressed:
            header = decompressed.read(64)
    else:
        header = source.read(64)
if len(header) != 64 or header[56:60] != b"ARM\x64":
    raise SystemExit("base guest kernel is not an AArch64 Linux boot Image")
PY
kernel_hash=$(sha256sum "$work/kernel/guest-kernel" | awk '{print $1}')
kernel_bytes=$(stat -c '%s' "$work/kernel/guest-kernel")

go_tag="ci-${SOURCE_SHA}-run-${CANDIDATE_RUN_ID}"
for asset in qualification.json terrascale-orchestrator-linux-arm64 \
	canary-linux-arm64.receipt.json canary-release-delegation.json canary-release-root.pub; do
	fj release asset download "$go_tag" "$asset" -o "$go_release/$asset"
done
for pair in \
	"qualification.json:qualification_sha256" \
	"terrascale-orchestrator-linux-arm64:binary_sha256" \
	"canary-linux-arm64.receipt.json:receipt_sha256" \
	"canary-release-delegation.json:delegation_sha256" \
	"canary-release-root.pub:root_key_sha256"; do
	asset=${pair%%:*}
	field=${pair#*:}
	expected=$(jq -r --arg field "$field" '.go_candidate[$field]' "$manifest")
	printf '%s  %s\n' "$expected" "$go_release/$asset" | sha256sum --check --status
done

qualification="$go_release/qualification.json"
jq -e --arg source "$SOURCE_SHA" --arg tree "$source_tree" \
	--arg binary "$(jq -r '.go_candidate.binary_sha256' "$manifest")" \
	--argjson run_id "$CANDIDATE_RUN_ID" --argjson run_number "$CANDIDATE_RUN_NUMBER" '
  .schema == "terrascale.release.qualification.v1" and
  .repository == "TerraScale/ts-orchestrator" and .source_revision == $source and
  .source_tree == $tree and .verification.workflow == "ci.yml" and
  .verification.job == "verify/go + artifact/linux-amd64-arm64" and
  .verification.run_id == $run_id and .verification.run_number == $run_number and
  .verification.conclusion == "success" and
  ([.artifacts[] | select(.name == "terrascale-orchestrator-linux-arm64" and
    .architecture == "arm64" and .sha256 == $binary)] | length) == 1
' "$qualification" >/dev/null
test "$(jq -r .go_mod_sha256 "$qualification")" = "$(sha256sum go.mod | awk '{print $1}')"
test "$(jq -r .go_sum_sha256 "$qualification")" = "$(sha256sum go.sum | awk '{print $1}')"
fj actions run-detail "$CANDIDATE_RUN_NUMBER" -r TerraScale/ts-orchestrator > "$work/go-run-detail.json"
jq -e --arg source "$SOURCE_SHA" --argjson run_id "$CANDIDATE_RUN_ID" \
	--argjson run_number "$CANDIDATE_RUN_NUMBER" '
  .run_id == $run_id and .run_number == $run_number and .head_sha == $source and
  .workflow == "ci.yml" and .status == "success" and
  ([.jobs[] | select(.run_id == $run_id and
    .name == "verify/go + artifact/linux-amd64-arm64" and .status == "success")] | length) == 1
' "$work/go-run-detail.json" >/dev/null

terrabase_tag=ci-77dbd680504012fcee1ebf489d4813da5104912d-run-11534
fj release asset download "$terrabase_tag" qualification.json -o "$terrabase/qualification.json"
fj release asset download "$terrabase_tag" tb-server-linux-arm64 -o "$terrabase/tb-server-linux-arm64"
printf '%s  %s\n' "$(jq -r .terrabase.qualification_sha256 "$manifest")" \
	"$terrabase/qualification.json" | sha256sum --check --status
printf '%s  %s\n' "$(jq -r .terrabase.binary_sha256 "$manifest")" \
	"$terrabase/tb-server-linux-arm64" | sha256sum --check --status
jq -e --arg source "$(jq -r .terrabase.source_revision "$manifest")" \
	--arg tree "$(jq -r .terrabase.source_tree "$manifest")" \
	--arg binary "$(jq -r .terrabase.binary_sha256 "$manifest")" '
  .schema == "terrascale.terrabase.qualification.v2" and
  .repository == "TerraScale/TerraBase" and .source_revision == $source and
  .source_tree == $tree and .verification.workflow == "fast.yml" and
  .verification.job == "fast" and .verification.run_id == 11534 and
  .verification.run_number == 988 and .verification.conclusion == "success" and
  ([.artifacts[] | select(.name == "tb-server-linux-arm64" and
    .target == "aarch64-unknown-linux-musl" and .sha256 == $binary)] | length) == 1
' "$terrabase/qualification.json" >/dev/null
fj actions run-detail 988 -r TerraScale/TerraBase > "$work/terrabase-run-detail.json"
jq -e --arg source "$(jq -r .terrabase.source_revision "$manifest")" '
  .run_id == 11534 and .run_number == 988 and .head_sha == $source and
  .workflow == "fast.yml" and .status == "success" and
  ([.jobs[] | select(.run_id == 11534 and .name == "fast" and .status == "success")] | length) == 1
' "$work/terrabase-run-detail.json" >/dev/null

mkdir -m 0700 "$work/tools"
go build -trimpath -buildvcs=true -o "$work/tools/ts-release" ./cmd/ts-release
go build -trimpath -buildvcs=true -o "$work/tools/ts-bootstrap" ./cmd/ts-bootstrap
for tool in ts-release ts-bootstrap; do
	build_info=$(go version -m "$work/tools/$tool")
	grep -Fq "vcs.revision=${SOURCE_SHA}" <<< "$build_info"
	grep -Fq 'vcs.modified=false' <<< "$build_info"
done

"$work/tools/ts-release" verify-binary \
	--receipt "$go_release/canary-linux-arm64.receipt.json" \
	--delegation "$go_release/canary-release-delegation.json" \
	--root-key "$go_release/canary-release-root.pub" \
	--binary "$go_release/terrascale-orchestrator-linux-arm64" \
	--qualification "$qualification" --environment canary

mkdir -p dist/image
test ! -e dist/image/terrascale-gru-arm64.qcow2
deploy/image/build-offline.sh \
	--base "$inputs/base-image.qcow2" \
	--binary "$go_release/terrascale-orchestrator-linux-arm64" \
	--receipt "$go_release/canary-linux-arm64.receipt.json" \
	--qualification "$qualification" \
	--delegation "$go_release/canary-release-delegation.json" \
	--root-key "$go_release/canary-release-root.pub" \
	--environment canary \
	--native-verifier-binary "$terrabase/tb-server-linux-arm64" \
	--native-verifier-sha256 "$(jq -r .terrabase.binary_sha256 "$manifest")" \
	--release-tool "$work/tools/ts-release" --bootstrap-tool "$work/tools/ts-bootstrap" \
	--bootstrap-anchor "$inputs/bootstrap-anchor.json" \
	--bootstrap-identity "$inputs/bootstrap-identity.json" \
	--bootstrap-root "$inputs/bootstrap-root-001.pem" \
	--timesyncd-config "$inputs/timesyncd-gru.conf" \
	--host-enrollment-public "$inputs/host-enrollment-public.json" \
	--host-enrollment-public-sha256 "$(jq -r '.assets["host-enrollment-public.json"].sha256' "$manifest")" \
	--runtime-priority-profile-id "$(jq -r .priority.profile_id "$manifest")" \
	--runtime-priority-system-reserve-bytes "$(jq -r .priority.system_reserve_bytes "$manifest")" \
	--host-memory-min-bytes "$(jq -r .priority.host_memory_min_bytes "$manifest")" \
	--host-memory-low-bytes "$(jq -r .priority.host_memory_low_bytes "$manifest")" \
	--controller-memory-min-bytes "$(jq -r .priority.controller_memory_min_bytes "$manifest")" \
	--controller-memory-low-bytes "$(jq -r .priority.controller_memory_low_bytes "$manifest")" \
	--system-slice-memory-min-bytes "$(jq -r .priority.system_slice_memory_min_bytes "$manifest")" \
	--system-slice-memory-low-bytes "$(jq -r .priority.system_slice_memory_low_bytes "$manifest")" \
	--out dist/image/terrascale-gru-arm64.qcow2
embedded_kernel_hash=$(virt-cat -a dist/image/terrascale-gru-arm64.qcow2 "$kernel_guest_path" | sha256sum | awk '{print $1}')
[[ $embedded_kernel_hash == "$kernel_hash" ]] || {
	echo 'final image guest kernel differs from signed base extraction' >&2
	exit 1
}
cp -- "$work/kernel/guest-kernel" dist/image/guest-kernel
chmod 0644 dist/image/guest-kernel
verify_file dist/image/guest-kernel "$kernel_hash" "$kernel_bytes"

image_hash=$(sha256sum dist/image/terrascale-gru-arm64.qcow2 | awk '{print $1}')
image_bytes=$(stat -c '%s' dist/image/terrascale-gru-arm64.qcow2)
fj actions run-detail "$GITHUB_RUN_NUMBER" -r TerraScale/ts-orchestrator > "$work/image-run-detail.json"
jq -e --arg source "$SOURCE_SHA" --argjson run_id "$GITHUB_RUN_ID" \
	--argjson run_number "$GITHUB_RUN_NUMBER" '
  .run_id == $run_id and .run_number == $run_number and .head_sha == $source and
  .workflow == "image.yml" and
  ([.jobs[] | select(.run_id == $run_id and .name == "build/qualified-gru-arm64-image" and
    .id > 0 and .attempt > 0 and (.status == "running" or .status == "in_progress"))] | length) == 1
' "$work/image-run-detail.json" > /dev/null
job_id=$(jq -r '.jobs[] | select(.name == "build/qualified-gru-arm64-image") | .id' "$work/image-run-detail.json")
run_attempt=$(jq -r '.jobs[] | select(.name == "build/qualified-gru-arm64-image") | .attempt' "$work/image-run-detail.json")
job_status=$(jq -r '.jobs[] | select(.name == "build/qualified-gru-arm64-image") | .status' "$work/image-run-detail.json")
if [[ -n ${GITHUB_RUN_ATTEMPT:-} ]]; then
	[[ $GITHUB_RUN_ATTEMPT =~ ^[1-9][0-9]*$ && $GITHUB_RUN_ATTEMPT == "$run_attempt" ]] || {
		echo 'Forgejo event attempt differs from current job attempt' >&2
		exit 1
	}
fi
output_tag="image-${SOURCE_SHA}-run-${GITHUB_RUN_ID}-attempt-${run_attempt}"
release_tool_hash=$(sha256sum "$work/tools/ts-release" | awk '{print $1}')
bootstrap_tool_hash=$(sha256sum "$work/tools/ts-bootstrap" | awk '{print $1}')
qemu_img_version=$(qemu-img --version | head -n 1)
guestfish_version=$(guestfish --version)
virt_cat_version=$(virt-cat --version)
gpgv_version=$(gpgv --version | head -n 1)
jq -cnS --slurpfile inputs "$manifest" \
	--arg source "$SOURCE_SHA" --arg tree "$source_tree" \
	--arg input_tag "$IMAGE_INPUT_TAG" --arg input_hash "$IMAGE_INPUT_MANIFEST_SHA256" \
	--arg go_tag "$go_tag" --arg terrabase_tag "$terrabase_tag" --arg output_tag "$output_tag" \
	--arg job_status "$job_status" \
	--arg go_version "$(go env GOVERSION)" --arg release_tool_hash "$release_tool_hash" \
	--arg bootstrap_tool_hash "$bootstrap_tool_hash" \
	--arg qemu_img_version "$qemu_img_version" --arg guestfish_version "$guestfish_version" \
	--arg virt_cat_version "$virt_cat_version" --arg gpgv_version "$gpgv_version" \
	--arg kernel_release "$kernel_release" --arg kernel_guest_path "$kernel_guest_path" \
	--arg kernel_hash "$kernel_hash" --argjson kernel_bytes "$kernel_bytes" \
	--arg image_hash "$image_hash" --argjson image_bytes "$image_bytes" \
	--argjson run_id "$GITHUB_RUN_ID" --argjson run_number "$GITHUB_RUN_NUMBER" \
	--argjson job_id "$job_id" --argjson run_attempt "$run_attempt" \
	'{schema:"terrascale.image.qualification.v1",source_revision:$source,source_tree:$tree,
    verification:{workflow:"image.yml",job:"build/qualified-gru-arm64-image",run_id:$run_id,
      run_number:$run_number,job_id:$job_id,run_attempt:$run_attempt,
      observed_job_status_at_publication:$job_status,
      required_final_run_status:"success",required_final_job_status:"success"},
    input_release_tag:$input_tag,input_manifest_sha256:$input_hash,inputs:$inputs[0],
    go_release_tag:$go_tag,terrabase_release_tag:$terrabase_tag,image_release_tag:$output_tag,
    toolchain:{go_version:$go_version,ts_release_sha256:$release_tool_hash,
      ts_bootstrap_sha256:$bootstrap_tool_hash,qemu_img_version:$qemu_img_version,
      guestfish_version:$guestfish_version,virt_cat_version:$virt_cat_version,
      gpgv_version:$gpgv_version,
      nixpkgs_revision:"e554fab72f81915600f3f449b786fd9af40439a5",
      nixpkgs_nar_hash:"sha256-ZKhUe/2IJUq1JhKxKMu8rbkgSGmPP2ZCqlIPn40aGCM="},
    kernel:{name:"guest-kernel",guest_path:$kernel_guest_path,release:$kernel_release,
      architecture:"arm64",bytes:$kernel_bytes,sha256:$kernel_hash},
    image:{name:"terrascale-gru-arm64.qcow2",format:"qcow2",architecture:"arm64",bytes:$image_bytes,sha256:$image_hash},
    image_receipt_status:"requires OCI import OCID and protected post-import signing"}' \
	> dist/image/image-qualification.json
(cd dist/image && sha256sum terrascale-gru-arm64.qcow2 guest-kernel image-qualification.json) > dist/image/SHA256SUMS

if ! fj release view --by-tag "$output_tag" > "$work/release-view.txt" 2> "$work/release-view-error.txt"; then
	fj release create "$output_tag" --create-tag="$output_tag" --branch "$SOURCE_SHA" --prerelease
	fj release view --by-tag "$output_tag" > "$work/release-view.txt"
fi
grep -Fq "$output_tag" "$work/release-view.txt" || {
	echo 'image release tag readback differs from the selected run' >&2
	exit 1
}
while IFS= read -r listed_asset; do
	case "$listed_asset" in
		'- terrascale-gru-arm64.qcow2'|'- guest-kernel'|'- SHA256SUMS'|'- image-qualification.json'|'- source.zip'|'- source.tar.gz') ;;
		*) echo "image release contains unexpected asset: $listed_asset" >&2; exit 1 ;;
	esac
done < <(grep '^- ' "$work/release-view.txt" || true)

readback="$work/release-readback"
mkdir -m 0700 "$readback"
retain_asset() {
	local name=$1 expected_hash=$2 expected_bytes=$3
	local source="dist/image/$name"
	if ! grep -Fqx -- "- $name" "$work/release-view.txt"; then
		fj release asset create "$output_tag" "$source"
	fi
	fj release asset download "$output_tag" "$name" -o "$readback/$name"
	verify_file "$readback/$name" "$expected_hash" "$expected_bytes" || {
		echo "retained image asset differs from this exact run: $name" >&2
		return 1
	}
}

retain_asset terrascale-gru-arm64.qcow2 "$image_hash" "$image_bytes"
retain_asset guest-kernel "$kernel_hash" "$kernel_bytes"
retain_asset SHA256SUMS "$(sha256sum dist/image/SHA256SUMS | awk '{print $1}')" \
	"$(stat -c '%s' dist/image/SHA256SUMS)"
# The provenance is the completion marker, uploaded only after both payloads read back.
retain_asset image-qualification.json \
	"$(sha256sum dist/image/image-qualification.json | awk '{print $1}')" \
	"$(stat -c '%s' dist/image/image-qualification.json)"
printf 'TS_IMAGE_QUALIFICATION_V1 source_sha=%s run_id=%s run_number=%s job_id=%s attempt=%s image_sha256=%s kernel_sha256=%s provenance_sha256=%s tag=%s\n' \
	"$SOURCE_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_NUMBER" "$job_id" "$run_attempt" \
	"$image_hash" "$kernel_hash" \
	"$(sha256sum dist/image/image-qualification.json | awk '{print $1}')" "$output_tag"
