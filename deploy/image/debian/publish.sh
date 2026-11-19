#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 <host-image-YYYYMMDD-sha> [<fleet-label>...]" >&2
	exit 2
}
[[ $# -ge 1 && $1 =~ ^host-image-[0-9]{8}-[0-9a-f]{7}$ ]] || usage
tag=$1
shift

here=$(cd "$(dirname "$0")" && pwd)
fleet=$here/../../fleet/fleet.json
repo=TerraScale/ts-orchestrator
debian=13
bucket=ts-host-images
labels=("$@")
((${#labels[@]})) || mapfile -t labels < <(jq -r '.staging.label, .regions[].label' "$fleet")

namespace=$(oci os ns get --query data --raw-output)
schema_id=$(oci compute global-image-capability-schema list --query 'data[0].id' --raw-output)
schema_version=$(oci compute global-image-capability-schema list --query 'data[0]."current-version-name"' --raw-output)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

shape_arch() {
	if [[ $1 =~ \.A[0-9]+\. ]]; then echo arm64; else echo amd64; fi
}

verified_sum() {
	local file=$1 published asset
	if [[ ! -f $work/$file.verified ]]; then
		gh release download "$tag" --repo "$repo" --dir "$work" --pattern "$file" --pattern "$file.sha256" >&2
		(cd "$work" && sha256sum --check --quiet "$file.sha256") >&2
		published=$(cut -d' ' -f1 "$work/$file.sha256")
		asset=$(gh release view "$tag" --repo "$repo" --json assets --jq ".assets[] | select(.name == \"$file\") | .digest")
		[[ $asset == "sha256:$published" ]] || {
			echo "$file: GitHub asset digest $asset does not match $published" >&2
			exit 1
		}
		echo "$published" > "$work/$file.verified"
	fi
	cat "$work/$file.verified"
}

ensure_object() {
	local region=$1 compartment=$2 file=$3 sum=$4 stored
	local object="$tag/$file"
	if ! oci --region "$region" os bucket get --namespace "$namespace" --bucket-name "$bucket" >/dev/null 2>&1; then
		oci --region "$region" os bucket create --namespace "$namespace" --compartment-id "$compartment" \
			--name "$bucket" --public-access-type NoPublicAccess >/dev/null
		echo "$region: created bucket $bucket" >&2
	fi
	stored=$(oci --region "$region" os object head --namespace "$namespace" --bucket-name "$bucket" --name "$object" 2>/dev/null |
		jq -r '."opc-meta-sha256" // empty' || true)
	if [[ $stored != "$sum" ]]; then
		oci --region "$region" os object put --namespace "$namespace" --bucket-name "$bucket" --name "$object" \
			--file "$work/$file" --metadata "{\"sha256\":\"$sum\"}" --force >/dev/null
		echo "$region: uploaded $object" >&2
	fi
}

wait_available() {
	local region=$1 image=$2 state
	for _ in $(seq 120); do
		state=$(oci --region "$region" compute image get --image-id "$image" --query 'data."lifecycle-state"' --raw-output)
		case $state in
		AVAILABLE) return 0 ;;
		PROVISIONING | IMPORTING) sleep 30 ;;
		*)
			echo "$region: image $image is $state" >&2
			exit 1
			;;
		esac
	done
	echo "$region: image $image is still $state after an hour" >&2
	exit 1
}

set_capabilities() {
	local region=$1 compartment=$2 image=$3 existing
	existing=$(oci --region "$region" compute image-capability-schema list --compartment-id "$compartment" --image-id "$image" \
		--query 'length(data)' --raw-output)
	[[ $existing == 0 ]] || return 0
	oci --region "$region" compute image-capability-schema create --compartment-id "$compartment" --image-id "$image" \
		--global-image-capability-schema-version-name "$schema_version" --schema-data "$(jq -cn '{
			"Compute.Firmware": {descriptorType: "enumstring", source: "IMAGE", values: ["UEFI_64"], defaultValue: "UEFI_64"},
			"Compute.LaunchMode": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
			"Storage.BootVolumeType": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
			"Storage.RemoteDataVolumeType": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
			"Network.AttachmentType": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
			"Storage.ConsistentVolumeNaming": {descriptorType: "boolean", source: "IMAGE", defaultValue: true}
		}')" >/dev/null
	echo "$region: set image capabilities from global schema $schema_id" >&2
}

set_shapes() {
	local region=$1 image=$2 arch=$3 shape
	local -a wanted current
	mapfile -t wanted < <(jq -r '[.staging, .regions[]] | map(.nodes.shape) | unique[]' "$fleet" | while read -r shape; do
		[[ $(shape_arch "$shape") != "$arch" ]] || echo "$shape"
	done)
	((${#wanted[@]})) || {
		echo "the fleet document names no $arch shape" >&2
		exit 1
	}
	mapfile -t current < <(oci --region "$region" compute image-shape-compatibility-entry list --image-id "$image" --all \
		--query 'data[].shape' | jq -r '.[]')
	for shape in "${wanted[@]}"; do
		oci --region "$region" compute image-shape-compatibility-entry add --image-id "$image" --shape-name "$shape" >/dev/null
	done
	for shape in "${current[@]}"; do
		[[ " ${wanted[*]} " == *" $shape "* ]] ||
			oci --region "$region" compute image-shape-compatibility-entry remove --image-id "$image" --shape-name "$shape" --force >/dev/null
	done
}

publish() {
	local label region compartment shape arch file name sum image tagged
	read -r label region compartment shape < <(jq -r --arg label "$1" \
		'[.staging, .regions[]] | map(select(.label == $label)) | .[0] // error("no fleet region \($label)") |
		[.label, .oci_region, .compartment_id, .nodes.shape] | @tsv' "$fleet")
	arch=$(shape_arch "$shape")
	file=ts-host-debian$debian-$arch.qcow2
	name=${file%.qcow2}-$tag
	image=$(oci --region "$region" compute image list --compartment-id "$compartment" --display-name "$name" --all |
		jq -r '[.data[]? | select(."lifecycle-state" != "DELETED")] | .[0] // empty | .id')
	sum=$(verified_sum "$file")
	if [[ -z $image ]]; then
		ensure_object "$region" "$compartment" "$file" "$sum"
		image=$(oci --region "$region" compute image import from-object --namespace "$namespace" --bucket-name "$bucket" \
			--name "$tag/$file" --compartment-id "$compartment" --display-name "$name" --source-image-type QCOW2 \
			--launch-mode PARAVIRTUALIZED --operating-system Debian --operating-system-version "$debian" \
			--freeform-tags "{\"terrascale-host-image\":\"$tag\",\"terrascale-sha256\":\"$sum\"}" --query data.id --raw-output)
		echo "$label: importing $name as $image" >&2
	else
		tagged=$(oci --region "$region" compute image get --image-id "$image" --query 'data."freeform-tags"."terrascale-sha256"' --raw-output)
		[[ $tagged == "$sum" ]] || {
			echo "$label: image $image is tagged sha256 $tagged, the release has $sum" >&2
			exit 1
		}
		echo "$label: found $name as $image" >&2
	fi
	wait_available "$region" "$image"
	set_capabilities "$region" "$compartment" "$image"
	set_shapes "$region" "$image" "$arch"
	jq -cn --arg region "$region" --arg arch "$arch" --arg image "$image" --arg debian "$debian" --arg sum "$sum" \
		'{region: $region, arch: $arch, image_ocid: $image, debian: $debian, sha256: $sum}'
}

for label in "${labels[@]}"; do
	publish "$label"
done
