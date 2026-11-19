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
fleet=$here/../fleet/fleet.json
repo=TerraScale/ts-orchestrator
debian=13
bucket=ts-host-images-prod
entries=$(jq -c '[.regions[]]' "$fleet")
labels=("$@")
((${#labels[@]})) || mapfile -t labels < <(jq -r '.[].label' <<<"$entries")
capabilities=$(jq -cn '{
	"Compute.Firmware": {descriptorType: "enumstring", source: "IMAGE", values: ["UEFI_64"], defaultValue: "UEFI_64"},
	"Compute.LaunchMode": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
	"Storage.BootVolumeType": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
	"Storage.RemoteDataVolumeType": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
	"Network.AttachmentType": {descriptorType: "enumstring", source: "IMAGE", values: ["PARAVIRTUALIZED"], defaultValue: "PARAVIRTUALIZED"},
	"Storage.ConsistentVolumeNaming": {descriptorType: "boolean", source: "IMAGE", defaultValue: true}
}')

namespace=$(oci os ns get --query data --raw-output)
assets=$(gh release view "$tag" --repo "$repo" --json assets)
token="$(hostname)/${USER:-operator}/$$/$(date -u +%Y%m%dT%H%M%SZ)"
lock_region=
lock_name=
work=$(mktemp -d)
trap 'release_lock; rm -rf "$work"' EXIT

die() {
	echo "$*" >&2
	exit 1
}

oci_status() {
	local result=$1
	shift
	if oci "$@" >"$result" 2>"$result.err"; then
		echo 200
	else
		sed -n '/^{/,$p' "$result.err" | jq -r '.status // "failed"' 2>/dev/null || echo failed
	fi
}

shape_arch() {
	if [[ $1 =~ \.A[0-9]+\. ]]; then echo arm64; else echo amd64; fi
}

asset_digest() {
	jq -r --arg name "$1" '.assets[] | select(.name == $name) | .digest' <<<"$assets"
}

verified_sum() {
	local file=$1 dir=$work/release-$1 sum sidecar_sum sidecar_name
	if [[ ! -f $dir/verified ]]; then
		mkdir "$dir"
		gh release download "$tag" --repo "$repo" --dir "$dir" --pattern "$file" --pattern "$file.sha256" >&2
		[[ $(asset_digest "$file.sha256") == "sha256:$(sha256sum <"$dir/$file.sha256" | cut -d' ' -f1)" ]] ||
			die "$file.sha256 does not match its GitHub asset digest"
		read -r sidecar_sum sidecar_name <"$dir/$file.sha256"
		sum=$(sha256sum <"$dir/$file" | cut -d' ' -f1)
		[[ $sidecar_name == "$file" && $sidecar_sum == "$sum" ]] ||
			die "$file hashes to $sum; its sidecar names $sidecar_name with $sidecar_sum"
		[[ $(asset_digest "$file") == "sha256:$sum" ]] || die "$file does not match its GitHub asset digest"
		echo "$sum" >"$dir/verified"
	fi
	cat "$dir/verified"
}

ensure_bucket() {
	local region=$1 owner status
	owner=$(jq -r --arg region "$region" 'map(select(.oci_region == $region)) | .[0].compartment_id' <<<"$entries")
	status=$(oci_status "$work/bucket" --region "$region" os bucket get --namespace "$namespace" --bucket-name "$bucket")
	if [[ $status == 404 ]]; then
		status=$(oci_status "$work/bucket" --region "$region" os bucket create --namespace "$namespace" \
			--compartment-id "$owner" --name "$bucket" --public-access-type NoPublicAccess)
		if [[ $status == 409 ]]; then
			status=$(oci_status "$work/bucket" --region "$region" os bucket get --namespace "$namespace" --bucket-name "$bucket")
		elif [[ $status == 200 ]]; then
			echo "$region: created bucket $bucket in $owner" >&2
		fi
	fi
	[[ $status == 200 ]] || {
		cat "$work/bucket.err" >&2
		die "$region: bucket $bucket returned $status"
	}
	jq -e --arg owner "$owner" '.data."compartment-id" == $owner and .data."public-access-type" == "NoPublicAccess"' \
		"$work/bucket" >/dev/null || die "$region: bucket $bucket must be NoPublicAccess in compartment $owner"
}

acquire_lock() {
	local region=$1 name=$2 status owner
	echo "$token" >"$work/lock-token"
	oci --region "$region" os object put --namespace "$namespace" --bucket-name "$bucket" --name "$name" --file "$work/lock-token" \
		--metadata "$(jq -cn --arg owner "$token" '{owner: $owner}')" --no-multipart --no-overwrite >/dev/null
	status=$(oci_status "$work/lock" --region "$region" os object head --namespace "$namespace" --bucket-name "$bucket" --name "$name")
	[[ $status == 200 ]] || {
		cat "$work/lock.err" >&2
		die "$region: lock $name returned $status"
	}
	owner=$(jq -r '."opc-meta-owner" // empty' "$work/lock")
	[[ $owner == "$token" ]] ||
		die "$region: $name is held by '$owner' since $(jq -r '."last-modified"' "$work/lock"). Wait for that run; if it is older than the one-hour import wait and no publish runs, remove it with: oci --region $region os object delete --namespace $namespace --bucket-name $bucket --name $name --force"
	lock_region=$region
	lock_name=$name
}

release_lock() {
	[[ -n $lock_name ]] || return 0
	if [[ $(oci --region "$lock_region" os object head --namespace "$namespace" --bucket-name "$bucket" --name "$lock_name" |
		jq -r '."opc-meta-owner" // empty') == "$token" ]]; then
		oci --region "$lock_region" os object delete --namespace "$namespace" --bucket-name "$bucket" --name "$lock_name" --force
	fi
	lock_name=
}

ensure_object() {
	local region=$1 file=$2 sum=$3 status md5
	local object=$tag/$2
	md5=$(openssl dgst -md5 -binary "$work/release-$file/$file" | base64)
	status=$(oci_status "$work/object" --region "$region" os object head --namespace "$namespace" --bucket-name "$bucket" --name "$object")
	if [[ $status == 404 ]]; then
		oci --region "$region" os object put --namespace "$namespace" --bucket-name "$bucket" --name "$object" \
			--file "$work/release-$file/$file" --metadata "{\"sha256\":\"$sum\"}" --content-md5 "$md5" --no-multipart --no-overwrite >/dev/null
		status=$(oci_status "$work/object" --region "$region" os object head --namespace "$namespace" --bucket-name "$bucket" --name "$object")
	fi
	[[ $status == 200 ]] || {
		cat "$work/object.err" >&2
		die "$region: $object returned $status"
	}
	jq -e --arg sum "$sum" --arg md5 "$md5" '."opc-meta-sha256" == $sum and ."content-md5" == $md5' "$work/object" >/dev/null ||
		die "$region: $object does not hold the release bytes (sha256 $sum, MD5 $md5). Delete it with: oci --region $region os object delete --namespace $namespace --bucket-name $bucket --name $object --force, and rerun"
	echo "$region: $object holds sha256 $sum, MD5 $md5" >&2
}

find_image() {
	local region=$1 compartment=$2 arch=$3 listed
	local -a found
	listed=$(oci --region "$region" compute image list --compartment-id "$compartment" --operating-system Debian --all)
	mapfile -t found < <(jq -r --arg tag "$tag" --arg arch "$arch" '.data[]? | select(."lifecycle-state" != "DELETED" and
		."freeform-tags"."terrascale-host-image" == $tag and ."freeform-tags"."terrascale-arch" == $arch) | .id' <<<"$listed")
	((${#found[@]} <= 1)) || die "$region: ${#found[@]} $arch images carry $tag: ${found[*]}; delete all but one"
	echo "${found[0]:-}"
}

import_failure() {
	local region=$1 compartment=$2 image=$3 requests request
	requests=$(oci --region "$region" work-requests work-request list --compartment-id "$compartment" --resource-id "$image" --all)
	for request in $(jq -r '.data[]?.id' <<<"$requests"); do
		oci --region "$region" work-requests work-request-error list --work-request-id "$request" --all |
			jq -r --arg region "$region" '.data[]? | "\($region): \(.code): \(.message)"' >&2
	done
}

bad_image() {
	import_failure "$1" "$2" "$3"
	die "$1: image $3 is $4. Check that its import work request has finished, delete it with: oci --region $1 compute image delete --image-id $3, and rerun"
}

import_request() {
	oci --region "$1" work-requests work-request list --compartment-id "$2" --resource-id "$3" --all |
		jq -r '[.data[]? | select(."operation-type" == "CreateImage")] | max_by(."time-accepted") | .status // "NONE"'
}

image_state() {
	oci --region "$1" compute image get --image-id "$2" --query 'data."lifecycle-state"' --raw-output
}

wait_available() {
	local region=$1 compartment=$2 image=$3 state request
	for _ in $(seq 120); do
		state=$(image_state "$region" "$image")
		[[ $state == AVAILABLE ]] && return 0
		[[ $state == PROVISIONING || $state == IMPORTING ]] || bad_image "$region" "$compartment" "$image" "$state"
		request=$(import_request "$region" "$compartment" "$image")
		case $request in
		ACCEPTED | IN_PROGRESS) sleep 30 ;;
		*)
			state=$(image_state "$region" "$image")
			[[ $state == AVAILABLE ]] && return 0
			bad_image "$region" "$compartment" "$image" "$state with import work request $request"
			;;
		esac
	done
	die "$region: image $image is still $state after an hour; rerun to keep waiting"
}

set_capabilities() {
	local region=$1 compartment=$2 image=$3 listed count schema current version
	listed=$(oci --region "$region" compute image-capability-schema list --compartment-id "$compartment" --image-id "$image")
	count=$(jq -s '.[0].data // [] | length' <<<"$listed")
	if [[ $count == 0 ]]; then
		version=$(oci --region "$region" compute global-image-capability-schema list --query 'data[0]."current-version-name"' --raw-output)
		oci --region "$region" compute image-capability-schema create --compartment-id "$compartment" --image-id "$image" \
			--global-image-capability-schema-version-name "$version" --schema-data "$capabilities" >/dev/null
		echo "$region: set image capabilities from global schema version $version" >&2
		return 0
	fi
	[[ $count == 1 ]] || die "$region: image $image has $count capability schemas"
	schema=$(jq -r '.data[0].id' <<<"$listed")
	current=$(oci --region "$region" compute image-capability-schema get --image-capability-schema-id "$schema" --query 'data."schema-data"')
	if ! jq -en --argjson want "$capabilities" --argjson have "$current" '$want | to_entries |
		all(.value.defaultValue == $have[.key]."default-value" and .value.values == $have[.key].values)' >/dev/null; then
		oci --region "$region" compute image-capability-schema update --image-capability-schema-id "$schema" \
			--schema-data "$capabilities" --force >/dev/null
		echo "$region: reset image capabilities of $image" >&2
	fi
}

set_shapes() {
	local region=$1 image=$2 arch=$3 listed shape
	local -a wanted current
	mapfile -t wanted < <(jq -r 'map(.nodes.shape) | unique[]' <<<"$entries" | while read -r shape; do
		[[ $(shape_arch "$shape") != "$arch" ]] || echo "$shape"
	done)
	((${#wanted[@]})) || die "the fleet document names no $arch shape"
	listed=$(oci --region "$region" compute image-shape-compatibility-entry list --image-id "$image" --all --query 'data[].shape')
	mapfile -t current < <(jq -r '.[]' <<<"$listed")
	for shape in "${wanted[@]}"; do
		[[ " ${current[*]} " == *" $shape "* ]] ||
			oci --region "$region" compute image-shape-compatibility-entry add --image-id "$image" --shape-name "$shape" >/dev/null
	done
	for shape in "${current[@]}"; do
		[[ $(shape_arch "$shape") == "$arch" || $shape == *.Generic ]] ||
			oci --region "$region" compute image-shape-compatibility-entry remove --image-id "$image" --shape-name "$shape" --force >/dev/null
	done
}

publish() {
	local label region compartment shape arch file sum image tagged state
	read -r label region compartment shape < <(jq -r --arg label "$1" \
		'map(select(.label == $label)) | .[0] // error("no fleet region \($label)") |
		[.label, .oci_region, .compartment_id, .nodes.shape] | @tsv' <<<"$entries")
	arch=$(shape_arch "$shape")
	file=ts-host-debian$debian-$arch.qcow2
	sum=$(verified_sum "$file")
	ensure_bucket "$region"
	acquire_lock "$region" "locks/$tag-$label-$arch"
	image=$(find_image "$region" "$compartment" "$arch")
	if [[ -n $image ]]; then
		state=$(image_state "$region" "$image")
		case $state in
		AVAILABLE | PROVISIONING | IMPORTING) ;;
		*) bad_image "$region" "$compartment" "$image" "$state" ;;
		esac
		tagged=$(oci --region "$region" compute image get --image-id "$image" --query 'data."freeform-tags"."terrascale-sha256"' --raw-output)
		[[ $tagged == "$sum" ]] || die "$label: image $image is tagged sha256 $tagged, the release has $sum"
		echo "$label: found $file of $tag as $image ($state)" >&2
	fi
	if [[ -z $image ]]; then
		ensure_object "$region" "$file" "$sum"
		image=$(oci --region "$region" compute image import from-object --namespace "$namespace" --bucket-name "$bucket" \
			--name "$tag/$file" --compartment-id "$compartment" --display-name "${file%.qcow2}-$tag" --source-image-type QCOW2 \
			--launch-mode PARAVIRTUALIZED --operating-system Debian --operating-system-version "$debian" \
			--freeform-tags "$(jq -cn --arg tag "$tag" --arg arch "$arch" --arg sum "$sum" \
				'{"terrascale-host-image": $tag, "terrascale-arch": $arch, "terrascale-sha256": $sum}')" \
			--query data.id --raw-output)
		echo "$label: importing $file of $tag as $image" >&2
	fi
	wait_available "$region" "$compartment" "$image"
	set_capabilities "$region" "$compartment" "$image"
	set_shapes "$region" "$image" "$arch"
	release_lock
	jq -cn --arg label "$label" --arg arch "$arch" --arg image "$image" --arg debian "$debian" --arg sum "$sum" \
		'{label: $label, arch: $arch, image_ocid: $image, debian: $debian, sha256: $sum}'
}

for label in "${labels[@]}"; do
	publish "$label"
done
