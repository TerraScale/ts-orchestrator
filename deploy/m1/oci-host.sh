#!/usr/bin/env bash
# Create a milestone 1 cell's compartment, network and single host, then print
# the host's public IP. Re-running creates nothing that exists.
#   deploy/m1/oci-host.sh <ts-orch-binary> <cell> <oci-region> <ssh-public-key>
# Example: deploy/m1/oci-host.sh ./ts-orch sjc-1 us-sanjose-1 ~/.ssh/key.pub
# The network is ts-orch's (`oci-region network`). The compartment and the
# instance use the oci CLI: ts-orch creates them only inside the full region
# foundation, which also creates a per-region Vault, HSM key and buckets that
# m1 does not use (one Vault in gru serves every region).
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 <ts-orch-binary> <cell> <oci-region> <ssh-public-key>" >&2
	exit 2
fi
tsorch=$1 cell=$2 region=$3 key=$4
[[ $cell =~ ^[a-z]{3}-1$ ]] || { echo "cell must look like sjc-1" >&2; exit 2; }
node="ts-${cell%-1}-1"
shape=VM.Standard.A1.Flex

tenancy=$(oci iam compartment list --query 'data[0]."compartment-id"' --raw-output)
parent=$(oci iam compartment list -c "$tenancy" --name TerraScale --lifecycle-state ACTIVE --query 'data[0].id' --raw-output)
comp=$(oci iam compartment list -c "$parent" --name "$cell-control" --lifecycle-state ACTIVE --query 'data[0].id' --raw-output)
if [[ -z $comp ]]; then
	comp=$(oci iam compartment create -c "$parent" --name "$cell-control" \
		--description "TerraScale $cell control plane" --wait-for-state ACTIVE --query 'data.id' --raw-output)
	echo "created compartment $cell-control $comp"
fi
# A new compartment takes a while to reach the other regions.
for i in 1 2 3 4 5 6 7 8 9; do
	"$tsorch" oci-region network "$cell" --apply && break
	((i < 9)) || exit 1
	sleep 20
done

found=$(oci compute instance list --region "$region" -c "$comp" --display-name "$node" \
	--query 'data[?"lifecycle-state"!=`TERMINATED`].id | [0]' --raw-output)
if [[ -z $found ]]; then
	image=$(oci compute image list --region "$region" -c "$comp" --operating-system "Canonical Ubuntu" \
		--operating-system-version 24.04 --shape "$shape" --sort-by TIMECREATED --sort-order DESC --all \
		--query 'data[?contains("display-name", `aarch64`) && !contains("display-name", `Minimal`)].id | [0]' --raw-output)
	subnet=$(oci network subnet list --region "$region" -c "$comp" --display-name "$cell-host-subnet" --query 'data[0].id' --raw-output)
	nsgs=$(oci network nsg list --region "$region" -c "$comp" --all \
		--query "data[?starts_with(\"display-name\", '$cell-')].id" --output json)
	# Out of host capacity in one AD: try the next, at most twice.
	tries=0
	for ad in $(oci iam availability-domain list --region "$region" --query 'data[].name' --raw-output | tr -d '[],"'); do
		if found=$(oci compute instance launch --region "$region" -c "$comp" --availability-domain "$ad" \
			--display-name "$node" --hostname-label "$node" --shape "$shape" \
			--shape-config '{"ocpus":2,"memoryInGBs":12}' --image-id "$image" --boot-volume-size-in-gbs 50 \
			--subnet-id "$subnet" --assign-public-ip true --nsg-ids "$nsgs" --ssh-authorized-keys-file "$key" \
			--wait-for-state RUNNING --query 'data.id' --raw-output); then
			echo "launched $node $found in $ad"
			break
		fi
		found=""
		((++tries < 2)) || break
	done
	[[ -n $found ]] || { echo "launch of $node failed" >&2; exit 1; }
fi
"$tsorch" oci-region network "$cell" --apply
oci compute instance list-vnics --region "$region" --instance-id "$found" --query 'data[0]."public-ip"' --raw-output
