#!/usr/bin/env bash
# Let every milestone 1 host read gru-vault (the one Vault for all regions)
# and create ts-orch-mesh-key in it. Re-running converges the dynamic group
# and policy to exactly this.
#   deploy/m1/oci-iam.sh <cell>...      e.g. deploy/m1/oci-iam.sh gru-1 sjc-1 fra-1
# shortcut: oci CLI, because ts-orch's IAM code lives in the full region
# foundation (per-region Vault and buckets); move it there when m1 adopts it.
set -euo pipefail

[[ $# -ge 1 ]] || { echo "usage: $0 <cell>..." >&2; exit 2; }
home=sa-saopaulo-1
tenancy=$(oci iam compartment list --query 'data[0]."compartment-id"' --raw-output)
parent=$(oci iam compartment list -c "$tenancy" --name TerraScale --lifecycle-state ACTIVE --query 'data[0].id' --raw-output)
compartment() { oci iam compartment list -c "$parent" --name "$1-control" --lifecycle-state ACTIVE --query 'data[0].id' --raw-output; }

rule=""
for cell in "$@"; do
	id=$(compartment "$cell")
	[[ -n $id ]] || { echo "no compartment $cell-control" >&2; exit 1; }
	rule+="${rule:+, }instance.compartment.id = '$id'"
done
rule="ANY {$rule}"
gru=$(compartment gru-1)
vault=$(oci kms management vault list --region "$home" -c "$gru" --all \
	--query 'data[?"display-name"==`gru-vault` && "lifecycle-state"==`ACTIVE`].id | [0]' --raw-output)
key=$(oci kms management key list --region "$home" -c "$gru" --all --endpoint \
	"$(oci kms management vault get --region "$home" --vault-id "$vault" --query 'data."management-endpoint"' --raw-output)" \
	--query 'data[?"display-name"==`gru-vault-master` && "lifecycle-state"==`ENABLED`].id | [0]' --raw-output)
statements=$(printf '%s\n' \
	"Allow dynamic-group ts-orch-hosts to read secret-bundles in compartment id $gru where target.vault.id = '$vault'" \
	"Allow dynamic-group ts-orch-hosts to read vaults in compartment id $gru where target.vault.id = '$vault'" \
	"Allow dynamic-group ts-orch-hosts to inspect secrets in compartment id $gru" \
	"Allow dynamic-group ts-orch-hosts to manage secret-family in compartment id $gru where all {target.vault.id = '$vault', target.secret.name = 'ts-orch-mesh-key'}" \
	"Allow dynamic-group ts-orch-hosts to use vaults in compartment id $gru where target.vault.id = '$vault'" \
	"Allow dynamic-group ts-orch-hosts to use keys in compartment id $gru where target.key.id = '$key'" |
	python3 -I -c 'import json,sys; print(json.dumps(sys.stdin.read().splitlines()))')

dg=$(oci iam dynamic-group list --name ts-orch-hosts --query 'data[0].id' --raw-output)
if [[ -z $dg ]]; then
	oci iam dynamic-group create --name ts-orch-hosts --description "ts-orch hosts of every region" \
		--matching-rule "$rule" --wait-for-state ACTIVE --query 'data.id' --raw-output
else
	oci iam dynamic-group update --dynamic-group-id "$dg" --matching-rule "$rule" --force --query 'data.id' --raw-output
fi
policy=$(oci iam policy list -c "$gru" --name ts-orch-hosts-vault --query 'data[0].id' --raw-output)
if [[ -z $policy ]]; then
	oci iam policy create -c "$gru" --name ts-orch-hosts-vault --description "ts-orch hosts read gru-vault" \
		--statements "$statements" --wait-for-state ACTIVE --query 'data.id' --raw-output
else
	oci iam policy update --policy-id "$policy" --statements "$statements" --force --query 'data.id' --raw-output
fi
