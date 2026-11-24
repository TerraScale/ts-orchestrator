locals {
  node_compartment_rules = [
    for region in local.fleet.regions :
    "instance.compartment.id = '${region.compartmentId}'"
  ]
  vault_compartment_id = one([
    for region in local.fleet.regions : region.compartmentId
    if region.ociRegion == local.fleet.oci.vault.region
  ])
}

resource "oci_identity_dynamic_group" "ts_orch_nodes" {
  provider       = oci.home
  compartment_id = local.fleet.oci.tenancyId
  name           = "ts-orch-nodes"
  description    = "TerraScale orchestrator nodes across all regional compartments"
  matching_rule  = "Any {${join(", ", local.node_compartment_rules)}}"
}

resource "oci_identity_policy" "ts_orch_nodes" {
  provider       = oci.home
  compartment_id = local.fleet.oci.tenancyId
  name           = "ts-orch-nodes-policy"
  description    = "Allow TerraScale orchestrator nodes to read Vault secret bundles"
  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.ts_orch_nodes.name} to read secret-bundles in compartment id ${local.vault_compartment_id}"
  ]
}
