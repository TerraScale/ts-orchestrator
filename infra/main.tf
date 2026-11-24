locals {
  fleet          = jsondecode(file("${path.module}/../deploy/fleet.json"))
  netbird        = jsondecode(file("${path.module}/../deploy/services/netbird-server.json"))
  auth           = jsondecode(file("${path.module}/../deploy/services/ts-auth.json"))
  regions        = { for region in local.fleet.regions : region.label => region }
  dns_oci_region = one([for region in local.fleet.regions : region.ociRegion if region.compartmentId == local.fleet.dns.compartmentId])
  bundle_url     = "https://github.com/TerraScale/ts-orchestrator/releases/download/${var.orch_release_tag}/ts-orch.tar.gz"
  boot_script    = file("${path.module}/../deploy/cloud-init/node-boot.sh")
}

provider "oci" {
  alias    = "region"
  for_each = toset([for region in local.fleet.regions : region.ociRegion])
  region   = each.key
}

provider "oci" {
  alias  = "dns"
  region = local.dns_oci_region
}

provider "oci" {
  alias  = "home"
  region = local.fleet.oci.vault.region
}

module "region" {
  source   = "./modules/region"
  for_each = local.regions

  providers = {
    oci = oci.region[each.value.ociRegion]
  }

  label                  = each.key
  tenancy_id             = local.fleet.oci.tenancyId
  compartment_id         = each.value.compartmentId
  vcn_cidr               = each.value.network.vcnCidr
  public_subnet_cidr     = each.value.network.publicSubnetCidr
  private_subnet_cidr    = each.value.network.privateSubnetCidr
  netbird_udp_ports      = contains(local.netbird.regions, each.key) ? local.netbird.udpPorts : []
  stateful_count         = each.value.pools.stateful.count
  stateful_fault_domains = lookup(var.stateful_fault_domains, each.key, ["FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"])
  stateful_shape         = each.value.pools.stateful.shape
  stateful_data_gib      = each.value.pools.stateful.dataGiB
  stateful_data_vpus     = each.value.pools.stateful.dataVpusPerGiB
  worker_min             = each.value.pools.worker.min
  worker_max             = each.value.pools.worker.max
  worker_shape           = each.value.pools.worker.shape
  boot_script            = local.boot_script
  release_tag            = var.orch_release_tag
  bundle_url             = local.bundle_url
  bundle_sha256          = var.orch_bundle_sha256
  custom_image_id        = lookup(var.custom_image_ids, each.key, "")
  enroll_vault_id        = local.fleet.oci.vault.vaultId
  enroll_secret_name     = "ts-orch-node-enroll"

  netbird_management_url   = local.fleet.netbird.managementUrl
  netbird_setup_key_secret = local.fleet.netbird.setupKeySecret
}

module "geodns" {
  source = "./modules/geodns"

  providers = {
    oci = oci.dns
  }

  compartment_id = local.fleet.dns.compartmentId
  zone           = local.fleet.dns.zone
  steered_names  = local.fleet.dns.steeredNames
  pinned_names = {
    "auth.${local.fleet.dns.zone}"    = one(local.auth.regions)
    "netbird.${local.fleet.dns.zone}" = one(local.netbird.regions)
  }
  ttl_seconds       = local.fleet.dns.ttlSeconds
  health_check_path = local.fleet.dns.healthCheckPath
  rollout_order     = local.fleet.rolloutOrder

  regions = {
    for label, region in local.regions : label => {
      nlb_ip     = module.region[label].nlb_ip
      continents = region.location.continents
    }
  }
}
