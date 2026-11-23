locals {
  fleet          = jsondecode(file("${path.module}/../deploy/fleet.json"))
  netbird        = jsondecode(file("${path.module}/../deploy/services/netbird-server.json"))
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

module "region" {
  source   = "./modules/region"
  for_each = local.regions

  providers = {
    oci = oci.region[each.value.ociRegion]
  }

  label               = each.key
  tenancy_id          = local.fleet.oci.tenancyId
  compartment_id      = each.value.compartmentId
  vcn_cidr            = each.value.network.vcnCidr
  public_subnet_cidr  = each.value.network.publicSubnetCidr
  private_subnet_cidr = each.value.network.privateSubnetCidr
  netbird_udp_ports   = contains(local.netbird.regions, each.key) ? local.netbird.udpPorts : []
  stateful_count      = each.value.pools.stateful.count
  stateful_shape      = each.value.pools.stateful.shape
  stateful_data_gib   = each.value.pools.stateful.dataGiB
  stateful_data_vpus  = each.value.pools.stateful.dataVpusPerGiB
  worker_min          = each.value.pools.worker.min
  worker_max          = each.value.pools.worker.max
  worker_shape        = each.value.pools.worker.shape
  boot_script         = local.boot_script
  bundle_url          = local.bundle_url
  bundle_sha256       = var.orch_bundle_sha256
}

module "geodns" {
  source = "./modules/geodns"

  providers = {
    oci = oci.dns
  }

  compartment_id    = local.fleet.dns.compartmentId
  zone              = local.fleet.dns.zone
  steered_names     = local.fleet.dns.steeredNames
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
