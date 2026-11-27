output "regions" {
  description = "Per-region static foundation identifiers consumed by the backplane."
  value = {
    for label, region in module.region : label => {
      nlb_ip                = region.nlb_ip
      nlb_id                = region.nlb_id
      instance_pool_id      = region.instance_pool_id
      stateful_instance_ids = region.stateful_instance_ids
      stateful_private_ips  = region.stateful_private_ips
      stateful_volume_ids   = region.stateful_volume_ids
    }
  }
}

output "geodns" {
  description = "Geo-steered DNS zone, health monitor and regional API records."
  value = {
    zone_id           = module.geodns.zone_id
    zone_nameservers  = module.geodns.nameservers
    health_monitor_id = module.geodns.health_monitor_id
    regional_api_fqdn = module.geodns.regional_api_fqdns
    regional_pg_fqdn  = module.geodns.regional_pg_fqdns
    pinned_fqdns      = module.geodns.pinned_fqdns
  }
}

output "backups" {
  description = "Object Storage bucket TerraBase archives commit logs and snapshots into."
  value = {
    namespace  = oci_objectstorage_bucket.backups.namespace
    name       = oci_objectstorage_bucket.backups.name
    region     = local.backup_oci_region
    versioning = oci_objectstorage_bucket.backups.versioning
  }
}
