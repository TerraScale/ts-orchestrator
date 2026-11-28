locals {
  terrabase             = jsondecode(file("${path.module}/../deploy/services/terrabase.json"))
  storage_namespace     = local.fleet.oci.registry.namespace
  backup_bucket_name    = local.terrabase.env.BUCKET_NAME
  backup_oci_region     = local.terrabase.env.AWS_REGION
  backup_compartment_id = one([for region in local.fleet.regions : region.compartmentId if region.ociRegion == local.backup_oci_region])
}

import {
  provider = oci.region[local.backup_oci_region]
  to       = oci_objectstorage_bucket.backups
  id       = "n/${local.storage_namespace}/b/${local.backup_bucket_name}"
}

resource "oci_objectstorage_bucket" "backups" {
  provider = oci.region[local.backup_oci_region]

  compartment_id        = local.backup_compartment_id
  namespace             = local.storage_namespace
  name                  = local.backup_bucket_name
  access_type           = "NoPublicAccess"
  storage_tier          = "Standard"
  versioning            = "Suspended"
  object_events_enabled = false

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [defined_tags, retention_rules]
  }
}
