output "zone_id" {
  description = "OCI DNS zone OCID."
  value       = oci_dns_zone.this.id
}

output "nameservers" {
  description = "Authoritative nameservers to delegate the zone to."
  value       = oci_dns_zone.this.nameservers[*].hostname
}

output "health_monitor_id" {
  description = "Shared HTTP health check monitor OCID."
  value       = oci_health_checks_http_monitor.readyz.id
}

output "pinned_fqdns" {
  description = "Single-region name to the region label whose NLB answers it."
  value       = { for name, record in oci_dns_rrset.pinned : name => var.pinned_names[name] }
}

output "regional_api_fqdns" {
  description = "Region label to regional API A record name."
  value       = { for label, record in oci_dns_rrset.regional_api : label => record.domain }
}

output "regional_pg_fqdns" {
  description = "Region label to regional PostgreSQL A record name."
  value       = { for label, record in oci_dns_rrset.regional_pg : label => record.domain }
}
