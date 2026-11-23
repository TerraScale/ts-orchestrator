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

output "regional_api_fqdns" {
  description = "Region label to regional API A record name."
  value       = { for label, record in oci_dns_rrset.regional_api : label => record.domain }
}
