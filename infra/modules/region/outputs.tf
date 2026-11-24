output "nlb_id" {
  description = "OCI Network Load Balancer OCID."
  value       = oci_network_load_balancer_network_load_balancer.this.id
}

output "nlb_ip" {
  description = "Reserved public IPv4 address of the regional Network Load Balancer."
  value       = oci_core_public_ip.nlb.ip_address
}

output "instance_pool_id" {
  description = "Stateless worker Instance Pool OCID the backplane resizes."
  value       = oci_core_instance_pool.worker.id
}

output "stateful_instance_ids" {
  description = "Stateful node instance OCIDs."
  value       = oci_core_instance.stateful[*].id
}

output "stateful_private_ips" {
  description = "Private VCN IPv4 addresses of stateful nodes."
  value       = oci_core_instance.stateful[*].private_ip
}

output "stateful_volume_ids" {
  description = "Persistent stateful data volume OCIDs the backplane grows online."
  value       = oci_core_volume.stateful_data[*].id
}
