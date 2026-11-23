variable "compartment_id" {
  type        = string
  description = "OCI compartment OCID that owns the DNS zone, steering policies and health monitor."
}

variable "zone" {
  type        = string
  description = "Geo-steered DNS zone name."
}

variable "steered_names" {
  type        = list(string)
  description = "Fully qualified names inside the zone answered by continent geo-steering."

  validation {
    condition     = length(var.steered_names) > 0
    error_message = "steered_names must not be empty."
  }
}

variable "ttl_seconds" {
  type        = number
  description = "TTL for steered answers and regional records."
}

variable "health_check_path" {
  type        = string
  description = "HTTP path probed on every regional NLB on port 80."
}

variable "rollout_order" {
  type        = list(string)
  description = "Region labels in rollout order; also the fallback preference when no continent matches."
}

variable "regions" {
  type = map(object({
    nlb_ip     = string
    continents = list(string)
  }))
  description = "Region label to NLB reserved IP and served continent codes."

  validation {
    condition     = alltrue(flatten([for region in values(var.regions) : [for continent in region.continents : contains(["AF", "AN", "AS", "EU", "NA", "OC", "SA"], continent)]]))
    error_message = "continents must be two-letter continent codes: AF, AN, AS, EU, NA, OC or SA."
  }
}
