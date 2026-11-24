variable "label" {
  type        = string
  description = "Short TerraScale region label such as gru, fra or sjc."

  validation {
    condition     = can(regex("^[a-z]{3}$", var.label))
    error_message = "label must be three lowercase letters."
  }
}

variable "tenancy_id" {
  type        = string
  description = "OCI tenancy OCID used to list availability domains."
}

variable "compartment_id" {
  type        = string
  description = "OCI compartment OCID that owns every regional resource."
}

variable "vcn_cidr" {
  type        = string
  description = "Regional VCN CIDR."
}

variable "public_subnet_cidr" {
  type        = string
  description = "Public subnet CIDR hosting only the network load balancer."
}

variable "private_subnet_cidr" {
  type        = string
  description = "Private subnet CIDR hosting every node."
}

variable "netbird_udp_ports" {
  type        = list(number)
  description = "NetBird UDP ports opened on nodes in regions that host netbird-server; empty elsewhere."
  default     = []
}

variable "netbird_management_url" {
  type        = string
  description = "NetBird management URL every node enrolls into."
}

variable "netbird_setup_key_secret" {
  type        = string
  description = "Name of the NetBird node setup key secret inside the enrollment OCI Vault."
}

variable "stateful_count" {
  type        = number
  description = "Number of stateful nodes with persistent data volumes."
  default     = 2

  validation {
    condition     = var.stateful_count >= 1 && floor(var.stateful_count) == var.stateful_count
    error_message = "stateful_count must be a whole number of at least 1."
  }
}

variable "stateful_fault_domains" {
  type        = list(string)
  description = "Ordered OCI fault domains assigned round-robin to stateful instances."
  default     = ["FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]

  validation {
    condition     = length(var.stateful_fault_domains) >= 1
    error_message = "stateful_fault_domains must list at least one fault domain."
  }
}

variable "stateful_shape" {
  type = object({
    name      = string
    ocpus     = number
    memoryGiB = number
    bootGiB   = number
  })
  description = "Flex shape for stateful nodes."
}

variable "stateful_data_gib" {
  type        = number
  description = "Initial size of each stateful data volume; the backplane grows it online afterwards."
  default     = 50

  validation {
    condition     = var.stateful_data_gib >= 50
    error_message = "stateful_data_gib must be at least 50."
  }
}

variable "stateful_data_vpus" {
  type        = number
  description = "Baseline VPUs per GB for stateful data volumes."
  default     = 10
}

variable "worker_min" {
  type        = number
  description = "Initial stateless worker pool size; the backplane owns the live size afterwards."
  default     = 0

  validation {
    condition     = var.worker_min >= 0 && var.worker_min <= 1
    error_message = "worker_min must be 0 or 1."
  }
}

variable "worker_max" {
  type        = number
  description = "Upper bound the backplane autoscaler may grow the worker pool to."
  default     = 50

  validation {
    condition     = var.worker_max >= 1 && var.worker_max <= 50
    error_message = "worker_max must be between 1 and 50."
  }
}

variable "worker_shape" {
  type = object({
    name      = string
    ocpus     = number
    memoryGiB = number
    bootGiB   = number
  })
  description = "Flex shape for stateless worker pool instances."
}

variable "boot_script" {
  type        = string
  description = "Arch-neutral cloud-init node boot script."
}

variable "release_tag" {
  type        = string
  description = "GitHub release tag of the ts-orch IL bundle."
}

variable "bundle_url" {
  type        = string
  description = "Download URL of the ts-orch IL bundle."
}

variable "bundle_sha256" {
  type        = string
  description = "SHA-256 of the ts-orch IL bundle."
}

variable "custom_image_id" {
  type        = string
  description = "Optional pre-baked custom Ubuntu 24.04 ARM64 OCI image OCID for this region."
  default     = ""
}

variable "enroll_vault_id" {
  type        = string
  description = "OCI Vault OCID holding the node enrollment secret, read by nodes through instance principal."
}

variable "enroll_secret_name" {
  type        = string
  description = "Name of the node enrollment secret inside the OCI Vault."
}
