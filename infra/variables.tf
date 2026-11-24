variable "orch_release_tag" {
  type        = string
  description = "GitHub release tag of the ts-orch IL bundle that new nodes boot, always v2-<commit sha>."

  validation {
    condition     = can(regex("^v2-[0-9a-f]{40}$", var.orch_release_tag))
    error_message = "orch_release_tag must be v2-<40 hex commit sha>; ci-* tags belong to the v1 fleet."
  }
}

variable "orch_bundle_sha256" {
  type        = string
  description = "SHA-256 of ts-orch.tar.gz published with orch_release_tag."

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.orch_bundle_sha256))
    error_message = "orch_bundle_sha256 must be 64 lowercase hex characters."
  }
}

variable "custom_image_ids" {
  type        = map(string)
  description = "Optional map of region label to pre-baked custom Ubuntu 24.04 ARM64 OCI image OCID."
  default     = {}
}
