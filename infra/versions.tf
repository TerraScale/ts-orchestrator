terraform {
  required_version = ">= 1.13.0"

  backend "s3" {}

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 7.0.0, < 9.0.0"
    }
  }
}
