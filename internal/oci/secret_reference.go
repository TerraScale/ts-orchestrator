package oci

import "errors"

// SecretVersionReference identifies one immutable OCI Vault secret version.
// It is safe to carry in signed placement and host desired state.
type SecretVersionReference struct {
	SecretOCID    string `json:"secret_ocid"`
	VersionNumber int64  `json:"version_number"`
}

func (reference SecretVersionReference) Validate() error {
	if !isOCID(reference.SecretOCID, "secret") || reference.VersionNumber <= 0 {
		return errors.New("OCI Vault secret reference requires an exact version")
	}
	return nil
}
