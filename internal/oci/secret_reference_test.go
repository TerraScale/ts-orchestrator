package oci

import "testing"

func TestSecretVersionReferenceRequiresVaultSecretAndExactVersion(t *testing.T) {
	valid := SecretVersionReference{
		SecretOCID:    "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		VersionNumber: 1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("canonical synthetic Vault secret version rejected: %v", err)
	}

	for _, reference := range []SecretVersionReference{
		{SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.synthetic", VersionNumber: 1},
		{SecretOCID: valid.SecretOCID, VersionNumber: 0},
	} {
		if err := reference.Validate(); err == nil {
			t.Fatalf("invalid Vault secret reference accepted: %+v", reference)
		}
	}
}
