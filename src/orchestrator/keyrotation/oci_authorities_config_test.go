package keyrotation

import "testing"

func TestOCIAuthorityFileConfiguration(t *testing.T) {
	identity := OCIIdentityIssuerFileConfig{Region: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1..fixture", CertificateAuthorityID: "ocid1.certificateauthority.oc1.sa-saopaulo-1.fixture", Principals: []OCIIdentityPrincipal{{ID: "node-a", SPIFFEID: "spiffe://terrascale/node-a"}}}
	if err := identity.Validate(); err != nil {
		t.Fatal(err)
	}
	identity.Principals = append(identity.Principals, OCIIdentityPrincipal{ID: "node-b", SPIFFEID: "spiffe://terrascale/node-a"})
	if identity.Validate() == nil {
		t.Fatal("duplicate principal credential accepted")
	}
	vault := OCICapabilityVaultFileConfig{Region: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1..fixture", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.fixture", KeyID: "ocid1.key.oc1.sa-saopaulo-1.fixture"}
	if err := vault.Validate(); err != nil {
		t.Fatal(err)
	}
	vault.KeyID = vault.VaultID
	if vault.Validate() == nil {
		t.Fatal("wrong OCI resource type accepted")
	}
}
