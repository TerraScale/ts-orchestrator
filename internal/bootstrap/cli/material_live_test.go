package cli

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

func TestMaterialLiveTargetRequiresExactActiveOCIResources(t *testing.T) {
	readback := manualFoundationReadback{
		OCIRegion: "sa-saopaulo-1", ControlCompartmentID: "ocid1.compartment.oc1..control",
		VaultID: "ocid1.vault.oc1.sa-saopaulo-1.vault", KeyID: "ocid1.key.oc1.sa-saopaulo-1.key",
	}
	compartment := identity.Compartment{Id: new(readback.ControlCompartmentID),
		LifecycleState: identity.CompartmentLifecycleStateActive}
	if !liveMaterialCompartmentMatches(readback.ControlCompartmentID, compartment) {
		t.Fatal("exact active compartment rejected")
	}
	compartment.LifecycleState = identity.CompartmentLifecycleStateDeleting
	if liveMaterialCompartmentMatches(readback.ControlCompartmentID, compartment) {
		t.Fatal("deleting compartment accepted")
	}
	vault := keymanagement.Vault{Id: new(readback.VaultID), CompartmentId: new(readback.ControlCompartmentID),
		LifecycleState:     keymanagement.VaultLifecycleStateActive,
		VaultType:          keymanagement.VaultVaultTypeDefault,
		ManagementEndpoint: new("https://vault-management.kms.sa-saopaulo-1.oraclecloud.com")}
	if _, err := liveMaterialVaultEndpoint(readback, vault); err != nil {
		t.Fatalf("exact active Vault rejected: %v", err)
	}
	vault.ManagementEndpoint = new("https://vault-management.kms.other-region.oraclecloud.com")
	if _, err := liveMaterialVaultEndpoint(readback, vault); err == nil {
		t.Fatal("out-of-region Vault management endpoint accepted")
	}
	vault.ManagementEndpoint = new("https://vault-management.kms.sa-saopaulo-1.oraclecloud.com")
	vault.CompartmentId = new("ocid1.compartment.oc1..other")
	if _, err := liveMaterialVaultEndpoint(readback, vault); err == nil {
		t.Fatal("Vault in a different compartment accepted")
	}
	key := keymanagement.Key{Id: new(readback.KeyID), CompartmentId: new(readback.ControlCompartmentID),
		VaultId: new(readback.VaultID), LifecycleState: keymanagement.KeyLifecycleStateEnabled,
		ProtectionMode: keymanagement.KeyProtectionModeHsm,
		KeyShape:       &keymanagement.KeyShape{Algorithm: keymanagement.KeyShapeAlgorithmAes, Length: new(32)}}
	if !liveMaterialKeyMatches(readback, key) {
		t.Fatal("exact enabled HSM AES-256 key rejected")
	}
	key.VaultId = new("ocid1.vault.oc1.sa-saopaulo-1.other")
	if liveMaterialKeyMatches(readback, key) {
		t.Fatal("key in a different Vault accepted")
	}
	key.VaultId = new(readback.VaultID)
	key.ProtectionMode = keymanagement.KeyProtectionModeSoftware
	if liveMaterialKeyMatches(readback, key) {
		t.Fatal("software key accepted")
	}
}

func TestMaterialVaultEndpointFollowsMappedRegion(t *testing.T) {
	for _, region := range []string{"us-sanjose-1", "eu-frankfurt-1"} {
		t.Run(region, func(t *testing.T) {
			readback := manualFoundationReadback{OCIRegion: region,
				ControlCompartmentID: "ocid1.compartment.oc1..control",
				VaultID:              "ocid1.vault.oc1." + region + ".vault"}
			vault := keymanagement.Vault{Id: new(readback.VaultID),
				CompartmentId:      new(readback.ControlCompartmentID),
				LifecycleState:     keymanagement.VaultLifecycleStateActive,
				VaultType:          keymanagement.VaultVaultTypeDefault,
				ManagementEndpoint: new("https://vault-management.kms." + region + ".oraclecloud.com")}
			if _, err := liveMaterialVaultEndpoint(readback, vault); err != nil {
				t.Fatalf("mapped Vault endpoint rejected: %v", err)
			}
			vault.ManagementEndpoint = new("https://vault-management.kms.sa-saopaulo-1.oraclecloud.com")
			if _, err := liveMaterialVaultEndpoint(readback, vault); err == nil {
				t.Fatal("cross-region Vault endpoint accepted")
			}
		})
	}
}
