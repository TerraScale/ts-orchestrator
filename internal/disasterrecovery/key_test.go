package disasterrecovery

import (
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

func TestKMSEndpointsBindRegionAndSupportBothOCIDomains(t *testing.T) {
	for _, operation := range []string{"management", "crypto"} {
		for _, domain := range []string{"oraclecloud.com", "oci.oraclecloud.com"} {
			endpoint := "https://vault-" + operation + ".kms.us-sanjose-1." + domain
			if got, err := kmsEndpoint(&endpoint, "us-sanjose-1", operation); err != nil || got != endpoint {
				t.Fatalf("valid OCI endpoint: %q, %v", got, err)
			}
			for _, invalid := range []string{
				strings.Replace(endpoint, "us-sanjose-1", "sa-saopaulo-1", 1), endpoint + ".example.com",
				strings.Replace(endpoint, "https://", "https://user@", 1), endpoint + ":443", endpoint + "/path",
				endpoint + "?token=hidden", endpoint + "#fragment", strings.Replace(endpoint, "https://", "http://", 1),
			} {
				if _, err := kmsEndpoint(&invalid, "us-sanjose-1", operation); err == nil {
					t.Fatalf("unsafe endpoint accepted: %q", invalid)
				}
			}
		}
	}
}

func TestReplicaVaultMustOwnTheEnabledBucketKey(t *testing.T) {
	config := Region{VaultID: "vault", KeyID: "key", CompartmentID: "control"}
	key := keymanagement.Key{Id: &config.KeyID, VaultId: &config.VaultID, CompartmentId: &config.CompartmentID, LifecycleState: keymanagement.KeyLifecycleStateEnabled}
	if err := validateVaultKey(key, config); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*keymanagement.Key){
		func(k *keymanagement.Key) { k.VaultId = new("unrelated") },
		func(k *keymanagement.Key) { k.CompartmentId = new("unrelated") },
		func(k *keymanagement.Key) { k.Id = new("unrelated") },
		func(k *keymanagement.Key) { k.LifecycleState = keymanagement.KeyLifecycleStateDisabled },
	} {
		k := key
		mutate(&k)
		if err := validateVaultKey(k, config); err == nil {
			t.Fatalf("wrong Vault/key accepted: %+v", k)
		}
	}
}
