package manager

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

var serverTarget = vaultsecret.Target{
	CompartmentID: "ocid1.compartment.oc1..aaaaaaaaserver",
	VaultID:       "ocid1.vault.oc1.sa-saopaulo-1.aaaaaaaaserver",
	KeyID:         "ocid1.key.oc1.sa-saopaulo-1.aaaaaaaaserver",
}

// memVault keeps one Vault's secrets in memory, as OCI does for one vault.
type memVault struct {
	items   []ocivault.SecretSummary
	bundles map[string]ocisecrets.Base64SecretBundleContentDetails
	creates int
}

func newMemVault() *memVault {
	return &memVault{bundles: map[string]ocisecrets.Base64SecretBundleContentDetails{}}
}

func (v *memVault) ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error) {
	return ocivault.ListSecretsResponse{Items: v.items}, nil
}

func (v *memVault) CreateSecret(_ context.Context, request ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error) {
	v.creates++
	details := request.CreateSecretDetails
	content := details.SecretContent.(ocivault.Base64SecretContentDetails)
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaa" + strconv.Itoa(len(v.items)+1)
	v.items = append(v.items, ocivault.SecretSummary{Id: new(id), SecretName: details.SecretName,
		LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
	v.bundles[*details.SecretName] = ocisecrets.Base64SecretBundleContentDetails{Content: content.Content}
	return ocivault.CreateSecretResponse{Secret: ocivault.Secret{Id: new(id)}}, nil
}

func (v *memVault) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	content, ok := v.bundles[*request.SecretName]
	if !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, errors.New("secret not found")
	}
	return ocisecrets.GetSecretBundleByNameResponse{SecretBundle: ocisecrets.SecretBundle{SecretBundleContent: content}}, nil
}

func TestServerBootstrapClaimsOnceAndStoresSecretsWithoutLeakingThem(t *testing.T) {
	f := newFakeManager(t)
	f.policies = []apiPolicy{{ID: "pol-default", Name: "Default", Enabled: true}}
	vault := newMemVault()
	server := ServerVault{Target: serverTarget, Management: vault, Bundles: vault}
	if err := PrepareServer(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gru-1-netbird-relay-auth-secret", "gru-1-netbird-session-cookie-key",
		"gru-1-netbird-datastore-encryption-key", "gru-1-netbird-owner-password"} {
		if _, ok := vault.bundles[name]; !ok {
			t.Fatalf("PrepareServer did not store %s", name)
		}
	}
	owner, err := vaultsecret.Read(t.Context(), vault, serverTarget.VaultID, ownerSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil {
		t.Fatal(err)
	}
	// Values are never printed: a mismatch names the field only.
	if len(f.setups) != 1 || f.setups[0].Email != ownerEmail || f.setups[0].Password != owner || !f.setups[0].CreatePAT {
		t.Fatalf("setup requests: %d, want one owner claim with the Vault password", len(f.setups))
	}
	if f.setupRequired || slices.ContainsFunc(f.policies, func(p apiPolicy) bool { return p.Name == "Default" }) {
		t.Fatal("setup did not finish or the Default policy survived")
	}
	pat, err := vaultsecret.Read(t.Context(), vault, serverTarget.VaultID, adminPATSecret)
	if err != nil || pat != testPAT {
		t.Fatalf("admin PAT in Vault: matches=%t error=%v", pat == testPAT, err)
	}
	for _, name := range []string{serversKeySecret, operatorsKeySecret} {
		if _, ok := vault.bundles[name]; !ok {
			t.Fatalf("BootstrapServer did not store %s", name)
		}
	}
	creates, keys := vault.creates, len(f.setupKeys)
	if creates != 7 || keys != 2 {
		t.Fatalf("first run: %d Vault creates, %d setup keys; want 7 and 2", creates, keys)
	}
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil {
		t.Fatal(err)
	}
	if vault.creates != creates || len(f.setupKeys) != keys || len(f.setups) != 1 {
		t.Fatalf("rerun: %d Vault creates, %d setup keys, %d claims; want no change",
			vault.creates-creates, len(f.setupKeys)-keys, len(f.setups)-1)
	}
}

func TestClientPinMatchesUpstreamRelease(t *testing.T) {
	if err := client.ValidatePin(clientPin); err != nil {
		t.Fatal(err)
	}
}
