package app

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
)

// TestWorkloadProfileSecretsStayWithTheirRole refuses a signed profile whose
// secrets reach another role's Vault secrets, a TerraBase profile with any but
// secret files, and one that sets the host's NATS identity settings.
func TestWorkloadProfileSecretsStayWithTheirRole(t *testing.T) {
	ref := func(name string) map[string]vaultsecret.Ref {
		return map[string]vaultsecret.Ref{"TOKEN": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: name}}
	}
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	if err := validateWorkloadProfiles("gru", map[string]WorkloadProfile{"billing": {Resources: resources, Secrets: ref("gru-1-billing-token")}}); err != nil {
		t.Fatal(err)
	}
	file := map[string]vaultsecret.Ref{"TERRABASE_BACKUP_SECRET_KEY_FILE": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: "gru-1-terrabase-backup-secret-key"}}
	if err := validateWorkloadProfiles("gru", map[string]WorkloadProfile{"terrabase": {Resources: resources, Secrets: file}}); err != nil {
		t.Fatalf("a TerraBase secret file was refused: %v", err)
	}
	for name, profiles := range map[string]map[string]WorkloadProfile{
		"other role":     {"billing": {Resources: resources, Secrets: ref("gru-1-netbird-admin-pat")}},
		"terrabase":      {"terrabase": {Resources: resources, Secrets: ref("gru-1-terrabase-token")}},
		"terrabase nats": {"terrabase": {Resources: resources, Env: map[string]string{"TERRABASE_NATS_URL": "tls://x:4222"}}},
		"also env":       {"billing": {Resources: resources, Env: map[string]string{"TOKEN": "x"}, Secrets: ref("gru-1-billing-token")}},
		// gru-1-billing-eu-token would be ambiguous between the two roles.
		"longer role": {"billing": {Resources: resources, Secrets: ref("gru-1-billing-eu-token")}, "billing-eu": {Resources: resources}},
	} {
		if err := validateWorkloadProfiles("gru", profiles); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// bundles is an OCI Vault holding secrets by name.
type bundles map[string]string

// resolve reads refs from b as a host agent reads them from the Vault.
func (b bundles) resolve(ctx context.Context, refs map[string]vaultsecret.Ref) (map[string]string, error) {
	return vaultsecret.Resolve(ctx, refs, func(string) (vaultsecret.BundleClient, error) { return b, nil })
}

func (b bundles) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	value, ok := b[*request.SecretName]
	if !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, errors.New("no such secret")
	}
	content := base64.StdEncoding.EncodeToString([]byte(value))
	return ocisecrets.GetSecretBundleByNameResponse{SecretBundle: ocisecrets.SecretBundle{
		SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: &content}}}, nil
}
