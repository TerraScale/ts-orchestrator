package vaultsecret

import (
	"context"
	"strings"
	"testing"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
)

// absentVault answers a missing secret as OCI does: HTTP 404.
type absentVault struct{ *fakeVault }

func (v absentVault) GetSecretBundleByName(ctx context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	if _, ok := v.bundles[*request.SecretName]; !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, testSecretServiceError{status: 404}
	}
	return v.fakeVault.GetSecretBundleByName(ctx, request)
}

func TestReadScopedMapsNamesAndFileKeys(t *testing.T) {
	vault := absentVault{newVault()}
	vault.store("gru-1-ts-auth-master-key", sentinel)
	vault.store("gru-1-terrabase-management-credential", "credential")
	client := func(string) (BundleClient, error) { return vault, nil }
	values, err := ReadScoped(t.Context(), testTarget.VaultID, "gru-1",
		[]string{"TS_AUTH_MASTER_KEY", "TERRABASE_MANAGEMENT_CREDENTIAL_FILE"}, client)
	if err != nil || values["TS_AUTH_MASTER_KEY"] != sentinel || values["TERRABASE_MANAGEMENT_CREDENTIAL_FILE"] != "credential" {
		t.Fatalf("resolved %d values: %v", len(values), err)
	}
	_, err = ReadScoped(t.Context(), testTarget.VaultID, "gru-1", []string{"TS_AUTH_MASTER_KEY", "CLOUDFLARE_EMAIL_TOKEN"}, client)
	if err == nil || err.Error() != "Vault secret gru-1-cloudflare-email-token does not exist" || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("missing secret error %v", err)
	}
}
