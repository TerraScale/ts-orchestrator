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

func TestResolveNamesAbsentSecret(t *testing.T) {
	vault := absentVault{newVault()}
	vault.store("gru-1-ts-auth-master-key", sentinel)
	client := func(string) (BundleClient, error) { return vault, nil }
	refs := map[string]Ref{"TS_AUTH_MASTER_KEY_FILE": {testTarget.VaultID, "gru-1-ts-auth-master-key"}}
	if values, err := Resolve(t.Context(), refs, client); err != nil || values["TS_AUTH_MASTER_KEY_FILE"] != sentinel {
		t.Fatalf("resolved %d values: %v", len(values), err)
	}
	refs["CLOUDFLARE_EMAIL_TOKEN_FILE"] = Ref{testTarget.VaultID, "gru-1-cloudflare-email-token"}
	_, err := Resolve(t.Context(), refs, client)
	if err == nil || err.Error() != "Vault secret gru-1-cloudflare-email-token does not exist" || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("missing secret error %v", err)
	}
}

func TestValidateServiceRefs(t *testing.T) {
	ref := func(name string) Ref { return Ref{testTarget.VaultID, name} }
	allowed := map[string]map[string]Ref{
		"ts-auth": {"TS_AUTH_MASTER_KEY_FILE": ref("gru-1-ts-auth-master-key"), "TERRABASE_PEER_SECRET_FILE": ref("gru-1-terrabase-peer-secret"),
			"CLOUDFLARE_EMAIL_TOKEN_FILE": ref("gru-1-cloudflare-email-token")},
		"ts-dashboard": {"STRIPE_SECRET_KEY_FILE": ref("gru-1-stripe-secret-key"), "TS_AUTH_DASHBOARD_CLIENT_SECRET_FILE": ref("gru-1-ts-auth-dashboard-client-secret"),
			"TS_DASHBOARD_SESSION_ENCRYPTION_KEY_FILE": ref("gru-1-ts-dashboard-session-encryption-key")},
		"terrabase": {"TERRABASE_MASTER_KEY_FILE": ref("gru-1-terrabase-master-key")},
	}
	for service, refs := range allowed {
		if err := ValidateServiceRefs("gru", testTarget.VaultID, service, refs); err != nil {
			t.Errorf("%s: %v", service, err)
		}
	}
	refused := map[string]struct {
		service string
		refs    map[string]Ref
	}{
		"another service's secret": {"ts-dashboard", map[string]Ref{"KEY_FILE": ref("gru-1-ts-auth-master-key")}},
		"infrastructure secret":    {"whoami", map[string]Ref{"KEY_FILE": ref("gru-1-netbird-admin-token")}},
		"shared not to this one":   {"terrabase", map[string]Ref{"KEY_FILE": ref("gru-1-stripe-secret-key")}},
		"infrastructure service":   {"netbird", map[string]Ref{"KEY_FILE": ref("gru-1-netbird-admin-token")}},
		"prefix service":           {"ts", map[string]Ref{"KEY_FILE": ref("gru-1-ts-auth-master-key")}},
		"plain env key":            {"ts-auth", map[string]Ref{"TS_AUTH_MASTER_KEY": ref("gru-1-ts-auth-master-key")}},
		"path key":                 {"ts-auth", map[string]Ref{"../X_FILE": ref("gru-1-ts-auth-master-key")}},
		"other Vault":              {"ts-auth", map[string]Ref{"KEY_FILE": ref("gru-1-ts-auth-master-key"), "B_FILE": {"ocid1.vault.oc1.sa-saopaulo-1.other", "gru-1-ts-auth-b"}}},
		"other region's Vault":     {"ts-auth", map[string]Ref{"KEY_FILE": {"ocid1.vault.oc1.us-sanjose-1.vault", "gru-1-ts-auth-master-key"}}},
		"other cell's secret":      {"ts-auth", map[string]Ref{"KEY_FILE": ref("sjc-1-ts-auth-master-key")}},
	}
	for name, c := range refused {
		if err := ValidateServiceRefs("gru", "", c.service, c.refs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A service's refs bind it to the cell of the Vault they name, wherever the
// host runs.
func TestRefsVaultBindsTheNamedVault(t *testing.T) {
	refs := map[string]Ref{"TERRABASE_MASTER_KEY_FILE": {testTarget.VaultID, "gru-1-terrabase-e2e-master-key"},
		"TERRABASE_PEER_SECRET_FILE": {testTarget.VaultID, "gru-1-terrabase-e2e-peer-secret"}}
	cell, vaultID, err := refsVault("terrabase-e2e", refs)
	if err != nil || cell != "gru" || vaultID != testTarget.VaultID {
		t.Fatalf("refsVault = %q %q %v", cell, vaultID, err)
	}
	refused := map[string]map[string]Ref{
		"two Vaults":            {"A_FILE": refs["TERRABASE_MASTER_KEY_FILE"], "B_FILE": {"ocid1.vault.oc1.sa-saopaulo-1.other", "gru-1-terrabase-e2e-x"}},
		"another service":       {"A_FILE": {testTarget.VaultID, "gru-1-ts-auth-master-key"}},
		"another cell's name":   {"A_FILE": {testTarget.VaultID, "sjc-1-terrabase-e2e-x"}},
		"Vault outside a cell":  {"A_FILE": {"ocid1.vault.oc1.us-ashburn-1.vault", "gru-1-terrabase-e2e-x"}},
		"infrastructure secret": {"A_FILE": {testTarget.VaultID, "gru-1-ghcr-pull-token"}},
	}
	for name, bad := range refused {
		if _, _, err := refsVault("terrabase-e2e", bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
