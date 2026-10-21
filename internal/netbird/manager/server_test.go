package manager

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

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
	bundles map[string]*memSecret
	creates int
}

// memSecret is one named secret: its OCID, CURRENT version and base64 content.
type memSecret struct {
	id      string
	version int64
	content string
}

func newMemVault() *memVault {
	return &memVault{bundles: map[string]*memSecret{}}
}

// serviceError answers like OCI's SDK error, so vaultsecret.Absent sees a 404.
type serviceError struct{ status int }

func (e serviceError) Error() string           { return "OCI service error" }
func (e serviceError) GetHTTPStatusCode() int  { return e.status }
func (e serviceError) GetMessage() string      { return "" }
func (e serviceError) GetCode() string         { return "" }
func (e serviceError) GetOpcRequestID() string { return "" }

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
	v.bundles[*details.SecretName] = &memSecret{id: id, version: 1, content: *content.Content}
	return ocivault.CreateSecretResponse{Secret: ocivault.Secret{Id: new(id)}}, nil
}

func (v *memVault) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	secret, ok := v.bundles[*request.SecretName]
	if !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, serviceError{status: http.StatusNotFound}
	}
	return ocisecrets.GetSecretBundleByNameResponse{SecretBundle: ocisecrets.SecretBundle{
		SecretId: new(secret.id), VersionNumber: new(secret.version),
		SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(secret.content)},
	}}, nil
}

func (v *memVault) GetSecret(_ context.Context, request ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error) {
	name, secret, ok := v.byID(*request.SecretId)
	if !ok {
		return ocivault.GetSecretResponse{}, serviceError{status: http.StatusNotFound}
	}
	return ocivault.GetSecretResponse{Secret: metadata(name, secret), Etag: new(etag(secret))}, nil
}

// UpdateSecret adds a CURRENT version only when If-Match names the current Etag.
func (v *memVault) UpdateSecret(_ context.Context, request ocivault.UpdateSecretRequest) (ocivault.UpdateSecretResponse, error) {
	name, secret, ok := v.byID(*request.SecretId)
	if !ok || request.IfMatch == nil || *request.IfMatch != etag(secret) {
		return ocivault.UpdateSecretResponse{}, serviceError{status: http.StatusPreconditionFailed}
	}
	content := request.UpdateSecretDetails.SecretContent.(ocivault.Base64SecretContentDetails)
	secret.content = *content.Content
	secret.version++
	return ocivault.UpdateSecretResponse{Secret: metadata(name, secret), Etag: new(etag(secret))}, nil
}

func (v *memVault) byID(id string) (string, *memSecret, bool) {
	for name, secret := range v.bundles {
		if secret.id == id {
			return name, secret, true
		}
	}
	return "", nil, false
}

func metadata(name string, secret *memSecret) ocivault.Secret {
	return ocivault.Secret{Id: new(secret.id), VaultId: new(serverTarget.VaultID), SecretName: new(name),
		LifecycleState: ocivault.SecretLifecycleStateActive, CurrentVersionNumber: new(secret.version)}
}

// etag changes with every version, so a stale If-Match is refused.
func etag(secret *memSecret) string {
	return secret.id + "/" + strconv.FormatInt(secret.version, 10)
}

func TestServerBootstrapClaimsOnceAndStoresSecretsWithoutLeakingThem(t *testing.T) {
	f := newFakeManager(t)
	f.policies = []apiPolicy{{ID: "pol-default", Name: "Default", Enabled: true}}
	vault := newMemVault()
	server := ServerVault{Target: serverTarget, Management: vault, Versions: vault, Bundles: vault}
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
	if vault.creates != creates || len(f.setupKeys) != keys || len(f.setups) != 1 || len(f.patDays) != 0 || len(f.tokens) != 1 {
		t.Fatalf("rerun: %d Vault creates, %d setup keys, %d claims, %d new PATs; want no change",
			vault.creates-creates, len(f.setupKeys)-keys, len(f.setups)-1, len(f.patDays))
	}
}

func TestServerRotatesExpiringCredentials(t *testing.T) {
	f := newFakeManager(t)
	f.policies = []apiPolicy{{ID: "pol-default", Name: "Default", Enabled: true}}
	vault := newMemVault()
	server := ServerVault{Target: serverTarget, Management: vault, Versions: vault, Bundles: vault}
	if err := PrepareServer(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil {
		t.Fatal(err)
	}
	names := []string{serversKeySecret, operatorsKeySecret, adminPATSecret}
	oldValue, oldVersion := map[string]string{}, map[string]int64{}
	for _, name := range names {
		oldValue[name], oldVersion[name] = vault.bundles[name].content, vault.bundles[name].version
	}
	oldKeys, oldTokens := map[string]bool{}, map[string]bool{}
	for _, key := range f.setupKeys {
		oldKeys[key["id"].(string)] = true
	}
	for _, token := range f.tokens {
		oldTokens[token.ID] = true
	}
	// Move every credential into the 30-day rotation window.
	soon := time.Now().AddDate(0, 0, 10)
	for _, key := range f.setupKeys {
		key["expires"] = soon
	}
	for _, token := range f.tokens {
		token.Expires = soon
	}
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil {
		t.Fatal(err)
	}
	// Values are never printed: a failure names the secret and its versions only.
	for _, name := range names {
		secret := vault.bundles[name]
		if secret.version != oldVersion[name]+1 || secret.content == oldValue[name] {
			t.Fatalf("%s: version %d, want %d with a new value", name, secret.version, oldVersion[name]+1)
		}
	}
	for _, key := range f.setupKeys {
		if oldKeys[key["id"].(string)] {
			if key["revoked"] != true {
				t.Fatalf("old setup key %v is still valid", key["id"])
			}
		} else if days := time.Until(key["expires"].(time.Time)).Hours() / 24; days < 89 || days > 91 {
			t.Fatalf("new setup key expires in %.1f days, want about %d", days, credentialDays)
		}
	}
	if len(f.tokens) != 1 || oldTokens[f.tokens[0].ID] || len(f.patDays) != 1 || f.patDays[0] != credentialDays {
		t.Fatalf("tokens: %d live, PAT lifetimes %v; want one successor of %d days", len(f.tokens), f.patDays, credentialDays)
	}
	creates, keys, tokens, pats := vault.creates, len(f.setupKeys), len(f.tokens), len(f.patDays)
	if err := BootstrapServer(t.Context(), server, f.server.URL); err != nil {
		t.Fatal(err)
	}
	if vault.creates != creates || len(f.setupKeys) != keys || len(f.tokens) != tokens || len(f.patDays) != pats {
		t.Fatal("a run after rotation changed credentials")
	}
	for _, name := range names {
		if vault.bundles[name].version != oldVersion[name]+1 {
			t.Fatalf("%s: version %d after a settled run, want %d", name, vault.bundles[name].version, oldVersion[name]+1)
		}
	}
}

func TestClientPinMatchesUpstreamRelease(t *testing.T) {
	if err := client.ValidatePin(clientPin); err != nil {
		t.Fatal(err)
	}
}
