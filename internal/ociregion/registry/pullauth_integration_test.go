package registry

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type pullVault struct {
	mu      sync.Mutex
	token   string
	version int64
	id      string
	status  int
	expiry  time.Time
	calls   atomic.Int64
	blocked atomic.Bool
}

func setupPull(t *testing.T) (*PullSecrets, *pullVault, PullScope, PullSecret) {
	t.Helper()
	vault := &pullVault{token: "test-issued-ocir-token-keep-private", version: 3, id: "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull"}
	owned := PullSecret{RegistryHost: "gru.ocir.io", Repository: "tenancy/terrascale/terrabase", Username: "tenancy/oci-pull-user", Ref: vaultsecret.Ref{Vault: "ocid1.vault.oc1.sa-saopaulo-1.owned", Name: "gru-orch-ocir-terrabase-pull"}}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		vault.calls.Add(1)
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName") ||
			r.URL.Query().Get("secretName") != owned.Ref.Name || r.URL.Query().Get("vaultId") != owned.Ref.Vault || r.URL.Query().Get("stage") != "CURRENT" {
			t.Errorf("unexpected secret read %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
			return
		}
		if vault.blocked.Load() {
			<-r.Context().Done()
			return
		}
		vault.mu.Lock()
		defer vault.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if vault.status != 0 {
			w.WriteHeader(vault.status)
			_, _ = w.Write([]byte(`{"code":"NotAuthorizedOrNotFound","message":"` + vault.token + `"}`))
			return
		}
		response := map[string]any{"secretId": vault.id, "versionNumber": vault.version, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(vault.token))}}
		if !vault.expiry.IsZero() {
			response["timeOfExpiry"] = vault.expiry.Format(time.RFC3339Nano)
		}
		wire, err := json.Marshal(response)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(wire)
	})
	reader, err := NewPullSecrets(factory)
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&reader.client.BaseClient, endpoint)
	reader.client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
	scope := PullScope{RegistryHost: owned.RegistryHost, Repository: owned.Repository, Digest: "sha256:" + strings.Repeat("a", 64), TaskPrincipal: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}
	return reader, vault, scope, owned
}

func TestVaultPullMetadataAndScopedCredentialHTTP(t *testing.T) {
	reader, vault, scope, owned := setupPull(t)
	claim, err := reader.Describe(t.Context(), scope, owned, 4)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := reader.Resolve(t.Context(), claim, scope, owned)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{string(wire), fmt.Sprint(credential), fmt.Sprintf("%+v", credential), fmt.Sprintf("%#v", credential)} {
		if strings.Contains(value, vault.token) || strings.Contains(value, owned.Username) {
			t.Fatal("credential formatting leaked private values")
		}
	}
	metadata, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), vault.token) {
		t.Fatal("admission metadata contains credential bytes")
	}
	var authenticated atomic.Bool
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != owned.Username || password != vault.token {
			w.WriteHeader(401)
			return
		}
		authenticated.Store(true)
		w.WriteHeader(200)
	}))
	defer registry.Close()
	username, password, err := credential.ForHost(scope.RegistryHost)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), "GET", registry.URL+"/v2/"+scope.Repository+"/manifests/"+scope.Digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth(username, password)
	response, err := registry.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || !authenticated.Load() {
		t.Fatal("scoped Vault credential failed registry authentication")
	}
	if username, password, err := credential.ForHost("other.ocir.io"); !errors.Is(err, ErrPullAuth) || username != "" || password != "" {
		t.Fatal("credentials disclosed to another registry origin")
	}
	calls := vault.calls.Load()
	for _, change := range []func(*PullClaim){
		func(c *PullClaim) { c.Scope.Digest = "sha256:" + strings.Repeat("b", 64) },
		func(c *PullClaim) { c.Scope.TaskPrincipal = "another-service" },
		func(c *PullClaim) { c.Secret.Ref.Name = "gru-orch-other-secret" },
		func(c *PullClaim) { c.Secret.RegistryHost = "other.ocir.io" },
	} {
		tampered := claim
		change(&tampered)
		if _, err := reader.Resolve(t.Context(), tampered, scope, owned); !errors.Is(err, ErrPullAuth) {
			t.Fatal("unbound task/release credential selection accepted")
		}
	}
	if vault.calls.Load() != calls {
		t.Fatal("unbound credential selection reached Vault")
	}
}

func TestVaultPullRotationExpiryAndMissingCredentialBlock(t *testing.T) {
	reader, vault, scope, owned := setupPull(t)
	claim, err := reader.Describe(t.Context(), scope, owned, 1)
	if err != nil {
		t.Fatal(err)
	}
	vault.mu.Lock()
	vault.token = "rotated-issued-private-ocir-token"
	vault.version++
	vault.mu.Unlock()
	if _, err := reader.Resolve(t.Context(), claim, scope, owned); !errors.Is(err, ErrPullAuth) {
		t.Fatal("stale credential version silently accepted")
	}
	next, err := reader.Describe(t.Context(), scope, owned, 2)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version <= claim.Version || next.SHA256 == claim.SHA256 {
		t.Fatal("rotation metadata did not advance")
	}
	if _, err := reader.Resolve(t.Context(), next, scope, owned); err != nil {
		t.Fatal(err)
	}
	vault.mu.Lock()
	vault.expiry = time.Now().Add(-time.Minute)
	vault.mu.Unlock()
	if _, err := reader.Resolve(t.Context(), next, scope, owned); !errors.Is(err, ErrPullAuth) {
		t.Fatal("expired Vault token accepted")
	}
	vault.mu.Lock()
	vault.expiry = time.Time{}
	vault.status = 403
	vault.mu.Unlock()
	if _, err := reader.Resolve(t.Context(), next, scope, owned); !errors.Is(err, ErrPullAuth) || strings.Contains(err.Error(), vault.token) {
		t.Fatal("missing private credential allowed fallback or leaked contents")
	}
}

func TestVaultPullReadCancellationAndIndependentBinding(t *testing.T) {
	reader, vault, scope, owned := setupPull(t)
	claim, err := reader.Describe(t.Context(), scope, owned, 1)
	if err != nil {
		t.Fatal(err)
	}
	wrong := owned
	wrong.Ref.Vault = "ocid1.vault.oc1.us-sanjose-1.other"
	if _, err := reader.Resolve(t.Context(), claim, scope, wrong); !errors.Is(err, ErrPullAuth) {
		t.Fatal("claim overrode independent owned binding")
	}
	if _, err := reader.Resolve(t.Context(), claim, scope, PullSecret{}); !errors.Is(err, ErrPullAuth) {
		t.Fatal("missing owned credential allowed anonymous fallback")
	}
	vault.blocked.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := reader.Resolve(ctx, claim, scope, owned); !errors.Is(err, ErrPullAuth) {
		t.Fatal("canceled Vault read succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("canceled SDK request remained active")
	}
}
