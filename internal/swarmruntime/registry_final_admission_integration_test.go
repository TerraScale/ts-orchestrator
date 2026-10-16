package swarmruntime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ociregistry "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestRegistryResolverRequiresCurrentAdmissionAfterVault(t *testing.T) {
	const credential = `{"username":"namespace/pull-user","password":"fixture-vault-token"}`
	const secretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull"
	owned := ociregistry.PullSecret{RegistryHost: "gru.ocir.io", Repository: "namespace/terrascale/auth",
		Ref: vaultsecret.Ref{Vault: "ocid1.vault.oc1.sa-saopaulo-1.owned", Name: "gru-orch-ocir-auth-pull"}}
	var reads atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/20190301/secretbundles/actions/getByName" ||
			r.URL.Query().Get("secretName") != owned.Ref.Name || r.URL.Query().Get("vaultId") != owned.Ref.Vault || r.URL.Query().Get("stage") != "CURRENT" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Errorf("unexpected Vault request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.MarshalWrite(w, map[string]any{"secretId": secretID, "versionNumber": 1,
			"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(credential))}}); err != nil {
			t.Error(err)
		}
	}
	factory, _ := ociresourcetest.Server(t, handler)
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unexpected plaintext Vault dial")
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com:443" {
			return nil, fmt.Errorf("unexpected Vault destination %q", address)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	// The SDK clones this transport; all signed requests stay on loopback TLS.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	previousTransport := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport; transport.CloseIdleConnections() })
	scope := ociregistry.PullScope{RegistryHost: owned.RegistryHost, Repository: owned.Repository,
		Digest: "sha256:" + strings.Repeat("a", 64), TaskPrincipal: "service-intent"}
	sum := sha256.Sum256([]byte(credential))
	claim := ociregistry.PullClaim{Scope: scope, Secret: owned, SecretID: secretID, Version: 1, SHA256: hex.EncodeToString(sum[:]), Generation: 1}
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: scope.RegistryHost + "/" + scope.Repository + "@" + scope.Digest, User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: "task1", ServiceID: "service1", NodeID: "node1", Spec: api.TaskSpec{Runtime: runtime,
		Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 32 << 20}}},
		ServiceAnnotations: api.Annotations{Labels: map[string]string{LabelEnvironment: "production", LabelRegion: "sa-saopaulo-1", LabelIntentID: scope.TaskPrincipal}}}
	node := &api.Node{ID: task.NodeID, Spec: api.NodeSpec{Annotations: api.Annotations{Labels: map[string]string{LabelRegion: "sa-saopaulo-1"}}}}
	stale := errors.New("task admission changed during Vault read")
	for _, name := range []string{"missing final guard", "current admission", "stale after Vault", "cancelled after Vault"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			before := reads.Load()
			called := false
			admission := &RegistryAdmission{ServiceID: task.ServiceID, Environment: "production", Region: "sa-saopaulo-1", Scope: scope, Secret: owned, Claim: claim}
			if name != "missing final guard" {
				admission.VerifyCurrent = func(ctx context.Context) error {
					called = true
					if ctx.Err() != nil || reads.Load() != before+1 {
						t.Fatal("final guard did not receive live outer context after Vault read")
					}
					if name == "stale after Vault" {
						return stale
					}
					if name == "cancelled after Vault" {
						cancel()
					}
					return nil
				}
			}
			resolver, err := NewOCIRegistryResolver(factory, func(context.Context, *api.Task) (*RegistryAdmission, error) {
				return admission, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver(ctx, task, node)
			switch name {
			case "missing final guard":
				if err == nil || result != nil || reads.Load() != before || called {
					t.Fatal("missing final guard reached Vault or published resolver")
				}
			case "current admission":
				if err != nil || result == nil || !called {
					t.Fatalf("current post-Vault admission rejected: %v", err)
				}
			case "stale after Vault":
				if !errors.Is(err, stale) || result != nil || !called {
					t.Fatalf("stale post-Vault admission published resolver: %v", err)
				}
			case "cancelled after Vault":
				if !errors.Is(err, context.Canceled) || result != nil || !called {
					t.Fatalf("cancelled post-Vault admission published resolver: %v", err)
				}
			}
		})
	}
}
