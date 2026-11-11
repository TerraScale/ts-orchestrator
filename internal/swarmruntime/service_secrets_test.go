package swarmruntime

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestApplyServiceSpecSecretsMissing(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			ctx, client, resolve, writes, _ := serviceSecretEnvironment(t, code)
			spec, before := serviceSecretBaseline(t, ctx, client)
			writes.Store(0)
			_, err := applyServiceSpec(ctx, client, spec, nil, resolve)
			if err == nil || !strings.Contains(err.Error(), spec.Secrets["SECOND_FILE"].Name) {
				t.Fatalf("apply must fail naming the unavailable secret: %v", err)
			}
			if strings.Contains(err.Error(), base64.StdEncoding.EncodeToString([]byte(t.Name()))) {
				t.Fatal("apply error exposed the Vault response body")
			}
			if writes.Load() != 0 {
				t.Fatal("apply mutated a service before resolving its secrets")
			}
			after, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: before.ID})
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(before, after.Service) {
				t.Fatal("failed apply changed the existing service")
			}
		})
	}
}

func TestApplyServiceSpecSecretsPresent(t *testing.T) {
	ctx, client, resolve, writes, reads := serviceSecretEnvironment(t, http.StatusOK)
	spec, before := serviceSecretBaseline(t, ctx, client)
	writes.Store(0)
	after, err := applyServiceSpec(ctx, client, spec, nil, resolve)
	if err != nil {
		t.Fatal(err)
	}
	want, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID || !proto.Equal(&after.Spec, want) || writes.Load() != 1 {
		t.Fatal("apply did not update the existing service to the requested spec")
	}
	for _, ref := range spec.Secrets {
		if _, ok := reads.Load(ref.Name); !ok {
			t.Fatalf("apply did not resolve Vault secret %s", ref.Name)
		}
	}
}

func serviceSecretBaseline(t *testing.T, ctx context.Context, client api.ControlClient) (ServiceSpec, *api.Service) {
	t.Helper()
	spec := ServiceSpec{Name: "preflight", Image: "example.com/preflight@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	before, err := ApplyServiceSpec(ctx, client, spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Env = map[string]string{"REVISION": "next"}
	spec.Secrets = map[string]vaultsecret.Ref{
		"FIRST_FILE":  {Vault: "ocid1.vault.oc1.sa-saopaulo-1.test", Name: "gru-1-preflight-present"},
		"SECOND_FILE": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.test", Name: "gru-1-preflight-missing"},
	}
	return spec, before
}

func serviceSecretEnvironment(t *testing.T, unavailableStatus int) (context.Context, api.ControlClient, SecretResolver, *atomic.Int32, *sync.Map) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	memory := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = memory.Close() })
	writes := new(atomic.Int32)
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.HasSuffix(info.FullMethod, "/CreateService") || strings.HasSuffix(info.FullMethod, "/UpdateService") || strings.HasSuffix(info.FullMethod, "/RemoveService") {
			writes.Add(1)
		}
		return handler(ctx, req)
	}))
	api.RegisterControlServer(server, controlapi.NewServer(memory, nil, nil, nil, nil))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	reads := new(sync.Map)
	content := base64.StdEncoding.EncodeToString([]byte(t.Name()))
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("secretName")
		if r.Method != http.MethodPost || r.URL.Path != "/20190301/secretbundles/actions/getByName" || r.URL.Query().Get("stage") != "CURRENT" || r.URL.Query().Get("vaultId") != "ocid1.vault.oc1.sa-saopaulo-1.test" {
			t.Errorf("unexpected Vault request: %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(name, "-missing") && unavailableStatus != http.StatusOK {
			w.WriteHeader(unavailableStatus)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "NotAuthorizedOrNotFound", "message": content})
			return
		}
		reads.Store(name, true)
		_ = json.NewEncoder(w).Encode(map[string]any{"secretBundleContent": map[string]string{"contentType": "BASE64", "content": content}})
	}))
	t.Cleanup(vault.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	bundles, err := secrets.NewSecretsClientWithConfigurationProvider(common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", private, nil))
	if err != nil {
		t.Fatal(err)
	}
	bundles.Host = vault.URL
	bundles.HTTPClient = vault.Client()
	resolve := func(ctx context.Context, service string, refs map[string]vaultsecret.Ref) (map[string]string, error) {
		if err := vaultsecret.ValidateServiceRefs("gru", "", service, refs); err != nil {
			return nil, err
		}
		return vaultsecret.Resolve(ctx, refs, func(string) (vaultsecret.BundleClient, error) { return bundles, nil })
	}
	return ctx, api.NewControlClient(conn), resolve, writes, reads
}
