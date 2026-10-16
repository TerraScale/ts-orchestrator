package swarmruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// This scenario starts at the post-verification boundary. The actual upstream
// manager, agent, Raft store and OCI Vault SDK communicate over real sockets.
func TestBootstrapVaultIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	fixture, vaultClient, bundles := bootstrapVaultServer(t)
	target := vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.control", KeyID: "ocid1.key.oc1.sa-saopaulo-1.control"}
	identity := bootstrapstart.RuntimeIdentity{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
		Environment: "production", Cell: "GRU", Slot: "controller-a", SeedSlot: "controller-a",
		InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.founder", PrivateIP: "127.0.0.1", SeedPrivateIP: "127.0.0.1"}
	founderDir := t.TempDir()
	refresh := func(context.Context) error { return nil }
	var running []*Node
	t.Cleanup(func() {
		for i := len(running) - 1; i >= 0; i-- {
			nodeFixtureStop(t, running[i])
		}
	})
	start := func(directory string, binding bootstrapstart.RuntimeIdentity) *Node {
		t.Helper()
		n, err := startAcceptedNodeAt(ctx, directory, binding, target, vaultClient, bundles, nodeIdleExecutor{}, refresh)
		if err != nil {
			t.Fatal(err)
		}
		running = append(running, n)
		client, err := n.ControlClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		registered, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: n.ID()})
		if err != nil {
			t.Fatal(err)
		}
		spec := registered.Node.Spec
		if spec.Annotations.Name != binding.Slot || spec.Annotations.Labels[LabelRegion] != strings.ToLower(binding.Cell) ||
			spec.Annotations.Labels[LabelInstanceID] != binding.InstanceID || spec.Annotations.Labels[LabelHostRole] != "manager" ||
			spec.Annotations.Labels[LabelExecutionScope] != "platform" {
			t.Fatal("manager returned without its trusted placement identity")
		}
		return n
	}
	founder := start(founderDir, identity)
	founderID := founder.ID()
	fixture.mu.Lock()
	if fixture.creates != 1 || len(fixture.values) != 1 {
		t.Errorf("expected one create-once Vault record, got %d creates and %d records", fixture.creates, len(fixture.values))
	}
	fixture.mu.Unlock()
	peer := identity
	peer.Slot, peer.InstanceID, peer.PrivateIP = "controller-b", "ocid1.instance.oc1.sa-saopaulo-1.peer", "127.0.0.2"
	peerNode := start(t.TempDir(), peer)
	client, err := peerNode.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil || len(nodes.Nodes) != 2 {
		t.Fatal("role-correct manager did not join the actual regional cluster", err)
	}
	nodeFixtureStop(t, founder)
	founder = start(founderDir, identity)
	if founder.ID() != founderID {
		t.Fatal("Vault retry changed the founder certificate identity")
	}
	fixture.mu.Lock()
	creates := fixture.creates
	fixture.mu.Unlock()
	if creates != 1 {
		t.Fatalf("restart regenerated Vault material: %d creates", creates)
	}
	if _, err := startAcceptedNodeAt(ctx, t.TempDir(), identity, target, vaultClient, bundles, nodeIdleExecutor{}, refresh); err == nil {
		t.Fatal("empty replacement disk re-founded an existing Vault-bound cluster")
	}
	changed := identity
	changed.ClusterID = "0000000000NBCYX286D4RHE6ZP"
	if _, err := startAcceptedNodeAt(ctx, founderDir, changed, target, vaultClient, bundles, nodeIdleExecutor{}, refresh); err == nil {
		t.Fatal("existing node accepted another signed cluster scope")
	}

	// Interrupt the first Vault write after the real founder is initialized.
	// Retrying must reuse its CA and identity, never create another cluster.
	interrupted := identity
	interrupted.ClusterID, interrupted.PrivateIP, interrupted.SeedPrivateIP = "0000000000NBCYX286D4RHE6ZP", "127.0.0.3", "127.0.0.3"
	interruptedDir := t.TempDir()
	fixture.mu.Lock()
	fixture.denyCreate = true
	fixture.mu.Unlock()
	if _, err := startAcceptedNodeAt(ctx, interruptedDir, interrupted, target, vaultClient, bundles, nodeIdleExecutor{}, refresh); err == nil {
		t.Fatal("interrupted Vault publication reported success")
	}
	caPath := filepath.Join(interruptedDir, "node", "certificates", "swarm-root-ca.crt")
	before, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.denyCreate = false
	fixture.mu.Unlock()
	_ = start(interruptedDir, interrupted)
	after, err := os.ReadFile(caPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retry after interrupted publication replaced the upstream CA", err)
	}
}

type bootstrapVaultFixture struct {
	mu         sync.Mutex
	values     map[string]string
	creates    int
	denyCreate bool
}

func bootstrapVaultServer(t *testing.T) (*bootstrapVaultFixture, *vault.VaultsClient, *secrets.SecretsClient) {
	t.Helper()
	f := &bootstrapVaultFixture{values: make(map[string]string)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "SDK request was unsigned", http.StatusUnauthorized)
			return
		}
		write := func(value any) { data, _ := json.Marshal(value); _, _ = w.Write(data) }
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
			name := r.URL.Query().Get("name")
			items := []any{}
			if _, exists := f.values[name]; exists {
				items = append(items, map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test", "secretName": name, "lifecycleState": "ACTIVE"})
			}
			write(items)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
			if f.denyCreate {
				w.WriteHeader(http.StatusForbidden)
				write(map[string]string{"code": "NotAuthorized", "message": "qualification interrupted publication"})
				return
			}
			var body struct {
				SecretName    string `json:"secretName"`
				SecretContent struct {
					Content string `json:"content"`
				} `json:"secretContent"`
			}
			if err := json.UnmarshalRead(r.Body, &body); err != nil || body.SecretName == "" || body.SecretContent.Content == "" {
				http.Error(w, "invalid OCI protocol request", http.StatusBadRequest)
				return
			}
			if _, exists := f.values[body.SecretName]; exists {
				w.WriteHeader(http.StatusConflict)
				write(map[string]string{"code": "Conflict", "message": "secret already exists"})
				return
			}
			f.values[body.SecretName] = body.SecretContent.Content
			f.creates++
			write(map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test", "secretName": body.SecretName, "lifecycleState": "ACTIVE"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "getByName"):
			value, exists := f.values[r.URL.Query().Get("secretName")]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				write(map[string]string{"code": "NotFound", "message": "absent"})
				return
			}
			write(map[string]any{"secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test", "versionNumber": 1,
				"secretBundleContent": map[string]string{"contentType": "BASE64", "content": value}})
		default:
			http.Error(w, "unexpected OCI protocol path", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test-fingerprint", string(private), nil)
	management, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	read, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management.Host, management.HTTPClient = server.URL, server.Client()
	read.Host, read.HTTPClient = server.URL, server.Client()
	return f, &management, &read
}
