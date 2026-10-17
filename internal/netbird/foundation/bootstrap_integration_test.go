package foundation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

// This scenario crosses the actual pinned upstream process, Dex, SQLite, HTTP and OCI SDK boundaries.
func TestBootstrapPinnedUpstreamAndLostVaultPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	container := "ts-netbird-bootstrap-" + strings.ToLower(randomCredential()[:12])
	directory := t.TempDir()
	config := filepath.Join(directory, "config.yaml")
	wire := fmt.Sprintf(`server:
  listenAddress: ":80"
  exposedAddress: "https://netbird.terrascale.tech:443"
  stunPorts: [3478]
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "error"
  logFile: "console"
  authSecret: %q
  dataDir: "/var/lib/netbird"
  auth:
    issuer: "https://netbird.terrascale.tech/oauth2"
    sessionCookieEncryptionKey: %q
    dashboardRedirectURIs: ["https://netbird.terrascale.tech/nb-auth"]
  store:
    engine: "sqlite"
    encryptionKey: %q
`, keyCredential(), keyCredential(), keyCredential())
	if err := os.WriteFile(config, []byte(wire), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	command := exec.CommandContext(ctx, "podman", "run", "--pull=never", "--memory=512m", "--pids-limit=256", "-d", "--name", container, "-v", container+"-data:/var/lib/netbird", "-p", fmt.Sprintf("127.0.0.1:%d:80", port), "-v", config+":/etc/netbird/config.yaml:ro", "docker.io/netbirdio/netbird-server:0.80.0@sha256:05b3d8d6d056e5062a2965d4d6e5d6d83f09f2bf9133947a8e5972e0e0e7a261", "--config", "/etc/netbird/config.yaml")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("pinned NetBird process start: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("podman", "logs", "--tail", "40", container).CombinedOutput()
			t.Logf("upstream process: %s", logs)
		}
		_ = exec.Command("podman", "rm", "-f", "-t", "1", container).Run()
		_ = exec.Command("podman", "volume", "rm", container+"-data").Run()
	})
	origin := fmt.Sprintf("http://127.0.0.1:%d", port)
	client, err := newBootstrapClient(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.http.CloseIdleConnections()
	for {
		err = client.api(ctx, "GET", "/instance", "", nil, new(any))
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("upstream readiness deadline")
		case <-time.After(200 * time.Millisecond):
		}
	}
	store := newVaultHTTP(t)
	target := store.clients(t)
	// Fail the first PAT publication after NetBird has minted it; the owner password is already durable.
	store.mu.Lock()
	store.failPAT = true
	store.mu.Unlock()
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target); err == nil || !strings.Contains(err.Error(), "service credential publication failed") {
		t.Fatalf("expected injected Vault publication failure, got %v", err)
	}
	store.mu.Lock()
	store.failPAT = false
	store.mu.Unlock()
	result, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target)
	if err != nil {
		t.Fatal(err)
	}
	if result.ManagementPAT.Name != ManagementSecretName || result.SecretID == "" {
		t.Fatal("missing public credential reference")
	}
	again, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target)
	if err != nil || again != result {
		t.Fatalf("restart did not reuse authoritative PAT: %v", err)
	}
	store.mu.Lock()
	pat, owner := store.values[ManagementSecretName], store.values[ownerSecretName]
	store.mu.Unlock()
	if pat == "" || owner == "" {
		t.Fatal("credentials not persisted through SDK HTTP")
	}
	api, err := manager.NewFencedAPI(origin, pat, target.Check)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if err := manager.RestrictBaseline(ctx, api); err != nil {
		t.Fatalf("restrict actual pinned genesis policy: %v", err)
	}
	inventory, err := manager.ReadInventory(ctx, api)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range inventory.Policies {
		if policy.Name == "Default" {
			t.Fatal("genesis All policy remained active")
		}
	}
	if err := manager.RestrictBaseline(ctx, api); err != nil {
		t.Fatalf("restart of restricted baseline failed: %v", err)
	}
	escrow, err := loadOwnerEscrow(filepath.Join(directory, "identity"))
	if err != nil || escrow.Password != owner || escrow.OwnerID == "" || escrow.Target != target.Target || escrow.StoreGeneration != target.StoreGeneration || escrow.SetupAttempt == "" {
		t.Fatal("owner recovery escrow does not match the authoritative identity")
	}
	other := target
	other.Target.KeyID += "replacement"
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), other); err == nil || !strings.Contains(err.Error(), "authenticated recovery") {
		t.Fatalf("changed Vault target was accepted: %v", err)
	}
	other = target
	other.StoreGeneration = "fixture-operation:2"
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), other); err == nil || !strings.Contains(err.Error(), "authenticated recovery") {
		t.Fatalf("changed admitted store generation was accepted: %v", err)
	}
	// A malformed escrow must fail before opening a blocking FIFO or accepting a hard link.
	unsafe := filepath.Join(directory, "unsafe-identity")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(unsafe, "owner.json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(ctx, origin, unsafe, target); err == nil || !strings.Contains(err.Error(), "not protected") {
		t.Fatalf("FIFO owner escrow was accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(unsafe, "owner.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(directory, "identity", "owner.json"), filepath.Join(unsafe, "owner.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(ctx, origin, unsafe, target); err == nil || !strings.Contains(err.Error(), "ownership differs") {
		t.Fatalf("hard-linked owner escrow was accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(unsafe, "owner.json")); err != nil {
		t.Fatal(err)
	}
	// Seed an actually issued one-day PAT, then lose the SDK response after Vault commits renewal.
	jwt, err := client.login(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	var currentOwner apiUser
	if err := client.api(ctx, "GET", "/users/current", "Bearer "+jwt, nil, &currentOwner); err != nil {
		t.Fatal(err)
	}
	var ownerToken struct {
		Plain    string   `json:"plain_token"`
		Metadata apiToken `json:"personal_access_token"`
	}
	ownerTokensPath := "/users/" + currentOwner.ID + "/tokens"
	if err := client.api(ctx, "POST", ownerTokensPath, "Bearer "+jwt, map[string]any{"name": "fixture-owner", "expires_in": 365}, &ownerToken); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.values[ManagementSecretName] = ownerToken.Plain
	store.mu.Unlock()
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("owner PAT was accepted as service credential: %v", err)
	}
	if err := client.api(ctx, "GET", "/users/current", "Token "+ownerToken.Plain, nil, new(apiUser)); err != nil {
		t.Fatal("refusing the wrong credential revoked its owner's PAT")
	}
	store.mu.Lock()
	store.values[ManagementSecretName] = pat
	store.mu.Unlock()
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target); err != nil {
		t.Fatal(err)
	}
	if err := client.api(ctx, "DELETE", ownerTokensPath+"/"+ownerToken.Metadata.ID, "Bearer "+jwt, nil, nil); err != nil {
		t.Fatal(err)
	}
	var users []apiUser
	if err := client.api(ctx, "GET", "/users", "Bearer "+jwt, nil, &users); err != nil {
		t.Fatal(err)
	}
	var serviceID string
	for _, user := range users {
		if user.Name == serviceName && user.Service {
			serviceID = user.ID
		}
	}
	if serviceID == "" {
		t.Fatal("service identity missing")
	}
	var existing []apiToken
	if err := client.api(ctx, "GET", "/users/"+serviceID+"/tokens", "Bearer "+jwt, nil, &existing); err != nil {
		t.Fatal(err)
	}
	for _, token := range existing {
		if err := client.api(ctx, "DELETE", "/users/"+serviceID+"/tokens/"+token.ID, "Bearer "+jwt, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	var short struct {
		Plain string `json:"plain_token"`
	}
	if err := client.api(ctx, "POST", "/users/"+serviceID+"/tokens", "Bearer "+jwt, map[string]any{"name": serviceName, "expires_in": 1}, &short); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.values[ManagementSecretName] = short.Plain
	store.loseUpdate = true
	store.mu.Unlock()
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target); err == nil || !strings.Contains(err.Error(), "publication failed") {
		t.Fatalf("expected lost Vault update response: %v", err)
	}
	if err := client.api(ctx, "GET", "/users", "Token "+short.Plain, nil, new([]apiUser)); err != nil {
		t.Fatal("previous CURRENT was revoked before replacement verification")
	}
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target); err != nil {
		t.Fatal(err)
	}
	if err := client.api(ctx, "GET", "/users", "Token "+short.Plain, nil, new([]apiUser)); err == nil {
		t.Fatal("recovered renewal retained the previous token")
	}
	// Reuse persists across the upstream process/store restart.
	if output, err := exec.CommandContext(ctx, "podman", "stop", "-t", "5", container).CombinedOutput(); err != nil {
		t.Fatalf("stop: %v: %s", err, output)
	}
	for attempt := range 10 {
		output, startErr := exec.CommandContext(ctx, "podman", "start", container).CombinedOutput()
		if startErr == nil {
			break
		}
		if attempt == 9 {
			t.Fatalf("restart: %v: %s", startErr, output)
		}
		select {
		case <-ctx.Done():
			t.Fatal("restart deadline")
		case <-time.After(500 * time.Millisecond):
		}
	}

	for {
		err = client.api(ctx, "GET", "/instance", "", nil, new(any))
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("upstream restart deadline")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if _, err := Bootstrap(ctx, origin, filepath.Join(directory, "identity"), target); err != nil {
		t.Fatal(err)
	}
	var status struct {
		SetupRequired bool `json:"setup_required"`
	}
	if err := client.api(ctx, "GET", "/instance", "", nil, &status); err != nil || status.SetupRequired {
		t.Fatal("initial setup reopened")
	}
	// Once closed, even a second valid-looking setup request cannot replace the owner.
	if err := client.api(ctx, "POST", "/setup", "", map[string]any{"email": "attacker@example.test", "password": randomCredential(), "name": "second owner"}, nil); err == nil {
		t.Fatal("closed setup accepted another owner")
	}
	// Model store loss before owner capture: retained pre-setup intent is the only identity evidence.
	uncaptured := escrow
	uncaptured.OwnerID = ""
	lostIdentity := filepath.Join(directory, "uncaptured-identity")
	if err := saveOwnerEscrow(lostIdentity, uncaptured); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	delete(store.values, identitySecretName)
	delete(store.values, ManagementSecretName)
	store.mu.Unlock()
	if output, err := exec.CommandContext(ctx, "podman", "rm", "-f", "-t", "1", container).CombinedOutput(); err != nil {
		t.Fatalf("discard disposable manager: %v: %s", err, output)
	}
	if output, err := exec.CommandContext(ctx, "podman", "volume", "rm", container+"-data").CombinedOutput(); err != nil {
		t.Fatalf("discard disposable store: %v: %s", err, output)
	}
	if output, err := exec.CommandContext(ctx, command.Args[0], command.Args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("start replacement disposable store: %v: %s", err, output)
	}
	for {
		if err := client.api(ctx, "GET", "/instance", "", nil, new(any)); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("replacement readiness deadline")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if _, err := Bootstrap(ctx, origin, lostIdentity, target); err == nil || !strings.Contains(err.Error(), "retained setup attempt") {
		t.Fatalf("lost uncaptured store accepted new genesis: %v", err)
	}
	if err := client.api(ctx, "GET", "/instance", "", nil, &status); err != nil || !status.SetupRequired {
		t.Fatal("refused recovery mutated replacement setup")
	}

}

type vaultHTTP struct {
	server     *httptest.Server
	mu         sync.Mutex
	values     map[string]string
	failPAT    bool
	loseUpdate bool
	versions   map[string]int64
}

const vaultTestID = "ocid1.vault.oc1.sa-saopaulo-1.test.fixture"

func newVaultHTTP(t *testing.T) *vaultHTTP {
	s := &vaultHTTP{values: map[string]string{}, versions: map[string]int64{}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		write := func(value any) {
			wire, err := json.Marshal(value)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(wire)
		}
		absent := func() {
			w.WriteHeader(404)
			write(map[string]any{"code": "NotAuthorizedOrNotFound", "message": "fixture absent"})
		}
		if strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName") {
			name := r.URL.Query().Get("secretName")
			value, ok := s.values[name]
			if !ok {
				absent()
				return
			}
			write(map[string]any{"secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test." + strings.ReplaceAll(name, "-", ""), "versionNumber": s.versions[name], "secretBundleContent": map[string]any{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(value))}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/secrets") && r.Method == "GET" {
			items := []map[string]any{}
			for name := range s.values {
				if name == r.URL.Query().Get("name") {
					items = append(items, map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test." + strings.ReplaceAll(name, "-", ""), "secretName": name, "lifecycleState": "ACTIVE"})
				}
			}
			write(items)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/secrets") && r.Method == "POST" {
			var req struct {
				Name    string `json:"secretName"`
				Content struct {
					Content string `json:"content"`
				} `json:"secretContent"`
			}
			if err := json.UnmarshalRead(r.Body, &req); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if req.Name == ManagementSecretName && s.failPAT {
				w.WriteHeader(400)
				write(map[string]any{"code": "InvalidParameter", "message": "injected publication rejection"})
				return
			}
			decoded, err := base64.StdEncoding.DecodeString(req.Content.Content)
			if err != nil {
				t.Error(err)
			}
			s.values[req.Name] = string(decoded)
			s.versions[req.Name] = 1
			w.WriteHeader(200)
			write(map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test." + strings.ReplaceAll(req.Name, "-", "")})
			return
		}
		for name, version := range s.versions {
			id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.test." + strings.ReplaceAll(name, "-", "")
			if !strings.HasSuffix(r.URL.Path, "/secrets/"+id) {
				continue
			}
			if r.Method == "PUT" {
				if r.Header.Get("If-Match") != strconv.FormatInt(version, 10) {
					w.WriteHeader(412)
					write(map[string]any{"code": "NoEtagMatch", "message": "fixture changed"})
					return
				}
				var req struct {
					Content struct {
						Content string `json:"content"`
					} `json:"secretContent"`
				}
				if err := json.UnmarshalRead(r.Body, &req); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				decoded, err := base64.StdEncoding.DecodeString(req.Content.Content)
				if err != nil {
					t.Error(err)
				}
				s.values[name] = string(decoded)
				version++
				s.versions[name] = version
				if s.loseUpdate {
					s.loseUpdate = false
					w.WriteHeader(500)
					write(map[string]any{"code": "InternalServerError", "message": "injected lost response after commit"})
					return
				}
			} else if r.Method != "GET" {
				break
			}
			w.Header().Set("etag", strconv.FormatInt(version, 10))
			write(map[string]any{"id": id, "vaultId": vaultTestID, "secretName": name, "lifecycleState": "ACTIVE", "currentVersionNumber": version})
			return
		}
		t.Errorf("unexpected OCI request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	}))
	t.Cleanup(s.server.Close)
	return s
}
func (s *vaultHTTP) clients(t *testing.T) BootstrapVault {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..fixture", "ocid1.user.oc1..fixture", "sa-saopaulo-1", "fixture", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	management, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management.Host = s.server.URL
	policy := common.NoRetryPolicy()
	management.Configuration.RetryPolicy = &policy
	bundles, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles.Host = s.server.URL
	bundles.Configuration.RetryPolicy = &policy
	return BootstrapVault{StoreGeneration: "fixture-operation:1", Check: func() error { return nil }, Target: vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..fixture", VaultID: vaultTestID, KeyID: "ocid1.key.oc1.sa-saopaulo-1.test.fixture"}, Management: management, Bundles: bundles}
}
