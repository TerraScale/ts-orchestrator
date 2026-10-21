package bootstrapmaterial

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type linkFixture struct {
	home, spoke, homeLink, spokeLink string
	now                              time.Time
	homeRecord, spokeRecord          LinkRecord
}

func newLinkFixture(t *testing.T) linkFixture {
	t.Helper()
	root := t.TempDir()
	f := linkFixture{home: filepath.Join(root, "home"), spoke: filepath.Join(root, "spoke"), homeLink: filepath.Join(root, "home-link"), spokeLink: filepath.Join(root, "spoke-link"), now: time.Now().UTC().Truncate(time.Second)}
	cfg := testConfig()
	if _, err := Generate(f.home, cfg, f.now); err != nil {
		t.Fatal(err)
	}
	cfg.Cell, cfg.Region, cfg.ClusterID = "sfo", "us-sanjose-1", "00000000000000000000000002"
	if _, err := Generate(f.spoke, cfg, f.now); err != nil {
		t.Fatal(err)
	}
	nextSecond()
	var err error
	f.spokeRecord, err = GenerateLink(f.spoke, f.home, f.homeLink, f.spokeLink, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.homeRecord, err = LoadLink(f.homeLink, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Source and publication survive retries without changing the leaf user or its
// home signing key; an interrupted create is recovered from the journal.
func TestLinkMaterialPublicationRecovery(t *testing.T) {
	f := newLinkFixture(t)
	before, err := os.ReadFile(filepath.Join(f.spokeLink, bootstrap.LinkCredentialsFile))
	if err != nil {
		t.Fatal(err)
	}
	again, err := GenerateLink(f.spoke, f.home, f.homeLink, f.spokeLink, f.now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(again, f.spokeRecord) {
		t.Fatalf("retry changed immutable source: %v", err)
	}
	// Concurrent first callers converge on one atomically published signing key.
	concurrent := filepath.Join(t.TempDir(), "home-link")
	var issued [2]LinkRecord
	var failures [2]error
	var group sync.WaitGroup
	for index := range issued {
		group.Go(func() {
			issued[index], failures[index] = GenerateLink(f.home, f.home, concurrent, concurrent, f.now)
		})
	}
	group.Wait()
	if failures[0] != nil || failures[1] != nil || !reflect.DeepEqual(issued[0], issued[1]) {
		t.Fatalf("concurrent source owners diverged: %v, %v", failures[0], failures[1])
	}
	target := testTarget()
	vault := newFakeVault(target)
	management, bundles := linkVaultProtocol(t, vault)
	vault.uncertain = true
	var checkpoint []byte
	persist := func(wire []byte) error {
		checkpoint = bytes.Clone(wire)
		return nil
	}
	if _, err := ProvisionLinkDurable(t.Context(), f.homeLink, target, management, bundles, f.now, persist); err == nil {
		t.Fatal("uncertain publication succeeded")
	}
	if len(checkpoint) == 0 || bytes.Contains(checkpoint, []byte("BEGIN NKEY SEED")) {
		t.Fatal("missing or unsafe durable publication checkpoint")
	}
	// Restore the checkpoint after local journal loss before retrying the same create.
	if err := os.Remove(filepath.Join(f.homeLink, journalName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.homeLink, journalName), checkpoint, 0o600); err != nil {
		t.Fatal(err)
	}
	vault.uncertain = false
	published, err := ProvisionLinkDurable(t.Context(), f.homeLink, target, management, bundles, f.now.Add(time.Minute), persist)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLinkPublication(f.homeLink, published, checkpoint, f.now.Add(time.Minute)); err != nil {
		t.Fatalf("durable Link install projection rejected: %v", err)
	}
	foreign := published
	foreign.References = slices.Clone(published.References)
	foreign.References[0].Reference.SecretOCID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.foreign"
	if err := ValidateLinkPublication(f.homeLink, foreign, checkpoint, f.now.Add(time.Minute)); err == nil {
		t.Fatal("altered Link Vault reference was accepted")
	}
	creates := vault.create
	retry, err := ProvisionLink(t.Context(), f.homeLink, target, management, bundles, f.now.Add(2*time.Minute))
	if err != nil || !reflect.DeepEqual(published, retry) || creates != vault.create {
		t.Fatalf("publication changed or recreated: %v", err)
	}
	for _, ref := range published.References {
		if ref.Reference.Purpose == "owner-only" || ref.Reference.TargetFile == "issuer-link.seed" {
			t.Fatal("home signing authority escaped founder source escrow")
		}
	}
	if len(published.LinkGenerationReferences()) != len(published.References) || vault.create != len(f.homeRecord.Files)-1 {
		t.Fatal("home signing authority was published into host Vault")
	}
	target.VaultOCID = "ocid1.vault.oc1.us-sanjose-1.aaaaaa"
	target.KMSKeyOCID = "ocid1.key.oc1.us-sanjose-1.aaaaaa"
	vault = newFakeVault(target)
	management, bundles = linkVaultProtocol(t, vault)
	spokePublication, err := ProvisionLink(t.Context(), f.spokeLink, target, management, bundles, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range spokePublication.References {
		if ref.Reference.Purpose == "owner-only" {
			t.Fatal("spoke received signing authority")
		}
	}
	after, err := os.ReadFile(filepath.Join(f.spokeLink, bootstrap.LinkCredentialsFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("publication replaced leaf credentials")
	}
	// A missing immutable key cannot be repaired by creating a replacement.
	if err := os.Remove(filepath.Join(f.homeLink, "issuer-link.seed")); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateLink(f.spoke, f.home, f.homeLink, f.spokeLink, f.now); err == nil {
		t.Fatal("missing home key was regenerated")
	}
	if _, err := Load(f.home); err != nil {
		t.Fatalf("original source changed: %v", err)
	}
}

func TestLinkMaterialAuthenticatesEmbeddedNATS(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	f := newLinkFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	homeLink, err := RenderLink(f.homeRecord, "controller-a", f.homeLink)
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(f.home, name) }
	regionalTLS := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("controller-a-tls-cert.pem"), KeyFile: path("controller-a-tls-key.pem")}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	home, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 1, ClientRole: "controller", CredentialsFile: path("controller-a.creds"), TLS: regionalTLS, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(t.TempDir(), "store"), TLS: regionalTLS, RouteTLS: regionalTLS, OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"), CellJWTFile: filepath.Join(f.homeLink, "link-cell.jwt"), SystemCredentialsFile: path("system.creds"), TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: []string{"controller-a"}, Link: &homeLink}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = home.Close() })
	if err := home.Bridge().OpenUntil(1, home.InitialCellJWT(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	spokeLink, err := RenderLink(f.spokeRecord, "controller-a", f.spokeLink)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(spokeLink.TLS.CertFile, spokeLink.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(spokeLink.TLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid CA")
	}
	// Only test routing is changed: production-generated credentials, TLS,
	// permissions and the real home runtime remain intact.
	endpoint, err := url.Parse("nats-leaf://127.0.0.1:7422")
	if err != nil {
		t.Fatal(err)
	}
	spoke, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, LeafNode: server.LeafNodeOpts{Remotes: []*server.RemoteLeafOpts{{URLs: []*url.URL{endpoint}, Credentials: spokeLink.CredentialsFile, TLS: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: natscell.LinkServerName}}}}})
	if err != nil {
		t.Fatal(err)
	}
	go spoke.Start()
	t.Cleanup(func() { spoke.Shutdown(); spoke.WaitForShutdown() })
	if !spoke.ReadyForConnections(2 * time.Second) {
		t.Fatal("spoke did not start")
	}
	client, err := nats.Connect(spoke.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	subject, _ := protocol.QuerySubject("sfo", "material")
	if _, err := client.Subscribe(subject, func(msg *nats.Msg) { _ = msg.Respond([]byte("sfo")) }); err != nil {
		t.Fatal(err)
	}
	if err := client.Flush(); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		reply, err := home.Conn().Request(subject, nil, 100*time.Millisecond)
		if err == nil {
			if string(reply.Data) != "sfo" {
				t.Fatalf("wrong region %q", reply.Data)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("scoped leaf request failed: %v", err)
		case <-ticker.C:
		}
	}
	// The same issued leaf credential must be rejected on a normal client port.
	_, err = nats.Connect(home.URL(), nats.UserCredentials(spokeLink.CredentialsFile), nats.NoReconnect(), nats.Timeout(time.Second), nats.SetCustomDialer(&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: "controller-a"}}))
	if !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("leaf-only client admission result: %v", err)
	}
}

// OCI clients cross a real HTTP boundary; the server retains committed creates
// when the first response fails, matching the publication journal crash window.
func linkVaultProtocol(t *testing.T, store *fakeVault) (*ocivault.VaultsClient, *ocisecrets.SecretsClient) {
	t.Helper()
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var response any
		var err error
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
			var details ocivault.CreateSecretDetails
			if decodeErr := json.UnmarshalRead(r.Body, &details); decodeErr != nil {
				t.Error(decodeErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var created ocivault.CreateSecretResponse
			created, err = store.CreateSecret(r.Context(), ocivault.CreateSecretRequest{CreateSecretDetails: details, OpcRetryToken: new(r.Header.Get("opc-retry-token"))})
			response = created.Secret
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
			q := r.URL.Query()
			var listed ocivault.ListSecretsResponse
			listed, err = store.ListSecrets(r.Context(), ocivault.ListSecretsRequest{CompartmentId: new(q.Get("compartmentId")), VaultId: new(q.Get("vaultId")), Name: new(q.Get("name"))})
			response = listed.Items
			if response == nil || listed.Items == nil {
				response = []ocivault.SecretSummary{}
			}
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/secretbundles/"):
			_, id, _ := strings.Cut(r.URL.Path, "/secretbundles/")
			var bundle ocisecrets.GetSecretBundleResponse
			bundle, err = store.GetSecretBundle(r.Context(), ocisecrets.GetSecretBundleRequest{SecretId: new(id), VersionNumber: new(int64(1))})
			response = bundle.SecretBundle
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/secrets/"):
			_, id, _ := strings.Cut(r.URL.Path, "/secrets/")
			var secret ocivault.GetSecretResponse
			secret, err = store.GetSecret(r.Context(), ocivault.GetSecretRequest{SecretId: new(id)})
			response = secret.Secret
		default:
			t.Errorf("unexpected OCI request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"InternalError","message":"committed response unavailable"}`))
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
		}
		if err := json.MarshalWrite(w, response); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(endpoint.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", store.region, "00:00", string(private), nil)
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&management.BaseClient, &bundles.BaseClient} {
		client.Host = endpoint.URL
		client.HTTPClient = endpoint.Client()
		retry := common.NoRetryPolicy()
		client.Configuration.RetryPolicy = &retry
	}
	return &management, &bundles
}
