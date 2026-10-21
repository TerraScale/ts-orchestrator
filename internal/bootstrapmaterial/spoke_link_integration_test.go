package bootstrapmaterial

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// The home receives only public recipient metadata, publishes scoped leaf files
// through the real OCI SDK protocol boundary, and authenticates the resulting leaf.
func TestSpokeLinkPublicRecipientAuthenticatesAndRecovers(t *testing.T) {
	f := newLinkFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	recipient, err := Load(f.spoke)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(filepath.Join(f.spoke, metadataName))
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest := digest(metadata)
	// No recipient private file remains reachable by the issuer.
	if err := os.RemoveAll(f.spoke); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "issued-spoke")
	var records [2]LinkRecord
	var failures [2]error
	var group sync.WaitGroup
	for index := range records {
		group.Go(func() {
			records[index], failures[index] = GenerateSpokeLink(f.home, f.homeLink, recipient, sourceDigest, directory, f.now)
		})
	}
	group.Wait()
	if failures[0] != nil || failures[1] != nil || !reflect.DeepEqual(records[0], records[1]) {
		t.Fatalf("concurrent public issuance diverged: %v, %v", failures[0], failures[1])
	}
	record := records[0]
	if record.SourceSHA256 != sourceDigest || record.HomeAccount != f.homeRecord.HomeAccount || record.Signer != f.homeRecord.Signer {
		t.Fatal("spoke material lost its authenticated recipient or home identity")
	}
	for _, file := range record.Files {
		if file.Purpose != bootstrap.SecretInterRegion || file.Name == "issuer-link.seed" {
			t.Fatalf("spoke received authority file %s", file.Name)
		}
	}
	if _, err := GenerateSpokeLink(f.home, f.homeLink, recipient, digest([]byte("wrong admission")), directory, f.now); err == nil {
		t.Fatal("mismatched public metadata digest was accepted")
	}
	wrong := recipient
	wrong.Config.DeploymentID = "00000000000000000000000003"
	wire, err := json.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSpokeLink(f.home, f.homeLink, wrong, digest(wire), filepath.Join(t.TempDir(), "wrong-deployment"), f.now); err == nil {
		t.Fatal("another deployment obtained home-issued credentials")
	}
	target := testTarget()
	target.VaultOCID = "ocid1.vault.oc1.us-sanjose-1.aaaaaa"
	target.KMSKeyOCID = "ocid1.key.oc1.us-sanjose-1.aaaaaa"
	vault := newFakeVault(target)
	management, bundles := linkVaultProtocol(t, vault)
	var checkpoint []byte
	persist := func(wire []byte) error {
		checkpoint = bytes.Clone(wire)
		return nil
	}
	vault.uncertain = true
	if _, err := ProvisionLinkDurable(ctx, directory, target, management, bundles, f.now, persist); err == nil {
		t.Fatal("interrupted Vault publication reported success")
	}
	vault.uncertain = false
	publication, err := ProvisionLinkDurable(ctx, directory, target, management, bundles, f.now, persist)
	if err != nil || ValidateLinkPublication(directory, publication, checkpoint, f.now) != nil {
		t.Fatalf("public recipient publication did not recover: %v", err)
	}
	creates := vault.create
	again, err := ProvisionLinkDurable(ctx, directory, target, management, bundles, f.now, persist)
	if err != nil || !reflect.DeepEqual(publication, again) || vault.create != creates {
		t.Fatalf("publication retry replaced credentials: %v", err)
	}
	for _, ref := range publication.LinkGenerationReferences() {
		if ref.Purpose != bootstrap.SecretInterRegion {
			t.Fatal("recipient publication exposed home authority")
		}
	}
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
	spokeLink, err := RenderLink(record, "controller-a", directory)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(spokeLink.TLS.CertFile, spokeLink.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(spokeLink.TLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("issued link CA is invalid")
	}
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
	subject, _ := protocol.QuerySubject("sjc", "public-recipient")
	if _, err := client.Subscribe(subject, func(message *nats.Msg) { _ = message.Respond([]byte("sjc")) }); err != nil {
		t.Fatal(err)
	}
	if err := client.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		reply, err := home.Conn().Request(subject, nil, 100*time.Millisecond)
		if err == nil {
			if string(reply.Data) != "sjc" {
				t.Fatalf("wrong responding region %q", reply.Data)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("public-issued scoped leaf did not authenticate: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err := os.Remove(filepath.Join(directory, bootstrap.LinkCredentialsFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSpokeLink(f.home, f.homeLink, recipient, sourceDigest, directory, f.now); err == nil {
		t.Fatal("corrupted published source silently replaced credentials")
	}
}
