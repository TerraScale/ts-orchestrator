//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

func ordinaryRuntimeFixture(t *testing.T, replicas int) (*qualificationRuntimeServices, nats.KeyValue) {
	t.Helper()
	plan, err := vmnet.Plan(vmnet.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newQualificationNATSAuthority(plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.close)
	// Give the real local cluster a loopback server identity while retaining the
	// independently issued client identities from the qualification fixture.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	transport.server = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	transport.ca = append(transport.ca, certPEM...)
	transport.roots.AppendCertsFromPEM(certPEM)
	transport.serverName = "127.0.0.1"
	readerIdentity := transport.guests["sfo-member-2"]
	pub, sub, err := nodeauthority.ReaderPermissions("ORCH_LEADERS")
	if err != nil {
		t.Fatal(err)
	}
	users := []*natsserver.NkeyUser{
		{Nkey: transport.controller.publicKey, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: []string{">"}}, Subscribe: &natsserver.SubjectPermission{Allow: []string{">"}}}},
		{Nkey: readerIdentity.publicKey, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: pub}, Subscribe: &natsserver.SubjectPermission{Allow: sub}}},
	}
	var servers []*natsserver.Server
	var routes []*url.URL
	for i := range replicas {
		options := &natsserver.Options{ServerName: "ordinary-" + string(rune('a'+i)), Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, Nkeys: users,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{transport.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: transport.roots},
			JetStream: true, StoreDir: t.TempDir(), JetStreamMaxMemory: 8 << 20, JetStreamMaxStore: 64 << 20}
		if replicas == 3 {
			options.Cluster = natsserver.ClusterOpts{Name: "ordinary-r3", Host: "127.0.0.1", Port: -1}
			if i == 0 {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				options.Cluster.Port = listener.Addr().(*net.TCPAddr).Port
				route, _ := url.Parse("nats-route://" + listener.Addr().String())
				routes = []*url.URL{route}
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			options.Routes = routes
		}
		server, err := natsserver.NewServer(options)
		if err != nil {
			t.Fatal(err)
		}
		server.Start()
		t.Cleanup(func() { server.Shutdown(); server.WaitForShutdown() })
		if !server.ReadyForConnections(5 * time.Second) {
			t.Fatal("NATS did not start")
		}
		servers = append(servers, server)
		if i == 0 && replicas == 3 {
			route, _ := url.Parse("nats-route://" + server.ClusterAddr().String())
			routes = []*url.URL{route}
		}
	}
	options, err := transport.options(transport.controller)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(servers[0].ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	var leaders nats.KeyValue
	deadline := time.Now().Add(10 * time.Second)
	for {
		leaders, err = js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "ORCH_LEADERS", Storage: nats.FileStorage, Replicas: replicas})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	endpoint := strings.Replace(servers[0].ClientURL(), "nats://", "tls://", 1)
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	reader := nodeauthority.ReaderConfig{Endpoint: endpoint, ServerName: servers[0].Name(), Account: "qualification", PublicNKey: readerIdentity.publicKey,
		NKeySeedFile: vmcontrolseed.AuthorityNKeyPath, CAFile: vmcontrolseed.AuthorityCAPath, CASHA256: digest(transport.ca), CertificateFile: vmcontrolseed.AuthorityCertificatePath, CertificateSHA256: digest(readerIdentity.certificate), KeyFile: vmcontrolseed.AuthorityPrivateKeyPath}
	refs := map[string]qualificationControlFile{}
	directory := t.TempDir()
	for path, raw := range map[string][]byte{reader.NKeySeedFile: readerIdentity.seed, reader.CAFile: transport.ca, reader.CertificateFile: readerIdentity.certificate, reader.KeyFile: readerIdentity.privateKey} {
		local := filepath.Join(directory, filepath.Base(path))
		if err := os.WriteFile(local, raw, 0600); err != nil {
			t.Fatal(err)
		}
		refs[path] = qualificationControlFile{Source: local, SHA256: digest(raw)}
	}
	now := time.Now().UTC()
	source := &qualificationAdmittedControlSource{config: bootstrap.NATSControlRuntimeConfig{Stores: map[string]bootstrap.ControlNATSStore{"sfo": {URL: endpoint, Options: options}}, Members: []bootstrap.ControlRuntimeMember{{HostID: "sfo-member-1", Instance: "sfo-member-1", Region: "sfo", Store: "sfo"}, {HostID: "sfo-member-2", Instance: "sfo-member-2", Region: "sfo", Store: "sfo"}}}, expectedStoreServers: map[string]string{"sfo": servers[0].Name()}, admissions: map[string]qualificationControlHostAdmission{"sfo-member-2": {Generation: 9}}, admittedIssuedAt: now.Add(-time.Minute), admittedExpiresAt: now.Add(time.Hour)}
	admission := &qualificationControlAdmission{source: source, authorityReaders: map[string]qualificationControlStoreDeclaration{"sfo-member-2": {Reader: reader, Files: refs}}, memberships: transport.memberships}
	production := transport.guests["fra-member-2"]
	root := "/etc/terrascale/run"
	run := vmcontrolseed.RunAdmission{HostID: "sfo-member-2", Generation: 9, Settings: map[string]string{"TS_ORCH_PROVIDER": "oci", "TS_ORCH_REPLICAS": "3", "TS_ORCH_PRODUCTION_RUNTIME_FILE": root + "/runtime.json"}, Files: map[string]vmcontrolseed.RunFile{}}
	run.Regional = vmcontrolseed.RunConnection{Endpoint: endpoint, ServerName: servers[0].Name(), Account: "qualification", Connection: initialgrant.Connection{PublicNKey: production.publicKey, NKeySeedFile: root + "/user.seed", TLS: initialgrant.TLSFiles{CAFile: root + "/ca.pem", CASHA256: digest(transport.ca), CertificateFile: root + "/client.pem", CertificateSHA256: digest(production.certificate), KeyFile: root + "/client.key"}}}
	runDir := t.TempDir()
	for path, raw := range map[string][]byte{root + "/user.seed": production.seed, root + "/ca.pem": transport.ca, root + "/client.pem": production.certificate, root + "/client.key": production.privateKey, root + "/runtime.json": []byte(`{"version":1}`)} {
		local := filepath.Join(runDir, filepath.Base(path))
		if err := os.WriteFile(local, raw, 0600); err != nil {
			t.Fatal(err)
		}
		run.Files[path] = vmcontrolseed.RunFile{Source: local, SHA256: digest(raw)}
	}
	artifacts := []guestArtifactInput{{manifest: vmimage.GuestArtifact{Component: "orchestrator", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}}, {manifest: vmimage.GuestArtifact{Component: "terrabase", Version: "1.0.0", SHA256: strings.Repeat("b", 64)}}, {manifest: vmimage.GuestArtifact{Component: "ts-node", Version: "1.0.0", SHA256: strings.Repeat("c", 64)}, binary: []byte("fixture"), signature: make([]byte, ed25519.SignatureSize)}}
	manifest, err := desiredHostManifest(artifacts, 8443)
	if err != nil {
		t.Fatal(err)
	}
	_, engineDeclaration := testengineconfig.Declaration(t, launchEngineBindings(plan), strings.Repeat("b", 64), "1.0.0")
	engines, err := vmengineconfig.Load(engineDeclaration, strings.Repeat("b", 64), "1.0.0", launchEngineBindings(plan))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, material := range engines {
			material.Clear()
		}
	})
	issuer, err := vmqualbootstrap.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	services := &qualificationRuntimeServices{plan: plan, natsAuthority: transport, artifacts: artifacts, manifest: manifest, engineSeeds: engines, bootstrapIssuer: issuer, controlAdmission: admission, runAdmissions: map[string]vmcontrolseed.RunAdmission{"sfo-member-2": run}}
	t.Cleanup(func() {
		for _, m := range services.runMaterials {
			m.Clear()
		}
		for _, m := range admission.ordinaryAuthorities {
			m.Clear()
		}
	})
	return services, leaders
}

func TestOrdinaryBootstrapUsesRealR3AndIndependentReader(t *testing.T) {
	services, leaders := ordinaryRuntimeFixture(t, 3)
	guest := vmqual.Guest{ID: "sfo-member-2", Region: vmnet.SFO}
	factory := &firecrackerFactory{services: services}
	if _, _, err := services.Bootstrap(guest); err == nil {
		t.Fatal("bootstrapped before live authority probe")
	}
	write := func(candidate string) {
		t.Helper()
		lease := authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "sfo-regional", Epoch: 7, CandidateId: candidate, LeaseId: "ordinary-lease", IssuedAt: time.Now().UTC().Add(-time.Second), DurationMilliseconds: 30000}
		raw, err := json.Marshal(lease)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaders.Put("authority.regional", raw); err != nil {
			t.Fatal(err)
		}
	}
	write("sfo-controller-foreign")
	if err := factory.prepareGuestAdmission(t.Context(), guest); err == nil {
		t.Fatal("foreign authority admitted ordinary member")
	}
	write("sfo-controller-sfo-member-1")
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := factory.prepareGuestAdmission(t.Context(), guest)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	seed, _, err := services.Bootstrap(guest)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.ControllerRun.Clear()
	defer seed.OrdinaryAuthority.Clear()
	defer seed.Engine.Clear()
	grant, err := hostagent.VerifyBootstrapGrant(guest.ID, seed.InitialGrant.PublicKeyPEM, seed.InitialGrant.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
	if err != nil || !bytes.Equal(canonical, seed.DesiredHostManifest) {
		t.Fatal("finite grant lost production manifest")
	}
	if seed.Controller != nil || seed.Candidate != nil || seed.ControllerRun.ExpectedManifestSHA != "" || seed.OrdinaryAuthority.ValidateManifest(guest.ID, grant.Manifest) != nil {
		t.Fatal("ordinary member forged a predecessor or lost reader pin")
	}
	for path := range seed.OrdinaryAuthority.Files {
		if seed.ControllerRun.Files[path] != nil {
			t.Fatal("root reader entered controller inventory")
		}
	}
	again, _, err := services.Bootstrap(guest)
	if err != nil {
		t.Fatal(err)
	}
	defer again.ControllerRun.Clear()
	defer again.OrdinaryAuthority.Clear()
	defer again.Engine.Clear()
	if !bytes.Equal(seed.InitialGrant.SignedGrant, again.InitialGrant.SignedGrant) {
		t.Fatal("retry changed finite grant")
	}
	write("sfo-controller-foreign")
	if err := factory.prepareGuestAdmission(t.Context(), guest); err == nil {
		t.Fatal("retry retained stale authority admission")
	}
	if _, _, err := services.Bootstrap(guest); err == nil {
		t.Fatal("failed retry left ordinary bootstrap admitted")
	}
}

func TestOrdinaryBootstrapRefusesRealR1(t *testing.T) {
	services, _ := ordinaryRuntimeFixture(t, 1)
	guest := vmqual.Guest{ID: "sfo-member-2", Region: vmnet.SFO}
	if err := (&firecrackerFactory{services: services}).prepareGuestAdmission(t.Context(), guest); err == nil {
		t.Fatal("R1 authorized ordinary member")
	}
	if services.ordinaryPrepared[guest.ID] {
		t.Fatal("failed preparation retained admission")
	}
}
