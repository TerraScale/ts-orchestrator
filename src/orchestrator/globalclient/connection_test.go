//go:build unix

package globalclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

func clientFixture(t *testing.T, maximumTLS uint16) (*directory.GlobalAuthorityNatsConfiguration, *natsserver.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(user.Wipe)
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certificate := write("identity.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	privateFile := write("private.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	seedFile := write("user.seed", seed)
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true, Nkeys: []*natsserver.NkeyUser{{Nkey: public}}, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: maximumTLS, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("TLS broker failed to start")
	}
	t.Cleanup(func() { server.Shutdown(); server.WaitForShutdown() })
	config := &directory.GlobalAuthorityNatsConfiguration{Url: "tls://" + server.Addr().String(), Cell: "gru", Replicas: 3, Authentication: &messaging.NatsAuthenticationFiles{NKeyFile: &seedFile, PublicKey: public}, Tls: &messaging.NatsTlsFiles{CaFile: certificate, CertificateFile: certificate, KeyFile: privateFile}}
	return config, server
}

func TestConcreteConnectionCopiesReferencesAndDisablesReconnect(t *testing.T) {
	config, server := clientFixture(t, tls.VersionTLS13)
	plan, err := Admit(config)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Matches(config) {
		t.Fatal("admitted config does not match")
	}
	originalPublic := config.Authentication.PublicKey
	*config.Authentication.NKeyFile = "missing-seed"
	config.Authentication.PublicKey = "changed"
	config.Tls.CaFile = "missing-ca"
	config.Url = "tls://other.invalid:4222"
	if plan.Matches(config) {
		t.Fatal("mutated config still matches")
	}
	dialCtx, cancelDial := context.WithCancel(context.Background())
	defer cancelDial()
	connection, err := plan.Connect(dialCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	cancelDial()
	if err := connection.FlushTimeout(time.Second); err != nil {
		t.Fatalf("establishment cancellation closed transferred connection: %v", err)
	}
	state, err := connection.TLSConnectionState()
	if err != nil {
		t.Fatal(err)
	}
	if connection.Opts.Nkey != originalPublic || connection.Opts.SignatureCB == nil || connection.Opts.AllowReconnect || connection.Opts.ReconnectBufSize != -1 || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		t.Fatal("connection lost admitted identity or transport bounds")
	}
	if _, err := keyrotation.NewNATSStateStore(keyrotation.NATSStateStoreConfig{Connection: connection, CandidateID: "global-controller-gru-test", AuthorityEpoch: 1, LeaseID: "test-lease"}); err != nil {
		t.Fatalf("rotation rejected concrete transport: %v", err)
	}
	if _, err := reaper.NewNATSStateStore(reaper.NATSStateStoreConfig{Connection: connection, CandidateID: "global-controller-gru-test", AuthorityEpoch: 1, LeaseID: "test-lease"}); err != nil {
		t.Fatalf("reaper rejected concrete transport: %v", err)
	}
	if _, err := restoredrill.NewNATSJournal(restoredrill.NATSJournalConfig{Connection: connection, CandidateID: "global-controller-gru-test", AuthorityEpoch: 1, LeaseID: "test-lease"}); err != nil {
		t.Fatalf("restore rejected concrete transport: %v", err)
	}
	closed := connection.StatusChanged(nats.CLOSED)
	server.Shutdown()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("session connection tried to reconnect")
	}
}

func TestConcreteConnectionRejectsDowngradeAndIdentityReplacement(t *testing.T) {
	t.Run("TLS12", func(t *testing.T) {
		config, _ := clientFixture(t, tls.VersionTLS12)
		plan, err := Admit(config)
		if err != nil {
			t.Fatal(err)
		}
		if connection, err := plan.Connect(context.Background()); err == nil {
			connection.Close()
			t.Fatal("TLS1.2 downgrade accepted")
		}
	})
	t.Run("changed seed", func(t *testing.T) {
		config, _ := clientFixture(t, tls.VersionTLS13)
		plan, err := Admit(config)
		if err != nil {
			t.Fatal(err)
		}
		other, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		defer other.Wipe()
		seed, err := other.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(*config.Authentication.NKeyFile, seed, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := plan.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("changed identity error=%v", err)
		}
	})
}

func TestConnectionAdmissionRejectsUnsupportedAndIncompleteIdentity(t *testing.T) {
	for _, mode := range []string{"JWT credentials", "missing seed", "changed public key", "missing TLS key", "URL credentials", "URL empty query", "URL empty fragment", "URL opaque", "wrong region", "R1"} {
		t.Run(mode, func(t *testing.T) {
			config, _ := clientFixture(t, tls.VersionTLS13)
			switch mode {
			case "JWT credentials":
				file := "declared.creds"
				config.Authentication.CredentialsFile = &file
			case "missing seed":
				config.Authentication.NKeyFile = nil
			case "changed public key":
				config.Authentication.PublicKey = "other"
			case "missing TLS key":
				config.Tls.KeyFile = ""
			case "URL credentials":
				config.Url = "tls://user:password@127.0.0.1:4222"
			case "URL empty query":
				config.Url += "?"
			case "URL empty fragment":
				config.Url += "#"
			case "URL opaque":
				config.Url = "tls:server"
			case "wrong region":
				config.Cell = "sfo"
			case "R1":
				config.Replicas = 1
			}
			if _, err := Admit(config); err == nil {
				t.Fatal("invalid identity admitted")
			}
		})
	}
	config, _ := clientFixture(t, tls.VersionTLS13)
	plan, err := Admit(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := plan.Connect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled connection error=%v", err)
	}
}

func TestConcreteConnectionDeadlineClosesStalledHandshake(t *testing.T) {
	config, _ := clientFixture(t, tls.VersionTLS13)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	config.Url = "tls://" + listener.Addr().String()
	plan, err := Admit(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	before := time.Now()
	connection, err := plan.Connect(ctx)
	if connection != nil {
		connection.Close()
		t.Fatal("stalled server produced a connection")
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(before) > time.Second {
		t.Fatalf("deadline did not bound connection: %v", err)
	}
	select {
	case peer := <-accepted:
		defer peer.Close()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		if _, err := peer.Read(buffer); !errors.Is(err, io.EOF) {
			t.Fatalf("stalled handshake socket was not closed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial never reached test listener")
	}
}
