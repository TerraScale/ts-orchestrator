package bootstrapcredentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func connectionFixture(t *testing.T) (Reference, string) {
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
	defer clear(private)
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	seed, _ := pair.Seed()
	defer clear(seed)
	public, _ := pair.PublicKey()
	root := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true, Nkeys: []*server.NkeyUser{{Nkey: public}}, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	if !srv.ReadyForConnections(time.Second) {
		t.Fatal("test broker not ready")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	return Reference{URL: "tls://" + srv.Addr().String(), CAFile: write("ca.pem", cert), CertificateFile: write("client.pem", cert), PrivateKeyFile: write("client.key", keyPEM), NKeySeedFile: write("user.seed", seed)}, public
}
func TestCapturedCredentialsConnectAfterFilesReplacedAndUntilClosed(t *testing.T) {
	ref, public := connectionFixture(t)
	credentials, err := Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Close()
	ca, _ := ReadFile(ref.CAFile, false, 1<<20)
	cert, _ := ReadFile(ref.CertificateFile, false, 1<<20)
	expected := Identity{URL: ref.URL, PublicNKey: public, CASHA256: hash(ca), CertificateSHA256: hash(cert)}
	if credentials.PublicIdentity() != expected {
		t.Fatal("captured public identity differs")
	}
	for _, path := range []string{ref.CAFile, ref.CertificateFile, ref.PrivateKeyFile, ref.NKeySeedFile} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		opts := append([]nats.Option(nil), credentials.Options...)
		opts = append(opts, nats.Timeout(time.Second))
		connection, err := nats.Connect(credentials.URL, opts...)
		if err != nil {
			t.Fatalf("captured identity connection %d: %v", i, err)
		}
		state, err := connection.TLSConnectionState()
		if err != nil || state.Version != tls.VersionTLS13 || !connection.AuthRequired() || connection.Opts.AllowReconnect || connection.Opts.ReconnectBufSize != -1 {
			t.Fatal("authenticated unbuffered TLS session not established")
		}
		connection.Close()
	}
	if err := credentials.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.sign([]byte("nonce")); err == nil {
		t.Fatal("closed credential still signed")
	}
	if credentials.PublicIdentity() != expected {
		t.Fatal("closing credentials changed public evidence")
	}
}
func TestLoadBoundsPrivateSeed(t *testing.T) {
	ref, _ := connectionFixture(t)
	if err := os.WriteFile(ref.NKeySeedFile, make([]byte, 4097), 0600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(ref); err == nil {
		c.Close()
		t.Fatal("oversized seed admitted")
	}
}
