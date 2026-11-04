package natscell

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

var testSerial = big.NewInt(100)

func nextSerial() *big.Int { return testSerial.Add(testSerial, big.NewInt(1)) }

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: new(big.Int).Set(nextSerial()), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return testCA{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a leaf for name at ip, valid until notAfter, for server and
// client use unless usages are given.
func (ca testCA) leaf(t *testing.T, name, ip string, notAfter time.Time, usages ...x509.ExtKeyUsage,
) (certPEM, keyPEM []byte, serial *big.Int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial = new(big.Int).Set(nextSerial())
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), serial
}

func (ca testCA) client(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, _ := ca.leaf(t, "client", "127.0.0.1", time.Now().Add(time.Hour))
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// replace installs a file the way a renewal does: write aside, then rename.
func replace(t *testing.T, path string, data []byte) {
	t.Helper()
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}

func installTLS(t *testing.T, files TLSFiles, certPEM, keyPEM []byte, bundle ...testCA) {
	t.Helper()
	var cas []byte
	for _, ca := range bundle {
		cas = append(cas, ca.pem...)
	}
	replace(t, files.CAFile, cas)
	replace(t, files.KeyFile, keyPEM)
	replace(t, files.CertFile, certPEM)
}

// serveEcho accepts TLS connections and echoes what they send.
func serveEcho(t *testing.T, config *tls.Config) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

// dial returns the serial the server presented, or an error when either side
// refused the handshake.
func dial(address string, config *tls.Config) (*tls.Conn, *big.Int, error) {
	conn, err := tls.Dial("tcp", address, config)
	if err != nil {
		return nil, nil, err
	}
	// TLS 1.3 reports a refused client certificate on the first read.
	if _, err := conn.Write([]byte("x")); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, conn.ConnectionState().PeerCertificates[0].SerialNumber, nil
}

func clientConfig(roots []testCA, certificate tls.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	for _, ca := range roots {
		pool.AddCert(ca.certificate)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{certificate}}
}

func testTLSFiles(t *testing.T) TLSFiles {
	dir := t.TempDir()
	return TLSFiles{CAFile: filepath.Join(dir, "ca.pem"), CertFile: filepath.Join(dir, "tls-cert.pem"),
		KeyFile: filepath.Join(dir, "tls-key.pem")}
}

// A CA rollover: the bundle first gains the new CA, then the leaf moves to
// it, then the old CA is dropped. Clients and peers of either CA work while
// both are trusted, and only the new CA's afterwards.
func TestReloadingTLSRollsOverTheCA(t *testing.T) {
	old, next := newTestCA(t, "cell CA"), newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, _ := old.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, old)
	reloading, err := newCheckingTLS(files, "route")
	if err != nil {
		t.Fatal(err)
	}
	address := serveEcho(t, reloading.ServerConfig())
	oldClient, nextClient := old.client(t), next.client(t)
	accepts := func(step string, roots []testCA, certificate tls.Certificate, want bool) {
		t.Helper()
		conn, _, err := dial(address, clientConfig(roots, certificate))
		if conn != nil {
			conn.Close()
		}
		if (err == nil) != want {
			t.Fatalf("%s: accepted %v, want %v (%v)", step, err == nil, want, err)
		}
	}
	accepts("before the rollover, a new-CA client", []testCA{old, next}, nextClient, false)

	installTLS(t, files, certPEM, keyPEM, old, next)
	accepts("both trusted, an old-CA client", []testCA{old}, oldClient, true)
	accepts("both trusted, a new-CA client", []testCA{old}, nextClient, true)

	nextCert, nextKey, _ := next.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, nextCert, nextKey, old, next)
	accepts("new leaf, a peer that trusts only the new CA", []testCA{next}, nextClient, true)

	installTLS(t, files, nextCert, nextKey, next)
	accepts("old CA dropped, an old-CA client", []testCA{old, next}, oldClient, false)
	accepts("old CA dropped, a new-CA client", []testCA{next}, nextClient, true)

	t.Run("startup sets are rejected on live route reload", func(t *testing.T) {
		ca, stranger := newTestCA(t, "cell CA"), newTestCA(t, "stranger CA")
		for name, leaf := range map[string]func() ([]byte, []byte){
			"an expired leaf": func() ([]byte, []byte) {
				cert, key, _ := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(-time.Minute))
				return cert, key
			},
			"a route leaf without client use": func() ([]byte, []byte) {
				cert, key, _ := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth)
				return cert, key
			},
			"a leaf outside the bundle": func() ([]byte, []byte) {
				cert, key, _ := stranger.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
				return cert, key
			},
		} {
			files := testTLSFiles(t)
			cert, key := leaf()
			validCert, validKey, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
			installTLS(t, files, validCert, validKey, ca)
			reloading, err := newCheckingTLS(files, "route")
			if err != nil {
				t.Fatal(err)
			}
			address := serveEcho(t, reloading.PeerConfig())
			client := clientConfig([]testCA{ca}, ca.client(t))
			conn, serial, err := dial(address, client)
			if err != nil || serial.Cmp(first) != 0 {
				t.Fatalf("%s: startup route presented %v, want %v (%v)", name, serial, first, err)
			}
			conn.Close()
			installTLS(t, files, cert, key, ca)
			if _, err := NewReloadingTLS(files, "route"); err == nil {
				t.Errorf("startup accepted %s", name)
			}
			conn, serial, err = dial(address, client)
			if err != nil || serial.Cmp(first) != 0 {
				t.Fatalf("%s: rejected startup set changed the live route leaf to %v, want %v (%v)", name, serial, first, err)
			}
			conn.Close()
			renewedCert, renewedKey, renewed := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
			installTLS(t, files, renewedCert, renewedKey, ca)
			conn, serial, err = dial(address, client)
			if err != nil || serial.Cmp(renewed) != 0 || serial.Cmp(first) == 0 {
				t.Fatalf("%s: repaired route presented %v, want renewal %v (%v)", name, serial, renewed, err)
			}
			conn.Close()
		}
	})
}

// newCheckingTLS checks the files on every handshake, so a test sees each
// change at once.
func newCheckingTLS(files TLSFiles, role string) (*ReloadingTLS, error) {
	reloading, err := NewReloadingTLS(files, role)
	if reloading != nil {
		reloading.checkEvery = 0
	}
	return reloading, err
}
