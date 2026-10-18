package natscell

import (
	"bytes"
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
	"sync"
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

// A renewed leaf is served on the next handshake while live connections keep
// working. A renewal caught between its two renames, a leaf for another slot,
// an expired leaf and a leaf from an untrusted CA are each refused, and the
// last good certificate stays in use.
func TestReloadingTLSServesRenewedLeafOnly(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	reloading, err := newCheckingTLS(files, "listener")
	if err != nil {
		t.Fatal(err)
	}
	address := serveEcho(t, reloading.ServerConfig())
	client := clientConfig([]testCA{ca}, ca.client(t))
	live, serial, err := dial(address, client)
	if err != nil || serial.Cmp(first) != 0 {
		t.Fatalf("startup leaf: serial %v, %v", serial, err)
	}
	defer live.Close()
	expect := func(want *big.Int, step string) {
		t.Helper()
		conn, serial, err := dial(address, client)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		conn.Close()
		if serial.Cmp(want) != 0 {
			t.Fatalf("%s: served serial %v, want %v", step, serial, want)
		}
	}

	renewedCert, renewedKey, renewed := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
	replace(t, files.CertFile, renewedCert)
	expect(first, "a certificate without its new key")
	replace(t, files.KeyFile, renewedKey)
	expect(renewed, "a complete renewal")

	otherCert, otherKey, _ := ca.leaf(t, "gru-1-ctl-2", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, otherCert, otherKey, ca)
	expect(renewed, "another slot's leaf")
	expiredCert, expiredKey, _ := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(-time.Minute))
	installTLS(t, files, expiredCert, expiredKey, ca)
	expect(renewed, "an expired leaf")
	stranger := newTestCA(t, "stranger CA")
	strangerCert, strangerKey, _ := stranger.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, strangerCert, strangerKey, ca)
	expect(renewed, "a leaf from an untrusted CA")
	installTLS(t, files, strangerCert, strangerKey, stranger)
	expect(renewed, "a wholesale swap to another CA")

	if _, err := live.Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("still here"))
	if _, err := io.ReadFull(live, echo); err != nil || !bytes.Equal(echo, []byte("still here")) {
		t.Fatalf("a live connection broke across reloads: %q, %v", echo, err)
	}
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

// The dialing end of a route presents a renewed certificate on its next dial
// and verifies the peer, address included, against the bundle it started
// with: a peer moved to a new CA is trusted only after a restart.
func TestReloadingTLSPeerConfig(t *testing.T) {
	old, next := newTestCA(t, "cell CA"), newTestCA(t, "cell CA")
	serverFiles, dialerFiles := testTLSFiles(t), testTLSFiles(t)
	serverCert, serverKey, _ := old.leaf(t, "gru-1-ctl-2", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, serverFiles, serverCert, serverKey, old, next)
	dialerCert, dialerKey, first := old.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, dialerFiles, dialerCert, dialerKey, old)
	server, err := newCheckingTLS(serverFiles, "route")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", server.PeerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	presented := make(chan *big.Int, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if err := conn.(*tls.Conn).Handshake(); err == nil {
					presented <- conn.(*tls.Conn).ConnectionState().PeerCertificates[0].SerialNumber
				}
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	route := func(dialer *ReloadingTLS, serverName string) (*big.Int, error) {
		config := dialer.PeerConfig().Clone()
		config.ServerName = serverName
		conn, _, err := dial(listener.Addr().String(), config)
		if err != nil {
			return nil, err
		}
		conn.Close()
		return <-presented, nil
	}
	dialer, err := newCheckingTLS(dialerFiles, "route")
	if err != nil {
		t.Fatal(err)
	}
	if serial, err := route(dialer, "127.0.0.1"); err != nil || serial.Cmp(first) != 0 {
		t.Fatalf("startup route: presented %v, %v", serial, err)
	}
	renewedCert, renewedKey, renewed := old.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
	installTLS(t, dialerFiles, renewedCert, renewedKey, old)
	if serial, err := route(dialer, "127.0.0.1"); err != nil || serial.Cmp(renewed) != 0 {
		t.Fatalf("renewed route: presented %v, want %v (%v)", serial, renewed, err)
	}
	if _, err := route(dialer, "10.0.0.9"); err == nil {
		t.Fatal("a route whose peer certificate names another address was accepted")
	}

	movedCert, movedKey, _ := next.leaf(t, "gru-1-ctl-2", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, serverFiles, movedCert, movedKey, old, next)
	installTLS(t, dialerFiles, renewedCert, renewedKey, old, next)
	if _, err := route(dialer, "127.0.0.1"); err == nil {
		t.Fatal("a running dialer trusted a CA it did not start with")
	}
	restarted, err := newCheckingTLS(dialerFiles, "route")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route(restarted, "127.0.0.1"); err != nil {
		t.Fatalf("after a restart the new CA's peer must be trusted: %v", err)
	}
}

// A renewed route leaf must still serve both ends of a route.
func TestReloadingTLSKeepsTheRoleUsages(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	route, err := newCheckingTLS(files, "route")
	if err != nil {
		t.Fatal(err)
	}
	serverOnly, serverOnlyKey, _ := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour),
		x509.ExtKeyUsageServerAuth)
	installTLS(t, files, serverOnly, serverOnlyKey, ca)
	if serial := route.material().certificate.Leaf.SerialNumber; serial.Cmp(first) != 0 {
		t.Fatalf("a route leaf without client use was loaded: serial %v", serial)
	}
	if _, err := NewReloadingTLS(files, "broker"); err == nil {
		t.Fatal("an unknown role was accepted")
	}
}

// Dropping a CA from the bundle stops the dialing side trusting it at once,
// even though it was in the bundle at startup.
func TestReloadingTLSPeerDropsACAAtOnce(t *testing.T) {
	old, next := newTestCA(t, "cell CA"), newTestCA(t, "cell CA")
	serverFiles, dialerFiles := testTLSFiles(t), testTLSFiles(t)
	serverCert, serverKey, _ := old.leaf(t, "gru-1-ctl-2", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, serverFiles, serverCert, serverKey, old, next)
	dialerCert, dialerKey, _ := next.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, dialerFiles, dialerCert, dialerKey, old, next)
	server, err := newCheckingTLS(serverFiles, "route")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := newCheckingTLS(dialerFiles, "route")
	if err != nil {
		t.Fatal(err)
	}
	address := serveEcho(t, server.PeerConfig())
	route := func() error {
		config := dialer.PeerConfig().Clone()
		config.ServerName = "127.0.0.1"
		conn, _, err := dial(address, config)
		if conn != nil {
			conn.Close()
		}
		return err
	}
	if err := route(); err != nil {
		t.Fatalf("both CAs trusted: %v", err)
	}
	installTLS(t, dialerFiles, dialerCert, dialerKey, next)
	if err := route(); err == nil {
		t.Fatal("a peer from a dropped CA was still trusted")
	}
}

// The whole subject is part of the identity, not only the common name.
func TestReloadingTLSKeepsTheWholeSubject(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	reloading, err := newCheckingTLS(files, "listener")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: nextSerial(),
		Subject:   pkix.Name{CommonName: "gru-1-ctl-1", Organization: []string{"someone else"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	installTLS(t, files, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), ca)
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(first) != 0 {
		t.Fatalf("a leaf with another subject organization was loaded: serial %v", serial)
	}
	renewedCert, renewedKey, renewed := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
	installTLS(t, files, renewedCert, renewedKey, ca)
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(renewed) != 0 {
		t.Fatalf("a renewal was not loaded: serial %v", serial)
	}
}

// While one handshake reloads, the others use the current set instead of
// waiting for its file reads.
func TestReloadingTLSDoesNotWaitForAReloadInFlight(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	reloading, err := newCheckingTLS(files, "listener")
	if err != nil {
		t.Fatal(err)
	}
	renewedCert, renewedKey, renewed := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
	installTLS(t, files, renewedCert, renewedKey, ca)
	reloading.mu.Lock()
	reloading.loading = true
	reloading.mu.Unlock()
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(first) != 0 {
		t.Fatalf("a handshake during a reload got serial %v, want the current %v", serial, first)
	}
	reloading.mu.Lock()
	reloading.loading = false
	reloading.mu.Unlock()
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(renewed) != 0 {
		t.Fatalf("after the reload: serial %v, want %v", serial, renewed)
	}
}

// Concurrent handshakes during repeated renewals always get a whole set and
// end on the last renewal.
func TestReloadingTLSConcurrentRenewals(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, _ := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	reloading, err := newCheckingTLS(files, "listener")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				material := reloading.material()
				if material.certificate == nil || material.roots == nil {
					t.Error("a handshake got an incomplete set")
					return
				}
			}
		})
	}
	var last *big.Int
	for range 5 {
		var cert, key []byte
		cert, key, last = ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
		installTLS(t, files, cert, key, ca)
		time.Sleep(10 * time.Millisecond)
	}
	close(done)
	workers.Wait()
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(last) != 0 {
		t.Fatalf("ended on serial %v, want the last renewal %v", serial, last)
	}
}

// Startup makes the checks a reload makes against its own bundle.
func TestReloadingTLSChecksTheStartupSet(t *testing.T) {
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
		installTLS(t, files, cert, key, ca)
		if _, err := NewReloadingTLS(files, "route"); err == nil {
			t.Errorf("startup accepted %s", name)
		}
	}
}

// A renewal written in place under the same inode, size and modification
// time is still seen: sets are told apart by their bytes.
func TestReloadingTLSSeesAnInPlaceRewrite(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	reloading, err := newCheckingTLS(files, "listener")
	if err != nil {
		t.Fatal(err)
	}
	var renewedCert, renewedKey []byte
	var renewed *big.Int
	for range 100 {
		renewedCert, renewedKey, renewed = ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
		if len(renewedCert) == len(certPEM) && len(renewedKey) == len(keyPEM) {
			break
		}
	}
	if len(renewedCert) != len(certPEM) || len(renewedKey) != len(keyPEM) {
		t.Skip("no renewal of the same encoded size was issued")
	}
	for path, data := range map[string][]byte{files.CertFile: renewedCert, files.KeyFile: renewedKey} {
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt(data, 0); err != nil {
			t.Fatal(err)
		}
		file.Close()
		if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
	}
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(renewed) != 0 || serial.Cmp(first) == 0 {
		t.Fatalf("an in-place rewrite was not seen: serial %v", serial)
	}
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

// Between checks no handshake reads the files; the next check sees the
// renewal.
func TestReloadingTLSChecksAtMostEveryInterval(t *testing.T) {
	ca := newTestCA(t, "cell CA")
	files := testTLSFiles(t)
	certPEM, keyPEM, first := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(time.Hour))
	installTLS(t, files, certPEM, keyPEM, ca)
	reloading, err := NewReloadingTLS(files, "listener")
	if err != nil {
		t.Fatal(err)
	}
	renewedCert, renewedKey, renewed := ca.leaf(t, "gru-1-ctl-1", "127.0.0.1", time.Now().Add(2*time.Hour))
	installTLS(t, files, renewedCert, renewedKey, ca)
	// The renewal is valid: any handshake that read the files would load it.
	for range 100 {
		if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(first) != 0 {
			t.Fatalf("a handshake between checks served serial %v", serial)
		}
	}
	reloading.mu.Lock()
	reloading.checkedAt = time.Now().Add(-tlsCheckEvery)
	reloading.mu.Unlock()
	if serial := reloading.material().certificate.Leaf.SerialNumber; serial.Cmp(renewed) != 0 {
		t.Fatalf("the next check served serial %v, want the renewal %v", serial, renewed)
	}
}
