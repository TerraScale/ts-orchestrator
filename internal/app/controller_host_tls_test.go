package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func testR3TLSMaterial(t *testing.T, root string) (natscell.TLSFiles, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "R3 test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "R3 test peer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	files := natscell.TLSFiles{
		CAFile:   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertFile: write("peer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		KeyFile:  write("peer-key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
	return files, write("route-password", []byte("r3-test-route-secret-0123456789"))
}

func r3RouteUser(production bool) string {
	if production {
		return "r3-test-route"
	}
	return ""
}

// This proxy leaves the host's TCP socket open when its upstream controller
// disappears, matching a network blackhole rather than a clean FIN or RST.
type r3BlackholeProxy struct {
	listener net.Listener
	blocked  atomic.Bool
	mu       sync.Mutex
	conns    []net.Conn
	release  chan struct{}
}

func newR3BlackholeProxy(t *testing.T, target string) *r3BlackholeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &r3BlackholeProxy{listener: listener, release: make(chan struct{})}
	t.Cleanup(func() {
		_ = listener.Close()
		close(proxy.release)
		proxy.mu.Lock()
		defer proxy.mu.Unlock()
		for _, conn := range proxy.conns {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			upstream, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			proxy.mu.Lock()
			proxy.conns = append(proxy.conns, client, upstream)
			proxy.mu.Unlock()
			go proxy.forward(client, upstream)
			go proxy.forward(upstream, client)
		}
	}()
	return proxy
}

func (p *r3BlackholeProxy) forward(source, destination net.Conn) {
	defer source.Close()
	defer destination.Close()
	var buffer [4096]byte
	for {
		count, err := source.Read(buffer[:])
		if err != nil {
			if p.blocked.Load() {
				<-p.release
			}
			return
		}
		if !p.blocked.Load() {
			if _, err := destination.Write(buffer[:count]); err != nil {
				if p.blocked.Load() {
					<-p.release
				}
				return
			}
		}
	}
}

type r3StopOnCloseRunner struct{ *inMemoryRunner }

func (r *r3StopOnCloseRunner) Close(ctx context.Context) error {
	return r.Stop(ctx, "terrabase")
}
