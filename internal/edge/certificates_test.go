package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/crypto/acme/autocert"
)

type testAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var trustedRoot testAuthority

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "edge-roots")
	if err != nil {
		panic(err)
	}
	trustedRoot = newAuthority(nil, "edge test root")
	path := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedRoot.cert.Raw}), 0600); err != nil {
		panic(err)
	}
	if err := os.Setenv("SSL_CERT_FILE", path); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newAuthority(parent *testAuthority, name string) testAuthority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return testAuthority{cert, key}
}

func leafPair(t *testing.T, name string, issuer *testAuthority, chain ...*x509.Certificate) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	parent, signer := template, any(key)
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	for _, cert := range chain {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return data
}

func testStore(t *testing.T) *certificateCache {
	t.Helper()
	node, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go node.Start()
	if !node.ReadyForConnections(3 * time.Second) {
		t.Fatal("store unavailable")
	}
	t.Cleanup(func() { node.Shutdown(); node.WaitForShutdown() })
	conn, err := nats.Connect(node.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{"edge-certs", "edge-cert-tokens"} {
		if _, err := js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{Bucket: bucket, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	cache := &certificateCache{local: autocert.DirCache(t.TempDir()), source: func() (*nats.Conn, []byte, error) { return conn, make([]byte, 32), nil }, roster: func() (string, []string, error) { return "live", []string{"live"}, nil }}
	if err := cache.open(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.stopWatch)
	return cache
}

func TestServedCertificateBecomesDurableAfterDiskRecovers(t *testing.T) {
	ctx := context.Background()
	name := "persistence.edge.test"
	cache := testStore(t)
	dir := string(cache.local)
	value, revision, err := cache.shared(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	value.Data = cache.seal.Seal(nil, nil, leafPair(t, name, &trustedRoot), []byte(name))
	if _, err := cache.write(ctx, name, value, revision); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
		t.Fatal(err)
	}
	edge := New(t.TempDir())
	edge.certs.cache = cache
	if err := cache.reconcile(ctx, name); err == nil {
		t.Fatal("reconcile reported success while the disk write failed")
	}
	if _, served := cache.memory.Load(name); !served {
		t.Fatal("certificate not served after a failed disk write")
	}
	if metric := certificateMetric(t, edge, "ts_orch_edge_certificate_not_durable"); metric != "1" {
		t.Errorf("not durable metric during disk failure = %q, want 1", metric)
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := cache.reconcile(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("certificate still not on disk after recovery: %v", err)
	}
	if metric := certificateMetric(t, edge, "ts_orch_edge_certificate_not_durable"); metric != "0" {
		t.Errorf("not durable metric after recovery = %q, want 0", metric)
	}
	restart := &certificateCache{local: cache.local}
	if err := restart.loadDisk(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := restart.memory.Load(name); !ok {
		t.Fatal("restart lost the served certificate")
	}
}

func certificateMetric(t *testing.T, edge *Edge, series string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	edge.serveCertificateMetrics(recorder, httptest.NewRequest(http.MethodGet, "/edge/certificates/metrics", nil))
	for line := range strings.SplitSeq(recorder.Body.String(), "\n") {
		if value, ok := strings.CutPrefix(line, series+" "); ok {
			return value
		}
	}
	return ""
}

func readinessEdge(t *testing.T, files map[string][]byte, routes ...string) *Edge {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "edge-certs"), 0700); err != nil {
		t.Fatal(err)
	}
	for key, data := range files {
		if err := os.WriteFile(filepath.Join(dir, "edge-certs", key), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	edge := New(dir)
	table := map[string]int{}
	for _, route := range routes {
		table[route] = 8080
	}
	edge.SetRoutes(table, nil)
	if err := edge.certs.cache.loadDisk(context.Background()); err != nil {
		t.Fatal(err)
	}
	edge.readyStatus.Store(&readinessVerdict{ok: true, at: time.Now()})
	return edge
}

func handshake(t *testing.T, edge *Edge, name string) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		done <- tls.Server(conn, edge.certificateTLSConfig()).Handshake()
	}()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{ServerName: name})
	if conn != nil {
		conn.Close()
	}
	<-done
	return err
}

func TestReadinessCountsCertificatesTheHandshakeSelects(t *testing.T) {
	routed := "two.wild.edge.test"
	edge := readinessEdge(t, map[string][]byte{"one.wild.edge.test": leafPair(t, "*.wild.edge.test", &trustedRoot)}, routed)
	if err := handshake(t, edge, routed); err != nil {
		t.Fatalf("handshake for wildcard-covered name: %v", err)
	}
	if ready, missing, names := edge.readiness(); !ready {
		t.Fatalf("ready=false while serving valid HTTPS: missing=%v names=%v", missing, names)
	}
}

func TestReadinessRejectsChainsClientsReject(t *testing.T) {
	intermediate := newAuthority(&trustedRoot, "edge test intermediate")
	cases := []struct {
		label string
		data  func(string) []byte
		ready bool
	}{
		{"untrusted", func(name string) []byte { return leafPair(t, name, nil) }, false},
		{"incomplete", func(name string) []byte { return leafPair(t, name, &intermediate) }, false},
		{"complete", func(name string) []byte { return leafPair(t, name, &intermediate, intermediate.cert) }, true},
	}
	for _, item := range cases {
		t.Run(item.label, func(t *testing.T) {
			name := item.label + ".chain.edge.test"
			edge := readinessEdge(t, map[string][]byte{name: item.data(name)}, name)
			handshakeErr := handshake(t, edge, name)
			ready, missing, names := edge.readiness()
			if ready != item.ready || (handshakeErr == nil) != item.ready {
				t.Fatalf("ready=%v missing=%v names=%v handshake=%v, want ready=%v", ready, missing, names, handshakeErr, item.ready)
			}
		})
	}
}

func TestRetiredMemberStopsBlockingNewNames(t *testing.T) {
	ctx := context.Background()
	cache := testStore(t)
	cache.roster = func() (string, []string, error) { return "live", []string{"live", "retired"}, nil }
	if err := cache.publishHoldings(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cache.orderEvidence(ctx, "new.edge.test"); !errors.Is(err, errIssueHeld) {
		t.Fatalf("order allowed while a member has not published: %v", err)
	}
	cache.roster = func() (string, []string, error) { return "live", []string{"live"}, nil }
	if err := cache.publishHoldings(ctx); err != nil {
		t.Fatal(err)
	}
	entry, err := cache.certs.Get(ctx, "holdings."+cacheKey("live"))
	if err != nil {
		t.Fatal(err)
	}
	var holdings certificateHoldings
	if err := json.Unmarshal(entry.Value(), &holdings); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(holdings.Registered, []string{"live"}) {
		t.Errorf("published roster %v, want [live]", holdings.Registered)
	}
	if err := cache.orderEvidence(ctx, "new.edge.test"); err != nil {
		t.Fatalf("retired member still blocks new names: %v", err)
	}
}

type ackGate struct {
	armed  atomic.Bool
	paused atomic.Bool
	resume chan struct{}
}

func (g *ackGate) Dial(network, address string) (net.Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &gatedConn{Conn: conn, gate: g}, nil
}

type gatedConn struct {
	net.Conn
	gate *ackGate
}

func (c *gatedConn) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(`"Lease"`)) && c.gate.armed.CompareAndSwap(true, false) {
		c.gate.paused.Store(true)
	}
	return c.Conn.Write(data)
}

func (c *gatedConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if c.gate.paused.Load() {
		<-c.gate.resume
	}
	return n, err
}

func TestAdoptedLeaseKeepsLongerAuthorityDeadline(t *testing.T) {
	ctx := context.Background()
	cache := testStore(t)
	key := "deadline.edge.test"
	source := cache.source
	gate := &ackGate{resume: make(chan struct{})}
	conn, err := nats.Connect(cache.conn.ConnectedUrl(), nats.SetCustomDialer(gate))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cache.source = func() (*nats.Conn, []byte, error) { return conn, make([]byte, 32), nil }
	if err := cache.open(ctx); err != nil {
		t.Fatal(err)
	}
	gate.armed.Store(true)
	first, err := cache.lease(ctx, key)
	close(gate.resume)
	if first != nil || err == nil {
		t.Fatalf("expected an unacknowledged lease write, got lease=%v err=%v", first != nil, err)
	}
	peer := &certificateCache{local: autocert.DirCache(t.TempDir()), source: source, roster: cache.roster}
	if err := peer.open(ctx); err != nil {
		t.Fatal(err)
	}
	defer peer.stopWatch()
	authority := certificateRetry{Attempt: 1, Next: time.Now().Add(48 * time.Hour), Updated: time.Now()}
	if err := peer.saveRetry(ctx, key, authority); err != nil {
		t.Fatal(err)
	}
	if err := peer.publishRetry(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := cache.reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	before, _, err := cache.shared(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := cache.lease(ctx, key)
	if lease != nil {
		lease.cancel()
		<-lease.done
	}
	after, _, readErr := cache.shared(ctx, key)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if lease != nil || !errors.Is(err, errIssueHeld) {
		t.Fatalf("adoption ordered before the 48h authority deadline: lease=%v err=%v", lease != nil, err)
	}
	if after.Retry.Next.Before(before.Retry.Next) {
		t.Fatalf("deadline shortened from %s to %s", before.Retry.Next, after.Retry.Next)
	}
}
