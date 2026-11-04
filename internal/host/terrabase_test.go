package host

import (
	"context"

	"crypto/tls"
	"crypto/x509"

	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

type stopRecorder struct {
	Runner
	stopped []string
	err     error
}

func (r *stopRecorder) Stop(_ context.Context, role string) error {
	r.stopped = append(r.stopped, role)
	return r.err
}

// TestTerraBaseMemberRestartsBeforeLoadedCertificateExpires checks that a
// running member is left alone while its certificate is far from expiry or
// once it serves the renewed certificate (a reloading binary), and is
// restarted when it still serves the expiring one or cannot be probed.
func TestTerraBaseMemberRestartsBeforeLoadedCertificateExpires(t *testing.T) {
	for _, address := range []string{"127.0.0.1"} {
		t.Run(address, func(t *testing.T) {
			testTerraBaseMemberCertificateRenewal(t, address)
		})
	}
}

func testTerraBaseMemberCertificateRenewal(t *testing.T, address string) {
	now := time.Now()
	caPEM, caKey, err := terrabase.NewCA("gru-1", now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"ca.pem": caPEM, "ca.key": caKey} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ca, err := terrabase.LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	// The member's peer listener: it serves whichever certificate served holds.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	var served atomic.Pointer[tls.Certificate]
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return served.Load(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.(*tls.Conn).Handshake()
			_ = connection.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	peer := terrabase.Peer{Name: "gru-1-db-1", Address: netip.AddrPortFrom(netip.MustParseAddr(address), uint16(port))}
	key, csr, err := terrabase.NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := ca.Issue(csr, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := ca.Issue(csr, peer, now.Add(-89*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "terrabase")
	layout := terrabase.Layout(root)
	for _, path := range []string{root, layout.TLS()} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string][]byte{layout.Key(): key, layout.Certificate(): renewed, layout.CA(): ca.CertificatePEM()} {
		if err := os.WriteFile(path, data, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	serve := func(certificate []byte) {
		pair, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			t.Fatal(err)
		}
		served.Store(&pair)
	}
	runner := &stopRecorder{}
	agent := &Agent{runner: runner, terraBase: map[string]terraBaseMember{}, cfg: AgentConfig{Node: peer.Name,
		TerraBaseRoot: root, WorkloadIdentity: WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}}}
	d := Desired{Role: terrabase.Role, Digest: "d", Env: map[string]string{terrabase.EnvAdminPort: "1",
		terrabase.EnvPeerPort: fmt.Sprint(port), terrabase.EnvPeers: "gru-1-db-1=" + peer.Address.String()}}
	loadedExpiry := terrabase.CertificateExpiry(expiring)

	serve(expiring)
	agent.terraBase[d.Role] = terraBaseMember{certificateExpiry: now.Add(80 * 24 * time.Hour)}
	if report := agent.terraBaseRunningReport(t.Context(), d); report.State != "starting" || len(runner.stopped) != 0 {
		t.Fatalf("certificate far from expiry: report %+v, stops %v", report, runner.stopped)
	}
	serve(renewed)
	agent.terraBase[d.Role] = terraBaseMember{certificateExpiry: loadedExpiry}
	if report := agent.terraBaseRunningReport(t.Context(), d); len(runner.stopped) != 0 ||
		!agent.terraBase[d.Role].certificateExpiry.Equal(terrabase.CertificateExpiry(renewed)) {
		t.Fatalf("member serving the reloaded certificate: report %+v, stops %v", report, runner.stopped)
	}
	serve(expiring)
	agent.terraBase[d.Role] = terraBaseMember{certificateExpiry: loadedExpiry}
	if report := agent.terraBaseRunningReport(t.Context(), d); report.State != "starting" || len(runner.stopped) != 1 {
		t.Fatalf("member still serving the expiring certificate: report %+v, stops %v", report, runner.stopped)
	}
	if _, kept := agent.terraBase[d.Role]; kept {
		t.Fatal("restarted member keeps its old certificate expiry")
	}
	listener.Close()
	runner.err = errors.New("cgroup busy")
	agent.terraBase[d.Role] = terraBaseMember{certificateExpiry: loadedExpiry}
	if agent.terraBaseRunningReport(t.Context(), d); len(runner.stopped) != 2 {
		t.Fatalf("unreachable member near certificate expiry was not restarted: stops %v", runner.stopped)
	}
	if !agent.terraBase[d.Role].certificateExpiry.Equal(loadedExpiry) {
		t.Fatal("a failed stop forgot the expiry, so the member would never be checked again")
	}
}

// traversableTempDir is a temporary directory every user may traverse but
// only its owner may change, like /srv on a host image.
func traversableTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ts-terrabase-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestTerraBaseRunningNeedsTheClientReadyz checks that a member counts as
// running only once its admin /healthz and its client /readyz both answer,
// verified against the member CA, and that a member without a client
// listener keeps the /healthz gate alone.
func TestTerraBaseRunningNeedsTheClientReadyz(t *testing.T) {
	now := time.Now()
	issue := func(cell string, peer terrabase.Peer) (caPEM []byte, pair tls.Certificate, key, certificate []byte) {
		caPEM, caKey, err := terrabase.NewCA(cell, now)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		for name, data := range map[string][]byte{"ca.pem": caPEM, "ca.key": caKey} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ca, err := terrabase.LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
		if err != nil {
			t.Fatal(err)
		}
		key, csr, err := terrabase.NewMemberKey()
		if err != nil {
			t.Fatal(err)
		}
		if certificate, err = ca.Issue(csr, peer, now); err != nil {
			t.Fatal(err)
		}
		if pair, err = tls.X509KeyPair(certificate, key); err != nil {
			t.Fatal(err)
		}
		return caPEM, pair, key, certificate
	}
	peer := terrabase.Peer{Name: "gru-1-db-1", Address: netip.MustParseAddrPort("127.0.0.1:9443")}
	caPEM, pair, key, certificate := issue("gru-1", peer)
	_, foreign, _, _ := issue("gru-2", peer)

	var healthy, ready atomic.Bool
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer admin.Close()
	var servedCertificate atomic.Pointer[tls.Certificate]
	servedCertificate.Store(&pair)
	client := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("catching up"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Kestrel offers h2; the probe must still read the answer.
	client.EnableHTTP2 = true
	// An IP server name sends no SNI, so swap the whole configuration.
	client.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{*servedCertificate.Load()}, NextProtos: []string{"h2", "http/1.1"}}, nil
	}}
	client.StartTLS()
	defer client.Close()

	root := filepath.Join(t.TempDir(), "terrabase")
	layout := terrabase.Layout(root)
	for _, path := range []string{root, layout.TLS()} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string][]byte{layout.Key(): key, layout.Certificate(): certificate, layout.CA(): caPEM} {
		if err := os.WriteFile(path, data, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	agent := &Agent{cfg: AgentConfig{Node: peer.Name, TerraBaseRoot: root}}
	port := func(server *httptest.Server) string { return fmt.Sprint(server.Listener.Addr().(*net.TCPAddr).Port) }
	d := Desired{Role: terrabase.Role, Env: map[string]string{terrabase.EnvAdminPort: port(admin), terrabase.EnvPeerPort: "9443",
		terrabase.EnvClientPort: port(client), terrabase.EnvPeers: "gru-1-db-1=127.0.0.1:9443"}}
	state := func() (string, error) {
		t.Helper()
		state, err := agent.terraBaseState(t.Context(), d)
		if state == "" {
			t.Fatalf("no state: %v", err)
		}
		return state, err
	}

	if s, err := state(); s != "starting" || err == nil {
		t.Fatalf("unhealthy member: %s %v", s, err)
	}
	healthy.Store(true)
	if s, err := state(); s != "starting" || err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("member still catching up: %s %v", s, err)
	}
	ready.Store(true)
	if s, err := state(); s != "running" || err != nil {
		t.Fatalf("ready member: %s %v", s, err)
	}
	// Something else on the client port cannot pass for the member.
	servedCertificate.Store(&foreign)
	if s, err := state(); s != "starting" || err == nil {
		t.Fatalf("listener with a foreign CA's certificate: %s %v", s, err)
	}
	servedCertificate.Store(&pair)
	// Without a client listener /healthz alone gates the member.
	ready.Store(false)
	delete(d.Env, terrabase.EnvClientPort)
	if s, err := state(); s != "running" || err != nil {
		t.Fatalf("member without a client listener: %s %v", s, err)
	}
}
