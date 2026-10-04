package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
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
	for _, address := range []string{"127.0.0.1", "2001:db8::1"} {
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

func TestTerraBaseRootMustBeSeparate(t *testing.T) {
	install, state := "/var/lib/host/install", "/var/lib/host/state"
	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	for _, root := range []string{"/", "/var/lib", "/var/lib/host/install", "/var/lib/host/install/terrabase", "/var/lib/host/state/x", "relative", "/srv/../srv/tb"} {
		if err := validateTerraBaseRoot(root, install, state, identity); err == nil {
			t.Errorf("terrabase root %q accepted", root)
		}
	}
	if err := validateTerraBaseRoot(filepath.Join(traversableTempDir(t), "terrabase"), install, state, identity); err != nil {
		t.Fatal(err)
	}
}

// TestTerraBaseRootRejectsUnsafeAncestors refuses a root reached through a
// symlink, a symlinked root and an ancestor the workload can replace, both
// when the agent starts and when an ancestor changes later.
func TestTerraBaseRootRejectsUnsafeAncestors(t *testing.T) {
	base := traversableTempDir(t)
	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	mkdir := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	mkdir(filepath.Join(base, "real"), 0o755)
	mkdir(filepath.Join(base, "open"), 0o777)
	mkdir(filepath.Join(base, "sticky"), 0o777|os.ModeSticky)
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(base, "link", "terrabase"), filepath.Join(base, "link"), filepath.Join(base, "open", "terrabase"),
		filepath.Join(base, "sticky", "terrabase"), filepath.Join(base, "sticky", "missing", "terrabase"),
		filepath.Join(base, "missing", "terrabase")} {
		if err := validateTerraBaseRoot(root, "/var/lib/host/install", "/var/lib/host/state", identity); err == nil {
			t.Errorf("unsafe terrabase root %s accepted", root)
		}
	}
	root := filepath.Join(base, "real", "terrabase")
	if err := validateTerraBaseRoot(root, "/var/lib/host/install", "/var/lib/host/state", identity); err != nil {
		t.Fatal(err)
	}
	// An ancestor swapped for a symlink after the agent started.
	if err := os.Rename(filepath.Join(base, "real"), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "moved"), filepath.Join(base, "real")); err != nil {
		t.Fatal(err)
	}
	agent := &Agent{terraBase: map[string]terraBaseMember{}, cfg: AgentConfig{Node: "gru-1-db-1", TerraBaseRoot: root,
		InstallRoot: "/var/lib/host/install", StateRoot: "/var/lib/host/state", WorkloadIdentity: identity}}
	d := Desired{Role: terrabase.Role, Env: map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.0.0.1:9443"}}
	if _, _, err := agent.prepareTerraBase(t.Context(), d); err == nil {
		t.Fatal("prepared a member below a symlinked ancestor")
	}
	if _, err := os.Stat(filepath.Join(base, "moved", "terrabase")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the agent wrote through the symlink: %v", err)
	}
	// A managed directory that is a symlink is never chowned through.
	if err := os.Symlink(filepath.Join(base, "moved"), filepath.Join(base, "data")); err != nil {
		t.Fatal(err)
	}
	if err := ensureOwnedDir(filepath.Join(base, "data"), os.Getuid(), os.Getgid(), 0o700); err == nil {
		t.Fatal("changed a managed directory through a symlink")
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

func TestTerraBaseMemberRefusesArguments(t *testing.T) {
	agent := &Agent{terraBase: map[string]terraBaseMember{}, cfg: AgentConfig{Node: "gru-1-db-1", TerraBaseRoot: t.TempDir()}}
	d := Desired{Role: terrabase.Role, Args: []string{"--data-directory=/"}, Env: map[string]string{
		terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.0.0.1:9443"}}
	if _, _, err := agent.prepareTerraBase(t.Context(), d); err == nil || !strings.Contains(err.Error(), "no arguments") {
		t.Fatalf("member with arguments: %v", err)
	}
}

func TestTerraBaseExitReportedOnceBeforeRelaunch(t *testing.T) {
	agent := &Agent{terraBase: map[string]terraBaseMember{}}
	d := Desired{Role: terrabase.Role, Digest: "d"}
	exited := Observation{Role: d.Role, Digest: "d", Fingerprint: "f"}
	for i, want := range []bool{true, false, true} {
		if got := agent.terraBaseExited(exited, d, "f"); got != want {
			t.Fatalf("observation %d: exited %v, want %v", i, got, want)
		}
	}
	running := exited
	running.Running = true
	if agent.terraBaseExited(running, d, "f") || agent.terraBaseExited(Observation{Role: d.Role}, d, "f") {
		t.Fatal("a running or never launched member counted as exited")
	}
}

// TestTerraBasePeerCertificateFollowsCurrentRegistration signs a member
// certificate only for a listed node whose desired is valid for its current
// registration, so a host moved to another environment cannot use the old
// environment's still-active desired.
func TestTerraBasePeerCertificateFollowsCurrentRegistration(t *testing.T) {
	c, _, store, _, _ := testController(t)
	artifact := []byte("terrabase member artifact")
	hash := sha256.Sum256(artifact)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, artifact); err != nil {
		t.Fatal(err)
	}
	caPEM, caKey, err := terrabase.NewCA("gru", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"ca.pem": caPEM, "ca.key": caKey} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.terraBaseCA, err = terrabase.LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: testNATSUserKey("node-a"), Generation: 1}
	if _, err := c.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "node-a=10.0.0.1:9443"}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase",
		Digest: digest, Generation: 1, AuthorityEpoch: 1, Env: env}); err != nil {
		t.Fatal(err)
	}
	_, csr, err := terrabase.NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(terraBasePeerQuery{CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(r Registration) error {
		_, err := c.serveTerraBasePeer(t.Context(), request{Node: "node-a", Payload: payload}, r)
		return err
	}
	if err := ask(registration); err != nil {
		t.Fatalf("listed member of the current environment: %v", err)
	}
	moved := registration
	moved.Environment, moved.Generation = "canary", 2
	if _, err := c.Register(t.Context(), moved); err != nil {
		t.Fatal(err)
	}
	if err := ask(moved); err == nil {
		t.Fatal("signed for a desired of the host's previous environment")
	}
}
