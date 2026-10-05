package host

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
)

const tsAuthTestAPIKey = "tb_never-print-this-api-key"

func tsAuthTestSecrets() map[string]string {
	secrets := map[string]string{tsauth.EnvAPIKey: tsAuthTestAPIKey, tsauth.EnvProjectID: "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d"}
	for i, key := range tsauth.Generated {
		secrets[key] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32)))
	}
	return secrets
}

func tsAuthTestDesired() Desired {
	return Desired{Cell: tsauth.Cell, Role: tsauth.Role, Digest: "d", Env: map[string]string{
		tsauth.EnvPublicOrigin: tsauth.PublicOrigin, tsauth.EnvAPIURL: tsauth.APIURL, tsauth.EnvDatabase: tsauth.Database}}
}

// tsAuthTestAgent is an agent whose ts-auth root and env file belong to the
// test's own user, standing in for the workload user.
func tsAuthTestAgent(t *testing.T, mode os.FileMode) (*Agent, string) {
	t.Helper()
	root := filepath.Join(traversableTempDir(t), "ts-auth")
	identity := WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	agent := &Agent{terraBase: map[string]terraBaseMember{}, cfg: AgentConfig{TSAuthRoot: root, WorkloadIdentity: identity,
		InstallRoot: "/var/lib/host/install", StateRoot: "/var/lib/host/state"}}
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	data, err := tsauth.RenderEnvFile(tsAuthTestSecrets())
	if err != nil {
		t.Fatal(err)
	}
	path := tsauth.Layout(root).EnvFile()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return agent, path
}

// TestTSAuthReplicaGetsEnvFileSecrets launches a replica with the signed
// profile, the env file's secrets and the host-owned listen address and
// bundle directory, which the agent creates for the workload user.
func TestTSAuthReplicaGetsEnvFileSecrets(t *testing.T) {
	agent, _ := tsAuthTestAgent(t, 0o600)
	d := tsAuthTestDesired()
	if !agent.tsAuthReplica(d) {
		t.Fatal("a ts-auth desired on a host with a ts-auth root is not a replica")
	}
	env, err := agent.prepareTSAuth(d)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range tsAuthTestSecrets() {
		if env[key] != want {
			t.Errorf("%s did not reach the replica", key)
		}
	}
	bundle := tsauth.Layout(agent.cfg.TSAuthRoot).Bundle()
	if env[tsauth.EnvListen] != "http://0.0.0.0:8080" || env[tsauth.EnvBundleExtract] != bundle || env[tsauth.EnvDatabase] != tsauth.Database {
		t.Fatalf("replica environment lacks the profile or host-owned settings: listen %q, bundle %q", env[tsauth.EnvListen], env[tsauth.EnvBundleExtract])
	}
	if info, err := os.Stat(bundle); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("bundle directory: %v, %v", info, err)
	}
	if _, set := d.Env[tsauth.EnvAPIKey]; set {
		t.Fatal("the secrets leaked into the desired state")
	}
	withdrawn := d
	withdrawn.Withdrawn = true
	if agent.tsAuthReplica(withdrawn) || (&Agent{}).tsAuthReplica(d) {
		t.Fatal("a withdrawn desired or a host without a ts-auth root launches a replica")
	}
}

// TestTSAuthEnvFileMustBeWorkloadOwnedAndPrivate refuses an env file others
// can read, one owned by another user, a symlink, and a profile that carries
// a secret or arguments. No error carries a secret.
func TestTSAuthEnvFileMustBeWorkloadOwnedAndPrivate(t *testing.T) {
	agent, path := tsAuthTestAgent(t, 0o640)
	if _, err := agent.prepareTSAuth(tsAuthTestDesired()); err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Fatalf("group-readable env file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	other := agent.cfg.WorkloadIdentity
	other.UID++
	if _, err := readTSAuthEnvFile(path, other); err == nil {
		t.Fatal("accepted an env file the workload user does not own")
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTSAuthEnvFile(link, agent.cfg.WorkloadIdentity); err == nil {
		t.Fatal("followed a symlinked env file")
	}
	if err := os.WriteFile(path, []byte(tsauth.EnvAPIKey+"="+tsAuthTestAPIKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readTSAuthEnvFile(path, agent.cfg.WorkloadIdentity)
	if err == nil || strings.Contains(err.Error(), tsAuthTestAPIKey) {
		t.Fatalf("incomplete env file: %v", err)
	}
	d := tsAuthTestDesired()
	d.Env[tsauth.EnvAPIKey] = tsAuthTestAPIKey
	if _, err := agent.prepareTSAuth(d); err == nil || strings.Contains(err.Error(), tsAuthTestAPIKey) {
		t.Fatalf("profile carrying a secret: %v", err)
	}
	d = tsAuthTestDesired()
	d.Args = []string{"--listen=http://0.0.0.0:1"}
	if _, err := agent.prepareTSAuth(d); err == nil {
		t.Fatal("launched a replica whose arguments override host-owned settings")
	}
}

// TestTSAuthRootBelowManagedRuntimeRoot accepts the image layout: every
// enrolled host's managed runtime root is /srv/ts-managed, the only tree the
// host unit may write, and the ts-auth root /srv/ts-managed/ts-auth is in it.
func TestTSAuthRootBelowManagedRuntimeRoot(t *testing.T) {
	agent, _ := tsAuthTestAgent(t, 0o600)
	agent.cfg.ManagedRuntimeRoot = filepath.Dir(agent.cfg.TSAuthRoot)
	if _, err := agent.prepareTSAuth(tsAuthTestDesired()); err != nil {
		t.Fatal(err)
	}
}

// TestTSAuthRefusedWithoutRoot keeps a host without a ts-auth root from
// launching ts-auth generically, without secrets and without a probe.
func TestTSAuthRefusedWithoutRoot(t *testing.T) {
	d := tsAuthTestDesired()
	if !(&Agent{}).tsAuthMisplaced(d) {
		t.Fatal("a host without a ts-auth root would launch ts-auth")
	}
	withdrawn := d
	withdrawn.Withdrawn = true
	if (&Agent{}).tsAuthMisplaced(withdrawn) || (&Agent{cfg: AgentConfig{TSAuthRoot: "/srv/ts-managed/ts-auth"}}).tsAuthMisplaced(d) {
		t.Fatal("a withdrawn ts-auth or one on a ts-auth host was refused")
	}
}

func TestTSAuthPortValidation(t *testing.T) {
	for _, port := range []int{-1, 65536, 70000} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			if _, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", TSAuthPort: port}); err == nil || !strings.Contains(err.Error(), "ts-auth port") {
				t.Fatalf("port %d accepted: %v", port, err)
			}
		})
	}
}

// TestTSAuthEnvFileFIFORefusedAtOnce keeps a FIFO in place of the env file
// from blocking the agent, which reconciles every role in one loop.
func TestTSAuthEnvFileFIFORefusedAtOnce(t *testing.T) {
	agent, path := tsAuthTestAgent(t, 0o600)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readTSAuthEnvFile(path, agent.cfg.WorkloadIdentity); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read a FIFO as the env file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO env file blocked")
	}
}

func TestTSAuthRootMustBeSeparate(t *testing.T) {
	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	terraBase := filepath.Join(traversableTempDir(t), "terrabase")
	for _, root := range []string{terraBase, filepath.Join(terraBase, "ts-auth"), "/var/lib/host/state/ts-auth", "relative"} {
		if err := validateWorkloadRoot("ts-auth", root, identity, "/var/lib/host/install", "/var/lib/host/state", terraBase); err == nil {
			t.Errorf("ts-auth root %q accepted", root)
		}
	}
}

// TestTSAuthRunningOnlyWhenReady reports a replica running only while both
// /healthz and /readyz answer, and starting with the reason otherwise.
func TestTSAuthRunningOnlyWhenReady(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == tsauth.HealthPath:
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case r.URL.Path == tsauth.ReadyPath && ready.Load():
			_, _ = w.Write([]byte(`{"status":"ready"}`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready"}`))
		}
	}))
	defer server.Close()
	agent := &Agent{cfg: AgentConfig{TSAuthRoot: "/srv/ts-managed/ts-auth", TSAuthPort: server.Listener.Addr().(*net.TCPAddr).Port}}
	d := tsAuthTestDesired()
	if report := agent.tsAuthRunningReport(t.Context(), d); report.State != "running" || report.Error != "" {
		t.Fatalf("ready replica reported %s: %s", report.State, report.Error)
	}
	ready.Store(false)
	if report := agent.tsAuthRunningReport(t.Context(), d); report.State != "starting" || !strings.Contains(report.Error, tsauth.ReadyPath) {
		t.Fatalf("unready replica reported %s: %s", report.State, report.Error)
	}
}

func TestTSAuthExitReportedOnceBeforeRelaunch(t *testing.T) {
	agent := &Agent{terraBase: map[string]terraBaseMember{}, cfg: AgentConfig{TSAuthRoot: "/srv/ts-managed/ts-auth"}}
	d := tsAuthTestDesired()
	exited := Observation{Role: d.Role, Digest: d.Digest, Fingerprint: "f"}
	for i, want := range []bool{true, false} {
		if got := agent.tsAuthReplica(d) && agent.terraBaseExited(exited, d, "f"); got != want {
			t.Fatalf("observation %d: exited %v, want %v", i, got, want)
		}
	}
}
