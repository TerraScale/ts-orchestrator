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
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const tsAuthTestAPIKey = "tb_never-print-this-api-key"

func tsAuthTestSecrets() map[string]string {
	secrets := map[string]string{tsauth.EnvAPIKey: tsAuthTestAPIKey, tsauth.EnvProjectID: "01K78000000000000000000001"}
	for i, key := range tsauth.Generated {
		secrets[key] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32)))
	}
	return secrets
}

// tsAuthTestVault is a gru-1 Vault OCID; the agent's resolver is a fake.
const tsAuthTestVault = "ocid1.vault.oc1.sa-saopaulo-1.vault"

func tsAuthTestDesired() Desired {
	secrets := map[string]vaultsecret.Ref{}
	for _, key := range tsauth.Secrets {
		secrets[key] = vaultsecret.Ref{Vault: tsAuthTestVault, Name: vaultsecret.Name("gru-1", key)}
	}
	return Desired{Cell: "gru", Role: tsauth.Role, Digest: "d", Env: map[string]string{
		tsauth.EnvPublicOrigin: tsauth.PublicOrigin("gru"), tsauth.EnvAPIURL: tsauth.APIURL("gru"), tsauth.EnvDatabase: tsauth.Database,
		tsauth.EnvAudiences: tsauth.APIURL("gru"), tsauth.EnvDashboardRedirectURIs: tsauth.DashboardRedirectURI,
		tsauth.EnvDashboardLogoutURIs: tsauth.DashboardLogoutURI}, Secrets: secrets}
}

// tsAuthTestAgent is an agent whose ts-auth root belongs to the test's own
// user, standing in for the workload user.
func tsAuthTestAgent(t *testing.T) *Agent {
	t.Helper()
	root := filepath.Join(traversableTempDir(t), "ts-auth")
	identity := WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	return &Agent{terraBase: map[string]terraBaseMember{}, cfg: AgentConfig{TSAuthRoot: root, WorkloadIdentity: identity,
		InstallRoot: "/var/lib/host/install", StateRoot: "/var/lib/host/state"}}
}

// TestTSAuthReplicaGetsVaultSecrets launches a replica with the signed
// profile, the secrets read from the Vault and the host-owned listen address
// and bundle directory, which the agent creates for the workload user.
func TestTSAuthReplicaGetsVaultSecrets(t *testing.T) {
	agent := tsAuthTestAgent(t)
	d := tsAuthTestDesired()
	if !agent.tsAuthReplica(d) {
		t.Fatal("a ts-auth desired on a host with a ts-auth root is not a replica")
	}
	valid := d
	valid.Generation, valid.Digest = 1, strings.Repeat("a", 64)
	if err := validateDesired(valid, "gru", Registration{Roles: []string{tsauth.Role}}); err != nil {
		t.Fatalf("ts-auth desired with its secret refs: %v", err)
	}
	secrets := tsAuthTestSecrets()
	env, err := agent.prepareTSAuth(d, secrets)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range secrets {
		if key != tsauth.EnvProjectID && env[key] != want {
			t.Errorf("%s did not reach the replica", key)
		}
	}
	if _, set := env[tsauth.EnvProjectID]; set {
		t.Error("the project ID reached the replica on its own")
	}
	// ts-auth selects its database as <project-ulid>/auth.
	bundle := tsauth.Layout(agent.cfg.TSAuthRoot).Bundle()
	if env[tsauth.EnvListen] != "http://0.0.0.0:8080" || env[tsauth.EnvBundleExtract] != bundle ||
		env[tsauth.EnvDatabase] != secrets[tsauth.EnvProjectID]+"/auth" || env[tsauth.EnvDashboardRedirectURIs] != tsauth.DashboardRedirectURI {
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

// TestTSAuthRefusesBadProfileOrSecrets refuses a profile that carries a
// secret, arguments or misses a secret ref, and Vault values in the wrong
// form. No error carries a secret.
func TestTSAuthRefusesBadProfileOrSecrets(t *testing.T) {
	agent := tsAuthTestAgent(t)
	d := tsAuthTestDesired()
	d.Env[tsauth.EnvAPIKey] = tsAuthTestAPIKey
	if _, err := agent.prepareTSAuth(d, tsAuthTestSecrets()); err == nil || strings.Contains(err.Error(), tsAuthTestAPIKey) {
		t.Fatalf("profile carrying a secret: %v", err)
	}
	d = tsAuthTestDesired()
	d.Args = []string{"--listen=http://0.0.0.0:1"}
	if _, err := agent.prepareTSAuth(d, tsAuthTestSecrets()); err == nil {
		t.Fatal("launched a replica whose arguments override host-owned settings")
	}
	d = tsAuthTestDesired()
	delete(d.Secrets, tsauth.EnvMasterKey)
	if _, err := agent.prepareTSAuth(d, tsAuthTestSecrets()); err == nil {
		t.Fatal("launched a replica whose profile names no master key")
	}
	for name, change := range map[string]func(map[string]string){
		"missing value": func(s map[string]string) { delete(s, tsauth.EnvOperatorKey) },
		"bad api key":   func(s map[string]string) { s[tsauth.EnvAPIKey] = "tb_ " + tsAuthTestAPIKey },
		"short key": func(s map[string]string) {
			s[tsauth.EnvMasterKey] = base64.StdEncoding.EncodeToString([]byte(tsAuthTestAPIKey))
		},
	} {
		secrets := tsAuthTestSecrets()
		change(secrets)
		_, err := agent.prepareTSAuth(tsAuthTestDesired(), secrets)
		if err == nil || strings.Contains(err.Error(), tsAuthTestAPIKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(agent.cfg.TSAuthRoot); err == nil {
		t.Fatal("prepared the replica's directory before its profile and secrets passed")
	}
}

// TestTSAuthRootBelowManagedRuntimeRoot accepts the image layout: every
// enrolled host's managed runtime root is /srv/ts-managed, the only tree the
// host unit may write, and the ts-auth root /srv/ts-managed/ts-auth is in it.
func TestTSAuthRootBelowManagedRuntimeRoot(t *testing.T) {
	agent := tsAuthTestAgent(t)
	agent.cfg.ManagedRuntimeRoot = filepath.Dir(agent.cfg.TSAuthRoot)
	if _, err := agent.prepareTSAuth(tsAuthTestDesired(), tsAuthTestSecrets()); err != nil {
		t.Fatal(err)
	}
}

// TestTSAuthRefusedWithoutRoot keeps a host without a ts-auth root from
// launching ts-auth generically, without its bundle directory or a probe.
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
