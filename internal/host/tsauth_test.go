package host

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"strings"
	"sync/atomic"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
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
	// ts-auth selects its database as <project-id>/auth.
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
