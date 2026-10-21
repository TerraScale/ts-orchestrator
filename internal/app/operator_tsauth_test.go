package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
)

// fakeTSAuthMagic starts every release the fake replica serves.
var fakeTSAuthMagic = fakeTerraBaseMagic[:64] + " fake ts-auth"

// TestTSAuthGRUConfigIsValid checks the committed gru-1 profile and service
// spec against the controller's signed-config validation.
func TestTSAuthGRUConfigIsValid(t *testing.T) {
	profile, spec := tsAuthGRUConfig(t)
	profiles := map[string]WorkloadProfile{tsauth.Role: profile}
	if err := validateWorkloadProfiles("gru", profiles); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkloadProfiles("sjc", profiles); err == nil {
		t.Fatal("sjc accepted gru-1's ts-auth endpoints")
	}
	if err := validateAutoscaleConfig(&AutoscaleConfig{Services: []workload.ServiceSpec{spec}}, profiles); err != nil {
		t.Fatal(err)
	}
	if spec.Kind != workload.KindStateless || spec.Replicas.Min != tsauth.Replicas || spec.Replicas.Max != tsauth.Replicas ||
		spec.Placement.MaxPerFailureDomain != 1 {
		t.Fatalf("gru-1 ts-auth spec %+v, want %d stateless replicas, one per failure domain", spec, tsauth.Replicas)
	}
	for _, key := range tsauth.Secrets {
		profile.Env[key] = "x"
		if err := validateWorkloadProfiles("gru", profiles); err == nil {
			t.Errorf("a signed ts-auth profile carrying %s was accepted", key)
		}
		delete(profile.Env, key)
	}
	// Its private TerraBase endpoints are the committed members' client
	// listeners, checked against the cell's terrabase profile.
	members, err := readReleaseProfile("../../deploy/oci-region/terrabase-gru-1-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	profiles[terrabase.Role] = members
	if err := validateWorkloadProfiles("gru", profiles); err != nil {
		t.Fatal(err)
	}
	members.Env[terrabase.EnvPeers] = "gru-1-db-1=10.251.0.21:9443"
	if err := validateWorkloadProfiles("gru", profiles); err == nil {
		t.Fatal("accepted ts-auth endpoints of a member the terrabase profile dropped")
	}
	delete(profiles, terrabase.Role)
	// The committed profile names the six secrets, the SMTP relay credentials
	// and the OCI signing API key; renaming a secret changes the config digest.
	if len(profile.Secrets) != len(tsauth.Secrets)+3 {
		t.Fatalf("committed profile names %d secrets", len(profile.Secrets))
	}
	renamed := maps.Clone(profile.Secrets)
	renamed[tsauth.EnvMasterKey] = vaultsecret.Ref{Vault: renamed[tsauth.EnvMasterKey].Vault, Name: "gru-1-ts-auth-master-key-2"}
	if delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) == delivery.ConfigDigestOf(profile.Args, profile.Env, renamed) ||
		delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) == delivery.ConfigDigestOf(profile.Args, profile.Env, nil) {
		t.Fatal("the config digest ignores the secret names")
	}
}

// TestWorkloadProfileSecretsStayWithTheirRole refuses a signed profile whose
// secrets reach another role's Vault secrets, a TerraBase profile with any but
// secret files, and one that sets the host's NATS identity settings.
func TestWorkloadProfileSecretsStayWithTheirRole(t *testing.T) {
	ref := func(name string) map[string]vaultsecret.Ref {
		return map[string]vaultsecret.Ref{"TOKEN": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: name}}
	}
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	if err := validateWorkloadProfiles("gru", map[string]WorkloadProfile{"billing": {Resources: resources, Secrets: ref("gru-1-billing-token")}}); err != nil {
		t.Fatal(err)
	}
	file := map[string]vaultsecret.Ref{"TERRABASE_BACKUP_SECRET_KEY_FILE": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: "gru-1-terrabase-backup-secret-key"}}
	if err := validateWorkloadProfiles("gru", map[string]WorkloadProfile{"terrabase": {Resources: resources, Secrets: file}}); err != nil {
		t.Fatalf("a TerraBase secret file was refused: %v", err)
	}
	for name, profiles := range map[string]map[string]WorkloadProfile{
		"other role":     {"billing": {Resources: resources, Secrets: ref("gru-1-netbird-admin-pat")}},
		"terrabase":      {"terrabase": {Resources: resources, Secrets: ref("gru-1-terrabase-token")}},
		"terrabase nats": {"terrabase": {Resources: resources, Env: map[string]string{"TERRABASE_NATS_URL": "tls://x:4222"}}},
		"also env":       {"billing": {Resources: resources, Env: map[string]string{"TOKEN": "x"}, Secrets: ref("gru-1-billing-token")}},
		// gru-1-billing-eu-token would be ambiguous between the two roles.
		"longer role": {"billing": {Resources: resources, Secrets: ref("gru-1-billing-eu-token")}, "billing-eu": {Resources: resources}},
	} {
		if err := validateWorkloadProfiles("gru", profiles); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTSAuthProfileRejectsOtherCell(t *testing.T) {
	profile, _ := tsAuthGRUConfig(t)
	if err := validateWorkloadProfiles("sjc", map[string]WorkloadProfile{tsauth.Role: profile}); err == nil {
		t.Fatal("accepted a GRU ts-auth profile for another cell")
	}
}

func TestTSAuthAutoscaleBoundsAreFixed(t *testing.T) {
	profile, spec := tsAuthGRUConfig(t)
	profiles := map[string]WorkloadProfile{tsauth.Role: profile}
	for name, mutate := range map[string]func(*workload.ServiceSpec){
		"lower replicas":      func(s *workload.ServiceSpec) { s.Replicas.Min = 1 },
		"higher replicas":     func(s *workload.ServiceSpec) { s.Replicas.Max = 4 },
		"multiple per domain": func(s *workload.ServiceSpec) { s.Placement.MaxPerFailureDomain = 2 },
	} {
		bad := spec
		mutate(&bad)
		if err := validateAutoscaleConfig(&AutoscaleConfig{Services: []workload.ServiceSpec{bad}}, profiles); err == nil {
			t.Errorf("%s: accepted ts-auth bounds %+v", name, bad)
		}
	}
}

// TestSFOProfilesAreValid checks the committed sjc-1 TerraBase and ts-auth
// profiles together, as the sjc controllers validate them (TS-662).
func TestSFOProfilesAreValid(t *testing.T) {
	profiles := map[string]WorkloadProfile{}
	for role, file := range map[string]string{terrabase.Role: "terrabase-sjc-1-profile.json", tsauth.Role: "ts-auth-sjc-1-profile.json"} {
		profile, err := readReleaseProfile("../../deploy/oci-region/" + file)
		if err != nil {
			t.Fatal(err)
		}
		profiles[role] = profile
	}
	if err := validateWorkloadProfiles("sjc", profiles); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkloadProfiles("gru", profiles); err == nil {
		t.Fatal("gru accepted sjc's ts-auth profile")
	}
}

func tsAuthGRUConfig(t *testing.T) (WorkloadProfile, workload.ServiceSpec) {
	t.Helper()
	profile, err := readReleaseProfile("../../deploy/oci-region/ts-auth-gru-1-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../deploy/oci-region/ts-auth-gru-1-service.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec workload.ServiceSpec
	if err := json.Unmarshal(data, &spec, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return profile, spec
}

// fakeTSAuthReplica stands in for the binary. It checks the environment the
// host prepared and serves /healthz and /readyz on TS_AUTH_LISTEN; a release
// that does not start with fakeTSAuthMagic exits at once.
func fakeTSAuthReplica(secrets map[string]string) func(host.Workload) (func(), chan struct{}, error) {
	return func(w host.Workload) (func(), chan struct{}, error) {
		exited := make(chan struct{})
		executable, err := os.ReadFile(w.Executable)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.HasPrefix(executable, []byte(fakeTSAuthMagic)) {
			time.AfterFunc(300*time.Millisecond, func() { close(exited) })
			return func() {}, exited, nil
		}
		for key, value := range secrets {
			if key != tsauth.EnvProjectID && w.Env[key] != value {
				return nil, nil, fmt.Errorf("replica lacks %s", key)
			}
		}
		// ts-auth selects its database as <project-uuid>/auth.
		if _, set := w.Env[tsauth.EnvProjectID]; set || w.Env[tsauth.EnvDatabase] != secrets[tsauth.EnvProjectID]+"/auth" {
			return nil, nil, fmt.Errorf("replica database %q", w.Env[tsauth.EnvDatabase])
		}
		if info, err := os.Stat(w.Env[tsauth.EnvBundleExtract]); err != nil || !info.IsDir() {
			return nil, nil, fmt.Errorf("replica bundle directory: %v", err)
		}
		if len(w.Args) != 0 || w.Env[tsauth.EnvAPIURL] != tsauth.APIURL("gru") || w.DrainTimeout == 0 {
			return nil, nil, errors.New("replica launched without its profile or drain")
		}
		listen, ok := strings.CutPrefix(w.Env[tsauth.EnvListen], "http://0.0.0.0:")
		if !ok {
			return nil, nil, errors.New("replica has no listen address")
		}
		listener, err := net.Listen("tcp", "127.0.0.1:"+listen)
		if err != nil {
			return nil, nil, err
		}
		server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			status := map[string]string{tsauth.HealthPath: "ok", tsauth.ReadyPath: "ready"}[request.URL.Path]
			_, _ = fmt.Fprintf(response, `{"status":%q}`, status)
		})}
		go func() { _ = server.Serve(listener) }()
		return func() {
			_ = server.Close()
			close(exited)
		}, exited, nil
	}
}

// writeTSAuthRelease writes data as a ts-auth release asset with its .sha256.
func writeTSAuthRelease(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := writeTerraBaseRelease(t, dir, data)
	name := strings.Replace(filepath.Base(path), "terrabase-", "ts-auth-", 1)
	asset := filepath.Join(dir, name)
	checksum, err := os.ReadFile(path + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, asset); err != nil {
		t.Fatal(err)
	}
	checksum = bytes.Replace(checksum, []byte(filepath.Base(path)), []byte(name), 1)
	if err := os.WriteFile(asset+".sha256", checksum, 0o644); err != nil {
		t.Fatal(err)
	}
	return asset
}

// bundles is an OCI Vault holding secrets by name.
type bundles map[string]string

// resolve reads refs from b as a host agent reads them from the Vault.
func (b bundles) resolve(ctx context.Context, refs map[string]vaultsecret.Ref) (map[string]string, error) {
	return vaultsecret.Resolve(ctx, refs, func(string) (vaultsecret.BundleClient, error) { return b, nil })
}

func (b bundles) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	value, ok := b[*request.SecretName]
	if !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, errors.New("no such secret")
	}
	content := base64.StdEncoding.EncodeToString([]byte(value))
	return ocisecrets.GetSecretBundleByNameResponse{SecretBundle: ocisecrets.SecretBundle{
		SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: &content}}}, nil
}

// TestReleaseReplacesFailedReplicasOfAnotherReleaseInPlace keeps a release
// on the hosts whose replicas failed with another digest, so rolling back a
// release that crashed everywhere needs no spare host; a failure of the same
// digest still quarantines its host.
func TestReleaseReplacesFailedReplicasOfAnotherReleaseInPlace(t *testing.T) {
	observation := workload.Observation{
		Active:      map[string]host.Desired{"ctl-1": {Node: "ctl-1", Digest: "broken"}, "ctl-2": {Node: "ctl-2", Digest: "good"}},
		Assignments: []placement.Assignment{{Node: "ctl-1", Role: tsauth.Role}, {Node: "ctl-2", Role: tsauth.Role, Ordinal: 1}},
	}
	previous := releaseFailures(observation, "good", delivery.ConfigDigestOf(nil, nil, nil))
	if !previous[0].Pending || previous[1].Pending {
		t.Fatalf("assignments %+v: want the broken release's replica replaced in place, the good one's failure kept", previous)
	}
	if observation.Assignments[0].Pending {
		t.Fatal("releaseFailures changed the observation")
	}
}

func TestReleaseReplacesFailedConfigurationOfSameArtifactInPlace(t *testing.T) {
	observation := workload.Observation{Active: map[string]host.Desired{"ctl-1": {Digest: "good", Env: map[string]string{"config": "B"}}, "ctl-2": {Digest: "good", Env: map[string]string{"config": "A"}}}, Assignments: []placement.Assignment{{Node: "ctl-1", Role: tsauth.Role}, {Node: "ctl-2", Role: tsauth.Role, Ordinal: 1}}}
	previous := releaseFailures(observation, "good", delivery.ConfigDigestOf(nil, map[string]string{"config": "A"}, nil))
	if !previous[0].Pending || previous[1].Pending {
		t.Fatalf("configuration-only failure could not be replaced in place: %+v", previous)
	}
}
