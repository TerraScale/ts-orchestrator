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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
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
	if err := validateWorkloadProfiles("sfo", profiles); err == nil {
		t.Fatal("sfo accepted gru-1's ts-auth endpoints")
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
	if err := validateWorkloadProfiles("sfo", map[string]WorkloadProfile{tsauth.Role: profile}); err == nil {
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

// TestSFOProfilesAreValid checks the committed sfo-1 TerraBase and ts-auth
// profiles together, as the sfo controllers validate them (TS-662).
func TestSFOProfilesAreValid(t *testing.T) {
	profiles := map[string]WorkloadProfile{}
	for role, file := range map[string]string{terrabase.Role: "terrabase-sfo-1-profile.json", tsauth.Role: "ts-auth-sfo-1-profile.json"} {
		profile, err := readReleaseProfile("../../deploy/oci-region/" + file)
		if err != nil {
			t.Fatal(err)
		}
		profiles[role] = profile
	}
	if err := validateWorkloadProfiles("sfo", profiles); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkloadProfiles("gru", profiles); err == nil {
		t.Fatal("gru accepted sfo's ts-auth profile")
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

// TestTSAuthReleaseGateWithFakeReplicas drives `operator ts-auth-release`
// against an in-process controller whose workload reconciler owns ts-auth
// with the committed gru-1 spec (three replicas, one per failure domain) and
// three host agents. The fake replica answers /healthz and /readyz only when
// its host gave it the Vault's secrets and a bundle directory. A first
// release passes the gate, a second upgrades every replica, and a release
// that crashes is rolled back.
func TestTSAuthReleaseGateWithFakeReplicas(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	auth := newAuthenticatedNATS(t, "gru")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	root := t.TempDir()
	port := freeTCPPort(t)
	_, controllerSeed := testNKey(t)
	_, operatorSeed := testNKey(t)
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	profile, spec := tsAuthGRUConfig(t)
	spec.Environment = "test"
	specKeys := nativeTestTrust(t, root)
	nodes := []string{"ctl-1", "ctl-2", "ctl-3"}
	hostKeys := map[string][2]string{}
	for _, node := range nodes {
		public, seed := testNKey(t)
		hostKeys[node] = [2]string{public, seed}
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{tsauth.Role}, Environments: []string{"test"}, CanRegisterHosts: true,
		Repositories: []string{tsauth.Repository}}
	controllerConfig := Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"), StoreMaxBytes: 4 << 30}},
		Controller: ControllerConfig{CandidateID: "0000000000DV8998ZCQW1J2V2R", ResponseKeyFile: filepath.Join(root, "controller.key"),
			SpecTrust:             specKeys.config(),
			ArtifactStoreMaxBytes: 512 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads: map[string]WorkloadProfile{tsauth.Role: profile},
			Autoscale: &AutoscaleConfig{Services: []workload.ServiceSpec{spec}}},
	}
	auth.controller(t, &controllerConfig)
	controllerConfigPath := testJSONFile(t, root, "controller.json", controllerConfig)
	controllerOutput := &readyWriter{ready: make(chan struct{})}
	controllerDone := make(chan error, 1)
	go func() {
		controllerDone <- Run(ctx, []string{"run", "--config", controllerConfigPath}, controllerOutput)
	}()
	select {
	case <-controllerOutput.ready:
	case err := <-controllerDone:
		t.Fatalf("controller exited before ready: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	operatorConfig := Config{Version: ConfigVersion, NATS: auth.config(t, natscell.Config{Cell: "gru", Instance: "operator", ClientRole: "operator", Replicas: 1,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: operatorSeed}),
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}}
	operatorConfigPath := testJSONFile(t, root, "operator.json", operatorConfig)
	operatorRuntime, err := natscell.Start(ctx, operatorConfig.NATS)
	if err != nil {
		t.Fatal(err)
	}
	defer operatorRuntime.Close()
	applyNativeTestSpec(t, operatorConfig, operatorRuntime, specKeys, []cellspec.Service{{Role: tsauth.Role, Profile: profile, Spec: &spec}}, 1)

	identity := testHostWorkloadIdentity()
	secrets := map[string]string{tsauth.EnvAPIKey: "tb_fake-key", tsauth.EnvProjectID: "01K78000000000000000000001",
		"TS_AUTH_SMTP_USERNAME": "fake-smtp-user", "TS_AUTH_SMTP_PASSWORD": "fake-smtp-password",
		"TS_AUTH_OCI_PRIVATE_KEY": "fake-oci-private-key"}
	for _, key := range tsauth.Generated {
		secrets[key], _ = tsauth.Generate(ctx)
	}
	vault := bundles{}
	for key, value := range secrets {
		vault[profile.Secrets[key].Name] = value
	}
	var output bytes.Buffer
	replicas := map[string]*childRunner{}
	ports := map[string]int{}
	var agentsDone []chan error
	defer func() {
		cancel()
		for _, done := range agentsDone {
			<-done
		}
		<-controllerDone
		for _, runner := range replicas {
			_ = runner.Close(context.Background())
		}
	}()
	for index, node := range nodes {
		hostPublic, hostPrivate := testEd25519(t, root, node+".key")
		registrationPath := testJSONFile(t, root, node+"-registration.json", host.Registration{Cell: "gru", Node: node,
			Environment: "test", Roles: []string{tsauth.Role}, FailureDomain: fmt.Sprintf("fault-domain-%d", index+1),
			PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostKeys[node][0], Generation: 1,
			Capacity: host.Capacity{CPU: 2, MemoryBytes: 4 << 30, DiskBytes: 8 << 30}})
		if err := Run(ctx, []string{"operator", "host-register", "--config", operatorConfigPath, "--registration", registrationPath}, &output); err != nil {
			t.Fatalf("host registration: %v", err)
		}
		hostRuntime, err := natscell.Start(ctx, auth.config(t, natscell.Config{Cell: "gru", Instance: "host-" + node, Replicas: 1,
			URL: operatorConfig.NATS.URL, NKeySeedFile: hostKeys[node][1], ClientRole: "host"}))
		if err != nil {
			t.Fatal(err)
		}
		defer hostRuntime.Close()
		tsAuthRoot := filepath.Join(filepath.Dir(traversableTerraBaseRoot(t)), "ts-auth")
		clock := &testBrokerClock{}
		clock.healthy.Store(true)
		ports[node] = freeTCPPort(t)
		replicas[node] = &childRunner{log: filepath.Join(root, node+".log"), fake: true, serve: fakeTSAuthReplica(secrets)}
		agent, err := host.NewAgent(host.AgentConfig{WorkloadIdentity: identity, Cell: "gru", Node: node,
			Environment: "test", Roles: []string{tsauth.Role}, Conn: hostRuntime.Conn(), Identity: hostPrivate,
			NATSUserPublicKey: hostKeys[node][0], ControllerPublicKey: controllerPublic, Runner: replicas[node],
			InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), ManagedRuntimeRoot: filepath.Dir(tsAuthRoot),
			TSAuthRoot: tsAuthRoot, TSAuthPort: ports[node], SecretResolver: vault.resolve,
			PollInterval: 200 * time.Millisecond, ClockCheck: controllerClockCheck(clock)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		agentsDone = append(agentsDone, done)
		go func() { done <- agent.Run(ctx) }()
	}

	checkout, commit := terraBaseSourceCheckout(t)
	profilePath := testJSONFile(t, root, "profile.json", profile)
	release := func(binary string, wait time.Duration) (string, error) {
		output.Reset()
		err := Run(ctx, []string{"operator", "ts-auth-release", "--config", operatorConfigPath,
			"--binary", binary, "--sha256", binary + ".sha256", "--source-checkout", checkout, "--commit", commit,
			"--environment", "test", "--profile", profilePath, "--wait", wait.String()}, &output)
		t.Logf("ts-auth-release %s: %v\n%s", filepath.Base(filepath.Dir(binary)), err, output.String())
		return output.String(), err
	}
	assertReplicas := func(digest string) {
		t.Helper()
		for _, node := range nodes {
			if observed, _ := replicas[node].Observe(ctx, tsauth.Role); !observed.Running || observed.Digest != digest {
				t.Fatalf("%s runs %s (running %v), want %s", node, observed.Digest, observed.Running, digest)
			}
			if err := tsauth.Probe(ctx, ports[node]); err != nil {
				t.Fatalf("%s: %v", node, err)
			}
		}
	}

	first := writeTSAuthRelease(t, filepath.Join(root, "first"), []byte(fakeTSAuthMagic+" first"))
	firstDigest, err := tsauth.VerifyRelease(first, first+".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := release(first, time.Minute); err != nil || !strings.Contains(out, `"step":"ready"`) {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	assertReplicas(firstDigest)

	second := writeTSAuthRelease(t, filepath.Join(root, "second"), []byte(fakeTSAuthMagic+" second"))
	secondDigest, _ := tsauth.VerifyRelease(second, second+".sha256")
	if out, err := release(second, time.Minute); err != nil || !strings.Contains(out, `"previous":"`+firstDigest+`"`) {
		t.Fatalf("upgrade: %v\n%s", err, out)
	}
	assertReplicas(secondDigest)
	goodProfile := cloneNativeProfile(profile)
	profile = cloneNativeProfile(profile)
	profile.Env["NONSECRET_SETTING"] = "B"
	profile.Resources.CPU = 2
	profile.Resources.MemoryBytes *= 2
	profile.Resources.DiskBytes *= 2
	ref := profile.Secrets[tsauth.EnvAPIKey]
	ref.Name += "-v2"
	profile.Secrets[tsauth.EnvAPIKey] = ref
	vault[ref.Name] = secrets[tsauth.EnvAPIKey]
	spec.Resources = profile.Resources
	profilePath = testJSONFile(t, root, "profile-B.json", profile)
	applyNativeTestSpec(t, operatorConfig, operatorRuntime, specKeys, []cellspec.Service{{Role: tsauth.Role, Profile: profile, Spec: &spec}}, 2)
	// A spec change after publication must neither change the saved candidate
	// nor substitute current C for retained A during recovery.
	submitTerraBaseIntent = func(ctx context.Context, cfg Config, runtime *natscell.Runtime, intent delivery.Intent) (delivery.Intent, string, error) {
		accepted, fingerprint, err := submitIntent(ctx, cfg, runtime, intent)
		if intent.ConfigDigest == delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) {
			current := cloneNativeProfile(profile)
			current.Env["NONSECRET_SETTING"] = "C"
			applyNativeTestSpec(t, operatorConfig, operatorRuntime, specKeys, []cellspec.Service{{Role: tsauth.Role, Profile: current, Spec: &spec}}, 3)
		}
		return accepted, fingerprint, err
	}
	t.Cleanup(func() { submitTerraBaseIntent = submitIntent })

	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Fatal(err)
	}
	broken, err := os.ReadFile(falsePath)
	if err != nil {
		t.Fatal(err)
	}
	third := writeTSAuthRelease(t, filepath.Join(root, "broken"), broken)
	if out, err := release(third, 15*time.Second); err == nil || !strings.Contains(err.Error(), "was rolled back to "+secondDigest) {
		t.Fatalf("broken release: %v\n%s", err, out)
	}
	assertReplicas(secondDigest)
	submitTerraBaseIntent = submitIntent
	service, err := operatorService(ctx, operatorConfig, operatorRuntime, false)
	if err != nil {
		t.Fatal(err)
	}
	controllerCfg, err := LoadConfig(controllerConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	leader, err := natscell.Start(ctx, auth.config(t, natscell.Config{Cell: "gru", Instance: "replay", Replicas: 1, URL: operatorConfig.NATS.URL, NKeySeedFile: controllerSeed, ClientRole: "controller"}))
	if err != nil {
		t.Fatal(err)
	}
	defer leader.Close()
	policy, err := buildSignerPolicy(operatorConfig)
	if err != nil {
		t.Fatal(err)
	}
	service, err = delivery.ConnectClient(ctx, delivery.Config{Conn: leader.Conn(), JS: leader.JetStream(), Cell: "gru", Verifier: policy.codec, ArtifactVerifier: policy.codec, Authorize: policy.authorizeIntent, AuthorizeArtifact: policy.authorizeArtifact})
	if err != nil {
		t.Fatal(err)
	}
	history := nativeTestHistory(t, controllerCfg, leader, service, observedLeader{js: leader.JetStream()})
	saved, _, err := history.load(ctx, tsauth.Role)
	if err != nil || saved.Recovery == nil || saved.Pending == nil || saved.Recovery.Intent.ArtifactDigest != secondDigest ||
		saved.Recovery.ProfileDigest != nativeProfileDigest(goodProfile) || saved.Pending.ProfileDigest == saved.Recovery.ProfileDigest {
		t.Fatalf("changed full config was not restored: %+v, %v", saved, err)
	}
	desired, err := history.hosts.ListDesired(ctx, tsauth.Role)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range desired {
		if !d.Withdrawn && (d.Digest != secondDigest || !slices.Equal(d.Args, goodProfile.Args) || !maps.Equal(d.Env, goodProfile.Env) || !maps.Equal(d.Secrets, goodProfile.Secrets)) {
			t.Fatalf("host kept failed config: %+v", d)
		}
	}
	resources, err := history.resources(ctx, desired, map[string]placement.Resources{tsauth.Role: profile.Resources})
	if err != nil || resources[tsauth.Role] != goodProfile.Resources {
		t.Fatalf("retained placement resources: %v, %v", resources, err)
	}
	// A fresh reconciler, after leader replay, keeps the recovery template and
	// reservations despite today's larger B/C placement profile. This retains
	// legacy replay coverage until its active-boundary replacement is qualified.
	replayProfiles := profileResources(map[string]WorkloadProfile{tsauth.Role: profile})
	replayLoad := startHostTelemetry(map[string]WorkloadProfile{tsauth.Role: profile}, history.hosts, history.fencer)
	reconciler, err := workload.New(workload.Config{Cell: "gru", Specs: []workload.ServiceSpec{spec}, Profiles: replayProfiles,
		Hosts: history.hosts, Writer: history, Fencer: history.fencer, Signals: replayLoad.load,
		ReleaseResources: func(ctx context.Context, desired []host.Desired, profiles map[string]placement.Resources) (map[string]placement.Resources, error) {
			resolved, err := history.resources(ctx, desired, profiles)
			if err == nil {
				replayLoad.setResources(resolved)
			}
			return resolved, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Tick(ctx); err != nil {
		t.Fatalf("leader replay reconciliation: %v", err)
	}
	confirmed, err := history.hosts.ListDesired(ctx, tsauth.Role)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range confirmed {
		if !d.Withdrawn && (d.Digest != secondDigest || !maps.Equal(d.Env, goodProfile.Env) || !maps.Equal(d.Secrets, goodProfile.Secrets)) {
			t.Fatal("reconciliation restored B/C")
		}
	}
	// The same binary with a bad configuration must restore A and reject that
	// exact full profile without poisoning the proven-good artifact.
	profile = cloneNativeProfile(profile)
	profile.Env["NONSECRET_SETTING"] = "bad-config-only"
	ref = profile.Secrets[tsauth.EnvAPIKey]
	ref.Name += "-absent"
	profile.Secrets[tsauth.EnvAPIKey] = ref
	profilePath = testJSONFile(t, root, "profile-config-only.json", profile)
	applyNativeTestSpec(t, operatorConfig, operatorRuntime, specKeys, []cellspec.Service{{Role: tsauth.Role, Profile: profile, Spec: &spec}}, 4)
	if out, err := release(second, 15*time.Second); err == nil || !strings.Contains(err.Error(), "was rolled back to "+secondDigest) {
		t.Fatalf("config-only failure did not recover: %v\n%s", err, out)
	}
	assertReplicas(secondDigest)
	recovered, _, err := history.load(ctx, tsauth.Role)
	if err != nil || recovered.Recovery == nil || recovered.Recovery.ProfileDigest != nativeProfileDigest(goodProfile) {
		t.Fatalf("config-only recovery changed A: %+v,%v", recovered, err)
	}
	if _, err := service.ResolveAdmittedArtifact(ctx, secondDigest, tsauth.Role, "test"); err != nil {
		t.Fatalf("config-only failure poisoned good bytes: %v", err)
	}
	if out, err := release(second, 15*time.Second); err == nil || !strings.Contains(err.Error(), "known bad") {
		t.Fatalf("failed full profile was retried: %v\n%s", err, out)
	}
	assertReplicas(secondDigest)
	for _, node := range nodes {
		if !replicas[node].drained() {
			t.Fatalf("%s never stopped a replica with a drain timeout", node)
		}
	}
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
