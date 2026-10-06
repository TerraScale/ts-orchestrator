package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/serviceset"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// testServiceTrust is a root, a release leaf and the root's service set
// delegation to the leaf for one identity.
type testServiceTrust struct {
	identity   serviceset.Identity
	roots      trust.Keyring
	leaf       ed25519.PrivateKey
	delegation []byte
	rootFile   string
}

func newTestServiceTrust(t *testing.T, dir string, identity serviceset.Identity) testServiceTrust {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := serviceset.SignDelegation(leafPublic, identity, now.Add(-time.Minute), now.Add(24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(dir, "service-root-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	rootFile := file.Name()
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	return testServiceTrust{identity: identity, roots: roots, leaf: leafPrivate, delegation: delegation, rootFile: rootFile}
}

// sign signs set and writes it to a new file in dir.
func (k testServiceTrust) sign(t *testing.T, dir string, set serviceset.Set) string {
	t.Helper()
	wire, err := serviceset.Sign(set, k.delegation, k.roots, time.Now(), time.Hour, k.leaf)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(dir, "signed-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

func (k testServiceTrust) config() *ServiceTrustConfig {
	return &ServiceTrustConfig{RootPublicKeyFile: k.rootFile, DeploymentID: k.identity.DeploymentID,
		Environment: k.identity.Environment}
}

func testServiceSetRoots(t *testing.T) trust.Keyring {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

// The generation 0 set is the signed config's generic workloads; TerraBase
// stays with placement, and only an enabled autoscale config reconciles.
func TestServiceRegistryBaselineFromSignedConfig(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	spec := workload.ServiceSpec{Role: "web", Environment: "test", Kind: workload.KindStateless,
		Replicas: workload.ReplicaBounds{Min: 1, Max: 2}}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}, "web": {Resources: resources}},
		Autoscale: &AutoscaleConfig{Enabled: true, Services: []workload.ServiceSpec{spec}}}}
	registry, err := newServiceRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	profiles, specs := registry.effective()
	if len(registry.current.Services) != 1 || registry.current.Services[0].Role != "web" || registry.current.Generation != 0 ||
		len(specs) != 1 || specs[0].Role != "web" || len(profiles) != 2 {
		t.Fatalf("baseline %+v, profiles %v, specs %v", registry.current, profiles, specs)
	}
	cfg.Controller.Autoscale.Enabled = false
	if registry, err = newServiceRegistry(cfg, ""); err != nil {
		t.Fatal(err)
	}
	if _, specs := registry.effective(); len(specs) != 0 {
		t.Fatalf("a disabled autoscale config reconciles %v", specs)
	}
	cfg.NATS.Lab = false
	cfg.Controller.ServiceTrust = &ServiceTrustConfig{}
	if _, err := newServiceRegistry(cfg, ""); err == nil || !strings.Contains(err.Error(), "lab setting") {
		t.Fatalf("a production controller accepted lab service trust: %v", err)
	}
}

// TestServiceSetAmendsARunningController adds, updates and removes a service
// on a running controller with signed service sets, and checks that it
// refuses replays, rollbacks, stale and foreign sets and placement-owned
// roles, and keeps the set across a restart.
func TestServiceSetAmendsARunningController(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	port := freeTCPPort(t)
	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	keys := newTestServiceTrust(t, root, serviceset.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "test"})
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase", "web"}, Environments: []string{"test"}}
	resources := placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}
	controllerConfig := testJSONFile(t, root, "controller.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"),
				StoreMaxBytes: 2 << 30, Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller"},
					{PublicKey: operatorNKey, Role: "operator"}}}},
		Controller: ControllerConfig{CandidateID: "one", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads:    map[string]WorkloadProfile{"terrabase": {Resources: resources}},
			ServiceTrust: keys.config()},
	})
	operatorConfig := testJSONFile(t, root, "operator.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "operator", Replicas: 1, Lab: true,
			URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: operatorSeed},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}})
	start := func() (context.CancelFunc, chan error) {
		runCtx, stop := context.WithCancel(ctx)
		output := &readyWriter{ready: make(chan struct{})}
		done := make(chan error, 1)
		go func() { done <- Run(runCtx, []string{"run", "--config", controllerConfig}, output) }()
		select {
		case <-output.ready:
		case err := <-done:
			t.Fatalf("controller exited before ready: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return stop, done
	}
	stop, done := start()
	defer func() {
		stop()
		<-done
	}()
	service := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := Run(ctx, append([]string{"service", args[0], "--config", operatorConfig}, args[1:]...), &output)
		return output.String(), err
	}
	list := func() serviceset.Set {
		t.Helper()
		out, err := service("list")
		if err != nil {
			t.Fatal(err)
		}
		var set serviceset.Set
		if err := json.Unmarshal([]byte(out), &set); err != nil {
			t.Fatal(err)
		}
		return set
	}
	current := list()
	if current.Generation != 0 || len(current.Services) != 0 || current.Identity != keys.identity {
		t.Fatalf("baseline %+v", current)
	}

	profile := testJSONFile(t, root, "web-profile.json", WorkloadProfile{Resources: resources, Env: map[string]string{"MODE": "a"}})
	spec := workload.ServiceSpec{Role: "web", Environment: "test", Kind: workload.KindStateless,
		Replicas: workload.ReplicaBounds{Min: 1, Max: 2}}
	specFile := testJSONFile(t, root, "web-spec.json", spec)
	candidate := filepath.Join(root, "add.json")
	out, err := service("add", "--role", "web", "--profile", profile, "--spec", specFile, "--out", candidate)
	if err != nil || !strings.Contains(out, `"added":["web"]`) || !strings.Contains(out, `"to_generation":1`) {
		t.Fatalf("plan add: %v\n%s", err, out)
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	first, err := serviceset.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	firstSigned := keys.sign(t, root, first)
	if out, err := service("apply", "--file", firstSigned); err != nil || !strings.Contains(out, `"status":"applied"`) {
		t.Fatalf("apply generation 1: %v\n%s", err, out)
	}
	if out, err := service("apply", "--file", firstSigned); err != nil || !strings.Contains(out, `"status":"unchanged"`) {
		t.Fatalf("re-apply generation 1: %v\n%s", err, out)
	}
	if out, err := service("add", "--role", "web", "--profile", profile, "--spec", specFile); err != nil ||
		!strings.Contains(out, `"status":"unchanged"`) {
		t.Fatalf("an identical add planned a change: %v\n%s", err, out)
	}
	if got := list(); got.Generation != 1 || len(got.Services) != 1 || got.Services[0].Spec == nil {
		t.Fatalf("after add: %+v", got)
	}

	// Two operators plan generation 2 from the same view: the second is stale.
	spec.Replicas.Max = 3
	updated := first
	updated.Generation = 2
	updated.Services = []serviceset.Service{{Role: "web", Profile: first.Services[0].Profile, Spec: &spec}}
	racing := updated
	racing.Services = nil
	updatedSigned, racingSigned := keys.sign(t, root, updated), keys.sign(t, root, racing)
	if out, err := service("apply", "--file", updatedSigned); err != nil || !strings.Contains(out, `"generation":2`) {
		t.Fatalf("apply generation 2: %v\n%s", err, out)
	}
	for name, path := range map[string]string{"stale generation 2": racingSigned, "replayed generation 1": firstSigned} {
		if _, err := service("apply", "--file", path); err == nil || !strings.Contains(err.Error(), "does not follow") {
			t.Errorf("%s: %v", name, err)
		}
	}
	next := updated
	next.Generation = 3
	foreign := newTestServiceTrust(t, root, keys.identity)
	other := newTestServiceTrust(t, root, serviceset.Identity{DeploymentID: "lab-sfo", Cell: "sfo", Environment: "test"})
	otherSet := next
	otherSet.Identity = other.identity
	// A set may only add settings to TerraBase's signed profile.
	grown := resources
	grown.CPU = 2
	reserved := next
	reserved.Services = append([]serviceset.Service{{Role: "terrabase", Profile: WorkloadProfile{Resources: grown}}},
		next.Services...)
	for name, path := range map[string]string{
		"untrusted root":      foreign.sign(t, root, next),
		"another cell":        other.sign(t, root, otherSet),
		"terrabase resources": keys.sign(t, root, reserved),
		"invalid profile":     keys.sign(t, root, withProfile(next, WorkloadProfile{})),
		"unsigned garbage":    testJSONFile(t, root, "garbage.json", map[string]string{"set": "{}"}),
	} {
		if _, err := service("apply", "--file", path); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if got := list(); got.Generation != 2 || got.Services[0].Spec.Replicas.Max != 3 {
		t.Fatalf("after refused sets: %+v", got)
	}

	// A holder of controller credentials writes an older signed set, then a
	// corrupt record, straight into the store: neither is adopted, and the
	// next generation still applies on top of the adopted set.
	probe, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "probe", Replicas: 1, Lab: true,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: controllerSeed})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	store, err := probe.JetStream().KeyValue(ctx, serviceSetBucket)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{mustRead(t, firstSigned), mustRead(t, racingSigned), []byte("{}")} {
		if _, err := store.Put(ctx, serviceSetKey, value); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if got := list(); got.Generation != 2 || len(got.Services) != 1 {
			t.Fatalf("a written record moved the set to %+v", got)
		}
		// The written set is not reported as the cell's.
		if _, err := service("apply", "--file", racingSigned); err == nil || !strings.Contains(err.Error(), "does not follow") {
			t.Fatalf("written record: applying the rival generation 2: %v", err)
		}
	}

	removal := filepath.Join(root, "remove.json")
	if out, err := service("remove", "--role", "web", "--out", removal); err != nil || !strings.Contains(out, `"removed":["web"]`) {
		t.Fatalf("plan remove: %v\n%s", err, out)
	}
	data, err = os.ReadFile(removal)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := serviceset.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service("apply", "--file", keys.sign(t, root, removed)); err != nil || !strings.Contains(out, `"generation":3`) {
		t.Fatalf("apply removal: %v\n%s", err, out)
	}

	// The accepted set survives a controller restart.
	stop()
	if err := <-done; err != nil {
		t.Fatalf("controller stop: %v", err)
	}
	stop, done = start()
	if got := list(); got.Generation != 3 || len(got.Services) != 0 {
		t.Fatalf("after restart: %+v", got)
	}

	// A host grant is planned, signed and applied like a service, keeps its
	// role from being removed, and is revoked the same way.
	applyPlanned := func(want string, args ...string) {
		t.Helper()
		candidate := filepath.Join(t.TempDir(), "candidate.json")
		out, err := service(append(args, "--out", candidate)...)
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("plan %v: %v\n%s", args, err, out)
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			t.Fatal(err)
		}
		set, err := serviceset.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := service("apply", "--file", keys.sign(t, root, set)); err != nil || !strings.Contains(out, `"status":"applied"`) {
			t.Fatalf("apply %v: %v\n%s", args, err, out)
		}
	}
	applyPlanned(`"added":["web"]`, "add", "--role", "web", "--profile", profile)
	applyPlanned(`"host_grants":["gru-1-ctl-1"]`, "grant-host", "--node", "gru-1-ctl-1", "--private-ip", "10.251.0.11",
		"--roles", "web", "--environment", "test")
	if got := list(); len(got.HostGrants) != 1 || got.HostGrants[0].PrivateIP != "10.251.0.11" {
		t.Fatalf("after grant: %+v", got)
	}
	removal = filepath.Join(root, "remove-granted.json")
	if _, err := service("remove", "--role", "web", "--out", removal); err != nil {
		t.Fatal(err)
	}
	if removed, err = serviceset.Decode(mustRead(t, removal)); err != nil {
		t.Fatal(err)
	}
	if _, err := service("apply", "--file", keys.sign(t, root, removed)); err == nil || !strings.Contains(err.Error(), "host grant") {
		t.Fatalf("removed a role a host grant names: %v", err)
	}
	applyPlanned(`"host_grants":["gru-1-ctl-1"]`, "revoke-host", "--node", "gru-1-ctl-1")
	if got := list(); len(got.HostGrants) != 0 || got.Generation != 6 {
		t.Fatalf("after revoke: %+v", got)
	}
}

// Grants name roles the cell delivers, never TerraBase, placement's member
// role or a listed TerraBase member.
func TestServiceRegistryValidatesHostGrants(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{terrabase.Role: {Resources: resources, Env: map[string]string{
			terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}}}}
	registry, err := newServiceRegistry(cfg, "member")
	if err != nil {
		t.Fatal(err)
	}
	web := serviceset.Service{Role: "web", Profile: WorkloadProfile{Resources: resources}}
	grant := func(node, ip string, roles ...string) serviceset.Set {
		return serviceset.Set{Schema: serviceset.Schema, Generation: 1, Services: []serviceset.Service{web},
			HostGrants: []serviceset.HostGrant{{Node: node, PrivateIP: ip, Roles: roles, Environment: "canary"}}}
	}
	if err := registry.validate(grant("gru-1-ctl-1", "10.251.0.11", "web")); err != nil {
		t.Fatalf("grant for a delivered role: %v", err)
	}
	for name, set := range map[string]serviceset.Set{
		"role without a profile": grant("gru-1-ctl-1", "10.251.0.11", "api"),
		"terrabase":              grant("gru-1-ctl-1", "10.251.0.11", terrabase.Role),
		"placement member role":  grant("gru-1-ctl-1", "10.251.0.11", "member"),
		"TerraBase member":       grant("gru-1-db-1", "10.251.0.21", "web"),
	} {
		if err := registry.validate(set); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	registry.adopt(grant("gru-1-ctl-1", "10.251.0.11", "web"), 1)
	if got, capacity, ok := registry.hostGrant("gru-1-ctl-1"); !ok || got.PrivateIP != "10.251.0.11" ||
		capacity != (host.Capacity{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}) {
		t.Fatalf("hostGrant = %+v, %+v, %v", got, capacity, ok)
	}
	if _, _, ok := registry.hostGrant("gru-1-ctl-2"); ok {
		t.Fatal("an ungranted node has a grant")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func withProfile(set serviceset.Set, profile WorkloadProfile) serviceset.Set {
	set.Services = []serviceset.Service{{Role: set.Services[0].Role, Profile: profile, Spec: set.Services[0].Spec}}
	return set
}

// A set may add environment settings to the signed TerraBase profile, and
// may let trusted signers release a service and register its hosts in the
// set's environment; nothing else widens.
func TestServiceSetTerraBaseSettingsAndReleasers(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	signed := WorkloadProfile{Resources: resources, Env: map[string]string{"TERRABASE_REGION": "gru-1",
		terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{terrabase.Role: signed},
		TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			Roles: []string{terrabase.Role}, Environments: []string{"canary"}}}}}
	registry, err := newServiceRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	registry.identity = serviceset.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "canary"}
	if len(registry.current.Services) != 0 {
		t.Fatalf("TerraBase joined the generation 0 set: %+v", registry.current.Services)
	}
	added := signed
	added.Env = maps.Clone(signed.Env)
	added.Env["TERRABASE_AUTH_ISSUER"] = "https://gru.auth.terrascale.tech/terrascale"
	web := serviceset.Service{Role: "web", Profile: WorkloadProfile{Resources: resources}, Releasers: []string{"ops"}}
	set := func(services ...serviceset.Service) serviceset.Set {
		return serviceset.Set{Schema: serviceset.Schema, Identity: registry.identity, Generation: 1, Services: services}
	}
	override := serviceset.Service{Role: terrabase.Role, Profile: added}
	if err := registry.validate(set(override, web)); err != nil {
		t.Fatalf("adding a TerraBase setting: %v", err)
	}
	changed, removed, grown := added, signed, signed
	changed.Env = maps.Clone(added.Env)
	changed.Env[terrabase.EnvPeers] = "gru-1-db-1=10.251.0.21:9443,gru-1-db-9=10.251.0.29:9443"
	removed.Env = map[string]string{"TERRABASE_REGION": "gru-1", terrabase.EnvPeerPort: "9443"}
	grown.Resources.CPU = 2
	stranger := web
	stranger.Releasers = []string{"intruder"}
	for name, candidate := range map[string]serviceset.Set{
		"changed peers":      set(serviceset.Service{Role: terrabase.Role, Profile: changed}),
		"removed peers":      set(serviceset.Service{Role: terrabase.Role, Profile: removed}),
		"changed resources":  set(serviceset.Service{Role: terrabase.Role, Profile: grown}),
		"untrusted releaser": set(stranger),
		"host-owned setting": set(serviceset.Service{Role: terrabase.Role, Profile: withEnv(added, terrabase.EnvDataDirectory, "/tmp")}),
	} {
		if err := registry.validate(candidate); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	withoutTerraBase := cfg
	withoutTerraBase.Controller.Workloads = map[string]WorkloadProfile{"web": {Resources: resources}}
	other, err := newServiceRegistry(withoutTerraBase, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.validate(set(override)); err == nil {
		t.Error("a cell without a signed TerraBase profile accepted one from a set")
	}

	registry.adopt(set(override, web), 1)
	if profiles := registry.profiles(); profiles[terrabase.Role].Env["TERRABASE_AUTH_ISSUER"] == "" {
		t.Fatalf("effective TerraBase profile %+v", profiles[terrabase.Role])
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	artifact := func(role, environment string) error {
		return policy.authorizeArtifact(t.Context(), "ops", delivery.ArtifactRecord{Cell: "gru", Role: role, Environment: environment})
	}
	if artifact("web", "canary") == nil {
		t.Fatal("a releaser was authorized before the policy saw the service set")
	}
	policy.services = registry
	if err := artifact("web", "canary"); err != nil {
		t.Fatalf("releaser: %v", err)
	}
	if err := artifact(terrabase.Role, "canary"); err != nil {
		t.Fatalf("signed grant: %v", err)
	}
	for _, refused := range [][2]string{{"web", "production"}, {"api", "canary"}} {
		if artifact(refused[0], refused[1]) == nil {
			t.Errorf("authorized %v", refused)
		}
	}
	if registry.releaser("someone", "web", "canary") {
		t.Error("an actor the set does not name may release")
	}
}

func withEnv(profile WorkloadProfile, key, value string) WorkloadProfile {
	profile.Env = maps.Clone(profile.Env)
	profile.Env[key] = value
	return profile
}
