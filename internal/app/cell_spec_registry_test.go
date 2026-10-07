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
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/kvsnapshot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// testSpecTrust is a root, a release leaf and the root's cell spec
// delegation to the leaf for one identity.
type testSpecTrust struct {
	identity   cellspec.Identity
	roots      trust.Keyring
	root, leaf ed25519.PrivateKey
	delegation []byte
	rootFile   string
}

func newTestSpecTrust(t *testing.T, dir string, identity cellspec.Identity) testSpecTrust {
	t.Helper()
	_, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestSpecTrustWithRoot(t, dir, identity, rootPrivate)
}

func newTestSpecTrustWithRoot(t *testing.T, dir string, identity cellspec.Identity, rootPrivate ed25519.PrivateKey) testSpecTrust {
	t.Helper()
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := cellspec.SignDelegation(leafPublic, identity, now.Add(-time.Minute), now.Add(24*time.Hour), rootPrivate)
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
	file, err := os.CreateTemp(dir, "spec-root-*.pem")
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
	return testSpecTrust{identity: identity, roots: roots, root: rootPrivate, leaf: leafPrivate, delegation: delegation,
		rootFile: rootFile}
}

// sign signs spec with the leaf and writes it to a new file in dir.
func (k testSpecTrust) sign(t *testing.T, dir string, spec cellspec.Spec) string {
	t.Helper()
	wire, err := cellspec.Sign(spec, k.delegation, k.roots, time.Now(), time.Hour, k.leaf)
	if err != nil {
		t.Fatal(err)
	}
	return writeSigned(t, dir, wire)
}

// signRoot signs spec with the root itself.
func (k testSpecTrust) signRoot(t *testing.T, dir string, spec cellspec.Spec) string {
	t.Helper()
	wire, err := cellspec.Sign(spec, nil, k.roots, time.Now(), time.Hour, k.root)
	if err != nil {
		t.Fatal(err)
	}
	return writeSigned(t, dir, wire)
}

func writeSigned(t *testing.T, dir string, wire []byte) string {
	t.Helper()
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

func (k testSpecTrust) config() *SpecTrustConfig {
	return &SpecTrustConfig{RootPublicKeyFile: k.rootFile, DeploymentID: k.identity.DeploymentID,
		Environment: k.identity.Environment}
}

func testSpecRoots(t *testing.T) trust.Keyring {
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
func TestSpecRegistryBaselineFromSignedConfig(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	spec := workload.ServiceSpec{Role: "web", Environment: "test", Kind: workload.KindStateless,
		Replicas: workload.ReplicaBounds{Min: 1, Max: 2}}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}, "web": {Resources: resources}},
		Autoscale: &AutoscaleConfig{Enabled: true, Services: []workload.ServiceSpec{spec}}}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	profiles, specs := registry.effective()
	if len(registry.current.Services) != 1 || registry.current.Services[0].Role != "web" || registry.current.Generation != 0 ||
		len(specs) != 1 || specs[0].Role != "web" || len(profiles) != 2 {
		t.Fatalf("baseline %+v, profiles %v, specs %v", registry.current, profiles, specs)
	}
	cfg.Controller.Autoscale.Enabled = false
	if registry, err = newSpecRegistry(cfg, ""); err != nil {
		t.Fatal(err)
	}
	if _, specs := registry.effective(); len(specs) != 0 {
		t.Fatalf("a disabled autoscale config reconciles %v", specs)
	}
	// A lab without spec_trust has no root chain and refuses every spec.
	if registry.roots != nil || registry.roots.current() != nil {
		t.Fatal("a lab without spec_trust has roots")
	}
	if _, err := registry.verify([]byte("{}"), nil); err == nil || !strings.Contains(err.Error(), "no cell spec trust roots") {
		t.Fatalf("a lab without spec_trust verified a spec: %v", err)
	}
	cfg.NATS.Lab = false
	cfg.Controller.SpecTrust = &SpecTrustConfig{}
	if _, err := newSpecRegistry(cfg, ""); err == nil || !strings.Contains(err.Error(), "lab setting") {
		t.Fatalf("a production controller accepted lab spec trust: %v", err)
	}
}

// TestCellSpecAmendsARunningController adds, updates and removes a service
// on a running controller with signed cell specs, and checks that it
// refuses replays, rollbacks, stale and foreign specs, placement-owned roles
// and leaf-signed authority widening, keeps its spec when the stored record
// needs a newer binary, and keeps the spec across a restart.
func TestCellSpecAmendsARunningController(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	port := freeTCPPort(t)
	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	keys := newTestSpecTrust(t, root, cellspec.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "test"})
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase", "web"}, Environments: []string{"test"}}
	resources := placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}
	controllerConfig := testJSONFile(t, root, "controller.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"),
				StoreMaxBytes: 2 << 30, Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller", Global: true},
					{PublicKey: operatorNKey, Role: "operator"}}}},
		Controller: ControllerConfig{CandidateID: "one", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}},
			SpecTrust: keys.config(), Global: &GlobalControlConfig{Enabled: true, Home: "gru"}},
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
	list := func() cellspec.Spec {
		t.Helper()
		out, err := service("list")
		if err != nil {
			t.Fatal(err)
		}
		var set cellspec.Spec
		if err := json.Unmarshal([]byte(out), &set); err != nil {
			t.Fatal(err)
		}
		return set
	}
	current := list()
	if current.Generation != 0 || current.RequiresBinary != 1 || len(current.Services) != 0 || current.Identity != keys.identity {
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
	first, err := cellspec.Decode(data)
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
	updated.Services = []cellspec.Service{{Role: "web", Profile: first.Services[0].Profile, Spec: &spec}}
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
	foreign := newTestSpecTrust(t, root, keys.identity)
	other := newTestSpecTrust(t, root, cellspec.Identity{DeploymentID: "lab-sfo", Cell: "sfo", Environment: "test"})
	otherSet := next
	otherSet.Identity = other.identity
	// Only a root may change TerraBase's resources.
	grown := resources
	grown.CPU = 2
	reserved := next
	reserved.Services = append([]cellspec.Service{{Role: "terrabase", Profile: WorkloadProfile{Resources: grown}}},
		next.Services...)
	// A spec for another cell goes to the global leader, which relays only
	// to interregion peers; a standalone home has none.
	if _, err := service("apply", "--file", other.sign(t, root, otherSet)); err == nil ||
		!strings.Contains(err.Error(), `cell "SFO" is not an interregion peer`) {
		t.Errorf("another cell: %v", err)
	}
	for name, path := range map[string]string{
		"untrusted root":      foreign.sign(t, root, next),
		"terrabase resources": keys.sign(t, root, reserved),
		"invalid profile":     keys.sign(t, root, withProfile(next, WorkloadProfile{})),
		"unsigned garbage":    testJSONFile(t, root, "garbage.json", map[string]string{"set": "{}"}),
	} {
		if _, err := service("apply", "--file", path); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if got := list(); got.Generation != 2 || got.Services[0].Spec.Replicas.Max != 3 {
		t.Fatalf("after refused specs: %+v", got)
	}
	if _, err := service("apply", "--file", keys.sign(t, root, reserved)); err == nil || !strings.Contains(err.Error(), "a root must sign it") {
		t.Fatalf("the leaf grew TerraBase: %v", err)
	}

	// A holder of controller credentials writes an older signed spec, then a
	// corrupt record, straight into the store: neither is adopted, and the
	// next generation still applies on top of the adopted spec.
	probe, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "probe", Replicas: 1, Lab: true,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: controllerSeed})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	store, err := probe.JetStream().KeyValue(ctx, cellSpecBucket)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{mustRead(t, firstSigned), mustRead(t, racingSigned), []byte("{}")} {
		if _, err := store.Put(ctx, cellSpecKey, value); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if got := list(); got.Generation != 2 || len(got.Services) != 1 {
			t.Fatalf("a written record moved the spec to %+v", got)
		}
		// The written spec is not reported as the cell's.
		if _, err := service("apply", "--file", racingSigned); err == nil || !strings.Contains(err.Error(), "does not follow") {
			t.Fatalf("written record: applying the rival generation 2: %v", err)
		}
	}

	// A record for a newer binary, with a section this binary does not know,
	// is not adopted, and the controller refuses to amend over it until its
	// binary is updated. Only the root may replace it, with the generation
	// that follows it, as after a binary rollback.
	payload, err := cellspec.Encode(next)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"requires_binary":1,`), []byte(fmt.Sprintf(`"requires_binary":%d,"edge":{},`, cellspec.BinaryLevel+1)), 1)
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, keys.identity.Scope(), now, now.Add(time.Hour), keys.leaf)
	if err != nil {
		t.Fatal(err)
	}
	envelopeWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := protocol.EncodeJSON(cellspec.Signed{Delegation: keys.delegation, Spec: envelopeWire})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, cellSpecKey, newer); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := list(); got.Generation != 2 {
		t.Fatalf("a newer-binary record moved the spec to %+v", got)
	}
	if _, err := service("apply", "--file", keys.sign(t, root, next)); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("requires binary level %d", cellspec.BinaryLevel+1)) || !strings.Contains(err.Error(), "update this controller's binary first") {
		t.Fatalf("amended over a newer-binary record: %v", err)
	}
	replacement := reserved
	replacement.Generation = 4
	if _, err := service("apply", "--file", keys.sign(t, root, replacement)); err == nil ||
		!strings.Contains(err.Error(), "update this controller's binary first") {
		t.Fatalf("the leaf replaced a newer-binary record: %v", err)
	}
	// The root may grow TerraBase, and the leaf's later amendments keep it.
	if out, err := service("apply", "--file", keys.signRoot(t, root, replacement)); err != nil || !strings.Contains(out, `"generation":4`) {
		t.Fatalf("root-signed replacement with TerraBase growth: %v\n%s", err, out)
	}

	removal := filepath.Join(root, "remove.json")
	if out, err := service("remove", "--role", "web", "--out", removal); err != nil || !strings.Contains(out, `"removed":["web"]`) {
		t.Fatalf("plan remove: %v\n%s", err, out)
	}
	data, err = os.ReadFile(removal)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := cellspec.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service("apply", "--file", keys.sign(t, root, removed)); err != nil || !strings.Contains(out, `"generation":5`) {
		t.Fatalf("apply removal: %v\n%s", err, out)
	}

	// The accepted spec survives a controller restart.
	stop()
	if err := <-done; err != nil {
		t.Fatalf("controller stop: %v", err)
	}
	stop, done = start()
	if got := list(); got.Generation != 5 || len(got.Services) != 1 || got.Services[0].Profile.Resources.CPU != 2 {
		t.Fatalf("after restart: %+v", got)
	}

	// A host grant is planned and applied like a service, but only a root
	// may sign a new one; it keeps its role from being removed, and the leaf
	// may revoke it.
	before := list().Generation
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
		set, err := cellspec.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		signed := keys.sign(t, root, set)
		if strings.Contains(out, `"root_required"`) {
			if _, err := service("apply", "--file", signed); err == nil || !strings.Contains(err.Error(), "a root must sign it") {
				t.Fatalf("the leaf applied %v: %v", args, err)
			}
			signed = keys.signRoot(t, root, set)
		}
		if out, err := service("apply", "--file", signed); err != nil || !strings.Contains(out, `"status":"applied"`) {
			t.Fatalf("apply %v: %v\n%s", args, err, out)
		}
	}
	applyPlanned(`"added":["web"]`, "add", "--role", "web", "--profile", profile)
	applyPlanned(`"root_required":["host grant gru-1-ctl-1"]`, "grant-host", "--node", "gru-1-ctl-1", "--private-ip", "10.251.0.11",
		"--roles", "web", "--environment", "test")
	if got := list(); len(got.HostGrants) != 1 || got.HostGrants[0].PrivateIP != "10.251.0.11" {
		t.Fatalf("after grant: %+v", got)
	}
	// The leader's plan already applies the cell's rules.
	if _, err := service("remove", "--role", "web"); err == nil || !strings.Contains(err.Error(), "host grant") {
		t.Fatalf("planned removing a role a host grant names: %v", err)
	}
	granted := list()
	granted.Generation++
	granted.Services = slices.DeleteFunc(granted.Services, func(s cellspec.Service) bool { return s.Role == "web" })
	if _, err := service("apply", "--file", keys.signRoot(t, root, granted)); err == nil || !strings.Contains(err.Error(), "host grant") {
		t.Fatalf("removed a role a host grant names: %v", err)
	}
	// A grant at the node's address renames it, naming its controller slot
	// (TS-609).
	applyPlanned(`"host_grants":["gru-1-ctl-1","ts-gru-1"]`, "grant-host", "--node", "ts-gru-1", "--private-ip", "10.251.0.11",
		"--roles", "web", "--environment", "test", "--controller", "controller-a")
	if got := list(); len(got.HostGrants) != 1 || got.HostGrants[0].Node != "ts-gru-1" || got.HostGrants[0].Controller != "controller-a" ||
		got.RequiresBinary != 17 {
		t.Fatalf("after rename: %+v", got)
	}
	applyPlanned(`"host_grants":["ts-gru-1"]`, "revoke-host", "--node", "ts-gru-1")
	if got := list(); len(got.HostGrants) != 0 || got.Generation != before+4 {
		t.Fatalf("after revoke: %+v", got)
	}
}

// Grants name roles the cell delivers, never TerraBase, placement's member
// role or a listed TerraBase member.
func TestSpecRegistryValidatesHostGrants(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{terrabase.Role: {Resources: resources, Env: map[string]string{
			terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}}}}
	registry, err := newSpecRegistry(cfg, "member")
	if err != nil {
		t.Fatal(err)
	}
	web := cellspec.Service{Role: "web", Profile: WorkloadProfile{Resources: resources}}
	grant := func(node, ip string, roles ...string) cellspec.Spec {
		return cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 1, Services: []cellspec.Service{web},
			HostGrants: []cellspec.HostGrant{{Node: node, PrivateIP: ip, Roles: roles, Environment: "canary"}}}
	}
	if err := registry.validate(grant("gru-1-ctl-1", "10.251.0.11", "web")); err != nil {
		t.Fatalf("grant for a delivered role: %v", err)
	}
	for name, set := range map[string]cellspec.Spec{
		"role without a profile":              grant("gru-1-ctl-1", "10.251.0.11", "api"),
		"terrabase on an unlisted host":       grant("gru-1-ctl-1", "10.251.0.11", terrabase.Role),
		"placement member role":               grant("gru-1-ctl-1", "10.251.0.11", "member"),
		"TerraBase member without its role":   grant("gru-1-db-1", "10.251.0.21", "web"),
		"TerraBase member at another address": grant("gru-1-db-1", "10.251.0.29", terrabase.Role, "web"),
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
	// A listed member granted at its peer address runs the member beside
	// the grant's other roles, with the capacity of both (TS-578).
	colocated := grant("gru-1-db-1", "10.251.0.21", terrabase.Role, "web")
	colocated.Generation = 2
	if err := registry.validate(colocated); err != nil {
		t.Fatalf("grant colocating a member: %v", err)
	}
	registry.adopt(colocated, 2)
	if _, capacity, ok := registry.hostGrant("gru-1-db-1"); !ok ||
		capacity != (host.Capacity{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 2 << 30}) {
		t.Fatalf("colocated grant capacity = %+v, %v", capacity, ok)
	}
	// A renamed node keeps the member at its address, and its grant names
	// the controller slot whose VM it is (TS-609).
	if registry.controllerNode("gru", "controller-a") != "gru-1-ctl-1" {
		t.Fatal("a slot without a grant does not keep its server name")
	}
	renamed := grant("ts-gru-1", "10.251.0.21", terrabase.Role, "web")
	renamed.Generation, renamed.RequiresBinary, renamed.HostGrants[0].Controller = 3, 17, "controller-a"
	if err := registry.validate(renamed); err != nil {
		t.Fatalf("grant renaming a member's node: %v", err)
	}
	registry.adopt(renamed, 3)
	if registry.controllerNode("gru", "controller-a") != "ts-gru-1" || registry.controllerNode("gru", "controller-b") != "gru-1-ctl-2" ||
		registry.nodeAddress("ts-gru-1") != "10.251.0.21" || registry.nodeAddress("gru-1-db-1") != "" {
		t.Fatal("the renamed grant does not map its controller slot and address")
	}
}

// A budget needs every node pool priced, and the pool scaler reads the
// adopted spec's budget, also after a restart adopted it before the scaler
// started.
func TestSpecRegistryBudgetNeedsPricedPools(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	pool := hostpool.NodePool{Name: "general", Environment: "test", Roles: []string{"web"},
		Shape: placement.Resources{CPU: 4, MemoryBytes: 8 << 30, DiskBytes: 50 << 30}, FailureDomains: []string{"fd-1"},
		Max: 2, IdleCooldownSeconds: 600}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{"web": {Resources: resources}},
		Autoscale: &AutoscaleConfig{Enabled: true, NodePools: []hostpool.NodePool{pool}}}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	set := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 3,
		Services: []cellspec.Service{{Role: "web", Profile: WorkloadProfile{Resources: resources}}},
		Budget:   &hostpool.Budget{MonthlyCapCents: 50000, Currency: "USD"}}
	if err := registry.validate(set); err == nil || !strings.Contains(err.Error(), "host_monthly_cents") {
		t.Fatalf("budget with an unpriced pool: %v", err)
	}
	cfg.Controller.Autoscale.NodePools[0].HostMonthlyCents = 2500
	if registry, err = newSpecRegistry(cfg, ""); err != nil {
		t.Fatal(err)
	}
	if err := registry.validate(set); err != nil {
		t.Fatalf("budget with priced pools: %v", err)
	}
	if registry.budget() != nil {
		t.Fatal("generation 0 has a budget")
	}
	registry.adopt(set, 1)
	if got := registry.budget(); got == nil || *got != *set.Budget {
		t.Fatalf("budget = %+v", got)
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

func withProfile(set cellspec.Spec, profile WorkloadProfile) cellspec.Spec {
	set.Services = []cellspec.Service{{Role: set.Services[0].Role, Profile: profile, Spec: set.Services[0].Spec}}
	return set
}

// A spec may replace the signed TerraBase profile and let trusted signers
// release a service and register its hosts in the spec's environment. The
// cell's rules bound both; which of them a root must sign is the leader's
// admission check (cellspec.AuthorityChanges).
func TestCellSpecTerraBaseSettingsAndReleasers(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	signed := WorkloadProfile{Resources: resources, Env: map[string]string{"TERRABASE_REGION": "gru-1",
		terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{terrabase.Role: signed},
		TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			Roles: []string{terrabase.Role}, Environments: []string{"canary"}}}}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	registry.identity = cellspec.Identity{DeploymentID: "lab-gru", Cell: "gru", Environment: "canary"}
	if len(registry.current.Services) != 0 {
		t.Fatalf("TerraBase joined the generation 0 spec: %+v", registry.current.Services)
	}
	added := signed
	added.Env = maps.Clone(signed.Env)
	added.Env["TERRABASE_AUTH_ISSUER"] = "https://gru.auth.terrascale.tech/terrascale"
	web := cellspec.Service{Role: "web", Profile: WorkloadProfile{Resources: resources}, Releasers: []string{"ops"}}
	set := func(services ...cellspec.Service) cellspec.Spec {
		return cellspec.Spec{Schema: cellspec.Schema, Identity: registry.identity, Generation: 1, RequiresBinary: 1,
			Services: services}
	}
	override := cellspec.Service{Role: terrabase.Role, Profile: added}
	changed, grown := added, signed
	changed.Env = maps.Clone(added.Env)
	changed.Env[terrabase.EnvPeers] = "gru-1-db-1=10.251.0.21:9443,gru-1-db-9=10.251.0.29:9443"
	grown.Resources.CPU = 2
	for name, candidate := range map[string]cellspec.Spec{
		"added TerraBase setting":  set(override, web),
		"changed TerraBase peers":  set(cellspec.Service{Role: terrabase.Role, Profile: changed}),
		"grown TerraBase resource": set(cellspec.Service{Role: terrabase.Role, Profile: grown}),
	} {
		if err := registry.validate(candidate); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	stranger := web
	stranger.Releasers = []string{"intruder"}
	reconciled := cellspec.Service{Role: terrabase.Role, Profile: added, Spec: &workload.ServiceSpec{Role: terrabase.Role,
		Environment: "canary", Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 1}}}
	for name, candidate := range map[string]cellspec.Spec{
		"untrusted releaser":   set(stranger),
		"reconciled TerraBase": set(reconciled),
		"invalid TerraBase":    set(cellspec.Service{Role: terrabase.Role, Profile: withEnv(added, terrabase.EnvPeerPort, "0")}),
		"host-owned setting":   set(cellspec.Service{Role: terrabase.Role, Profile: withEnv(added, terrabase.EnvDataDirectory, "/tmp")}),
		"TerraBase port clash": set(cellspec.Service{Role: terrabase.Role, Profile: withEnv(added, terrabase.EnvClientPort, "9443")}),
	} {
		if err := registry.validate(candidate); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	withoutTerraBase := cfg
	withoutTerraBase.Controller.Workloads = map[string]WorkloadProfile{"web": {Resources: resources}}
	other, err := newSpecRegistry(withoutTerraBase, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.validate(set(override)); err == nil {
		t.Error("a cell without a signed TerraBase profile accepted one from a spec")
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
		t.Fatal("a releaser was authorized before the policy saw the cell spec")
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
		t.Error("an actor the spec does not name may release")
	}
}

func withEnv(profile WorkloadProfile, key, value string) WorkloadProfile {
	profile.Env = maps.Clone(profile.Env)
	profile.Env[key] = value
	return profile
}

// A kv_snapshot schedule needs the signed snapshot location, and the
// uploader reads the adopted spec's interval and pause.
func TestSpecRegistryKVSnapshotSchedule(t *testing.T) {
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	set := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 5,
		KVSnapshot: &cellspec.KVSnapshot{IntervalSeconds: 300}}
	if err := registry.validate(set); err == nil || !strings.Contains(err.Error(), "kv_snapshot location") {
		t.Fatalf("schedule without a signed location: %v", err)
	}
	cfg.Controller.KVSnapshot = kvsnapshot.Config{Enabled: true, Region: "sa-saopaulo-1", Namespace: "ns", Bucket: "kv"}
	if registry, err = newSpecRegistry(cfg, ""); err != nil {
		t.Fatal(err)
	}
	if err := registry.validate(set); err != nil {
		t.Fatalf("schedule with a signed location: %v", err)
	}
	if interval, paused := registry.kvSnapshot(30 * time.Second); interval != 30*time.Second || paused {
		t.Fatalf("generation 0 schedule = %s, %v", interval, paused)
	}
	registry.adopt(set, 1)
	if interval, paused := registry.kvSnapshot(30 * time.Second); interval != 5*time.Minute || paused {
		t.Fatalf("adopted schedule = %s, %v", interval, paused)
	}
	set.Generation, set.KVSnapshot = 2, &cellspec.KVSnapshot{Paused: true}
	registry.adopt(set, 2)
	if interval, paused := registry.kvSnapshot(30 * time.Second); interval != 30*time.Second || !paused {
		t.Fatalf("paused schedule = %s, %v", interval, paused)
	}
}

// Plans compare what is in force: the signed rollout policy (or the default)
// and an empty kv_snapshot schedule are generation 0, so restating them
// changes nothing and dropping a section returns to them.
func TestSpecRegistryPlansAgainstTheSignedSettings(t *testing.T) {
	signed := rollout.DefaultPolicy()
	signed.BatchSize = 1
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{
		Rollouts:   &RolloutsConfig{Enabled: true, Executor: true, Policy: &signed},
		KVSnapshot: kvsnapshot.Config{Enabled: true, Region: "sa-saopaulo-1", Namespace: "ns", Bucket: "kv"}}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	other := rollout.DefaultPolicy()
	spec := func(policy *rollout.Policy, snapshot *cellspec.KVSnapshot) cellspec.Spec {
		return cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 6, RolloutPolicy: policy, KVSnapshot: snapshot}
	}
	for name, test := range map[string]struct {
		current, next      cellspec.Spec
		policy, kvSnapshot string
	}{
		"restate the signed policy": {current: spec(nil, nil), next: spec(&signed, nil)},
		"another policy":            {current: spec(nil, nil), next: spec(&other, nil), policy: "updated"},
		"drop back to the signed":   {current: spec(&other, nil), next: spec(nil, nil), policy: "updated"},
		"drop a restated policy":    {current: spec(&signed, nil), next: spec(nil, nil)},
		"empty schedule":            {current: spec(nil, nil), next: spec(nil, &cellspec.KVSnapshot{})},
		"pause":                     {current: spec(nil, nil), next: spec(nil, &cellspec.KVSnapshot{Paused: true}), kvSnapshot: "updated"},
	} {
		test.next.Generation = 2
		plan, err := cellspec.Diff(registry.withSigned(test.current), registry.withSigned(test.next), nil)
		if err != nil || plan.RolloutPolicy != test.policy || plan.KVSnapshot != test.kvSnapshot {
			t.Errorf("%s: plan = %+v, %v", name, plan, err)
		}
	}
}

// A cell spec terrabase entry needs the signed member CA, without which no
// member gets a certificate, but no signed TerraBase profile: an identity-only
// controller config gets TerraBase's profile as its first cell spec.
func TestSpecRegistryTerraBaseEntryNeedsOnlyTheSignedMemberCA(t *testing.T) {
	profile := staticTerraBaseWorkloads()[terrabase.Role]
	spec := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 1,
		Services: []cellspec.Service{{Role: terrabase.Role, Profile: profile}}}
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}}
	without, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := without.validate(spec); err == nil || !strings.Contains(err.Error(), "member CA") {
		t.Fatalf("terrabase entry without the member CA: %v", err)
	}
	cfg.Controller.TerraBaseCACertFile, cfg.Controller.TerraBaseCAKeyFile = "/material/ca.pem", "/material/ca.key"
	with, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := with.validate(spec); err != nil {
		t.Fatalf("terrabase entry on an identity-only config: %v", err)
	}
	reconciled := spec
	reconciled.Services = []cellspec.Service{{Role: terrabase.Role, Profile: profile,
		Spec: &workload.ServiceSpec{Role: terrabase.Role}}}
	if err := with.validate(reconciled); err == nil {
		t.Fatal("a reconciled terrabase entry was accepted")
	}
}
