package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
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

func authorityTestSpecTrust(t *testing.T, dir, cell string) *SpecTrustConfig {
	t.Helper()
	return newTestSpecTrust(t, dir, cellspec.Identity{
		DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Cell: cell, Environment: "test",
	}).config()
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

func TestSpecRegistryStartupRefusesRetiredStoredPolicy(t *testing.T) {
	dir := t.TempDir()
	keys := newTestSpecTrust(t, dir, cellspec.Identity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "test"})
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{SpecTrust: keys.config()}}
	newAcceptedSpecTrust(t, &cfg)
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	js := testRolloutJetStream(t)
	if err := registry.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	spec := cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: 1, RequiresBinary: 1,
		Services: []cellspec.Service{}}
	payload, err := cellspec.Encode(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"rollout_policy":{}}`)...)
	now := time.Now()
	envelope, err := trust.Sign(payload, keys.identity.Scope(), now, now.Add(time.Hour), keys.root)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(cellspec.Signed{Spec: signed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.kv.Put(t.Context(), cellSpecKey, wire); err != nil {
		t.Fatal(err)
	}
	restarted, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.open(t.Context(), js, 1); err == nil || !strings.Contains(err.Error(), "rollout_policy") {
		t.Fatalf("startup discarded the stored policy and used bootstrap settings: %v", err)
	}
}

// The generation 0 set is the signed config's generic workloads; TerraBase
// stays with placement, and explicit signed service policies reconcile.
func TestSpecRegistryBaselineFromSignedConfig(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	spec := workload.ServiceSpec{Role: "web", Environment: "test", Kind: workload.KindStateless,
		Replicas: workload.ReplicaBounds{Min: 1, Max: 2}}
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}, "web": {Resources: resources}},
		Autoscale: &AutoscaleConfig{Services: []workload.ServiceSpec{spec}}}}
	newAcceptedSpecTrust(t, &cfg)
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	profiles, specs := registry.effective()
	if len(registry.current.Services) != 1 || registry.current.Services[0].Role != "web" || registry.current.Generation != 0 ||
		len(specs) != 1 || specs[0].Role != "web" || len(profiles) != 2 {
		t.Fatalf("baseline %+v, profiles %v, specs %v", registry.current, profiles, specs)
	}
	cfg.Controller.Autoscale = nil
	if registry, err = newSpecRegistry(cfg, ""); err != nil {
		t.Fatal(err)
	}
	if _, specs := registry.effective(); len(specs) != 0 {
		t.Fatalf("an absent autoscale declaration reconciles %v", specs)
	}
	if registry.roots == nil || len(registry.roots.current()) == 0 {
		t.Fatal("accepted image roots are missing")
	}
	if _, err := registry.verify([]byte("{}"), nil); err == nil {
		t.Fatal("accepted image roots verified an unsigned spec")
	}
	cfg.Controller.SpecTrust = &SpecTrustConfig{}
	if _, err := newSpecRegistry(cfg, ""); err == nil || !strings.Contains(err.Error(), "image trust roots") {
		t.Fatalf("a production controller accepted local spec trust: %v", err)
	}
}

// Grants name roles the cell delivers, never TerraBase, placement's member
// role or a listed TerraBase member.
func TestSpecRegistryValidatesHostGrants(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{terrabase.Role: {Resources: resources, Env: map[string]string{
			terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.251.0.21:9443"}}}}}
	newAcceptedSpecTrust(t, &cfg)
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
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{
		Workloads: map[string]WorkloadProfile{terrabase.Role: signed},
		TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			Roles: []string{terrabase.Role}, Environments: []string{"canary"}}}}}
	newAcceptedSpecTrust(t, &cfg)
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	registry.identity = cellspec.Identity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "canary"}
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

// A cell spec terrabase entry needs the signed member CA, without which no
// member gets a certificate, but no signed TerraBase profile: an identity-only
// controller config gets TerraBase's profile as its first cell spec.
func TestSpecRegistryTerraBaseEntryNeedsOnlyTheSignedMemberCA(t *testing.T) {
	profile := staticTerraBaseWorkloads()[terrabase.Role]
	spec := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 1,
		Services: []cellspec.Service{{Role: terrabase.Role, Profile: profile}}}
	cfg := Config{NATS: natscell.Config{Cell: "gru"}}
	newAcceptedSpecTrust(t, &cfg)
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
