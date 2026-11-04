package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
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

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
