package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func bakedFixture(t *testing.T) (bakedStore, string, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "bootstrap")
	roots := filepath.Join(directory, "trust-roots")
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyWire := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	writeBakedFixture(t, filepath.Join(roots, "001.pem"), keyWire)
	identityWire, err := protocol.EncodeJSON(BakedIdentity{
		SchemaVersion: 1, DeploymentID: "deployment-a", Environment: "production", Cell: oci.RegionGRU,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(directory, "identity.json"), identityWire)
	now := time.Now().UTC().Truncate(time.Second)
	anchorEnvelope, err := trust.Sign([]byte(`{}`), trust.Scope{
		Domain: "terrascale.bootstrap.anchor", DeploymentID: "deployment-a", Cell: "GRU",
		Environment: "production", Role: "deployment-anchor", Slot: "region",
	}, now, now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(directory, "anchor.json"), anchorWire)
	return bakedStore{directory: directory, ownerUID: uint32(os.Getuid()),
		ownerGID: uint32(os.Getgid()), allowUnsafeAncestors: true}, roots, filepath.Join(directory, "anchor.json")
}

func writeBakedFixture(t *testing.T, path string, wire []byte) {
	t.Helper()
	if err := os.WriteFile(path, wire, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
}

func TestBakedInputsRequireCanonicalRootOwnedPublicFiles(t *testing.T) {
	store, roots, anchorPath := bakedFixture(t)
	loaded, err := store.load()
	if err != nil || len(loaded.Roots) != 1 || loaded.Identity.DeploymentID != "deployment-a" || len(loaded.AnchorWire) == 0 {
		t.Fatalf("load baked public inputs = %+v, %v", loaded.Identity, err)
	}
	if err := os.Chmod(anchorPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(); !errors.Is(err, ErrBakedInputs) {
		t.Fatalf("writable baked anchor = %v, want refusal", err)
	}
	if err := os.Chmod(anchorPath, 0o444); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(filepath.Join(roots, "001.pem"))
	if err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(roots, "002.pem"), wire)
	if _, err := store.load(); err == nil {
		t.Fatal("accepted two root files with the same key ID")
	}
}

func TestBakedInputsRejectSymlinkAndUnknownRootEntry(t *testing.T) {
	store, roots, anchorPath := bakedFixture(t)
	anchorWire, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("identity.json", anchorPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(); err == nil {
		t.Fatal("followed baked anchor symlink")
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, anchorPath, []byte(`{}`))
	if _, err := store.load(); err == nil {
		t.Fatal("accepted unsigned baked anchor")
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, anchorPath, anchorWire)
	if err := os.WriteFile(filepath.Join(roots, "notes.txt"), []byte("unexpected"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(); err == nil {
		t.Fatal("accepted unknown trust-root directory entry")
	}
}
