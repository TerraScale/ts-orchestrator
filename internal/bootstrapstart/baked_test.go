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
		SchemaVersion: 1, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", Cell: oci.RegionGRU,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(directory, "identity.json"), identityWire)
	now := time.Now().UTC().Truncate(time.Second)
	anchorEnvelope, err := trust.Sign([]byte(`{}`), trust.Scope{
		Domain: "terrascale.bootstrap.anchor", DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU",
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
	if err != nil || len(loaded.Roots) != 1 || loaded.Identity.DeploymentID != "0000000000F9PR1WNVDTEXS31Z" || len(loaded.AnchorWire) == 0 {
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

// The baked roots are only the genesis of the root chain the controller
// adopted: records signed by a rotated root verify without a rebuild, and a
// damaged or foreign chain fails closed instead of falling back to genesis.
func TestBakedInputsExtendGenesisWithTheAdoptedRootChain(t *testing.T) {
	store, roots, _ := bakedFixture(t)
	genesisPublic, genesisPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(genesisPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(roots, "001.pem")); err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(roots, "001.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	store.chainFile = filepath.Join(t.TempDir(), "root-chain.json")
	loaded, err := store.load()
	if err != nil || len(loaded.Roots) != 1 || len(loaded.Genesis) != 1 || len(loaded.Chain.Rotations) != 0 {
		t.Fatalf("without an adopted chain: %+v, %v", loaded.Roots, err)
	}

	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signChain := func(id trust.ChainIdentity) []byte {
		start, err := trust.VerifyRootChain(loaded.Genesis, id, trust.RootChain{})
		if err != nil {
			t.Fatal(err)
		}
		rotation, err := trust.NextRotation(start, nextPublic)
		if err != nil {
			t.Fatal(err)
		}
		var signed trust.SignedRotation
		now := time.Now().UTC().Truncate(time.Second)
		for _, key := range []ed25519.PrivateKey{genesisPrivate, nextPrivate} {
			envelope, err := trust.SignRotation(rotation, id, now, now.Add(time.Hour), key)
			if err != nil {
				t.Fatal(err)
			}
			signed.Signatures = append(signed.Signatures, envelope)
		}
		wire, err := trust.EncodeRootChain(trust.RootChain{Rotations: []trust.SignedRotation{signed}})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	if err := os.WriteFile(store.chainFile, signChain(loaded.Identity.ChainIdentity()), 0o600); err != nil {
		t.Fatal(err)
	}
	extended, err := store.load()
	nextID, _ := trust.KeyID(nextPublic)
	if err != nil || len(extended.Roots) != 2 || extended.Roots[nextID] == nil || len(extended.Genesis) != 1 ||
		len(extended.Chain.Rotations) != 1 {
		t.Fatalf("with an adopted chain: %+v, %v", extended.Roots, err)
	}

	foreign := loaded.Identity.ChainIdentity()
	foreign.Cell = "sfo"
	for name, wire := range map[string][]byte{"another cell's chain": signChain(foreign), "damaged chain": []byte("{")} {
		if err := os.WriteFile(store.chainFile, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.load(); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
