package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

func TestTrustInputsDoNotReadRetiredIdentityOrAnchor(t *testing.T) {
	accepted := acceptedIdentityFixture(t)
	store, _, _ := bakedFixture(t)
	for _, name := range []string{"identity.json", "anchor.json"} {
		if err := os.Remove(filepath.Join(store.directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := store.loadTrustInputs(accepted)
	if err != nil || len(loaded.Genesis) != 1 || len(loaded.Roots.Current) != 1 || len(loaded.Chain.Rotations) != 0 ||
		loaded.ChainIdentity != (trust.ChainIdentity{DeploymentID: accepted.DeploymentID, Cell: "gru", Environment: accepted.Environment}) {
		t.Fatalf("roots without old files: %+v, %v", loaded, err)
	}
	for _, name := range []string{"identity.json", "anchor.json"} {
		if err := os.Symlink("unreadable-retired-proof", filepath.Join(store.directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.loadTrustInputs(accepted); err != nil {
		t.Fatalf("read retired symlink: %v", err)
	}
	invalid := accepted.Clone()
	invalid.DeploymentID = "obsolete-deployment"
	if _, err := store.loadTrustInputs(invalid); err == nil {
		t.Fatal("noncanonical accepted deployment selected roots")
	}
}

func TestTrustInputsNonemptyChainRequiresAcceptedDeploymentLineage(t *testing.T) {
	accepted := acceptedIdentityFixture(t)
	store, rootDir, _ := bakedFixture(t)
	genesisPublic, genesisPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(genesisPublic)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(rootDir, "001.pem")
	if err := os.Remove(rootPath); err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	loaded, err := store.loadTrustInputs(accepted)
	if err != nil {
		t.Fatal(err)
	}
	currentPublic, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chainWire := func(id trust.ChainIdentity) []byte {
		t.Helper()
		initial, err := trust.VerifyRootChain(loaded.Genesis, id, trust.RootChain{Version: 1})
		if err != nil {
			t.Fatal(err)
		}
		rotation, err := trust.NextRotation(initial, currentPublic)
		if err != nil {
			t.Fatal(err)
		}
		var signed trust.SignedRotation
		for _, private := range []ed25519.PrivateKey{genesisPrivate, currentPrivate} {
			envelope, err := trust.SignRotation(rotation, id, accepted.AcceptedAt.Add(-time.Hour), accepted.AcceptedAt.Add(time.Hour), private)
			if err != nil {
				t.Fatal(err)
			}
			signed.Signatures = append(signed.Signatures, envelope)
		}
		wire, err := trust.EncodeRootChain(trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	store.chainFile = filepath.Join(t.TempDir(), "root-chain.json")
	if err := os.WriteFile(store.chainFile, chainWire(loaded.ChainIdentity), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.loadTrustInputs(accepted)
	currentID, _ := trust.KeyID(currentPublic)
	genesisID, _ := trust.KeyID(genesisPublic)
	if err != nil || rotated.Roots.Sequence != 1 || rotated.Roots.Current[currentID] == nil || rotated.Roots.Current[genesisID] != nil ||
		len(rotated.Roots.Historical) != 2 || len(rotated.Genesis) != 1 {
		t.Fatalf("rotated lineage: %+v, %v", rotated.Roots, err)
	}
	for _, field := range []string{"deployment", "cell", "environment", "uppercase cell", "damaged"} {
		t.Run(field, func(t *testing.T) {
			id := loaded.ChainIdentity
			switch field {
			case "deployment":
				id.DeploymentID = entityid.Derive("retired-deployment")
			case "cell":
				id.Cell = "sfo"
			case "environment":
				id.Environment = "production"
			case "uppercase cell":
				id.Cell = "GRU"
			}
			wire := chainWire(id)
			if field == "damaged" {
				wire = []byte(`{"rotations":[`)
			}
			if err := os.WriteFile(store.chainFile, wire, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.loadTrustInputs(accepted); err == nil {
				t.Fatal("foreign/damaged chain fell back to genesis")
			}
		})
	}
}

func TestTrustInputsRejectUnsafeGenesisFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "directory symlink", "mode", "hardlink", "owner", "unknown entry"} {
		t.Run(kind, func(t *testing.T) {
			accepted := acceptedIdentityFixture(t)
			store, rootDir, _ := bakedFixture(t)
			path := filepath.Join(rootDir, "001.pem")
			var err error
			switch kind {
			case "symlink":
				err = os.Rename(path, filepath.Join(store.directory, "root.pem"))
				if err == nil {
					err = os.Symlink(filepath.Join(store.directory, "root.pem"), path)
				}
			case "directory symlink":
				err = os.Rename(rootDir, rootDir+".original")
				if err == nil {
					err = os.Symlink(rootDir+".original", rootDir)
				}
			case "mode":
				err = os.Chmod(path, 0o644)
			case "hardlink":
				err = os.Link(path, filepath.Join(store.directory, "linked.pem"))
			case "owner":
				store.ownerUID++
			case "unknown entry":
				err = os.WriteFile(filepath.Join(rootDir, "identity.json"), []byte(`{}`), 0o444)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.loadTrustInputs(accepted); err == nil {
				t.Fatal("unsafe genesis loaded")
			}
		})
	}
}

func TestTrustInputsRejectIndirectOrWritableAdoptedChain(t *testing.T) {
	for _, kind := range []string{"symlink", "parent symlink", "writable", "special mode", "hardlink", "FIFO"} {
		t.Run(kind, func(t *testing.T) {
			accepted := acceptedIdentityFixture(t)
			store, _, _ := bakedFixture(t)
			directory := filepath.Join(t.TempDir(), "trust")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			store.chainFile = filepath.Join(directory, "root-chain.json")
			wire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.chainFile, wire, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				err = os.Rename(store.chainFile, store.chainFile+".original")
				if err == nil {
					err = os.Symlink(store.chainFile+".original", store.chainFile)
				}
			case "parent symlink":
				err = os.Symlink(directory, directory+".link")
				store.chainFile = filepath.Join(directory+".link", "root-chain.json")
			case "writable":
				err = os.Chmod(store.chainFile, 0o666)
			case "special mode":
				err = unix.Chmod(store.chainFile, 0o4600)
			case "hardlink":
				err = os.Link(store.chainFile, store.chainFile+".link")
			case "FIFO":
				err = os.Remove(store.chainFile)
				if err == nil {
					err = unix.Mkfifo(store.chainFile, 0o600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.loadTrustInputs(accepted); err == nil {
				t.Fatal("unsafe chain loaded")
			}
		})
	}
}
