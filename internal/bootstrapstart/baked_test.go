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

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
