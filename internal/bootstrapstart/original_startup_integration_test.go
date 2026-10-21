package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// These boundaries exercise real signatures, a nonempty root chain and secure
// durable files. They do not qualify the fixed production SDK constructor.
func TestOriginalOriginHOMEChainAndRegionalFilesIntegration(t *testing.T) {
	anchor, _, genesis, private, anchorWire := verifiedAnchorFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	home := anchor.Anchor()
	id := trust.ChainIdentity{DeploymentID: home.DeploymentID, Environment: home.Environment, Cell: "gru"}
	start, err := trust.VerifyRootChain(genesis, id, trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := trust.NextRotation(start, private.Public().(ed25519.PublicKey), nextPublic)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	for _, key := range []ed25519.PrivateKey{private, nextPrivate} {
		envelope, err := trust.SignRotation(rotation, id, now.Add(-time.Minute), now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	chainWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}})
	if err != nil {
		t.Fatal(err)
	}
	origin := originalStartupOrigin{SchemaVersion: 1, Cell: oci.RegionSJC, AnchorWire: anchorWire, RootChainWire: chainWire,
		GrantWire: []byte("untrusted transport DATA"), AuthorityWire: []byte("untrusted transport DATA")}
	verified, roots, err := origin.verifyAnchor(genesis, now)
	if err != nil || verified.Digest() != anchor.Digest() || len(roots) != 2 {
		t.Fatalf("genuine HOME rotation boundary: %v", err)
	}
	regional := BakedIdentity{SchemaVersion: 1, DeploymentID: "0000000000NBCYX286D4RHE6ZP", Environment: home.Environment, Cell: oci.RegionSJC}
	if regional.DeploymentID == verified.Anchor().DeploymentID || verified.Anchor().Cell != oci.RegionGRU {
		t.Fatal("fixture did not retain distinct regional and HOME identities")
	}
	if _, err := trust.VerifyRootChain(genesis, regional.ChainIdentity(), trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}}); err == nil {
		t.Fatal("HOME rotation accepted as a regional root chain")
	}
	store, _, _ := bakedFixture(t)
	wire, err := protocol.EncodeJSON(origin)
	if err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(store.directory, OriginalStartupOriginFilename), wire)
	stored, err := store.readOriginalOrigin()
	if err != nil || !bytes.Equal(stored, wire) {
		t.Fatalf("secure companion read: %v", err)
	}
	if err := os.Chmod(filepath.Join(store.directory, OriginalStartupOriginFilename), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readOriginalOrigin(); err == nil {
		t.Fatal("writable companion accepted")
	}
}

func TestOriginalAcceptedRosterDoesNotPromotePinnedTransportIntegration(t *testing.T) {
	accepted, store, markers := acceptedLaunchFixture(t)
	originWire := []byte(`{"schemaVersion":1}`)
	delete(accepted.LaunchMaterialSHA256, OperatorSSHKeyFilename)
	accepted.LaunchMaterialSHA256[OriginalStartupOriginFilename] = digest(originWire)
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(markers.directory, markerName))
	if err != nil {
		t.Fatal(err)
	}
	if err := markers.publishIdentity(accepted, digest(old), func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		return accepted.Broker, accepted.Store, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.directory, OperatorSSHKeyFilename)); err != nil {
		t.Fatal(err)
	}
	writeBakedFixture(t, filepath.Join(store.directory, OriginalStartupOriginFilename), originWire)
	if _, err := store.loadAcceptedHostLaunchMaterialContext(t.Context(), accepted, markers); err == nil {
		t.Fatal("pin and file presence granted original host launch authority")
	}
	if _, _, err := store.loadAcceptedManagedImageMaterialContext(t.Context(), accepted, markers); err == nil {
		t.Fatal("managed image loading skipped companion provenance")
	}
	if _, err := store.load(); err == nil {
		t.Fatal("malformed present origin fell back to ordinary baked startup")
	}
}
