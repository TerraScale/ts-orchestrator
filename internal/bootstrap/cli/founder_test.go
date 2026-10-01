package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestSignFounderSelectionPublishesOnlyPinnedReadOnlyProofs(t *testing.T) {
	fixture := newManifestFixture(t, 24*time.Hour, 24*time.Hour)
	identity := bootstrapstart.BakedIdentity{SchemaVersion: 1, DeploymentID: fixture.anchor.DeploymentID,
		Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell}
	identityWire, err := protocol.EncodeJSON(identity)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(fixture.directory, "founder-identity.json")
	writeFixture(t, identityPath, identityWire, 0o644)
	material := map[string]string{"controller.creds": strings.Repeat("a", 64)}
	credentialDigest, err := bootstrap.InstallContinuityCredentialDigest(material)
	if err != nil {
		t.Fatal(err)
	}
	pins := make([]bootstrapstart.FounderContinuityPin, 0, 3)
	proofPaths := make([]string, 0, 3)
	for _, slot := range []string{"controller-a", "controller-b", "seed-a"} {
		claim := bootstrap.InstallContinuity{SchemaVersion: bootstrap.InstallContinuitySchemaVersion,
			DeploymentID: identity.DeploymentID, Environment: identity.Environment,
			ClusterID: fixture.anchor.ClusterID, Cell: identity.Cell, OCIRegion: fixture.anchor.OCIRegion,
			Slot: slot, GenesisAnchorSHA256: strings.Repeat("a", 64),
			AcceptedMarkerSHA256: strings.Repeat("b", 64), ManifestSHA256: strings.Repeat("c", 64),
			ResultSHA256: strings.Repeat("d", 64), ReceiptSHA256: strings.Repeat("e", 64),
			ImageReceiptSHA256: strings.Repeat("f", 64),
			ImageOCID:          "ocid1.image.oc1.sa-saopaulo-1.example",
			InstanceOCID:       "ocid1.instance.oc1.sa-saopaulo-1.example",
			PrimaryVNICOCID:    "ocid1.vnic.oc1.sa-saopaulo-1.example", PrimaryPrivateIP: "10.0.0.3",
			LedgerAttempt: 1, LedgerGeneration: 1, AcceptedAt: fixture.now.Add(-time.Hour),
			BinarySHA256: strings.Repeat("1", 64), MaterialSHA256: material,
			CredentialSHA256: credentialDigest, CredentialValidUntil: fixture.now.Add(2 * time.Hour),
			SelectorGeneration: 2}
		envelope, err := bootstrap.SignInstallContinuity(claim, fixture.now, fixture.now.Add(time.Hour), fixture.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(wire)
		pins = append(pins, bootstrapstart.FounderContinuityPin{Slot: slot, SHA256: hex.EncodeToString(digest[:])})
		path := filepath.Join(fixture.directory, slot+".continuity.json")
		writeFixture(t, path, wire, 0o644)
		proofPaths = append(proofPaths, path)
	}
	selection := bootstrapstart.FounderSelection{SchemaVersion: 2, DeploymentID: identity.DeploymentID,
		Cell: string(identity.Cell), Environment: identity.Environment, Generation: 2, Continuities: pins}
	candidateWire, err := protocol.EncodeJSON(selection)
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(fixture.directory, "continuity-selection.candidate.json")
	writeFixture(t, candidatePath, candidateWire, 0o644)
	outputPath := filepath.Join(fixture.directory, "continuity-selection.signed.json")
	args := []string{"sign-founder-selection", "--candidate", candidatePath, "--identity", identityPath,
		"--root-key", fixture.rootPath, "--signing-key", fixture.privatePath, "--out", outputPath,
		"--valid-for", "1h"}
	for _, path := range proofPaths {
		args = append(args, "--proof", path)
	}
	if err := runAt(args, fixture.now); err != nil {
		t.Fatal(err)
	}
	signedWire, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.DecodeEnvelope(signedWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.VerifyCurrent(signed, trust.Scope{Domain: bootstrapstart.FounderSelectionDomain,
		DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment,
		Role: "deployment-anchor", Slot: "region"}, fixture.roots, fixture.now,
		bootstrap.BootstrapAnchorTrustPolicy()); err != nil {
		t.Fatalf("CLI did not create a current root-signed selector: %v", err)
	}
	selection.Continuities[0].SHA256 = strings.Repeat("0", 64)
	badWire, err := protocol.EncodeJSON(selection)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, candidatePath, badWire, 0o644)
	args[0] = "sign-founder-selection"
	args[10] = filepath.Join(fixture.directory, "bad-selection.signed.json")
	if err := runAt(args, fixture.now); err == nil {
		t.Fatal("CLI signed selector with a continuity pin that differed from the supplied proof")
	}
}
