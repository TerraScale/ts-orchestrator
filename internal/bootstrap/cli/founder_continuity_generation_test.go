package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// An install that adopted a material generation gets a continuity proof
// bound to the newest generation, valid until it expires: the owner renders
// and signs it from the chain instead of the marker-pinned files.
func TestFounderContinuityBindsTheAdoptedGeneration(t *testing.T) {
	fixture := newManifestFixture(t, 30*24*time.Hour, 30*24*time.Hour)
	anchorWire, err := os.ReadFile(fixture.anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	marker := bootstrapstart.AcceptedInstall{SchemaVersion: 1, AnchorSHA256: digest(anchorWire),
		ManifestSHA256: strings.Repeat("1", 64), ReceiptSHA256: strings.Repeat("2", 64),
		ImageReceiptSHA256: strings.Repeat("3", 64), DeploymentID: "deployment-a", Cell: "GRU", Slot: "seed-a",
		SeedSlot: "seed-a", ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image",
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance", PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.vnic",
		PrimaryPrivateIP: "10.0.1.10", HeadAttempt: 1, HeadGeneration: 1, ResultSHA256: strings.Repeat("4", 64),
		BinarySHA256: strings.Repeat("5", 64), MaterialSHA256: map[string]string{"seed-a.creds": strings.Repeat("6", 64)},
		AcceptedAt: fixture.now}
	markerWire, err := protocol.EncodeJSON(marker)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(fixture.directory, "marker.json")
	writeFixture(t, markerPath, markerWire, 0o600)
	expected := bootstrap.MaterialGenerationExpectation{DeploymentID: "deployment-a", Environment: "production",
		ClusterID: "cluster-a", Cell: "GRU", ControllerSlots: []string{"seed-a"}}
	material := generationtest.New(t, fixture.now)
	writeChain := func(name string, key ed25519.PrivateKey) (string, time.Time, string) {
		t.Helper()
		envelope, err := bootstrap.SignMaterialGeneration(material.Generation(expected, 1, ""), fixture.now,
			fixture.now.AddDate(0, 6, 0), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixture.directory, name)
		writeFixture(t, path, wire, 0o600)
		fingerprint, _ := trust.Fingerprint(envelope)
		return path, envelope.ExpiresAt, fingerprint
	}
	chainPath, generationExpiry, fingerprint := writeChain("generations.json", fixture.rootPrivate)

	candidatePath := filepath.Join(fixture.directory, "continuity.json")
	if err := renderFounderContinuityAt([]string{"--marker", markerPath, "--anchor", fixture.anchorPath,
		"--material-generations", chainPath, "--selector-generation", "2", "--out", candidatePath}); err != nil {
		t.Fatal(err)
	}
	candidateWire, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	var candidate bootstrap.InstallContinuity
	if err := protocol.DecodeStrict(candidateWire, &candidate, bootstrap.MaxInstallContinuityBytes); err != nil {
		t.Fatal(err)
	}
	want, _ := bootstrap.InstallContinuityGenerationDigest(fingerprint)
	if candidate.CredentialSHA256 != want || !candidate.CredentialValidUntil.Equal(generationExpiry) {
		t.Fatalf("candidate binds %s until %s, want the generation %s until %s", candidate.CredentialSHA256,
			candidate.CredentialValidUntil, want, generationExpiry)
	}
	sign := func(candidate, chain, out string) error {
		args := []string{"--candidate", candidate, "--marker", markerPath, "--anchor", fixture.anchorPath,
			"--root-key", fixture.rootPath, "--signing-key", fixture.privatePath, "--out", out}
		if chain != "" {
			args = append(args, "--material-generations", chain)
		}
		return signFounderContinuityAt(args, fixture.now)
	}
	_, otherRoot, _ := ed25519.GenerateKey(rand.Reader)
	strangerChain, _, _ := writeChain("stranger-generations.json", otherRoot)
	longer := candidate
	longer.CredentialValidUntil = generationExpiry.Add(24 * time.Hour)
	longerWire, _ := protocol.EncodeJSON(longer)
	longerPath := filepath.Join(fixture.directory, "longer.json")
	writeFixture(t, longerPath, longerWire, 0o600)
	refused := filepath.Join(fixture.directory, "refused.json")
	for name, args := range map[string][2]string{
		"a generation candidate signed as manifest material": {candidatePath, ""},
		"a chain from an untrusted root":                     {candidatePath, strangerChain},
		"a proof outliving the generation":                   {longerPath, chainPath},
	} {
		if err := sign(args[0], args[1], refused); err == nil {
			t.Errorf("signed %s", name)
		}
	}
	signed := filepath.Join(fixture.directory, "continuity.signed.json")
	if err := sign(candidatePath, chainPath, signed); err != nil {
		t.Fatal(err)
	}
	if err := renderFounderContinuityAt([]string{"--marker", markerPath, "--anchor", fixture.anchorPath,
		"--material-directory", fixture.directory, "--material-generations", chainPath,
		"--selector-generation", "2", "--out", filepath.Join(fixture.directory, "both.json")}); err == nil {
		t.Fatal("rendered from both the material and the generations")
	}
}
