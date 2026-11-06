package bootstrapstart

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

func identityRekeyMaterialFixture(t *testing.T) (*generationInstall, MaterialStore, VerifiedIdentityRekey, TrustInputs, []byte, map[string][]byte) {
	t.Helper()
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	accepted := install.accepted.Clone()
	accepted.MaterialGenerationSHA256, err = trust.Fingerprint(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	accepted.Broker.AccountSigner = generation.AccountSigner
	refs := materialReferences(accepted, nil)
	for _, reference := range generation.Secrets {
		refs[reference.TargetFile] = reference
	}
	accepted.MaterialReferences = nil
	for reference := range maps.Values(refs) {
		accepted.MaterialReferences = append(accepted.MaterialReferences, reference)
	}
	checkpoint, _, _ := acceptedCheckpoint(t, accepted, []byte("opaque previous acceptance"))
	checkpoint.MaterialGenerationSHA256 = accepted.MaterialGenerationSHA256
	checkpoint.Slots[0].MaterialReferences = accepted.MaterialReferences
	journal, inputs, accepted := identityRekeyJournalForCheckpoint(t, accepted, []byte("opaque previous acceptance"), checkpoint, install.rootKey, install.roots)
	initial, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	journal.Values[2] = wire
	envelope, err := initial.ResetEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	reset := initial.Reset()
	reset.Records[2].SHA256 = digest(wire)
	envelope, err = authority.SignIdentityReset(reset, envelope.IssuedAt, envelope.ExpiresAt, install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	journal.ResetWire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	store := install.store()
	copyDir := t.TempDir()
	if err := os.Chmod(copyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	store.chainCopy = filepath.Join(copyDir, MaterialGenerationsFile)
	old := []byte("old material chain")
	install.write(MaterialGenerationsFile, old)
	if err := os.WriteFile(store.chainCopy, old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.chainCopy, 0o644); err != nil {
		t.Fatal(err)
	}
	return install, store, verified, inputs, wire, files
}

func TestIdentityRekeyMaterialRecoversAfterDurableCopyAndPartialRename(t *testing.T) {
	install, store, verified, inputs, wire, files := identityRekeyMaterialFixture(t)
	stagePath := filepath.Join(install.dir, generationStaging)
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := unix.Open(stagePath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stage)
	for name, content := range files {
		if err := store.writeStaged(stage, name, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.writeStaged(stage, MaterialGenerationsFile, wire); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.chainCopy, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.chainCopy, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(stagePath, "ca.pem"), filepath.Join(install.dir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.FinishIdentityRekeyMaterialAdoption(verified, inputs, install.configPath, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if install.staged() || !bytes.Equal(install.read(MaterialGenerationsFile), wire) {
		t.Fatal("recovery did not finish the exact rooted target")
	}
}
