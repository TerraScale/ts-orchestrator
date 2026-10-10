package bootstrapstart

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
	return install, store, verified, inputs, wire, files
}

func TestIdentityRekeyMaterialReplacesOnlyExactOpaquePredecessors(t *testing.T) {
	for _, fault := range []string{"none", "installed", "durable", "symlink", "hardlink", "unverified", "expired"} {
		t.Run(fault, func(t *testing.T) {
			install, store, verified, inputs, wire, files := identityRekeyMaterialFixture(t)
			now := time.Now().UTC()
			before := install.read("ca.pem")
			if err := store.AdoptGeneration(install.target(), install.roots, wire, files, nil, now); err == nil {
				t.Fatal("ordinary adoption admitted opaque predecessor")
			}
			switch fault {
			case "installed":
				install.write(MaterialGenerationsFile, []byte("foreign installed bytes"))
			case "durable":
				if err := os.WriteFile(store.chainCopy, []byte("foreign durable bytes"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(store.chainCopy); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(install.dir, MaterialGenerationsFile), store.chainCopy); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(store.chainCopy, store.chainCopy+".link"); err != nil {
					t.Fatal(err)
				}
			case "unverified":
				verified = VerifiedIdentityRekey{}
			case "expired":
				now = now.Add(2 * time.Hour)
			}
			err := store.AdoptIdentityRekeyGeneration(verified, inputs, files, nil, now)
			if (err == nil) != (fault == "none") {
				t.Fatalf("opaque predecessor %s: %v", fault, err)
			}
			if fault == "none" {
				for _, path := range []string{filepath.Join(install.dir, MaterialGenerationsFile), store.chainCopy} {
					actual, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(actual, wire) {
						t.Fatal("exact rooted target did not replace both copies")
					}
				}
			} else if !bytes.Equal(before, install.read("ca.pem")) || install.staged() {
				t.Fatal("refused predecessor changed material or created a stage")
			}
		})
	}
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
