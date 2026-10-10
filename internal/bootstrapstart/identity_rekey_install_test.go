package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func rootInstallerFixture(t *testing.T) (MarkerStore, bakedStore, IdentityRekeyJournal, TrustInputs, AcceptedIdentity) {
	t.Helper()
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	markers := testMarkerStore(t)
	if err := os.WriteFile(filepath.Join(markers.directory, markerName), []byte("obsolete identity bytes are opaque"), 0o644); err != nil {
		t.Fatal(err)
	}
	baked, rootDirectory, _ := bakedFixture(t)
	for _, key := range inputs.Genesis {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		rootPath := filepath.Join(rootDirectory, "001.pem")
		if err := os.Remove(rootPath); err != nil {
			t.Fatal(err)
		}
		writeBakedFixture(t, rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	// Retired inputs cannot authorize the proposed target, even when damaged.
	for _, name := range []string{identityFilename, anchorFilename} {
		if err := os.Remove(filepath.Join(baked.directory, name)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("absent-retired-authority", filepath.Join(baked.directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	return markers, baked, journal, inputs, accepted
}

func TestRootInstallerRejectsWrongCurrentProofAndTargetBeforeEffects(t *testing.T) {
	for _, fault := range []string{"root", "target", "checkpoint", "handoff", "reset", "expired", "predecessor"} {
		t.Run(fault, func(t *testing.T) {
			markers, baked, journal, _, accepted := rootInstallerFixture(t)
			now := accepted.AcceptedAt
			switch fault {
			case "root":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKIXPublicKey(public)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(baked.directory, "trust-roots", "001.pem")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				writeBakedFixture(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			case "target":
				accepted.PrimaryPrivateIP = "10.251.0.19"
				accepted.ControllerBindings[0].PrimaryPrivateIP = accepted.PrimaryPrivateIP
				journal.AcceptedWire, _ = EncodeAcceptedIdentity(accepted)
			case "checkpoint":
				journal.CheckpointWire[len(journal.CheckpointWire)/2] ^= 1
			case "handoff":
				journal.HostObservation.Epoch++
			case "reset":
				journal.Values[0][0] ^= 1
			case "expired":
				now = now.Add(2 * time.Hour)
			case "predecessor":
				if err := os.WriteFile(filepath.Join(markers.directory, markerName), []byte("changed predecessor"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(markers.directory, markerName))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, now, false); err == nil {
				t.Fatal("invalid proposal was admitted")
			}
			after, err := os.ReadFile(filepath.Join(markers.directory, markerName))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused proposal changed its predecessor")
			}
			if _, err := os.Stat(filepath.Join(markers.directory, identityRekeyJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("verification created recovery state")
			}
		})
	}
}

func TestRootInstallerInterruptedOperationResumesOnlyExactJournal(t *testing.T) {
	markers, baked, journal, _, accepted := rootInstallerFixture(t)
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unstaged proposal admitted external precommit: %v", err)
	}
	verified, inputs, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := markers.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); err != nil {
			t.Fatalf("interrupted exact operation did not resume: %v", err)
		}
	}
	changed := journal
	changed.AcceptedWire = bytes.Clone(journal.AcceptedWire)
	other := accepted.Clone()
	other.AcceptedAt = other.AcceptedAt.Add(time.Second)
	changed.AcceptedWire, err = EncodeAcceptedIdentity(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, changed, other.AcceptedAt, true); !errors.Is(err, ErrIdentityRekeyJournal) {
		t.Fatalf("another valid projection replaced the immutable operation: %v", err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt.Add(2*time.Hour), true); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired operation resumed effects: %v", err)
	}
	if err := markers.ReplaceIdentity(verified.Checkpoint(), accepted.Slot, accepted.AcceptedAt, acceptedObservation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); err != nil {
		t.Fatalf("retry after local commit failed: %v", err)
	}
	if err := os.Remove(filepath.Join(markers.directory, identityRekeyJournalName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false); !errors.Is(err, ErrAcceptancePredecessor) {
		t.Fatalf("accepted bytes without their journal fabricated a retry: %v", err)
	}
}

func TestRootInstallerChangedPhysicalStoreCannotPublishJournalOrAcceptance(t *testing.T) {
	for _, pin := range []string{"server-name", "node-identity.json"} {
		t.Run(pin, func(t *testing.T) {
			markers, baked, journal, _, accepted := rootInstallerFixture(t)
			verified, inputs, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(accepted.Store.Directory, pin), []byte("changed existing store"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := markers.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err == nil {
				t.Fatal("changed physical store authorized durable journal")
			}
			if err := markers.ReplaceIdentity(verified.Checkpoint(), accepted.Slot, accepted.AcceptedAt, acceptedObservation); err == nil {
				t.Fatal("changed physical store authorized accepted publication")
			}
			wire, err := os.ReadFile(filepath.Join(markers.directory, markerName))
			if err != nil || string(wire) != "obsolete identity bytes are opaque" {
				t.Fatal("store refusal changed the predecessor")
			}
		})
	}
}

func TestRootInstallerRecomputesInstalledChainInsteadOfTrustingExportedRoots(t *testing.T) {
	markers, baked, journal, inputs, accepted := rootInstallerFixture(t)
	for _, key := range inputs.Roots.Current {
		key[0] ^= 1
	}
	verified, loaded, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false)
	if err != nil || !verified.IsVerified() || trust.RootSetDigest(loaded.Genesis) != journal.GenesisSHA256 {
		t.Fatalf("exported roots replaced fixed genesis: %v", err)
	}
	baked.chainFile = filepath.Join(t.TempDir(), "root-chain.json")
	if err := os.WriteFile(baked.chainFile, []byte(`{"rotations":[{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false); err == nil {
		t.Fatal("damaged adopted chain fell back to empty/genesis")
	}
}

func TestRootInstallerLocalObservationIsIndependent(t *testing.T) {
	markers, baked, journal, _, accepted := rootInstallerFixture(t)
	_, inputs, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	observe := func(identity AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		identity.Broker.HostSigner = acceptedPublicKey(t, false)
		return identity.Broker, identity.Store, nil
	}
	if err := markers.WriteIdentityRekeyJournal(journal, inputs, observe, accepted.AcceptedAt); err == nil {
		t.Fatal("signed pins substituted for an independent actual broker")
	}
	if _, err := os.Stat(filepath.Join(markers.directory, identityRekeyJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong broker created recovery state")
	}
	// Exact canonical journal bytes are mandatory, even with valid signatures.
	wire, err := protocol.EncodeJSON(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markers.directory, identityRekeyJournalName), append(wire, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyIdentityRekeyInstall(markers, baked, journal, accepted.AcceptedAt, true); err == nil {
		t.Fatal("noncanonical root journal admitted precommit")
	}
}

func TestRootInstallerAdoptionRequiresExactInterruptedMaterial(t *testing.T) {
	for _, fault := range []string{"exact partial", "truncated partial", "empty partial", "chain write interrupted", "symlink", "unrelated", "exact committed", "wrong committed", "signed successor"} {
		t.Run(fault, func(t *testing.T) {
			staged := newSpooledInstall(t)
			target := staged.installer.target
			target.MaterialGenerationSHA256 = staged.fingerprint
			store := staged.installer.store
			before := staged.read("ca.pem")
			switch fault {
			case "exact partial":
				staged.stage(map[string][]byte{"ca.pem": staged.files["ca.pem"]})
			case "truncated partial", "empty partial", "chain write interrupted", "symlink":
				staged.stage(map[string][]byte{"ca.pem": staged.files["ca.pem"]})
				path := filepath.Join(store.installedDirectory, generationStaging, "ca.pem")
				if fault == "symlink" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("../ca.pem", path); err != nil {
						t.Fatal(err)
					}
				} else {
					wire := []byte("partial write")
					if fault == "empty partial" {
						wire = nil
					}
					if fault == "chain write interrupted" {
						path = filepath.Join(filepath.Dir(path), generationChainTemporary)
					}
					if err := os.WriteFile(path, wire, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "unrelated":
				staged.stage(map[string][]byte{"offline.seed": []byte("must remain")})
			case "exact committed":
				staged.stage(staged.files)
				staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
			case "wrong committed":
				staged.stage(staged.files)
				staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire, "ca.pem": []byte("partial write after commit")})
			case "signed successor":
				chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
				if err != nil {
					t.Fatal(err)
				}
				generation, err := bootstrap.MaterialGenerationPayload(chain[0])
				if err != nil {
					t.Fatal(err)
				}
				generation.Generation, generation.Previous = 2, staged.fingerprint
				envelope, err := bootstrap.SignMaterialGeneration(generation, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), staged.rootKey)
				if err != nil {
					t.Fatal(err)
				}
				chain = append(chain, envelope)
				if _, err := target.VerifyChain(chain, staged.roots, time.Now()); err != nil {
					t.Fatalf("fixture successor is not valid ordinary renewal: %v", err)
				}
				wire, err := bootstrap.EncodeMaterialGenerationChain(chain)
				if err != nil {
					t.Fatal(err)
				}
				staged.stage(map[string][]byte{MaterialGenerationsFile: wire})
			}
			err := store.VerifyIdentityRekeyMaterialAdoption(target, staged.roots, staged.wire, time.Now())
			wantValid := fault == "exact partial" || fault == "exact committed" || fault == "truncated partial" || fault == "empty partial" || fault == "chain write interrupted"
			if (err == nil) != wantValid {
				t.Fatalf("exact-operation stage admission = %v, want valid %t", err, wantValid)
			}
			if !staged.staged() || !bytes.Equal(before, staged.read("ca.pem")) {
				t.Fatal("readonly recovery verification changed material or deleted its stage")
			}
			if wantValid && fault != "exact committed" {
				if err := store.FinishMaterialAdoption(target, staged.roots, staged.installer.config, time.Now()); err != nil {
					t.Fatal(err)
				}
				if staged.staged() || !bytes.Equal(before, staged.read("ca.pem")) {
					t.Fatal("incomplete stage was not safely discarded")
				}
				staged.arm()
				if outcome := staged.install(); outcome != "installed generation 1" {
					t.Fatalf("retry after interrupted write: %s", outcome)
				}
			}
		})
	}
}

func TestRootInstallerInstalledMaterialBindsConfigAndRecoversExactChain(t *testing.T) {
	for _, fault := range []string{"complete", "interrupted rename", "config", "material", "successor"} {
		t.Run(fault, func(t *testing.T) {
			staged := newSpooledInstall(t)
			accepted := staged.accepted.Clone()
			accepted.MaterialGenerationSHA256 = staged.fingerprint
			accepted.ConfigSHA256["controller.json"] = digest(staged.config)
			chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := bootstrap.MaterialGenerationPayload(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			refs := materialReferences(accepted, nil)
			for _, ref := range generation.Secrets {
				if ref.Slot == "" || ref.Slot == accepted.Slot {
					refs[ref.TargetFile] = ref
				}
			}
			accepted.MaterialReferences = nil
			for ref := range maps.Values(refs) {
				accepted.MaterialReferences = append(accepted.MaterialReferences, ref)
			}
			target, err := GenerationTargetFromAccepted(accepted)
			if err != nil {
				t.Fatal(err)
			}
			store := staged.installer.store
			staged.stage(staged.files)
			staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
			if err := os.WriteFile(staged.pending(), staged.config, 0o444); err != nil {
				t.Fatal(err)
			}
			if fault == "interrupted rename" {
				if err := os.Rename(filepath.Join(staged.dir, generationStaging, "ca.pem"), filepath.Join(staged.dir, "ca.pem")); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.VerifyIdentityRekeyMaterialAdoption(target, staged.roots, staged.wire, time.Now()); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := store.FinishMaterialAdoption(target, staged.roots, staged.installer.config, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			config := bytes.Clone(staged.config)
			switch fault {
			case "config":
				config = []byte("wrong controller config")
			case "material":
				staged.write("ca.pem", []byte("wrong installed CA"))
			case "successor":
				generation.Generation, generation.Previous = 2, staged.fingerprint
				next, err := bootstrap.SignMaterialGeneration(generation, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), staged.rootKey)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := bootstrap.EncodeMaterialGenerationChain(append(chain, next))
				if err != nil {
					t.Fatal(err)
				}
				staged.write(MaterialGenerationsFile, wire)
			}
			_, err = store.VerifyIdentityRekeyInstalledMaterial(t.Context(), accepted, staged.roots, staged.wire, config, time.Now())
			if (err == nil) != (fault == "complete" || fault == "interrupted rename") {
				t.Fatalf("exact installed chain/config verification = %v", err)
			}
			if staged.staged() {
				t.Fatal("exact native recovery left its committed stage")
			}
		})
	}
}

func TestCommittedInstallerRecoversExpiredProofsOnlyUnderExactDurableHold(t *testing.T) {
	markers, baked, journal, inputs, accepted := rootInstallerFixture(t)
	journal.Replicas = 1
	if err := markers.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	js := completionJetStream(t)
	for i := range 10 {
		subject, data := protocol.ControlRoot+".gru.host.audit", []byte("retained audit")
		if i == 8 {
			subject, data = protocol.ControlRoot+".gru.lease", []byte("obsolete identity bytes are opaque")
		}
		if _, err := js.Publish(t.Context(), subject, data); err != nil {
			t.Fatal(err)
		}
	}
	later := accepted.AcceptedAt.Add(2 * time.Hour)
	if _, _, err := verifyCommittedIdentityRekeyInstall(t.Context(), markers, baked, journal, js, later); err == nil {
		t.Fatal("uncommitted expired proposal admitted")
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := verified.ResetEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ResetIdentityLease(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	recovered, _, err := verifyCommittedIdentityRekeyInstall(t.Context(), markers, baked, journal, js, later)
	if err != nil || !recovered.InstallationTime(later).Equal(accepted.AcceptedAt) {
		t.Fatalf("committed replay: %v", err)
	}
	if _, err := recovered.VerifyCurrent(inputs, later); err != nil {
		t.Fatal(err)
	}
	if _, err := verified.VerifyCurrent(inputs, later); err == nil {
		t.Fatal("historical evidence acquired mutation authority without shared proof")
	}
	if err := os.WriteFile(filepath.Join(markers.directory, identityRekeyJournalName), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.VerifyCurrent(inputs, later); err == nil {
		t.Fatal("committed replay ignored changed durable journal")
	}
}
