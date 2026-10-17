package bootstrapstart

import (
	"bytes"
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// spooledInstall is controller-a's credential directory, controller.json and
// the stager's spool holding gru-1's v1 generation 1 (TS-668).
type spooledInstall struct {
	*generationInstall
	installer   generationInstaller
	wire        []byte
	fingerprint string
	files       map[string][]byte
	config      []byte
}

const oldConfig = `{"manifest":"era"}`

func TestInterruptedStaleAdoptionRequiresFreshArmedSuccessor(t *testing.T) {
	for _, fault := range []string{"expired", "retired signer", "unarmed", "missing successor", "tampered successor", "fork", "tampered predecessor"} {
		t.Run(fault, func(t *testing.T) {
			staged := newSpooledInstall(t)
			now := time.Now()
			chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := bootstrap.MaterialGenerationPayload(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			first, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.Add(time.Hour), staged.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			firstWire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first})
			if err != nil {
				t.Fatal(err)
			}
			staged.stage(staged.files)
			staged.stage(map[string][]byte{MaterialGenerationsFile: firstWire})
			if err := os.Rename(filepath.Join(staged.dir, generationStaging, "ca.pem"), filepath.Join(staged.dir, "ca.pem")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged.pending(), staged.config, 0o600); err != nil {
				t.Fatal(err)
			}
			at := now.Add(2 * time.Hour)
			key := staged.rootKey
			if fault == "retired signer" {
				newRoot := newGenerationInstall(t)
				key = newRoot.rootKey
				staged.installer.roots = newRoot.roots
				staged.installer.historicalRoots = maps.Clone(staged.roots)
				maps.Copy(staged.installer.historicalRoots, newRoot.roots)
				at = now
			}
			if err := staged.installer.store.FinishMaterialAdoption(staged.installer.target, staged.installer.roots, staged.installer.config, at); err == nil {
				t.Fatal("stale stage passed ordinary startup")
			}
			generation.Generation = 2
			generation.Previous, err = trust.Fingerprint(first)
			if err != nil {
				t.Fatal(err)
			}
			staged.config = append(bytes.Clone(staged.config), '\n')
			for i := range generation.ControllerConfigs {
				if generation.ControllerConfigs[i].Slot == staged.installer.target.Slot {
					generation.ControllerConfigs[i].SHA256 = digest(staged.config)
					generation.ControllerConfigs[i].Size = int64(len(staged.config))
				}
			}
			if fault == "fork" {
				generation.Generation, generation.Previous = 1, ""
			}
			second, err := bootstrap.SignMaterialGeneration(generation, now, now.Add(4*time.Hour), key)
			if err != nil {
				t.Fatal(err)
			}
			next := []trust.Envelope{first, second}
			if fault == "fork" {
				next = []trust.Envelope{second}
			}
			staged.wire, err = bootstrap.EncodeMaterialGenerationChain(next)
			if err != nil {
				t.Fatal(err)
			}
			staged.fingerprint, _ = trust.Fingerprint(second)
			staged.spool(MaterialGenerationsFile, staged.wire)
			staged.spool(GenerationConfigFile(staged.installer.target.Slot), staged.config)
			staged.arm()
			switch fault {
			case "unarmed":
				if err := os.Remove(filepath.Join(staged.installer.spool, GenerationArmedFile)); err != nil {
					t.Fatal(err)
				}
			case "missing successor":
				if err := os.Remove(filepath.Join(staged.installer.spool, MaterialGenerationsFile)); err != nil {
					t.Fatal(err)
				}
			case "tampered successor":
				staged.spool("cell.jwt", []byte("wrong successor"))
			case "tampered predecessor":
				staged.stage(map[string][]byte{"cell.jwt": []byte("wrong predecessor")})
			}
			outcome, err := staged.installer.install(at)
			if fault == "expired" || fault == "retired signer" {
				if err != nil || outcome != "installed generation 2" || !staged.installed() {
					t.Fatalf("fresh successor did not recover partial adoption: %s, %v", outcome, err)
				}
			} else {
				if err == nil || !staged.staged() || !bytes.Equal(staged.read("ca.pem"), staged.files["ca.pem"]) {
					t.Fatal("invalid successor changed the partial adoption")
				}
				if _, err := os.Stat(filepath.Join(staged.dir, MaterialGenerationsFile)); !os.IsNotExist(err) {
					t.Fatal("refused successor committed a generation")
				}
			}
		})
	}
}

func TestRestoreMatchingArmedGenerationAfterMemoryLoss(t *testing.T) {
	staged := newSpooledInstall(t)
	staged.installer.store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	staged.arm()
	if outcome := staged.install(); outcome != "installed generation 1" {
		t.Fatal(outcome)
	}
	vault := map[string][]byte{}
	names, err := os.ReadDir(staged.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		vault[name.Name()] = staged.read(name.Name())
		if err := os.Remove(filepath.Join(staged.dir, name.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := staged.installer.restoreArmedGeneration(time.Now()); err != nil {
		t.Fatalf("matching armed spool prevented Vault restoration after reboot: %v", err)
	}
	store := staged.installer.store
	dir, err := openMaterialDirectory(staged.dir, store.serviceUID, store.serviceGID, 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	refs, chain, err := store.restorePlan(dir, staged.accepted, staged.roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	contents, err := readReferences(t.Context(), refs, func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
		return bytes.Clone(vault[ref.TargetFile]), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clearContents(contents)
	if err := convergeRestoredConfig(store, staged.installer.target, staged.roots, chain, staged.installer.config, time.Now(), contents); err != nil {
		t.Fatal(err)
	}
	if err := store.fill(contents, chain); err != nil {
		t.Fatal(err)
	}
	if !staged.installed() {
		t.Fatal("Vault restoration did not recover the installed generation")
	}

	t.Run("current root admission", func(t *testing.T) {
		staged := newSpooledInstall(t)
		staged.arm()
		before := staged.read("system.creds")
		staged.installer.store.admitGeneration = func(GenerationTarget, []trust.Envelope) error { return ErrMaterial }
		if outcome := staged.install(); !strings.HasPrefix(outcome, "refused: ") {
			t.Fatal("activation ignored current root admission", outcome)
		}
		if err := staged.installer.restoreArmedGeneration(time.Now()); err == nil {
			t.Fatal("restore ignored current root admission")
		}
		staged.stage(staged.files)
		staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
		if err := writeSynced(staged.pending(), staged.config); err != nil {
			t.Fatal(err)
		}
		if err := staged.installer.finishAdoption(time.Now()); err == nil {
			t.Fatal("interrupted adoption ignored current root admission")
		}
		if !bytes.Equal(before, staged.read("system.creds")) {
			t.Fatal("refused current admission changed installed credentials")
		}
		t.Run("expiry after current admission", func(t *testing.T) {
			staged := newSpooledInstall(t)
			staged.arm()
			held, err := staged.installer.heldGenerations()
			if err != nil {
				t.Fatal(err)
			}
			wire, chain, files, config, delivery, err := staged.installer.armedStage(held, time.Now())
			if err != nil || delivery == nil {
				t.Fatal("read admitted private stage", err)
			}
			defer clearContents(files)
			before := staged.read("system.creds")
			delivery.admit = func() error {
				delivery.ExpiresAt = time.Now().Add(-time.Second)
				return nil
			}
			if _, err := staged.installer.installArmed(held, wire, chain, files, config, delivery, time.Now()); err == nil {
				t.Fatal("activation published after the original delivery expired during admission")
			}
			if !bytes.Equal(before, staged.read("system.creds")) {
				t.Fatal("expired current admission changed installed credentials")
			}
		})

		for _, failure := range []string{"context cancellation", "source expiry"} {
			t.Run("restore original seal after final admission/"+failure, func(t *testing.T) {
				staged := newSpooledInstall(t)
				staged.arm()
				held, err := staged.installer.heldGenerations()
				if err != nil {
					t.Fatal(err)
				}
				wire, chain, files, config, delivery, err := staged.installer.armedStage(held, time.Now())
				if err != nil || delivery == nil {
					t.Fatal("read admitted private stage", err)
				}
				defer clearContents(files)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				expired := false
				staged.installer.store.restoreCurrent = func([]trust.Envelope) error { return nil }
				staged.installer.store.restoreSeal = func() error {
					if expired {
						return ErrMaterial
					}
					return ctx.Err()
				}
				admissions := 0
				delivery.admit = func() error {
					admissions++
					if admissions == 2 {
						if failure == "context cancellation" {
							cancel()
						} else {
							expired = true
						}
					}
					return nil
				}
				before := staged.read("system.creds")
				if _, err := staged.installer.installArmed(held, wire, chain, files, config, delivery, time.Now()); err == nil {
					t.Fatal("activation published after restore original became invalid during final admission")
				}
				if admissions != 2 || !bytes.Equal(before, staged.read("system.creds")) {
					t.Fatal("restore original seal did not precede publication", admissions)
				}
			})
		}

	})
}

func TestArmedSuccessorPreservesCommittedPendingConfigBeforeFailure(t *testing.T) {
	staged := newSpooledInstall(t)
	now := time.Now()
	chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	first, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.Add(time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	firstWire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(staged.pending(), staged.config); err != nil {
		t.Fatal(err)
	}
	if err := staged.installer.store.AdoptGeneration(staged.installer.target, staged.roots, firstWire, staged.files, staged.config, now); err != nil {
		t.Fatal(err)
	}
	previousConfig := bytes.Clone(staged.config)
	generation.Generation = 2
	generation.Previous, err = trust.Fingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	staged.config = append(bytes.Clone(staged.config), '\n')
	for i := range generation.ControllerConfigs {
		if generation.ControllerConfigs[i].Slot == staged.installer.target.Slot {
			generation.ControllerConfigs[i].SHA256 = digest(staged.config)
			generation.ControllerConfigs[i].Size = int64(len(staged.config))
		}
	}
	second, err := bootstrap.SignMaterialGeneration(generation, now, now.Add(4*time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	staged.wire, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first, second})
	if err != nil {
		t.Fatal(err)
	}
	staged.fingerprint, _ = trust.Fingerprint(second)
	staged.spool(MaterialGenerationsFile, staged.wire)
	staged.spool(GenerationConfigFile(staged.installer.target.Slot), staged.config)
	staged.arm()
	obstruction := filepath.Join(staged.dir, generationStaging)
	if err := os.WriteFile(obstruction, []byte("refuse adoption before its commit"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := staged.installer.install(now.Add(2 * time.Hour)); err == nil {
		t.Fatal("successor unexpectedly committed through an obstructed stage")
	}
	if current, err := os.ReadFile(staged.installer.config); err != nil || !bytes.Equal(current, previousConfig) {
		if pending, pendingErr := os.ReadFile(staged.pending()); pendingErr != nil || !bytes.Equal(pending, previousConfig) {
			t.Fatalf("successor lost the expired predecessor's only matching config: %v, %v", err, pendingErr)
		}
	}
	if !bytes.Equal(staged.read(MaterialGenerationsFile), firstWire) {
		t.Fatal("failed successor changed the committed generation")
	}
	if err := os.Remove(obstruction); err != nil {
		t.Fatal(err)
	}
	if outcome, err := staged.installer.install(now.Add(2 * time.Hour)); err != nil || outcome != "installed generation 2" {
		t.Fatalf("valid successor could not recover: %s, %v", outcome, err)
	}
}

func TestArmedRenewalInstallsAfterOldGenerationExpiry(t *testing.T) {
	staged := newSpooledInstall(t)
	now := time.Now()
	decoded, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
	if err != nil {
		t.Fatal(err)
	}
	first, err := bootstrap.MaterialGenerationPayload(decoded[0])
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bootstrap.SignMaterialGeneration(first, now.Add(-time.Minute), now.Add(time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	staged.wire, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
	if err != nil {
		t.Fatal(err)
	}
	staged.fingerprint, err = trust.Fingerprint(envelope)
	if err != nil {
		t.Fatal(err)
	}
	staged.spool(MaterialGenerationsFile, staged.wire)
	staged.arm()
	if _, err := staged.installer.install(now); err != nil {
		t.Fatal(err)
	}
	first.Generation, first.Previous = 2, staged.fingerprint
	renewed, err := bootstrap.SignMaterialGeneration(first, now, now.Add(4*time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	staged.wire, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope, renewed})
	if err != nil {
		t.Fatal(err)
	}
	staged.fingerprint, err = trust.Fingerprint(renewed)
	if err != nil {
		t.Fatal(err)
	}
	staged.spool(MaterialGenerationsFile, staged.wire)
	staged.arm()
	if outcome, err := staged.installer.install(now.Add(2 * time.Hour)); err != nil || outcome != "installed generation 2" {
		t.Fatalf("valid armed renewal blocked by expired predecessor: %s, %v", outcome, err)
	}
}

func TestRestoreInstallsFreshArmedSuccessorBeforeExpiredInventoryCheck(t *testing.T) {
	for _, fault := range []string{"fresh successor", "unarmed", "tampered successor"} {
		t.Run(fault, func(t *testing.T) {
			staged := newSpooledInstall(t)
			now := time.Now()
			decoded, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := bootstrap.MaterialGenerationPayload(decoded[0])
			if err != nil {
				t.Fatal(err)
			}
			first, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.Add(time.Hour), staged.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			staged.wire, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first})
			if err != nil {
				t.Fatal(err)
			}
			staged.fingerprint, _ = trust.Fingerprint(first)
			staged.spool(MaterialGenerationsFile, staged.wire)
			staged.arm()
			if outcome := staged.install(); outcome != "installed generation 1" {
				t.Fatal(outcome)
			}
			at := now.Add(2 * time.Hour)
			store := staged.installer.store
			dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, true)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(dir)
			if _, _, err := store.restorePlan(dir, staged.accepted, staged.roots, at); err == nil {
				t.Fatal("expired installed generation admitted restoration")
			}
			generation.Generation, generation.Previous = 2, staged.fingerprint
			second, err := bootstrap.SignMaterialGeneration(generation, now, now.Add(4*time.Hour), staged.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			staged.wire, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first, second})
			if err != nil {
				t.Fatal(err)
			}
			staged.fingerprint, _ = trust.Fingerprint(second)
			staged.spool(MaterialGenerationsFile, staged.wire)
			staged.arm()
			if fault == "unarmed" {
				if err := os.Remove(filepath.Join(staged.installer.spool, GenerationArmedFile)); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "tampered successor" {
				staged.spool("ca.pem", []byte("tampered"))
			}
			if err := staged.installer.restoreArmedGeneration(at); err != nil && fault == "fresh successor" {
				t.Fatal(err)
			}
			_, chain, err := store.restorePlan(dir, staged.accepted, staged.roots, at)
			if fault != "fresh successor" {
				if err == nil {
					t.Fatal("invalid or unarmed successor bypassed installed expiry")
				}
				return
			}
			if err != nil || !bytes.Equal(chain, staged.wire) {
				t.Fatalf("restore did not select verified fresh successor: %v", err)
			}
			if err := verifyRestoreContents(staged.installer.target, staged.roots, chain, staged.files, staged.installer.config, at); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestoreArmedStageCannotRollBackDurableChainAfterMemoryLoss(t *testing.T) {
	staged := newSpooledInstall(t)
	staged.installer.store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	firstWire, firstFingerprint := bytes.Clone(staged.wire), staged.fingerprint
	staged.arm()
	if outcome := staged.install(); outcome != "installed generation 1" {
		t.Fatal(outcome)
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(firstWire)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	generation.Generation, generation.Previous = 2, firstFingerprint
	second, err := bootstrap.SignMaterialGeneration(generation, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	staged.wire, err = bootstrap.EncodeMaterialGenerationChain(append(chain, second))
	if err != nil {
		t.Fatal(err)
	}
	staged.fingerprint, _ = trust.Fingerprint(second)
	staged.spool(MaterialGenerationsFile, staged.wire)
	staged.arm()
	if outcome := staged.install(); outcome != "installed generation 2" {
		t.Fatal(outcome)
	}
	if err := os.Remove(filepath.Join(staged.dir, MaterialGenerationsFile)); err != nil {
		t.Fatal(err)
	}
	staged.spool(MaterialGenerationsFile, firstWire)
	staged.spool(GenerationArmedFile, []byte(firstFingerprint))
	if err := staged.installer.restoreArmedGeneration(time.Now()); err == nil {
		t.Fatal("restore admitted a stale armed chain")
	}
	durable, err := os.ReadFile(staged.installer.store.chainCopy)
	if err != nil || !bytes.Equal(durable, staged.wire) {
		t.Fatal("stale armed spool rolled back the durable chain")
	}
	if _, err := os.Stat(filepath.Join(staged.dir, MaterialGenerationsFile)); !os.IsNotExist(err) {
		t.Fatal("stale armed spool installed an old chain")
	}
}

func newSpooledInstall(t *testing.T) *spooledInstall {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("private generation custody requires root")
	}
	install := newGenerationInstall(t)
	now := time.Now()
	material := install.material.WithoutIssuers(t).InterRegion(t, now, install.expected.ControllerSlots).
		WithControllerCredentials(t, install.expected.ControllerSlots)
	generation := material.Generation(install.expected, 1, "")
	for index := range generation.ControllerConfigs {
		generation.ControllerConfigs[index].AcceptanceSHA256 = install.acceptance()
	}
	envelope, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.AddDate(0, 6, 0),
		install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	spool, etc := filepath.Join(base, "spool"), filepath.Join(base, "etc")
	privateSpool := filepath.Join(base, "private")
	for _, dir := range []string{spool, etc, privateSpool} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	staged := &spooledInstall{generationInstall: install, wire: wire, fingerprint: fingerprint, files: map[string][]byte{},
		config: material.Files[GenerationConfigFile("controller-a")]}
	for _, secret := range generation.Secrets {
		if secret.Slot == "" || secret.Slot == "controller-a" {
			staged.files[secret.TargetFile] = material.Files[secret.TargetFile]
		}
	}
	staged.installer = generationInstaller{store: install.store(), roots: install.roots, historicalRoots: install.roots, spool: spool, privateSpool: privateSpool,
		config: filepath.Join(etc, "controller.json"), target: install.target()}
	staged.spool(MaterialGenerationsFile, wire)
	staged.spool(GenerationConfigFile("controller-a"), staged.config)
	for name, data := range staged.files {
		staged.spool(name, data)
	}
	if err := os.WriteFile(staged.installer.config, []byte(oldConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	return staged
}

func (staged *spooledInstall) spool(name string, data []byte) {
	staged.t.Helper()
	directory := staged.installer.privateSpool
	if name == MaterialGenerationsFile || name == GenerationArmedFile || name == GenerationConfigFile(staged.installer.target.Slot) {
		directory = staged.installer.spool
	}
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		staged.t.Fatal(err)
	}
	if name == MaterialGenerationsFile {
		chain, err := bootstrap.DecodeMaterialGenerationChain(data)
		if err != nil {
			staged.t.Fatal(err)
		}
		fingerprint, err := trust.Fingerprint(chain[len(chain)-1])
		if err != nil {
			staged.t.Fatal(err)
		}
		metadata, err := protocol.EncodeJSON(GenerationDeliveryLifetime{AcceptanceSHA256: staged.installer.target.AcceptanceSHA256,
			ChainSHA256: digest(data), GenerationSHA256: fingerprint, ExpiresAt: chain[len(chain)-1].ExpiresAt})
		if err != nil {
			staged.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staged.installer.privateSpool, GenerationDeliveryFile), metadata, 0o600); err != nil {
			staged.t.Fatal(err)
		}
	}
}

func (staged *spooledInstall) arm() {
	staged.spool(GenerationArmedFile, []byte(staged.fingerprint+"\n"))
}

func (staged *spooledInstall) pending() string {
	return filepath.Join(filepath.Dir(staged.installer.config), pendingControllerConfig)
}

func (staged *spooledInstall) install() string {
	staged.t.Helper()
	outcome, err := staged.installer.install(time.Now())
	if err != nil {
		staged.t.Fatal(err)
	}
	return outcome
}

// installed reports whether the generation is installed, and fails when it
// is only partly so.
func (staged *spooledInstall) installed() bool {
	staged.t.Helper()
	chain, chainErr := os.ReadFile(filepath.Join(staged.dir, MaterialGenerationsFile))
	config, err := os.ReadFile(staged.installer.config)
	if err != nil {
		staged.t.Fatal(err)
	}
	if os.IsNotExist(chainErr) {
		if string(config) != oldConfig || staged.staged() {
			staged.t.Fatal("controller.json or a stage changed without an installed chain")
		}
		return false
	}
	if !bytes.Equal(chain, staged.wire) || !bytes.Equal(config, staged.config) || staged.staged() {
		staged.t.Fatalf("partial install: chain %v, config %v, staging left %v", bytes.Equal(chain, staged.wire),
			bytes.Equal(config, staged.config), staged.staged())
	}
	for name, data := range staged.files {
		info, err := os.Stat(filepath.Join(staged.dir, name))
		if err != nil || !bytes.Equal(staged.read(name), data) || info.Mode().Perm() != 0o600 {
			staged.t.Fatalf("installed %s differs from its pin or mode: %v", name, err)
		}
	}
	for _, other := range []string{"controller-b", "controller-c"} {
		cert, key := bootstrap.InterRegionTLSFiles(other)
		for _, name := range []string{cert, key, other + ".creds"} {
			if _, err := os.Stat(filepath.Join(staged.dir, name)); err == nil {
				staged.t.Fatalf("installed another slot's %s", name)
			}
		}
	}
	if _, err := os.Stat(staged.pending()); err == nil {
		staged.t.Fatal("the pending controller config survived the install")
	}
	return true
}

// prepare never installs an unarmed stage; an armed one replaces the slot's
// files and controller.json, and a repeated prepare changes nothing.
func TestInstallGenerationOnlyWhenArmed(t *testing.T) {
	staged := newSpooledInstall(t)
	if outcome := staged.install(); outcome != "none" || staged.installed() {
		t.Fatalf("unarmed stage: %q", outcome)
	}
	staged.arm()
	if outcome := staged.install(); outcome != "installed generation 1" || !staged.installed() {
		t.Fatalf("armed stage: %q", outcome)
	}
	// Restart admission accepts the installed set with the new controller.json.
	staged.loaded = staged.config
	staged.credential.Config.Embedded.InterRegion = embeddedBlock(t, staged.config, staged.dir).InterRegion
	if err := staged.verify(pinnedIP); err != nil {
		t.Fatalf("restart admission refuses the installed generation: %v", err)
	}
	if outcome := staged.install(); outcome != "none" || !staged.installed() {
		t.Fatalf("repeated prepare: %q", outcome)
	}

	t.Run("ordinary raw copies", func(t *testing.T) {
		staged := newSpooledInstall(t)
		staged.arm()
		if err := os.WriteFile(filepath.Join(staged.installer.spool, "system.creds"), []byte("ordinary replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		if outcome := staged.install(); outcome != "installed generation 1" || !staged.installed() {
			t.Fatal(outcome)
		}
		if !bytes.Equal(staged.read("system.creds"), staged.files["system.creds"]) {
			t.Fatal("installed ordinary SYSTEM copy")
		}
	})
}

// Everything in the spool is checked again; a refusal installs nothing.
func TestInstallGenerationRefusesATamperedSpool(t *testing.T) {
	for name, tamper := range map[string]func(*spooledInstall){
		"a changed file": func(staged *spooledInstall) {
			staged.spool("interregion-ca.pem", []byte("not the pinned CA"))
		},
		"a changed config": func(staged *spooledInstall) {
			staged.spool(GenerationConfigFile("controller-a"), []byte(`{"controller":{},"nats":{}}`))
		},
		"a missing file": func(staged *spooledInstall) {
			cert, _ := bootstrap.InterRegionTLSFiles("controller-a")
			if err := os.Remove(filepath.Join(staged.installer.spool, cert)); err != nil {
				t.Fatal(err)
			}
		},
		"an arm for another generation": func(staged *spooledInstall) {
			staged.spool(GenerationArmedFile, []byte(strings.Repeat("0", 64)))
		},
		"a generation for another manifest": func(staged *spooledInstall) {
			staged.installer.target.AcceptanceSHA256 = digest([]byte("another manifest"))
		},
		"a chain under another root": func(staged *spooledInstall) {
			staged.installer.roots = newGenerationInstall(t).roots
		},
		"a link out of the spool": func(staged *spooledInstall) {
			outside := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(outside, staged.files["ca.pem"], 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(staged.installer.privateSpool, "ca.pem")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		staged := newSpooledInstall(t)
		staged.arm()
		tamper(staged)
		if outcome := staged.install(); !strings.HasPrefix(outcome, "refused: ") || staged.installed() {
			t.Fatalf("%s: %q", name, outcome)
		}
	}

	t.Run("private inventory drift", func(t *testing.T) {
		for _, fault := range []string{"missing", "expired", "wrong owner", "foreign acceptance", "changed bytes"} {
			t.Run(fault, func(t *testing.T) {
				staged := newSpooledInstall(t)
				staged.arm()
				// A valid ordinary copy must never recover a refused private source.
				if err := os.WriteFile(filepath.Join(staged.installer.spool, "system.creds"), staged.files["system.creds"], 0o600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(staged.installer.privateSpool, "system.creds")
				switch fault {
				case "missing":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "wrong owner":
					if err := os.Chown(path, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				case "changed bytes":
					if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
						t.Fatal(err)
					}
				default:
					metadata, err := os.ReadFile(filepath.Join(staged.installer.privateSpool, GenerationDeliveryFile))
					if err != nil {
						t.Fatal(err)
					}
					var lifetime GenerationDeliveryLifetime
					if err := protocol.DecodeStrict(metadata, &lifetime, maxGenerationDeliveryBytes); err != nil {
						t.Fatal(err)
					}
					if fault == "expired" {
						lifetime.ExpiresAt = time.Now().Add(-time.Second)
					} else {
						lifetime.AcceptanceSHA256 = digest([]byte("foreign"))
					}
					metadata, err = protocol.EncodeJSON(lifetime)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(staged.installer.privateSpool, GenerationDeliveryFile), metadata, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if outcome := staged.install(); !strings.HasPrefix(outcome, "refused: ") || staged.installed() {
					t.Fatalf("activation admitted %s: %s", fault, outcome)
				}
				if err := staged.installer.restoreArmedGeneration(time.Now()); err == nil {
					t.Fatalf("restore admitted %s", fault)
				}
			})
		}
	})
}

// prepare re-runs on every start, so each crash point converges on the next
// one: before the commit the stage is installed again, after it the
// credential directory rolls forward and controller.json follows from the
// pending copy.
func TestInstallGenerationConvergesAfterACrash(t *testing.T) {
	for name, crash := range map[string]func(*spooledInstall){
		"after the pending config": func(staged *spooledInstall) {
			if err := writeSynced(staged.pending(), staged.config); err != nil {
				t.Fatal(err)
			}
		},
		"before the commit": func(staged *spooledInstall) {
			if err := writeSynced(staged.pending(), staged.config); err != nil {
				t.Fatal(err)
			}
			staged.stage(map[string][]byte{"ca.pem": staged.files["ca.pem"]})
		},
		"after the commit": func(staged *spooledInstall) {
			if err := writeSynced(staged.pending(), staged.config); err != nil {
				t.Fatal(err)
			}
			staged.stage(staged.files)
			staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
		},
		"after the chain was installed": func(staged *spooledInstall) {
			if err := writeSynced(staged.pending(), staged.config); err != nil {
				t.Fatal(err)
			}
			for name, data := range staged.files {
				staged.write(name, data)
			}
			staged.write(MaterialGenerationsFile, staged.wire)
		},
	} {
		staged := newSpooledInstall(t)
		staged.arm()
		crash(staged)
		if err := staged.installer.store.FinishMaterialAdoption(staged.installer.target, staged.roots, staged.installer.config, time.Now()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if outcome := staged.install(); strings.HasPrefix(outcome, "refused") || !staged.installed() {
			t.Fatalf("%s: %q", name, outcome)
		}
	}
	// Disarmed after a crash before the commit: nothing is installed and
	// the stale pending copy is never used.
	staged := newSpooledInstall(t)
	if err := writeSynced(staged.pending(), staged.config); err != nil {
		t.Fatal(err)
	}
	if outcome := staged.install(); outcome != "none" || staged.installed() {
		t.Fatalf("disarmed: %q", outcome)
	}

	t.Run("original delivery lifetime", func(t *testing.T) {
		staged := newSpooledInstall(t)
		staged.arm()
		staged.stage(staged.files)
		staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
		if err := writeSynced(staged.pending(), staged.config); err != nil {
			t.Fatal(err)
		}
		metadata, err := os.ReadFile(filepath.Join(staged.dir, generationStaging, GenerationDeliveryFile))
		if err != nil {
			t.Fatal(err)
		}
		var lifetime GenerationDeliveryLifetime
		if err := protocol.DecodeStrict(metadata, &lifetime, maxGenerationDeliveryBytes); err != nil {
			t.Fatal(err)
		}
		lifetime.ExpiresAt = time.Now().Add(-time.Second)
		metadata, err = protocol.EncodeJSON(lifetime)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staged.dir, generationStaging, GenerationDeliveryFile), metadata, 0o600); err != nil {
			t.Fatal(err)
		}
		before := staged.read("system.creds")
		if err := staged.installer.finishAdoption(time.Now()); err == nil {
			t.Fatal("restart renewed expired delivery lifetime")
		}
		if !bytes.Equal(before, staged.read("system.creds")) {
			t.Fatal("expired interrupted stage changed installed credentials")
		}
	})
}

// A reboot after an adoption's commit but before prepare replaced
// controller.json: the restore before admission puts the pending config in
// place, as admission needs the generation's config (TS-745).
func TestRestoreConvergesThePendingControllerConfig(t *testing.T) {
	staged := newSpooledInstall(t)
	if err := writeSynced(staged.pending(), staged.config); err != nil {
		t.Fatal(err)
	}
	for name, data := range staged.files {
		staged.write(name, data)
	}
	staged.write(MaterialGenerationsFile, staged.wire)
	if err := convergeRestoredConfig(staged.installer.store, staged.installer.target, staged.roots, staged.wire, staged.installer.config, time.Now(), staged.files); err != nil {
		t.Fatal(err)
	}
	if !staged.installed() {
		t.Fatal("the generation is not installed after the restore")
	}
	// Without a matching pending copy the restore refuses, as admission would.
	if err := os.WriteFile(staged.installer.config, []byte(oldConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := convergeRestoredConfig(staged.installer.store, staged.installer.target, staged.roots, staged.wire, staged.installer.config, time.Now(), staged.files); err == nil {
		t.Fatal("restored a chain whose config is not in place")
	}
}
