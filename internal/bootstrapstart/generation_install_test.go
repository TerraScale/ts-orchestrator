package bootstrapstart

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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

func TestRestoreArmedStageCannotRollBackDurableChainAfterMemoryLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
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
	if err := staged.installer.restoreArmedGeneration(time.Now()); err != nil {
		t.Fatal(err)
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
	for _, dir := range []string{spool, etc} {
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
	staged.installer = generationInstaller{store: install.store(), roots: install.roots, historicalRoots: install.roots, spool: spool,
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
	if err := os.WriteFile(filepath.Join(staged.installer.spool, name), data, 0o600); err != nil {
		staged.t.Fatal(err)
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

// prepare re-runs on every start, so each crash point converges on the next
// one: before the commit the stage is installed again, after it the
// credential directory rolls forward and controller.json follows from the
// pending copy.
func TestInstallGenerationConvergesAfterACrash(t *testing.T) {
	for name, crash := range map[string]func(*spooledInstall){
		"after the commit": func(staged *spooledInstall) {
			if err := writeSynced(staged.pending(), staged.config); err != nil {
				t.Fatal(err)
			}
			staged.stage(staged.files)
			staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
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
}
