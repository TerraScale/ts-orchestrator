package bootstrapstart

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// spooledInstall is controller-a's credential directory, controller.json and
// the stager's spool holding gru-1's schema-2 generation 1 (TS-668).
type spooledInstall struct {
	*generationInstall
	installer   generationInstaller
	wire        []byte
	fingerprint string
	files       map[string][]byte
	config      []byte
}

const oldConfig = `{"manifest":"era"}`

func newSpooledInstall(t *testing.T) *spooledInstall {
	t.Helper()
	install := newGenerationInstall(t)
	now := time.Now()
	material := install.material.SchemaTwo(t).WithoutIssuers(t).InterRegion(t, now, install.expected.ControllerSlots)
	generation := material.Generation(install.expected, 1, "")
	for index := range generation.ControllerConfigs {
		generation.ControllerConfigs[index].ManifestSHA256 = acceptedManifest
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
	staged.installer = generationInstaller{store: install.store(), roots: install.roots, spool: spool,
		config: filepath.Join(etc, "controller.json"), target: GenerationTarget{Slot: "controller-a",
			ManifestSHA256: acceptedManifest, Expected: install.expected}}
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
		for _, name := range []string{cert, key} {
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
	staged.credential.Config.Embedded.InterRegion = interRegionBlock(t, staged.config, staged.dir)
	if err := staged.verify(pinnedIP); err != nil {
		t.Fatalf("restart admission refuses the installed generation: %v", err)
	}
	if outcome := staged.install(); outcome != "none" || !staged.installed() {
		t.Fatalf("repeated prepare: %q", outcome)
	}
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
			staged.installer.target.ManifestSHA256 = digest([]byte("another manifest"))
		},
		"a chain under another root": func(staged *spooledInstall) {
			staged.installer.roots = newGenerationInstall(t).roots
		},
		"a link out of the spool": func(staged *spooledInstall) {
			outside := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(outside, staged.files["ca.pem"], 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(staged.installer.spool, "ca.pem")
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
		if err := staged.installer.store.FinishMaterialAdoption(); err != nil {
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
	if err := convergeRestoredConfig(staged.installer.store, staged.installer.target, staged.wire, staged.installer.config); err != nil {
		t.Fatal(err)
	}
	if !staged.installed() {
		t.Fatal("the generation is not installed after the restore")
	}
	// Without a matching pending copy the restore refuses, as admission would.
	if err := os.WriteFile(staged.installer.config, []byte(oldConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := convergeRestoredConfig(staged.installer.store, staged.installer.target, staged.wire, staged.installer.config); err == nil {
		t.Fatal("restored a chain whose config is not in place")
	}
}
