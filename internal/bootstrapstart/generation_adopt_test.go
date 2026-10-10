package bootstrapstart

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// signedGeneration returns the install's generation 1 chain and its files.
func (install *generationInstall) signedGeneration() ([]byte, map[string][]byte) {
	install.t.Helper()
	envelope, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 1, ""),
		time.Now().Add(-time.Minute), time.Now().AddDate(0, 6, 0), install.rootKey)
	if err != nil {
		install.t.Fatal(err)
	}
	wire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
	if err != nil {
		install.t.Fatal(err)
	}
	files := map[string][]byte{}
	for name := range bootstrap.MaterialGenerationFiles() {
		files[name] = install.material.Files[name]
	}
	return wire, files
}

func TestCommittedStageRequiresRootedAcceptedTargetBeforeAnyRename(t *testing.T) {
	for _, fault := range []string{"root", "broker", "slot", "config", "material"} {
		t.Run(fault, func(t *testing.T) {
			staged := newSpooledInstall(t)
			staged.stage(staged.files)
			staged.stage(map[string][]byte{MaterialGenerationsFile: staged.wire})
			if err := os.WriteFile(staged.pending(), staged.config, 0o600); err != nil {
				t.Fatal(err)
			}
			target, roots := staged.installer.target, staged.roots
			switch fault {
			case "root":
				roots = newGenerationInstall(t).roots
			case "broker":
				target.Broker = newGenerationInstall(t).accepted.Broker
			case "slot":
				target.Slot = "controller-b"
			case "config":
				target.AcceptanceSHA256 = digest([]byte("foreign acceptance"))
			case "material":
				staged.stage(map[string][]byte{"ca.pem": []byte("altered")})
			}
			before := staged.read("ca.pem")
			if err := staged.installer.store.FinishMaterialAdoption(target, roots, staged.installer.config, time.Now()); err == nil {
				t.Fatal("committed stage was accepted")
			}
			if !staged.staged() || !bytes.Equal(before, staged.read("ca.pem")) {
				t.Fatal("refusal changed installed material or removed committed stage")
			}
			if _, err := os.Stat(filepath.Join(staged.dir, MaterialGenerationsFile)); !os.IsNotExist(err) {
				t.Fatal("refusal committed a chain")
			}
			if config, err := os.ReadFile(staged.installer.config); err != nil || string(config) != oldConfig {
				t.Fatal("refusal replaced controller config")
			}
		})
	}
}

func TestServiceOwnedCommittedStageUnderBadRootHasNoPrivilegedRename(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("distinct service ownership requires root")
	}
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	install.stage(files)
	install.stage(map[string][]byte{MaterialGenerationsFile: wire})
	stage := filepath.Join(install.dir, generationStaging)
	for _, path := range []string{install.dir, stage} {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	for name := range files {
		if err := os.Chown(filepath.Join(stage, name), 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(filepath.Join(stage, MaterialGenerationsFile), 65534, 65534); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(stage, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store := install.store()
	store.serviceUID, store.serviceGID = 65534, 65534
	if err := store.FinishMaterialAdoption(install.target(), newGenerationInstall(t).roots, install.configPath, time.Now()); err == nil {
		t.Fatal("foreign root was accepted")
	}
	after, err := os.Stat(filepath.Join(stage, "ca.pem"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("bad-root refusal renamed a service-owned file")
	}
	var stat unix.Stat_t
	if err := unix.Stat(stage, &stat); err != nil || stat.Uid != 65534 || stat.Gid != 65534 {
		t.Fatal("bad-root refusal changed stage ownership")
	}
	if _, err := os.Stat(filepath.Join(install.dir, MaterialGenerationsFile)); !os.IsNotExist(err) {
		t.Fatal("bad-root refusal installed a chain")
	}
}

func TestUncommittedStageLeavesUnrelatedFilesUntouched(t *testing.T) {
	install := newGenerationInstall(t)
	install.stage(map[string][]byte{"ca.pem": []byte("partial"), "unrelated.txt": []byte("retain")})
	if err := install.store().FinishMaterialAdoption(install.target(), install.roots, install.configPath, time.Now()); err == nil {
		t.Fatal("unrelated stage was accepted")
	}
	for name, want := range map[string]string{"ca.pem": "partial", "unrelated.txt": "retain"} {
		wire, err := os.ReadFile(filepath.Join(install.dir, generationStaging, name))
		if err != nil || string(wire) != want {
			t.Fatalf("uncommitted %s was changed: %v", name, err)
		}
	}
}

func TestRootOwnedRollForwardTemporaryRecoversAfterCrash(t *testing.T) {
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	install.stage(maps.Clone(files))
	install.stage(map[string][]byte{MaterialGenerationsFile: wire, verifiedMaterialTemporary: []byte("incomplete rewrite")})
	if err := unix.Chown(filepath.Join(install.dir, generationStaging), os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := install.store().FinishMaterialAdoption(install.target(), install.roots, install.configPath, time.Now()); err != nil {
		t.Fatal(err)
	}
	if install.staged() {
		t.Fatal("recovered stage survived")
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatal(err)
	}
}

func (install *generationInstall) store() MaterialStore {
	return MaterialStore{installedDirectory: install.dir, serviceUID: uint32(os.Getuid()),
		serviceGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
}

// stage writes a stage as a crash would leave it.
func (install *generationInstall) stage(files map[string][]byte) {
	install.t.Helper()
	staging := filepath.Join(install.dir, generationStaging)
	if err := os.Mkdir(staging, 0o700); err != nil && !os.IsExist(err) {
		install.t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(staging, name), content, 0o600); err != nil {
			install.t.Fatal(err)
		}
	}
}

func (install *generationInstall) staged() bool {
	_, err := os.Stat(filepath.Join(install.dir, generationStaging))
	return err == nil
}

func TestAdoptGenerationInstallsWhatRestartAdmits(t *testing.T) {
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	if err := install.store().AdoptGeneration(install.target(), install.roots, wire, files, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if install.staged() {
		t.Fatal("staging survived a completed install")
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("restart admission of the adopted generation: %v", err)
	}
	missing := map[string][]byte{}
	for name, content := range files {
		if name != "cell.jwt" {
			missing[name] = content
		}
	}
	changed := map[string][]byte{}
	for name, content := range files {
		changed[name] = content
	}
	changed["ca.pem"] = []byte("not the pinned bundle")
	for name, bad := range map[string]map[string][]byte{"a missing file": missing, "a file unlike its pin": changed} {
		if err := install.store().AdoptGeneration(install.target(), install.roots, wire, bad, nil, time.Now()); err == nil {
			t.Errorf("adopted %s", name)
		}
	}
}

// A crash leaves a stage behind; FinishMaterialAdoption, which runs before
// restart admission, completes a committed stage and drops any other.
func TestFinishMaterialAdoptionAfterACrash(t *testing.T) {
	wire, files := newGenerationInstall(t).signedGeneration()
	for name, crash := range map[string]struct {
		setup     func(*generationInstall, []byte, map[string][]byte)
		installed bool
	}{
		"before the commit": {setup: func(install *generationInstall, _ []byte, files map[string][]byte) {
			install.stage(map[string][]byte{"ca.pem": files["ca.pem"], "cell.jwt": files["cell.jwt"]})
		}},
		"while renaming": {installed: true, setup: func(install *generationInstall, wire []byte, files map[string][]byte) {
			install.stage(files)
			install.stage(map[string][]byte{MaterialGenerationsFile: wire})
			for _, name := range []string{"ca.pem", "operator.jwt"} {
				if err := os.Rename(filepath.Join(install.dir, generationStaging, name), filepath.Join(install.dir, name)); err != nil {
					t.Fatal(err)
				}
			}
		}},
		"after the chain was installed": {installed: true, setup: func(install *generationInstall, wire []byte, files map[string][]byte) {
			for name, content := range files {
				install.write(name, content)
			}
			install.write(MaterialGenerationsFile, wire)
			install.stage(nil)
		}},
	} {
		install := newGenerationInstall(t)
		// Every install signs with its own root; use its own generation.
		wire, files = install.signedGeneration()
		crash.setup(install, wire, files)
		if err := install.store().FinishMaterialAdoption(install.target(), install.roots, install.configPath, time.Now()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if install.staged() {
			t.Fatalf("%s: staging survived", name)
		}
		if err := install.verify(pinnedIP); err != nil {
			t.Fatalf("%s: restart admission after recovery: %v", name, err)
		}
		_, err := os.Stat(filepath.Join(install.dir, MaterialGenerationsFile))
		if adopted := err == nil; adopted != crash.installed {
			t.Fatalf("%s: adopted %v, want %v", name, adopted, crash.installed)
		}
	}
	corrupted := newGenerationInstall(t)
	badWire, badFiles := corrupted.signedGeneration()
	corrupted.stage(badFiles)
	corrupted.stage(map[string][]byte{"cell.jwt": []byte("corrupted"), MaterialGenerationsFile: badWire})
	if err := corrupted.store().FinishMaterialAdoption(corrupted.target(), corrupted.roots, corrupted.configPath, time.Now()); err == nil || !corrupted.staged() {
		t.Fatal("committed corrupt stage did not fail closed")
	}
	install := newGenerationInstall(t)
	foreign := filepath.Join(install.dir, generationStaging)
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := install.store().FinishMaterialAdoption(install.target(), install.roots, install.configPath, time.Now()); err == nil {
		t.Fatal("a staging directory others can read was used")
	}
}
