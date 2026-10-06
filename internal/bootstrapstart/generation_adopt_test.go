package bootstrapstart

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
	if err := install.store().AdoptGeneration(wire, files); err != nil {
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
		if err := install.store().AdoptGeneration(wire, bad); err == nil {
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
		"with a corrupted staged file": {setup: func(install *generationInstall, wire []byte, files map[string][]byte) {
			install.stage(files)
			install.stage(map[string][]byte{"cell.jwt": []byte("corrupted"), MaterialGenerationsFile: wire})
		}},
	} {
		install := newGenerationInstall(t)
		// Every install signs with its own root; use its own generation.
		wire, files = install.signedGeneration()
		crash.setup(install, wire, files)
		if err := install.store().FinishMaterialAdoption(); err != nil {
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
	install := newGenerationInstall(t)
	foreign := filepath.Join(install.dir, generationStaging)
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := install.store().FinishMaterialAdoption(); err == nil {
		t.Fatal("a staging directory others can read was used")
	}
}
