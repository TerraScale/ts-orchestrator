package bootstrapstart

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
	if err := install.store().AdoptGeneration(install.target(), install.roots, wire, files, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if install.staged() {
		t.Fatal("staging survived a completed install")
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("restart admission of the adopted generation: %v", err)
	}
	changed := map[string][]byte{}
	for name, content := range files {
		changed[name] = content
	}
	changed["ca.pem"] = []byte("not the pinned bundle")
	for name, bad := range map[string]map[string][]byte{
		"a file unlike its pin": changed,
	} {
		if err := install.store().AdoptGeneration(install.target(), install.roots, wire, bad, nil, time.Now()); err == nil {
			t.Errorf("adopted %s", name)
		}
	}
}
