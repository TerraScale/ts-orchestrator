package bootstrapstart

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// After a reboot empties the in-memory credential directory, the exact Vault
// versions the manifest and the adopted generation pin, plus the chain's
// durable copy, are again what restart admission accepts (TS-745).
func TestRestoredMaterialPassesRestartAdmission(t *testing.T) {
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	store := install.store()
	store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	if err := store.AdoptGeneration("controller-a", wire, files); err != nil {
		t.Fatal(err)
	}
	if kept, err := os.ReadFile(store.chainCopy); err != nil || !bytes.Equal(kept, wire) {
		t.Fatalf("durable chain copy = %v, want the adopted chain", err)
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(chain, install.roots, install.expected)
	if err != nil {
		t.Fatal(err)
	}
	refs := materialReferences(install.manifest, &verified[len(verified)-1])
	vault := map[string][]byte{}
	for name := range refs {
		vault[refs[name].SHA256] = install.read(name)
	}
	read := func(_ context.Context, reference bootstrap.SecretReference) ([]byte, error) {
		return bytes.Clone(vault[reference.SHA256]), nil
	}

	// A disk copy without a Vault version is never removed.
	install.write("stray.key", []byte("unrecovered"))
	contents, err := readReferences(t.Context(), refs, read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.removeDiskCopies(contents, wire); err == nil {
		t.Fatal("removed disk copies beside a file with no Vault copy")
	}
	if err := os.Remove(filepath.Join(install.dir, "stray.key")); err != nil {
		t.Fatal(err)
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("a refused removal changed the directory: %v", err)
	}
	removed, err := store.removeDiskCopies(contents, wire)
	if err != nil || removed != len(refs)+1 {
		t.Fatalf("removed %d disk copies, %v; want %d", removed, err, len(refs)+1)
	}

	// The reboot: an empty directory, filled from Vault and the copy.
	missing, err := store.missing(refs)
	if err != nil || len(missing) != len(refs) {
		t.Fatalf("missing = %d, %v; want every pin", len(missing), err)
	}
	if err := store.fill(contents, wire); err != nil {
		t.Fatal(err)
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("restart admission of the restored directory: %v", err)
	}
	if missing, err := store.missing(refs); err != nil || len(missing) != 0 {
		t.Fatalf("missing after restore = %d, %v", len(missing), err)
	}
	// A live chain that is not its durable copy is never silently kept.
	if err := store.fill(nil, append(bytes.Clone(wire), ' ')); err == nil {
		t.Fatal("kept an installed chain that differs from its durable copy")
	}
	if note, err := store.checkRestore(t.Context(), refs, wire, read); err != nil {
		t.Fatalf("check after restore: %v", err)
	} else if note == "" {
		t.Fatal("check printed nothing")
	}
}

// A release that predates the durable chain copy adopts a generation without
// updating it: restore keeps the installed chain that extends the copy, and
// never a shorter or unrelated one.
func TestRestoreKeepsTheNewerInstalledChain(t *testing.T) {
	install := newGenerationInstall(t)
	first, _ := install.signedGeneration()
	chain, err := bootstrap.DecodeMaterialGenerationChain(first)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := trust.Fingerprint(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	next, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 2, previous),
		time.Now().Add(-time.Minute), time.Now().AddDate(0, 6, 0), install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	both, err := bootstrap.EncodeMaterialGenerationChain(append(chain, next))
	if err != nil {
		t.Fatal(err)
	}
	if kept, newer := newerChain(first, both); !newer || !bytes.Equal(kept, both) {
		t.Fatal("restore kept a durable copy older than the installed chain")
	}
	for _, installed := range [][]byte{first, []byte("not a chain"), nil} {
		if kept, newer := newerChain(both, installed); newer || !bytes.Equal(kept, both) {
			t.Fatalf("restore replaced the durable copy with %q", installed)
		}
	}
}
