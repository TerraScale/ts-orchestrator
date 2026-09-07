package vmqualbootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentIssuerReusesExactGrantAndRejectsChangedManifest(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "admission")
	const runID = "0123456789abcdef0123456789abcdef"
	issuer, err := NewPersistentIssuer(directory, runID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := grantManifest(t)
	first, err := issuer.Grant("gru-member-1", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Close(); err != nil {
		t.Fatal(err)
	}
	issuer, err = NewPersistentIssuer(directory, runID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { issuer.Close() })
	second, err := issuer.Grant("gru-member-1", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKeyPEM, second.PublicKeyPEM) || !bytes.Equal(first.SignedGrant, second.SignedGrant) {
		t.Fatal("restart changed original signed source grant")
	}
	manifest.Components[0].CPUWeight++
	if _, err := issuer.Grant("gru-member-1", manifest); err == nil {
		t.Fatal("reissued grant for changed source manifest")
	}
	if _, err := NewPersistentIssuer(directory, "abcdef0123456789abcdef0123456789"); err == nil {
		t.Fatal("accepted issuer from another run")
	}
}

func TestPersistentIssuerRecoversExactPendingGrantAndRejectsCorruptIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "admission")
	const runID = "0123456789abcdef0123456789abcdef"
	issuer, err := NewPersistentIssuer(directory, runID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := grantManifest(t)
	first, err := issuer.Grant("gru-member-1", manifest)
	if err != nil {
		t.Fatal(err)
	}
	issuer.Close()
	filename := filepath.Join(directory, "grant-gru-member-1.json")
	if err := os.Rename(filename, filename+".pending"); err != nil {
		t.Fatal(err)
	}
	issuer, err = NewPersistentIssuer(directory, runID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.Grant("gru-member-1", manifest)
	if err != nil {
		t.Fatal(err)
	}
	issuer.Close()
	if !bytes.Equal(first.SignedGrant, second.SignedGrant) {
		t.Fatal("pending publication regenerated signature")
	}
	path := filepath.Join(directory, "initial-issuer.json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentIssuer(directory, runID); err == nil {
		t.Fatal("corrupt identity was replaced")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "{corrupt" {
		t.Fatal("corrupt evidence overwritten")
	}
}
