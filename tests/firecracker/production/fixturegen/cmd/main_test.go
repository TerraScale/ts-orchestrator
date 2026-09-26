package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectKeyInsideMaterialIncludingSymlinkAlias(t *testing.T) {
	root := t.TempDir()
	material := filepath.Join(root, "material")
	guest := filepath.Join(material, "controllers", "seed-a", "guest-root", "var", "lib", "terrascale-orchestrator-secrets")
	if err := os.MkdirAll(guest, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(guest, "root.pem")
	if err := os.WriteFile(inside, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectKeyInsideMaterial(material, inside); err == nil {
		t.Fatal("guest material accepted as root signing key")
	}
	alias := filepath.Join(root, "alias.pem")
	if err := os.Symlink(inside, alias); err != nil {
		t.Fatal(err)
	}
	if err := rejectKeyInsideMaterial(material, alias); err == nil {
		t.Fatal("symlink alias to guest root key accepted")
	}
	outside := filepath.Join(root, "offline-root.pem")
	if err := os.WriteFile(outside, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectKeyInsideMaterial(material, outside); err != nil {
		t.Fatal(err)
	}
}
