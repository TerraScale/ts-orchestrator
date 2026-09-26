package fixturegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageGuestRejectsHostRootAndPlainDirectory(t *testing.T) {
	if err := verifyMountedGuestRoot("/"); err == nil || !strings.Contains(err.Error(), "non-root") {
		t.Fatalf("host root accepted for image staging: %v", err)
	}
	plain := t.TempDir()
	if err := verifyMountedGuestRoot(plain); err == nil || !strings.Contains(err.Error(), "mount point") {
		t.Fatalf("plain host directory accepted for image staging: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(plain, alias); err != nil {
		t.Fatal(err)
	}
	if err := verifyMountedGuestRoot(alias); err == nil {
		t.Fatal("symlink to a plain host directory accepted for image staging")
	}
}

func TestStageGuestRejectsServiceIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"etc/passwd": "terrascale-orchestrator:x:1001:1001::/var/lib/terrascale-orchestrator-controller:/usr/sbin/nologin\n",
		"etc/group":  "terrascale-orchestrator:x:1001:\n",
	} {
		name := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyGuestAccount(root, 1000, 1000); err == nil {
		t.Fatal("guest account with different numeric ownership accepted")
	}
	if err := verifyGuestAccount(root, 1001, 1001); err != nil {
		t.Fatalf("matching guest account rejected: %v", err)
	}
}
