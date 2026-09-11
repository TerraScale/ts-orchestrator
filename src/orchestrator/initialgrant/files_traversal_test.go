package initialgrant

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The credential walk must traverse root-owned 0711 directories (the
// published production layout: traversal only, no listing) while running as
// an unprivileged service user. Opening an ancestor O_RDONLY would require
// directory read permission and deny the service user its own credentials;
// the walk must need traversal alone. The child re-exec drops to uid 65534,
// so the credential file is owned by that uid and every directory stays
// root-owned, exactly like the guest and production layouts.
func TestMaterialWalkTraversesPrivateRootDirectories(t *testing.T) {
	if path := strings.TrimSpace(os.Getenv("TS_INITIALGRANT_WALK_CHILD")); path != "" {
		raw, err := readMaterial(path, 1<<20, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "walk child error: %v\n", err)
			os.Exit(1)
		}
		if !bytes.Equal(raw, []byte("captured")) {
			fmt.Fprintf(os.Stderr, "walk child content mismatch\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to build a root-owned credential tree")
	}
	// Build the tree under a controlled root: t.TempDir's parent stays 0700
	// and would deny traversal before the credential directories are reached.
	root, err := os.MkdirTemp("", "initialgrant-tree-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	credential := filepath.Join(root, "terrascale", "orchestrator", "regional", "ca.pem")
	if err := os.MkdirAll(filepath.Dir(credential), 0711); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{root, filepath.Join(root, "terrascale"), filepath.Join(root, "terrascale", "orchestrator"), filepath.Join(root, "terrascale", "orchestrator", "regional")} {
		if err := os.Chown(directory, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0711); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(credential, []byte("captured"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(credential, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	// The test binary lives in a 0700 build directory; give the unprivileged
	// child a world-traversable copy it can execute.
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	publicDir, err := os.MkdirTemp("", "initialgrant-walk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(publicDir) })
	child := filepath.Join(publicDir, "child.test")
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, body, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicDir, 0755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(child, "-test.run", "^TestMaterialWalkTraversesPrivateRootDirectories$")
	command.Env = append(os.Environ(), "TS_INITIALGRANT_WALK_CHILD="+credential)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("traversal-only credential walk failed: %v: %s", err, output)
	}
}
