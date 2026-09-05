//go:build sandboxvm

package vmqual

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

func TestNoCloudRootFilesystemReadback(t *testing.T) {
	for _, tool := range []string{"mkfs.ext4", "debugfs", "e2fsck"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("real ext4 seed test requires e2fsprogs in PATH")
		}
	}
	directory := t.TempDir()
	base := filepath.Join(directory, "base")
	if err := os.MkdirAll(filepath.Join(base, "var", "lib"), 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(directory, "root.ext4")
	if pinned := os.Getenv("TS_VM_NOCLOUD_TEST_ROOTFS"); pinned != "" {
		if !filepath.IsAbs(pinned) {
			t.Fatal("pinned image path must be absolute")
		}
		if output, err := exec.Command("cp", "--reflink=auto", "--", pinned, root).CombinedOutput(); err != nil {
			t.Fatalf("clone pinned image: %v: %s", err, output)
		}
	} else {
		file, err := os.Create(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(32 << 20); err != nil {
			file.Close()
			t.Fatal(err)
		}
		file.Close()
		if output, err := exec.Command("mkfs.ext4", "-F", "-q", "-d", base, root).CombinedOutput(); err != nil {
			t.Fatalf("format test root: %v: %s", err, output)
		}
	}
	seed := vmimage.NoCloudSeed{
		RootFiles:     []vmimage.NoCloudRootFile{{Path: vmimage.GuestControlPath, Mode: 0500, Content: []byte(strings.Repeat("binary\x00", 1<<20))}, {Path: "/opt/terrascale/bootstrap/ts-node", Mode: 0600, Content: []byte(strings.Repeat("signed\x00", 1<<20))}},
		MetaData:      []byte("instance-id: seed-test\n"),
		NetworkConfig: []byte("version: 2\nethernets: {}\n"),
		UserData:      []byte("#cloud-config\n#" + strings.Repeat("x", 2<<20) + "\n"),
	}
	for name, data := range map[string][]byte{"meta-data": seed.MetaData, "network-config": seed.NetworkConfig, "user-data": seed.UserData} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := injectNoCloudRoot(context.Background(), root, directory, seed); err != nil {
		t.Fatal(err)
	}
	seed.MetaData = []byte("instance-id: conflicting-seed\n")
	if err := os.WriteFile(filepath.Join(directory, "meta-data"), seed.MetaData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := injectNoCloudRoot(context.Background(), root, directory, seed); err == nil {
		t.Fatal("accepted conflicting seed contents already present in the root")
	}
}
