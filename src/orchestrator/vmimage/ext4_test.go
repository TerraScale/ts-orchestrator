package vmimage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testUbuntuFSTab = "LABEL=cloudimg-rootfs\t/\text4\tdiscard,commit=30,errors=remount-ro\t0\t1\n" +
	"LABEL=BOOT\t/boot\text4\tdefaults\t0\t2\n" +
	"LABEL=UEFI\t/boot/efi\tvfat\tumask=0077\t0\t1\n"

func TestVerifyUbuntuIdentityAndSanitizeFSTab(t *testing.T) {
	t.Parallel()
	identity, err := verifyUbuntuIdentity([]byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"Ubuntu 24.04.3 LTS (Noble Numbat)\"\n"), "24.04.3")
	if err != nil || identity.ID != "ubuntu" || identity.VersionID != "24.04" {
		t.Fatalf("identity = %#v, err = %v", identity, err)
	}
	if _, err := verifyUbuntuIdentity([]byte("ID=debian\nVERSION_ID=\"24.04\"\nVERSION=\"Ubuntu 24.04.3 LTS\"\n"), "24.04.3"); err == nil {
		t.Fatal("non-Ubuntu identity was accepted")
	}
	sanitized, err := sanitizeUbuntuFSTab([]byte(testUbuntuFSTab))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(strings.Replace(testUbuntuFSTab, "LABEL=BOOT", "#ABEL=BOOT", 1), "LABEL=UEFI", "#ABEL=UEFI", 1)
	if string(sanitized) != want || len(sanitized) != len(testUbuntuFSTab) {
		t.Fatalf("sanitized fstab = %q, want %q", sanitized, want)
	}
	for name, invalid := range map[string]string{
		"extra mount":  testUbuntuFSTab + "LABEL=EXTRA /srv ext4 defaults 0 2\n",
		"wrong boot":   strings.Replace(testUbuntuFSTab, "defaults\t0\t2", "ro\t0\t2", 1),
		"missing root": strings.SplitN(testUbuntuFSTab, "\n", 2)[1],
	} {
		if _, err := sanitizeUbuntuFSTab([]byte(invalid)); err == nil {
			t.Fatalf("%s fstab was accepted", name)
		}
	}
}

type ext4Call struct {
	executable string
	args       []string
}

type ext4TestRunner struct {
	t          *testing.T
	image      string
	fstab      []byte
	blockSize  int64
	block      int64
	calls      []ext4Call
	fstabReads int
}

func (runner *ext4TestRunner) Output(_ context.Context, executable string, args ...string) ([]byte, error) {
	runner.calls = append(runner.calls, ext4Call{executable: executable, args: append([]string(nil), args...)})
	if len(args) < 2 || args[len(args)-1] != runner.image {
		return nil, errors.New("unexpected filesystem-tool arguments")
	}
	switch {
	case args[0] == "-R" && args[1] == "cat /usr/lib/os-release":
		return []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"Ubuntu 24.04.3 LTS (Noble Numbat)\"\n"), nil
	case args[0] == "-R" && args[1] == "cat /etc/fstab":
		runner.fstabReads++
		if runner.fstabReads == 1 {
			return append([]byte(nil), runner.fstab...), nil
		}
		file, err := os.Open(runner.image)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		got := make([]byte, len(runner.fstab))
		_, err = file.ReadAt(got, runner.block*runner.blockSize)
		return got, err
	case args[0] == "-R" && args[1] == "stats":
		return []byte("Block size: 1024\n"), nil
	case args[0] == "-R" && args[1] == "blocks /etc/fstab":
		return []byte("2\n"), nil
	case len(args) == 2 && args[0] == "-fn":
		return []byte("clean\n"), nil
	default:
		return nil, errors.New("unexpected filesystem-tool call")
	}
}

func TestExt4PreparerPatchesDeclaredBlockAndChecksFilesystem(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	image := filepath.Join(directory, "rootfs.ext4")
	backing := make([]byte, 4096)
	copy(backing[2048:], []byte(testUbuntuFSTab))
	if err := os.WriteFile(image, backing, 0o600); err != nil {
		t.Fatal(err)
	}
	debugReal := writeExecutableFixture(t, directory, "debugfs.real")
	debugLink := filepath.Join(directory, "debugfs")
	if err := os.Symlink(debugReal, debugLink); err != nil {
		t.Fatal(err)
	}
	e2fsck := writeExecutableFixture(t, directory, "e2fsck")
	runner := &ext4TestRunner{t: t, image: image, fstab: []byte(testUbuntuFSTab), blockSize: 1024, block: 2}
	inspection, err := (Ext4Preparer{DebugFSPath: debugLink, E2FSCKPath: e2fsck, Runner: runner}).Prepare(context.Background(), image, "24.04.3")
	if err != nil {
		t.Fatal(err)
	}
	if inspection.OSID != "ubuntu" || inspection.OSVersionID != "24.04" || inspection.FilesystemCheck != "e2fsck -fn" ||
		!reflect.DeepEqual(inspection.SanitizedMounts, []string{"/boot", "/boot/efi"}) {
		t.Fatalf("inspection = %#v", inspection)
	}
	if len(runner.calls) != 6 || runner.calls[0].executable != debugReal || runner.calls[5].executable != e2fsck ||
		!reflect.DeepEqual(runner.calls[5].args, []string{"-fn", image}) {
		t.Fatalf("filesystem calls = %#v", runner.calls)
	}
	got, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, _ := sanitizeUbuntuFSTab([]byte(testUbuntuFSTab))
	if !bytes.Equal(got[2048:2048+len(sanitized)], sanitized) {
		t.Fatal("fstab block was not patched exactly")
	}
}

func writeExecutableFixture(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
