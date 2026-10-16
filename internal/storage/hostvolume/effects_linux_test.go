//go:build linux

package hostvolume

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBtrfsRootExcludesEveryKernelMember(t *testing.T) {
	sysRoot := t.TempDir()
	const uuid = "0d370616-bf07-48e3-90a4-75e58c799c01"
	root := filepath.Join(sysRoot, "fs/btrfs", uuid)
	var want []string
	for i, device := range []string{"8:1", "8:17"} {
		name := "disk" + strconv.Itoa(i)
		whole := filepath.Join(sysRoot, "devices/block", name)
		partition := filepath.Join(whole, name+"1")
		for _, directory := range []string{partition, filepath.Join(sysRoot, "dev/block"), filepath.Join(root, "devices", name), filepath.Join(root, "devinfo", strconv.Itoa(i+1))} {
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(partition, "partition"), []byte("1\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(partition, filepath.Join(sysRoot, "dev/block", device)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "devices", name, "dev"), []byte(device+"\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		for field, value := range map[string]string{"missing": "0", "in_fs_metadata": "1", "replace_target": "0", "fsid": uuid} {
			if err := os.WriteFile(filepath.Join(root, "devinfo", strconv.Itoa(i+1), field), []byte(value+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want = append(want, whole)
	}
	got, err := btrfsRootDevices(sysRoot, unix.Mkdev(8, 1))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete root disks: %v, %v; want %v", got, err, want)
	}
	for field, unsafe := range map[string]string{"missing": "1", "in_fs_metadata": "0", "replace_target": "1", "fsid": "another-filesystem"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(root, "devinfo/2", field)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(unsafe), 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(path, original, 0o644)
			if _, err := btrfsRootDevices(sysRoot, unix.Mkdev(8, 1)); err == nil {
				t.Fatal("incomplete or changing root membership accepted")
			}
		})
	}
	if err := os.Remove(filepath.Join(sysRoot, "dev/block/8:17")); err != nil {
		t.Fatal(err)
	}
	if _, err := btrfsRootDevices(sysRoot, unix.Mkdev(8, 1)); err == nil {
		t.Fatal("unresolvable second root member accepted")
	}
}

func TestBlockDeviceMountedMatchesExactDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(mountInfo), 0o600); err != nil {
		t.Fatal(err)
	}
	for rdev, want := range map[uint64]bool{unix.Mkdev(8, 16): true, unix.Mkdev(8, 32): true, unix.Mkdev(8, 48): false, unix.Mkdev(8, 1): true} {
		if got, err := BlockDeviceMounted(path, rdev); err != nil || got != want {
			t.Fatalf("BlockDeviceMounted(%d:%d) = %v, %v; want %v", unix.Major(rdev), unix.Minor(rdev), got, err, want)
		}
	}
}
