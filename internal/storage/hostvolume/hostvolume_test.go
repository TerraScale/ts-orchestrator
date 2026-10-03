package hostvolume

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const mountInfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
31 22 8:16 / /srv/ts-managed/m/volume rw,nosuid,nodev,noexec,noatime shared:2 - ext4 /dev/sdb rw,errors=remount-ro
32 22 8:32 / /srv/ts-managed/n/volume rw,relatime shared:3 - xfs /dev/sdc rw
`

func TestOptionsHardenedRequiresEveryFlag(t *testing.T) {
	cases := map[string]bool{
		"rw,nosuid,nodev,noexec,noatime":  true,
		"rw,noexec,nodev,nosuid,noatime":  true,
		"rw,noexec,nodev,nosuid":          false,
		"rw,nosuid,nodev,noexec,relatime": false,
		"rw,nosuid,nodev":                 false,
		"rw,relatime":                     false,
		"":                                false,
		"rw,nosuidx,nodev,noexec":         false,
	}
	for options, want := range cases {
		if got := OptionsHardened(options); got != want {
			t.Fatalf("OptionsHardened(%q) = %v, want %v", options, got, want)
		}
	}
}

func TestMountOptionsSelectsExactMountID(t *testing.T) {
	options, err := MountOptions(strings.NewReader(mountInfo), 31)
	if err != nil || options != "rw,nosuid,nodev,noexec,noatime" {
		t.Fatalf("mount 31 options = %q, %v", options, err)
	}
	if _, err := MountOptions(strings.NewReader(mountInfo), 99); err == nil {
		t.Fatal("missing mount ID was found")
	}
	if _, err := MountOptions(strings.NewReader("x 1 8:1 / / rw - ext4 /dev/sda rw\n"), 1); err == nil {
		t.Fatal("corrupt mountinfo was accepted")
	}
}

func TestRequireHardenedReadsMountInfoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(mountInfo), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireHardened(path, 31); err != nil {
		t.Fatalf("hardened mount rejected: %v", err)
	}
	if err := RequireHardened(path, 32); err == nil {
		t.Fatal("unhardened mount accepted")
	}
}

func TestFormatCommandPinsUUIDAndSupportsXFS(t *testing.T) {
	uuid := "123e4567-e89b-12d3-a456-426614174000"
	tool, args, err := FormatCommand("ext4", uuid)
	if err != nil || tool != "/usr/sbin/mkfs.ext4" || !slices.Contains(args, uuid) {
		t.Fatalf("ext4 command = %s %v, %v", tool, args, err)
	}
	tool, args, err = FormatCommand("xfs", uuid)
	if err != nil || tool != "/usr/sbin/mkfs.xfs" || !slices.Contains(args, "uuid="+uuid) {
		t.Fatalf("xfs command = %s %v, %v", tool, args, err)
	}
	for _, bad := range []struct{ fs, uuid string }{
		{"btrfs", uuid},
		{"ext4", "123E4567-E89B-12D3-A456-426614174000"},
		{"ext4", "not-a-uuid"},
		{"xfs", uuid + "0"},
		{"ext4", "123e4567-e89b-12d3-a456-42661417400g"},
	} {
		if _, _, err := FormatCommand(bad.fs, bad.uuid); err == nil {
			t.Fatalf("FormatCommand(%q, %q) accepted", bad.fs, bad.uuid)
		}
	}
}

func TestFilesystemData(t *testing.T) {
	if FilesystemData("ext4") != "errors=remount-ro" || FilesystemData("xfs") != "" {
		t.Fatal("unexpected filesystem mount data")
	}
}

func TestExt4ResizeBlocks(t *testing.T) {
	blocks, err := Ext4ResizeBlocks(100<<30+123, 4096)
	if err != nil || blocks != (100<<30)/4096 {
		t.Fatalf("blocks = %d, %v", blocks, err)
	}
	for _, size := range []uint64{0, 512, 3000, 1 << 17} {
		if _, err := Ext4ResizeBlocks(1<<30, size); err == nil {
			t.Fatalf("block size %d accepted", size)
		}
	}
	if _, err := Ext4ResizeBlocks(1000, 4096); err == nil {
		t.Fatal("device smaller than a block accepted")
	}
}

func TestSysfsDeviceBytesReadsSectors(t *testing.T) {
	root := t.TempDir()
	node := filepath.Join(root, "dev", "block", "8:16")
	if err := os.MkdirAll(node, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(node, "size"), []byte("104857600\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if size, err := SysfsDeviceBytes(root, 8, 16); err != nil || size != 50<<30 {
		t.Fatalf("size = %d, %v; want 50 GiB", size, err)
	}
	if _, err := SysfsDeviceBytes(root, 8, 32); err == nil {
		t.Fatal("missing device reported a size")
	}
	for _, bad := range []string{"0", "garbage", "-1"} {
		if err := os.WriteFile(filepath.Join(node, "size"), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := SysfsDeviceBytes(root, 8, 16); err == nil {
			t.Fatalf("size %q was accepted", bad)
		}
	}
}

func TestGrowSlackTriggersOnEveryWholeGiBResize(t *testing.T) {
	const block = 4096
	// XFS reports roughly 0.3% and ext4 up to about 2% of the device as
	// metadata overhead below statfs blocks; a 1 GiB resize must still clear
	// the gate on large volumes.
	for _, size := range []uint64{50 << 30, 64 << 30, 1 << 40} {
		fsBlocks := (size - size/50) / block
		if !GrowNeeded(size+1<<30, fsBlocks, block, GrowSlack) {
			t.Fatalf("a +1 GiB resize of a %d GiB volume did not trigger growth", size>>30)
		}
	}
	if GrowNeeded(50<<30, (50<<30-200<<20)/block, block, GrowSlack) {
		t.Fatal("metadata overhead of an unresized small volume triggered growth")
	}
}

func TestGrowNeededIgnoresSmallTailsAndNeverShrinks(t *testing.T) {
	const block = 4096
	fsBlocks := uint64(50<<30) / block
	if GrowNeeded(50<<30, fsBlocks, block, 128<<20) {
		t.Fatal("equal sizes need growth")
	}
	if GrowNeeded(50<<30+64<<20, fsBlocks, block, 128<<20) {
		t.Fatal("small tail triggered growth")
	}
	if !GrowNeeded(100<<30, fsBlocks, block, 128<<20) {
		t.Fatal("doubled device did not need growth")
	}
	if GrowNeeded(40<<30, fsBlocks, block, 128<<20) {
		t.Fatal("smaller device requested growth")
	}
	if GrowNeeded(100<<30, fsBlocks, 0, 0) {
		t.Fatal("zero block size requested growth")
	}
}
