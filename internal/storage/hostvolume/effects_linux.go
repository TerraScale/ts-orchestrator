//go:build linux

package hostvolume

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"golang.org/x/sys/unix"
)

// MountFlags are the hardened per-mount flags applied to managed volumes.
const MountFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME

// ext4IocResizeFS is EXT4_IOC_RESIZE_FS, _IOW('f', 16, __u64). It needs
// CAP_SYS_RESOURCE, which the volume initializer unit does not grant by
// default; see GrowConfig.
const ext4IocResizeFS = 0x40086610

// HardenRemount applies MountFlags to an existing mount at target without
// touching the filesystem superblock. A bind remount changes only per-mount
// flags, so a running workload keeps its open files.
func HardenRemount(target string) error {
	if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|MountFlags, ""); err != nil {
		return fmt.Errorf("harden managed volume mount: %w", err)
	}
	return nil
}

// DeviceBytes returns the kernel's current size of the block device rdev.
// The initializer pins its device through an O_PATH descriptor, which
// ioctl(2) rejects, so the size is read from the same sysfs node Rescan
// writes to.
func DeviceBytes(rdev uint64) (uint64, error) {
	return SysfsDeviceBytes("/sys", unix.Major(rdev), unix.Minor(rdev))
}

// Rescan asks the SCSI layer to re-read the capacity of the device rdev after
// an OCI volume resize. Devices without a rescan attribute (virtio-blk)
// update their capacity on their own and are skipped.
func Rescan(rdev uint64) error {
	path := filepath.Join(fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(rdev), unix.Minor(rdev)), "device", "rescan")
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open managed device rescan: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString("1"); err != nil {
		return fmt.Errorf("rescan managed device: %w", err)
	}
	return nil
}

// Grow rescans the pinned device and grows the mounted filesystem at
// mountPath to the device size. It is idempotent and never shrinks. The
// caller must already have verified that mountPath is the exclusive mount of
// the pinned device.
func Grow(ctx context.Context, cfg GrowConfig, mountPath string, rdev uint64, fsType string) (bool, error) {
	if !cfg.Enabled {
		return false, nil
	}
	if err := Rescan(rdev); err != nil {
		return false, err
	}
	deviceBytes, err := DeviceBytes(rdev)
	if err != nil {
		return false, err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(mountPath, &stat); err != nil {
		return false, fmt.Errorf("inspect managed filesystem: %w", err)
	}
	blockSize := uint64(stat.Bsize)
	// statfs reports blocks net of metadata overhead, so slack is never
	// exact. GrowSlack is half the OCI resize granularity: every real resize
	// clears it, and an attempt on a filesystem that already spans its device
	// is a no-op for both ext4 and xfs, so the gate only saves needless work.
	if !GrowNeeded(deviceBytes, stat.Blocks, blockSize, GrowSlack) {
		return false, nil
	}
	if err := growFilesystem(ctx, mountPath, deviceBytes, blockSize, fsType); err != nil {
		return false, err
	}
	var after unix.Statfs_t
	if err := unix.Statfs(mountPath, &after); err != nil {
		return false, fmt.Errorf("inspect grown managed filesystem: %w", err)
	}
	return after.Blocks > stat.Blocks, nil
}

func growFilesystem(ctx context.Context, mountPath string, deviceBytes, blockSize uint64, fsType string) error {
	switch fsType {
	case storage.FileSystemExt4:
		blocks, err := Ext4ResizeBlocks(deviceBytes, blockSize)
		if err != nil {
			return err
		}
		directory, err := unix.Open(mountPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(directory)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(directory), ext4IocResizeFS, uintptr(unsafe.Pointer(&blocks))); errno != 0 {
			return fmt.Errorf("grow managed ext4 filesystem: %w", errno)
		}
		return nil
	case storage.FileSystemXFS:
		output, err := exec.CommandContext(ctx, "/usr/sbin/xfs_growfs", "-d", mountPath).CombinedOutput()
		if err != nil {
			if len(output) > 512 {
				output = output[:512]
			}
			return fmt.Errorf("grow managed xfs filesystem: %w: %s", err, output)
		}
		return nil
	default:
		return fmt.Errorf("managed filesystem type %q cannot grow", fsType)
	}
}
