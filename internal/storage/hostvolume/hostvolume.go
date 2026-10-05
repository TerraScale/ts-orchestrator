// Package hostvolume holds the host-side retained volume primitives used by
// the root volume initializer: hardened mount options, filesystem format
// commands for the signed ext4 or xfs pin, and online filesystem growth after
// an OCI volume resize. Authorization (signed permits, device pinning, claim
// provenance) stays in internal/host; this package only performs the bounded
// effect it is asked for on an already pinned device.
package hostvolume

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

// HardenedOptions are the per-mount options every managed TerraBase volume
// carries. The workload executes its binary from the managed runtime root and
// only stores data, replication state and a claim file on the volume, so it
// never needs set-id, device nodes or exec there.
// noatime is required too: MountFlags and HardenRemount set it, so a legacy
// mount without it is upgraded instead of drifting from fresh mounts.
var HardenedOptions = []string{"nosuid", "nodev", "noexec", "noatime"}

// OptionsHardened reports whether a mountinfo per-mount option field (for
// example "rw,nosuid,nodev,noexec,noatime") carries every hardened option.
func OptionsHardened(options string) bool {
	present := make(map[string]bool)
	for _, option := range strings.Split(options, ",") {
		present[option] = true
	}
	for _, required := range HardenedOptions {
		if !present[required] {
			return false
		}
	}
	return true
}

// MountOptions returns the per-mount option field of mountID from a
// /proc/self/mountinfo formatted reader.
func MountOptions(mountInfo io.Reader, mountID uint64) (string, error) {
	scanner := bufio.NewScanner(mountInfo)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return "", fmt.Errorf("parse mountinfo ID: %w", err)
		}
		if id == mountID {
			return fields[5], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("mount %d is not visible", mountID)
}

// RequireHardened fails unless mountID in mountInfoPath carries every
// hardened option.
func RequireHardened(mountInfoPath string, mountID uint64) error {
	file, err := os.Open(mountInfoPath)
	if err != nil {
		return err
	}
	defer file.Close()
	options, err := MountOptions(file, mountID)
	if err != nil {
		return err
	}
	if !OptionsHardened(options) {
		return fmt.Errorf("managed volume mount lacks %s", strings.Join(HardenedOptions, ","))
	}
	return nil
}

// FilesystemData is the filesystem-specific mount data. ext4 remounts
// read-only on a metadata error instead of continuing to write.
func FilesystemData(fsType string) string {
	if fsType == storage.FileSystemExt4 {
		return "errors=remount-ro"
	}
	return ""
}

// FormatCommand returns the fixed absolute mkfs tool and arguments that create
// fsType with the signed UUID. The pinned device is appended by the caller.
func FormatCommand(fsType, uuid string) (string, []string, error) {
	if !ValidUUID(uuid) {
		return "", nil, errors.New("managed filesystem UUID is invalid")
	}
	switch fsType {
	case storage.FileSystemExt4:
		return "/usr/sbin/mkfs.ext4", []string{"-F", "-U", uuid, "-m", "0", "-E", "lazy_itable_init=0,lazy_journal_init=0"}, nil
	case storage.FileSystemXFS:
		return "/usr/sbin/mkfs.xfs", []string{"-f", "-m", "uuid=" + uuid}, nil
	default:
		return "", nil, fmt.Errorf("managed filesystem type %q is unsupported", fsType)
	}
}

// GrowConfig enables online filesystem growth. The retired managed member
// path keeps it off unless the operator opts in; the C# TerraBase data volume
// always grows. ext4 growth needs CAP_SYS_RESOURCE, which the volume
// initializer unit grants.
type GrowConfig struct {
	Enabled bool
}

// Ext4ResizeBlocks returns the block count passed to EXT4_IOC_RESIZE_FS for a
// device of deviceBytes and a filesystem block size. The kernel treats an
// unchanged count as a no-op and rejects shrinking, so growth stays one-way.
func Ext4ResizeBlocks(deviceBytes, blockSize uint64) (uint64, error) {
	if blockSize < 1024 || blockSize > 65536 || blockSize&(blockSize-1) != 0 {
		return 0, errors.New("ext4 block size is invalid")
	}
	if deviceBytes < blockSize {
		return 0, errors.New("managed block device is smaller than one filesystem block")
	}
	return deviceBytes / blockSize, nil
}

// GrowSlack is the minimum unused device space that triggers an online grow:
// half of OCI's 1 GiB volume resize granularity, so any real resize clears
// it whatever the filesystem's metadata overhead.
const GrowSlack = 512 << 20

// SysfsDeviceBytes reads the size of block device major:minor from the
// sysfs tree rooted at sysRoot. sysfs reports 512-byte sectors.
func SysfsDeviceBytes(sysRoot string, major, minor uint32) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor), "size"))
	if err != nil {
		return 0, fmt.Errorf("read managed block device size: %w", err)
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || sectors == 0 || sectors > math.MaxUint64/512 {
		return 0, errors.New("managed block device size is invalid")
	}
	return sectors * 512, nil
}

// GrowNeeded reports whether a filesystem of fsBlocks*blockSize bytes can grow
// by at least one block group's worth of space (minSlack) on deviceBytes.
// Small tails left by alignment never trigger a resize.
func GrowNeeded(deviceBytes, fsBlocks, blockSize, minSlack uint64) bool {
	if blockSize == 0 || fsBlocks > deviceBytes/blockSize {
		return false
	}
	return deviceBytes-fsBlocks*blockSize >= minSlack
}

// ValidUUID accepts only a canonical lowercase filesystem UUID.
func ValidUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdef", character) {
				return false
			}
		}
	}
	return true
}
