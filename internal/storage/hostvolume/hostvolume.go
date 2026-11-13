// Package hostvolume holds the host-side retained volume primitives used by
// the root volume initializer: hardened mount options, filesystem format
// commands for the signed ext4 or xfs pin, and online filesystem growth after
// an OCI volume resize. Authorization (signed permits, device pinning, claim
// provenance) stays in internal/host; this package only performs the bounded
// effect it is asked for on an already pinned device.
package hostvolume

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/storage"
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
