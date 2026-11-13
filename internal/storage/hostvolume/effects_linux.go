//go:build linux

package hostvolume

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// MountFlags are the hardened per-mount flags applied to managed volumes.
const MountFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME

// BlockDeviceMounted reports whether block device rdev has any mount in a
// /proc/self/mountinfo formatted file.
func BlockDeviceMounted(path string, rdev uint64) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	want := fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev))
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) > 4 && fields[2] == want {
			return true, nil
		}
	}
	return false, scan.Err()
}

// RejectBootOrPartitionDevice fails for a partition, a disk with partitions
// or kernel holders, and the disk the host root filesystem is on.
func RejectBootOrPartitionDevice(rdev uint64) error {
	target, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(rdev), unix.Minor(rdev)))
	if err != nil {
		return errors.New("managed device has no kernel block identity")
	}
	name := filepath.Base(target)
	if _, err := os.Stat(filepath.Join(target, "partition")); err == nil {
		return errors.New("managed device is a partition")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	children, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	for _, child := range children {
		if strings.HasPrefix(child.Name(), name) && child.Name() != name {
			if _, err := os.Stat(filepath.Join(target, child.Name(), "partition")); err == nil {
				return errors.New("managed device contains partitions")
			}
		}
	}
	holders, err := os.ReadDir(filepath.Join(target, "holders"))
	if err != nil || len(holders) != 0 {
		return errors.New("managed device has kernel holders")
	}
	rootDevice, fsType, source, err := rootMountIdentity("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	var roots []string
	if fsType == "btrfs" {
		var stat unix.Stat_t
		if !cleanMountPath(source) || unix.Stat(source, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK {
			return errors.New("btrfs root source has no exact block identity")
		}
		roots, err = btrfsRootDevices("/sys", stat.Rdev)
	} else {
		var root string
		root, err = wholeKernelDevice("/sys", rootDevice)
		roots = []string{root}
	}
	if err != nil || len(roots) == 0 {
		return errors.New("complete host root block device set cannot be identified")
	}
	if slices.Contains(roots, target) {
		return errors.New("managed device is the host boot disk")
	}
	return nil
}

func wholeKernelDevice(sysRoot, device string) (string, error) {
	target, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "dev/block", device))
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(target, "partition")); err == nil {
		return filepath.Dir(target), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return target, nil
}

// Btrfs reports an anonymous mount device. Select its kernel filesystem by the
// root source, then require every metadata member present before excluding all.
func btrfsRootDevices(sysRoot string, source uint64) ([]string, error) {
	filesystems, err := os.ReadDir(filepath.Join(sysRoot, "fs/btrfs"))
	if err != nil {
		return nil, err
	}
	want := fmt.Sprintf("%d:%d", unix.Major(source), unix.Minor(source))
	var roots []string
	matches := 0
	for _, filesystem := range filesystems {
		if !ValidUUID(filesystem.Name()) {
			continue
		}
		root := filepath.Join(sysRoot, "fs/btrfs", filesystem.Name())
		members, err := os.ReadDir(filepath.Join(root, "devices"))
		if err != nil {
			return nil, err
		}
		var devices []string
		matched := false
		for _, member := range members {
			data, err := os.ReadFile(filepath.Join(root, "devices", member.Name(), "dev"))
			if err != nil {
				return nil, err
			}
			device := strings.TrimSpace(string(data))
			var major, minor uint32
			if _, err := fmt.Sscanf(device, "%d:%d", &major, &minor); err != nil || device != fmt.Sprintf("%d:%d", major, minor) || slices.Contains(devices, device) {
				return nil, errors.New("btrfs member has an invalid or repeated kernel identity")
			}
			devices = append(devices, device)
			matched = matched || device == want
		}
		if !matched {
			continue
		}
		metadata, err := os.ReadDir(filepath.Join(root, "devinfo"))
		if err != nil || len(metadata) == 0 || len(metadata) != len(devices) {
			return nil, errors.New("btrfs root device membership is incomplete")
		}
		for _, member := range metadata {
			for name, expected := range map[string]string{"missing": "0", "in_fs_metadata": "1", "replace_target": "0", "fsid": filesystem.Name()} {
				value, err := os.ReadFile(filepath.Join(root, "devinfo", member.Name(), name))
				if err != nil || strings.TrimSpace(string(value)) != expected {
					return nil, errors.New("btrfs root has a missing, replacing, or unverified metadata member")
				}
			}
		}
		matches++
		for _, device := range devices {
			whole, err := wholeKernelDevice(sysRoot, device)
			if err != nil {
				return nil, err
			}
			roots = append(roots, whole)
		}
	}
	if matches != 1 || len(roots) == 0 {
		return nil, errors.New("btrfs root does not identify one complete kernel filesystem")
	}
	return roots, nil
}

func rootMountIdentity(path string) (string, string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) > 4 && fields[4] == "/" {
			for i := 6; i+3 < len(fields); i++ {
				if fields[i] == "-" {
					return fields[2], fields[i+1], fields[i+2], nil
				}
			}
			return "", "", "", errors.New("host root mount identity is malformed")
		}
	}
	return "", "", "", errors.Join(errors.New("host root mount is unavailable"), scan.Err())
}
