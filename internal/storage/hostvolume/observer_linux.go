//go:build linux

package hostvolume

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// MountPins describe an already initialized retained filesystem. Observation
// never formats, mounts, repairs, or consumes a first-format permit.
type MountPins struct {
	DevicePath, MountPath, FileSystemUUID, FileSystemType string
	UID, GID                                              uint32
}

// MountWitness retains the actual device and filesystem root across a check.
type MountWitness struct {
	initialized      bool
	pins             MountPins
	deviceFD, rootFD int
	device, root     unix.Stat_t
	mountID          uint64
}

func (w *MountWitness) Close() {
	if w != nil && w.initialized {
		if w.deviceFD >= 0 {
			_ = unix.Close(w.deviceFD)
			w.deviceFD = -1
		}
		if w.rootFD >= 0 {
			_ = unix.Close(w.rootFD)
			w.rootFD = -1
		}
	}
}

// ObserveMount extracts the native retained-volume device/mount checks for
// container execution, retaining the open witnesses instead of trusting paths.
func ObserveMount(pins MountPins) (_ *MountWitness, err error) {
	if pins.UID == 0 || pins.GID == 0 || !ValidUUID(pins.FileSystemUUID) ||
		(pins.FileSystemType != "ext4" && pins.FileSystemType != "xfs") ||
		!cleanMountPath(pins.MountPath) || pins.MountPath == "/" {
		return nil, errors.New("incomplete retained mount pins")
	}
	if err := trustedDirectories(filepath.Dir(pins.MountPath)); err != nil {
		return nil, err
	}
	w := &MountWitness{initialized: true, pins: pins, deviceFD: -1, rootFD: -1}
	defer func() {
		if err != nil {
			w.Close()
		}
	}()
	w.deviceFD, w.device, err = openBlockDevice(pins.DevicePath)
	if err != nil {
		return nil, err
	}
	if err := RejectBootOrPartitionDevice(w.device.Rdev); err != nil {
		return nil, err
	}
	if err := trustedDirectories("/dev/disk/by-uuid"); err != nil {
		return nil, err
	}
	var uuid unix.Stat_t
	if err := unix.Stat(filepath.Join("/dev/disk/by-uuid", pins.FileSystemUUID), &uuid); err != nil {
		return nil, err
	}
	if uuid.Mode&unix.S_IFMT != unix.S_IFBLK || uuid.Rdev != w.device.Rdev || uuid.Uid != 0 {
		return nil, errors.New("filesystem UUID does not identify the pinned block device")
	}
	w.rootFD, err = unix.Open(pins.MountPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Fstat(w.rootFD, &w.root); err != nil {
		return nil, err
	}
	if w.root.Dev != w.device.Rdev || w.root.Uid != 0 || w.root.Gid != pins.GID || w.root.Mode&0o7777 != 0o750 {
		return nil, errors.New("retained filesystem root ownership or device differs")
	}
	w.mountID, err = observedMountID(w.rootFD)
	if err != nil {
		return nil, err
	}
	if err := exclusiveHardenedMount("/proc/self/mountinfo", pins.MountPath, w.device.Rdev, pins.FileSystemType, w.mountID); err != nil {
		return nil, err
	}
	for _, child := range []string{"data", "replication"} {
		var stat unix.Stat_t
		if err := unix.Fstatat(w.rootFD, child, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 ||
			stat.Dev != w.device.Rdev || stat.Uid != pins.UID || stat.Gid != pins.GID {
			return nil, fmt.Errorf("unsafe retained %s directory", child)
		}
	}
	if err := w.recheckPaths(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *MountWitness) recheckPaths() error {
	fd, device, err := openBlockDevice(w.pins.DevicePath)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if !sameObject(device, w.device) {
		return errors.New("retained device alias changed during observation")
	}
	var root, uuid unix.Stat_t
	if err := unix.Lstat(w.pins.MountPath, &root); err != nil {
		return err
	}
	if err := unix.Stat(filepath.Join("/dev/disk/by-uuid", w.pins.FileSystemUUID), &uuid); err != nil {
		return err
	}
	var mounted unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, w.pins.MountPath, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &mounted); err != nil {
		return err
	}
	if !sameObject(root, w.root) || uuid.Mode&unix.S_IFMT != unix.S_IFBLK || uuid.Uid != 0 || uuid.Rdev != w.device.Rdev ||
		mounted.Mask&unix.STATX_MNT_ID == 0 || mounted.Mnt_id != w.mountID {
		return errors.New("retained UUID or mounted root changed during observation")
	}
	return nil
}

// Recheck rejects replacement of either path or either held kernel object.
func (w *MountWitness) Recheck() error {
	if w == nil || !w.initialized || w.deviceFD < 0 || w.rootFD < 0 {
		return errors.New("retained mount witness is closed")
	}
	for _, held := range []struct {
		fd   int
		stat unix.Stat_t
	}{{w.deviceFD, w.device}, {w.rootFD, w.root}} {
		var current unix.Stat_t
		if err := unix.Fstat(held.fd, &current); err != nil || !sameObject(current, held.stat) {
			return errors.New("retained open device or root changed")
		}
	}
	current, err := ObserveMount(w.pins)
	if err != nil {
		return err
	}
	defer current.Close()
	if current.mountID != w.mountID || !sameObject(current.device, w.device) || !sameObject(current.root, w.root) {
		return errors.New("retained mount path changed from held witness")
	}
	return nil
}

// VerifyContainerMount inspects the process's actual mount namespace through
// its proc root. No Go thread enters the container's namespaces.
func (w *MountWitness) VerifyContainerMount(hostPID int, destination string) error {
	if hostPID < 2 || !cleanMountPath(destination) || destination == "/" {
		return errors.New("invalid container mount identity")
	}
	if err := w.Recheck(); err != nil {
		return err
	}
	root, err := unix.Open(fmt.Sprintf("/proc/%d/root", hostPID), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, strings.TrimPrefix(destination, "/"), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		return err
	}
	if !sameObject(actual, w.root) {
		return errors.New("container volume is not the held retained filesystem root")
	}
	id, err := observedMountID(fd)
	if err != nil {
		return err
	}
	if err := exclusiveHardenedMount(fmt.Sprintf("/proc/%d/mountinfo", hostPID), destination, w.device.Rdev, w.pins.FileSystemType, id); err != nil {
		return err
	}
	if err := w.Recheck(); err != nil {
		return err
	}
	currentRoot, err := unix.Open(fmt.Sprintf("/proc/%d/root", hostPID), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(currentRoot)
	currentFD, err := unix.Openat2(currentRoot, strings.TrimPrefix(destination, "/"), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer unix.Close(currentFD)
	currentID, err := observedMountID(currentFD)
	if err != nil || currentID != id {
		return errors.New("container retained mount changed during observation")
	}
	return nil
}

func cleanMountPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\\ \t\r\n\x00")
}

func trustedDirectories(path string) error {
	if !cleanMountPath(path) {
		return errors.New("untrusted mount ancestor path")
	}
	for current := path; ; current = filepath.Dir(current) {
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return errors.New("retained path ancestor is writable or untrusted")
		}
		if current == "/" {
			return nil
		}
	}
}

func openBlockDevice(path string) (int, unix.Stat_t, error) {
	if !cleanMountPath(path) || (filepath.Dir(path) != "/dev" && filepath.Dir(path) != "/dev/oracleoci") {
		return -1, unix.Stat_t{}, errors.New("retained block device is not a direct /dev node or OCI alias")
	}
	if err := trustedDirectories(filepath.Dir(path)); err != nil {
		return -1, unix.Stat_t{}, err
	}
	resolved := path
	if filepath.Dir(path) == "/dev/oracleoci" {
		var alias unix.Stat_t
		if err := unix.Lstat(path, &alias); err != nil {
			return -1, unix.Stat_t{}, err
		}
		target, err := os.Readlink(path)
		if err != nil || alias.Uid != 0 || alias.Mode&unix.S_IFMT != unix.S_IFLNK ||
			target != "../"+filepath.Base(target) || !cleanMountPath(filepath.Join("/dev", filepath.Base(target))) {
			return -1, unix.Stat_t{}, errors.New("retained OCI alias is not a root-owned one-hop device link")
		}
		resolved = filepath.Join("/dev", filepath.Base(target))
	}
	fd, err := unix.Open(resolved, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Uid != 0 {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("retained device is not an exact root-owned block node")
	}
	return fd, stat, nil
}

func sameObject(left, right unix.Stat_t) bool {
	return left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Dev == right.Dev && left.Rdev == right.Rdev && left.Ino == right.Ino
}

func observedMountID(fd int) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, errors.New("kernel did not identify the retained mount")
	}
	return stat.Mnt_id, nil
}

func exclusiveHardenedMount(path, target string, device uint64, fsType string, visible uint64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	want := fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device))
	found := false
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 3 || fields[2] != want {
			continue
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 10 || separator < 0 || separator+3 >= len(fields) || fields[3] != "/" ||
			fields[4] != target || fields[separator+1] != fsType || !OptionsHardened(fields[5]) ||
			!strings.Contains(","+fields[5]+",", ",rw,") || !strings.Contains(","+fields[separator+3]+",", ",rw,") {
			return errors.New("retained device has another, unhardened, or partial-root mount")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return err
		}
		found = found || id == visible
	}
	if err := scan.Err(); err != nil {
		return err
	}
	if !found || visible == 0 {
		return errors.New("retained filesystem is not the visible pinned mount")
	}
	return nil
}
