package vmguest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	storageMountInfoPath     = "/proc/self/mountinfo"
	maxStorageMountInfoBytes = 1 << 20
	storageProbeBytes        = 4 << 10
	storageFillBytes         = 64 << 20
	storageDiagnosticChunk   = 1 << 20
	storageFillName          = ".vmguest-recovery-fill"
	storageFilesystem        = "ext4"
	storageFSCKPath          = "/usr/sbin/e2fsck"
	storageGrowPath          = "/usr/sbin/resize2fs"
)

type storageMount struct {
	id         uint64
	major      uint32
	minor      uint32
	path       string
	filesystem string
	readOnly   bool
}

type storageTarget struct {
	observation    StorageObservation
	devicePresent  bool
	deviceMounted  bool
	mountID        uint64
	dataRootExists bool
}

type storageSyncWriter interface {
	io.Writer
	Sync() error
}

func storageDiagnostic(ctx context.Context, config Config, action StorageAction) (StorageObservation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validStorageAction(action) || config.DataDevice != DefaultDataDevice {
		return StorageObservation{}, errors.New("vmguest: storage diagnostic configuration is invalid")
	}
	if action != StorageActionObserve {
		if err := acquireStorageWrite(ctx); err != nil {
			return StorageObservation{Action: action, Device: config.DataDevice}, err
		}
		defer releaseStorageWrite()
	}
	target, err := inspectStorageTarget(ctx, config.DataRoot, config.DataDevice, action)
	if err != nil {
		return target.observation, err
	}
	switch action {
	case StorageActionObserve:
		return target.observation, nil
	case StorageActionFSCKRepair, StorageActionFSCKCheck:
		return runStorageFSCK(ctx, config, target, action)
	case StorageActionProbeWrite:
		return runStorageProbe(ctx, config, target)
	case StorageActionFillENOSPC:
		return runStorageFill(ctx, config, target)
	case StorageActionClearFill:
		return runStorageClearFill(ctx, config, target)
	case StorageActionGrow:
		return runStorageGrow(ctx, config, target)
	default:
		return target.observation, errors.New("vmguest: storage diagnostic action is invalid")
	}
}

func inspectStorageTarget(ctx context.Context, dataRoot, device string, action StorageAction) (storageTarget, error) {
	target := storageTarget{observation: StorageObservation{Action: action, Device: device}}
	if err := ctx.Err(); err != nil {
		return target, err
	}
	var deviceStat unix.Stat_t
	if err := unix.Lstat(device, &deviceStat); err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
			target.observation.Errno = StorageErrnoENODEV
			return target, nil
		}
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: inspect storage device")
	}
	if deviceStat.Mode&unix.S_IFMT != unix.S_IFBLK || deviceStat.Uid != 0 || deviceStat.Nlink != 1 || deviceStat.Rdev == 0 {
		return target, errors.New("vmguest: storage device identity is unsafe")
	}
	target.devicePresent = true
	deviceMajor, deviceMinor := unix.Major(uint64(deviceStat.Rdev)), unix.Minor(uint64(deviceStat.Rdev))
	mounts, err := loadStorageMounts(ctx)
	if err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, err
	}
	var selected *storageMount
	for index := range mounts {
		mount := &mounts[index]
		if mount.major != deviceMajor || mount.minor != deviceMinor {
			continue
		}
		target.deviceMounted = true
		if pathInside(mount.path, dataRoot) && (selected == nil || len(mount.path) > len(selected.path)) {
			selected = mount
		}
	}
	if selected == nil {
		target.observation.Errno = StorageErrnoENODEV
		return target, nil
	}
	target.observation.MountPath = selected.path
	target.observation.Filesystem = selected.filesystem
	target.observation.Mounted = true
	target.observation.ReadOnly = selected.readOnly
	target.mountID = selected.id

	mountFD, err := openStorageRoot(ctx, selected.path, false)
	if err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: open configured storage mount")
	}
	defer unix.Close(mountFD)
	var mountStat unix.Stat_t
	actualMountID, mountIDErr := descriptorMountID(mountFD)
	if err := unix.Fstat(mountFD, &mountStat); err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: inspect configured storage mount")
	}
	if mountIDErr != nil {
		if setStorageErrno(&target.observation, mountIDErr) {
			return target, nil
		}
		return target, errors.New("vmguest: inspect configured storage mount identity")
	}
	if actualMountID != selected.id ||
		unix.Major(uint64(mountStat.Dev)) != deviceMajor || unix.Minor(uint64(mountStat.Dev)) != deviceMinor {
		return target, errors.New("vmguest: configured storage mount identity changed")
	}
	var statistics unix.Statfs_t
	if err := unix.Fstatfs(mountFD, &statistics); err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: inspect storage capacity")
	}
	total, available, err := storageCapacity(statistics)
	if err != nil {
		return target, err
	}
	target.observation.TotalBytes = total
	target.observation.AvailableBytes = available
	target.observation.ReadOnly = target.observation.ReadOnly || statistics.Flags&unix.ST_RDONLY != 0
	target.observation.Healthy = selected.filesystem == storageFilesystem && !target.observation.ReadOnly

	if _, err := os.Lstat(dataRoot); errors.Is(err, os.ErrNotExist) {
		return target, nil
	} else if err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: inspect configured persistent root")
	}
	dataFD, err := openStorageRoot(ctx, dataRoot, false)
	if err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: open configured persistent root")
	}
	defer unix.Close(dataFD)
	dataMountID, err := descriptorMountID(dataFD)
	if err != nil {
		if setStorageErrno(&target.observation, err) {
			return target, nil
		}
		return target, errors.New("vmguest: inspect configured persistent root mount")
	}
	if dataMountID != target.mountID {
		return target, errors.New("vmguest: configured persistent root crosses a storage mount")
	}
	target.dataRootExists = true
	return target, nil
}

func storageCapacity(statistics unix.Statfs_t) (uint64, uint64, error) {
	if statistics.Bsize <= 0 {
		return 0, 0, errors.New("vmguest: storage block size is invalid")
	}
	blockSize := uint64(statistics.Bsize)
	if uint64(statistics.Blocks) > math.MaxUint64/blockSize || uint64(statistics.Bavail) > math.MaxUint64/blockSize {
		return 0, 0, errors.New("vmguest: storage capacity overflows")
	}
	return uint64(statistics.Blocks) * blockSize, uint64(statistics.Bavail) * blockSize, nil
}

func loadStorageMounts(ctx context.Context) ([]storageMount, error) {
	file, err := os.Open(storageMountInfoPath)
	if err != nil {
		return nil, errors.New("vmguest: open storage mount information")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStorageMountInfoBytes+1))
	if err != nil || len(data) > maxStorageMountInfoBytes {
		return nil, errors.New("vmguest: read bounded storage mount information")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return parseStorageMounts(string(data))
}

func parseStorageMounts(data string) ([]storageMount, error) {
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	result := make([]storageMount, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) {
			return nil, errors.New("vmguest: storage mount information is invalid")
		}
		mountID, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || mountID == 0 {
			return nil, errors.New("vmguest: storage mount id is invalid")
		}
		deviceParts := strings.Split(fields[2], ":")
		if len(deviceParts) != 2 {
			return nil, errors.New("vmguest: storage mount device is invalid")
		}
		major, majorErr := strconv.ParseUint(deviceParts[0], 10, 32)
		minor, minorErr := strconv.ParseUint(deviceParts[1], 10, 32)
		mountPath, pathErr := decodeMountInfoPath(fields[4])
		if majorErr != nil || minorErr != nil || pathErr != nil || !filepath.IsAbs(mountPath) || filepath.Clean(mountPath) != mountPath {
			return nil, errors.New("vmguest: storage mount identity is invalid")
		}
		result = append(result, storageMount{
			id:         mountID,
			major:      uint32(major),
			minor:      uint32(minor),
			path:       mountPath,
			filesystem: fields[separator+1],
			readOnly:   mountOption(fields[5], "ro"),
		})
	}
	if len(result) == 0 {
		return nil, errors.New("vmguest: storage mount information is empty")
	}
	return result, nil
}

func decodeMountInfoPath(value string) (string, error) {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			if value[index] == 0 {
				return "", errors.New("mount path contains NUL")
			}
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", errors.New("mount path escape is incomplete")
		}
		decoded := byte(0)
		for offset := 1; offset <= 3; offset++ {
			current := value[index+offset]
			if current < '0' || current > '7' {
				return "", errors.New("mount path escape is invalid")
			}
			decoded = decoded*8 + current - '0'
		}
		if decoded == 0 {
			return "", errors.New("mount path contains NUL")
		}
		result.WriteByte(decoded)
		index += 3
	}
	return result.String(), nil
}

func mountOption(options, expected string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == expected {
			return true
		}
	}
	return false
}

func runStorageProbe(ctx context.Context, config Config, target storageTarget) (StorageObservation, error) {
	observation := target.observation
	if !observation.Mounted {
		return observation, nil
	}
	rootFD, rootStat, rootMount, err := openDiagnosticDataRoot(ctx, config.DataRoot, target.mountID, true)
	if err != nil {
		if setStorageErrno(&observation, err) {
			return observation, nil
		}
		return observation, err
	}
	defer unix.Close(rootFD)
	temporary, file, err := createDiagnosticProbe(ctx, rootFD, rootStat, rootMount)
	if err != nil {
		if setStorageErrno(&observation, err) {
			return observation, nil
		}
		return observation, err
	}
	defer func() {
		_ = file.Close()
		_ = unix.Unlinkat(rootFD, temporary, 0)
	}()
	attempted, written, writeErr := writeDiagnosticBytes(ctx, file, storageProbeBytes, false)
	observation.AttemptedBytes, observation.WrittenBytes = attempted, written
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	removeErr := unix.Unlinkat(rootFD, temporary, 0)
	if errors.Is(removeErr, unix.ENOENT) {
		removeErr = nil
	}
	if removeErr == nil {
		removeErr = unix.Fsync(rootFD)
	}
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr == nil {
		writeErr = removeErr
	}
	if writeErr != nil {
		observation.Healthy = false
		if setStorageErrno(&observation, writeErr) {
			return observation, nil
		}
		return observation, errors.New("vmguest: storage probe write failed")
	}
	if err := refreshStorageObservation(ctx, config, &observation); err != nil {
		return observation, err
	}
	observation.Healthy = observation.Errno == StorageErrnoNone && observation.Mounted && !observation.ReadOnly && observation.WrittenBytes == observation.AttemptedBytes
	return observation, nil
}

func runStorageFill(ctx context.Context, config Config, target storageTarget) (StorageObservation, error) {
	observation := target.observation
	if !observation.Mounted {
		return observation, nil
	}
	rootFD, rootStat, rootMount, err := openDiagnosticDataRoot(ctx, config.DataRoot, target.mountID, true)
	if err != nil {
		if setStorageErrno(&observation, err) {
			return observation, nil
		}
		return observation, err
	}
	defer unix.Close(rootFD)
	file, created, err := openStorageFill(rootFD, rootStat, rootMount)
	if err != nil {
		if setStorageErrno(&observation, err) {
			return observation, nil
		}
		return observation, err
	}
	attempted, written, writeErr := writeDiagnosticBytes(ctx, file, storageFillBytes, true)
	observation.AttemptedBytes, observation.WrittenBytes = attempted, written
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if created {
		if syncErr := unix.Fsync(rootFD); writeErr == nil {
			writeErr = syncErr
		}
	}
	if writeErr != nil {
		observation.Healthy = false
		if setStorageErrno(&observation, writeErr) {
			_ = refreshStorageObservation(ctx, config, &observation)
			observation.Healthy = false
			return observation, nil
		}
		return observation, errors.New("vmguest: storage fill write failed")
	}
	if err := refreshStorageObservation(ctx, config, &observation); err != nil {
		return observation, err
	}
	return observation, nil
}

func runStorageClearFill(ctx context.Context, config Config, target storageTarget) (StorageObservation, error) {
	observation := target.observation
	if !observation.Mounted || !target.dataRootExists {
		return observation, nil
	}
	rootFD, rootStat, rootMount, err := openDiagnosticDataRoot(ctx, config.DataRoot, target.mountID, false)
	if err != nil {
		if setStorageErrno(&observation, err) {
			return observation, nil
		}
		return observation, err
	}
	defer unix.Close(rootFD)
	if err := removeStorageFill(rootFD, rootStat, rootMount); err != nil {
		observation.Healthy = false
		if setStorageErrno(&observation, err) {
			return observation, nil
		}
		return observation, err
	}
	if err := refreshStorageObservation(ctx, config, &observation); err != nil {
		return observation, err
	}
	return observation, nil
}

func runStorageFSCK(ctx context.Context, config Config, target storageTarget, action StorageAction) (StorageObservation, error) {
	observation := target.observation
	if !target.devicePresent {
		return observation, nil
	}
	if target.deviceMounted {
		return observation, errors.New("vmguest: filesystem check requires an unmounted data device")
	}
	observation.Errno = StorageErrnoNone
	args := []string{"-f", "-n", config.DataDevice}
	if action == StorageActionFSCKRepair {
		args = []string{"-f", "-p", config.DataDevice}
	}
	result := runCommand(ctx, config, storageFSCKPath, args)
	observation.ExitCode = result.ExitCode
	if result.ExitCode < 0 || result.ExitCode == 124 {
		return observation, errors.New("vmguest: filesystem check did not complete")
	}
	if result.ExitCode > 255 {
		return observation, errors.New("vmguest: filesystem check status is invalid")
	}
	status := result.ExitCode
	observation.CorruptionDetected = status != 0
	if action == StorageActionFSCKRepair {
		observation.Repaired = status&(1|2) != 0 && status&(4|8|16|32|128) == 0
		observation.Healthy = status&^(1|2) == 0
	} else {
		observation.Healthy = status == 0
	}
	return observation, nil
}

func runStorageGrow(ctx context.Context, config Config, target storageTarget) (StorageObservation, error) {
	observation := target.observation
	if !observation.Mounted {
		return observation, nil
	}
	if observation.Filesystem != storageFilesystem {
		return observation, errors.New("vmguest: filesystem growth requires mounted ext4")
	}
	result := runCommand(ctx, config, storageGrowPath, []string{config.DataDevice})
	observation.ExitCode = result.ExitCode
	if result.ExitCode < 0 || result.ExitCode == 124 {
		return observation, errors.New("vmguest: filesystem growth did not complete")
	}
	if result.ExitCode != 0 {
		observation.Healthy = false
		return observation, nil
	}
	if err := refreshStorageObservation(ctx, config, &observation); err != nil {
		return observation, err
	}
	observation.Healthy = observation.Errno == StorageErrnoNone && observation.Mounted && observation.Filesystem == storageFilesystem && !observation.ReadOnly
	return observation, nil
}

func openDiagnosticDataRoot(ctx context.Context, path string, expectedMount uint64, create bool) (int, unix.Stat_t, uint64, error) {
	fd, err := openStorageRoot(ctx, path, create)
	if err != nil {
		return -1, unix.Stat_t{}, 0, err
	}
	var stat unix.Stat_t
	mount, err := descriptorMountID(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, 0, err
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, 0, storageFailure("vmguest: inspect persistent root", err)
	}
	if mount != expectedMount {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, 0, errors.New("vmguest: persistent root is outside the configured data mount")
	}
	return fd, stat, mount, nil
}

func openStorageFill(rootFD int, rootStat unix.Stat_t, rootMount uint64) (*os.File, bool, error) {
	fd, err := unix.Openat(rootFD, storageFillName, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(rootFD, storageFillName, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		created = err == nil
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), storageFillName)
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, errors.New("vmguest: wrap storage fill file")
	}
	if _, err := validateOpenedStorageFile(fd, rootStat, rootMount, 0o600); err != nil {
		_ = file.Close()
		if created {
			_ = unix.Unlinkat(rootFD, storageFillName, 0)
		}
		return nil, false, err
	}
	return file, created, nil
}

func removeStorageFill(rootFD int, rootStat unix.Stat_t, rootMount uint64) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(rootFD, storageFillName, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return storageFailure("vmguest: inspect storage fill file", err)
	}
	mount, err := pathMountID(rootFD, storageFillName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if mount != rootMount || !safeStorageFile(stat, rootStat, 0o600) {
		return errors.New("vmguest: storage fill file identity is unsafe")
	}
	if err := unix.Unlinkat(rootFD, storageFillName, 0); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return err
	}
	return nil
}

func createDiagnosticProbe(ctx context.Context, rootFD int, rootStat unix.Stat_t, rootMount uint64) (string, *os.File, error) {
	for range 10 {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, errors.New("vmguest: generate storage probe name")
		}
		name := ".vmguest-write-" + hex.EncodeToString(random)
		fd, err := unix.Openat(rootFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				return "", nil, errors.New("vmguest: wrap storage probe file")
			}
			if _, err := validateOpenedStorageFile(fd, rootStat, rootMount, 0o600); err != nil {
				_ = file.Close()
				_ = unix.Unlinkat(rootFD, name, 0)
				return "", nil, err
			}
			return name, file, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("vmguest: allocate storage probe name")
}

func writeDiagnosticBytes(ctx context.Context, file storageSyncWriter, limit int, syncEveryWrite bool) (uint64, uint64, error) {
	buffer := make([]byte, min(limit, storageDiagnosticChunk))
	var attempted, written uint64
	remaining := limit
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return attempted, written, err
		}
		chunk := buffer
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		attempted += uint64(len(chunk))
		count, err := file.Write(chunk)
		if count < 0 || count > len(chunk) {
			return attempted, written, io.ErrShortWrite
		}
		written += uint64(count)
		remaining -= count
		if err != nil {
			return attempted, written, err
		}
		if count == 0 {
			return attempted, written, io.ErrNoProgress
		}
		if syncEveryWrite {
			if err := file.Sync(); err != nil {
				return attempted, written, err
			}
		}
	}
	return attempted, written, nil
}

func refreshStorageObservation(ctx context.Context, config Config, observation *StorageObservation) error {
	fresh, err := inspectStorageTarget(ctx, config.DataRoot, config.DataDevice, observation.Action)
	if err != nil {
		return err
	}
	status := *observation
	*observation = fresh.observation
	observation.AttemptedBytes = status.AttemptedBytes
	observation.WrittenBytes = status.WrittenBytes
	observation.ExitCode = status.ExitCode
	observation.CorruptionDetected = status.CorruptionDetected
	observation.Repaired = status.Repaired
	if status.Errno != StorageErrnoNone {
		observation.Errno = status.Errno
		observation.Healthy = false
	}
	return nil
}

func setStorageErrno(observation *StorageObservation, err error) bool {
	switch {
	case errors.Is(err, unix.ENOSPC):
		observation.Errno = StorageErrnoENOSPC
	case errors.Is(err, unix.EIO):
		observation.Errno = StorageErrnoEIO
	case errors.Is(err, unix.EROFS):
		observation.Errno = StorageErrnoEROFS
	case errors.Is(err, unix.ENODEV), errors.Is(err, unix.ENOENT):
		observation.Errno = StorageErrnoENODEV
	default:
		return false
	}
	observation.Healthy = false
	return true
}
