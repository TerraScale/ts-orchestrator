//go:build linux

package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const managedVolumeClaimName = ".terrascale-member-claim"

// The claim is in the root-owned filesystem root. A workload can write the
// replication directory, so a claim there would not survive a hostile process.
func managedVolumeClaimBytes(launch ManagedMemberLaunch) []byte {
	scope := launch.Member.Scope
	pins := launch.Runtime
	var claim []byte
	claim = append(claim, "TB-MEMBER-VOLUME-CLAIM-V1\n"...)
	for _, value := range []string{
		launch.VolumeID, pins.FileSystemUUID, pins.FileSystemType, scope.ClusterID, scope.TenantID,
		scope.DatabaseID, strconv.FormatUint(scope.ShardID, 10), scope.MemberID,
		scope.Incarnation, strconv.FormatUint(launch.Authority.Epoch, 10),
		launch.Authority.ConfigurationID, launch.Authority.CertificateSHA256,
		pins.TrustedKeySHA256,
	} {
		claim = append(claim, value...)
		claim = append(claim, '\n')
	}
	return claim
}

// TerraBase's AcceptedAuthority::encode_record writes this exact byte layout.
// A read-only preflight is needed because its recovery path creates the lock
// file before checking the record; a partial child must never be started.
func managedAcceptedAuthorityRecord(launch ManagedMemberLaunch, certificate []byte) ([]byte, error) {
	const headerLength = 8 + 4 + 32 + 32 + 4
	const maximumCertificate = 4<<20 + 64
	if len(certificate) == 0 || len(certificate) > maximumCertificate {
		return nil, errors.New("managed authority certificate length is invalid")
	}
	trusted, err := hex.DecodeString(launch.Runtime.TrustedKeySHA256)
	if err != nil || len(trusted) != sha256.Size {
		return nil, errors.New("managed trusted key digest is invalid")
	}
	configuration, err := hex.DecodeString(launch.Authority.ConfigurationID)
	if err != nil || len(configuration) != sha256.Size {
		return nil, errors.New("managed authority configuration is invalid")
	}
	length := headerLength + len(certificate) + 4
	record := make([]byte, 0, length)
	record = append(record, "TBACR001"...)
	record = binary.LittleEndian.AppendUint32(record, uint32(length))
	record = append(record, trusted...)
	record = append(record, configuration...)
	record = binary.LittleEndian.AppendUint32(record, uint32(len(certificate)))
	record = append(record, certificate...)
	checksum := crc32.Checksum(record, crc32.MakeTable(crc32.Castagnoli))
	return binary.LittleEndian.AppendUint32(record, checksum), nil
}

func openManagedVolumeDirectory(parent int, name string, device uint64) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Dev != device {
		_ = unix.Close(fd)
		return -1, errors.New("managed volume directory changed device")
	}
	return fd, nil
}

func managedDirectoryEntries(fd int) ([]os.DirEntry, error) {
	copyFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(copyFD), "managed volume directory")
	defer directory.Close()
	return directory.ReadDir(-1)
}

func managedEmptyDirectory(fd int) error {
	entries, err := managedDirectoryEntries(fd)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("managed volume preformat directory is not empty")
	}
	return nil
}

func managedReadExactFile(parent int, name string, expected []byte, device uint64, ownerUID int64) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Dev != device ||
		(ownerUID >= 0 && (before.Uid != uint32(ownerUID) || before.Mode&0777 != 0600)) ||
		before.Size != int64(len(expected)) {
		return errors.New("managed volume record has unsafe ownership, type or length")
	}
	read, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil {
		return err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || !bytes.Equal(read, expected) {
		return errors.New("managed volume record differs from signed member identity")
	}
	return nil
}

func managedAuthorityDirectorySafe(fd int, identity WorkloadIdentity, device uint64) error {
	var directory unix.Stat_t
	if err := unix.Fstat(fd, &directory); err != nil {
		return err
	}
	if directory.Uid != identity.UID || directory.Gid != identity.GID || directory.Mode&0777 != 0700 {
		return errors.New("managed authority directory is unsafe")
	}
	entries, err := managedDirectoryEntries(fd)
	if err != nil {
		return err
	}
	seenRecord := false
	for _, entry := range entries {
		switch entry.Name() {
		case "accepted.tbca":
			seenRecord = true
		case "lock":
			var lock unix.Stat_t
			if err := unix.Fstatat(fd, "lock", &lock, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if lock.Mode&unix.S_IFMT != unix.S_IFREG || lock.Dev != device || lock.Uid != identity.UID ||
				lock.Gid != identity.GID || lock.Mode&0777 != 0600 || lock.Size != 0 {
				return errors.New("managed authority lock is unsafe")
			}
		default:
			return fmt.Errorf("unexpected managed authority entry %q", entry.Name())
		}
	}
	if !seenRecord {
		return errors.New("managed authority record is missing")
	}
	return nil
}

func managedShardDirectorySafe(fd int, identity WorkloadIdentity) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != identity.UID || stat.Gid != identity.GID || stat.Mode&0777 != 0700 {
		return errors.New("managed shard directory is unsafe")
	}
	return nil
}

func managedPreformatEmpty(mountFD int, launch ManagedMemberLaunch, identity WorkloadIdentity, device uint64, hasClaim bool) error {
	entries, err := managedDirectoryEntries(mountFD)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if seen[name] || name != "data" && name != "replication" && name != managedVolumeClaimName &&
			(name != "lost+found" || launch.Runtime.FileSystemType != "ext4") {
			return fmt.Errorf("unexpected managed volume root entry %q", name)
		}
		seen[name] = true
	}
	if !seen["data"] || !seen["replication"] || seen[managedVolumeClaimName] != hasClaim {
		return errors.New("managed volume preformat layout is incomplete")
	}
	for _, name := range []string{"data", "replication"} {
		fd, err := openManagedVolumeDirectory(mountFD, name, device)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err == nil && (stat.Uid != identity.UID || stat.Gid != identity.GID || stat.Mode&0777 != 0700) {
			err = fmt.Errorf("unsafe managed volume %s directory", name)
		}
		if err == nil {
			err = managedEmptyDirectory(fd)
		}
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	if seen["lost+found"] {
		fd, err := openManagedVolumeDirectory(mountFD, "lost+found", device)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err == nil && (stat.Uid != 0 || stat.Mode&0777 != 0700) {
			err = errors.New("unsafe managed lost+found directory")
		}
		if err == nil {
			err = managedEmptyDirectory(fd)
		}
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}

func managedRecoveredLayout(mountFD int, launch ManagedMemberLaunch, identity WorkloadIdentity, device uint64) error {
	entries, err := managedDirectoryEntries(mountFD)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if seen[name] || name != "data" && name != "replication" && name != managedVolumeClaimName &&
			(name != "lost+found" || launch.Runtime.FileSystemType != "ext4") {
			return fmt.Errorf("unexpected managed volume root entry %q", name)
		}
		seen[name] = true
	}
	if !seen["data"] || !seen["replication"] || !seen[managedVolumeClaimName] {
		return errors.New("managed recovered volume layout is incomplete")
	}
	for _, name := range []string{"data", "replication"} {
		fd, err := openManagedVolumeDirectory(mountFD, name, device)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err == nil && (stat.Uid != identity.UID || stat.Gid != identity.GID || stat.Mode&0777 != 0700) {
			err = fmt.Errorf("unsafe managed recovered %s directory", name)
		}
		if err == nil && name == "replication" {
			var children []os.DirEntry
			children, err = managedDirectoryEntries(fd)
			if err == nil && (len(children) != 1 || children[0].Name() != "shard") {
				err = errors.New("managed replication parent contains unexpected entries")
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	if seen["lost+found"] {
		fd, err := openManagedVolumeDirectory(mountFD, "lost+found", device)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstat(fd, &stat)
		if err == nil && (stat.Uid != 0 || stat.Mode&0777 != 0700) {
			err = errors.New("unsafe managed lost+found directory")
		}
		if err == nil {
			err = managedEmptyDirectory(fd)
		}
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureManagedVolumeClaim is the only write to a mounted member volume made
// by the host. Call it after the final cycle and execution-lease checks and
// after the previous role cgroup has been proven quiescent.
func ensureManagedVolumeClaim(paths managedRuntimePaths, launch ManagedMemberLaunch, identity WorkloadIdentity, mount managedMount, certificate []byte) error {
	if launch.Runtime == nil || paths.mount != launch.Runtime.MountPath {
		return errors.New("managed volume claim lacks signed runtime pins")
	}
	fd, err := unix.Open(paths.mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var root unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil {
		return err
	}
	if root.Dev != mount.witness.stat.Rdev || root.Uid != 0 || root.Gid != identity.GID || root.Mode&0777 != 0750 {
		return errors.New("managed claim volume root changed")
	}
	return ensureManagedVolumeClaimAt(fd, launch, identity, root.Dev, certificate, 0)
}

func ensureManagedVolumeClaimAt(fd int, launch ManagedMemberLaunch, identity WorkloadIdentity, device uint64, certificate []byte, ownerUID int64) error {
	expected := managedVolumeClaimBytes(launch)
	err := managedReadExactFile(fd, managedVolumeClaimName, expected, device, ownerUID)
	if errors.Is(err, syscall.ENOENT) {
		if err := managedPreformatEmpty(fd, launch, identity, device, false); err != nil {
			return err
		}
		var claimFD int
		claimFD, err = unix.Openat(fd, managedVolumeClaimName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		claim := os.NewFile(uintptr(claimFD), managedVolumeClaimName)
		if _, err := claim.Write(expected); err != nil {
			_ = claim.Close()
			return err
		}
		if err := claim.Sync(); err != nil {
			_ = claim.Close()
			return err
		}
		if err := claim.Close(); err != nil {
			return err
		}
		if err := unix.Fsync(fd); err != nil {
			return err
		}
		err = managedReadExactFile(fd, managedVolumeClaimName, expected, device, ownerUID)
		if err != nil {
			return fmt.Errorf("verify newly installed managed claim: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("read managed claim: %w", err)
	}
	replicationFD, err := openManagedVolumeDirectory(fd, "replication", device)
	if err != nil {
		return fmt.Errorf("open managed replication parent: %w", err)
	}
	defer unix.Close(replicationFD)
	shardFD, err := openManagedVolumeDirectory(replicationFD, "shard", device)
	if errors.Is(err, syscall.ENOENT) {
		return managedPreformatEmpty(fd, launch, identity, device, true)
	}
	if err != nil {
		return fmt.Errorf("open managed shard: %w", err)
	}
	defer unix.Close(shardFD)
	if err := managedShardDirectorySafe(shardFD, identity); err != nil {
		return err
	}
	if err := managedRecoveredLayout(fd, launch, identity, device); err != nil {
		return err
	}
	authorityFD, err := openManagedVolumeDirectory(shardFD, "authority", device)
	if err != nil {
		return err
	}
	defer unix.Close(authorityFD)
	if err := managedAuthorityDirectorySafe(authorityFD, identity, device); err != nil {
		return err
	}
	record, err := managedAcceptedAuthorityRecord(launch, certificate)
	if err != nil {
		return err
	}
	return managedReadExactFile(authorityFD, "accepted.tbca", record, device, int64(identity.UID))
}

func managedShardPath(paths managedRuntimePaths) string {
	return filepath.Join(paths.mount, "replication", "shard")
}

func requireManagedRoleQuiescent(runner Runner, role string) error {
	native, ok := runner.(*processRunner)
	if !ok || native == nil {
		return errors.New("managed volume claim requires native process runner")
	}
	populated, err := cgroupPopulated(filepath.Join(native.cgroups, role))
	if err != nil {
		return err
	}
	if populated {
		return errors.New("managed role cgroup is not quiescent")
	}
	return nil
}

// inspectManagedVolumeClaim never creates or repairs state. It is used before
// accepting a process that was already running when reconciliation began.
func inspectManagedVolumeClaim(paths managedRuntimePaths, launch ManagedMemberLaunch, identity WorkloadIdentity, mount managedMount, certificate []byte) error {
	if launch.Runtime == nil || paths.mount != launch.Runtime.MountPath {
		return errors.New("managed volume claim lacks signed runtime pins")
	}
	fd, err := unix.Open(paths.mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var root unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil {
		return err
	}
	if root.Dev != mount.witness.stat.Rdev || root.Uid != 0 || root.Gid != identity.GID || root.Mode&0777 != 0750 {
		return errors.New("managed claim volume root changed")
	}
	if err := managedReadExactFile(fd, managedVolumeClaimName, managedVolumeClaimBytes(launch), root.Dev, 0); err != nil {
		return err
	}
	replicationFD, err := openManagedVolumeDirectory(fd, "replication", root.Dev)
	if err != nil {
		return err
	}
	defer unix.Close(replicationFD)
	shardFD, err := openManagedVolumeDirectory(replicationFD, "shard", root.Dev)
	if err != nil {
		return err
	}
	defer unix.Close(shardFD)
	if err := managedShardDirectorySafe(shardFD, identity); err != nil {
		return err
	}
	if err := managedRecoveredLayout(fd, launch, identity, root.Dev); err != nil {
		return err
	}
	authorityFD, err := openManagedVolumeDirectory(shardFD, "authority", root.Dev)
	if err != nil {
		return err
	}
	defer unix.Close(authorityFD)
	if err := managedAuthorityDirectorySafe(authorityFD, identity, root.Dev); err != nil {
		return err
	}
	record, err := managedAcceptedAuthorityRecord(launch, certificate)
	if err != nil {
		return err
	}
	return managedReadExactFile(authorityFD, "accepted.tbca", record, root.Dev, int64(identity.UID))
}
