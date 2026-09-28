//go:build linux

package host

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"golang.org/x/sys/unix"
)

// These paths are host-owned, not supplied by a workload or an arbitrary
// controller field. An operator provisions the exact files and a mounted,
// preformatted retained volume before the signed desired may be executed.
type managedRuntimePaths struct {
	memberDir, mount, material, socket, nativeRoot string
}

type managedMount struct {
	id      uint64
	device  string
	uuid    string
	fsType  string
	witness *managedDevice
}

type managedDevice struct {
	fd   int
	stat syscall.Stat_t
}

func (device *managedDevice) close() {
	if device != nil && device.fd >= 0 {
		_ = unix.Close(device.fd)
		device.fd = -1
	}
}

func (mount managedMount) close() { mount.witness.close() }

func sameManagedMount(left, right managedMount) bool {
	return left.id == right.id && left.device == right.device && left.uuid == right.uuid &&
		left.fsType == right.fsType && left.witness != nil && right.witness != nil &&
		sameDeviceObject(left.witness.stat, right.witness.stat)
}

func verifyManagedMountPair(left, right managedMount) error {
	if !sameManagedMount(left, right) {
		return errors.New("managed mount identity changed")
	}
	if err := verifyManagedDeviceWitness(left); err != nil {
		return err
	}
	return verifyManagedDeviceWitness(right)
}

// ManagedMountPath is the deterministic host-owned mount target for a signed
// member attempt. The operator provisions this path below the configured root.
func ManagedMountPath(root string, member ManagedMemberBinding) (string, error) {
	paths, err := runtimePaths(root, ManagedMemberLaunch{Member: member})
	if err != nil {
		return "", err
	}
	return paths.mount, nil
}

// ManagedMaterialPath is the exact host-owned directory for one signed member
// attempt. Preparation uses this path so client configuration cannot redirect
// a host to operator-chosen material.
func ManagedMaterialPath(root string, member ManagedMemberBinding) (string, error) {
	paths, err := runtimePaths(root, ManagedMemberLaunch{Member: member})
	if err != nil {
		return "", err
	}
	return paths.material, nil
}

// ValidateManagedRuntimeRoot rejects an unsafe configured root before native
// startup. An absent root is allowed only for a host that keeps managed launch
// on its deliberate hold path.
func ValidateManagedRuntimeRoot(root, installRoot, stateRoot string, identity WorkloadIdentity) error {
	if root == "" {
		return nil
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" ||
		root == installRoot || root == stateRoot ||
		strings.HasPrefix(root, installRoot+string(filepath.Separator)) ||
		strings.HasPrefix(root, stateRoot+string(filepath.Separator)) ||
		strings.HasPrefix(installRoot, root+string(filepath.Separator)) ||
		strings.HasPrefix(stateRoot, root+string(filepath.Separator)) {
		return errors.New("managed runtime root must be clean, absolute and separate from host roots")
	}
	return verifyManagedDirectory(root, identity, 0750)
}

func runtimePaths(root string, launch ManagedMemberLaunch) (managedRuntimePaths, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return managedRuntimePaths{}, errors.New("managed runtime root must be a clean absolute directory")
	}
	scope := launch.Member.Scope
	if err := validateManagedMemberBinding(launch.Member); err != nil {
		return managedRuntimePaths{}, err
	}
	sum := sha256.Sum256([]byte(scope.ClusterID + "/" + scope.TenantID + "/" + scope.DatabaseID + "/" +
		strconv.FormatUint(scope.ShardID, 10) + "/" + scope.MemberID + "/" + scope.Incarnation + "/" +
		strconv.FormatUint(launch.Member.HostAttempt, 10)))
	memberDir := filepath.Join(root, hex.EncodeToString(sum[:16]))
	paths := managedRuntimePaths{
		memberDir:  memberDir,
		mount:      filepath.Join(memberDir, "volume"),
		material:   filepath.Join(memberDir, "material"),
		socket:     filepath.Join(memberDir, "control", "member.sock"),
		nativeRoot: filepath.Join(memberDir, "native-root.sock"),
	}
	if len(paths.socket) >= 108 || len(paths.nativeRoot) >= 108 {
		return managedRuntimePaths{}, errors.New("managed socket path exceeds Unix limit")
	}
	return paths, nil
}

func verifyManagedDirectory(path string, identity WorkloadIdentity, mode os.FileMode) error {
	if err := inspectWorkloadPath(filepath.Dir(path), identity, true, false, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != 0 || owner.Gid != identity.GID || info.Mode().Perm() != mode {
		return fmt.Errorf("unsafe managed runtime directory %s", path)
	}
	return nil
}

func verifyManagedMaterial(path, digest string, identity WorkloadIdentity, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != 0 || owner.Gid != identity.GID ||
		info.Mode().Perm() != 0440 || info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("unsafe managed runtime material %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	check, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, check) || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("managed runtime material changed while reading %s", path)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("managed runtime material digest mismatch for %s", path)
	}
	return data, nil
}

func verifyManagedMount(paths managedRuntimePaths, pins ManagedRuntimePins, identity WorkloadIdentity) (_ managedMount, err error) {
	if paths.mount != pins.MountPath {
		return managedMount{}, errors.New("managed mount path differs from signed pin")
	}
	if err := verifyManagedDirectory(paths.memberDir, identity, 0750); err != nil {
		return managedMount{}, err
	}
	device, err := managedBlockDevice(pins.DevicePath)
	if err != nil {
		return managedMount{}, err
	}
	defer func() {
		if err != nil {
			device.close()
		}
	}()
	uuidInfo, err := os.Stat(filepath.Join("/dev/disk/by-uuid", pins.FileSystemUUID))
	if err != nil {
		return managedMount{}, err
	}
	uuidDevice, ok := uuidInfo.Sys().(*syscall.Stat_t)
	if !ok || uuidDevice.Rdev != device.stat.Rdev {
		return managedMount{}, errors.New("filesystem UUID does not identify the signed device")
	}
	mountInfo, err := os.Lstat(paths.mount)
	if err != nil {
		return managedMount{}, err
	}
	if !mountInfo.IsDir() || mountInfo.Mode()&os.ModeSymlink != 0 {
		return managedMount{}, errors.New("managed volume mountpoint is unsafe")
	}
	mountedStat, ok := mountInfo.Sys().(*syscall.Stat_t)
	if !ok || !validManagedMountRoot(mountedStat, mountInfo.Mode(), identity, device.stat.Rdev) {
		return managedMount{}, errors.New("managed volume root is tenant-writable or has wrong device")
	}
	mount, err := findExclusiveMount("/proc/self/mountinfo", paths.mount, device.stat.Rdev, pins.FileSystemType)
	if err != nil {
		return managedMount{}, err
	}
	for _, child := range []string{"data", "replication"} {
		info, err := os.Lstat(filepath.Join(paths.mount, child))
		if err != nil {
			return managedMount{}, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Dev != device.stat.Rdev ||
			owner.Uid != identity.UID || owner.Gid != identity.GID || info.Mode().Perm() != 0700 {
			return managedMount{}, fmt.Errorf("unsafe managed volume %s directory", child)
		}
	}
	result := managedMount{id: mount, device: pins.DevicePath, uuid: pins.FileSystemUUID, fsType: pins.FileSystemType, witness: device}
	if err := verifyManagedDeviceWitness(result); err != nil {
		return managedMount{}, err
	}
	return result, nil
}

// OCI's /dev/oracleoci names are commonly one root-owned symlink to a block
// device directly below /dev. Resolve only that form and pin the opened rdev.
func managedBlockDevice(devicePath string) (*managedDevice, error) {
	resolved := devicePath
	ancestors, err := managedDeviceAncestors(devicePath)
	if err != nil {
		return nil, err
	}
	for _, directory := range ancestors {
		info, err := os.Lstat(directory)
		if err != nil {
			return nil, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !validManagedDeviceAncestor(info.Mode(), owner) {
			return nil, errors.New("managed device ancestor is writable or untrusted")
		}
	}
	if len(ancestors) == 2 {
		info, err := os.Lstat(devicePath)
		if err != nil {
			return nil, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink == 0 || owner.Uid != 0 {
			return nil, errors.New("OCI device alias is not a root-owned symlink")
		}
		target, err := os.Readlink(devicePath)
		if err != nil {
			return nil, err
		}
		resolved, err = oracleOCIAliasTarget(devicePath, target)
		if err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	device, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 ||
		info.Mode()&os.ModeSymlink != 0 || device.Uid != 0 {
		return nil, errors.New("managed device is not an exact root-owned block device")
	}
	fd, err := unix.Open(resolved, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if opened.Mode&syscall.S_IFMT != syscall.S_IFBLK || opened.Uid != 0 || opened.Rdev != device.Rdev {
		_ = unix.Close(fd)
		return nil, errors.New("opened managed block device differs from signed alias target")
	}
	return &managedDevice{fd: fd, stat: opened}, nil
}

func managedDeviceAncestors(path string) ([]string, error) {
	switch filepath.Dir(path) {
	case "/dev":
		return []string{"/dev"}, nil
	case "/dev/oracleoci":
		return []string{"/dev", "/dev/oracleoci"}, nil
	default:
		return nil, errors.New("managed block device must be a direct /dev node or OCI alias")
	}
}

func validManagedDeviceAncestor(mode os.FileMode, owner *syscall.Stat_t) bool {
	return owner != nil && mode.IsDir() && mode&os.ModeSymlink == 0 && owner.Uid == 0 && mode.Perm()&0022 == 0
}

func verifyOpenDeviceIdentity(fd int, expected syscall.Stat_t) error {
	if expected.Mode&syscall.S_IFMT != syscall.S_IFBLK || expected.Uid != 0 {
		return errors.New("managed block device witness is not a root-owned block device")
	}
	current, err := statOpenWitness(fd)
	if err != nil {
		return err
	}
	if current.Mode&syscall.S_IFMT != syscall.S_IFBLK || current.Uid != 0 ||
		!sameDeviceObject(current, expected) {
		return errors.New("managed block device witness changed")
	}
	return nil
}

func statOpenWitness(fd int) (syscall.Stat_t, error) {
	if fd < 0 {
		return syscall.Stat_t{}, errors.New("managed block device witness is closed")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return syscall.Stat_t{}, err
	}
	return stat, nil
}

func sameDeviceObject(left, right syscall.Stat_t) bool {
	return left.Mode&syscall.S_IFMT == right.Mode&syscall.S_IFMT && left.Uid == right.Uid &&
		left.Rdev == right.Rdev && left.Dev == right.Dev && left.Ino == right.Ino
}

func verifyManagedDeviceWitness(mount managedMount) error {
	if mount.witness == nil {
		return errors.New("managed mount has no open block device witness")
	}
	if err := verifyOpenDeviceIdentity(mount.witness.fd, mount.witness.stat); err != nil {
		return err
	}
	current, err := managedBlockDevice(mount.device)
	if err != nil {
		return err
	}
	defer current.close()
	if !sameDeviceObject(current.stat, mount.witness.stat) {
		return errors.New("managed device path changed from held block device")
	}
	return nil
}

func oracleOCIAliasTarget(alias, target string) (string, error) {
	if filepath.Dir(alias) != "/dev/oracleoci" || filepath.IsAbs(target) ||
		target != "../"+filepath.Base(target) || filepath.Base(target) == "." ||
		strings.ContainsAny(target, " \t\r\n\x00") {
		return "", errors.New("invalid OCI device alias target")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(alias), target))
	if filepath.Dir(resolved) != "/dev" {
		return "", errors.New("OCI device alias must resolve to one /dev block node")
	}
	return resolved, nil
}

func validManagedMountRoot(stat *syscall.Stat_t, mode os.FileMode, identity WorkloadIdentity, device uint64) bool {
	return stat != nil && stat.Dev == device && stat.Uid == 0 && stat.Gid == identity.GID &&
		mode.IsDir() && mode.Perm() == 0750
}

func findExclusiveMount(mountInfoPath, target string, rdev uint64, fsType string) (uint64, error) {
	file, err := os.Open(mountInfoPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	device := fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev))
	var id uint64
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[2] != device {
			continue
		}
		count++
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
		}
		if fields[4] != target || fields[3] != "/" || !strings.Contains(","+fields[5]+",", ",rw,") ||
			separator < 0 || separator+1 >= len(fields) || fields[separator+1] != fsType {
			return 0, errors.New("retained filesystem has another or unsafe mount")
		}
		parsed, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, err
		}
		id = parsed
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if count != 1 || id == 0 {
		return 0, errors.New("retained filesystem is not mounted exactly once")
	}
	return id, nil
}

func prepareManagedRuntime(ctx context.Context, cfg AgentConfig, d Desired, executable, fingerprint string) (Workload, managedMount, string, error) {
	launch := d.ManagedMember
	if launch == nil || launch.Runtime == nil || cfg.ManagedRuntimeRoot == "" {
		return Workload{}, managedMount{}, "", errors.New("managed member launch awaits verified mount, artifact, authority material and member identity")
	}
	if err := ctx.Err(); err != nil {
		return Workload{}, managedMount{}, "", err
	}
	paths, err := runtimePaths(cfg.ManagedRuntimeRoot, *launch)
	if err != nil {
		return Workload{}, managedMount{}, "", err
	}
	if paths.mount != launch.Runtime.MountPath {
		return Workload{}, managedMount{}, "", errors.New("managed mount path differs from signed desired")
	}
	identity := cfg.WorkloadIdentity
	if err := verifyManagedDirectory(cfg.ManagedRuntimeRoot, identity, 0750); err != nil {
		return Workload{}, managedMount{}, "", err
	}
	if err := verifyManagedDirectory(paths.material, identity, 0750); err != nil {
		return Workload{}, managedMount{}, "", err
	}
	if err := verifyManagedDirectory(filepath.Dir(paths.socket), identity, 0730); err != nil {
		return Workload{}, managedMount{}, "", err
	}
	mount, err := verifyManagedMount(paths, *launch.Runtime, identity)
	if err != nil {
		return Workload{}, managedMount{}, "", err
	}
	keepMount := false
	defer func() {
		if !keepMount {
			mount.close()
		}
	}()
	files := []struct {
		name, digest string
		maximum      int64
	}{
		{"authority.tbca", launch.Authority.CertificateSHA256, 1 << 20},
		{"trusted-public-key", launch.Runtime.TrustedKeySHA256, 32},
		{"server.crt", launch.Runtime.ServerCertificateSHA256, 1 << 20},
		{"server.key", launch.Runtime.ServerPrivateKeySHA256, 1 << 20},
		{"client-ca.pem", launch.Runtime.ClientCARootsSHA256, 1 << 20},
		{"signed-v2-s3-config.json", launch.Runtime.LiveS3ConfigSHA256, 16 << 10},
	}
	contents := make(map[string][]byte, len(files))
	for _, item := range files {
		contents[item.name], err = verifyManagedMaterial(filepath.Join(paths.material, item.name), item.digest, identity, item.maximum)
		if err != nil {
			return Workload{}, managedMount{}, "", err
		}
	}
	if len(contents["trusted-public-key"]) != 32 {
		return Workload{}, managedMount{}, "", errors.New("authority trust key has wrong length")
	}
	_, nativeRoot, err := nativeRootTarget(*launch, contents["signed-v2-s3-config.json"])
	if err != nil {
		return Workload{}, managedMount{}, "", err
	}
	chain, err := tls.X509KeyPair(contents["server.crt"], contents["server.key"])
	if err != nil || len(chain.Certificate) == 0 {
		return Workload{}, managedMount{}, "", errors.New("member TLS leaf and private key do not match")
	}
	leaf := sha256.Sum256(chain.Certificate[0])
	if hex.EncodeToString(leaf[:]) != launch.Authority.TLSLeafSHA256 {
		return Workload{}, managedMount{}, "", errors.New("member TLS leaf differs from signed authority pin")
	}
	if pool := x509.NewCertPool(); !pool.AppendCertsFromPEM(contents["client-ca.pem"]) {
		return Workload{}, managedMount{}, "", errors.New("member client CA roots are invalid")
	}
	clientArgs, err := readManagedClientMaterial(paths.material, launch.Runtime.ClientManagedMaterialManifestSHA256, identity, 0)
	if err != nil {
		return Workload{}, managedMount{}, "", fmt.Errorf("managed client HTTPS material: %w", err)
	}
	_, credentialState, err := readManagedCredentialState(filepath.Join(paths.material, managedCredentialFileName), identity)
	if err != nil {
		return Workload{}, managedMount{}, "", fmt.Errorf("managed client credential state: %w", err)
	}
	if credentialState.Generation > 1 {
		clientArgs = append(clientArgs, "--client-credentials-current", filepath.Join(paths.material, managedCredentialFileName))
	}
	args := []string{
		"--signed-v2-s3-config", filepath.Join(paths.material, "signed-v2-s3-config.json"),
		"--data-dir", filepath.Join(paths.mount, "data"),
		"--memory-limit-bytes", strconv.FormatUint(launch.ProcessMemoryBytes, 10),
		"--memory-headroom-bytes", strconv.FormatUint(launch.MemoryHeadroomBytes, 10),
		"--replication-listen-addr", launch.Runtime.ReplicationListenAddress,
		"--replication-data-dir", managedShardPath(paths),
		"--authority-certificate", filepath.Join(paths.material, "authority.tbca"),
		"--trusted-public-key", filepath.Join(paths.material, "trusted-public-key"),
		"--replication-server-certificate", filepath.Join(paths.material, "server.crt"),
		"--replication-server-private-key", filepath.Join(paths.material, "server.key"),
		"--replication-client-ca-roots", filepath.Join(paths.material, "client-ca.pem"),
		"--cluster-id", launch.Member.Scope.ClusterID,
		"--tenant-id", launch.Member.Scope.TenantID,
		"--database-id", launch.Member.Scope.DatabaseID,
		"--shard-id", strconv.FormatUint(launch.Member.Scope.ShardID, 10),
		"--member-id", launch.Member.Scope.MemberID,
		"--member-incarnation", launch.Member.Scope.Incarnation,
		"--member-control-socket", paths.socket,
	}
	if nativeRoot {
		args = append(args, "--native-oci-root-socket", paths.nativeRoot)
	}
	if launch.Runtime.ReplicationPeerMemberID != "" {
		roots, err := verifyManagedMaterial(filepath.Join(paths.material, "server-ca.pem"), launch.Runtime.ReplicationServerCASHA256, identity, 1<<20)
		if err != nil {
			return Workload{}, managedMount{}, "", err
		}
		if pool := x509.NewCertPool(); !pool.AppendCertsFromPEM(roots) {
			return Workload{}, managedMount{}, "", errors.New("member server CA roots are invalid")
		}
		args = append(args, "--replication-peer-member-id", launch.Runtime.ReplicationPeerMemberID,
			"--replication-peer-addr", launch.Runtime.ReplicationPeerAddress,
			"--replication-server-ca-roots", filepath.Join(paths.material, "server-ca.pem"))
	}
	args = append(args, clientArgs...)
	var childEnv map[string]string
	if executable != "" {
		if cfg.ManagedS3Credentials == nil {
			return Workload{}, managedMount{}, "", errors.New("managed S3 credential resolver is unavailable")
		}
		credentials, err := cfg.ManagedS3Credentials.Resolve(ctx, launch.Runtime.LiveS3Credential)
		if err != nil {
			return Workload{}, managedMount{}, "", errors.New("managed S3 credential resolution failed")
		}
		if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
			return Workload{}, managedMount{}, "", errors.New("managed S3 credential response is incomplete")
		}
		childEnv = map[string]string{"AWS_ACCESS_KEY_ID": credentials.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY": credentials.SecretAccessKey}
	}
	keepMount = true
	return Workload{Role: d.Role, Digest: d.Digest, Fingerprint: fingerprint, Executable: executable,
		Args: args, Env: childEnv,
		CgroupMemoryMaxBytes: launch.CgroupMemoryMaxBytes, SystemReserveBytes: launch.SystemReserveBytes}, mount, paths.socket, nil
}

func removeStoppedMemberSocket(path string, identity WorkloadIdentity) error {
	parent, err := inspectMemberSocket(path, identity)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := verifyMemberSocket(path, identity, parent); err != nil {
		return err
	}
	return os.Remove(path)
}

func readManagedStatus(ctx context.Context, runner Runner, d Desired, socket string) (MemberStatus, string, string, error) {
	p, ok := runner.(*processRunner)
	if !ok || p == nil {
		return MemberStatus{}, "", "", errors.New("managed status requires native process runner")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		status, err := ReadMemberStatus(ctx, p, ExpectedMemberStatus{SocketPath: socket, Role: d.Role,
			Scope: d.ManagedMember.Member.Scope, Authority: d.ManagedMember.Authority})
		if err == nil {
			pid, start, cgroup, observationErr := observeMemberProcess(ctx, p, d.Role)
			if observationErr == nil && pid == status.Process.PID && status.Local.StorageRecovered && status.Local.ReplicationListenerReady && status.Local.Healthy && status.Local.Ready {
				return status, start, cgroup, nil
			}
			if observationErr != nil {
				err = observationErr
			} else {
				err = errors.New("member local runtime is not ready")
			}
		}
		if time.Now().After(deadline) {
			return MemberStatus{}, "", "", fmt.Errorf("managed member status not ready: %w", err)
		}
		select {
		case <-ctx.Done():
			return MemberStatus{}, "", "", ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (a *Agent) reconcileManaged(ctx context.Context, d Desired, target desiredReply) (resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, a.stopManagedNativeRoot(d.Role))
		}
	}()
	launch := d.ManagedMember
	current, err := a.runner.Observe(ctx, d.Role)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	if current.Running && current.CgroupMemoryMaxBytes != launch.CgroupMemoryMaxBytes {
		return errors.Join(errors.New("managed role memory.max drifted from desired cap"), a.runner.Stop(ctx, d.Role))
	}
	if launch.Runtime == nil || a.cfg.ManagedRuntimeRoot == "" {
		return errors.Join(errors.New("managed member launch awaits verified mount, artifact, authority material and member identity"), a.runner.Stop(ctx, d.Role))
	}
	if target.Registration == nil || target.Registration.SystemReserveBytes <= 0 ||
		a.cfg.BakedSystemReserveBytes == 0 ||
		launch.SystemReserveBytes != a.cfg.BakedSystemReserveBytes ||
		uint64(target.Registration.SystemReserveBytes) != a.cfg.BakedSystemReserveBytes {
		return errors.Join(errors.New("managed system reserve differs from image priority profile"), a.runner.Stop(ctx, d.Role))
	}
	check := a.memoryCheck
	if check == nil {
		check = validateManagedHostMemory
	}
	if err := check(*target.Registration); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	fingerprint, err := desiredFingerprint(d)
	if err != nil {
		return err
	}
	if err := a.stopManagedNativeRootIfChanged(d.Role, fingerprint); err != nil {
		return err
	}
	executable, err := a.fetchArtifact(ctx, d.Role, d.Digest)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	if err := a.fetchManagedMaterial(ctx, d, *target.Registration); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	previousCredentialGeneration, credentialGeneration, credentialChanged, err := a.fetchManagedCredentials(ctx, d, *target.Registration)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	reloadCredentials := current.Running && credentialChanged && previousCredentialGeneration >= 2
	if current.Running && credentialChanged && credentialGeneration > 1 && !reloadCredentials {
		if err := a.runner.Stop(ctx, d.Role); err != nil {
			return err
		}
		current.Running = false
	}
	if err := a.ensureManagedVolume(ctx, d, target); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	_, mount, socket, err := prepareManagedRuntime(ctx, a.cfg, d, "", "")
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	defer mount.close()
	if current.Running && current.Digest == d.Digest && current.Fingerprint == fingerprint {
		paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *launch)
		if err != nil {
			return errors.Join(err, a.runner.Stop(ctx, d.Role))
		}
		certificate, err := verifyManagedMaterial(filepath.Join(paths.material, "authority.tbca"), launch.Authority.CertificateSHA256, a.cfg.WorkloadIdentity, 1<<20)
		if err == nil {
			err = inspectManagedVolumeClaim(paths, *launch, a.cfg.WorkloadIdentity, mount, certificate)
		}
		if err != nil {
			return errors.Join(err, a.runner.Stop(ctx, d.Role))
		}
		if err := a.ensureManagedNativeRoot(ctx, d, fingerprint); err != nil {
			return errors.Join(err, a.runner.Stop(ctx, d.Role))
		}
		if reloadCredentials {
			if err := a.reloadManagedCredentials(ctx, d, socket, credentialGeneration); err != nil {
				return errors.Join(err, a.runner.Stop(ctx, d.Role))
			}
		}
		return a.reportManagedStatus(ctx, d, mount, socket)
	}
	if err := a.stopManagedNativeRoot(d.Role); err != nil {
		return err
	}
	if err := a.runner.Stop(ctx, d.Role); err != nil {
		return err
	}
	if err := removeStoppedMemberSocket(socket, a.cfg.WorkloadIdentity); err != nil {
		return err
	}
	var latest desiredReply
	if err := a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{d.Role}, &latest); err != nil {
		return err
	}
	if err := a.validateDesiredReply(latest); err != nil {
		return err
	}
	if !sameDesiredReplyBinding(target, latest) {
		return errors.New("managed desired changed before native apply")
	}
	query := cycleQuery{}
	if pending, exists := a.pending[d.Role]; exists {
		query = pending.query
		if query.Role != d.Role || query.Digest != d.Digest || query.Generation != d.Generation ||
			query.AuthorityEpoch != d.AuthorityEpoch || query.Attempt == "" {
			return errors.New("managed pending cycle differs from signed desired")
		}
	} else {
		attempt, err := randomID()
		if err != nil {
			return err
		}
		query = cycleQuery{Role: d.Role, Digest: d.Digest, Generation: d.Generation, AuthorityEpoch: d.AuthorityEpoch, Attempt: attempt}
	}
	var cycle cycleReply
	if err := a.request(ctx, "cycle", query, &cycle); err != nil {
		return err
	}
	if cycle.State != "active" || cycle.CycleID == "" || cycle.Fence == 0 ||
		query.CycleID != "" && (query.CycleID != cycle.CycleID || query.Fence != cycle.Fence) {
		return errors.New("managed cycle is not active")
	}
	query.CycleID, query.Fence = cycle.CycleID, cycle.Fence
	a.pending[d.Role] = pendingCycle{query: query}
	defer func() {
		pending, ok := a.pending[d.Role]
		if !ok || pending.outcomeReady || ctx.Err() != nil || a.sessionLost.Load() {
			return
		}
		pending.outcomeReady = true
		a.pending[d.Role] = pending
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.flushCycle(finishCtx, d.Role)
	}()
	var active cycleReply
	if err := a.request(ctx, "cycle", cycleQuery{Role: d.Role, Digest: d.Digest, Generation: d.Generation,
		AuthorityEpoch: d.AuthorityEpoch, Attempt: query.Attempt}, &active); err != nil {
		return err
	}
	if active.State != "active" || active.CycleID != cycle.CycleID || active.Fence != cycle.Fence {
		return errors.New("managed cycle fence changed before native apply")
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	// Material and the mounted block device are rechecked across the network
	// round trips. A changed or absent binding never reaches native Apply.
	currentWorkload, currentMount, currentSocket, err := prepareManagedRuntime(ctx, a.cfg, d, executable, fingerprint)
	if err != nil {
		return errors.Join(errors.New("managed mount or material changed before apply"), err)
	}
	defer currentMount.close()
	if currentSocket != socket {
		return errors.New("managed control socket changed before apply")
	}
	if err := verifyManagedMountPair(currentMount, mount); err != nil {
		return errors.Join(errors.New("managed mount or material changed before apply"), err)
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *launch)
	if err != nil {
		return err
	}
	if err := requireManagedRoleQuiescent(a.runner, d.Role); err != nil {
		return err
	}
	certificate, err := verifyManagedMaterial(filepath.Join(paths.material, "authority.tbca"), launch.Authority.CertificateSHA256, a.cfg.WorkloadIdentity, 1<<20)
	if err != nil {
		return err
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	if err := ensureManagedVolumeClaim(paths, *launch, a.cfg.WorkloadIdentity, currentMount, certificate); err != nil {
		return fmt.Errorf("managed retained volume claim held: %w", err)
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	if err := a.ensureManagedNativeRoot(ctx, d, fingerprint); err != nil {
		return err
	}
	if err := a.runner.Apply(ctx, currentWorkload); err != nil {
		return err
	}
	if err := verifyManagedMountPair(currentMount, mount); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	if err := a.reportManagedStatus(ctx, d, mount, socket); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	pending := a.pending[d.Role]
	pending.query.Succeeded = true
	pending.outcomeReady = true
	a.pending[d.Role] = pending
	return a.flushCycle(ctx, d.Role)
}

func (a *Agent) reportManagedStatus(ctx context.Context, d Desired, mount managedMount, socket string) error {
	if err := verifyManagedDeviceWitness(mount); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	status, start, cgroup, err := readManagedStatus(ctx, a.runner, d, socket)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *d.ManagedMember)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	_, credentialState, err := readManagedCredentialState(filepath.Join(paths.material, managedCredentialFileName), a.cfg.WorkloadIdentity)
	if err != nil || credentialState.Generation > 1 && status.CredentialGeneration != credentialState.Generation {
		return errors.Join(errors.New("native client credential generation is behind the durable host floor"),
			err, a.runner.Stop(ctx, d.Role))
	}
	// TerraBase constructs this status identity only after accepting the signed
	// authority and certifying the local TLS leaf. Recheck host-owned byte pins
	// and the mount after that native validation, before publishing any report.
	_, check, checkSocket, err := prepareManagedRuntime(ctx, a.cfg, d, "", "")
	if err != nil {
		return errors.Join(errors.New("managed mount or material changed while reading process status"), err, a.runner.Stop(ctx, d.Role))
	}
	defer check.close()
	if checkSocket != socket || paths.mount != d.ManagedMember.Runtime.MountPath {
		return errors.Join(errors.New("managed control socket or mount path changed while reading process status"), a.runner.Stop(ctx, d.Role))
	}
	if err := verifyManagedMountPair(check, mount); err != nil {
		return errors.Join(errors.New("managed mount or material changed while reading process status"), err, a.runner.Stop(ctx, d.Role))
	}
	proof, err := readManagedServingProof(ctx, a.runner, d, socket, status)
	if err != nil {
		return errors.Join(errors.New("managed serving proof could not be bound to the native process"), err, a.runner.Stop(ctx, d.Role))
	}
	if err := verifyManagedMountPair(check, mount); err != nil {
		return errors.Join(errors.New("managed mount changed while reading serving proof"), err, a.runner.Stop(ctx, d.Role))
	}
	report := a.reportFor(d, "running", nil)
	report.Managed = &ManagedRuntimeReport{
		ClientCredentialGeneration: status.CredentialGeneration,
		Member:                     d.ManagedMember.Member, Authority: d.ManagedMember.Authority, OCI: d.ManagedMember.OCI,
		VolumeID: d.ManagedMember.VolumeID, AttachmentID: d.ManagedMember.AttachmentID,
		AttachmentETag: d.ManagedMember.AttachmentETag,
		FileSystemUUID: mount.uuid, FileSystemType: mount.fsType,
		MountDevice: mount.device, MountPath: paths.mount, MountID: mount.id,
		ProcessPID: status.Process.PID, ProcessStart: start, ProcessCgroup: cgroup,
		ProcessBootID: status.Process.StartNonce, StorageRecovered: status.Local.StorageRecovered,
		ListenerReady: status.Local.ReplicationListenerReady, ServingProof: proof,
	}
	if err := a.publishReport(ctx, report); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	return nil
}

func validateManagedReportForDesired(report Report, desired Desired) error {
	if desired.ManagedMember == nil {
		if report.Managed != nil {
			return errors.New("generic desired cannot accept a managed process report")
		}
		return nil
	}
	if report.State != "running" {
		if report.Managed != nil {
			return errors.New("nonrunning managed report cannot carry process proof")
		}
		return nil
	}
	launch, observation := desired.ManagedMember, report.Managed
	if launch.Runtime == nil || observation == nil || observation.Member != launch.Member ||
		observation.Authority != launch.Authority || observation.OCI != launch.OCI ||
		observation.VolumeID != launch.VolumeID || observation.AttachmentID != launch.AttachmentID ||
		observation.AttachmentETag != launch.AttachmentETag ||
		observation.FileSystemUUID != launch.Runtime.FileSystemUUID ||
		observation.FileSystemType != launch.Runtime.FileSystemType ||
		observation.MountDevice != launch.Runtime.DevicePath || observation.MountPath != launch.Runtime.MountPath ||
		observation.MountID == 0 || observation.ProcessPID < 2 || observation.ProcessStart == "" ||
		!strings.HasPrefix(observation.ProcessCgroup, "/") || !lowerHex(observation.ProcessBootID, 32) ||
		!observation.StorageRecovered || !observation.ListenerReady {
		return errors.New("managed report lacks exact mounted process identity")
	}
	if proof := observation.ServingProof; proof != nil {
		if proof.SchemaVersion != 1 || proof.Process.PID != observation.ProcessPID ||
			proof.Process.StartNonce != observation.ProcessBootID ||
			proof.Scope != (memberstatus.Scope{
				ClusterID: launch.Member.Scope.ClusterID, TenantID: launch.Member.Scope.TenantID,
				DatabaseID: launch.Member.Scope.DatabaseID, ShardID: launch.Member.Scope.ShardID,
				MemberID: launch.Member.Scope.MemberID, Incarnation: launch.Member.Scope.Incarnation,
			}) || proof.Authority != (memberstatus.Authority{
			Epoch: launch.Authority.Epoch, ConfigurationID: launch.Authority.ConfigurationID,
			CertificateSHA256: launch.Authority.CertificateSHA256, TLSLeafSHA256: launch.Authority.TLSLeafSHA256,
		}) || !proof.Serving || !proof.Listeners.Client || !proof.Listeners.Replication ||
			proof.Replication.PeerMemberID != launch.Runtime.ReplicationPeerMemberID {
			return errors.New("managed serving proof differs from the desired process or signed member")
		}
	}
	return nil
}
