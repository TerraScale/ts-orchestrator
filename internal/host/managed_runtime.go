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

	"golang.org/x/sys/unix"
)

// These paths are host-owned, not supplied by a workload or an arbitrary
// controller field. An operator provisions the exact files and a mounted,
// preformatted retained volume before the signed desired may be executed.
type managedRuntimePaths struct {
	memberDir, mount, material, socket string
}

type managedMount struct {
	id     uint64
	device string
	uuid   string
	fsType string
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
		memberDir: memberDir,
		mount:     filepath.Join(memberDir, "volume"),
		material:  filepath.Join(memberDir, "material"),
		socket:    filepath.Join(memberDir, "control", "member.sock"),
	}
	if len(paths.socket) >= 108 {
		return managedRuntimePaths{}, errors.New("managed control socket path exceeds Unix limit")
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

func verifyManagedMount(paths managedRuntimePaths, pins ManagedRuntimePins, identity WorkloadIdentity) (managedMount, error) {
	if paths.mount != pins.MountPath {
		return managedMount{}, errors.New("managed mount path differs from signed pin")
	}
	if err := verifyManagedDirectory(paths.memberDir, identity, 0750); err != nil {
		return managedMount{}, err
	}
	deviceInfo, err := os.Lstat(pins.DevicePath)
	if err != nil {
		return managedMount{}, err
	}
	device, ok := deviceInfo.Sys().(*syscall.Stat_t)
	if !ok || deviceInfo.Mode()&os.ModeDevice == 0 || deviceInfo.Mode()&os.ModeCharDevice != 0 || deviceInfo.Mode()&os.ModeSymlink != 0 || device.Uid != 0 {
		return managedMount{}, errors.New("managed device is not an exact root-owned block device")
	}
	uuidInfo, err := os.Stat(filepath.Join("/dev/disk/by-uuid", pins.FileSystemUUID))
	if err != nil {
		return managedMount{}, err
	}
	uuidDevice, ok := uuidInfo.Sys().(*syscall.Stat_t)
	if !ok || uuidDevice.Rdev != device.Rdev {
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
	if !ok || !validManagedMountRoot(mountedStat, mountInfo.Mode(), identity, device.Rdev) {
		return managedMount{}, errors.New("managed volume root is tenant-writable or has wrong device")
	}
	mount, err := findExclusiveMount("/proc/self/mountinfo", paths.mount, device.Rdev, pins.FileSystemType)
	if err != nil {
		return managedMount{}, err
	}
	for _, child := range []string{"data", "replication"} {
		info, err := os.Lstat(filepath.Join(paths.mount, child))
		if err != nil {
			return managedMount{}, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Dev != device.Rdev ||
			owner.Uid != identity.UID || owner.Gid != identity.GID || info.Mode().Perm() != 0700 {
			return managedMount{}, fmt.Errorf("unsafe managed volume %s directory", child)
		}
	}
	return managedMount{id: mount, device: pins.DevicePath, uuid: pins.FileSystemUUID, fsType: pins.FileSystemType}, nil
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
	files := []struct {
		name, digest string
		maximum      int64
	}{
		{"authority.tbca", launch.Authority.CertificateSHA256, 1 << 20},
		{"trusted-public-key", launch.Runtime.TrustedKeySHA256, 32},
		{"server.crt", launch.Runtime.ServerCertificateSHA256, 1 << 20},
		{"server.key", launch.Runtime.ServerPrivateKeySHA256, 1 << 20},
		{"client-ca.pem", launch.Runtime.ClientCARootsSHA256, 1 << 20},
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
	args := []string{
		"--data-dir", filepath.Join(paths.mount, "data"),
		"--memory-limit-bytes", strconv.FormatUint(launch.ProcessMemoryBytes, 10),
		"--memory-headroom-bytes", strconv.FormatUint(launch.MemoryHeadroomBytes, 10),
		"--replication-listen-addr", launch.Runtime.ReplicationListenAddress,
		"--replication-data-dir", filepath.Join(paths.mount, "replication"),
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
	return Workload{Role: d.Role, Digest: d.Digest, Fingerprint: fingerprint, Executable: executable,
		Args: args, CgroupMemoryMaxBytes: launch.CgroupMemoryMaxBytes}, mount, paths.socket, nil
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

func (a *Agent) reconcileManaged(ctx context.Context, d Desired, target desiredReply) error {
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
	executable, err := a.fetchArtifact(ctx, d.Role, d.Digest)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	workload, mount, socket, err := prepareManagedRuntime(ctx, a.cfg, d, executable, fingerprint)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	if current.Running && current.Digest == d.Digest && current.Fingerprint == fingerprint {
		return a.reportManagedStatus(ctx, d, mount, socket)
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
	_, currentMount, currentSocket, err := prepareManagedRuntime(ctx, a.cfg, d, executable, fingerprint)
	if err != nil || currentMount != mount || currentSocket != socket {
		return errors.Join(errors.New("managed mount or material changed before apply"), err)
	}
	if err := a.runner.Apply(ctx, workload); err != nil {
		return err
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
	status, start, cgroup, err := readManagedStatus(ctx, a.runner, d, socket)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *d.ManagedMember)
	if err != nil {
		return errors.Join(err, a.runner.Stop(ctx, d.Role))
	}
	// TerraBase constructs this status identity only after accepting the signed
	// authority and certifying the local TLS leaf. Recheck host-owned byte pins
	// and the mount after that native validation, before publishing any report.
	_, check, checkSocket, err := prepareManagedRuntime(ctx, a.cfg, d, "", "")
	if err != nil || check != mount || checkSocket != socket || paths.mount != d.ManagedMember.Runtime.MountPath {
		return errors.Join(errors.New("managed mount or material changed while reading process status"), err, a.runner.Stop(ctx, d.Role))
	}
	report := a.reportFor(d, "running", nil)
	report.Managed = &ManagedRuntimeReport{
		Member: d.ManagedMember.Member, Authority: d.ManagedMember.Authority, OCI: d.ManagedMember.OCI,
		VolumeID: d.ManagedMember.VolumeID, AttachmentID: d.ManagedMember.AttachmentID,
		FileSystemUUID: mount.uuid, FileSystemType: mount.fsType,
		MountDevice: mount.device, MountPath: paths.mount, MountID: mount.id,
		ProcessPID: status.Process.PID, ProcessStart: start, ProcessCgroup: cgroup,
		ProcessBootID: status.Process.StartNonce, StorageRecovered: status.Local.StorageRecovered,
		ListenerReady: status.Local.ReplicationListenerReady,
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
		observation.FileSystemUUID != launch.Runtime.FileSystemUUID ||
		observation.FileSystemType != launch.Runtime.FileSystemType ||
		observation.MountDevice != launch.Runtime.DevicePath || observation.MountPath != launch.Runtime.MountPath ||
		observation.MountID == 0 || observation.ProcessPID < 2 || observation.ProcessStart == "" ||
		!strings.HasPrefix(observation.ProcessCgroup, "/") || !lowerHex(observation.ProcessBootID, 32) ||
		!observation.StorageRecovered || !observation.ListenerReady {
		return errors.New("managed report lacks exact mounted process identity")
	}
	return nil
}
