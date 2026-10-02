//go:build linux

package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"golang.org/x/sys/unix"
)

const volumeInitSocketPath = "/run/terrascale-orchestrator-volume-init.sock"

type VolumeInitConfig struct {
	Cell, Node, Environment string
	ControllerPublicKey     ed25519.PublicKey
	ManagedRuntimeRoot      string
	StateRoot               string
	WorkloadIdentity        WorkloadIdentity
	ReadMetadata            func(context.Context) (VolumeInitMetadata, error)
	// Grow enables online filesystem growth after an OCI volume resize. It is
	// off by default; ext4 growth needs CAP_SYS_RESOURCE in the unit.
	Grow hostvolume.GrowConfig
}

type VolumeInitMetadata struct {
	InstanceID string
	Descriptor hostboot.Descriptor
}

type volumeFilesystemProbe struct {
	FSUUID, FSType    string
	Signatures        bool
	ForeignSignatures bool
	Mounted           bool
	BlankSample       bool
}

type volumeInitAction uint8

const (
	volumeInitHold volumeInitAction = iota
	volumeInitFormat
	volumeInitMount
)

type volumeInitEffects struct {
	Consume func() error
	Format  func(context.Context) error
	Probe   func(context.Context) (volumeFilesystemProbe, error)
	Mount   func(context.Context, bool) error
}

// executeVolumeInitAction is the ordered mutation seam shared by the real
// helper and rootless tests. The one-way durable marker precedes mkfs, and a
// retry after a crash can only adopt a positively matching filesystem.
func executeVolumeInitAction(ctx context.Context, pins ManagedRuntimePins, probe volumeFilesystemProbe,
	allowFormat, consumed bool, expiresAt time.Time, effects volumeInitEffects,
) error {
	action, err := volumeInitActionFor(probe, pins, allowFormat, consumed)
	if err != nil {
		return err
	}
	if effects.Mount == nil {
		return errors.New("volume initializer has no mount effect")
	}
	if action == volumeInitFormat {
		if !storage.ValidFileSystem(pins.FileSystemType) || effects.Consume == nil || effects.Format == nil || effects.Probe == nil {
			return errors.New("fresh managed formatting requires a supported ext4 or xfs pin and effects")
		}
		if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
			return errors.New("volume format permit expired before disk effect")
		}
		if err := effects.Consume(); err != nil {
			return err
		}
		if err := effects.Format(ctx); err != nil {
			return err
		}
		observed, err := effects.Probe(ctx)
		if err != nil || observed.Mounted || observed.ForeignSignatures ||
			observed.FSUUID != pins.FileSystemUUID || observed.FSType != pins.FileSystemType {
			return errors.New("formatted managed filesystem did not read back exact UUID and type")
		}
	}
	return effects.Mount(ctx, action == volumeInitFormat || consumed)
}

func volumeInitActionFor(probe volumeFilesystemProbe, pins ManagedRuntimePins, allowFormat, consumed bool) (volumeInitAction, error) {
	if probe.Mounted {
		return volumeInitHold, errors.New("managed block device is already mounted")
	}
	if probe.FSUUID == pins.FileSystemUUID && probe.FSType == pins.FileSystemType &&
		probe.Signatures && !probe.ForeignSignatures {
		return volumeInitMount, nil
	}
	if probe.FSUUID != "" || probe.FSType != "" || probe.Signatures || !probe.BlankSample {
		return volumeInitHold, errors.New("managed block device contains foreign or ambiguous data")
	}
	if !allowFormat || consumed {
		return volumeInitHold, errors.New("managed blank volume has no unused first-format authority")
	}
	return volumeInitFormat, nil
}

// RunVolumeInitializer serves the fixed root-only systemd socket. The signed
// envelope is the authorization boundary; peer credentials only reject a
// request originating outside the host manager service.
func RunVolumeInitializer(ctx context.Context, cfg VolumeInitConfig) error {
	if os.Geteuid() != 0 || len(cfg.ControllerPublicKey) != ed25519.PublicKeySize ||
		cfg.Cell == "" || cfg.Node == "" || cfg.ManagedRuntimeRoot == "" || cfg.StateRoot == "" {
		return errors.New("volume initializer requires fixed root host identity and paths")
	}
	if os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return errors.New("volume initializer requires one systemd-activated socket")
	}
	file := os.NewFile(3, "volume-init-socket")
	if file == nil {
		return errors.New("volume initializer socket is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if unixConnection, ok := connection.(*net.UnixConn); ok {
			// The caller only sees a closed connection; the journal keeps the cause.
			if err := serveVolumeInitConnection(ctx, cfg, unixConnection); err != nil {
				slog.Warn("volume initialization request failed", "error", err)
			}
		}
		_ = connection.Close()
	}
}

func serveVolumeInitConnection(ctx context.Context, cfg VolumeInitConfig, connection *net.UnixConn) error {
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Minute))
	if err := requireHostManagerPeer(connection); err != nil {
		return err
	}
	var size [4]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > 64<<10 {
		return errors.New("volume initialization permit is too large")
	}
	wire := make([]byte, length)
	if _, err := io.ReadFull(connection, wire); err != nil {
		return err
	}
	var signed protocol.Envelope
	if err := protocol.DecodeStrict(wire, &signed, 64<<10); err != nil {
		return err
	}
	if cfg.ReadMetadata == nil {
		return errors.New("volume initializer has no instance metadata reader")
	}
	metadata, err := cfg.ReadMetadata(requestCtx)
	if err != nil {
		return err
	}
	permit, err := verifyVolumeInitPermit(cfg, signed, metadata)
	if err != nil {
		return err
	}
	if err := prepareManagedVolumeDevice(requestCtx, cfg, permit); err != nil {
		return err
	}
	_, err = connection.Write([]byte{0})
	return err
}

func requireHostManagerPeer(connection *net.UnixConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var credentials *unix.Ucred
	if err := raw.Control(func(fd uintptr) {
		credentials, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if err != nil || credentials == nil || credentials.Uid != 0 || credentials.Pid < 2 {
		return errors.New("volume initializer caller is not the root host manager")
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", credentials.Pid))
	if err != nil || !bytes.Contains(cgroup, []byte("/terrascale-orchestrator-host.service")) {
		return errors.New("volume initializer caller is outside host manager service")
	}
	return nil
}

func verifyVolumeInitPermit(cfg VolumeInitConfig, signed protocol.Envelope, metadata VolumeInitMetadata) (volumeInitPermit, error) {
	if err := protocol.VerifyEnvelope(signed, protocol.EnvelopeScope{
		Region: cfg.Cell, Kind: "host.response.volume-init", Actor: "controller",
		OperationID: signed.OperationID, Epoch: signed.Epoch,
	}, cfg.ControllerPublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: requestTTL, ClockSkew: maxClockSkew}); err != nil {
		return volumeInitPermit{}, err
	}
	var reply response
	if err := decodeStrict([]byte(signed.Payload), &reply); err != nil {
		return volumeInitPermit{}, err
	}
	if reply.Error != "" || reply.Nonce != signed.OperationID || reply.Epoch != signed.Epoch ||
		reply.Operation != "volume-init" || reply.Node != cfg.Node || reply.SessionID == "" {
		return volumeInitPermit{}, errors.New("volume initializer response binding is invalid")
	}
	var permit volumeInitPermit
	if err := decodeStrict(reply.Payload, &permit); err != nil {
		return volumeInitPermit{}, err
	}
	d, r := permit.Desired, permit.Registration
	if permit.SessionID != reply.SessionID || permit.DesiredRevision == 0 || permit.RegistrationRevision == 0 ||
		d.Cell != cfg.Cell || d.Node != cfg.Node || d.Environment != cfg.Environment || d.Withdrawn ||
		d.AuthorityEpoch == 0 || d.ManagedMember == nil || d.ManagedMember.Runtime == nil ||
		r.Cell != cfg.Cell || r.Node != cfg.Node || r.Environment != cfg.Environment ||
		r.ManagedOCI == nil || r.ManagedPlacement == nil || r.ManagedMember == nil {
		return volumeInitPermit{}, errors.New("volume initializer desired, session or registration differs from host")
	}
	if err := validateDesired(d, cfg.Cell, r); err != nil {
		return volumeInitPermit{}, err
	}
	launch := d.ManagedMember
	if launch.OCI != *r.ManagedOCI || launch.Member != *r.ManagedMember ||
		launch.OCI.InstanceID != metadata.InstanceID || launch.OCI.Region != metadata.Descriptor.Region ||
		launch.OCI.CreateKey != metadata.Descriptor.CreateKey || launch.OCI.Owner != metadata.Descriptor.Owner ||
		launch.OCI.FleetGeneration != metadata.Descriptor.FleetGeneration ||
		metadata.Descriptor.Node != cfg.Node || metadata.Descriptor.DatabaseID != r.ManagedPlacement.DatabaseID ||
		metadata.Descriptor.PartitionID != r.ManagedPlacement.PartitionID ||
		metadata.Descriptor.SeatID != r.ManagedPlacement.SeatID ||
		metadata.Descriptor.HostAttempt != launch.Member.HostAttempt ||
		metadata.Descriptor.IntentGeneration != r.ManagedPlacement.IntentGeneration ||
		metadata.Descriptor.IntentPayloadDigest != r.ManagedPlacement.IntentPayloadDigest ||
		metadata.Descriptor.CanonicalRosterDigest != r.ManagedPlacement.CanonicalRosterDigest ||
		metadata.Descriptor.ManagedHostProfileDigest != r.ManagedPlacement.ManagedHostProfileDigest ||
		metadata.Descriptor.RuntimeManifestDigest == "" {
		return volumeInitPermit{}, errors.New("volume initializer IMDS descriptor differs from signed host")
	}
	digest, err := metadata.Descriptor.Digest()
	if err != nil || digest != permit.Observation.BootDescriptorSHA256 {
		return volumeInitPermit{}, errors.New("volume initializer boot descriptor differs from owned OCI host")
	}
	paths, err := runtimePaths(cfg.ManagedRuntimeRoot, *launch)
	if err != nil || launch.Runtime.MountPath != paths.mount {
		return volumeInitPermit{}, errors.New("volume initializer mount path differs from signed host root")
	}
	permit.expiresAt = signed.ExpiresAt
	return permit, nil
}

func prepareManagedVolumeDevice(ctx context.Context, cfg VolumeInitConfig, permit volumeInitPermit) error {
	launch := permit.Desired.ManagedMember
	if launch == nil || launch.Runtime == nil {
		return errors.New("volume initializer lacks runtime pins")
	}
	paths, err := runtimePaths(cfg.ManagedRuntimeRoot, *launch)
	if err != nil {
		return err
	}
	if err := verifyManagedDirectory(cfg.ManagedRuntimeRoot, cfg.WorkloadIdentity, 0750); err != nil {
		return err
	}
	if err := verifyManagedDirectory(paths.memberDir, cfg.WorkloadIdentity, 0750); err != nil {
		return err
	}
	device, err := managedBlockDevice(launch.Runtime.DevicePath)
	if err != nil {
		return err
	}
	defer device.close()
	if err := rejectBootOrPartitionDevice(device.stat.Rdev); err != nil {
		return err
	}
	lock, consumed, err := lockVolumeFormatState(cfg.StateRoot, permit)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}()
	if mounted, err := verifyManagedMount(paths, *launch.Runtime, cfg.WorkloadIdentity); err == nil {
		maintainManagedMount(ctx, cfg, paths, mounted, device)
		mounted.close()
		return requireManagedVolumeProvenance(paths, *launch, consumed)
	}
	if alreadyMounted, err := blockDeviceMounted("/proc/self/mountinfo", device.stat.Rdev); err != nil {
		return err
	} else if alreadyMounted {
		if _, err := findExclusiveMount("/proc/self/mountinfo", paths.mount, device.stat.Rdev, launch.Runtime.FileSystemType); err != nil {
			return err
		}
		if err := waitManagedUUID(ctx, launch.Runtime.FileSystemUUID, device.stat.Rdev); err != nil {
			return err
		}
		if err := completeManagedVolumeLayout(paths.mount, *launch.Runtime, cfg.WorkloadIdentity,
			device.stat.Rdev, consumed); err != nil {
			return err
		}
		mount, err := verifyManagedMount(paths, *launch.Runtime, cfg.WorkloadIdentity)
		if err != nil {
			return err
		}
		maintainManagedMount(ctx, cfg, paths, mount, device)
		mount.close()
		return requireManagedVolumeProvenance(paths, *launch, consumed)
	}
	if occupied, err := mountTargetOccupied("/proc/self/mountinfo", paths.mount); err != nil {
		return err
	} else if occupied {
		return errors.New("managed mount target is occupied by another filesystem")
	}
	probe, err := probeManagedVolume(ctx, device)
	if err != nil {
		return err
	}
	err = executeVolumeInitAction(ctx, *launch.Runtime, probe, permit.Observation.AllowFormat, consumed,
		permit.expiresAt, volumeInitEffects{
			Consume: func() error { return consumeVolumeFormatState(cfg.StateRoot, permit) },
			Format: func(ctx context.Context) error {
				if err := verifyOpenDeviceIdentity(device.fd, device.stat); err != nil {
					return err
				}
				current, err := managedBlockDevice(launch.Runtime.DevicePath)
				if err != nil {
					return err
				}
				same := sameDeviceObject(device.stat, current.stat)
				current.close()
				if !same {
					return errors.New("managed block alias changed before format")
				}
				return formatManagedFilesystem(ctx, device, launch.Runtime.FileSystemType, launch.Runtime.FileSystemUUID)
			},
			Probe: func(ctx context.Context) (volumeFilesystemProbe, error) { return probeManagedVolume(ctx, device) },
			Mount: func(ctx context.Context, complete bool) error {
				return mountManagedVolume(ctx, device, paths, *launch.Runtime, cfg.WorkloadIdentity, complete)
			},
		})
	if err != nil {
		return err
	}
	mount, err := verifyManagedMount(paths, *launch.Runtime, cfg.WorkloadIdentity)
	if err != nil {
		return err
	}
	maintainManagedMount(ctx, cfg, paths, mount, device)
	mount.close()
	return requireManagedVolumeProvenance(paths, *launch, true)
}

func requireManagedVolumeProvenance(paths managedRuntimePaths, launch ManagedMemberLaunch, consumed bool) error {
	claimed, err := managedVolumeHasExactClaim(paths, launch)
	if err != nil {
		return err
	}
	if claimed || consumed {
		return nil
	}
	return errors.New("unclaimed managed filesystem lacks local first-format provenance")
}

func managedVolumeHasExactClaim(paths managedRuntimePaths, launch ManagedMemberLaunch) (bool, error) {
	path := filepath.Join(paths.mount, managedVolumeClaimName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		owner.Uid != 0 || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return false, errors.New("managed volume claim has unsafe metadata")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(wire, managedVolumeClaimBytes(launch)) {
		return false, errors.New("managed volume claim differs from signed member")
	}
	return true, nil
}

func volumeFormatStatePath(root string, permit volumeInitPermit) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return "", errors.New("volume format state root is invalid")
	}
	launch := permit.Desired.ManagedMember
	if launch == nil || launch.Runtime == nil {
		return "", errors.New("volume format state lacks runtime")
	}
	key := sha256.Sum256([]byte(launch.VolumeID))
	return filepath.Join(root, "volume-format", hex.EncodeToString(key[:])[:32]), nil
}

func lockVolumeFormatState(root string, permit volumeInitPermit) (*os.File, bool, error) {
	path, err := volumeFormatStatePath(root, permit)
	if err != nil {
		return nil, false, err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, false, errors.New("volume format state directory is unsafe")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, false, errors.New("volume format state is not root-owned")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, false, err
	}
	_, err = os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = lock.Close()
		return nil, false, err
	}
	if err == nil {
		content, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(content, volumeFormatStateBytes(permit)) {
			_ = lock.Close()
			return nil, false, errors.New("volume format attempt belongs to another exact binding")
		}
	}
	return lock, err == nil, nil
}

func consumeVolumeFormatState(root string, permit volumeInitPermit) error {
	path, err := volumeFormatStatePath(root, permit)
	if err != nil {
		return err
	}
	content := volumeFormatStateBytes(permit)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func volumeFormatStateBytes(permit volumeInitPermit) []byte {
	launch := permit.Desired.ManagedMember
	return []byte(launch.OCI.InstanceID + "\n" + launch.VolumeID + "\n" + launch.AttachmentID + "\n" +
		launch.AttachmentETag + "\n" + launch.Runtime.DevicePath + "\n" +
		launch.Runtime.FileSystemUUID + "\n" + launch.Runtime.FileSystemType + "\n")
}

func probeManagedVolume(ctx context.Context, device *managedDevice) (volumeFilesystemProbe, error) {
	var probe volumeFilesystemProbe
	mounted, err := blockDeviceMounted("/proc/self/mountinfo", device.stat.Rdev)
	if err != nil {
		return probe, err
	}
	probe.Mounted = mounted
	if mounted {
		return probe, nil
	}
	output, code, err := runPinnedBlockTool(ctx, device, "/usr/sbin/blkid", "-p", "-o", "export")
	if err != nil || code != 0 && code != 2 {
		return probe, errors.New("managed block identity probe failed")
	}
	if code == 0 {
		for _, line := range strings.Split(output, "\n") {
			if value, ok := strings.CutPrefix(line, "UUID="); ok {
				probe.FSUUID = value
			}
			if value, ok := strings.CutPrefix(line, "TYPE="); ok {
				probe.FSType = value
			}
		}
	}
	output, code, err = runPinnedBlockTool(ctx, device, "/usr/sbin/wipefs", "--no-act", "--noheadings", "--output", "OFFSET,TYPE")
	if err != nil || code != 0 {
		return probe, errors.New("managed block signature probe failed")
	}
	probe.Signatures = strings.TrimSpace(output) != ""
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != probe.FSType {
			probe.ForeignSignatures = true
		}
	}
	if probe.FSUUID != "" || probe.FSType != "" || probe.Signatures {
		return probe, nil
	}
	blank, err := sampledManagedBlockZero(device)
	if err != nil {
		return probe, err
	}
	probe.BlankSample = blank
	return probe, nil
}

func runPinnedBlockTool(ctx context.Context, device *managedDevice, tool string, args ...string) (string, int, error) {
	duplicate, err := unix.Dup(device.fd)
	if err != nil {
		return "", 0, err
	}
	file := os.NewFile(uintptr(duplicate), "managed-block-witness")
	defer file.Close()
	cmd := exec.CommandContext(ctx, tool, append(args, "/proc/self/fd/3")...)
	cmd.ExtraFiles = []*os.File{file}
	output, err := cmd.Output()
	if len(output) > 4096 {
		return "", 0, errors.New("managed block probe output exceeds bound")
	}
	if err == nil {
		return string(output), 0, nil
	}
	var status *exec.ExitError
	if errors.As(err, &status) {
		return string(output), status.ExitCode(), nil
	}
	return "", 0, err
}

func blockDeviceMounted(path string, rdev uint64) (bool, error) {
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

func mountTargetOccupied(path, target string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) > 4 && fields[4] == target {
			return true, nil
		}
	}
	return false, scan.Err()
}

func sampledManagedBlockZero(device *managedDevice) (bool, error) {
	path := fmt.Sprintf("/proc/self/fd/%d", device.fd)
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	length, err := file.Seek(0, io.SeekEnd)
	if err != nil || length < 50<<30 {
		return false, errors.New("managed retained block volume is smaller than the minimum OCI volume")
	}
	const sample = int64(1 << 20)
	buf := make([]byte, sample)
	for _, offset := range []int64{0, length / 3, 2 * length / 3, length - sample} {
		if _, err := file.ReadAt(buf, offset); err != nil {
			return false, err
		}
		for _, value := range buf {
			if value != 0 {
				return false, nil
			}
		}
	}
	return true, nil
}

func rejectBootOrPartitionDevice(rdev uint64) error {
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
	rootDevice, err := rootMountBlockDevice("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	rootTarget, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%s", rootDevice))
	if err != nil {
		return errors.New("host root block device cannot be identified")
	}
	if _, err := os.Stat(filepath.Join(rootTarget, "partition")); err == nil {
		rootTarget = filepath.Dir(rootTarget)
	}
	if rootTarget == target {
		return errors.New("managed device is the host boot disk")
	}
	return nil
}

func rootMountBlockDevice(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) > 4 && fields[4] == "/" {
			return fields[2], nil
		}
	}
	return "", errors.New("host root mount is unavailable")
}

func formatManagedFilesystem(ctx context.Context, device *managedDevice, fsType, uuid string) error {
	tool, args, err := hostvolume.FormatCommand(fsType, uuid)
	if err != nil {
		return err
	}
	_, code, err := runPinnedBlockTool(ctx, device, tool, args...)
	if err != nil || code != 0 {
		return fmt.Errorf("managed %s formatting failed; retained volume is held", fsType)
	}
	return nil
}

// maintainManagedMount upgrades an already verified mount: it adds the
// hardened per-mount flags to a mount made by an older initializer and, when
// enabled, grows the filesystem after an OCI resize. Failures are logged, not
// returned, so a serving member keeps its verified mount.
func maintainManagedMount(ctx context.Context, cfg VolumeInitConfig, paths managedRuntimePaths, mount managedMount, device *managedDevice) {
	if err := hostvolume.RequireHardened("/proc/self/mountinfo", mount.id); err != nil {
		if err := hostvolume.HardenRemount(paths.mount); err != nil {
			slog.Warn("managed volume mount hardening failed", "mount", paths.mount, "error", err)
		}
	}
	if grown, err := hostvolume.Grow(ctx, cfg.Grow, paths.mount, device.fd, device.stat.Rdev, mount.fsType); err != nil {
		slog.Warn("managed volume online grow failed", "mount", paths.mount, "error", err)
	} else if grown {
		slog.Info("managed volume filesystem grown to its device size", "mount", paths.mount)
	}
}

func mountManagedVolume(ctx context.Context, device *managedDevice, paths managedRuntimePaths,
	pins ManagedRuntimePins, identity WorkloadIdentity, mayCompleteLayout bool,
) error {
	if err := ensureManagedMountTarget(paths.mount, identity); err != nil {
		return err
	}
	if err := verifyOpenDeviceIdentity(device.fd, device.stat); err != nil {
		return err
	}
	current, err := managedBlockDevice(pins.DevicePath)
	if err != nil {
		return err
	}
	same := sameDeviceObject(device.stat, current.stat)
	current.close()
	if !same {
		return errors.New("managed block alias changed before mount")
	}
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", device.fd), paths.mount, pins.FileSystemType,
		hostvolume.MountFlags, hostvolume.FilesystemData(pins.FileSystemType)); err != nil {
		return fmt.Errorf("mount signed managed volume: %w", err)
	}
	mountID, err := findExclusiveMount("/proc/self/mountinfo", paths.mount, device.stat.Rdev, pins.FileSystemType)
	if err != nil {
		return err
	}
	if err := hostvolume.RequireHardened("/proc/self/mountinfo", mountID); err != nil {
		return err
	}
	if err := waitManagedUUID(ctx, pins.FileSystemUUID, device.stat.Rdev); err != nil {
		return err
	}
	return completeManagedVolumeLayout(paths.mount, pins, identity, device.stat.Rdev, mayCompleteLayout)
}

func ensureManagedMountTarget(path string, identity WorkloadIdentity) error {
	if err := os.Mkdir(path, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != 0 {
		return errors.New("managed mount target is not a root-owned directory")
	}
	if err := os.Chown(path, 0, int(identity.GID)); err != nil {
		return err
	}
	return os.Chmod(path, 0750)
}

func waitManagedUUID(ctx context.Context, uuid string, rdev uint64) error {
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		info, err := os.Stat(filepath.Join("/dev/disk/by-uuid", uuid))
		if err == nil {
			device, ok := info.Sys().(*syscall.Stat_t)
			if ok && device.Rdev == rdev {
				return nil
			}
			return errors.New("signed filesystem UUID points to another block device")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("signed filesystem UUID did not appear after format or mount")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func completeManagedVolumeLayout(root string, pins ManagedRuntimePins, identity WorkloadIdentity,
	rdev uint64, mayComplete bool,
) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Dev != rdev {
		return errors.New("managed mount root is not the signed filesystem")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	hasClaim := false
	for _, entry := range entries {
		switch entry.Name() {
		case managedVolumeClaimName:
			hasClaim = true
		case "data", "replication":
		case "lost+found":
			if pins.FileSystemType != "ext4" {
				return errors.New("managed volume has unexpected lost+found")
			}
		default:
			return errors.New("managed volume has unexpected root content")
		}
	}
	if !hasClaim && !mayComplete {
		return errors.New("unclaimed retained filesystem lacks local format attempt provenance")
	}
	if hasClaim {
		return nil
	}
	if err := os.Chown(root, 0, int(identity.GID)); err != nil {
		return err
	}
	if err := os.Chmod(root, 0750); err != nil {
		return err
	}
	for _, child := range []string{"data", "replication"} {
		path := filepath.Join(root, child)
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		childInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}
		childOwner, ok := childInfo.Sys().(*syscall.Stat_t)
		if !ok || !childInfo.IsDir() || childInfo.Mode()&os.ModeSymlink != 0 || childOwner.Dev != rdev {
			return errors.New("managed volume child is unsafe")
		}
		// The initializer holds CAP_CHOWN but not CAP_FOWNER or DAC overrides:
		// it takes the child back as root to inspect it and set its mode, which
		// also resumes an interrupted layout, and hands it over last.
		if err := os.Lchown(path, 0, 0); err != nil {
			return err
		}
		children, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("inspect unclaimed managed volume child: %w", err)
		}
		if len(children) != 0 {
			return errors.New("unclaimed managed volume child contains data")
		}
		if err := os.Chmod(path, 0700); err != nil {
			return err
		}
		if err := os.Lchown(path, int(identity.UID), int(identity.GID)); err != nil {
			return err
		}
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	// One filesystem sync persists the children's modes and owners with the root.
	return unix.Syncfs(int(directory.Fd()))
}
