//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"golang.org/x/sys/unix"
)

// A C# TerraBase member on a host with host.terrabase_data_volume keeps its
// data directory on its OCI block volume, attached at oci.MemberVolumeDevice.
// The host agent cannot mount, so it asks the root volume initializer, which
// mounts the device on the data directory owned by the workload identity and
// records the mount in /etc/fstab. The agent launches the member only once it
// has verified that mount itself: a missing volume keeps the member stopped
// and never falls back to the boot disk.
//
// A blank device is formatted only with the controller's one first-format
// grant for the member's registered volume, recorded before answering. A
// lost response may be redelivered only to the original initializer attempt.
// A replacement host, or a blank device after consumption, never gets another.

// terraBaseDataRequest asks the volume initializer to establish the data
// volume mount. The device, mount target and owner come from the
// initializer's own host configuration; the request may only append, after a
// newline, the controller-signed first-format grant.
var terraBaseDataRequest = []byte("terrabase-data-volume")

// errFormatGrantNeeded is the initializer's answer for a blank device when
// the request carried no first-format grant.
var errFormatGrantNeeded = errors.New("the blank data volume needs the member's first-format grant")

// terraBaseFormatNeeded carries the initializer's durable, volume-scoped
// attempt identity. It survives agent/helper restarts, but not host replacement.
type terraBaseFormatNeeded struct {
	AttemptID string
}

func (terraBaseFormatNeeded) Error() string { return errFormatGrantNeeded.Error() }
func (terraBaseFormatNeeded) Unwrap() error { return errFormatGrantNeeded }

// volumeInitNeedsGrant is the initializer's result byte for errFormatGrantNeeded.
const volumeInitNeedsGrant = 2

// terraBaseVolumeRecheck is how long the agent trusts a verified mount before
// it asks the initializer again, which also grows the filesystem after the
// OCI volume was resized.
const terraBaseVolumeRecheck = 10 * time.Minute

// terraBaseMaintenanceTimeout bounds a maintenance request for a mounted
// volume: hardening, ownership, fstab and online growth.
var terraBaseMaintenanceTimeout = 2 * time.Minute

const fstabPath = "/etc/fstab"

// hostAgentUnit is the host agent's systemd unit; the data volume's boot
// mount is ordered before it.
const hostAgentUnit = "terrascale-orchestrator-host.service"

// Seams of the data volume checks; tests replace them to run the agent's
// decisions without a block device or a controller.
var (
	verifyDataMount       = verifyTerraBaseDataMount
	dataFilesystemUUID    = func() (string, error) { return mountedFilesystemUUID(oci.MemberVolumeDevice) }
	confirmDataFilesystem = func(ctx context.Context, a *Agent, uuid string) (string, error) {
		var reply terraBaseFormatReply
		if _, err := a.sendToLeader(ctx, "terrabase-format", terraBaseFormatQuery{Mounted: uuid, VolumeID: a.cfg.TerraBaseDataVolumeID}, &reply, nil, nil); err != nil {
			return "", fmt.Errorf("record terrabase data volume filesystem: %w", err)
		}
		if reply.VolumeID != a.cfg.TerraBaseDataVolumeID {
			return "", errors.New("recorded filesystem belongs to another volume")
		}
		return reply.UUID, nil
	}
)

// ensureTerraBaseDataVolume returns nil only while the member data directory
// is the hardened, workload-owned mount of the data volume holding the
// filesystem the controller recorded for the member.
func (a *Agent) ensureTerraBaseDataVolume(ctx context.Context) error {
	if err := a.establishTerraBaseDataVolume(ctx); err != nil {
		a.terraBaseVolumeConfirmed = ""
		return err
	}
	uuid, err := dataFilesystemUUID()
	if err != nil || uuid == a.terraBaseVolumeConfirmed {
		return err
	}
	// A filesystem not yet confirmed is recorded, or checked against the
	// record: an adopted volume spends the member's first format too, and
	// another filesystem on the device is refused.
	a.terraBaseVolumeConfirmed = ""
	recorded, err := confirmDataFilesystem(ctx, a, uuid)
	if err != nil {
		return err
	}
	if recorded != uuid {
		return fmt.Errorf("data volume holds ext4 %s, but member %s was initialized with %s; attach the member's own volume or restore it",
			uuid, a.cfg.Node, recorded)
	}
	a.terraBaseVolumeConfirmed = uuid
	return nil
}

// terraBaseDataVolumeIntact checks locally, without repairing anything, that
// the member data directory is the verified mount of the filesystem the
// controller confirmed.
func (a *Agent) terraBaseDataVolumeIntact() error {
	if err := verifyDataMount(terrabase.Layout(a.cfg.TerraBaseRoot).Data(), a.cfg.WorkloadIdentity); err != nil {
		return err
	}
	uuid, err := dataFilesystemUUID()
	if err != nil {
		return err
	}
	if a.terraBaseVolumeConfirmed == "" || uuid != a.terraBaseVolumeConfirmed {
		return fmt.Errorf("data volume holds ext4 %s, not the confirmed %q", uuid, a.terraBaseVolumeConfirmed)
	}
	return nil
}

// fenceTerraBaseMember stops the member when its data volume is not intact,
// before anything tries to repair the mount. It checks the volume first and
// stops whenever the runner cannot show that the member is stopped. stopped
// reports a member it stopped; an error means a writer may still run, and
// the caller must not go on to repair the mount.
func (a *Agent) fenceTerraBaseMember(ctx context.Context, role string) (stopped bool, err error) {
	if !a.cfg.TerraBaseDataVolume || role != terrabase.Role {
		return false, nil
	}
	lost := a.terraBaseDataVolumeIntact()
	if lost == nil {
		return false, nil
	}
	a.terraBaseVolumeConfirmed = ""
	current, observeErr := a.runner.Observe(ctx, role)
	if observeErr == nil && !current.Running {
		return false, nil
	}
	if err := a.runner.Stop(ctx, role); err != nil {
		return false, errors.Join(fmt.Errorf("stop the terrabase member: data volume: %w", lost), observeErr, err)
	}
	delete(a.terraBase, role)
	slog.WarnContext(ctx, "terrabase member stopped: its data volume is not intact", "error", lost)
	return true, nil
}

// establishTerraBaseDataVolume returns nil once the member data directory is
// the hardened, workload-owned mount of the data volume.
func (a *Agent) establishTerraBaseDataVolume(ctx context.Context) error {
	data := terrabase.Layout(a.cfg.TerraBaseRoot).Data()
	if verifyDataMount(data, a.cfg.WorkloadIdentity) == nil {
		if time.Since(a.terraBaseVolumeChecked) < terraBaseVolumeRecheck {
			return nil
		}
		// The mount is in place, so maintenance is best effort, and bounded:
		// the member is fenced again only after it returns.
		a.terraBaseVolumeChecked = time.Now()
		maintenance, cancel := context.WithTimeout(ctx, terraBaseMaintenanceTimeout)
		defer cancel()
		if err := requestTerraBaseDataVolume(maintenance, a.cfg.VolumeInitSocket, nil); err != nil {
			slog.WarnContext(maintenance, "terrabase data volume maintenance failed", "error", err)
		}
		return verifyDataMount(data, a.cfg.WorkloadIdentity)
	}
	err := requestTerraBaseDataVolume(ctx, a.cfg.VolumeInitSocket, nil)
	if needed, ok := errors.AsType[terraBaseFormatNeeded](err); ok {
		// Retry the same durable initializer attempt; issuing a response does
		// not consume it. The helper consumes it durably immediately before mkfs.
		var reply terraBaseFormatReply
		var grant protocol.Envelope
		if _, err = a.sendToLeader(ctx, "terrabase-format", terraBaseFormatQuery{VolumeID: a.cfg.TerraBaseDataVolumeID, AttemptID: needed.AttemptID}, &reply, &grant, nil); err == nil {
			err = requestTerraBaseDataVolume(ctx, a.cfg.VolumeInitSocket, &grant)
		}
	}
	if err != nil {
		return fmt.Errorf("terrabase data volume is not mounted: %w", err)
	}
	if err := verifyDataMount(data, a.cfg.WorkloadIdentity); err != nil {
		return fmt.Errorf("terrabase data volume mount readback: %w", err)
	}
	a.terraBaseVolumeChecked = time.Now()
	return nil
}

func requestTerraBaseDataVolume(ctx context.Context, socket string, grant *protocol.Envelope) error {
	wire := terraBaseDataRequest
	if grant != nil {
		encoded, err := protocol.EncodeJSON(*grant)
		if err != nil {
			return err
		}
		wire = slices.Concat(terraBaseDataRequest, []byte("\n"), encoded)
	}
	if socket == "" {
		socket = volumeInitSocketPath
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("connect fixed volume initializer: %w", err)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	// The first mount may format the whole volume.
	if err := connection.SetDeadline(time.Now().Add(20 * time.Minute)); err != nil {
		return err
	}
	if err := exchangeVolumeInit(connection, wire); err != nil {
		if errors.Is(err, errFormatGrantNeeded) {
			return err
		}
		return fmt.Errorf("volume initializer did not mount %s; its journal has the cause: %w", oci.MemberVolumeDevice, err)
	}
	return nil
}

// verifyTerraBaseDataMount checks that data is the only mount of the data
// volume, hardened, and owned by the workload identity with mode 0700.
func verifyTerraBaseDataMount(data string, identity WorkloadIdentity) error {
	device, err := managedBlockDevice(oci.MemberVolumeDevice)
	if err != nil {
		return fmt.Errorf("data volume %s is not attached: %w", oci.MemberVolumeDevice, err)
	}
	defer device.close()
	info, err := os.Lstat(data)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || owner.Dev != device.stat.Rdev || owner.Uid != identity.UID ||
		owner.Gid != identity.GID || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s is not the workload-owned data volume", data)
	}
	mountID, err := findExclusiveMount("/proc/self/mountinfo", data, device.stat.Rdev, storage.FileSystemExt4)
	if err != nil {
		return err
	}
	return hostvolume.RequireHardened("/proc/self/mountinfo", mountID)
}

// prepareTerraBaseDataVolume runs in the root volume initializer. It mounts
// the data volume on cfg.TerraBaseDataDir, formatting a blank device first
// only with a verified first-format grant, then hardens, owns, records and
// grows the mount.
func prepareTerraBaseDataVolume(ctx context.Context, cfg VolumeInitConfig, grant *protocol.Envelope) error {
	if !strings.HasPrefix(cfg.TerraBaseDataVolumeID, "ocid1.volume.") {
		return errors.New("terrabase data volume initializer needs its recorded volume OCID")
	}
	target := cfg.TerraBaseDataDir
	device, err := managedBlockDevice(oci.MemberVolumeDevice)
	if err != nil {
		return fmt.Errorf("data volume %s is not attached: %w", oci.MemberVolumeDevice, err)
	}
	defer device.close()
	if err := hostvolume.RejectBootOrPartitionDevice(device.stat.Rdev); err != nil {
		return err
	}
	mounted, err := hostvolume.BlockDeviceMounted("/proc/self/mountinfo", device.stat.Rdev)
	if err != nil {
		return err
	}
	if !mounted {
		if err := mountTerraBaseDataVolume(ctx, cfg, device, target, grant); err != nil {
			return err
		}
	}
	mountID, err := findExclusiveMount("/proc/self/mountinfo", target, device.stat.Rdev, storage.FileSystemExt4)
	if err != nil {
		return err
	}
	if hostvolume.RequireHardened("/proc/self/mountinfo", mountID) != nil {
		if err := hostvolume.HardenRemount(target); err != nil {
			return err
		}
	}
	if err := ownTerraBaseDataRoot(target, device.stat.Rdev, cfg.WorkloadIdentity); err != nil {
		return err
	}
	uuid, fsType, err := blockFilesystemIdentity(ctx, device)
	if err != nil || fsType != storage.FileSystemExt4 {
		return errors.Join(errors.New("mounted data volume has no ext4 identity"), err)
	}
	if err := writeTerraBaseFstab(fstabPath, uuid, target); err != nil {
		return fmt.Errorf("record data volume mount: %w", err)
	}
	// ponytail: growth runs only when the agent asks, at most every
	// terraBaseVolumeRecheck; a udev or resize event trigger can replace that.
	if grown, err := hostvolume.Grow(ctx, target, device.stat.Rdev, storage.FileSystemExt4); err != nil {
		slog.WarnContext(ctx, "terrabase data volume online grow failed", "mount", target, "error", err)
	} else if grown {
		slog.InfoContext(ctx, "terrabase data volume filesystem grown to its device size", "mount", target)
	}
	return nil
}

func mountTerraBaseDataVolume(ctx context.Context, cfg VolumeInitConfig, device *managedDevice, target string, grant *protocol.Envelope) error {
	if occupied, err := mountTargetOccupied("/proc/self/mountinfo", target); err != nil {
		return err
	} else if occupied {
		return errors.New("terrabase data directory is occupied by another filesystem")
	}
	probe, err := probeManagedVolume(ctx, device)
	if err != nil {
		return err
	}
	var uuid string
	var expires time.Time
	if grant != nil {
		if uuid, err = verifyTerraBaseFormatGrant(cfg, *grant); err != nil {
			return err
		}
		expires = grant.ExpiresAt
	}
	marker := terraBaseFormatMarkerPath(cfg)
	_, err = os.Lstat(marker)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err = executeTerraBaseVolume(ctx, probe, uuid, expires, err == nil, volumeInitEffects{
		Consume: func() error {
			if err := os.MkdirAll(cfg.StateRoot, 0o700); err != nil {
				return err
			}
			return createDurableMarker(marker, []byte(uuid+"\n"))
		},
		Format: func(ctx context.Context) error {
			if err := requireSameDataDevice(device); err != nil {
				return err
			}
			return formatManagedFilesystem(ctx, device, storage.FileSystemExt4, uuid)
		},
		Probe: func(ctx context.Context) (volumeFilesystemProbe, error) { return probeManagedVolume(ctx, device) },
		Mount: func(context.Context, bool) error {
			if err := emptyMountTarget(target); err != nil {
				return err
			}
			if err := requireSameDataDevice(device); err != nil {
				return err
			}
			if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", device.fd), target, storage.FileSystemExt4,
				hostvolume.MountFlags, hostvolume.FilesystemData(storage.FileSystemExt4)); err != nil {
				return fmt.Errorf("mount data volume: %w", err)
			}
			return nil
		},
	})
	if errors.Is(err, errFormatGrantNeeded) {
		attempt, err := pendingTerraBaseFormatAttempt(cfg)
		if err != nil {
			return err
		}
		return terraBaseFormatNeeded{AttemptID: attempt}
	}
	return err
}

// terraBaseFormatMarker, in the initializer's state root, records that this
// host formatted its data volume. It is written durably before mkfs, so a
// replayed grant, or a blank device after the first format, holds instead.
const terraBaseFormatMarker = "terrabase-data-format"

func terraBaseFormatMarkerPath(cfg VolumeInitConfig) string {
	return filepath.Join(cfg.StateRoot, fmt.Sprintf("%s-%x", terraBaseFormatMarker, sha256.Sum256([]byte(cfg.TerraBaseDataVolumeID))))
}

// pendingTerraBaseFormatAttempt records an attempt before any controller RPC.
// Neither retry nor lost response creates a second attempt for this volume.
func pendingTerraBaseFormatAttempt(cfg VolumeInitConfig) (string, error) {
	if attempt, err := readTerraBaseFormatAttempt(cfg); !errors.Is(err, os.ErrNotExist) {
		return attempt, err
	}
	if err := os.MkdirAll(cfg.StateRoot, 0o700); err != nil {
		return "", err
	}
	attempt, err := randomID()
	if err != nil {
		return "", err
	}
	if err := createDurableMarker(terraBaseFormatMarkerPath(cfg)+"-attempt", []byte(attempt+"\n")); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return readTerraBaseFormatAttempt(cfg)
}

func readTerraBaseFormatAttempt(cfg VolumeInitConfig) (string, error) {
	if cfg.StateRoot == "" || !strings.HasPrefix(cfg.TerraBaseDataVolumeID, "ocid1.volume.") {
		return "", errors.New("first-format attempt needs its fixed state root and volume OCID")
	}
	path := terraBaseFormatMarkerPath(cfg) + "-attempt"
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 27 {
		return "", errors.Join(errors.New("invalid durable first-format attempt"), err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return "", errors.New("first-format attempt is not owned by the initializer")
	}
	var wire [27]byte
	if _, err := io.ReadFull(file, wire[:]); err != nil {
		return "", err
	}
	attempt := string(wire[:26])
	if !entityid.Valid(attempt) || wire[26] != '\n' {
		return "", errors.New("invalid durable first-format attempt")
	}
	// A prior create may have failed during fsync. Re-establish durability
	// before returning even an existing attempt to the agent.
	if err := file.Sync(); err != nil {
		return "", err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer directory.Close()
	return attempt, directory.Sync()
}

// executeTerraBaseVolume decides on the probed data device and runs the
// managed initializer's ordered effects: it mounts one existing ext4
// filesystem, and formats a blank device only with a verified grant's UUID
// (grantUUID, valid until grantExpires) on a host that has not formatted
// before, consuming that durably first and mounting only a filesystem that
// reads back the granted UUID.
func executeTerraBaseVolume(ctx context.Context, probe volumeFilesystemProbe, grantUUID string, grantExpires time.Time,
	consumed bool, effects volumeInitEffects,
) error {
	action, err := terraBaseVolumeAction(probe)
	if err != nil {
		return err
	}
	pins := ManagedRuntimePins{FileSystemType: storage.FileSystemExt4, FileSystemUUID: probe.FSUUID}
	if action == volumeInitFormat {
		if consumed {
			return errors.New("blank terrabase volume has a consumed first-format grant; operator recovery is required")
		}
		if grantUUID == "" {
			return errFormatGrantNeeded
		}
		pins.FileSystemUUID = grantUUID
	}
	return executeVolumeInitAction(ctx, pins, probe, action == volumeInitFormat, consumed, grantExpires, effects)
}

// terraBaseFormatGrant pins one UUID and the original initializer/registration.
// Mounted confirmation clears AttemptID and closes the grant.
type terraBaseFormatGrant struct {
	UUID       string `json:"uuid"`
	AttemptID  string `json:"attempt_id,omitempty"`
	HostKey    string `json:"host_key,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}

// terraBaseFormatQuery asks for the member's first-format grant, or, with
// Mounted, records the filesystem the host mounted when none is recorded.
type terraBaseFormatQuery struct {
	Mounted   string `json:"mounted,omitempty"`
	VolumeID  string `json:"volume_id"`
	AttemptID string `json:"attempt_id,omitempty"`
}

// terraBaseFormatReply answers a host's first-format request. Granted is
// true only for the original, still-pending initializer and registration;
// redelivery preserves UUID and AttemptID.
type terraBaseFormatReply struct {
	Granted   bool   `json:"granted"`
	UUID      string `json:"uuid"`
	VolumeID  string `json:"volume_id"`
	AttemptID string `json:"attempt_id,omitempty"`
}

func terraBaseFormatKey(cell, node, volumeID string) string {
	return entityid.Derive("terrabase-format", cell, node, volumeID)
}

// serveTerraBaseFormat records a C# member's data volume filesystem, keyed by
// the member's registered volume OCID, before answering: a first format, or the
// filesystem a host mounted. Only the original pending initializer can obtain
// redelivery. Its durable consumption marker still forbids another mkfs.
func (c *Controller) serveTerraBaseFormat(ctx context.Context, req request, r Registration) (any, error) {
	if !slices.Contains(r.Roles, terrabase.Role) || r.ManagedOCI != nil {
		return nil, errors.New("host does not run C# TerraBase members")
	}
	var query terraBaseFormatQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(r.TerraBaseDataVolumeID, "ocid1.volume.") || query.VolumeID != r.TerraBaseDataVolumeID {
		return nil, errors.New("first-format request does not match the registered terrabase volume OCID")
	}
	if query.Mounted != "" && !hostvolume.ValidUUID(query.Mounted) {
		return nil, errors.New("mounted filesystem UUID is invalid")
	}
	if query.Mounted == "" && !entityid.Valid(query.AttemptID) || query.Mounted != "" && query.AttemptID != "" {
		return nil, errors.New("first-format request has no valid initializer attempt")
	}
	key := terraBaseFormatKey(c.cell, req.Node, r.TerraBaseDataVolumeID)
	for range 8 {
		var grant terraBaseFormatGrant
		revision, found, err := c.get(ctx, key, &grant)
		if err != nil {
			return nil, err
		}
		if found {
			if query.Mounted == grant.UUID && grant.AttemptID != "" {
				grant.AttemptID, grant.HostKey, grant.Generation = "", "", 0
				if _, err := c.cas(ctx, key, grant, revision); err != nil {
					if casConflict(err) {
						continue
					}
					return nil, err
				}
			}
			granted := query.Mounted == "" && grant.AttemptID != "" && grant.AttemptID == query.AttemptID &&
				grant.HostKey == r.PublicKey && grant.Generation == r.Generation
			reply := terraBaseFormatReply{Granted: granted, UUID: grant.UUID, VolumeID: r.TerraBaseDataVolumeID}
			if granted {
				reply.AttemptID = grant.AttemptID
			}
			return reply, nil
		}
		grant.UUID = query.Mounted
		if grant.UUID == "" {
			grant.AttemptID, grant.HostKey, grant.Generation = query.AttemptID, r.PublicKey, r.Generation
			if grant.UUID, err = newFilesystemUUID(); err != nil {
				return nil, err
			}
		}
		if _, err := c.cas(ctx, key, grant, revision); err == nil {
			return terraBaseFormatReply{Granted: query.Mounted == "", UUID: grant.UUID, VolumeID: r.TerraBaseDataVolumeID, AttemptID: grant.AttemptID}, nil
		} else if !casConflict(err) {
			return nil, err
		}
	}
	return nil, errors.New("terrabase format grant contention")
}

// verifyTerraBaseFormatGrant returns the filesystem UUID of a current,
// controller-signed first-format grant for this host's node.
func verifyTerraBaseFormatGrant(cfg VolumeInitConfig, signed protocol.Envelope) (string, error) {
	if err := protocol.VerifyEnvelope(signed, protocol.EnvelopeScope{
		Region: cfg.Cell, Kind: "host.response.terrabase-format", Actor: "controller",
		OperationID: signed.OperationID, Epoch: signed.Epoch,
	}, cfg.ControllerPublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: requestTTL, ClockSkew: maxClockSkew}); err != nil {
		return "", err
	}
	var reply response
	if err := decodeStrict([]byte(signed.Payload), &reply); err != nil {
		return "", err
	}
	if reply.Error != "" || !lowerHex(reply.Nonce, 32) || entityid.Derive("host-request", reply.Nonce) != signed.OperationID || reply.Epoch != signed.Epoch ||
		reply.Operation != "terrabase-format" || reply.Node != cfg.Node {
		return "", errors.New("first-format grant binding is invalid")
	}
	var grant terraBaseFormatReply
	if err := decodeStrict(reply.Payload, &grant); err != nil {
		return "", err
	}
	if !strings.HasPrefix(cfg.TerraBaseDataVolumeID, "ocid1.volume.") || grant.VolumeID != cfg.TerraBaseDataVolumeID {
		return "", errors.New("first-format grant belongs to another volume")
	}
	if !grant.Granted {
		return "", fmt.Errorf("member %s has no unused first-format authority for this initializer (ext4 %s); recover its original initializer state or restore the volume from a backup", cfg.Node, grant.UUID)
	}
	if !hostvolume.ValidUUID(grant.UUID) {
		return "", errors.New("first-format grant has no valid filesystem UUID")
	}
	attempt, err := readTerraBaseFormatAttempt(cfg)
	if err != nil {
		return "", fmt.Errorf("read the original initializer attempt: %w", err)
	}
	if grant.AttemptID != attempt {
		return "", errors.New("first-format grant belongs to another initializer attempt")
	}
	return grant.UUID, nil
}

// terraBaseVolumeAction mounts one existing ext4 filesystem and formats only
// a device without any signature whose sampled blocks are all zero. Anything
// else holds: an existing filesystem is never formatted.
func terraBaseVolumeAction(probe volumeFilesystemProbe) (volumeInitAction, error) {
	switch {
	case probe.Mounted:
		return volumeInitHold, errors.New("data volume is already mounted elsewhere")
	case probe.FSType == storage.FileSystemExt4 && probe.FSUUID != "" && probe.Signatures && !probe.ForeignSignatures:
		return volumeInitMount, nil
	case probe.FSUUID != "" || probe.FSType != "" || probe.Signatures || probe.ForeignSignatures || !probe.BlankSample:
		return volumeInitHold, errors.New("data volume holds data that is not one ext4 filesystem; it is never formatted")
	}
	return volumeInitFormat, nil
}

// requireSameDataDevice rechecks, right before a disk effect, that the open
// device is still the one the data volume path names.
func requireSameDataDevice(device *managedDevice) error {
	if err := verifyOpenDeviceIdentity(device.fd, device.stat); err != nil {
		return err
	}
	current, err := managedBlockDevice(oci.MemberVolumeDevice)
	if err != nil {
		return err
	}
	defer current.close()
	if !sameDeviceObject(device.stat, current.stat) {
		return errors.New("data volume device path changed")
	}
	return nil
}

// emptyMountTarget creates the mount point, or accepts an existing empty
// directory, and leaves it root-owned with mode 0700: mounting over boot disk
// files would hide them, and should the volume ever be unmounted under a
// running member, the workload cannot create a file on the boot disk there.
func emptyMountTarget(target string) error {
	if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s must be a directory, not a symlink: %w", target, err)
	}
	defer unix.Close(fd)
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s holds boot disk files; move them before the data volume is mounted there", target)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid == 0 && stat.Gid == 0 && stat.Mode&0o7777 == 0o700 {
		return nil
	}
	// Without CAP_FOWNER the initializer takes the directory first.
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0o700)
}

// ownTerraBaseDataRoot gives the mounted filesystem root to the workload
// identity with mode 0700. The initializer opens the workload-owned root with
// CAP_DAC_READ_SEARCH; it holds CAP_CHOWN but not CAP_FOWNER, so it takes the
// root back to set the mode and hands it over last.
func ownTerraBaseDataRoot(target string, rdev uint64, identity WorkloadIdentity) error {
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Dev != rdev {
		return errors.New("data directory is not the data volume root")
	}
	if stat.Uid == identity.UID && stat.Gid == identity.GID && stat.Mode&0o7777 == 0o700 {
		return nil
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	if err := unix.Fchown(fd, int(identity.UID), int(identity.GID)); err != nil {
		return err
	}
	return unix.Syncfs(fd)
}

// terraBaseFstab returns fstab with exactly one entry for target, mounting
// the ext4 filesystem uuid with the hardened options. systemd mounts it at
// boot before the host agent starts; nofail keeps a boot without the volume
// going, and the agent then keeps the member stopped. Every other line is
// kept as it is.
func terraBaseFstab(fstab []byte, uuid, target string) ([]byte, error) {
	if !hostvolume.ValidUUID(uuid) || !filepath.IsAbs(target) || filepath.Clean(target) != target || target == "/" ||
		strings.ContainsAny(target, " \t\r\n\\#") {
		return nil, errors.New("data volume fstab entry needs a filesystem UUID and a plain absolute mount path")
	}
	var out bytes.Buffer
	for line := range strings.Lines(string(fstab)) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "#") && filepath.Clean(fields[1]) == target {
			continue
		}
		out.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			out.WriteByte('\n')
		}
	}
	fmt.Fprintf(&out, "UUID=%s %s %s %s,%s,nofail,x-systemd.device-timeout=30s,x-systemd.before=%s 0 2\n",
		uuid, target, storage.FileSystemExt4, strings.Join(hostvolume.HardenedOptions, ","),
		hostvolume.FilesystemData(storage.FileSystemExt4), hostAgentUnit)
	return out.Bytes(), nil
}

func writeTerraBaseFstab(path, uuid, target string) error {
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, err := terraBaseFstab(current, uuid, target)
	if err != nil || bytes.Equal(updated, current) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	_, err = temporary.Write(updated)
	if err == nil {
		err = temporary.Chmod(0o644)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// newFilesystemUUID returns a random version 4 UUID in the canonical
// lowercase form hostvolume.FormatCommand requires.
func newFilesystemUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// mountedFilesystemUUID reads the UUID of the ext4 filesystem on device from
// its superblock, without depending on udev's /dev/disk/by-uuid links.
func mountedFilesystemUUID(device string) (string, error) {
	file, err := os.Open(device)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return ext4SuperblockUUID(file)
}

// ext4SuperblockUUID returns s_uuid of the ext4 superblock at byte 1024,
// in the canonical lowercase form.
func ext4SuperblockUUID(device io.ReaderAt) (string, error) {
	var superblock [0x78]byte
	if _, err := device.ReadAt(superblock[:], 1024); err != nil {
		return "", fmt.Errorf("read ext4 superblock: %w", err)
	}
	if superblock[0x38] != 0x53 || superblock[0x39] != 0xef {
		return "", errors.New("device has no ext4 superblock")
	}
	id := superblock[0x68:0x78]
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), nil
}
