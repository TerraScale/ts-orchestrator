//go:build linux

package host

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
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
