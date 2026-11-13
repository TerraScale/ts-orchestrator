package regionhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const dataDevice = "/dev/oracleoci/oraclevdb"
const dataPolicy = "ts-host-data-daily-7d"
const dataFormattedTag = "terrascale-data-formatted"
const dataSerialTag = "terrascale-data-serial"
const dataUUIDTag = "terrascale-data-uuid"
const dataVolumeTag = "terrascale-data-volume"
const dataFormatTag = "terrascale-data-may-format"
const dataInstanceTag = "terrascale-data-instance"

func volumeTags(host string) map[string]string {
	return map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-resource": "data-volume", "terrascale-host": host}
}

func (r *run) dataVolume(host string) (*core.Volume, error) {
	var found *core.Volume
	req := core.ListVolumesRequest{CompartmentId: &r.compartment}
	for {
		page, err := r.storage.ListVolumes(r.ctx, req)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Items {
			if v.LifecycleState == core.VolumeLifecycleStateTerminated || v.LifecycleState == core.VolumeLifecycleStateTerminating {
				continue
			}
			if !sameTags(v.FreeformTags, volumeTags(host)) {
				continue
			}
			if found != nil {
				return nil, fmt.Errorf("multiple data volumes for %s; refusing to choose", host)
			}
			found = &v
		}
		if page.OpcNextPage == nil {
			return found, nil
		}
		req.Page = page.OpcNextPage
	}
}

func sameTags(actual, want map[string]string) bool {
	for k, v := range want {
		if actual[k] != v {
			return false
		}
	}
	return true
}

func (r *run) ensureDataVolume(host, ad string, volume *core.Volume) (*core.Volume, error) {
	policy, err := r.ensureDataPolicy()
	if err != nil {
		return nil, err
	}
	verb := "unchanged"
	if volume == nil {
		verb = "created"
		volume = &core.Volume{Id: new("-"), DisplayName: new(host + "-data"), AvailabilityDomain: &ad}
		if !r.dry {
			created, err := r.storage.CreateVolume(r.ctx, core.CreateVolumeRequest{CreateVolumeDetails: core.CreateVolumeDetails{
				CompartmentId: &r.compartment, AvailabilityDomain: &ad, DisplayName: volume.DisplayName,
				SizeInGBs: new(int64(100)), VpusPerGB: new(int64(10)), FreeformTags: volumeTags(host),
			}})
			if err != nil {
				return nil, err
			}
			volume = &created.Volume
			if r.createdVolumes == nil {
				r.createdVolumes = make(map[string]bool)
			}
			r.createdVolumes[deref(volume.Id)] = true
		}
	}
	if !r.dry {
		if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
			g, err := r.storage.GetVolume(r.ctx, core.GetVolumeRequest{VolumeId: volume.Id})
			if err == nil {
				volume = &g.Volume
			}
			return g.LifecycleState == core.VolumeLifecycleStateAvailable, err
		}); err != nil {
			return nil, err
		}
	}
	if err := r.report(verb, "data-volume", host+"-data", deref(volume.Id)); err != nil {
		return nil, err
	}
	assigned := ""
	if deref(volume.Id) != "-" {
		assigned, err = r.bootBackupAssignment(deref(volume.Id))
		if err != nil {
			return nil, err
		}
	}
	if assigned != "" && assigned != policy {
		return nil, errors.New("data volume already has a different backup policy; refusing to replace it")
	}
	verb = "unchanged"
	if assigned == "" {
		verb = "created"
		if !r.dry {
			_, err := r.storage.CreateVolumeBackupPolicyAssignment(r.ctx, core.CreateVolumeBackupPolicyAssignmentRequest{
				CreateVolumeBackupPolicyAssignmentDetails: core.CreateVolumeBackupPolicyAssignmentDetails{AssetId: volume.Id, PolicyId: &policy}})
			if err != nil {
				return nil, err
			}
			assigned, err = r.bootBackupAssignment(deref(volume.Id))
			if err != nil {
				return nil, err
			}
			if assigned != policy {
				return nil, errors.New("data volume backup policy did not match after assignment")
			}
		}
	}
	return volume, r.report(verb, "backup-assignment", host+"-data", policy)
}

func (r *run) ensureDataPolicy() (string, error) {
	want := []core.VolumeBackupSchedule{{Period: core.VolumeBackupSchedulePeriodDay, BackupType: core.VolumeBackupScheduleBackupTypeIncremental,
		RetentionSeconds: new(7 * 24 * 60 * 60), OffsetType: core.VolumeBackupScheduleOffsetTypeStructured,
		HourOfDay: new(2), TimeZone: core.VolumeBackupScheduleTimeZoneUtc}}
	var found *core.VolumeBackupPolicy
	req := core.ListVolumeBackupPoliciesRequest{CompartmentId: &r.compartment}
	for {
		page, err := r.storage.ListVolumeBackupPolicies(r.ctx, req)
		if err != nil {
			return "", err
		}
		for _, p := range page.Items {
			if deref(p.DisplayName) == dataPolicy && p.FreeformTags["terrascale-managed-by"] == "ts-orchestrator" {
				if found != nil {
					return "", errors.New("multiple managed data backup policies")
				}
				found = &p
			}
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	verb, id := "created", "-"
	if found == nil {
		if !r.dry {
			p, err := r.storage.CreateVolumeBackupPolicy(r.ctx, core.CreateVolumeBackupPolicyRequest{CreateVolumeBackupPolicyDetails: core.CreateVolumeBackupPolicyDetails{
				CompartmentId: &r.compartment, DisplayName: new(dataPolicy), Schedules: want,
				FreeformTags: map[string]string{"terrascale-managed-by": "ts-orchestrator"},
			}})
			if err != nil {
				return "", err
			}
			id = deref(p.Id)
		}
	} else {
		verb, id = "unchanged", deref(found.Id)
		if !dataScheduleMatches(found.Schedules) {
			verb = "updated"
			if !r.dry {
				_, err := r.storage.UpdateVolumeBackupPolicy(r.ctx, core.UpdateVolumeBackupPolicyRequest{PolicyId: found.Id,
					UpdateVolumeBackupPolicyDetails: core.UpdateVolumeBackupPolicyDetails{Schedules: want}})
				if err != nil {
					return "", err
				}
			}
		}
	}
	if !r.dry {
		read, err := r.storage.GetVolumeBackupPolicy(r.ctx, core.GetVolumeBackupPolicyRequest{PolicyId: &id})
		if err != nil {
			return "", err
		}
		policy := read.VolumeBackupPolicy
		if deref(policy.Id) != id || deref(policy.CompartmentId) != r.compartment || deref(policy.DisplayName) != dataPolicy ||
			deref(policy.DestinationRegion) != "" || !dataScheduleMatches(policy.Schedules) {
			return "", errors.New("data backup policy readback does not match its full daily schedule")
		}
	}
	return id, r.report(verb, "backup-policy", dataPolicy, id)
}

func (r *run) attachDataVolume(host string, instance *core.Instance, volume *core.Volume) error {
	if r.dry && deref(volume.Id) == "-" {
		return r.report("created", "data-attachment", host, dataDevice)
	}
	if !r.dry {
		current, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
		if err != nil {
			return err
		}
		read, err := r.storage.GetVolume(r.ctx, core.GetVolumeRequest{VolumeId: volume.Id})
		if err != nil {
			return err
		}
		instance, volume = &current.Instance, &read.Volume
		if instance.Metadata[dataVolumeTag] != deref(volume.Id) || volume.FreeformTags[dataInstanceTag] != deref(instance.Id) {
			return fmt.Errorf("refusing attachment: instance %s launched for volume %s; requested volume %s bound to instance %s", deref(instance.Id), instance.Metadata[dataVolumeTag], deref(volume.Id), volume.FreeformTags[dataInstanceTag])
		}
		if instance.LifecycleState != core.InstanceLifecycleStateRunning {
			return fmt.Errorf("instance %s is %s; finish or abandon the removal before add", deref(instance.Id), instance.LifecycleState)
		}
	}
	attachment, err := r.dataAttachment(instance, volume)
	if err != nil {
		return err
	}
	verb := "unchanged"
	if attachment == nil {
		verb = "created"
		if !r.dry {
			a, err := r.compute.AttachVolume(r.ctx, core.AttachVolumeRequest{AttachVolumeDetails: core.AttachParavirtualizedVolumeDetails{
				InstanceId: instance.Id, VolumeId: volume.Id, Device: new(dataDevice), IsReadOnly: new(false), IsShareable: new(false),
			}})
			if err != nil {
				return err
			}
			attachment = a.VolumeAttachment
		}
	}
	if !r.dry {
		if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
			g, err := r.compute.GetVolumeAttachment(r.ctx, core.GetVolumeAttachmentRequest{VolumeAttachmentId: attachment.GetId()})
			return g.VolumeAttachment.GetLifecycleState() == core.VolumeAttachmentLifecycleStateAttached, err
		}); err != nil {
			return err
		}
	}
	return r.report(verb, "data-attachment", host, dataDevice)
}

func (r *run) dataAttachment(instance *core.Instance, volume *core.Volume) (core.VolumeAttachment, error) {
	req := core.ListVolumeAttachmentsRequest{CompartmentId: &r.compartment, VolumeId: volume.Id}
	var attachment core.VolumeAttachment
	for {
		page, err := r.compute.ListVolumeAttachments(r.ctx, req)
		if err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			if a.GetLifecycleState() == core.VolumeAttachmentLifecycleStateDetached {
				continue
			}
			_, pv := a.(core.ParavirtualizedVolumeAttachment)
			if instance == nil || deref(a.GetInstanceId()) != deref(instance.Id) || !pv || deref(a.GetDevice()) != dataDevice || deref(a.GetIsReadOnly()) || deref(a.GetIsShareable()) {
				return nil, fmt.Errorf("data volume %s has a conflicting attachment", deref(volume.DisplayName))
			}
			if attachment != nil {
				return nil, errors.New("multiple live data volume attachments")
			}
			attachment = a
		}
		if page.OpcNextPage == nil {
			break
		}
		req.Page = page.OpcNextPage
	}
	return attachment, nil
}

func dataScheduleMatches(schedules []core.VolumeBackupSchedule) bool {
	if len(schedules) != 1 {
		return false
	}
	s := schedules[0]
	return s.Period == core.VolumeBackupSchedulePeriodDay && s.BackupType == core.VolumeBackupScheduleBackupTypeIncremental &&
		deref(s.RetentionSeconds) == 7*24*60*60 && s.OffsetType == core.VolumeBackupScheduleOffsetTypeStructured &&
		deref(s.HourOfDay) == 2 && s.TimeZone == core.VolumeBackupScheduleTimeZoneUtc && s.DayOfWeek == "" &&
		deref(s.DayOfMonth) == 0 && s.Month == "" && s.RetentionPeriod == nil &&
		!deref(s.IsPreventDeletionEnabled) && !deref(s.IsRetentionLockEnabled)
}

func (r *run) confirmDataMounted(host string, instance *core.Instance, volume *core.Volume) error {
	if r.dry {
		return nil
	}
	ip, err := r.publicIP(instance)
	if err != nil {
		return err
	}
	pin, err := livePin(r.ctx, ip)
	if err != nil {
		return fmt.Errorf("host %s mount report unavailable: %w", host, err)
	}
	token, err := releasepush.MintToken(r.ctx)
	if err != nil {
		return fmt.Errorf("authenticate host %s mount report: %w", host, err)
	}
	conn, err := releasepush.Dial(releasepush.Region{Region: r.code, NATS: "tls://" + ip + ":4222", SPKISHA256: pin}, token, nats.NoReconnect())
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(r.ctx, 8*time.Second)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, releasepush.SubjectHealth, nil)
	if err != nil {
		return fmt.Errorf("host %s mount report: %w", host, err)
	}
	var reply releasepush.Reply
	if err := json.Unmarshal(message.Data, &reply); err != nil {
		return err
	}
	mount := reply.DataMount
	if mount == nil {
		return fmt.Errorf("host %s has no data mount report: %s", host, reply.DataMountError)
	}
	read, err := r.storage.GetVolume(r.ctx, core.GetVolumeRequest{VolumeId: volume.Id})
	if err != nil {
		return err
	}
	if mount.MountPoint != "/var/lib/ts-data" || mount.Device != dataDevice || mount.FilesystemType != "ext4" || !filesystemUUID.MatchString(mount.UUID) || !diskSerial.MatchString(mount.Serial) {
		return fmt.Errorf("host %s data mount identity mismatch: got %+v; want /var/lib/ts-data on %s, ext4, a filesystem UUID and a disk serial", host, mount, dataDevice)
	}
	expectedSize := deref(read.SizeInGBs) * 1024 * 1024 * 1024
	if expectedSize <= 0 || mount.SizeBytes != expectedSize {
		return fmt.Errorf("volume %s size mismatch: host %d bytes, API %d bytes", deref(volume.Id), mount.SizeBytes, expectedSize)
	}
	expectedSerial := read.FreeformTags[dataSerialTag]
	if expectedSerial != "" && mount.Serial != expectedSerial {
		return fmt.Errorf("volume %s serial mismatch: host %s, volume tag %s", deref(volume.Id), mount.Serial, expectedSerial)
	}
	expectedUUID := read.FreeformTags[dataUUIDTag]
	if expectedUUID != "" && mount.UUID != expectedUUID {
		return fmt.Errorf("volume %s UUID mismatch: host %s, volume tag %s", deref(volume.Id), mount.UUID, expectedUUID)
	}
	if !r.createdVolumes[deref(volume.Id)] && (read.FreeformTags[dataFormattedTag] != "yes" || expectedUUID == "") {
		return fmt.Errorf("adopted volume %s requires initialised tag and UUID", deref(volume.Id))
	}
	if read.FreeformTags[dataFormattedTag] == "yes" && expectedUUID == mount.UUID && expectedSerial == mount.Serial {
		return r.report("unchanged", "data-volume-formatted", host+"-data", deref(volume.Id))
	}
	tags := maps.Clone(read.FreeformTags)
	tags[dataFormattedTag], tags[dataUUIDTag], tags[dataSerialTag] = "yes", mount.UUID, mount.Serial
	_, err = r.storage.UpdateVolume(r.ctx, core.UpdateVolumeRequest{VolumeId: volume.Id, IfMatch: read.Etag, UpdateVolumeDetails: core.UpdateVolumeDetails{FreeformTags: tags}})
	if err != nil {
		return err
	}
	verified, err := r.storage.GetVolume(r.ctx, core.GetVolumeRequest{VolumeId: volume.Id})
	if err != nil {
		return err
	}
	if verified.FreeformTags[dataFormattedTag] != "yes" || verified.FreeformTags[dataUUIDTag] != mount.UUID || verified.FreeformTags[dataSerialTag] != mount.Serial {
		return errors.New("data volume initialised tag, UUID and serial did not read back")
	}
	return r.report("updated", "data-volume-formatted", host+"-data", deref(volume.Id))
}

func (r *run) bindDataVolume(instance *core.Instance, volume *core.Volume) error {
	if r.dry {
		return nil
	}
	if instance.Metadata[dataVolumeTag] != deref(volume.Id) {
		return fmt.Errorf("instance %s launched for volume %s, refusing volume %s", deref(instance.Id), instance.Metadata[dataVolumeTag], deref(volume.Id))
	}
	read, err := r.storage.GetVolume(r.ctx, core.GetVolumeRequest{VolumeId: volume.Id})
	if err != nil {
		return err
	}
	previous := read.FreeformTags[dataInstanceTag]
	if previous != "" && previous != deref(instance.Id) {
		old, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: &previous})
		if err != nil {
			return err
		}
		if old.LifecycleState != core.InstanceLifecycleStateTerminated {
			return fmt.Errorf("volume %s is bound to instance %s, refusing instance %s", deref(volume.Id), previous, deref(instance.Id))
		}
	}
	tags := maps.Clone(read.FreeformTags)
	tags[dataInstanceTag] = deref(instance.Id)
	_, err = r.storage.UpdateVolume(r.ctx, core.UpdateVolumeRequest{VolumeId: volume.Id, IfMatch: read.Etag, UpdateVolumeDetails: core.UpdateVolumeDetails{FreeformTags: tags}})
	return err
}
