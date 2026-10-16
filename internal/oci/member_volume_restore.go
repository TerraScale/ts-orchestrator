package oci

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// Restore drill. A member's backups are proven restorable by restoring one
// into a new volume on a scratch host, where terrabase restore-check starts
// TerraBase on it and reads a document. The restored volume never touches the
// member: it gets its own create key and resource tag, no backup policy, and
// attaches only to an instance that is not a member of the cell.

// RestoreVolumeDevice is where a restored volume attaches: a device no member
// volume uses, so terrabase restore-check, which mounts only this device,
// never mounts a member's own volume.
const RestoreVolumeDevice = "/dev/oracleoci/oraclevdz"

const (
	resourceMemberRestore = "member-data-restore"
	tagRestoreMember      = "terrascale-restore-member"
	tagRestoreBackup      = "terrascale-restore-backup"
	// restoreSettleTimeout bounds the wait until a restored volume is
	// AVAILABLE; OCI restores a backup into a new volume in minutes.
	restoreSettleTimeout = 20 * time.Minute
)

// RestoreRequest restores one backup of a member's data volume into a new
// volume and attaches it to a scratch instance.
type RestoreRequest struct {
	Member string
	// BackupID is the backup to restore. Empty restores the newest
	// AVAILABLE backup of the member's current data volume; a volume that is
	// gone needs an explicit backup.
	BackupID          string
	ScratchInstanceID string
	// SourceVolumeID is the member's recorded volume (MemberVolumeRequest).
	// Every restored backup must be of it, or of the member's current
	// volume, which must then be the same one; with the volume gone it is
	// required.
	SourceVolumeID string
}

// RestoredVolume is a backup restored into a new volume and its attachment.
type RestoredVolume struct {
	BackupID string
	Attachment
}

// volumeBackupReader is the part of VolumeBackupProvider a restore reads.
type volumeBackupReader interface {
	ListVolumeBackups(ctx context.Context, volumeID string) ([]CloudVolumeBackup, error)
	GetVolumeBackup(ctx context.Context, backupID string) (CloudVolumeBackup, error)
}

// Restore restores the backup into a volume named restore-<member>-data and
// attaches it at RestoreVolumeDevice to the scratch instance. It is
// idempotent for one member and backup: a rerun reuses the restored volume.
func (v *MemberVolumes) Restore(ctx context.Context, request RestoreRequest) (RestoredVolume, error) {
	name, err := v.volumeName(request.Member)
	if err != nil {
		return RestoredVolume{}, err
	}
	f := v.fleet
	backups, ok := f.provider.(volumeBackupReader)
	if !ok {
		return RestoredVolume{}, errors.New("OCI provider cannot read volume backups")
	}
	if err := v.requireScratchInstance(ctx, request.ScratchInstanceID); err != nil {
		return RestoredVolume{}, err
	}
	backup, err := v.selectBackup(ctx, backups, name, request.BackupID, request.SourceVolumeID)
	if err != nil {
		return RestoredVolume{}, err
	}
	restoreName := "restore-" + name
	createKey := entityid.Derive("restore-volume", f.config.Owner, request.Member, backup.ID)
	volume, found, err := v.findRestoredVolume(ctx, createKey)
	if err != nil {
		return RestoredVolume{}, err
	}
	if err := v.requireOnlyAttachment(ctx, request.ScratchInstanceID, volume.ID, false); err != nil {
		return RestoredVolume{}, err
	}
	if !found {
		create := VolumeCreateRequest{Name: restoreName, CreateKey: createKey, SizeGB: backup.SizeGB,
			AvailabilityDomain: f.config.AvailabilityDomain, SourceBackupID: backup.ID}
		tags := volumeTags(f.config, create)
		tags[tagResource] = resourceMemberRestore
		tags[tagRestoreMember], tags[tagRestoreBackup] = request.Member, backup.ID
		retry := retryToken(strings.Join([]string{f.config.Owner, string(f.config.Region), createKey}, ":"))
		_, createErr := f.provider.CreateVolume(ctx, create, tags, retry)
		if volume, found, err = v.findRestoredVolume(ctx, createKey); err != nil || !found {
			return RestoredVolume{}, errors.Join(ErrOutcomeUnknown, createErr, err,
				fmt.Errorf("restored volume %s was not observed after its create", restoreName))
		}
	}
	if volume, err = v.awaitRestored(ctx, volume.ID); err != nil {
		return RestoredVolume{}, err
	}
	attachment, err := v.attach(ctx, restoreName, volume.ID, request.ScratchInstanceID, RestoreVolumeDevice)
	if err != nil {
		return RestoredVolume{}, err
	}
	// Read back what restore-check will mount: the scratch instance holds
	// exactly this restored volume at RestoreVolumeDevice.
	attachment, err = v.VerifyRestoredAttachment(ctx, request.ScratchInstanceID, volume.ID)
	if err != nil {
		return RestoredVolume{}, err
	}
	return RestoredVolume{BackupID: backup.ID, Attachment: attachment}, nil
}

// VerifyRestoredAttachment reads the exact restored volume and its exclusive
// attachment before restore-check mounts it. It performs no OCI mutations.
func (v *MemberVolumes) VerifyRestoredAttachment(ctx context.Context, scratchInstanceID, restoredVolumeID string) (Attachment, error) {
	if scratchInstanceID == "" || restoredVolumeID == "" {
		return Attachment{}, errors.New("restore verification requires scratch instance and restored volume IDs")
	}
	if err := v.requireScratchInstance(ctx, scratchInstanceID); err != nil {
		return Attachment{}, err
	}
	f := v.fleet
	volume, identity, err := f.reobserveVolumeResource(ctx, restoredVolumeID, resourceMemberRestore)
	if err != nil {
		return Attachment{}, err
	}
	if volume.LifecycleState != "AVAILABLE" || !f.memberName(volume.FreeformTags[tagRestoreMember], false) || volume.FreeformTags[tagRestoreBackup] == "" || identity.CreateKey != entityid.Derive("restore-volume", f.config.Owner, volume.FreeformTags[tagRestoreMember], volume.FreeformTags[tagRestoreBackup]) {
		return Attachment{}, fmt.Errorf("%w: volume %s is not an available restore copy", ErrForeignResource, restoredVolumeID)
	}
	if err := v.requireOnlyAttachment(ctx, scratchInstanceID, restoredVolumeID, true); err != nil {
		return Attachment{}, err
	}
	records, err := f.findVolumeAttachments(ctx, restoredVolumeID)
	if err != nil {
		return Attachment{}, err
	}
	live := liveAttachments(records)
	if len(live) != 1 || live[0].InstanceID != scratchInstanceID {
		return Attachment{}, fmt.Errorf("%w: restored volume %s has no exclusive scratch attachment", ErrAttachmentRecoveryHold, restoredVolumeID)
	}
	return f.reobserveAttachment(ctx, live[0].ID, restoredVolumeID, scratchInstanceID, RestoreVolumeDevice)
}

// requireScratchInstance accepts a running instance of the cell's compartment
// and availability domain with consistent volume naming that is not named as
// a member: a restored copy never reaches a member host.
func (v *MemberVolumes) requireScratchInstance(ctx context.Context, instanceID string) error {
	f := v.fleet
	instance, err := f.provider.GetInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	if instance.ID != instanceID || instance.CompartmentID != f.config.CompartmentID || instance.AvailabilityDomain != f.config.AvailabilityDomain {
		return fmt.Errorf("%w: scratch instance %s is outside the cell's compartment and availability domain", ErrForeignResource, instanceID)
	}
	if f.memberName(instance.DisplayName, false) {
		return fmt.Errorf("instance %s is member %s; a restore drill needs a scratch instance", instanceID, instance.DisplayName)
	}
	if instance.LifecycleState != "RUNNING" || instance.ConsistentVolumeNamingEnabled == nil || !*instance.ConsistentVolumeNamingEnabled {
		return fmt.Errorf("scratch instance %s must be RUNNING with consistent volume naming", instanceID)
	}
	return nil
}

func (v *MemberVolumes) selectBackup(ctx context.Context, backups volumeBackupReader, name, backupID, source string) (CloudVolumeBackup, error) {
	current, _, found, err := v.fleet.findVolumeByCreateKey(ctx, memberVolumeCreateKey(name))
	if err != nil {
		return CloudVolumeBackup{}, err
	}
	switch {
	case found && source != "" && current.ID != source:
		return CloudVolumeBackup{}, fmt.Errorf("%w: data volume %s is %s, not the recorded %s", ErrForeignResource, name, current.ID, source)
	case found:
		source = current.ID
	case source == "":
		return CloudVolumeBackup{}, fmt.Errorf("data volume %s is gone and no recorded volume ID names its backups", name)
	}
	if backupID != "" {
		backup, err := backups.GetVolumeBackup(ctx, backupID)
		if err != nil {
			return CloudVolumeBackup{}, err
		}
		if backup.ID != backupID || backup.LifecycleState != "AVAILABLE" || backup.SizeGB < minRetainedVolumeSizeGB {
			return CloudVolumeBackup{}, fmt.Errorf("backup %s is %s at %d GB; it must be AVAILABLE", backupID, backup.LifecycleState, backup.SizeGB)
		}
		if backup.VolumeID != source {
			return CloudVolumeBackup{}, fmt.Errorf("%w: backup %s is of volume %s, not %s of %s", ErrForeignResource, backupID, backup.VolumeID, source, name)
		}
		return backup, nil
	}
	listed, err := backups.ListVolumeBackups(ctx, source)
	if err != nil {
		return CloudVolumeBackup{}, err
	}
	var newest CloudVolumeBackup
	for _, backup := range listed {
		if backup.VolumeID == source && backup.LifecycleState == "AVAILABLE" && backup.SizeGB >= minRetainedVolumeSizeGB &&
			backup.CreatedAt.After(newest.CreatedAt) {
			newest = backup
		}
	}
	if newest.ID == "" {
		return CloudVolumeBackup{}, fmt.Errorf("data volume %s (%s) has no AVAILABLE backup", name, source)
	}
	return newest, nil
}

func (v *MemberVolumes) findRestoredVolume(ctx context.Context, createKey string) (CloudVolume, bool, error) {
	f := v.fleet
	volumes, err := f.provider.ListVolumes(ctx, f.config.CompartmentID, f.config.AvailabilityDomain)
	if err != nil {
		return CloudVolume{}, false, err
	}
	var found []CloudVolume
	for _, volume := range volumes {
		if volume.FreeformTags[tagCreateKey] == createKey && volume.LifecycleState != "TERMINATED" {
			found = append(found, volume)
		}
	}
	switch {
	case len(found) > 1:
		return CloudVolume{}, false, ErrDuplicateCreateKey
	case len(found) == 0:
		return CloudVolume{}, false, nil
	}
	volume, identity, err := f.reobserveVolumeResource(ctx, found[0].ID, resourceMemberRestore)
	if err != nil {
		return CloudVolume{}, false, err
	}
	if identity.CreateKey != createKey {
		return CloudVolume{}, false, ErrForeignResource
	}
	return volume, true, nil
}

// awaitRestored waits, bounded by restoreSettle, until the restored volume is
// AVAILABLE.
func (v *MemberVolumes) awaitRestored(ctx context.Context, volumeID string) (CloudVolume, error) {
	settleCtx, cancel := context.WithTimeout(ctx, v.restoreSettle)
	defer cancel()
	for {
		volume, _, err := v.fleet.reobserveVolumeResource(settleCtx, volumeID, resourceMemberRestore)
		if err != nil {
			return CloudVolume{}, err
		}
		switch volume.LifecycleState {
		case "AVAILABLE":
			return volume, nil
		case "PROVISIONING", "RESTORING":
		default:
			return CloudVolume{}, fmt.Errorf("restored volume %s is %s", volumeID, volume.LifecycleState)
		}
		select {
		case <-settleCtx.Done():
			return CloudVolume{}, fmt.Errorf("restored volume %s is still %s: %w", volumeID, volume.LifecycleState, settleCtx.Err())
		case <-time.After(attachmentSettlePoll):
		}
	}
}

// requireOnlyAttachment fails when the scratch instance has a live volume
// attachment other than the restored volume, or, with attached, unless that
// volume is attached at RestoreVolumeDevice.
func (v *MemberVolumes) requireOnlyAttachment(ctx context.Context, instanceID, volumeID string, attached bool) error {
	f := v.fleet
	listed, err := f.provider.ListVolumeAttachments(ctx, f.config.CompartmentID, instanceID)
	if err != nil {
		return err
	}
	found := false
	count := 0
	for _, attachment := range liveAttachments(listed) {
		if attachment.InstanceID != instanceID {
			continue
		}
		count++
		if attachment.VolumeID != volumeID {
			return fmt.Errorf("scratch instance %s also has volume %s attached; a restore drill needs it to hold only the restored volume",
				instanceID, attachment.VolumeID)
		}
		found = attachment.LifecycleState == "ATTACHED" && attachment.Device == RestoreVolumeDevice
	}
	if count > 1 {
		return fmt.Errorf("%w: scratch instance %s has multiple live attachments", ErrAttachmentRecoveryHold, instanceID)
	}
	if attached && !found {
		return fmt.Errorf("restored volume %s is not attached at %s on scratch instance %s", volumeID, RestoreVolumeDevice, instanceID)
	}
	return nil
}
