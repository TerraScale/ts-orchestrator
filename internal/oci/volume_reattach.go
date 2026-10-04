package oci

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Reattach on host loss. The storage failover slice decides the steps; this
// file is the OCI boundary it drives. The rule it never bends: a retained
// volume moves to another instance only after OCI reports the old instance
// TERMINATED. TERMINATING, STOPPED, a 404 or an unreachable host are not
// proof: a stopped instance can start again with the volume attached, and
// OCI answers 404 for authorization failures too.

const (
	attachmentStateDetached  = "DETACHED"
	attachmentStateDetaching = "DETACHING"
	instanceStateTerminated  = "TERMINATED"
)

// VolumeReattacher is implemented by the OCI fleet. Callers type-assert it
// so fleets without reattach support (and test doubles) keep compiling.
type VolumeReattacher interface {
	// FencedInstanceState reports the OCI lifecycle state of an owned
	// instance. Only TERMINATED is fence proof.
	FencedInstanceState(ctx context.Context, instanceID string) (string, error)
	// RetainedVolumeAttachments lists every attachment record of an owned
	// retained volume, including DETACHING and DETACHED history.
	RetainedVolumeAttachments(ctx context.Context, volumeID string) ([]Attachment, error)
	// DetachFencedAttachment detaches an attachment of a proven TERMINATED
	// instance through a journaled, epoch-fenced detach.
	DetachFencedAttachment(ctx context.Context, request FencedDetachRequest) error
	// GrantVolumeMountExisting records a mount-existing (never format) permit
	// for the replacement attachment of a reattached volume.
	GrantVolumeMountExisting(ctx context.Context, permit VolumeMountPermit) error
	// HasVolumeMountExisting reports whether exactly this permit is recorded.
	HasVolumeMountExisting(ctx context.Context, permit VolumeMountPermit) (bool, error)
}

// FencedDetachRequest names one attachment of a lost instance. ExpectedETag
// is the attachment ETag the caller observed; a changed attachment holds.
type FencedDetachRequest struct {
	DatabaseID, PartitionID string
	AttachmentID            string
	ExpectedETag            string
	InstanceID              string
}

// VolumeMountPermit authorizes the replacement host to mount the existing
// filesystem of a reattached volume. It never carries format authority.
type VolumeMountPermit struct {
	DatabaseID            string
	PartitionID           string
	VolumeID              string
	AttachmentID          string
	ReplacementInstanceID string
	FencedInstanceID      string
}

func (permit VolumeMountPermit) complete() bool {
	return permit.DatabaseID != "" && permit.PartitionID != "" && permit.VolumeID != "" &&
		permit.AttachmentID != "" && permit.ReplacementInstanceID != "" && permit.FencedInstanceID != "" &&
		permit.ReplacementInstanceID != permit.FencedInstanceID
}

// VolumeMountPermitRecord is the durable, immutable mount-existing permit.
type VolumeMountPermitRecord struct {
	Region                Region `json:"region"`
	Generation            uint64 `json:"generation"`
	Owner                 string `json:"owner"`
	DatabaseID            string `json:"database_id"`
	PartitionID           string `json:"partition_id"`
	VolumeID              string `json:"volume_id"`
	AttachmentID          string `json:"attachment_id"`
	ReplacementInstanceID string `json:"replacement_instance_id"`
	FencedInstanceID      string `json:"fenced_instance_id"`
	FencedInstanceState   string `json:"fenced_instance_state"`
}

// VolumeMountPermitStore is the optional Journal seam for mount permits.
type VolumeMountPermitStore interface {
	RecordVolumeMountPermit(context.Context, VolumeMountPermitRecord) error
	GetVolumeMountPermit(ctx context.Context, region Region, generation uint64, owner, volumeID, attachmentID string) (VolumeMountPermitRecord, bool, error)
}

func (f *fleet) FencedInstanceState(ctx context.Context, instanceID string) (string, error) {
	if instanceID == "" {
		return "", errors.New("fenced instance lookup requires an instance ID")
	}
	cloud, _, err := f.ownedInstance(ctx, instanceID)
	if err != nil {
		return "", err
	}
	return cloud.LifecycleState, nil
}

func (f *fleet) RetainedVolumeAttachments(ctx context.Context, volumeID string) ([]Attachment, error) {
	if volumeID == "" {
		return nil, errors.New("retained volume attachment listing requires a volume ID")
	}
	if _, err := f.ownedVolume(ctx, volumeID); err != nil {
		return nil, err
	}
	listed, err := f.findVolumeAttachments(ctx, volumeID)
	if err != nil {
		return nil, err
	}
	if len(listed) > maxProviderItems {
		return nil, errors.New("OCI volume attachment history exceeds its safety bound")
	}
	attachments := make([]Attachment, 0, len(listed))
	for _, cloud := range listed {
		if cloud.ID == "" || cloud.InstanceID == "" || cloud.VolumeID != volumeID {
			return nil, fmt.Errorf("%w: OCI attachment scope changed", ErrForeignResource)
		}
		attachments = append(attachments, Attachment{
			ID: cloud.ID, VolumeID: cloud.VolumeID, InstanceID: cloud.InstanceID,
			ETag: cloud.ETag, State: cloud.LifecycleState, Device: cloud.Device,
		})
	}
	return attachments, nil
}

// DetachFencedAttachment journals and issues a detach of an attachment whose
// instance OCI reports TERMINATED. It replaces writer-stop evidence with the
// terminated-instance proof, which is re-read after the authority guard and
// immediately before the effect.
func (f *fleet) DetachFencedAttachment(ctx context.Context, request FencedDetachRequest) error {
	if request.DatabaseID == "" || request.PartitionID == "" || request.AttachmentID == "" ||
		request.ExpectedETag == "" || request.InstanceID == "" {
		return errors.New("fenced detach requires a workload scope, attachment fence and lost instance")
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, request.DatabaseID, request.PartitionID)
	if err != nil {
		return err
	}
	defer release()
	attachment, err := f.provider.GetVolumeAttachment(ctx, request.AttachmentID)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if attachment.ID != request.AttachmentID || attachment.InstanceID != request.InstanceID {
		return fmt.Errorf("%w: attachment no longer belongs to the lost instance", ErrForeignResource)
	}
	if attachment.LifecycleState == attachmentStateDetached {
		return nil
	}
	if attachment.ETag != request.ExpectedETag {
		return ErrStaleETag
	}
	instance, identity, err := f.ownedInstance(ctx, request.InstanceID)
	if err != nil {
		return err
	}
	if instance.LifecycleState != instanceStateTerminated {
		return fmt.Errorf("%w: instance %s is %s, not TERMINATED", ErrWriterStopUnverified, request.InstanceID, instance.LifecycleState)
	}
	if _, err := f.ownedVolume(ctx, attachment.VolumeID); err != nil {
		return err
	}
	// The same key as an evidence-driven Detach of this exact attachment
	// fence, so both paths converge on one journaled operation.
	intent := f.intent(actionVolumeDetach, digest(request.AttachmentID, request.ExpectedETag), request.AttachmentID,
		identity.CreateKey, request.ExpectedETag, "", attachment.VolumeID)
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return err
	}
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	if current, err := f.provider.GetInstance(ctx, request.InstanceID); err != nil || current.LifecycleState != instanceStateTerminated {
		return errors.Join(ErrWriterStopUnverified, err)
	}
	detachErr := f.provider.DetachVolume(ctx, request.AttachmentID, request.ExpectedETag)
	settled, observeErr := f.awaitDetached(ctx, request.AttachmentID)
	if observeErr != nil || !settled {
		return errors.Join(ErrOutcomeUnknown, detachErr, observeErr,
			errors.New("fenced volume detach has not reached a confirmed detached state"),
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	return f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: attachment.VolumeID, ETag: request.ExpectedETag})
}

// awaitDetached waits, bounded by attachmentSettle, until the attachment is
// DETACHED or gone. Only those two observations settle the detach.
func (f *fleet) awaitDetached(ctx context.Context, attachmentID string) (bool, error) {
	settleCtx, cancel := context.WithTimeout(ctx, f.attachmentSettle)
	defer cancel()
	for {
		current, err := f.provider.GetVolumeAttachment(settleCtx, attachmentID)
		if isNotFound(err) {
			return true, nil
		}
		if err != nil {
			if settleCtx.Err() != nil && ctx.Err() == nil {
				return false, nil
			}
			return false, err
		}
		if current.ID != attachmentID {
			return false, fmt.Errorf("%w: OCI attachment scope changed", ErrForeignResource)
		}
		if current.LifecycleState == attachmentStateDetached {
			return true, nil
		}
		select {
		case <-settleCtx.Done():
			return false, nil
		case <-time.After(attachmentSettlePoll):
		}
	}
}

// detachSettled reports a journaled detach whose outcome no longer matters
// because its exact attachment is now DETACHED or gone. A read failure keeps
// the detach unsettled.
func (f *fleet) detachSettled(ctx context.Context, op OperationIntent) bool {
	if op.Action != actionVolumeDetach || op.ResourceID == "" {
		return false
	}
	current, err := f.provider.GetVolumeAttachment(ctx, op.ResourceID)
	if err != nil {
		return isNotFound(err)
	}
	return current.ID == op.ResourceID && current.LifecycleState == attachmentStateDetached
}

// GrantVolumeMountExisting records the mount-existing permit for the
// replacement attachment after re-proving the fence. The replacement must
// hold the only live attachment, and it must be journal-owned.
func (f *fleet) GrantVolumeMountExisting(ctx context.Context, permit VolumeMountPermit) error {
	if !permit.complete() {
		return errors.New("volume mount permit is incomplete")
	}
	store, ok := f.journal.(VolumeMountPermitStore)
	if !ok {
		return errors.New("OCI journal cannot record volume mount permits")
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, permit.DatabaseID, permit.PartitionID)
	if err != nil {
		return err
	}
	defer release()
	fenced, _, err := f.ownedInstance(ctx, permit.FencedInstanceID)
	if err != nil {
		return err
	}
	if fenced.LifecycleState != instanceStateTerminated {
		return fmt.Errorf("%w: instance %s is %s, not TERMINATED", ErrWriterStopUnverified, permit.FencedInstanceID, fenced.LifecycleState)
	}
	if err := f.verifySoleLiveAttachment(ctx, permit); err != nil {
		return err
	}
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	return store.RecordVolumeMountPermit(ctx, VolumeMountPermitRecord{
		Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner,
		DatabaseID: permit.DatabaseID, PartitionID: permit.PartitionID, VolumeID: permit.VolumeID,
		AttachmentID: permit.AttachmentID, ReplacementInstanceID: permit.ReplacementInstanceID,
		FencedInstanceID: permit.FencedInstanceID, FencedInstanceState: fenced.LifecycleState,
	})
}

func (f *fleet) HasVolumeMountExisting(ctx context.Context, permit VolumeMountPermit) (bool, error) {
	if !permit.complete() {
		return false, errors.New("volume mount permit is incomplete")
	}
	record, found, err := f.mountPermit(ctx, permit.VolumeID, permit.AttachmentID)
	if err != nil || !found {
		return false, err
	}
	return record.DatabaseID == permit.DatabaseID && record.PartitionID == permit.PartitionID &&
		record.ReplacementInstanceID == permit.ReplacementInstanceID &&
		record.FencedInstanceID == permit.FencedInstanceID, nil
}

func (f *fleet) mountPermit(ctx context.Context, volumeID, attachmentID string) (VolumeMountPermitRecord, bool, error) {
	store, ok := f.journal.(VolumeMountPermitStore)
	if !ok {
		return VolumeMountPermitRecord{}, false, nil
	}
	return store.GetVolumeMountPermit(ctx, f.config.Region, f.config.Generation, f.config.Owner, volumeID, attachmentID)
}

// verifySoleLiveAttachment requires the permit's attachment to be the only
// non-DETACHED attachment of the owned volume, ATTACHED to the replacement
// with the fixed retained-volume policy and a confirmed journal receipt.
func (f *fleet) verifySoleLiveAttachment(ctx context.Context, permit VolumeMountPermit) error {
	if _, err := f.ownedVolume(ctx, permit.VolumeID); err != nil {
		return err
	}
	attachments, err := f.findVolumeAttachments(ctx, permit.VolumeID)
	if err != nil {
		return err
	}
	live := liveAttachments(attachments)
	if len(live) != 1 || live[0].ID != permit.AttachmentID || live[0].InstanceID != permit.ReplacementInstanceID {
		return fmt.Errorf("%w: the replacement attachment is not the volume's only live attachment", ErrAttachmentRecoveryHold)
	}
	attachment, err := f.reobserveAttachment(ctx, permit.AttachmentID, permit.VolumeID, permit.ReplacementInstanceID, "")
	if err != nil {
		return err
	}
	_, identity, err := f.ownedInstance(ctx, permit.ReplacementInstanceID)
	if err != nil {
		return err
	}
	owned, err := f.journal.IsOwnedAttachment(ctx, AttachmentIdentity{
		ID: attachment.ID, InstanceID: attachment.InstanceID, VolumeID: attachment.VolumeID,
		Device: attachment.Device, ETag: attachment.ETag, Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner, CreateKey: identity.CreateKey,
		IsReadOnly: attachment.IsReadOnly, IsShareable: attachment.IsShareable,
		IsPvEncryptionInTransitEnabled: attachment.IsPvEncryptionInTransitEnabled,
	})
	if err != nil {
		return fmt.Errorf("read OCI attachment ownership journal: %w", err)
	}
	if !owned {
		return fmt.Errorf("%w: attachment %s has no matching confirmed operation", ErrAttachmentRecoveryHold, attachment.ID)
	}
	return nil
}

// attachAttachments lists the attachments AttachRetainedVolume reasons
// about. By default that is every record, so any history holds the attach.
// A reattach request (AllowDetachedHistory) ignores DETACHED records only:
// they no longer give any instance access to the volume.
func (f *fleet) attachAttachments(ctx context.Context, request VolumeAttachRequest) ([]CloudAttachment, error) {
	attachments, err := f.findVolumeAttachments(ctx, request.VolumeID)
	if err != nil || !request.AllowDetachedHistory {
		return attachments, err
	}
	return liveAttachments(attachments), nil
}

// liveAttachments drops DETACHED history. Every other state, including
// DETACHING and states this code does not know, still counts as live.
func liveAttachments(attachments []CloudAttachment) []CloudAttachment {
	live := make([]CloudAttachment, 0, len(attachments))
	for _, attachment := range attachments {
		if attachment.LifecycleState != attachmentStateDetached {
			live = append(live, attachment)
		}
	}
	return live
}
