package failover

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// OCIFleet is the slice of the OCI fleet a reattach drives: the journaled
// reattach boundary plus the regular retained-volume attach.
type OCIFleet interface {
	oci.VolumeReattacher
	AttachRetainedVolume(context.Context, oci.VolumeAttachRequest) (oci.Attachment, error)
}

// OCIBoundary adapts the OCI fleet to the Reattacher's instance, volume and
// permit boundaries. Every effect stays journaled and epoch-fenced inside
// internal/oci; this adapter only translates types.
type OCIBoundary struct {
	Fleet OCIFleet
}

// NewOCIBoundary returns the adapter when fleet supports reattach.
func NewOCIBoundary(fleet any) (OCIBoundary, bool) {
	supported, ok := fleet.(OCIFleet)
	if !ok || supported == nil {
		return OCIBoundary{}, false
	}
	return OCIBoundary{Fleet: supported}, true
}

func (boundary OCIBoundary) InstanceLifecycleState(ctx context.Context, instanceID string) (string, error) {
	if boundary.Fleet == nil {
		return "", errors.New("reattach OCI boundary has no fleet")
	}
	return boundary.Fleet.FencedInstanceState(ctx, instanceID)
}

func (boundary OCIBoundary) VolumeAttachments(ctx context.Context, volumeID string) ([]Attachment, error) {
	if boundary.Fleet == nil {
		return nil, errors.New("reattach OCI boundary has no fleet")
	}
	listed, err := boundary.Fleet.RetainedVolumeAttachments(ctx, volumeID)
	if err != nil {
		return nil, err
	}
	attachments := make([]Attachment, 0, len(listed))
	for _, attachment := range listed {
		attachments = append(attachments, fromOCI(attachment))
	}
	return attachments, nil
}

func (boundary OCIBoundary) DetachFenced(ctx context.Context, request Request, attachment Attachment, proof FenceProof) error {
	if boundary.Fleet == nil {
		return errors.New("reattach OCI boundary has no fleet")
	}
	if proof.InstanceID != request.OldInstanceID || proof.State != "TERMINATED" ||
		attachment.InstanceID != request.OldInstanceID || attachment.VolumeID != request.VolumeID {
		return ErrFenceProofMismatch
	}
	return boundary.Fleet.DetachFencedAttachment(ctx, oci.FencedDetachRequest{
		DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
		AttachmentID: attachment.ID, ExpectedETag: attachment.ETag, InstanceID: attachment.InstanceID,
	})
}

func (boundary OCIBoundary) AttachReplacement(ctx context.Context, request Request, proof FenceProof) (Attachment, error) {
	if boundary.Fleet == nil {
		return Attachment{}, errors.New("reattach OCI boundary has no fleet")
	}
	if proof.InstanceID != request.OldInstanceID || proof.State != "TERMINATED" {
		return Attachment{}, ErrFenceProofMismatch
	}
	attached, err := boundary.Fleet.AttachRetainedVolume(ctx, oci.VolumeAttachRequest{
		DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
		VolumeID: request.VolumeID, InstanceID: request.ReplacementInstanceID,
		IdempotencyKey: request.AttachKey, AllowDetachedHistory: true,
	})
	if err != nil {
		return Attachment{}, err
	}
	return fromOCI(attached), nil
}

func (boundary OCIBoundary) GrantMountExisting(ctx context.Context, request Request, attachment Attachment) error {
	if boundary.Fleet == nil {
		return errors.New("reattach OCI boundary has no fleet")
	}
	return boundary.Fleet.GrantVolumeMountExisting(ctx, mountPermit(request, attachment))
}

func (boundary OCIBoundary) HasMountExisting(ctx context.Context, request Request, attachment Attachment) (bool, error) {
	if boundary.Fleet == nil {
		return false, errors.New("reattach OCI boundary has no fleet")
	}
	return boundary.Fleet.HasVolumeMountExisting(ctx, mountPermit(request, attachment))
}

// ErrFenceProofMismatch reports a fence proof that does not name the
// request's old instance as TERMINATED.
var ErrFenceProofMismatch = errors.New("reattach fence proof does not match the lost instance")

func mountPermit(request Request, attachment Attachment) oci.VolumeMountPermit {
	return oci.VolumeMountPermit{
		DatabaseID: request.DatabaseID, PartitionID: request.PartitionID, VolumeID: request.VolumeID,
		AttachmentID: attachment.ID, ReplacementInstanceID: request.ReplacementInstanceID,
		FencedInstanceID: request.OldInstanceID,
	}
}

func fromOCI(attachment oci.Attachment) Attachment {
	return Attachment{ID: attachment.ID, VolumeID: attachment.VolumeID, InstanceID: attachment.InstanceID,
		State: attachment.State, ETag: attachment.ETag}
}
