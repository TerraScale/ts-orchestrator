package oci

import (
	"context"
	"errors"
	"fmt"
)

// VolumeInitializationPins are the immutable signed host desired bindings.
type VolumeInitializationPins struct {
	DatabaseID, PartitionID                        string
	InstanceID, HostCreateKey                      string
	VolumeID, AttachmentID, AttachmentETag, Device string
	FileSystemUUID, FileSystemType                 string
}

type VolumeInitializationProof struct {
	BootDescriptorSHA256 string
	AllowFormat          bool
}

// VolumeFormatPermitRecord permanently consumes the only first-format grant
// for one retained volume. It is separate from OCI operations because issuing
// a guest permission does not mutate OCI and must not block forced teardown.
type VolumeFormatPermitRecord struct {
	Region               Region `json:"region"`
	Generation           uint64 `json:"generation"`
	Owner                string `json:"owner"`
	DatabaseID           string `json:"database_id"`
	PartitionID          string `json:"partition_id"`
	InstanceID           string `json:"instance_id"`
	HostCreateKey        string `json:"host_create_key"`
	VolumeID             string `json:"volume_id"`
	AttachmentID         string `json:"attachment_id"`
	AttachmentETag       string `json:"attachment_etag"`
	Device               string `json:"device"`
	FileSystemUUID       string `json:"filesystem_uuid"`
	FileSystemType       string `json:"filesystem_type"`
	BootDescriptorSHA256 string `json:"boot_descriptor_sha256"`
}

type VolumeFormatPermitStore interface {
	ClaimVolumeFormatPermit(context.Context, VolumeFormatPermitRecord) (bool, error)
}

// VolumeInitializationInspector is the OCI boundary used before a guest
// receives a short-lived signed device-preparation permit.
type VolumeInitializationInspector interface {
	InspectVolumeInitialization(context.Context, VolumeInitializationPins) (VolumeInitializationProof, error)
}

func (f *fleet) InspectVolumeInitialization(ctx context.Context, pins VolumeInitializationPins) (VolumeInitializationProof, error) {
	if pins.InstanceID == "" || pins.HostCreateKey == "" || pins.VolumeID == "" || pins.AttachmentID == "" ||
		pins.DatabaseID == "" || pins.PartitionID == "" || pins.AttachmentETag == "" || !validDevicePath(pins.Device) ||
		pins.FileSystemUUID == "" || pins.FileSystemType != "ext4" && pins.FileSystemType != "xfs" {
		return VolumeInitializationProof{}, errors.New("volume initialization pins are incomplete")
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, pins.DatabaseID, pins.PartitionID)
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	defer release()
	instances, err := f.Observe(ctx)
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	var selected *Instance
	for i := range instances {
		if instances[i].ID == pins.InstanceID {
			selected = &instances[i]
			break
		}
	}
	if selected == nil || selected.CreateKey != pins.HostCreateKey || selected.State != "RUNNING" ||
		selected.BootDescriptorSHA256 == "" {
		return VolumeInitializationProof{}, fmt.Errorf("%w: signed host is not an owned running instance", ErrForeignResource)
	}
	matched := false
	for _, attachment := range selected.Attachments {
		if attachment.ID == pins.AttachmentID && attachment.VolumeID == pins.VolumeID &&
			attachment.InstanceID == pins.InstanceID && attachment.ETag == pins.AttachmentETag &&
			attachment.Device == pins.Device && attachment.State == "ATTACHED" &&
			!attachment.IsReadOnly && !attachment.IsShareable && attachment.IsPvEncryptionInTransitEnabled {
			matched = true
		}
	}
	if !matched {
		return VolumeInitializationProof{}, fmt.Errorf("%w: signed attachment is not current on the owned instance", ErrForeignResource)
	}
	volume, err := f.ownedVolume(ctx, pins.VolumeID)
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	if volume.LifecycleState != "AVAILABLE" || volume.CompartmentID != f.config.CompartmentID ||
		volume.AvailabilityDomain != f.config.AvailabilityDomain {
		return VolumeInitializationProof{}, fmt.Errorf("%w: retained volume is not the available regional resource", ErrForeignResource)
	}
	attachments, err := f.findVolumeAttachments(ctx, pins.VolumeID)
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	if len(attachments) != 1 || attachments[0].ID != pins.AttachmentID || attachments[0].InstanceID != pins.InstanceID {
		return VolumeInitializationProof{}, fmt.Errorf("%w: volume has another attachment history", ErrForeignResource)
	}
	operations, err := f.journal.ListOperations(ctx)
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	creates, attaches, otherAttachmentEffects := 0, 0, 0
	for _, operation := range operations {
		intent, result := operation.Intent, operation.Result
		if intent.Region != f.config.Region || intent.Generation != f.config.Generation || intent.Owner != f.config.Owner ||
			intent.VolumeID != pins.VolumeID && result.ResourceID != pins.VolumeID {
			continue
		}
		switch intent.Action {
		case actionVolumeCreate:
			if result.ResourceID == pins.VolumeID && !result.Unknown && !result.RecordedAt.IsZero() {
				creates++
			}
		case actionVolumeAttach:
			if intent.ResourceID == pins.InstanceID && intent.VolumeID == pins.VolumeID && intent.Device == pins.Device &&
				result.ResourceID == pins.AttachmentID && result.ETag == pins.AttachmentETag &&
				!result.Unknown && !result.RecordedAt.IsZero() {
				attaches++
			} else {
				otherAttachmentEffects++
			}
		case actionVolumeDetach:
			otherAttachmentEffects++
		}
	}
	proof := VolumeInitializationProof{BootDescriptorSHA256: selected.BootDescriptorSHA256}
	if pins.FileSystemType != "ext4" || creates != 1 || attaches != 1 || otherAttachmentEffects != 0 {
		return proof, nil
	}
	if err := f.guard(ctx, epoch); err != nil {
		return VolumeInitializationProof{}, err
	}
	store, ok := f.journal.(VolumeFormatPermitStore)
	if !ok {
		return VolumeInitializationProof{}, errors.New("OCI journal cannot atomically consume volume format authority")
	}
	proof.AllowFormat, err = store.ClaimVolumeFormatPermit(ctx, VolumeFormatPermitRecord{
		Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner,
		DatabaseID: pins.DatabaseID, PartitionID: pins.PartitionID,
		InstanceID: pins.InstanceID, HostCreateKey: pins.HostCreateKey,
		VolumeID: pins.VolumeID, AttachmentID: pins.AttachmentID,
		AttachmentETag: pins.AttachmentETag, Device: pins.Device,
		FileSystemUUID: pins.FileSystemUUID, FileSystemType: pins.FileSystemType,
		BootDescriptorSHA256: selected.BootDescriptorSHA256,
	})
	if err != nil {
		return VolumeInitializationProof{}, err
	}
	return proof, nil
}
