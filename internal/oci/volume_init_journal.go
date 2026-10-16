package oci

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

// ClaimVolumeFormatPermit atomically creates a one-way first-format record.
// Only the caller whose KV Create positively succeeded receives true. A retry
// or an ambiguous write never receives another format authorization.
func (journal *KVJournal) ClaimVolumeFormatPermit(ctx context.Context, record VolumeFormatPermitRecord) (bool, error) {
	if journal == nil || record.Region == "" || record.Generation == 0 || record.Owner == "" ||
		!entityid.Valid(record.DatabaseID) || !entityid.Valid(record.PartitionID) || record.InstanceID == "" ||
		!entityid.Valid(record.HostCreateKey) || record.VolumeID == "" || record.AttachmentID == "" ||
		record.AttachmentETag == "" || !validDevicePath(record.Device) ||
		record.FileSystemUUID == "" || record.FileSystemType != "ext4" && record.FileSystemType != "xfs" ||
		!isLowerHexSHA256(record.BootDescriptorSHA256) {
		return false, errors.New("volume format permit record is incomplete")
	}
	data, err := json.Marshal(journalEntry{SchemaVersion: journalSchema, Kind: "format-permit", FormatPermit: record})
	if err != nil {
		return false, err
	}
	key := entityid.Derive("volume-format-permit", string(record.Region), fmt.Sprint(record.Generation), record.Owner, record.VolumeID)
	if _, err := journal.kv.Create(ctx, key, data); err == nil {
		return true, nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		// A timed-out create might have committed. Never grant true without a
		// positive Create result, even if readback finds our exact bytes.
		return false, fmt.Errorf("create volume format permit: %w", err)
	}
	entry, err := journal.kv.Get(ctx, key)
	if err != nil {
		return false, err
	}
	var current journalEntry
	if err := json.Unmarshal(entry.Value(), &current, json.RejectUnknownMembers(true)); err != nil {
		return false, err
	}
	if current.SchemaVersion != journalSchema || current.Kind != "format-permit" || current.FormatPermit != record {
		return false, errors.New("volume format permit key belongs to a different immutable binding")
	}
	return false, nil
}

func volumeMountPermitKey(region Region, generation uint64, owner, volumeID, attachmentID string) string {
	return entityid.Derive("volume-mount-permit", string(region), fmt.Sprint(generation), owner, volumeID, attachmentID)
}

func validVolumeMountPermitRecord(record VolumeMountPermitRecord) bool {
	return record.Region != "" && record.Generation != 0 && record.Owner != "" &&
		entityid.Valid(record.DatabaseID) && entityid.Valid(record.PartitionID) && record.VolumeID != "" &&
		record.AttachmentID != "" && record.ReplacementInstanceID != "" && record.FencedInstanceID != "" &&
		record.ReplacementInstanceID != record.FencedInstanceID && record.FencedInstanceState == instanceStateTerminated
}

// RecordVolumeMountPermit creates the immutable mount-existing permit of one
// replacement attachment. A retry with the exact record succeeds; any other
// record under the same key is refused.
func (journal *KVJournal) RecordVolumeMountPermit(ctx context.Context, record VolumeMountPermitRecord) error {
	if journal == nil || !validVolumeMountPermitRecord(record) {
		return errors.New("volume mount permit record is incomplete")
	}
	data, err := json.Marshal(journalEntry{SchemaVersion: journalSchema, Kind: "mount-permit", MountPermit: record})
	if err != nil {
		return err
	}
	key := volumeMountPermitKey(record.Region, record.Generation, record.Owner, record.VolumeID, record.AttachmentID)
	if _, err := journal.kv.Create(ctx, key, data); err == nil {
		return nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("create volume mount permit: %w", err)
	}
	current, found, err := journal.GetVolumeMountPermit(ctx, record.Region, record.Generation, record.Owner,
		record.VolumeID, record.AttachmentID)
	if err != nil {
		return err
	}
	if !found || current != record {
		return errors.New("volume mount permit key belongs to a different immutable binding")
	}
	return nil
}

// GetVolumeMountPermit reads the mount-existing permit of one attachment.
func (journal *KVJournal) GetVolumeMountPermit(ctx context.Context, region Region, generation uint64,
	owner, volumeID, attachmentID string,
) (VolumeMountPermitRecord, bool, error) {
	if journal == nil || region == "" || generation == 0 || owner == "" || volumeID == "" || attachmentID == "" {
		return VolumeMountPermitRecord{}, false, errors.New("volume mount permit lookup is incomplete")
	}
	entry, err := journal.kv.Get(ctx, volumeMountPermitKey(region, generation, owner, volumeID, attachmentID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return VolumeMountPermitRecord{}, false, nil
	}
	if err != nil {
		return VolumeMountPermitRecord{}, false, err
	}
	var current journalEntry
	if err := json.Unmarshal(entry.Value(), &current, json.RejectUnknownMembers(true)); err != nil {
		return VolumeMountPermitRecord{}, false, err
	}
	record := current.MountPermit
	if current.SchemaVersion != journalSchema || current.Kind != "mount-permit" || !validVolumeMountPermitRecord(record) || record.Region != region ||
		record.Generation != generation || record.Owner != owner || record.VolumeID != volumeID ||
		record.AttachmentID != attachmentID {
		return VolumeMountPermitRecord{}, false, errors.New("volume mount permit record is corrupt")
	}
	return record, true, nil
}
