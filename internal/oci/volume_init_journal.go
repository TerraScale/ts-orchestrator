package oci

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

type volumeFormatPermitEntry struct {
	SchemaVersion int                      `json:"schema_version"`
	Record        VolumeFormatPermitRecord `json:"record"`
}

// ClaimVolumeFormatPermit atomically creates a one-way first-format record.
// Only the caller whose KV Create positively succeeded receives true. A retry
// or an ambiguous write never receives another format authorization.
func (journal *KVJournal) ClaimVolumeFormatPermit(ctx context.Context, record VolumeFormatPermitRecord) (bool, error) {
	if journal == nil || record.Region == "" || record.Generation == 0 || record.Owner == "" ||
		record.DatabaseID == "" || record.PartitionID == "" || record.InstanceID == "" ||
		record.HostCreateKey == "" || record.VolumeID == "" || record.AttachmentID == "" ||
		record.AttachmentETag == "" || !validDevicePath(record.Device) ||
		record.FileSystemUUID == "" || record.FileSystemType != "ext4" && record.FileSystemType != "xfs" ||
		!isLowerHexSHA256(record.BootDescriptorSHA256) {
		return false, errors.New("volume format permit record is incomplete")
	}
	data, err := json.Marshal(volumeFormatPermitEntry{SchemaVersion: 1, Record: record})
	if err != nil {
		return false, err
	}
	key := "volume-format-permit." + digest(string(record.Region), fmt.Sprint(record.Generation), record.Owner, record.VolumeID)
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
	var current volumeFormatPermitEntry
	if err := json.Unmarshal(entry.Value(), &current, json.RejectUnknownMembers(true)); err != nil {
		return false, err
	}
	if current.SchemaVersion != 1 || current.Record != record {
		return false, errors.New("volume format permit key belongs to a different immutable binding")
	}
	return false, nil
}
