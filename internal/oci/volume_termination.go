package oci

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// OCI volume IDs cannot be reused; a verified TERMINATED observation stays true.
type volumeTermination struct {
	VolumeID           string    `json:"volume_id"`
	Region             Region    `json:"region"`
	Owner              string    `json:"owner"`
	CompartmentID      string    `json:"compartment_id"`
	AvailabilityDomain string    `json:"availability_domain"`
	ObservedAt         time.Time `json:"observed_at"`
}

func (journal *KVJournal) volumeTerminated(ctx context.Context, config RegionConfig, volumeID string) (bool, error) {
	entry, err := journal.read(ctx, ownershipKey("volume-termination", volumeID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	proof := entry.VolumeTermination
	if entry.Kind != "volume-termination" || proof.VolumeID != volumeID || proof.Region != config.Region ||
		proof.Owner != config.Owner || proof.CompartmentID != config.CompartmentID ||
		proof.AvailabilityDomain != config.AvailabilityDomain || proof.ObservedAt.IsZero() ||
		proof.ObservedAt.Location() != time.UTC {
		return false, errors.New("OCI volume termination proof has a different or corrupt scope")
	}
	return true, nil
}

func (journal *KVJournal) RecordVolumeTermination(ctx context.Context, config RegionConfig, volumeID string) error {
	if volumeID == "" || config.Owner == "" || config.Region == "" || config.CompartmentID == "" || config.AvailabilityDomain == "" {
		return errors.New("OCI volume termination proof requires complete scope")
	}
	proof := volumeTermination{VolumeID: volumeID, Region: config.Region, Owner: config.Owner,
		CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		ObservedAt: time.Now().UTC()}
	data, err := json.Marshal(journalEntry{SchemaVersion: journalSchema, Kind: "volume-termination", VolumeTermination: proof})
	if err != nil {
		return err
	}
	if _, err := journal.kv.Create(ctx, ownershipKey("volume-termination", volumeID), data); err == nil {
		return nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("persist OCI volume termination proof: %w", err)
	}
	terminated, err := journal.volumeTerminated(ctx, config, volumeID)
	if err != nil {
		return err
	}
	if !terminated {
		return errors.New("OCI volume termination proof disappeared before readback")
	}
	return nil
}
