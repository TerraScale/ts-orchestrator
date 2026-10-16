package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
)

type activePlacementReader interface {
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

// The production authority implements this reader. The opaque Fencer seam is
// also used by isolated fleet tests, so the deterministic key and descriptor
// checks remain independent of the optional readback.
func (f *fleet) verifyActivePlacement(ctx context.Context, databaseID, partitionID string,
	generation uint64, payloadDigest string,
) error {
	reader, ok := f.fencer.(activePlacementReader)
	if !ok {
		return nil
	}
	entry, err := reader.ReadPlacementIntent(ctx, databaseID, partitionID)
	if err != nil {
		return fmt.Errorf("read signed placement for OCI effect: %w", err)
	}
	if entry.Kind != authority.MutationPlacementIntent || entry.SubjectKey != databaseID+"."+partitionID {
		return errors.New("OCI effect placement authority differs from requested workload")
	}
	var placement struct {
		DatabaseID  string `json:"database_id"`
		PartitionID string `json:"partition_id"`
		Generation  uint64 `json:"generation"`
	}
	if err := json.Unmarshal(entry.Payload, &placement); err != nil {
		return err
	}
	sum := sha256.Sum256(entry.Payload)
	if placement.DatabaseID != databaseID || placement.PartitionID != partitionID ||
		placement.Generation != generation || hex.EncodeToString(sum[:]) != payloadDigest {
		return errors.New("OCI effect differs from current signed placement generation or digest")
	}
	return nil
}

func (f *fleet) verifyLaunchScope(ctx context.Context, descriptor hostboot.Descriptor, createKey string) error {
	if _, ok := f.fencer.(activePlacementReader); !ok {
		return nil
	}
	if createKey != terminalDigestToken("th", descriptor.DatabaseID, descriptor.PartitionID,
		string(f.config.Region), descriptor.SeatID, fmt.Sprint(descriptor.HostAttempt)) {
		return fmt.Errorf("%w: host create key differs from gated workload", ErrHostBootBindingMismatch)
	}
	return f.verifyActivePlacement(ctx, descriptor.DatabaseID, descriptor.PartitionID,
		descriptor.IntentGeneration, descriptor.IntentPayloadDigest)
}

func (f *fleet) verifyAttachScope(ctx context.Context, databaseID, partitionID string,
	instanceID string, volume CloudVolume,
) error {
	if _, ok := f.fencer.(activePlacementReader); !ok {
		return nil
	}
	cloud, identity, err := f.ownedInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	launch, found, err := f.journal.GetOperation(ctx, OperationScope{Action: actionLaunch, Key: identity.CreateKey,
		Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner})
	if err != nil || !found {
		return fmt.Errorf("%w: attachment host has no immutable launch scope: %v", ErrHostBootBindingMismatch, err)
	}
	descriptor, err := launchIntentDescriptor(launch)
	if err != nil || descriptor.DatabaseID != databaseID || descriptor.PartitionID != partitionID ||
		cloud.Metadata[hostboot.MetadataKey] != launch.BootDescriptor ||
		volume.FreeformTags[tagCreateKey] != terminalDigestToken("tv", databaseID, partitionID,
			string(f.config.Region), descriptor.SeatID) {
		return fmt.Errorf("%w: attachment resource differs from gated workload", ErrForeignResource)
	}
	return f.verifyActivePlacement(ctx, databaseID, partitionID,
		descriptor.IntentGeneration, descriptor.IntentPayloadDigest)
}

func (f *fleet) verifyDataCreateScope(ctx context.Context, request VolumeCreateRequest) error {
	reader, ok := f.fencer.(activePlacementReader)
	if !ok {
		return nil
	}
	if request.MemberID == "" || request.CreateKey != terminalDigestToken("tv", request.DatabaseID,
		request.PartitionID, string(f.config.Region), request.MemberID) {
		return fmt.Errorf("%w: data volume create key differs from gated workload", ErrForeignResource)
	}
	entry, err := reader.ReadPlacementIntent(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return err
	}
	var placement struct {
		DatabaseID      string `json:"database_id"`
		PartitionID     string `json:"partition_id"`
		CanonicalRoster struct {
			Rows []struct {
				Region   Region `json:"region"`
				SeatID   string `json:"seat_id"`
				MemberID string `json:"member_id"`
			} `json:"members"`
		} `json:"canonical_roster"`
	}
	if err := json.Unmarshal(entry.Payload, &placement); err != nil {
		return err
	}
	if entry.Kind != authority.MutationPlacementIntent || entry.SubjectKey != request.DatabaseID+"."+request.PartitionID ||
		placement.DatabaseID != request.DatabaseID || placement.PartitionID != request.PartitionID {
		return errors.New("OCI data create scope differs from current signed placement")
	}
	for _, row := range placement.CanonicalRoster.Rows {
		if row.Region == f.config.Region && row.SeatID == request.MemberID && row.MemberID != "" {
			return nil
		}
	}
	return errors.New("OCI data create member is absent from signed placement roster")
}
