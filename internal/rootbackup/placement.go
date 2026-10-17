package rootbackup

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/storage/backup"
)

type verifiedIntents struct {
	placement.AdmittedIntentReader
	material *managedmaterial.PreparationReader
}

func (reader verifiedIntents) ListPlacementIntents(ctx context.Context, cell string) ([]placement.Intent, error) {
	intents, err := reader.AdmittedIntentReader.ListPlacementIntents(ctx, cell)
	if err != nil {
		return nil, err
	}
	for _, intent := range intents {
		if err := reader.material.Verify(ctx, intent); err != nil {
			return nil, fmt.Errorf("current placement preparation: %w", err)
		}
	}
	return intents, nil
}

type placementPin struct {
	database, partition, member, volume, intent string
	revision                                    uint64
}

type placementSnapshot struct {
	volumes []string
	pins    []placementPin
	partial []string
}

func capture(ctx context.Context, reader placement.ListingReader, region oci.Region) (placementSnapshot, error) {
	intents, err := reader.ListIntents(ctx)
	if err != nil {
		return placementSnapshot{}, err
	}
	var snapshot placementSnapshot
	var failures []error
	seen := make(map[string]bool)
	for _, intent := range intents {
		members, err := reader.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err == nil {
			for _, member := range members {
				state := member.State
				if state.Region == region && state.VolumeID != "" && state.Stage != placement.StageRemoved &&
					(state.IntentGeneration != intent.Generation || state.IntentPayloadDigest != intent.PayloadDigest()) {
					err = errors.New("retained member differs from the current admitted intent")
					break
				}
			}
		}
		if err != nil {
			snapshot.partial = append(snapshot.partial, intent.DatabaseID+"."+intent.PartitionID)
			failures = append(failures, fmt.Errorf("partition %s/%s: %w", intent.DatabaseID, intent.PartitionID, err))
			continue
		}
		for _, member := range members {
			state := member.State
			if state.Region != region || state.VolumeID == "" || state.Stage == placement.StageRemoved {
				continue
			}
			if seen[state.VolumeID] {
				return placementSnapshot{}, errors.New("retained volume is assigned to multiple current placement members")
			}
			seen[state.VolumeID] = true
			snapshot.volumes = append(snapshot.volumes, state.VolumeID)
			snapshot.pins = append(snapshot.pins, placementPin{database: state.DatabaseID, partition: state.PartitionID,
				member: state.MemberID, volume: state.VolumeID, intent: intent.PayloadDigest(), revision: member.Revision})
		}
	}
	slices.Sort(snapshot.volumes)
	slices.Sort(snapshot.partial)
	if len(failures) != 0 {
		return snapshot, errors.Join(append([]error{backup.ErrPartialVolumes}, failures...)...)
	}
	return snapshot, nil
}
