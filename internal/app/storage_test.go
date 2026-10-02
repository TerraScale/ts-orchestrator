package app

import (
	"context"
	"errors"
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

type volumeListStore struct {
	placement.Store
	intents []placement.Intent
	members map[string][]placement.VersionedMemberState
}

func (store volumeListStore) ListIntents(context.Context) ([]placement.Intent, error) {
	return store.intents, nil
}

func (store volumeListStore) ListMembers(_ context.Context, databaseID, partitionID string) ([]placement.VersionedMemberState, error) {
	return store.members[databaseID+"/"+partitionID], nil
}

func (volumeListStore) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, errors.New("unused")
}

func TestPlacementVolumeIDsListsPlacedRetainedVolumesOnce(t *testing.T) {
	member := func(volumeID string, stage placement.MemberStage) placement.VersionedMemberState {
		return placement.VersionedMemberState{State: placement.MemberState{VolumeID: volumeID, Stage: stage}}
	}
	store := volumeListStore{
		intents: []placement.Intent{{DatabaseID: "db-a", PartitionID: "p1"}, {DatabaseID: "db-b", PartitionID: "p1"}},
		members: map[string][]placement.VersionedMemberState{
			"db-a/p1": {member("vol-1", placement.StageAwaitingRuntimeContract), member("", placement.StagePreparedHost), member("vol-1", placement.StageAwaitingRuntimeContract)},
			"db-b/p1": {member("vol-2", placement.StageAwaitingRuntimeContract), member("vol-3", placement.StageRemoved)},
		},
	}
	volumes, err := placementVolumeIDs(t.Context(), store)
	if err != nil || !slices.Equal(volumes, []string{"vol-1", "vol-2"}) {
		t.Fatalf("volumes = %v, %v", volumes, err)
	}
}

func TestStorageFeaturesAreOffByDefault(t *testing.T) {
	if err := startControllerStorageCapacity(t.Context(), Config{}, nil); err != nil {
		t.Fatalf("disabled capacity collector started: %v", err)
	}
	if err := startVolumeBackups(t.Context(), Config{}, nil, nil, nil); err != nil {
		t.Fatalf("disabled volume backups started: %v", err)
	}
	var cfg Config
	cfg.Controller.VolumeBackup.Enabled = true
	if err := startVolumeBackups(t.Context(), cfg, nil, nil, nil); err == nil {
		t.Fatal("volume backups started without a managed controller")
	}
	cfg.Controller.StorageCapacity.Enabled = true
	cfg.Controller.StorageCapacity.IntervalSeconds = 60
	cfg.Controller.StorageCapacity.TTLSeconds = 30
	if err := startControllerStorageCapacity(t.Context(), cfg, nil); err == nil {
		t.Fatal("capacity collector accepted a TTL shorter than its interval")
	}
}
