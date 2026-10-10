package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/backup"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/capacity"
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
	if members, ok := store.members[databaseID+"/"+partitionID]; ok {
		return members, nil
	}
	return nil, errors.New("partition unreadable")
}

func (volumeListStore) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, errors.New("unused")
}

func TestPlacementVolumeIDsListsPlacedRetainedVolumesOnce(t *testing.T) {
	member := func(volumeID string, stage placement.MemberStage) placement.VersionedMemberState {
		return placement.VersionedMemberState{State: placement.MemberState{VolumeID: volumeID, Stage: stage}}
	}
	store := volumeListStore{
		intents: []placement.Intent{{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "00000000003ZJEV7X3HYJENEYG"}, {DatabaseID: "0000000000FX8HQMQT5DWS7PQ9", PartitionID: "00000000003ZJEV7X3HYJENEYG"}},
		members: map[string][]placement.VersionedMemberState{
			"00000000001Y9Z8VKC1VV66J6B/00000000003ZJEV7X3HYJENEYG": {member("vol-1", placement.StageAwaitingRuntimeContract), member("", placement.StagePreparedHost), member("vol-1", placement.StageAwaitingRuntimeContract)},
			"0000000000FX8HQMQT5DWS7PQ9/00000000003ZJEV7X3HYJENEYG": {member("vol-2", placement.StageAwaitingRuntimeContract), member("vol-3", placement.StageRemoved)},
		},
	}
	volumes, err := placementVolumeIDs(t.Context(), store)
	if err != nil || !slices.Equal(volumes, []string{"vol-1", "vol-2"}) {
		t.Fatalf("volumes = %v, %v", volumes, err)
	}
}

func TestPlacementVolumeIDsSkipsAnUnreadablePartition(t *testing.T) {
	store := volumeListStore{
		intents: []placement.Intent{{DatabaseID: "00000000001Y9Z8VKC1VV66J6B", PartitionID: "00000000003ZJEV7X3HYJENEYG"}, {DatabaseID: "0000000000CKCFR634PYANR7D4", PartitionID: "00000000003ZJEV7X3HYJENEYG"}},
		members: map[string][]placement.VersionedMemberState{
			"00000000001Y9Z8VKC1VV66J6B/00000000003ZJEV7X3HYJENEYG": {{State: placement.MemberState{VolumeID: "vol-1", Stage: placement.StageAwaitingRuntimeContract}}},
		},
	}
	volumes, err := placementVolumeIDs(t.Context(), store)
	if !errors.Is(err, backup.ErrPartialVolumes) || !slices.Equal(volumes, []string{"vol-1"}) {
		t.Fatalf("volumes = %v, %v; want the readable partition's volumes and a partial-listing error", volumes, err)
	}
}

func TestStorageFeaturesRequireTheirDependenciesWithoutAnOptIn(t *testing.T) {
	if _, err := startControllerStorageCapacity(t.Context(), Config{}, nil, nil); err == nil {
		t.Fatal("capacity collector silently skipped without its embedded broker")
	}
	if _, err := startVolumeBackups(t.Context(), nil, nil, nil, nil); err == nil {
		t.Fatal("volume backups silently skipped without a managed controller")
	}
}

func TestControllerCollectsStorageWithoutSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "storage-controller", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}}}
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	stop, err := startControllerStorageCapacity(ctx, cfg, runtime, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	store, err := capacity.OpenUsageStore(ctx, runtime.JetStream(), 1, storage.DefaultUsageTTL, capacity.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for {
		usages, err := store.Usages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(usages) == 2 {
			for _, usage := range usages {
				if usage.Node != cfg.NATS.Instance || usage.TotalBytes == 0 {
					t.Fatalf("invalid controller measurement: %+v", usage)
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("controller published no boot and JetStream measurements")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRoleConfigRejectsRemovedStorageControls(t *testing.T) {
	for _, section := range []string{
		`"controller":{"storage_capacity":{"enabled":false}}`,
		`"controller":{"storage_capacity":{"enabled":true}}`,
		`"controller":{"storage_capacity":{"interval_seconds":30}}`,
		`"controller":{"volume_backup":{"enabled":false}}`,
		`"controller":{"volume_backup":{"prune":true}}`,
		`"controller":{"volume_backup":{"retain":7}}`,
		`"controller":{"oci_observe_verify_cache_seconds":0}`,
		`"controller":{"oci_observe_verify_cache_seconds":60}`,
		`"host":{"managed_volume_online_grow":false}`,
		`"host":{"managed_volume_online_grow":true}`,
	} {
		wire := []byte(`{"version":1,` + section + `}`)
		if _, err := decodeConfig(wire); err == nil {
			t.Errorf("retired setting accepted: %s", wire)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHostLocalOptions(path); err == nil {
			t.Errorf("renewal discarded a retired setting: %s", wire)
		}
	}
}

func TestOwnedLoopStopCancelsAndJoins(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	stop := ownedLoop(context.Background(), "test loop", func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond)
		close(finished)
		return ctx.Err()
	})
	<-started
	stop()
	select {
	case <-finished:
	default:
		t.Fatal("stop returned before the loop finished")
	}
}
