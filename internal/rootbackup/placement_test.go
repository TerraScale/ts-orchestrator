package rootbackup

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/storage/backup"
)

type listingFixture struct {
	intents []placement.Intent
	members map[string][]placement.VersionedMemberState
	failed  string
}

func (fixture listingFixture) ListIntents(context.Context) ([]placement.Intent, error) {
	return fixture.intents, nil
}

func (fixture listingFixture) ListMembers(_ context.Context, _, partition string) ([]placement.VersionedMemberState, error) {
	if partition == fixture.failed {
		return nil, errors.New("partition unreadable")
	}
	return fixture.members[partition], nil
}

func TestBackupPlacementKeepsHealthyRegionalVolumesWithoutOrphanAuthority(t *testing.T) {
	fixture := listingFixture{intents: []placement.Intent{{DatabaseID: "database", PartitionID: "healthy", Generation: 1},
		{DatabaseID: "database", PartitionID: "unreadable", Generation: 1}}, failed: "unreadable",
		members: map[string][]placement.VersionedMemberState{"healthy": {
			{Revision: 9, State: placement.MemberState{DatabaseID: "database", PartitionID: "healthy", MemberID: "own",
				Region: oci.RegionGRU, IntentGeneration: 1, VolumeID: "ocid1.volume.own", Stage: placement.StageServing}},
			{Revision: 10, State: placement.MemberState{Region: oci.RegionSFO, IntentGeneration: 1, VolumeID: "ocid1.volume.other-region"}},
			{Revision: 11, State: placement.MemberState{Region: oci.RegionGRU, VolumeID: "ocid1.volume.removed", Stage: placement.StageRemoved}},
		}}}
	listed, err := capture(t.Context(), fixture, oci.RegionGRU)
	if !errors.Is(err, backup.ErrPartialVolumes) || !reflect.DeepEqual(listed.volumes, []string{"ocid1.volume.own"}) ||
		!reflect.DeepEqual(listed.partial, []string{"database.unreadable"}) || len(listed.pins) != 1 || listed.pins[0].revision != 9 {
		t.Fatalf("partial regional listing = %+v, %v", listed, err)
	}
	fixture.failed = ""
	complete, err := capture(t.Context(), fixture, oci.RegionGRU)
	if err != nil || reflect.DeepEqual(listed, complete) {
		t.Fatalf("recovered partition did not change the guarded snapshot: %+v, %v", complete, err)
	}
}

func TestBackupPlacementRejectsStaleIntentAndDuplicateVolume(t *testing.T) {
	member := placement.VersionedMemberState{Revision: 9, State: placement.MemberState{Region: oci.RegionGRU,
		IntentGeneration: 1, VolumeID: "ocid1.volume.own", Stage: placement.StageServing}}
	fixture := listingFixture{intents: []placement.Intent{{DatabaseID: "database", PartitionID: "partition", Generation: 2}},
		members: map[string][]placement.VersionedMemberState{"partition": {member}}}
	listed, err := capture(t.Context(), fixture, oci.RegionGRU)
	if !errors.Is(err, backup.ErrPartialVolumes) || len(listed.volumes) != 0 {
		t.Fatalf("stale intent acquired backup authority: %+v, %v", listed, err)
	}
	fixture.intents[0].Generation = 1
	fixture.members["partition"] = append(fixture.members["partition"], member)
	if listed, err := capture(t.Context(), fixture, oci.RegionGRU); err == nil || len(listed.volumes) != 0 {
		t.Fatalf("duplicate volume acquired backup authority: %+v, %v", listed, err)
	}
}
