package databaseadmission

import (
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func allocationFixture(t *testing.T) (*MemoryJournal, Record, time.Time) {
	t.Helper()
	journal := NewMemoryJournal()
	record := journalFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	record.CreatedAt = now.Add(-time.Hour)
	for i := range record.PlacementTargets {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(record.PlacementTargets[i].Proposal, stage); err != nil {
			t.Fatal(err)
		}
		stage.Declarations = []*pb.PlacementDatabaseDeclaration{{Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, SelectedRegions: []string{"GRU"}}}
		encoded, err := proto.Marshal(stage)
		if err != nil {
			t.Fatal(err)
		}
		record.PlacementTargets[i].Proposal = encoded
		record.Targets[i].Proposal = encoded
	}
	if _, err := journal.Save(t.Context(), ScopeKey(record.Request), 0, record); err != nil {
		t.Fatal(err)
	}
	return journal, record, now
}

func TestAllocatePlacementStreamsInitialRetryAndCoverage(t *testing.T) {
	journal, record, now := allocationFixture(t)
	if err := journal.AllocatePlacementStreams(t.Context(), record, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); err != nil {
		t.Fatal(err)
	}
	_, resources, err := journal.LifecycleResources(t.Context())
	if err != nil || len(resources) != 1 || len(resources[0].Streams) != 1 {
		t.Fatalf("resources=%+v err=%v", resources, err)
	}
	stream := resources[0].Streams[0]
	if stream.StartedAt != record.CreatedAt || stream.Epoch != 1 || stream.Partition == "" {
		t.Fatalf("initial stream=%+v", stream)
	}
	if _, err := journal.FreezeInventory(t.Context(), record.Request.TenantID, record.CreatedAt, now); err != nil {
		t.Fatalf("delayed initial stream left inventory uncovered: %v", err)
	}
	revision := resources[0]
	if err := journal.AllocatePlacementStreams(t.Context(), record, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, resources, err = journal.LifecycleResources(t.Context())
	if err != nil || len(resources[0].Streams) != 1 || resources[0].Streams[0].Partition != stream.Partition || !resources[0].Streams[0].StartedAt.Equal(stream.StartedAt) {
		t.Fatalf("retry changed stream=%+v err=%v", resources[0].Streams, err)
	}
	if !slices.Equal(resources[0].Regions, revision.Regions) {
		t.Fatal("retry changed resource scope")
	}
}

func TestAllocatePlacementStreamsRejectsChangedProof(t *testing.T) {
	journal, record, now := allocationFixture(t)
	if err := journal.AllocatePlacementStreams(t.Context(), record, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); err != nil {
		t.Fatal(err)
	}
	if err := journal.AllocatePlacementStreams(t.Context(), record, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now.Add(time.Minute)); err == nil {
		t.Fatal("changed proof accepted")
	}
}

func TestAllocatePlacementStreamsSkipsDeleted(t *testing.T) {
	journal, record, now := allocationFixture(t)
	if err := journal.AllocatePlacementStreams(t.Context(), record, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); err != nil {
		t.Fatal(err)
	}
	_, resources, _ := journal.LifecycleResources(t.Context())
	identity := resources[0].Identity
	resources[0].DeletedAt = now
	resources[0].UsageStoppedAt = now
	resources[0].AccessRevoked = true
	// Deletion is applied through the journal state to retain the authoritative flags.
	if err := journal.lifecycleTransact(t.Context(), func(state *journalState) error {
		state.Lifecycle.Resources[databaselifecycle.Key(identity)] = resources[0]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.AllocatePlacementStreams(t.Context(), record, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestAllocatePlacementStreamsAtomicMissingScope(t *testing.T) {
	journal, record, now := allocationFixture(t)
	stage := new(pb.PlacementStageRequest)
	if err := proto.Unmarshal(record.PlacementTargets[0].Proposal, stage); err != nil {
		t.Fatal(err)
	}
	stage.Proposal.Assignments[0].Database = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	encoded, _ := proto.Marshal(stage)
	for i := range record.PlacementTargets {
		record.PlacementTargets[i].Proposal = encoded
	}
	if err := journal.AllocatePlacementStreams(t.Context(), record, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing scope err=%v", err)
	}
	_, resources, err := journal.LifecycleResources(t.Context())
	if err != nil || len(resources) != 1 || len(resources[0].Streams) != 0 {
		t.Fatalf("partial allocation resources=%+v err=%v", resources, err)
	}
}
