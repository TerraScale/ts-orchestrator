package databaseadmission

import (
	"errors"
	"reflect"
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
	if err := journal.AllocatePlacementStreams(t.Context(), record, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing scope err=%v", err)
	}
	_, resources, err := journal.LifecycleResources(t.Context())
	if err != nil || len(resources) != 1 || len(resources[0].Streams) != 0 {
		t.Fatalf("partial allocation resources=%+v err=%v", resources, err)
	}
}

// Provisioned key sizes are immutable and release their unused reservation
// before the next database admission enters the shared authority journal.
func provisionAllocationKeys(t *testing.T, journal *MemoryJournal, record Record) {
	t.Helper()
	current, found, err := journal.Load(t.Context(), ScopeKey(record.Request))
	if err != nil || !found {
		t.Fatalf("load record: %v", err)
	}
	current.Wrapped = journalWrapped(current)
	current.State = "keys_provisioned"
	if _, err := journal.Save(t.Context(), ScopeKey(current.Request), current.Revision, current); err != nil {
		t.Fatal(err)
	}
}

func allocationSuccessor(t *testing.T, first Record, now time.Time) Record {
	t.Helper()
	second := first
	second.Targets = slices.Clone(first.Targets)
	second.PlacementTargets = slices.Clone(first.PlacementTargets)
	second.Request.Name = "example-two"
	second.Request.OperationID = "create-example-two"
	second.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	second.KeyVersion = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
	second.CreatedAt = now.Add(-30 * time.Minute)
	second.Revision = 0
	stage := new(pb.PlacementStageRequest)
	if err := proto.Unmarshal(first.PlacementTargets[0].Proposal, stage); err != nil {
		t.Fatal(err)
	}
	stage.Proposal.Epoch = 2
	stage.Proposal.Generation = 2
	stage.Declarations = append(stage.Declarations, &pb.PlacementDatabaseDeclaration{Tenant: second.Request.TenantID, Project: second.Request.ProjectID, Database: second.DatabaseID, SelectedRegions: slices.Clone(second.Request.Regions)})
	stage.Proposal.Assignments = append(stage.Proposal.Assignments, &pb.PlacementDatabaseAssignment{Tenant: second.Request.TenantID, Project: second.Request.ProjectID, Database: second.DatabaseID, Region: "GRU", WriterMember: stage.Proposal.Regions[0].Members[0], FollowerMember: stage.Proposal.Regions[0].Members[1]})
	encoded, err := proto.Marshal(stage)
	if err != nil {
		t.Fatal(err)
	}
	for i := range second.Targets {
		second.Targets[i].Proposal = encoded
		second.Targets[i].Provision.Binding.DatabaseID = second.DatabaseID
		second.Targets[i].Provision.Binding.KeyVersion = second.KeyVersion
	}
	for i := range second.PlacementTargets {
		second.PlacementTargets[i].Proposal = encoded
	}
	return second
}

func TestAllocatePlacementStreamsMergedSuccessorPreservesOldPartitions(t *testing.T) {
	journal, first, now := allocationFixture(t)
	const proof = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := journal.AllocatePlacementStreams(t.Context(), first, proof, now); err != nil {
		t.Fatal(err)
	}
	_, before, err := journal.LifecycleResources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	original := before[0].Streams[0]
	provisionAllocationKeys(t, journal, first)
	second := allocationSuccessor(t, first, now)
	if _, err := journal.Save(t.Context(), ScopeKey(second.Request), 0, second); err != nil {
		t.Fatal(err)
	}
	transition := now.Add(time.Minute)
	if err := journal.AllocatePlacementStreams(t.Context(), second, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", transition); err != nil {
		t.Fatal(err)
	}
	revision, after, err := journal.LifecycleResources(t.Context())
	if err != nil || len(after) != 2 {
		t.Fatalf("resources=%+v err=%v", after, err)
	}
	for _, resource := range after {
		count := 0
		for _, stream := range resource.Streams {
			if stream.Epoch == 1 {
				if resource.DatabaseID != first.DatabaseID || stream.Partition != original.Partition || !stream.StartedAt.Equal(original.StartedAt) || !stream.StoppedAt.Equal(transition) {
					t.Fatalf("history changed: %+v", stream)
				}
			} else if stream.Epoch == 2 && stream.StoppedAt.IsZero() {
				count++
				if resource.DatabaseID == first.DatabaseID && !stream.StartedAt.Equal(transition) {
					t.Fatal("successor gap")
				}
				if resource.DatabaseID == second.DatabaseID && !stream.StartedAt.Equal(second.CreatedAt) {
					t.Fatal("initial scope gap")
				}
			} else {
				t.Fatalf("unexpected stream: %+v", stream)
			}
		}
		if count != 1 {
			t.Fatal("missing successor stream")
		}
	}
	if err := journal.AllocatePlacementStreams(t.Context(), first, proof, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("historical retry: %v", err)
	}
	retryRevision, retry, err := journal.LifecycleResources(t.Context())
	if err != nil || retryRevision != revision || !reflect.DeepEqual(retry, after) {
		t.Fatal("historical retry mutated lifecycle")
	}
}

func TestAllocatePlacementStreamsRollsBackEarlierMergedScopeOnLaterConflict(t *testing.T) {
	journal, first, now := allocationFixture(t)
	if err := journal.AllocatePlacementStreams(t.Context(), first, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); err != nil {
		t.Fatal(err)
	}
	provisionAllocationKeys(t, journal, first)
	second := allocationSuccessor(t, first, now)
	if _, err := journal.Save(t.Context(), ScopeKey(second.Request), 0, second); err != nil {
		t.Fatal(err)
	}
	if err := journal.ApplyLifecycle(t.Context(), databaselifecycle.Event{
		OperationID: "later-epoch", Kind: "streams", Identity: admissionLifecycleEvent(second).Identity, At: now,
		Streams: []databaselifecycle.Stream{{Region: "GRU", Partition: "01ARZ3NDEKTSV4RRFFQ69G5FB4", Epoch: 3, StartedAt: second.CreatedAt}},
	}); err != nil {
		t.Fatal(err)
	}
	before, err := journal.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AllocatePlacementStreams(t.Context(), second, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict=%v", err)
	}
	after, err := journal.snapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("earlier scope survived rolled-back batch")
	}
}
