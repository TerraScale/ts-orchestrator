package databaseadmission

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

const scopeProof = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func rewriteAllocationProposal(t *testing.T, record *Record, mutate func(*pb.PlacementProposal)) {
	t.Helper()
	for i := range record.PlacementTargets {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(record.PlacementTargets[i].Proposal, stage); err != nil {
			t.Fatal(err)
		}
		mutate(stage.Proposal)
		encoded, err := proto.Marshal(stage)
		if err != nil {
			t.Fatal(err)
		}
		record.PlacementTargets[i].Proposal = encoded
		record.Targets[i].Proposal = encoded
	}
}

func lifecycleResourceSnapshot(t *testing.T, journal *MemoryJournal) []databaselifecycle.Resource {
	t.Helper()
	_, resources, err := journal.LifecycleResources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func TestAllocatePlacementStreamsRejectsCrossScopeAndStaleOrDeletedState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*pb.PlacementProposal)
	}{
		{name: "wrong tenant", mutate: func(proposal *pb.PlacementProposal) {
			proposal.Assignments[0].Tenant = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
		}},
		{name: "wrong project", mutate: func(proposal *pb.PlacementProposal) {
			proposal.Assignments[0].Project = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
		}},
		{name: "wrong region", mutate: func(proposal *pb.PlacementProposal) {
			proposal.Assignments[0].Region = "SFO"
		}},
		{name: "missing database", mutate: func(proposal *pb.PlacementProposal) {
			proposal.Assignments[0].Database = "01ARZ3NDEKTSV4RRFFQ69G5FC0"
		}},
		{name: "stale accepted epoch", mutate: func(proposal *pb.PlacementProposal) {
			proposal.Epoch = 0
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			journal, record, now := allocationFixture(t)
			before := lifecycleResourceSnapshot(t, journal)
			rewriteAllocationProposal(t, &record, tc.mutate)
			err := journal.AllocatePlacementStreams(t.Context(), record, scopeProof, now)
			if err == nil {
				t.Fatalf("scope mutation error=%v", err)
			}
			after := lifecycleResourceSnapshot(t, journal)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected allocation changed lifecycle: before=%+v after=%+v", before, after)
			}
		})
	}

	t.Run("deleted", func(t *testing.T) {
		journal, record, now := allocationFixture(t)
		if err := journal.AllocatePlacementStreams(t.Context(), record, scopeProof, now); err != nil {
			t.Fatal(err)
		}
		before := lifecycleResourceSnapshot(t, journal)
		identity := before[0].Identity
		if err := journal.lifecycleTransact(t.Context(), func(state *journalState) error {
			resource := state.Lifecycle.Resources[databaselifecycle.Key(identity)]
			resource.DeletedAt = now
			resource.UsageStoppedAt = now
			resource.AccessRevoked = true
			state.Lifecycle.Resources[databaselifecycle.Key(identity)] = resource
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		before = lifecycleResourceSnapshot(t, journal)
		if err := journal.AllocatePlacementStreams(t.Context(), record, strings.Repeat("b", 64), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		after := lifecycleResourceSnapshot(t, journal)
		if !reflect.DeepEqual(before, after[:1]) {
			t.Fatalf("deleted allocation changed lifecycle: before=%+v after=%+v", before, after)
		}
	})
}

func TestNATSLifecycleReopenKeepsSameMemberDatabasesSeparate(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	putAdmissionLease(t, ctx, store, admissionLease(1, "global-controller-gru-one"))
	journal := newAdmissionJournalClient(t, connection, 1, "global-controller-gru-one")
	_, first, now := allocationFixture(t)
	key := ScopeKey(first.Request)
	if _, err := journal.Save(ctx, key, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := journal.AllocatePlacementStreams(ctx, first, scopeProof, now); err != nil {
		t.Fatal(err)
	}
	second := allocationSuccessor(t, first, now)
	first.State = "keys_provisioned"
	first.Wrapped = journalWrapped(first)
	first.Revision = 1
	if _, err := journal.Save(ctx, key, 1, first); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Save(ctx, ScopeKey(second.Request), 0, second); err != nil {
		t.Fatal(err)
	}

	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, ctx, connection, false)
	putAdmissionLease(t, ctx, store, admissionLease(2, "global-controller-gru-two"))
	reopened := newAdmissionJournalClient(t, connection, 2, "global-controller-gru-two")
	if err := reopened.AllocatePlacementStreams(ctx, second, strings.Repeat("b", 64), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, resources, err := reopened.LifecycleResources(ctx)
	if err != nil || len(resources) != 2 {
		t.Fatalf("reopened resources=%+v err=%v", resources, err)
	}
	seen := map[string]bool{}
	for _, resource := range resources {
		if len(resource.Streams) == 0 || !slices.Contains([]string{first.DatabaseID, second.DatabaseID}, resource.DatabaseID) {
			t.Fatalf("database lifecycle scope merged or missing: %+v", resource)
		}
		seen[resource.DatabaseID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("database lifecycle scopes=%v", seen)
	}
}
