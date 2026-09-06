package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func usagePlanFixture(t *testing.T) (databaseadmission.Record, []databaseadmission.Record, []databaselifecycle.Resource, time.Time) {
	t.Helper()
	env, cluster := "production", "01ARZ3NDEKTSV4RRFFQ69G5FAA"
	members := []string{"01ARZ3NDEKTSV4RRFFQ69G5FAB", "01ARZ3NDEKTSV4RRFFQ69G5FAC", "01ARZ3NDEKTSV4RRFFQ69G5FAD", "01ARZ3NDEKTSV4RRFFQ69G5FAE"}
	tenant, project := "01ARZ3NDEKTSV4RRFFQ69G5FAF", "01ARZ3NDEKTSV4RRFFQ69G5FAG"
	ids := []string{"01ARZ3NDEKTSV4RRFFQ69G5FAH", "01ARZ3NDEKTSV4RRFFQ69G5FAJ"}
	now := time.Now().UTC().Truncate(time.Millisecond)
	proposal := &pb.PlacementProposal{Environment: env, Cluster: cluster, Generation: 2, Epoch: 7, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: members[:2]}, {Region: "FRA", Members: members[2:]}}, Assignments: []*pb.PlacementDatabaseAssignment{}}
	declarations := []*pb.PlacementDatabaseDeclaration{}
	records := make([]databaseadmission.Record, 0, len(ids))
	resources := make([]databaselifecycle.Resource, 0, len(ids))
	for i, id := range ids {
		request := databaseadmission.Request{Environment: env, TenantID: tenant, ProjectID: project, Name: []string{"orders", "invoices"}[i], OperationID: "create-" + []string{"orders", "invoices"}[i], Regions: []string{"GRU", "FRA"}, Residency: ""}
		proposal.Assignments = append(proposal.Assignments, &pb.PlacementDatabaseAssignment{Tenant: tenant, Project: project, Database: id, Region: "GRU", WriterMember: members[0], FollowerMember: members[1]}, &pb.PlacementDatabaseAssignment{Tenant: tenant, Project: project, Database: id, Region: "FRA", WriterMember: members[2], FollowerMember: members[3]})
		declarations = append(declarations, &pb.PlacementDatabaseDeclaration{Tenant: tenant, Project: project, Database: id, SelectedRegions: []string{"FRA", "GRU"}})
		records = append(records, databaseadmission.Record{Request: request, DatabaseID: id, CreatedAt: now.Add(-time.Minute)})
		resources = append(resources, databaselifecycle.Resource{Identity: databaselifecycle.Identity{Environment: env, OrganizationID: tenant, ProjectID: project, DatabaseID: id}, Regions: []string{"FRA", "GRU"}, CreatedAt: now.Add(-time.Minute), RoutingComplete: true, Streams: []databaselifecycle.Stream{{Region: "GRU", Partition: "p-" + id, Epoch: 7, StartedAt: now.Add(-time.Second)}, {Region: "FRA", Partition: "p-" + id, Epoch: 7, StartedAt: now.Add(-time.Second)}}})
	}
	stageBytes, err := proto.Marshal(&pb.PlacementControlServiceStageRequest{Proposal: proposal, Declarations: declarations})
	if err != nil {
		t.Fatal(err)
	}
	current := records[1]
	for _, member := range members {
		region := "FRA"
		if member == members[0] || member == members[1] {
			region = "GRU"
		}
		current.PlacementTargets = append(current.PlacementTargets, databaseadmission.PlacementTarget{ServerIdentity: "spiffe://terrascale.tech/" + env + "/terrabase-member/" + cluster + "/" + member, MemberID: member, Region: region, Proposal: stageBytes})
	}
	return current, records, resources, now
}

func TestPlanDatabaseUsageCoversAllAssignmentsAndSeats(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	deliveries, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 8 {
		t.Fatalf("deliveries = %d, want 8", len(deliveries))
	}
	first := deliveries[0].Registration
	retry, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now)
	if err != nil || len(retry) != len(deliveries) || retry[0].Registration.OperationID != first.OperationID {
		t.Fatalf("unstable retry plan: %v", err)
	}
}

func TestPlanDatabaseUsageRejectsStreamAndProposalChanges(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	resources[0].Streams[0].Epoch = 6
	if _, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("accepted stream epoch mismatch")
	}
	record, records, resources, now = usagePlanFixture(t)
	stage := new(pb.PlacementControlServiceStageRequest)
	if err := proto.Unmarshal(record.PlacementTargets[0].Proposal, stage); err != nil {
		t.Fatal(err)
	}
	stage.Proposal.Generation = 9
	changed, err := proto.Marshal(stage)
	if err != nil {
		t.Fatal(err)
	}
	record.PlacementTargets[0].Proposal = changed
	if _, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("accepted changed proposal")
	}
}

func TestPlanDatabaseUsageAcceptsHostLocalRevisionDifferences(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	for i := range record.PlacementTargets {
		stage := new(pb.PlacementControlServiceStageRequest)
		if err := proto.Unmarshal(record.PlacementTargets[i].Proposal, stage); err != nil {
			t.Fatal(err)
		}
		stage.ExpectedRevision = uint64(i + 1)
		record.PlacementTargets[i].Proposal, _ = proto.Marshal(stage)
	}
	if deliveries, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err != nil || len(deliveries) != 8 {
		t.Fatalf("host-local revisions changed plan: %v", err)
	}
}

func TestPlanDatabaseUsageRejectsInvalidStreams(t *testing.T) {
	cases := map[string]func(*databaselifecycle.Resource, time.Time){
		"missing": func(resource *databaselifecycle.Resource, _ time.Time) { resource.Streams = resource.Streams[:1] },
		"stopped": func(resource *databaselifecycle.Resource, now time.Time) {
			resource.Streams[0].StoppedAt = now.Add(-time.Second)
		},
		"ambiguous": func(resource *databaselifecycle.Resource, now time.Time) {
			resource.Streams = append(resource.Streams, databaselifecycle.Stream{Region: "GRU", Partition: "other", Epoch: 7, StartedAt: now.Add(-time.Second)})
		},
		"future": func(resource *databaselifecycle.Resource, now time.Time) {
			resource.Streams[0].StartedAt = now.Add(time.Second)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			record, records, resources, now := usagePlanFixture(t)
			mutate(&resources[1], now)
			if _, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err == nil {
				t.Fatal("accepted invalid stream inventory")
			}
		})
	}
	record, records, resources, now := usagePlanFixture(t)
	resources[1].ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAT"
	if _, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("accepted parent identity mismatch")
	}
}

type usageSourceFixture struct {
	records          []databaseadmission.Record
	resources        []databaselifecycle.Resource
	revision         uint64
	reads            int
	changeAfterFirst bool
}

func (s *usageSourceFixture) List(context.Context) ([]databaseadmission.Record, error) {
	return s.records, nil
}
func (s *usageSourceFixture) LifecycleResources(context.Context) (uint64, []databaselifecycle.Resource, error) {
	s.reads++
	if s.changeAfterFirst && s.reads > 2 {
		return s.revision + 1, s.resources, nil
	}
	return s.revision, s.resources, nil
}

func TestDeliverDatabaseUsageGuardsEffects(t *testing.T) {
	record, records, resources, _ := usagePlanFixture(t)
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		check     func(*usageSourceFixture) func(context.Context) error
		mutate    func(*usageSourceFixture)
		sendErr   error
		wantSends int
	}{
		{name: "authority loss", check: func(*usageSourceFixture) func(context.Context) error {
			calls := 0
			return func(context.Context) error {
				calls++
				if calls > 2 {
					return errors.New("lost")
				}
				return nil
			}
		}, wantSends: 1},
		{name: "revision change", check: func(*usageSourceFixture) func(context.Context) error {
			return func(context.Context) error { return nil }
		}, mutate: func(s *usageSourceFixture) { s.changeAfterFirst = true }, wantSends: 1},
		{name: "sender failure", check: func(*usageSourceFixture) func(context.Context) error {
			return func(context.Context) error { return nil }
		}, sendErr: errors.New("send failed"), wantSends: 1},
		{name: "invalid plan", check: func(*usageSourceFixture) func(context.Context) error {
			return func(context.Context) error { return nil }
		}, mutate: func(s *usageSourceFixture) { s.resources[1].Streams[0].Epoch = 6 }, wantSends: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := &usageSourceFixture{records: records, resources: resources, revision: 1}
			if tc.mutate != nil {
				tc.mutate(source)
			}
			sends := 0
			err := deliverDatabaseUsage(t.Context(), source, tc.check(source), func(context.Context, databaseadmission.Target, databaseadmission.UsageRegistration) error {
				sends++
				return tc.sendErr
			}, record, digest)
			if err == nil {
				t.Fatal("effect delivery succeeded")
			}
			if sends != tc.wantSends {
				t.Fatalf("sends = %d, want %d", sends, tc.wantSends)
			}
		})
	}
}

func TestPlanDatabaseUsageSkipsRetainedDeletedScope(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	deletedAt := now.Add(-time.Second)
	resources[0].DeletedAt = deletedAt
	resources[0].UsageStoppedAt = deletedAt
	resources[0].AccessRevoked = true
	deliveries, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 4 {
		t.Fatalf("deliveries = %d, want only live scope's two seats in two Regions", len(deliveries))
	}
	for _, delivery := range deliveries {
		if delivery.Registration.DatabaseID == records[0].DatabaseID {
			t.Fatal("deleted retained scope received usage registration")
		}
	}
}

func TestPlanDatabaseUsageAllowsUnrelatedAdmissionRecord(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	unrelated := records[0]
	unrelated.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAK"
	unrelated.Request.Name = "unrelated"
	unrelated.Request.OperationID = "create-unrelated"
	records = append(records, unrelated)
	if deliveries, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err != nil || len(deliveries) != 8 {
		t.Fatalf("unrelated record blocked plan: %v", err)
	}
}

func TestPlanDatabaseUsageAllowsUnroutedDeletedScope(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	deletedAt := now.Add(-time.Second)
	resources[0].DeletedAt, resources[0].UsageStoppedAt, resources[0].AccessRevoked = deletedAt, deletedAt, true
	resources[0].RoutingComplete = false
	if deliveries, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err != nil || len(deliveries) != 4 {
		t.Fatalf("unrouted deleted scope blocked plan: %v", err)
	}
}

func TestPlanDatabaseUsageRejectsForeignTarget(t *testing.T) {
	record, records, resources, now := usagePlanFixture(t)
	record.PlacementTargets[0].ServerIdentity = "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAK/01ARZ3NDEKTSV4RRFFQ69G5FAB"
	if _, err := planDatabaseUsage(record, records, resources, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("accepted foreign target identity")
	}
}
