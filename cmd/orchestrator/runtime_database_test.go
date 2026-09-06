package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type databasePlanJournal struct {
	records []databaseadmission.Record
	failure error
}

func (j *databasePlanJournal) List(context.Context) ([]databaseadmission.Record, error) {
	return j.records, j.failure
}
func (j *databasePlanJournal) Load(context.Context, string) (databaseadmission.Record, bool, error) {
	return databaseadmission.Record{}, false, nil
}
func (j *databasePlanJournal) Save(context.Context, string, uint64, databaseadmission.Record) (uint64, error) {
	return 0, errors.New("not used")
}

type databasePlacementJournal map[string]placementpublisher.Record

func (j databasePlacementJournal) Load(_ context.Context, host string) (placementpublisher.Record, error) {
	r, ok := j[host]
	if !ok {
		return r, placementpublisher.ErrIntentMissing
	}
	return r, nil
}
func (j databasePlacementJournal) Accept(context.Context, placementpublisher.Record) error {
	return errors.New("not used")
}
func (j databasePlacementJournal) Acknowledge(context.Context, placementpublisher.Record, *pb.PlacementProposalResponse) error {
	return errors.New("not used")
}
func databasePlanFixture() (productionDatabaseConfig, databaseadmission.Record) {
	cluster := "01ARZ3NDEKTSV4RRFFQ69G5FAA"
	member1, member2 := "01ARZ3NDEKTSV4RRFFQ69G5FAB", "01ARZ3NDEKTSV4RRFFQ69G5FAC"
	identity := func(member string) string {
		return "spiffe://terrascale.tech/production/terrabase-member/" + cluster + "/" + member
	}
	config := productionDatabaseConfig{Environment: "production", Cluster: cluster, Regions: []productionDatabaseRegion{{Region: "GRU", Writer: productionDatabaseHost{identity(member2), member2}, Follower: productionDatabaseHost{identity(member1), member1}, Vault: keylease.ProvisionTarget{LeaseSeconds: 60, NotAfter: time.Now().Add(time.Hour)}}}}
	record := databaseadmission.Record{Request: databaseadmission.Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAD", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAE", Name: "orders", OperationID: "create-orders", Regions: []string{"GRU"}}, DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAF", KeyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FAG", State: "accepted"}
	return config, record
}
func TestDatabasePlanRetainsExplicitRolesAndImmutableScope(t *testing.T) {
	config, record := databasePlanFixture()
	targets, err := config.plan(t.Context(), record, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	record.Targets = targets
	if err := databaseadmission.ValidateRecord(record); err != nil {
		t.Fatal(err)
	}
	stage := new(pb.PlacementStageRequest)
	if err := proto.Unmarshal(targets[0].Proposal, stage); err != nil {
		t.Fatal(err)
	}
	if stage.Proposal.Assignments[0].WriterMember != config.Regions[0].Writer.MemberID {
		t.Fatal("sorted seats changed writer role")
	}
	journal := &databasePlanJournal{records: []databaseadmission.Record{record}}
	if err := validateDatabaseProposal(t.Context(), journal, targets[0].ServerIdentity, databaseadmission.PlacementOperationID(record.Request), stage); err != nil {
		t.Fatal(err)
	}
	stage.Proposal.Assignments[0].Project = "01ARZ3NDEKTSV4RRFFQ69G5FAH"
	if err := validateDatabaseProposal(t.Context(), journal, targets[0].ServerIdentity, databaseadmission.PlacementOperationID(record.Request), stage); err == nil {
		t.Fatal("modified project accepted")
	}
}
func TestDatabasePlanWaitsForReceiptAndPreservesAssignments(t *testing.T) {
	config, record := databasePlanFixture()
	journal := &databasePlanJournal{}
	placements := databasePlacementJournal{}
	targets, err := config.plan(t.Context(), record, journal, placements)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		placements[target.ServerIdentity] = placementpublisher.Record{Request: target.Proposal}
	}
	next := record
	next.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAH"
	next.Request.Name = "invoices"
	next.Request.OperationID = "create-invoices"
	if _, err := config.plan(t.Context(), next, journal, placements); err == nil {
		t.Fatal("unresolved predecessor was replaced")
	}
	for _, target := range targets {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(target.Proposal, stage); err != nil {
			t.Fatal(err)
		}
		receipt, err := proto.Marshal(&pb.PlacementProposalResponse{Revision: 1, Proposal: stage.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING})
		if err != nil {
			t.Fatal(err)
		}
		placements[target.ServerIdentity] = placementpublisher.Record{Request: target.Proposal, Receipt: receipt}
	}
	planned, err := config.plan(t.Context(), next, journal, placements)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range planned {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(target.Proposal, stage); err != nil {
			t.Fatal(err)
		}
		if stage.ExpectedRevision != 1 || stage.Proposal.Generation != 2 || stage.Proposal.Epoch != 2 || len(stage.Proposal.Assignments) != 2 {
			t.Fatalf("lost predecessor or CAS metadata: %v", stage)
		}
	}
}

func TestDatabaseReconcileRetriesTransportButStopsFencedOrCorrupt(t *testing.T) {
	transport := errors.New("host disconnected")
	fenced := errors.New("authority fenced")
	for _, tt := range []struct {
		name                          string
		failure, authority, errorWant error
	}{
		{"transient", transport, nil, nil},
		{"fenced", transport, fenced, fenced},
		{"corrupt", databaseadmission.ErrInvalid, nil, databaseadmission.ErrInvalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			journal := &databasePlanJournal{failure: tt.failure}
			pipeline, err := databaseadmission.New(databaseadmission.Config{
				Journal: journal, CatalogPath: "/unopened/catalog.json", CheckAuthority: func(context.Context) error { return nil },
				Authorize: func(context.Context, databaseadmission.Request) error { return nil },
				Plan:      func(context.Context, databaseadmission.Record) ([]databaseadmission.Target, error) { return nil, nil },
				Install: func(context.Context, databaseadmission.Record, databaseadmission.Target, []keylease.Entry) error {
					return nil
				},
				AcceptPlacement: func(context.Context, string, string, *pb.PlacementStageRequest) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			runtime := &productionDatabase{pipeline: pipeline, check: func(context.Context) error { return tt.authority }}
			err = runtime.Reconcile(t.Context())
			if !errors.Is(err, tt.errorWant) {
				t.Fatalf("got %v, want %v", err, tt.errorWant)
			}
		})
	}
}
