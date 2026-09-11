package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/byokstatus"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestPublishProductionBYOKStatusUsesAdmissionTimestampAndFailsClosed(t *testing.T) {
	created := time.Date(2026, 9, 9, 12, 0, 0, 123000000, time.UTC)
	updatedAt := created.Format("2006-01-02T15:04:05.000Z")
	record := databaseadmission.Record{CreatedAt: created, Request: databaseadmission.Request{ProjectID: "project"}, BYOK: &databaseadmission.BYOKReference{ConfigurationUpdatedAt: updatedAt}}
	if err := publishProductionBYOKStatus(t.Context(), record, "verified", nil); !errors.Is(err, databaseadmission.ErrForbidden) {
		t.Fatalf("missing status publisher error = %v", err)
	}
	var got byokstatus.Update
	if err := publishProductionBYOKStatus(t.Context(), record, "verified", func(_ context.Context, update byokstatus.Update) error { got = update; return nil }); err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != "project" || got.Status != "verified" || got.ConfigurationUpdatedAt != updatedAt {
		t.Fatalf("unexpected status update: %#v", got)
	}
}

func TestInstallProductionBYOKWithholdsVerifiedUntilEveryTargetInstalled(t *testing.T) {
	byok := &databaseadmission.BYOKReference{ConfigurationUpdatedAt: "2026-09-09T00:00:00.000Z"}
	record := databaseadmission.Record{Request: databaseadmission.Request{ProjectID: "project", OperationID: "create-one"}, BYOK: byok, Targets: []databaseadmission.Target{{ServerIdentity: "member-a"}, {ServerIdentity: "member-b"}}}
	var statuses []string
	publish := func(_ context.Context, r databaseadmission.Record, status string) error {
		statuses = append(statuses, r.Request.OperationID+":"+status)
		return nil
	}
	install := func(context.Context, databaseadmission.Record, databaseadmission.Target, []keylease.Entry) error {
		return nil
	}
	// The first member's durable install must withhold the project-level
	// verified publication while the second member is still pending.
	if err := installProductionBYOK(t.Context(), record, record.Targets[0], nil, install, publish); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 0 {
		t.Fatalf("verified published before every target installed: %v", statuses)
	}
	// The caller journals the first member's install receipt before the
	// second member installs; the last durable install publishes once.
	durablyInstalled := record
	durablyInstalled.Targets[0].Installed = true
	if err := installProductionBYOK(t.Context(), durablyInstalled, durablyInstalled.Targets[1], nil, install, publish); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(statuses, []string{"create-one:verified"}) {
		t.Fatalf("final install publications = %v", statuses)
	}
}

func TestInstallProductionBYOKDoesNotPoisonProjectOnLostResponse(t *testing.T) {
	byok := &databaseadmission.BYOKReference{ConfigurationUpdatedAt: "2026-09-09T00:00:00.000Z"}
	record := databaseadmission.Record{Request: databaseadmission.Request{ProjectID: "project", OperationID: "create-one"}, BYOK: byok, Targets: []databaseadmission.Target{{ServerIdentity: "member-one"}}}
	target := record.Targets[0]
	transient := errors.New("lost host response")
	installs := 0
	statuses := []string{}
	install := func(context.Context, databaseadmission.Record, databaseadmission.Target, []keylease.Entry) error {
		installs++
		if installs == 1 {
			return transient
		}
		return nil
	}
	publish := func(_ context.Context, r databaseadmission.Record, status string) error {
		statuses = append(statuses, r.Request.OperationID+":"+status+":"+r.BYOK.ConfigurationUpdatedAt)
		return nil
	}
	if err := installProductionBYOK(t.Context(), record, target, nil, install, publish); !errors.Is(err, transient) {
		t.Fatalf("lost install error = %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("transient install published project status: %v", statuses)
	}
	if err := installProductionBYOK(t.Context(), record, target, nil, install, publish); err != nil {
		t.Fatal(err)
	}
	other := record
	other.Request.OperationID = "create-two"
	if err := installProductionBYOK(t.Context(), other, target, nil, func(context.Context, databaseadmission.Record, databaseadmission.Target, []keylease.Entry) error {
		return nil
	}, publish); err != nil {
		t.Fatal(err)
	}
	if got, want := statuses, []string{"create-one:verified:2026-09-09T00:00:00.000Z", "create-two:verified:2026-09-09T00:00:00.000Z"}; !slices.Equal(got, want) {
		t.Fatalf("status publications = %v, want %v", got, want)
	}
}

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
	config := productionDatabaseConfig{Environment: "production", Cluster: cluster, Regions: []productionDatabaseRegion{{Region: "GRU", Writer: productionDatabaseHost{ServerIdentity: identity(member2), MemberID: member2}, Follower: productionDatabaseHost{ServerIdentity: identity(member1), MemberID: member1}, Vault: keylease.ProvisionTarget{LeaseSeconds: 60, NotAfter: time.Now().Add(time.Hour)}}}}
	record := databaseadmission.Record{Request: databaseadmission.Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAD", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAE", Name: "orders", OperationID: "create-orders", Regions: []string{"GRU"}}, DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAF", KeyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FAG", State: "accepted"}
	return config, record
}
func TestDatabasePlanRetainsExplicitRolesAndImmutableScope(t *testing.T) {
	config, record := databasePlanFixture()
	plan, err := config.plan(t.Context(), record, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	targets := plan.Members
	record.Targets = targets
	record.PlacementTargets = plan.Placements
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
	if len(stage.Declarations) != 1 || stage.Declarations[0].Tenant != record.Request.TenantID || stage.Declarations[0].Project != record.Request.ProjectID || stage.Declarations[0].Database != record.DatabaseID || !slices.Equal(stage.Declarations[0].SelectedRegions, []string{"GRU"}) {
		t.Fatalf("database declaration missing or changed: %+v", stage.Declarations)
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

func TestDatabasePlanUsesCustomerProviderForAllPurposeKeys(t *testing.T) {
	config, record := databasePlanFixture()
	record.BYOK = &databaseadmission.BYOKReference{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test", ConfigurationUpdatedAt: "2026-09-09T12:00:00.000Z"}
	record.Request.BYOK = record.BYOK
	plan, err := config.plan(t.Context(), record, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range plan.Members {
		if target.Provision.Provider != "aws-kms" || target.Provision.KeyID != record.BYOK.KeyID || target.Provision.CryptoEndpoint != "" || target.Provision.KEKID != "" || target.Provision.KEKVersionID != "" {
			t.Fatalf("customer provider tuple not selected: %+v", target.Provision)
		}
		// The admission operation and the complete BYOK metadata copy are
		// the renewal-fence inputs; dropping any field silently unfences
		// the lease path.
		if target.Provision.AdmissionOperationID != record.Request.OperationID {
			t.Fatalf("admission operation not stamped: %+v", target.Provision)
		}
		if target.Provision.BYOK == nil || *target.Provision.BYOK != (keylease.BYOKMetadata{BackupEndpoint: record.BYOK.BackupEndpoint, BackupBucket: record.BYOK.BackupBucket, BackupRegion: record.BYOK.BackupRegion, BackupRoleARN: record.BYOK.BackupRoleARN, KeyProvider: record.BYOK.KeyProvider, KeyID: record.BYOK.KeyID, KeyRegion: record.BYOK.KeyRegion, KeyEndpoint: record.BYOK.KeyEndpoint, ConfigurationUpdatedAt: record.BYOK.ConfigurationUpdatedAt}) {
			t.Fatalf("BYOK metadata not copied verbatim: %+v", target.Provision.BYOK)
		}
	}
}
func TestDatabasePlanWaitsForReceiptAndPreservesAssignments(t *testing.T) {
	config, record := databasePlanFixture()
	journal := &databasePlanJournal{}
	placements := databasePlacementJournal{}
	plan, err := config.plan(t.Context(), record, journal, placements)
	if err != nil {
		t.Fatal(err)
	}
	targets := plan.Members
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
	record.State = "ready"
	journal.records = []databaseadmission.Record{record}
	planned, err := config.plan(t.Context(), next, journal, placements)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range planned.Placements {
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
				ActivatePlacement: func(context.Context, databaseadmission.Record) error { return errors.New("activation must not run") },
				Journal:           journal, CatalogPath: "/unopened/catalog.json", CheckAuthority: func(context.Context) error { return nil },
				Authorize: func(context.Context, databaseadmission.Request) error { return nil },
				Plan: func(context.Context, databaseadmission.Record) (databaseadmission.Plan, error) {
					return databaseadmission.Plan{}, nil
				},
				Install: func(context.Context, databaseadmission.Record, databaseadmission.Target, []keylease.Entry) error {
					return nil
				},
				AcceptPlacement: func(_ context.Context, _ string, _ string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
					return &pb.PlacementProposalResponse{Revision: 1, Proposal: request.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			runtime := &productionDatabase{pipeline: pipeline, deletion: &databaseadmission.DeletionWorkflow{Journal: databaseadmission.NewMemoryJournal(), Stopper: unexpectedDeletionStopper{}}, check: func(context.Context) error { return tt.authority }}
			err = runtime.Reconcile(t.Context())
			if !errors.Is(err, tt.errorWant) {
				t.Fatalf("got %v, want %v", err, tt.errorWant)
			}
		})
	}
}

type unexpectedDeletionStopper struct{}

func (unexpectedDeletionStopper) StopDeletion(context.Context, databaseadmission.DeletionStop) (databaseadmission.DeletionReceipt, error) {
	return databaseadmission.DeletionReceipt{}, errors.New("unexpected deletion stop")
}

func (unexpectedDeletionStopper) PrepareDeletion(context.Context, databaseadmission.DeletionStop) (databaseadmission.DeletionPreparation, error) {
	return databaseadmission.DeletionPreparation{}, errors.New("unexpected deletion prepare")
}

func TestDatabasePlanAdvancesAllClusterMembersWithoutResidencyLeak(t *testing.T) {
	config, record := databasePlanFixture()
	for i, region := range []string{"SFO", "FRA"} {
		writer := "01ARZ3NDEKTSV4RRFFQ69G5FA" + string(rune('J'+i*2))
		follower := "01ARZ3NDEKTSV4RRFFQ69G5FA" + string(rune('K'+i*2))
		identity := func(member string) string {
			return "spiffe://terrascale.tech/production/terrabase-member/" + config.Cluster + "/" + member
		}
		config.Regions = append(config.Regions, productionDatabaseRegion{Region: region, Writer: productionDatabaseHost{ServerIdentity: identity(writer), MemberID: writer}, Follower: productionDatabaseHost{ServerIdentity: identity(follower), MemberID: follower}, Vault: config.Regions[0].Vault})
	}
	// Use valid canonical Crockford ULIDs (L is not an allowed digit).
	config.Regions[2].Writer.MemberID = "01ARZ3NDEKTSV4RRFFQ69G5FAN"
	config.Regions[2].Follower.MemberID = "01ARZ3NDEKTSV4RRFFQ69G5FAP"
	for _, host := range []*productionDatabaseHost{&config.Regions[2].Writer, &config.Regions[2].Follower} {
		host.ServerIdentity = "spiffe://terrascale.tech/production/terrabase-member/" + config.Cluster + "/" + host.MemberID
	}
	record.Request.Residency = "br-only"
	plan, err := config.plan(t.Context(), record, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Members) != 2 || len(plan.Placements) != 6 {
		t.Fatalf("member/placement targets: %d/%d", len(plan.Members), len(plan.Placements))
	}
	record.Targets, record.PlacementTargets = plan.Members, plan.Placements
	if err := databaseadmission.ValidateRecord(record); err != nil {
		t.Fatal(err)
	}
	for _, target := range plan.Members {
		if target.Region != "GRU" {
			t.Fatal("customer key outside residency")
		}
	}
	for _, target := range plan.Placements {
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(target.Proposal, stage); err != nil {
			t.Fatal(err)
		}
		if len(stage.Proposal.Regions) != 3 || len(stage.Proposal.Assignments) != 1 || stage.Proposal.Assignments[0].Region != "GRU" {
			t.Fatal("placement dropped cluster members or leaked database assignment")
		}
		if len(stage.Declarations) != 1 || !slices.Equal(stage.Declarations[0].SelectedRegions, []string{"GRU"}) {
			t.Fatalf("remote placement declaration leaked storage residency: %+v", stage.Declarations)
		}
	}
	record.PlacementTargets = record.PlacementTargets[:5]
	if err := databaseadmission.ValidateRecord(record); err == nil {
		t.Fatal("incomplete epoch transition accepted")
	}
}

func TestDatabasePlanCarriesCanonicalDeclarationsForPriorAndCurrentScopes(t *testing.T) {
	config, current := databasePlanFixture()
	prior := current
	prior.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAH"
	prior.Request.Name = "invoices"
	prior.Request.OperationID = "create-invoices"
	prior.State = "ready"
	current.State = "accepted"
	j := &databasePlanJournal{records: []databaseadmission.Record{prior}}
	priorPlan, err := config.plan(t.Context(), prior, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	placements := databasePlacementJournal{}
	for _, target := range priorPlan.Placements {
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
	plan, err := config.plan(t.Context(), current, j, placements)
	if err != nil {
		t.Fatal(err)
	}
	stage := new(pb.PlacementStageRequest)
	if err := proto.Unmarshal(plan.Placements[0].Proposal, stage); err != nil {
		t.Fatal(err)
	}
	if len(stage.Declarations) != 2 {
		t.Fatalf("declaration count = %d, want 2", len(stage.Declarations))
	}
	if stage.Declarations[0].Database != current.DatabaseID || stage.Declarations[1].Database != prior.DatabaseID {
		t.Fatalf("declarations are not canonical: %+v", stage.Declarations)
	}
	if !slices.Equal(stage.Declarations[0].SelectedRegions, []string{"GRU"}) || !slices.Equal(stage.Declarations[1].SelectedRegions, []string{"GRU"}) {
		t.Fatalf("declaration regions changed: %+v", stage.Declarations)
	}
	for _, target := range plan.Members {
		memberStage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(target.Proposal, memberStage); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(stage, memberStage) {
			t.Fatal("storage and placement stage declarations differ")
		}
	}
}

func TestDatabasePlanRejectsDatabaseOwnerCollision(t *testing.T) {
	config, current := databasePlanFixture()
	prior := current
	prior.State = "ready"
	prior.Request.TenantID = "01ARZ3NDEKTSV4RRFFQ69G5FAH"
	if _, err := config.plan(t.Context(), current, &databasePlanJournal{records: []databaseadmission.Record{prior}}, databasePlacementJournal{}); !errors.Is(err, databaseadmission.ErrConflict) {
		t.Fatalf("owner collision error = %v", err)
	}
}

func TestDatabasePlanRejectsMissingPriorAssignment(t *testing.T) {
	config, current := databasePlanFixture()
	prior := current
	prior.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAH"
	prior.Request.Name = "invoices"
	prior.State = "ready"
	if _, err := config.plan(t.Context(), current, &databasePlanJournal{records: []databaseadmission.Record{prior}}, databasePlacementJournal{}); !errors.Is(err, databaseadmission.ErrConflict) {
		t.Fatalf("missing prior assignment error = %v", err)
	}
}

func TestDatabasePlanRejectsConflictingResidencyDeclaration(t *testing.T) {
	config, current := databasePlanFixture()
	prior := current
	prior.State = "ready"
	prior.Request.Regions = []string{"SFO"}
	if _, err := config.plan(t.Context(), current, &databasePlanJournal{records: []databaseadmission.Record{prior}}, databasePlacementJournal{}); !errors.Is(err, databaseadmission.ErrConflict) {
		t.Fatalf("residency conflict error = %v", err)
	}
}
