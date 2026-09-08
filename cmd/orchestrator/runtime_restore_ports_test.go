package main

import (
	"context"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

func TestProductionAdmissionDatabaseListerExcludesBranches(t *testing.T) {
	config, root := databasePlanFixture()
	rootPlan, err := config.plan(t.Context(), root, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	root.Targets, root.PlacementTargets = rootPlan.Members, rootPlan.Placements
	if err := databaseadmission.ValidateRecord(root); err != nil {
		t.Fatal(err)
	}

	branch := root
	branch.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	branch.KeyVersion = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	branch.Request.Name = "branch"
	branch.Request.OperationID = "create-branch"
	branch.Request.ParentDatabaseID = root.DatabaseID
	branch.Request.RecoveryPointID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	branch.Request.JournalCut = "1"
	branch.Request.RestoreEpoch = 1
	branch.Request.RestoreProvider = "oci"
	branchPlan, err := config.plan(t.Context(), branch, &databasePlanJournal{}, databasePlacementJournal{})
	if err != nil {
		t.Fatal(err)
	}
	branch.Targets, branch.PlacementTargets = branchPlan.Members, branchPlan.Placements
	if err := databaseadmission.ValidateRecord(branch); err != nil {
		t.Fatal(err)
	}

	journal := &databasePlanJournal{records: []databaseadmission.Record{root, branch}}
	listed, err := (productionAdmissionDatabaseLister{journal: journal}).ListDatabases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != root.DatabaseID {
		t.Fatalf("listed databases = %+v, want only root %s", listed, root.DatabaseID)
	}
}

var _ databaseadmission.Journal = (*databasePlanJournal)(nil)
var _ placementpublisher.Journal = (databasePlacementJournal)(nil)
