package main

import (
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func TestDeferredProductionEstateSnapshotFailsClosedBeforeDatabaseAdmission(t *testing.T) {
	var database *productionDatabase
	source := deferredProductionEstateSnapshot(estate.Spec{}, "/missing-health.json", &database)
	_, err := source(t.Context())
	if err == nil || !strings.Contains(err.Error(), "admitted database journal is unavailable") {
		t.Fatalf("snapshot without admitted database = %v", err)
	}
}

func TestDeferredProductionEstateSnapshotRejectsMissingOwnerPointer(t *testing.T) {
	source := deferredProductionEstateSnapshot(estate.Spec{}, "/missing-health.json", nil)
	_, err := source(t.Context())
	if err == nil {
		t.Fatal("snapshot accepted missing owner pointer")
	}
}
