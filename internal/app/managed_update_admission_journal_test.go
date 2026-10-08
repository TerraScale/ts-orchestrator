package app

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// An idempotent Prepare replay journals the admission once, under an ID any
// controller can derive from the operation.
func TestManagedUpdateAdmissionIsJournaledOncePerOperation(t *testing.T) {
	journal := installTestJournal(t)
	intent := placement.ManagedUpdateIntent{OperationID: "0000000000FHW0KDCDCG304MTS", DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD",
		CanarySeatID: "000000000082AXF7GZQT1D126Y"}
	for range 3 {
		recordManagedUpdateAdmission(t.Context(), "lab", "operator", intent, 12)
	}
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindReleaseAdmitted}})
	if len(result.Decisions) != 1 || result.Decisions[0].ID != placement.ManagedUpdateAdmissionID("lab", intent.DatabaseID, intent.PartitionID, intent.OperationID) {
		t.Fatalf("admissions = %+v", result.Decisions)
	}
	if stats := journal.Stats(); stats.Recorded != 1 {
		t.Fatalf("recorded = %d, want 1", stats.Recorded)
	}
}
