package databaseadmission

import (
	"encoding/json/v2"
	"reflect"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"testing"
	"time"
)

func capacitySize(t *testing.T, state journalState) int {
	t.Helper()
	before, err := cloneState(state)
	if err != nil {
		t.Fatal(err)
	}
	reserved := state
	reserveLifecycleCapacity(&reserved)
	reserveDeletionCapacity(&reserved)
	data, err := json.Marshal(reserved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, state) {
		t.Fatal("capacity reservation mutated authority state")
	}
	return len(data)
}
func TestLifecycleTerminalCapacityReservedBeforeEffects(t *testing.T) {
	journal := NewMemoryJournal()
	record := journalFixture(t)
	record.CreatedAt = time.Now().UTC().Add(-time.Hour)
	if _, err := journal.Save(t.Context(), ScopeKey(record.Request), 0, record); err != nil {
		t.Fatal(err)
	}
	event := admissionLifecycleEvent(record)
	event.Kind = "streams"
	event.OperationID = "routing"
	event.Regions = nil
	event.Streams = []databaselifecycle.Stream{{Region: "GRU", Partition: "root", Epoch: 1, StartedAt: record.CreatedAt}}
	if err := journal.ApplyLifecycle(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	before, err := journal.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reservedBefore := capacitySize(t, before)
	request := DeleteRequest{Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID, OperationID: strings.Repeat("d", 128)}
	cutoff := time.Now().UTC()
	deletion, err := journal.BeginDeletion(t.Context(), request, cutoff, cutoff.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range deletion.Targets {
		preparedAt := deletion.RequestedAt.UTC().Truncate(time.Millisecond)
		deletion, err = journal.RecordDeletionPreparation(t.Context(), request, DeletionPreparation{Identity: target.Stop.Identity, OperationID: target.Stop.OperationID, Region: target.Stop.Region, Prepared: true, LastAccountedAt: preparedAt}, preparedAt)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range deletion.Targets {
		if _, err := journal.RecordDeletionStop(t.Context(), request, DeletionReceipt{DeletionStop: target.Stop, AccessRevoked: true, UsageStopped: true}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := journal.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if terminal := capacitySize(t, after); terminal > reservedBefore {
		t.Fatalf("terminal lifecycle exceeded reservation: before=%d after=%d", reservedBefore, terminal)
	}
}
