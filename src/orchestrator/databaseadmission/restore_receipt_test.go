package databaseadmission

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
)

func TestPersistedRestoreReceiptCannotBypassRecovery(t *testing.T) {
	for _, mutation := range []string{"valid", "malformed", "target", "facts"} {
		t.Run(mutation, func(t *testing.T) {
			journal := NewMemoryJournal()
			record := restoreSourceFixture(t, journal)
			facts := restoreFactsFixture()
			facts.Epoch = 1
			record.Request.ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
			record.Request.RecoveryPointID, record.Request.JournalCut, record.Request.RestoreEpoch, record.Request.RestoreProvider = facts.PointID, facts.JournalCut, facts.Epoch, facts.Provider
			request := restoreRequestFixture(record)
			request.SourceDatabaseID, request.Name, request.OperationID = record.Request.ParentDatabaseID, record.Request.Name, record.Request.OperationID
			record.Restore, record.RestoreFacts = &request, &facts
			ack := RestoreAcknowledgement{Version: 1, TargetDatabaseID: record.DatabaseID, SourceDatabaseID: record.Request.ParentDatabaseID, Facts: facts}
			raw, err := json.Marshal(ack)
			if err != nil {
				t.Fatal(err)
			}
			record.RestoreReceipt = raw
			if err := ValidateRecord(record); err != nil {
				t.Fatalf("baseline restore record: %v", err)
			}
			// Seed the immutable admitted identity; progress and lifecycle come from the ready fixture.
			key := ScopeKey(record.Request)
			journal.state.Records[key] = record
			for key, resource := range journal.state.Lifecycle.Resources {
				resource.Identity.ParentDatabaseID = record.Request.ParentDatabaseID
				journal.state.Lifecycle.Resources[key] = resource
			}
			for key, event := range journal.state.Lifecycle.Events {
				event.Identity.ParentDatabaseID = record.Request.ParentDatabaseID
				event.Kind = "branch_create"
				journal.state.Lifecycle.Events[key] = event
			}
			if err := validateJournalState(journal.state); err != nil {
				t.Fatalf("baseline journal: %v", err)
			}
			switch mutation {
			case "target":
				ack.TargetDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
			case "facts":
				ack.Facts.Checksum = strings.Repeat("e", 64)
			}
			raw, err = json.Marshal(ack)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "malformed" {
				raw = []byte(`{"version":`)
			}
			record.RestoreReceipt = raw
			_, err = journal.Save(t.Context(), key, record.Revision, record)
			if mutation == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("save accepted invalid receipt: %v", err)
			}
			// Decode persisted bytes and run the same state validator used by NATS recovery.
			state, err := cloneState(journal.state)
			if err != nil {
				t.Fatal(err)
			}
			state.Records[key] = record
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			var recovered journalState
			if err := json.Unmarshal(data, &recovered); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(validateJournalState(recovered), ErrInvalid) {
				t.Fatal("recovery accepted invalid receipt")
			}
			// Even a journal implementation returning the corrupted ready record cannot bypass validation.
			journal.state = recovered
			config := pipelineConfig(t, journal)
			pipeline, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(pipeline.Reconcile(t.Context()), ErrInvalid) {
				t.Fatal("ready replay skipped receipt validation")
			}
		})
	}
}
