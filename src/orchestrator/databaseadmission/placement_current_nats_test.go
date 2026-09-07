package databaseadmission

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNATSPlacementRelocationCompetesWithDeletion(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	const candidate = "global-controller-gru-one"
	putAdmissionLease(t, ctx, store, admissionLease(1, candidate))
	journal := newAdmissionJournalClient(t, connection, 1, candidate)
	record := journalFixture(t)
	var err error
	record.Revision, err = journal.Save(ctx, ScopeKey(record.Request), 0, record)
	if err != nil {
		t.Fatal(err)
	}
	record.State = "ready"
	record.Wrapped = journalWrapped(record)
	for i := range record.Targets {
		record.Targets[i].Installed = true
		record.PlacementTargets[i].Proposed = true
	}
	record.ReadinessNonce = strings.Repeat("e", 64)
	record.ReadyEvidence, _, _ = readinessFixture(t, record, record.ReadinessNonce)
	record.Revision, err = journal.Save(ctx, ScopeKey(record.Request), record.Revision, record)
	if err != nil {
		t.Fatal(err)
	}
	request := DeleteRequest{Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID, OperationID: "delete-race"}
	start := make(chan struct{})
	var relocationErr, deletionErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		relocationErr = journal.BeginPlacementRelocation(ctx, "relocate-race", []Record{record})
	})
	wg.Go(func() {
		<-start
		_, deletionErr = journal.BeginDeletion(ctx, request, time.Now().UTC().Truncate(time.Millisecond), time.Time{})
	})
	close(start)
	wg.Wait()
	if (relocationErr == nil) == (deletionErr == nil) {
		t.Fatalf("exactly one effect must win: relocation=%v deletion=%v", relocationErr, deletionErr)
	}
	for _, err := range []error{relocationErr, deletionErr} {
		if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrJournalConflict) {
			t.Fatal(err)
		}
	}
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, ctx, connection, false)
	putAdmissionLease(t, ctx, store, admissionLease(2, candidate))
	restarted := newAdmissionJournalClient(t, connection, 2, candidate)
	if relocationErr == nil {
		if _, err := restarted.BeginDeletion(ctx, request, time.Now().UTC().Truncate(time.Millisecond), time.Time{}); !errors.Is(err, ErrConflict) {
			t.Fatalf("restart lost relocation fence: %v", err)
		}
	} else if err := restarted.BeginPlacementRelocation(ctx, "relocate-race", []Record{record}); !errors.Is(err, ErrConflict) {
		t.Fatalf("restart lost deletion fence: %v", err)
	}
}
