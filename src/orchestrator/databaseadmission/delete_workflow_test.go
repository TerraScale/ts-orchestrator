package databaseadmission

import (
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"testing"
	"time"
)

func deletionFixture(t *testing.T) (journalState, DeleteRequest, time.Time) {
	t.Helper()
	s := newJournalState()
	at := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Hour)
	r := DeleteRequest{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", OperationID: "delete-one"}
	root := databaselifecycle.Identity{Environment: r.Environment, OrganizationID: r.TenantID, ProjectID: r.ProjectID, DatabaseID: r.DatabaseID}
	child := root
	child.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	child.ParentDatabaseID = root.DatabaseID
	for i, id := range []databaselifecycle.Identity{root, child} {
		kind := "create"
		if i > 0 {
			kind = "branch_create"
		}
		if err := databaselifecycle.Apply(&s.Lifecycle, databaselifecycle.Event{Identity: id, Kind: kind, OperationID: kind, At: at, Regions: []string{"GRU", "FRA"}, Streams: []databaselifecycle.Stream{{Region: "GRU", Partition: "p", Epoch: 1, StartedAt: at}, {Region: "FRA", Partition: "p", Epoch: 1, StartedAt: at}}}); err != nil {
			t.Fatal(err)
		}
	}
	return s, r, at.Add(time.Minute)
}
func TestDeletionRequiresEveryExactRegionalStop(t *testing.T) {
	s, r, cutoff := deletionFixture(t)
	d, err := beginDeletion(&s, r, cutoff, cutoff.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Targets) != 4 {
		t.Fatal("missing branch or region")
	}
	if !d.Cutoff.IsZero() || d.State != "preparing" {
		t.Fatal("cutoff selected before prepare")
	}
	for _, target := range d.Targets {
		var err error
		d, err = recordDeletionPreparation(&s, r, DeletionPreparation{Identity: target.Stop.Identity, OperationID: r.OperationID, Region: target.Stop.Region, Prepared: true, LastAccountedAt: cutoff}, cutoff)
		if err != nil {
			t.Fatal(err)
		}
	}
	retry, err := beginDeletion(&s, r, cutoff.Add(time.Minute), cutoff.Add(2*time.Hour))
	if err != nil || !retry.Cutoff.Equal(cutoff) {
		t.Fatal("retry changed cutoff", err)
	}
	if !deletionBlocksFreeze(&s, r.TenantID, cutoff.Add(time.Minute)) {
		t.Fatal("inventory not fenced")
	}
	if !deletionBlocksEvent(&s, databaselifecycle.Event{Identity: databaselifecycle.Identity{Environment: r.Environment, OrganizationID: r.TenantID, ParentDatabaseID: r.DatabaseID}}) {
		t.Fatal("new branch not fenced")
	}
	wrong := DeletionReceipt{DeletionStop: d.Targets[0].Stop, AccessRevoked: true, UsageStopped: true}
	wrong.Cutoff = wrong.Cutoff.Add(time.Millisecond)
	if _, err := recordDeletionStop(&s, r, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted wrong cutoff", err)
	}
	for i, target := range d.Targets {
		receipt := DeletionReceipt{DeletionStop: target.Stop, AccessRevoked: true, UsageStopped: true}
		result, err := recordDeletionStop(&s, r, receipt)
		if err != nil {
			t.Fatal(err)
		}
		if i < len(d.Targets)-1 && result.State != "stopping" {
			t.Fatal("premature completion")
		}
	}
	if s.Deletions[deletionKey(r)].State != "edge_pending" {
		t.Fatal("missing cleanup state")
	}
	for _, v := range s.Lifecycle.Resources {
		if !v.DeletedAt.Equal(cutoff) || !v.AccessRevoked || !v.EffectsCompletedAt.IsZero() {
			t.Fatal("invalid logical deletion", v)
		}
		for _, stream := range v.Streams {
			if !stream.StoppedAt.Equal(cutoff) {
				t.Fatal("usage not stopped at cutoff")
			}
		}
	}
	if _, err := recordDeletionEdge(&s, r, DeletionEdgeReceipt{Request: r, Cutoff: cutoff, AccessRevoked: true}); err != nil {
		t.Fatal(err)
	}
	if err := validateDeletions(s); err != nil {
		t.Fatal(err)
	}
}
func TestDeletionRejectsClosedCutoffAndScopeChange(t *testing.T) {
	s, r, cutoff := deletionFixture(t)
	if _, err := databaselifecycle.Freeze(&s.Lifecycle, r.TenantID, cutoff.Add(-time.Minute), cutoff.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := beginDeletion(&s, r, cutoff, cutoff.Add(time.Hour)); !errors.Is(err, databaselifecycle.ErrClosed) {
		t.Fatal(err)
	}
	s, r, cutoff = deletionFixture(t)
	if _, err := beginDeletion(&s, r, cutoff, cutoff.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	if _, err := beginDeletion(&s, r, cutoff, cutoff.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatal("operation rebound", err)
	}
}
