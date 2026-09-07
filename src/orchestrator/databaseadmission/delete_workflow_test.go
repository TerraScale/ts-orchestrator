package databaseadmission

import (
	"context"
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

type automaticDeletionStopper struct {
	prepare int
	stop    int
	retains []time.Time
}

func (s *automaticDeletionStopper) PrepareDeletion(_ context.Context, stop DeletionStop) (DeletionPreparation, error) {
	s.prepare++
	s.retains = append(s.retains, stop.RetainUntil)
	return DeletionPreparation{Identity: stop.Identity, OperationID: stop.OperationID, Region: stop.Region, Prepared: true, LastAccountedAt: time.Now().UTC().Truncate(time.Millisecond)}, nil
}
func (s *automaticDeletionStopper) StopDeletion(_ context.Context, stop DeletionStop) (DeletionReceipt, error) {
	s.stop++
	s.retains = append(s.retains, stop.RetainUntil)
	return DeletionReceipt{DeletionStop: stop, AccessRevoked: true, UsageStopped: true}, nil
}

type automaticDeletionEdge struct{}

func (automaticDeletionEdge) RevokeDeletion(_ context.Context, d Deletion) (DeletionEdgeReceipt, error) {
	return DeletionEdgeReceipt{Request: d.Request, Cutoff: d.Cutoff, AccessRevoked: true}, nil
}

func automaticWorkflowFixture(t *testing.T) (*MemoryJournal, AutomaticDeleteRequest, DeletionClaimReceipt) {
	t.Helper()
	s, request, _ := deletionFixture(t)
	journal := NewMemoryJournal()
	automatic := AutomaticDeleteRequest{DeleteRequest: request, PolicyRevision: "policy-v1", GraceCondition: "card-loss", Deadline: time.Now().UTC().Add(-time.Hour)}
	if _, err := beginAutomaticIntent(&s, automatic, time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	journal.state = s
	claim := DeletionClaimReceipt{SchemaVersion: 1, Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, DatabaseID: request.DatabaseID, OperationID: request.OperationID, PolicyRevision: automatic.PolicyRevision, PolicyFingerprint: "fingerprint", GraceCondition: automatic.GraceCondition, Deadline: automatic.Deadline, AcceptedAt: time.Now().UTC()}
	return journal, automatic, claim
}

func TestAutomaticIntentWithoutClaimIsInertOnResume(t *testing.T) {
	journal, _, _ := automaticWorkflowFixture(t)
	stopper := new(automaticDeletionStopper)
	workflow := &DeletionWorkflow{Journal: journal, Stopper: stopper, Edge: automaticDeletionEdge{}}
	err := workflow.Resume(t.Context())
	if stopper.prepare != 0 || stopper.stop != 0 {
		t.Fatalf("unclaimed intent caused effects: prepare=%d stop=%d err=%v", stopper.prepare, stopper.stop, err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticClaimAcceptedAfterDelayUsesZeroRetention(t *testing.T) {
	journal, automatic, claim := automaticWorkflowFixture(t)
	stopper := new(automaticDeletionStopper)
	workflow := &DeletionWorkflow{Journal: journal, Stopper: stopper, Edge: automaticDeletionEdge{}}
	// The claim arrives after the eligibility deadline and must still authorize
	// deletion without turning the deadline into a physical retention cutoff.
	time.Sleep(time.Millisecond)
	_, err := workflow.BeginAutomatic(t.Context(), automatic, claim)
	if stopper.prepare == 0 || stopper.stop == 0 {
		t.Fatalf("accepted claim did not progress: prepare=%d stop=%d err=%v", stopper.prepare, stopper.stop, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for i, retain := range stopper.retains {
		if !retain.IsZero() {
			t.Fatalf("effect %d carried non-zero automatic retention %v", i, retain)
		}
	}
}

func TestAutomaticClaimPolicyMismatchFailsBeforeEffects(t *testing.T) {
	journal, automatic, claim := automaticWorkflowFixture(t)
	journal.state.Deletions[deletionKey(automatic.DeleteRequest)] = func() Deletion {
		d := journal.state.Deletions[deletionKey(automatic.DeleteRequest)]
		d.AutomaticPolicyRevision = "policy-v2"
		return d
	}()
	stopper := new(automaticDeletionStopper)
	workflow := &DeletionWorkflow{Journal: journal, Stopper: stopper, Edge: automaticDeletionEdge{}}
	if _, err := workflow.BeginAutomatic(t.Context(), automatic, claim); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched persisted policy returned %v, want explicit rejection", err)
	}
	if stopper.prepare != 0 || stopper.stop != 0 {
		t.Fatalf("mismatched policy caused effects: prepare=%d stop=%d", stopper.prepare, stopper.stop)
	}
}
