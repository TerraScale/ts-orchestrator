package databaseadmission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMemoryProjectDeletionFenceReplayAndScope(t *testing.T) {
	j := NewMemoryJournal()
	ctx := context.Background()
	r := ProjectDeletionRequest{Environment: "gru", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", OperationID: "project-op", PolicyFingerprint: "policy-v1"}
	now := time.Unix(1700000000, 0).UTC()
	first, err := j.BeginProjectDeletion(ctx, r, now)
	if err != nil || first.RequestedAt != now || len(first.Targets) != 0 {
		t.Fatalf("begin = %#v, %v", first, err)
	}
	replay, err := j.BeginProjectDeletion(ctx, r, now.Add(time.Hour))
	if err != nil || replay.RequestedAt != now {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	changed := r
	changed.PolicyFingerprint = "policy-v2"
	if _, err := j.BeginProjectDeletion(ctx, changed, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed intent = %v", err)
	}
	foreign := r
	foreign.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
	if _, err := j.BeginProjectDeletion(ctx, foreign, now); err != nil {
		t.Fatalf("foreign scope = %v", err)
	}
}

func TestBeginProjectDeletionCapacityFailureIsAtomic(t *testing.T) {
	state := newJournalState()
	policy := "policy-" + strings.Repeat("x", 500)
	for i := range 1100 {
		projectID := "01ARZ3NDEKTSV4RRFFQ69G5FAW"
		r := ProjectDeletionRequest{Environment: "gru", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: projectID, OperationID: fmt.Sprintf("existing-operation-%04d", i), PolicyFingerprint: policy}
		state.ProjectDeletions[projectDeletionKey(r)] = ProjectDeletion{Request: r, State: "accepted", Revision: 1, RequestedAt: time.Unix(1700000000, 0).UTC()}
		state.ProjectFences[projectScopeKey(r)] = r.OperationID
	}
	candidate := ProjectDeletionRequest{Environment: "gru", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", OperationID: "new-operation", PolicyFingerprint: policy}
	before := len(state.ProjectDeletions)
	if _, err := beginProjectDeletion(&state, candidate, time.Unix(1700000000, 0).UTC()); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatalf("capacity error = %v", err)
	}
	if len(state.ProjectDeletions) != before || state.ProjectFences[projectScopeKey(candidate)] != "" {
		t.Fatal("capacity rejection mutated project state")
	}
}
