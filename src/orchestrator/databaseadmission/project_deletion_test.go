package databaseadmission

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryProjectDeletionFenceReplayAndScope(t *testing.T) {
	ctx := context.Background()
	j := NewMemoryJournal()
	r := ProjectDeletionRequest{Environment: "gru", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", OperationID: "project-op", PolicyFingerprint: "policy-v1"}
	now := time.Unix(1700000000, 0).UTC()
	first, err := j.BeginProjectDeletion(ctx, r, now)
	if err != nil || first.State != "accepted" || first.RequestedAt != now || len(first.Targets) != 0 {
		t.Fatalf("begin empty project deletion = %#v, %v", first, err)
	}
	replay, err := j.BeginProjectDeletion(ctx, r, now.Add(time.Hour))
	if err != nil || replay.RequestedAt != now {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	changed := r
	changed.PolicyFingerprint = "policy-v2"
	if _, err := j.BeginProjectDeletion(ctx, changed, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed immutable intent error = %v", err)
	}
	foreign := r
	foreign.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"

	if _, err := j.BeginProjectDeletion(ctx, foreign, now); err != nil {
		t.Fatalf("foreign project should be isolated: %v", err)
	}
}
