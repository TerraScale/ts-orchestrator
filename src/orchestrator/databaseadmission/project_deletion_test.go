package databaseadmission

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
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
	j := NewMemoryJournal()
	record := journalFixture(t)
	if _, err := j.Save(t.Context(), ScopeKey(record.Request), 0, record); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0).UTC()
	// Each pressure row owns a distinct valid project scope and is admitted
	// through the production transaction and reservation calculation.
	for i := range 1000 {
		r := ProjectDeletionRequest{Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: fmt.Sprintf("%026d", i), OperationID: "pressure-operation", PolicyFingerprint: strings.Repeat("x", 512)}
		_, err := j.BeginProjectDeletion(t.Context(), r, now)
		if errors.Is(err, ErrJournalUnavailable) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if i == 999 {
			t.Fatal("pressure never reached the reservation budget")
		}
	}
	candidate := ProjectDeletionRequest{Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, OperationID: "pressure-operation", PolicyFingerprint: strings.Repeat("x", 512)}
	before, err := j.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(before.ProjectDeletions) == 0 || validateJournalState(before) != nil || validateReservedCapacity(before) != nil {
		t.Fatal("pressure must start from a valid admitted state within its reservation budget")
	}
	// The actual bytes still fit: rejection must protect future progress,
	// rather than merely enforce the encoded-state ceiling.
	encoded, err := json.Marshal(before)
	if err != nil || len(encoded)+4096 >= authorityjournal.MaximumStateBytes {
		t.Fatalf("insufficient actual capacity for candidate: bytes=%d err=%v", len(encoded), err)
	}
	if _, err := j.BeginProjectDeletion(t.Context(), candidate, time.Unix(1700000000, 0).UTC()); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatalf("capacity error = %v", err)
	}
	after, err := j.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("capacity rejection mutated journal state")
	}
	loaded, found, err := j.Load(t.Context(), ScopeKey(record.Request))
	if err != nil || !found {
		t.Fatalf("existing admission load = %v", err)
	}
	loaded.State = "keys_provisioned"
	loaded.Wrapped = journalWrapped(loaded)
	if _, err := j.Save(t.Context(), ScopeKey(record.Request), loaded.Revision, loaded); err != nil {
		t.Fatalf("existing admission progress after rejection = %v", err)
	}
	progressed, err := j.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(progressed.ProjectDeletions, before.ProjectDeletions) || !reflect.DeepEqual(progressed.ProjectFences, before.ProjectFences) {
		t.Fatal("progress removed capacity pressure")
	}
	got := progressed.Records[ScopeKey(record.Request)]
	if got.State != "keys_provisioned" || got.Revision != loaded.Revision+1 || !reflect.DeepEqual(got.Wrapped, loaded.Wrapped) {
		t.Fatal("next admission step was not persisted")
	}
}
