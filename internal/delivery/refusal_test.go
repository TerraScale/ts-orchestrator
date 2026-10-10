package delivery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
)

func TestRefuseIntentPreservesDurableIdentity(t *testing.T) {
	writer := &testWriter{}
	s, ctx := testService(t, writer)
	i := testIntent(t, s, ctx)
	for range 2 {
		if err := s.RefuseIntent(ctx, i, "operator", i.AuthorityEpoch, "release is not retained"); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.StatusFor(ctx, i)
	if err != nil || r.Status != "rejected" || r.Error != "release is not retained" || writer.count() != 0 {
		t.Fatalf("refusal=%+v err=%v writes=%d", r, err, writer.count())
	}
	conflict := i
	conflict.Generation++
	if err := s.RefuseIntent(ctx, conflict, "operator", i.AuthorityEpoch, "different release"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting refusal: %v", err)
	}
	if terminal, err := s.process(ctx, mustJSON(i)); !terminal || err != nil || writer.count() != 0 {
		t.Fatalf("refused replay: terminal=%t err=%v writes=%d", terminal, err, writer.count())
	}
}

func TestRefuseIntentPreservesAcceptedOperation(t *testing.T) {
	writer := &testWriter{}
	s, ctx := testService(t, writer)
	i := testIntent(t, s, ctx)
	if terminal, err := s.process(ctx, mustJSON(i)); !terminal || err != nil {
		t.Fatalf("accept: terminal=%t err=%v", terminal, err)
	}
	if err := s.RefuseIntent(ctx, i, "operator", i.AuthorityEpoch, "late refusal"); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted operation overwritten: %v", err)
	}
	r, err := s.StatusFor(ctx, i)
	if err != nil || r.Status != "accepted" || writer.count() != 1 {
		t.Fatalf("accepted=%+v err=%v writes=%d", r, err, writer.count())
	}
}

func TestRefuseIntentRequiresAuthorizationAndAuthority(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	i := testIntent(t, s, ctx)
	denied := errors.New("not authorized")
	s.config.Authorize = func(context.Context, string, Intent) error { return denied }
	if err := s.RefuseIntent(ctx, i, "operator", i.AuthorityEpoch, "ineligible"); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	s.config.Authorize = func(context.Context, string, Intent) error { return nil }
	i.AuthorityEpoch++
	if err := s.RefuseIntent(ctx, i, "operator", i.AuthorityEpoch, "ineligible"); err == nil {
		t.Fatal("stale authority wrote refusal")
	}
	if _, err := s.Status(ctx, i.OperationID); !errors.Is(err, ErrPending) {
		t.Fatalf("unauthorized/fenced refusal persisted: %v", err)
	}
}

func TestStatusForChecksPendingOperationFingerprint(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	i := testIntent(t, s, ctx)
	fp, _ := i.Fingerprint()
	wire, err := json.Marshal(operation{Intent: i, Fingerprint: fp, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operations.Create(ctx, operationKey(i.OperationID), wire); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StatusFor(ctx, i); !errors.Is(err, ErrPending) {
		t.Fatalf("matching pending request: %v", err)
	}
	i.Generation++
	if _, err := s.StatusFor(ctx, i); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending operation ID collision: %v", err)
	}
}

func TestRefuseIntentSettlesOldEpochWithoutReplacingClaimedPlan(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	i := testIntent(t, s, ctx)
	i.AuthorityEpoch = 2
	if err := s.RefuseIntent(ctx, i, "operator", 1, "expired unsent selection"); err != nil {
		t.Fatal(err)
	}
	r, err := s.StatusFor(ctx, i)
	if err != nil || r.Status != "rejected" || r.AuthorityEpoch != i.AuthorityEpoch {
		t.Fatalf("old-epoch identity not preserved: %+v %v", r, err)
	}
	claimed := i
	claimed.OperationID = "00000000001Y9Z8VKC1VV66J6B"
	fp, _ := claimed.Fingerprint()
	wire, err := json.Marshal(operation{Intent: claimed, Fingerprint: fp, Actor: "operator", Plan: nil})
	if err != nil {
		t.Fatal(err)
	}
	key := operationKey(claimed.OperationID)
	revision, err := s.operations.Create(ctx, key, wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RefuseIntent(ctx, claimed, "operator", 1, "cannot assume the plan was unwritten"); !errors.Is(err, ErrConflict) {
		t.Fatalf("claimed plan overwritten: %v", err)
	}
	entry, err := s.operations.Get(ctx, key)
	if err != nil || entry.Revision() != revision || string(entry.Value()) != string(wire) {
		t.Fatalf("claimed operation changed: %v", err)
	}
}
