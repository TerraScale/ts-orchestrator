package security

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestScheduledRotationUsesExpiryAndRetiresOverlap(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 4, 0, 1, 0, 0, time.UTC)
	clock, store := &rotationClock{now: start}, &rotationStore{}
	c := testCoordinator(t, &rotationConsumers{}, clock, store)
	lead := 15 * time.Minute
	first, err := c.Reconcile(ctx, lead)
	if err != nil || first.NewVersion != 1 {
		t.Fatalf("initial generation = %+v, %v", first, err)
	}
	issuer := c.issuer.(*rotationIssuer)
	saves := store.saves
	// Every production polling interval before the lead boundary is a no-op.
	for at := start.Add(time.Minute); at.Before(first.NewExpiry.Add(-lead)); at = at.Add(time.Minute) {
		clock.Set(at)
		if _, err := c.Reconcile(ctx, lead); err != nil {
			t.Fatal(err)
		}
	}
	if issuer.calls != 1 || store.saves != saves {
		t.Fatalf("healthy polling reissued or rewrote state: issues=%d saves=%d", issuer.calls, store.saves)
	}
	clock.Set(first.NewExpiry.Add(-lead))
	second, err := c.Reconcile(ctx, lead)
	if err != nil || second.NewVersion != 2 || second.OldVersion != 1 || second.OperationID == first.OperationID {
		t.Fatalf("expiry rotation = %+v, %v", second, err)
	}
	if clock.Now().Day() != start.Day() {
		t.Fatal("fixture must rotate twice on the same UTC day")
	}
	// Recreate the coordinator with the same authorities and durable store.
	// A restart must neither regenerate the key nor postpone retirement.
	c, err = NewCoordinator(Config{Issuer: c.issuer, Vault: c.vault, Members: c.members, Secrets: c.secrets, Reloader: c.reloader, State: store, Regions: c.regions, Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	clock.Set(store.state.OldExpiry.Add(-time.Nanosecond))
	beforeRetirement, err := c.Reconcile(ctx, lead)
	if err != nil || beforeRetirement.OldVersion != 1 {
		t.Fatalf("early retirement = %+v, %v", beforeRetirement, err)
	}
	clock.Set(store.state.OldExpiry)
	afterRetirement, err := c.Reconcile(ctx, lead)
	if err != nil || afterRetirement.OldVersion != 0 || issuer.calls != 2 {
		t.Fatalf("retirement = %+v, %v, issues=%d", afterRetirement, err, issuer.calls)
	}
}

func TestScheduledRotationResumesDurableOperationAcrossMidnight(t *testing.T) {
	ctx := context.Background()
	clock := &rotationClock{now: time.Date(2026, 9, 4, 23, 59, 0, 0, time.UTC)}
	store := &rotationStore{}
	c := testCoordinator(t, &rotationConsumers{}, clock, store)
	// Simulate a crash after the prepare intent reached durable storage and
	// before its first issuer call. Preserve the original operation identity.
	pending := c.newState(PersistedState{}, "capability-rotation-before-restart", clock.Now())
	if err := store.Save(ctx, pending); err != nil {
		t.Fatal(err)
	}
	clock.Set(clock.Now().Add(2 * time.Minute))
	got, err := c.Reconcile(ctx, 15*time.Minute)
	if err != nil || got.Phase != PhaseActive || got.OperationID != pending.OperationID || got.NewVersion != 1 {
		t.Fatalf("restart = %+v, %v", got, err)
	}
	if _, err := c.Reconcile(ctx, 15*time.Minute); err != nil || c.issuer.(*rotationIssuer).calls != 1 {
		t.Fatalf("restart duplicated issuance: %v", err)
	}
}

func TestScheduledRotationRejectsUnsafeLeadAndFailedState(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store := &rotationStore{}
	c := testCoordinator(t, &rotationConsumers{}, clock, store)
	for _, lead := range []time.Duration{0, DefaultExpirySafety, CapabilityOverlap - time.Nanosecond, CapabilityPeriod} {
		if _, err := c.Reconcile(context.Background(), lead); err == nil {
			t.Fatalf("accepted unsafe lead %v", lead)
		}
	}
	if c.issuer.(*rotationIssuer).calls != 0 || store.saves != 0 {
		t.Fatal("invalid scheduling mutated providers or state")
	}
	store.state, store.exists = PersistedState{Phase: PhaseFailed, OperationID: "failed", Regions: c.regions}, true
	_, err := c.Reconcile(context.Background(), 15*time.Minute)
	var rotationError *RotationError
	if !errors.As(err, &rotationError) || rotationError.Code != "rotation_failed_closed" {
		t.Fatalf("failed state = %v", err)
	}
}
