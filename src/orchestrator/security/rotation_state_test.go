package security

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRotationRejectsIncompleteActiveKeyRingWithoutDiscardingState(t *testing.T) {
	for _, damage := range []struct {
		name  string
		apply func(*PersistedState)
	}{
		{"retired record without current fields", func(s *PersistedState) {
			s.CurrentVersion, s.CurrentIdentityRef, s.CurrentCapabilityRef, s.CurrentCapabilityID, s.CurrentExpiry = 0, "", "", "", time.Time{}
		}},
		{"missing current reference", func(s *PersistedState) { s.CurrentCapabilityRef = "" }},
		{"missing current ID", func(s *PersistedState) { s.CurrentCapabilityID = "" }},
		{"missing current expiry", func(s *PersistedState) { s.CurrentExpiry = time.Time{} }},
		{"mismatched candidate", func(s *PersistedState) { s.NewVersion++ }},
		{"missing old version", func(s *PersistedState) { s.OldVersion = 0 }},
		{"missing old reference", func(s *PersistedState) { s.OldIdentityRef = "" }},
		{"missing old expiry", func(s *PersistedState) { s.OldExpiry = time.Time{} }},
		{"mismatched previous ID", func(s *PersistedState) { s.PreviousCapabilityID = "wrong" }},
	} {
		t.Run(damage.name, func(t *testing.T) {
			ctx := context.Background()
			clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
			store := &rotationStore{}
			c := testCoordinator(t, &rotationConsumers{}, clock, store)
			if _, err := c.Rotate(ctx, "first"); err != nil {
				t.Fatal(err)
			}
			clock.Set(clock.Now().Add(time.Hour))
			if _, err := c.Rotate(ctx, "second"); err != nil {
				t.Fatal(err)
			}
			damage.apply(&store.state)
			before, saves := cloneState(store.state), store.saves
			issuer := c.issuer.(*rotationIssuer)
			issued := issuer.calls
			for _, run := range []func() (RotationResult, error){
				func() (RotationResult, error) { return c.Rotate(ctx, "third") },
				func() (RotationResult, error) { return c.Resume(ctx) },
				func() (RotationResult, error) { return c.RetireExpired(ctx) },
				func() (RotationResult, error) { return c.Reconcile(ctx, 15*time.Minute) },
			} {
				_, err := run()
				var rotationError *RotationError
				if !errors.As(err, &rotationError) || rotationError.Code != "state_invalid" {
					t.Fatalf("malformed state accepted: %v", err)
				}
			}
			if !reflect.DeepEqual(before, store.state) || saves != store.saves || issued != issuer.calls {
				t.Fatal("invalid state caused mutation or lost retirement obligations")
			}
		})
	}
}

func TestRotationDoesNotDiscardUnavailablePreviousMaterial(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store := &rotationStore{}
	c := testCoordinator(t, &rotationConsumers{}, clock, store)
	if _, err := c.Rotate(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	oldRef := store.state.CurrentCapabilityRef
	delete(c.vault.(*rotationVault).materials, oldRef)
	clock.Set(clock.Now().Add(time.Hour))
	_, err := c.Rotate(context.Background(), "second")
	var rotationError *RotationError
	if !errors.As(err, &rotationError) || rotationError.Code != "previous_material_unavailable" {
		t.Fatalf("missing previous material was accepted: %v", err)
	}
	if store.state.Phase != PhaseFailed || store.state.OldCapabilityRef != oldRef {
		t.Fatal("missing previous material lost its durable obligation")
	}
}

func TestExplicitRotationPreservesOutstandingOverlap(t *testing.T) {
	ctx := context.Background()
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store := &rotationStore{}
	c := testCoordinator(t, &rotationConsumers{}, clock, store)
	if _, err := c.Rotate(ctx, "first"); err != nil {
		t.Fatal(err)
	}
	clock.Set(clock.Now().Add(time.Hour))
	if _, err := c.Rotate(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	before, saves := cloneState(store.state), store.saves
	_, err := c.Rotate(ctx, "third")
	var rotationError *RotationError
	if !errors.As(err, &rotationError) || rotationError.Code != "rotation_overlap_active" {
		t.Fatalf("outstanding overlap was discarded: %v", err)
	}
	if !reflect.DeepEqual(before, store.state) || saves != store.saves {
		t.Fatal("overlap rejection mutated state")
	}
	clock.Set(before.OldExpiry)
	result, err := c.Rotate(ctx, "third")
	if err != nil || result.NewVersion != 3 || result.OldVersion != 2 {
		t.Fatalf("rotation after retirement = %+v, %v", result, err)
	}
}

func TestRotationResumePreservesIssuedReferencesWhenProviderChangesResult(t *testing.T) {
	for _, kind := range []string{"identity", "capability"} {
		t.Run(kind, func(t *testing.T) {
			clock := &rotationClock{now: time.Now().UTC()}
			store := &rotationStore{}
			coordinator := testCoordinator(t, &rotationConsumers{}, clock, store)
			state := coordinator.newState(emptyState(coordinator.regions), "resumed-issuance", clock.Now())
			state.NewIdentityRef = "identity-1"
			if kind == "identity" {
				state.NewIdentityRef = "previously-admitted-identity"
			} else {
				state.NewCapabilityRef = "previously-admitted-capability"
				state.NewCapabilityID = "previously-admitted-key"
			}
			if err := store.Save(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Resume(context.Background()); err == nil {
				t.Fatal("provider replaced issued reference under same operation")
			}
			if store.state.NewIdentityRef != state.NewIdentityRef || store.state.NewCapabilityRef != state.NewCapabilityRef || store.state.NewCapabilityID != state.NewCapabilityID || store.state.Phase != PhaseFailed {
				t.Fatal("failed resume lost durable issuance/retirement references")
			}
		})
	}
}
