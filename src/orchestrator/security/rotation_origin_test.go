package security

import (
	"context"
	"testing"
	"time"
)

type originProofTestVault struct {
	items map[string]OriginProofMaterial
}

func (v *originProofTestVault) Generate(_ context.Context, r OriginProofRequest) (OriginProofMaterial, error) {
	if v.items == nil {
		v.items = map[string]OriginProofMaterial{}
	}
	ref := "origin-proof-" + time.Unix(r.Bucket, 0).UTC().Format("150405")
	m := OriginProofMaterial{ID: ref, Reference: ref, Version: r.Generation, Bucket: r.Bucket, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Secret: []byte("origin-proof-secret")}
	v.items[ref] = m
	return m, nil
}
func (v *originProofTestVault) Fetch(_ context.Context, ref string) (OriginProofMaterial, error) {
	m := v.items[ref]
	m.Secret = append([]byte(nil), m.Secret...)
	return m, nil
}
func (*originProofTestVault) Retire(context.Context, string, string) error { return nil }

func TestOriginProofRotationUsesIndependentRingAcrossRestart(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store := &rotationStore{}
	origin := &originProofTestVault{}
	base := testCoordinator(t, &rotationConsumers{}, clock, store)
	base.originProof = origin
	if _, err := base.Rotate(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	if store.state.CurrentOriginProofRef == "" || store.state.CurrentOriginProofID == "" || store.state.CurrentOriginProofRef == store.state.CurrentCapabilityRef {
		t.Fatalf("origin proof ring was not independent: %+v", store.state)
	}
	clock.Set(clock.Now().Add(time.Hour))
	restarted, err := NewCoordinator(Config{Issuer: base.issuer, Vault: base.vault, OriginProof: origin, Members: base.members, Secrets: base.secrets, Reloader: base.reloader, State: store, Regions: base.regions, Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Rotate(context.Background(), "second"); err != nil {
		t.Fatal(err)
	}
	if store.state.OldOriginProofRef == "" || store.state.OldOriginProofID == "" || store.state.OldOriginProofRef == store.state.CurrentOriginProofRef {
		t.Fatalf("origin proof overlap was not durable: %+v", store.state)
	}
}

func TestPreviousOriginProofRejectsExpiredMaterial(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	vault := &originProofTestVault{items: map[string]OriginProofMaterial{"old": {ID: "old", Reference: "old", Version: 1, Bucket: OriginProofBucket(now), ExpiresAt: now.Add(-time.Second), Secret: []byte("secret")}}}
	c := &Coordinator{originProof: vault}
	state := PersistedState{OldOriginProofRef: "old", OldOriginProofID: "old", OldVersion: 1, OldOriginProofExpiry: now.Add(-time.Second)}
	if _, err := c.previousOriginProof(context.Background(), state, now); err == nil {
		t.Fatal("expired previous origin proof was reused")
	}
}
