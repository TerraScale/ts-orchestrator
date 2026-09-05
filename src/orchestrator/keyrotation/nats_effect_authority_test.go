package keyrotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestEffectAuthorityKeepsStateCursorAndPinsLeaseIdentity(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	ctx := t.Context()
	kv := openRotationTestLeaseStore(t, ctx, connection, true)
	lease := rotationTestLease(9, "global-controller-gru-effect-check")
	putRotationTestLease(t, ctx, kv, lease)
	session := newRotationTestSession(t, connection, lease)
	if _, err := session.Load(ctx); !errors.Is(err, security.ErrNoState) {
		t.Fatal(err)
	}
	state := rotationTestState()
	if err := session.Save(ctx, state); err != nil {
		t.Fatal(err)
	}
	loaded, revision := session.loaded, session.revision
	before, found, err := session.rawGet(ctx, rotationStateSubject, 0)
	if err != nil || !found {
		t.Fatal("state record missing")
	}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	proof, err := session.RefreshAuthority(ctx)
	if err != nil || proof.LeaseId != lease.LeaseId || proof.CandidateId != lease.CandidateId || proof.Epoch != lease.Epoch {
		t.Fatalf("exact lease proof failed: %v", err)
	}
	if session.loaded != loaded || session.revision != revision {
		t.Fatal("effect proof changed optimistic state session cursor")
	}
	after, found, err := session.rawGet(ctx, rotationStateSubject, 0)
	if err != nil || !found || after.Sequence != before.Sequence {
		t.Fatal("effect proof rewrote rotation state")
	}
	// Lease renewal changes its timestamp and revision, not its identity.
	lease.IssuedAt = time.Now().UTC()
	putRotationTestLease(t, ctx, kv, lease)
	proof, err = session.RefreshAuthority(ctx)
	if err != nil || !proof.IssuedAt.Equal(lease.IssuedAt) {
		t.Fatalf("ordinary renewal failed: %v", err)
	}
	if session.loaded != loaded || session.revision != revision {
		t.Fatal("renewal changed state cursor")
	}
	if err := session.Save(ctx, state); err != nil {
		t.Fatalf("guard broke later identical state save: %v", err)
	}
	replacement := lease
	replacement.LeaseId = "different-lease-same-candidate-and-term"
	putRotationTestLease(t, ctx, kv, replacement)
	if err := session.CheckEffectAuthority(ctx); !errors.Is(err, ErrStateFenced) {
		t.Fatalf("accepted replaced lease identity: %v", err)
	}
	if _, err := NewNATSStateStore(NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch)}); err == nil {
		t.Fatal("effect session accepted missing lease ID")
	}
	// A reachable member cannot authorize effects once quorum is gone.
	putRotationTestLease(t, ctx, kv, lease)
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := session.CheckEffectAuthority(bounded); err == nil {
		t.Fatal("minority authorized provider effect")
	}
}
