package delivery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHostCommandIdentityStableAcrossTakeoverAndRequiresLiveFence(t *testing.T) {
	fence := OperationFence{OperationID: "operation", RequestDigest: "request", OwnerID: "first", Generation: 1}
	denied := false
	check := func(OperationFence) error {
		if denied {
			return ErrOperationLeaseActive
		}
		return nil
	}
	ctx, err := WithExecutionFence(context.Background(), fence, check)
	if err != nil {
		t.Fatal(err)
	}
	first, err := HostCommandID(ctx, "host", "deploy", "payload")
	if err != nil || len(first) > 63 {
		t.Fatalf("identity %q: %v", first, err)
	}
	fence.OwnerID = "second"
	fence.Generation = 2
	next, err := WithExecutionFence(context.Background(), fence, check)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HostCommandID(next, "host", "deploy", "payload")
	if err != nil || second != first {
		t.Fatalf("takeover changed identity: %q %v", second, err)
	}
	changed, err := HostCommandID(next, "host", "deploy", "changed")
	if err != nil || changed == first {
		t.Fatal("changed payload reused identity")
	}
	denied = true
	if _, err := HostCommandID(next, "host", "deploy", "payload"); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("lost authority: %v", err)
	}
	if _, err := HostCommandID(context.Background(), "host", "deploy", "payload"); err == nil {
		t.Fatal("unfenced command admitted")
	}
	if _, err := NewExecutor(ExecutorConfig{MirrorMode: MirrorModePrepareAll}); err == nil {
		t.Fatal("executor accepted missing authority")
	}
}

func TestRegionalCommandAuthorityIsResolvedLiveUnderOperationFence(t *testing.T) {
	denied := false
	fence := OperationFence{OperationID: "operation", RequestDigest: "request", OwnerID: "owner", Generation: 1}
	ctx, err := WithExecutionFence(context.Background(), fence, func(OperationFence) error {
		if denied {
			return ErrOperationLeaseActive
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	value := RegionalCommandAuthority{AuthorityID: "gru-regional", Epoch: 1, CandidateID: "gru-controller-one", LeaseID: "lease", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), DesiredGeneration: 3}
	calls := 0
	ctx, err = WithRegionalCommandAuthority(ctx, func(context.Context) (RegionalCommandAuthority, error) { calls++; return value, nil })
	if err != nil {
		t.Fatal(err)
	}
	first, err := RegionalCommandAuthorityFromContext(ctx)
	if err != nil || first.Epoch != 1 {
		t.Fatalf("first lease: %+v %v", first, err)
	}
	value.Epoch = 2
	second, err := RegionalCommandAuthorityFromContext(ctx)
	if err != nil || second.Epoch != 2 || calls != 2 {
		t.Fatalf("cached lease: %+v %v calls=%d", second, err, calls)
	}
	denied = true
	if _, err := RegionalCommandAuthorityFromContext(ctx); !errors.Is(err, ErrOperationLeaseActive) || calls != 2 {
		t.Fatalf("fenced resolver invoked: %v calls=%d", err, calls)
	}
	denied = false
	value.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := RegionalCommandAuthorityFromContext(ctx); err == nil {
		t.Fatal("expired lease exported")
	}
	if _, err := NewExecutor(ExecutorConfig{Authority: func(context.Context, *Request) error { return nil }}); err == nil {
		t.Fatal("missing mirror mode admitted")
	}
}
