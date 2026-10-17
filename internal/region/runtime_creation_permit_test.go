package region

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func TestRuntimeCreationRejectsUnverifiedAndCanceledSource(t *testing.T) {
	for _, permit := range []*RuntimeCreationPermit{nil, {}} {
		if err := permit.GuardCreateFor(t.Context(), nil, bootstrapstart.AcceptedIdentity{}); err == nil {
			t.Fatal("unverified creation permit authorized a founder")
		}
		if err := permit.GuardStarted(t.Context()); err == nil {
			t.Fatal("unverified creation permit authorized a genesis commit")
		}
	}
	original, revoke := context.WithCancel(t.Context())
	permit := &RuntimeCreationPermit{ctx: original, expires: time.Now().Add(time.Minute)}
	bound, closeBound, err := permit.bound(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer closeBound()
	deadline, _ := bound.Deadline()
	if !deadline.Equal(permit.ExpiresAt()) {
		t.Fatal("runtime creation failed to retain its original expiry")
	}
	revoke()
	select {
	case <-bound.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime creation outlived original caller cancellation")
	}
	if _, _, err := permit.bound(t.Context()); err == nil {
		t.Fatal("new caller context revived a canceled runtime creation")
	}
}
