package ociclient

import (
	"context"
	"testing"
	"time"
)

func TestCheckpointContextPreservesRootGuardAndOriginalDeadline(t *testing.T) {
	original, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Minute))
	ctx := original
	for _, key := range []any{authorityKey{}, admissionKey{}, wireAttemptKey{}, admissionDeadlineKey{}, requestGuardKey{}} {
		ctx = context.WithValue(ctx, key, "original")
	}
	checkpoint := CheckpointContext(ctx)
	for _, key := range []any{authorityKey{}, admissionKey{}, wireAttemptKey{}, admissionDeadlineKey{}} {
		if checkpoint.Value(key) != nil {
			t.Fatal("checkpoint inherited provider mutation hooks")
		}
	}
	if checkpoint.Value(requestGuardKey{}) != "original" {
		t.Fatal("checkpoint lost its final root request guard")
	}
	want, _ := original.Deadline()
	if got, ok := checkpoint.Deadline(); !ok || !got.Equal(want) {
		t.Fatal("checkpoint changed the original deadline")
	}
	cancel()
	if checkpoint.Err() != context.Canceled {
		t.Fatal("checkpoint detached from original cancellation")
	}
}
