package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// A --timeout that expires while a seat is awaited counts as a transient
// failure toward --transient-block-after; only an explicit cancellation is a
// plain interruption (#127 12022).
func TestTerraBaseSyncCountsAnExpiredDeadlineAsTransient(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 20)
	policy := cdRetryPolicy{Backoff: staged.Backoff{Initial: time.Millisecond, Attempts: 1}, BlockAfter: time.Hour}
	awaitSeat := func(ctx context.Context) func(terrabaseReleaseFiles) error {
		return func(terrabaseReleaseFiles) error {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	run := func(policy cdRetryPolicy) error {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		return syncTerraBaseWithPolicy(ctx, state, root, feed.run, awaitSeat(ctx), io.Discard, policy)
	}
	if err := run(policy); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline = %v", err)
	}
	var record cdTransientRecord
	readDeployTestState(t, state, cdTransientFile, &record)
	if record.FirstAt.IsZero() || !strings.Contains(record.Reason, "sync deadline expired") {
		t.Fatalf("expired deadline not recorded as transient: %+v", record)
	}
	if _, err := os.Stat(filepath.Join(state, cdBlockedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a first expired deadline blocked automation: %v", err)
	}
	policy.BlockAfter = time.Nanosecond
	if err := run(policy); err == nil {
		t.Fatal("persistent expired deadline succeeded")
	}
	var blocked struct {
		Reason string `json:"reason"`
	}
	readDeployTestState(t, state, cdBlockedFile, &blocked)
	if !strings.Contains(blocked.Reason, "transient failures persisted since") {
		t.Fatalf("persistent expired deadlines did not escalate: %+v", blocked)
	}
}

// An explicit cancellation records nothing and keeps the pin.
func TestTerraBaseSyncCancellationRecordsNothing(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 20)
	ctx, cancel := context.WithCancel(t.Context())
	err := syncTerraBaseWithPolicy(ctx, state, root, feed.run, func(terrabaseReleaseFiles) error {
		cancel()
		return ctx.Err()
	}, io.Discard, defaultCDRetryPolicy)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sync = %v", err)
	}
	for _, name := range []string{cdBlockedFile, cdTransientFile} {
		if _, err := os.Stat(filepath.Join(state, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written on cancellation: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(state, cdActiveFile)); err != nil {
		t.Fatalf("pin lost on cancellation: %v", err)
	}
}
