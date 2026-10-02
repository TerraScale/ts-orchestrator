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

func TestTerraBaseSyncRetriesTransientFailuresWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	second := feed.add(root, "2", 20)
	var slept []time.Duration
	policy := cdRetryPolicy{Backoff: staged.Backoff{Initial: time.Second, Max: 3 * time.Second, Attempts: 3},
		BlockAfter: time.Hour, sleep: func(_ context.Context, delay time.Duration) error {
			slept = append(slept, delay)
			return nil
		}}
	attempts := 0
	update := func(terrabaseReleaseFiles) error {
		attempts++
		if attempts < 3 {
			return staged.Transient(errors.New("request TerraBase placement status: nats: timeout"))
		}
		return nil
	}
	if err := syncTerraBaseWithPolicy(t.Context(), state, root, feed.run, update, io.Discard, policy); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || len(slept) != 2 || slept[0] != time.Second || slept[1] != 2*time.Second {
		t.Fatalf("transient failures were not retried with backoff: attempts %d slept %v", attempts, slept)
	}
	var completed terrabaseCDCandidate
	readDeployTestState(t, state, cdReceiptName(1), &completed)
	if completed.Tag != second {
		t.Fatalf("completed = %+v", completed)
	}
	for _, name := range []string{cdBlockedFile, cdTransientFile, cdActiveFile} {
		if _, err := os.Stat(filepath.Join(state, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s retained after a recovered transient failure: %v", name, err)
		}
	}
}

func TestTerraBaseSyncKeepsPinOnPersistentTransientFailureThenEscalates(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 20)
	policy := cdRetryPolicy{Backoff: staged.Backoff{Initial: time.Millisecond, Attempts: 1}, BlockAfter: time.Hour,
		sleep: func(context.Context, time.Duration) error { return nil }}
	attempts := 0
	transient := func(terrabaseReleaseFiles) error {
		attempts++
		return staged.Transient(errors.New("a member is not serving"))
	}
	for run := range 2 {
		if err := syncTerraBaseWithPolicy(t.Context(), state, root, feed.run, transient, io.Discard, policy); err == nil ||
			!staged.IsTransient(err) {
			t.Fatalf("run %d: transient failure was not reported: %v", run, err)
		}
	}
	if attempts != 4 {
		t.Fatalf("attempts = %d, want two bounded tries per run", attempts)
	}
	if _, err := os.Stat(filepath.Join(state, cdBlockedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a transient failure blocked automation: %v", err)
	}
	var pinned, retained cdTransientRecord
	readDeployTestState(t, state, cdTransientFile, &retained)
	readDeployTestState(t, state, cdActiveFile, &pinned.Candidate)
	if retained.Candidate != pinned.Candidate || retained.FirstAt.IsZero() {
		t.Fatalf("transient failure not tracked for the pinned candidate: %+v", retained)
	}
	policy.BlockAfter = time.Nanosecond
	err := syncTerraBaseWithPolicy(t.Context(), state, root, feed.run, transient, io.Discard, policy)
	if err == nil {
		t.Fatal("persistent transient failure succeeded")
	}
	var blocked struct {
		Candidate terrabaseCDCandidate `json:"candidate"`
		Reason    string               `json:"reason"`
	}
	readDeployTestState(t, state, cdBlockedFile, &blocked)
	if blocked.Candidate != pinned.Candidate || !strings.Contains(blocked.Reason, "transient failures persisted since") {
		t.Fatalf("persistent transient failure did not escalate: %+v", blocked)
	}
}

func TestTerraBaseSyncBlocksTerminalFailuresImmediately(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 20)
	attempts := 0
	err := syncTerraBaseWithPolicy(t.Context(), state, root, feed.run, func(terrabaseReleaseFiles) error {
		attempts++
		return staged.Terminal(errors.New("candidate was held"))
	}, io.Discard, defaultCDRetryPolicy)
	if err == nil || attempts != 1 {
		t.Fatalf("terminal failure was retried: attempts %d err %v", attempts, err)
	}
	if _, err := os.Stat(filepath.Join(state, cdBlockedFile)); err != nil {
		t.Fatalf("terminal failure did not block: %v", err)
	}
}
