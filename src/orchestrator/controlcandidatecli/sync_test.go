package controlcandidatecli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type syncHarness struct {
	mu       sync.Mutex
	receipt  nodeauthority.CandidatePreparationReceipt
	request  preliminarytransfer.VerifiedCandidate
	invalid  bool
	lost     bool
	reads    int
	statuses chan syncStatus
}

func newSyncHarness() *syncHarness {
	return &syncHarness{receipt: nodeauthority.CandidatePreparationReceipt{Phase: "admitted", ExpiresAt: time.Now().Add(time.Minute)}, request: preliminarytransfer.VerifiedCandidate{Digest: "request-a", Scope: preliminarytransfer.VerifiedScope{Digest: "scope-a"}, Authorization: preliminarytransfer.CandidateAuthorization{ExpiresAt: time.Now().Add(time.Minute)}}, statuses: make(chan syncStatus, 32)}
}
func (h *syncHarness) Write(raw []byte) (int, error) {
	var s syncStatus
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	h.statuses <- s
	return len(raw), nil
}
func (h *syncHarness) validate(context.Context, transitiongrant.Config) (nodeauthority.CandidatePreparationReceipt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lost {
		return h.receipt, errors.New("lost")
	}
	return h.receipt, nil
}
func (h *syncHarness) deps(run func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error)) syncDependencies {
	return syncDependencies{read: func(string) ([]byte, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.reads++
		return []byte("signed"), nil
	}, verify: func(context.Context, transitiongrant.Config, []byte) (preliminarytransfer.VerifiedCandidate, nodeauthority.CandidatePreparationReceipt, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.invalid {
			return h.request, h.receipt, errors.New("private /credentials/key")
		}
		return h.request, h.receipt, nil
	}, within: func(ctx context.Context, _ transitiongrant.Config, fn func(context.Context) error) error {
		return fn(ctx)
	}, run: run}
}
func (h *syncHarness) expect(t *testing.T, state string) {
	t.Helper()
	select {
	case s := <-h.statuses:
		if s.State != state {
			t.Fatalf("state %q, want %q", s.State, state)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s status", state)
	}
}
func startSyncHarness(t *testing.T, h *syncHarness, run func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error)) (context.CancelFunc, chan time.Time, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	tick := make(chan time.Time)
	done := make(chan error, 1)
	config := candidateCommandConfig()
	config.Sync = &transitiongrant.CandidateSyncConfig{RequestFile: "/fixed/request"}
	go func() { done <- watchCandidate(ctx, config, h, h.receipt, h.validate, h.deps(run), tick) }()
	t.Cleanup(cancel)
	return cancel, tick, done
}
func awaitCandidateStop(t *testing.T, done <-chan error, wantError bool) {
	t.Helper()
	select {
	case err := <-done:
		if (err != nil) != wantError {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("candidate did not join worker")
	}
}

func TestSyncCancellationAndPreparationLossJoinWorker(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "proof-loss"}[loss], func(t *testing.T) {
			h := newSyncHarness()
			started := make(chan struct{})
			canceled := make(chan struct{})
			release := make(chan struct{})
			cancel, tick, done := startSyncHarness(t, h, func(ctx context.Context, _ transitiongrant.Config, _ preliminarytransfer.VerifiedCandidate) ([]byte, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				<-release
				return nil, ctx.Err()
			})
			h.expect(t, "syncing")
			<-started
			if loss {
				h.mu.Lock()
				h.lost = true
				h.mu.Unlock()
				tick <- time.Now()
			} else {
				cancel()
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("worker not canceled")
			}
			select {
			case <-done:
				t.Fatal("returned before worker cleanup")
			default:
			}
			close(release)
			awaitCandidateStop(t, done, loss)
		})
	}
}
func TestSyncInvalidRequestKeepsPreparationAliveAndCorrectionStarts(t *testing.T) {
	h := newSyncHarness()
	h.invalid = true
	started := make(chan struct{})
	cancel, tick, done := startSyncHarness(t, h, func(ctx context.Context, _ transitiongrant.Config, _ preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	h.expect(t, "request-refused")
	select {
	case <-done:
		t.Fatal("invalid request killed preparation")
	default:
	}
	h.mu.Lock()
	h.invalid = false
	h.mu.Unlock()
	tick <- time.Now()
	h.expect(t, "syncing")
	<-started
	cancel()
	awaitCandidateStop(t, done, false)
}
func TestSyncScopeConflictCancelsWorkerAndCannotReplacePin(t *testing.T) {
	h := newSyncHarness()
	started := make(chan struct{})
	stopped := make(chan struct{})
	cancel, tick, done := startSyncHarness(t, h, func(ctx context.Context, _ transitiongrant.Config, _ preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	h.expect(t, "syncing")
	<-started
	h.mu.Lock()
	h.request.Scope.Digest = "different"
	h.mu.Unlock()
	tick <- time.Now()
	h.expect(t, "scope-conflict")
	<-stopped
	cancel()
	awaitCandidateStop(t, done, false)
}
func TestSyncSuccessDeduplicatesOnlyFreshExactAuthorization(t *testing.T) {
	h := newSyncHarness()
	var mu sync.Mutex
	calls := 0
	cancel, tick, done := startSyncHarness(t, h, func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return []byte("signed-receipt"), nil
	})
	h.expect(t, "syncing")
	h.expect(t, "complete")
	tick <- time.Now()
	tick <- time.Now()
	h.mu.Lock()
	h.request.Digest = "renewed"
	h.mu.Unlock()
	tick <- time.Now()
	h.expect(t, "syncing")
	h.expect(t, "complete")
	cancel()
	awaitCandidateStop(t, done, false)
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("attempts %d", calls)
	}
}
func TestSyncWorkerFailureStatusDoesNotExposeErrors(t *testing.T) {
	h := newSyncHarness()
	cancel, _, done := startSyncHarness(t, h, func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		return nil, errors.New("credential secret /private/key")
	})
	h.expect(t, "syncing")
	select {
	case status := <-h.statuses:
		raw, _ := json.Marshal(status)
		if status.State != "failed" || bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte("private")) {
			t.Fatalf("unsafe status %s", raw)
		}
	case <-time.After(time.Second):
		t.Fatal("missing failure")
	}
	cancel()
	awaitCandidateStop(t, done, false)
}

func TestSyncPreparationExpiryCancelsAndJoins(t *testing.T) {
	h := newSyncHarness()
	h.receipt.ExpiresAt = time.Now().Add(80 * time.Millisecond)
	stopped := make(chan struct{})
	_, _, done := startSyncHarness(t, h, func(ctx context.Context, _ transitiongrant.Config, _ preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	h.expect(t, "syncing")
	awaitCandidateStop(t, done, true)
	select {
	case <-stopped:
	default:
		t.Fatal("expiry returned before worker stopped")
	}
}

func TestSyncRequestIsReverifiedInsideActivityLock(t *testing.T) {
	h := newSyncHarness()
	config := candidateCommandConfig()
	config.Sync = &transitiongrant.CandidateSyncConfig{RequestFile: "/fixed/request"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	deps := h.deps(func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		t.Error("effect ran after request changed before activity lock")
		return nil, nil
	})
	deps.within = func(ctx context.Context, _ transitiongrant.Config, fn func(context.Context) error) error {
		h.mu.Lock()
		h.invalid = true
		h.mu.Unlock()
		return fn(ctx)
	}
	done := make(chan error, 1)
	go func() { done <- watchCandidate(ctx, config, h, h.receipt, h.validate, deps, make(chan time.Time)) }()
	h.expect(t, "syncing")
	h.expect(t, "failed")
	cancel()
	awaitCandidateStop(t, done, false)
}

func candidateCommandConfig() transitiongrant.Config {
	return transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "transition-1", NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem"}
}

func TestSyncRetriesAreBoundedForOneAuthorization(t *testing.T) {
	h := newSyncHarness()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	config := candidateCommandConfig()
	config.Sync = &transitiongrant.CandidateSyncConfig{RequestFile: "/fixed/request"}
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	attempts := 0
	deps := h.deps(func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error) {
		attempts++
		return nil, errors.New("transient")
	})
	done := make(chan error, 1)
	go func() { done <- watchCandidate(ctx, config, h, h.receipt, h.validate, deps, poll.C) }()
	for i := 0; i < 3; i++ {
		h.expect(t, "syncing")
		h.expect(t, "failed")
	}
	// The third failure's backoff expires while the same valid authorization is
	// continually checked. No fourth attempt may start without a new signature.
	select {
	case status := <-h.statuses:
		t.Fatalf("unbounded retry: %+v", status)
	case <-time.After(3200 * time.Millisecond):
	}
	cancel()
	awaitCandidateStop(t, done, false)
	if attempts != 3 {
		t.Fatalf("attempts %d", attempts)
	}
}
