package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func TestReleaseFenceContextLocksCancelWithoutEffectsAndRetry(t *testing.T) {
	for _, operation := range []string{"client", "fence", "restore", "quorum"} {
		t.Run(operation, func(t *testing.T) {
			f, _, api, _, _ := newFenceTest(t)
			ctx := t.Context()
			spec, addresses := f.spec()
			var unlock func()
			var invoke func(context.Context) error
			switch operation {
			case "client":
				f.mu.Lock()
				unlock = f.mu.Unlock
				invoke = func(ctx context.Context) error { _, err := f.client(ctx); return err }
			case "fence":
				unlock = f.lockNode("gru-1-ctl-1") // Existing holders use this API.
				invoke = func(ctx context.Context) error {
					return f.fence(ctx, api, 3, *spec, "gru-1-ctl-1", addresses["gru-1-ctl-1"], 0, netbirdHold)
				}
			case "restore":
				if err := f.save(ctx, 3, "gru-1-ctl-1", fenceRecord{Holders: []string{netbirdHold}}); err != nil {
					t.Fatal(err)
				}
				unlock = f.lockNode("gru-1-ctl-1")
				invoke = func(ctx context.Context) error {
					_, err := f.restore(ctx, api, 3, "gru-1-ctl-1", netbirdHold, true)
					return err
				}
			case "quorum":
				f.quorum.Lock()
				unlock = f.quorum.Unlock
				invoke = func(ctx context.Context) error {
					return f.takeOut(ctx, api, 3, fencedBackend{LoadBalancerID: spec.LoadBalancerID, Set: "terrabase",
						IP: addresses["gru-1-ctl-1"], Port: 9465}, "gru-1-ctl-1", false)
				}
			}
			unlocked := false
			defer func() {
				if !unlocked {
					unlock()
				}
			}()
			limited, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- invoke(limited) }()
			select {
			case err := <-result:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("held %s lock returned %v", operation, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("held %s lock ignored the caller deadline", operation)
			}
			if len(api.log) != 0 || f.api != nil {
				t.Fatalf("cancelled %s operation changed provider state: log=%v client=%v", operation, api.log, f.api)
			}
			if _, found, err := f.record(ctx, "gru-1-ctl-1"); err != nil || found != (operation == "restore") {
				t.Fatalf("cancelled %s operation changed its journal: found=%t error=%v", operation, found, err)
			}
			unlock()
			unlocked = true
			if err := invoke(ctx); err != nil {
				t.Fatalf("released %s lock did not permit retry: %v", operation, err)
			}
			if operation == "restore" {
				if _, found, err := f.record(ctx, "gru-1-ctl-1"); err != nil || found {
					t.Fatalf("retry did not release the original fence: found=%t error=%v", found, err)
				}
			}
		})
	}
}

type fenceQuorumBlocker struct {
	lb.API
	entered chan struct{}
	release chan struct{}
	active  atomic.Int32
	overlap atomic.Bool
}

func (a *fenceQuorumBlocker) ListBackends(ctx context.Context, id, set string) ([]lb.Backend, error) {
	if a.active.Load() != 0 {
		a.overlap.Store(true)
	}
	return a.API.ListBackends(ctx, id, set)
}

func (a *fenceQuorumBlocker) UpdateBackend(ctx context.Context, id, set string, backend lb.Backend) (string, error) {
	if a.active.Add(1) != 1 {
		a.overlap.Store(true)
	}
	defer a.active.Add(-1)
	a.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-a.release:
		return a.API.UpdateBackend(ctx, id, set, backend)
	}
}

func TestReleaseFenceContextQuorumSerializesObservationAndUpdate(t *testing.T) {
	f, _, api, _, _ := newFenceTest(t)
	blocking := &fenceQuorumBlocker{API: api, entered: make(chan struct{}, 2), release: make(chan struct{})}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	spec, addresses := f.spec()
	results := make(chan error, 2)
	takeOut := func(node string) {
		results <- f.takeOut(ctx, blocking, 3, fencedBackend{LoadBalancerID: spec.LoadBalancerID,
			Set: "terrabase", IP: addresses[node], Port: 9465}, node, false)
	}
	go takeOut("gru-1-ctl-1")
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("first operation did not reach its guarded update")
	}
	go takeOut("gru-1-ctl-2")
	select {
	case <-blocking.entered:
		t.Fatal("second operation updated during the first quorum guard")
	case <-time.After(50 * time.Millisecond):
	}
	close(blocking.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if blocking.overlap.Load() || len(api.log) != 2 {
		t.Fatalf("quorum observations and updates overlapped: overlap=%t log=%v", blocking.overlap.Load(), api.log)
	}
}
