package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type raftFencer struct {
	node  *swarmruntime.Node
	mu    sync.Mutex
	term  uint64
	guard func(context.Context) error
}

func (f *raftFencer) Current() authority.Snapshot {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	term, guard, err := f.node.LeaderTerm(ctx)
	if err != nil {
		return authority.Snapshot{Reason: err.Error()}
	}
	f.mu.Lock()
	f.term, f.guard = term, guard
	f.mu.Unlock()
	return authority.Snapshot{Leader: true, Ready: true, Epoch: term}
}

func (f *raftFencer) Guard(ctx context.Context, epoch uint64) error {
	f.mu.Lock()
	term, guard := f.term, f.guard
	f.mu.Unlock()
	if guard == nil || term != epoch {
		return errors.New("the Raft leader term changed")
	}
	return guard(ctx)
}

func runOCIReconcile(ctx context.Context, state, region string, node *swarmruntime.Node) {
	fencer := &raftFencer{node: node}
	runner, err := fleet.Reconciler(ctx, region, fencer)
	if err != nil {
		slog.ErrorContext(ctx, "OCI reconcile loop changes nothing", "region", region, "error", err)
		go regionhealth.ServeReconcile(ctx, state, func() (regionhealth.Reconcile, bool) {
			return regionhealth.Reconcile{Error: err.Error()}, fencer.Current().Leader
		})
		return
	}
	go regionhealth.ServeReconcile(ctx, state, func() (regionhealth.Reconcile, bool) {
		return regionhealth.Reconcile{Kinds: runner.Status()}, fencer.Current().Leader
	})
	runner.Run(ctx)
}
