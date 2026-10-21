package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// Initial credentials gate root admission. Later rotation retains the original
// source lifetime and cancels that lifetime on failure; stop joins every effect.
func startManagedRuntimeOCIR(ctx context.Context, backend *rootfoundation.Backend, guard func(context.Context) error) (context.Context, func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, nil, rootoci.ErrUnauthorized
	}
	lifetime, cancel := context.WithCancelCause(ctx)
	if err := backend.ReconcileOCIR(lifetime, guard); err != nil {
		cancel(err)
		return nil, nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticks := time.Tick(time.Hour)
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticks:
				if err := backend.ReconcileOCIR(lifetime, guard); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	return lifetime, func() { cancel(context.Canceled); <-done }, nil
}
