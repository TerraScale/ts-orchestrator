package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
)

func prepareNodeStop(ctx context.Context, public *edge.Edge, prepare func(context.Context) error) {
	stop := plannedstop.Begin(ctx)
	public.Drain()
	preparation, cancel := context.WithTimeout(stop, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- prepare(preparation) }()
	select {
	case err := <-done:
		if err != nil {
			slog.Warn("node stop preparation refused; stopping within shutdown budget", "error", err)
		}
	case <-preparation.Done():
		plannedstop.Abandon(ctx, "mesh stop preparation", preparation.Err())
	}
}
