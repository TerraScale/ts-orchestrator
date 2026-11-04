package app

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func TestFounderStartsWhileRegionalClusterIsWaiting(t *testing.T) {
	clusterWaiting := make(chan struct{})
	founderStarted := make(chan struct{})
	supervisor, stop, err := superviseFounderAndWaitCluster(t.Context(), func(ctx context.Context) error {
		close(clusterWaiting)
		select {
		case <-founderStarted:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func(ctx context.Context) error {
		select {
		case <-clusterWaiting:
			close(founderStarted)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		t.Fatalf("founder and cluster must progress concurrently: %v", err)
	}
	stop()
	if status := supervisor.Status(); status.Phase != bootstrapstart.FounderPhaseComplete {
		t.Fatalf("founder status = %+v", status)
	}
}
