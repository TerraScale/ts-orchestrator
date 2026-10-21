package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/kvsnapshot"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/nats-io/nats.go/jetstream"
)

// restoreControllerKV restores the configuration buckets from their OCI
// Object Storage snapshots when this cell has never completed a restore, so
// a rebuilt controller set comes back with its configuration. It runs once
// the cluster has formed and before any store opens. An ordinary restart
// only reads the completed plan and needs no OCI.
func restoreControllerKV(ctx context.Context, cfg Config, js jetstream.JetStream, fullClusterReady func() bool) error {
	done, _, err := retryControllerOpen(ctx, "read KV restore plan", fullClusterReady, false,
		func(attempt context.Context) (bool, error) {
			return kvsnapshot.RestoreComplete(attempt, js, cfg.NATS.Replicas)
		}, nil)
	if err != nil || done {
		return err
	}
	objects, err := kvsnapshot.NewInstancePrincipalObjects(ctx, catalog.OCIRegion(strings.ToUpper(cfg.NATS.Cell)), cfg.NATS.Cell)
	if err != nil {
		return fmt.Errorf("open KV snapshot storage: %w", err)
	}
	// A restore resumes where an earlier attempt stopped, so every error is
	// retried here with the broker still serving the other controllers'
	// quorum; an attempt is bounded well above one large download.
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, kvRestoreAttemptTimeout)
		report, err := kvsnapshot.Restore(attemptCtx, js, objects, kvsnapshot.Buckets, cfg.NATS.Replicas, time.Now())
		cancel()
		if err == nil {
			slog.InfoContext(attemptCtx, "KV snapshot restore complete", observability.ComponentKey, "kvsnapshot",
				"buckets", report.Buckets, "written", report.Written, "kept", report.Kept)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.WarnContext(attemptCtx, "KV snapshot restore retrying", observability.ComponentKey, "kvsnapshot",
			"attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(time.Duration(attempt)*time.Second, 30*time.Second)):
		}
	}
}

const kvRestoreAttemptTimeout = 2 * time.Minute

// startKVSnapshots uploads each changed configuration bucket from the
// authority leader every thirty seconds. The returned stop cancels
// the uploader and waits for it; view reads its current snapshot health.
func startKVSnapshots(ctx context.Context, cfg Config, js jetstream.JetStream, control authority.Fencer) (stop func(), view func() observability.KVSnapshotView, err error) {
	objects, err := kvsnapshot.NewInstancePrincipalObjects(ctx, catalog.OCIRegion(strings.ToUpper(cfg.NATS.Cell)), cfg.NATS.Cell)
	if err != nil {
		return nil, nil, fmt.Errorf("open KV snapshot storage: %w", err)
	}
	snapshotter := &kvsnapshot.Snapshotter{JS: js, Objects: objects, Buckets: kvsnapshot.Buckets,
		Leader: func() bool { return control.Current().CanMutate() }}
	return ownedLoop(ctx, "KV snapshot uploader", snapshotter.Run), snapshotter.Status, nil
}
