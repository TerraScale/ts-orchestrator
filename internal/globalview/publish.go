package globalview

import (
	"context"
	"log/slog"
	"time"

	json "encoding/json/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

// Publish publishes build(ctx) on protocol.RegionRollupSubject(cell) every
// PublishEvery while leading() is true and hands it to view. It returns when
// ctx ends.
func Publish(ctx context.Context, conn *nats.Conn, cell string, leading func() bool, build func(context.Context) Rollup, view *View) {
	ticker := time.NewTicker(PublishEvery)
	defer ticker.Stop()
	for {
		if leading() {
			publishOnce(ctx, conn, cell, build, view)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func publishOnce(ctx context.Context, conn *nats.Conn, cell string, build func(context.Context) Rollup, view *View) {
	buildCtx, cancel := context.WithTimeout(ctx, PublishEvery)
	defer cancel()
	r := build(buildCtx)
	data, err := json.Marshal(r)
	if err != nil {
		slog.Warn("dashboard rollup not encoded", observability.ComponentKey, "globalview", "cell", cell, "error", err)
		return
	}
	if len(data) > MaxBytes {
		slog.Warn("dashboard rollup too large, not published", observability.ComponentKey, "globalview", "cell", cell, "bytes", len(data))
		return
	}
	if err := conn.Publish(protocol.RegionRollupSubject(cell), data); err != nil {
		slog.Warn("dashboard rollup not published", observability.ComponentKey, "globalview", "cell", cell, "error", err)
	}
	view.Accept(r)
}
