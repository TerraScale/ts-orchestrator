package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/logs"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// logSummaryRetry is how often a controller retries opening the log summary
// stream while JetStream forms.
const logSummaryRetry = 5 * time.Second

// attachLogs starts this controller's log summary: the view, the stream that
// fills it, the query responder and GET /v1/logs. Nothing here can fail the
// controller: every step that cannot start is logged and skipped.
func (runtime *runtimeObservability) attachLogs(ctx context.Context, observed controllerObservation) {
	view := logs.NewView(runtime.cell)
	runtime.logView = view
	if runtime.server != nil {
		runtime.server.HandleAuthenticated("GET /v1/logs", logs.Handler(view))
	}
	go openLogStream(ctx, observed, runtime.cell, view)
	if _, err := logs.Serve(ctx, observed.nats.Conn(), runtime.cell, view); err != nil {
		slog.Warn("log query responder unavailable", observability.ComponentKey, "logs", "error", err)
	}
}

// openLogStream follows the log summary stream into view until ctx ends,
// retrying the open while the cell forms. A window is kept only when its node is
// registered with the NKey in its subject.
func openLogStream(ctx context.Context, observed controllerObservation, cell string, view *logs.View) {
	verify := func(ctx context.Context, node, nkey string) bool {
		if observed.hosts == nil {
			return false
		}
		key, err := observed.hosts.NodeKey(ctx, node)
		return err == nil && key == nkey
	}
	for attempt := 1; ; attempt++ {
		openCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		stream, err := logs.OpenStream(openCtx, observed.nats.JetStream(), cell, observed.replicas)
		cancel()
		if err == nil {
			stream.Follow(ctx, view, verify)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if attempt == 1 || attempt%12 == 0 {
			slog.Warn("log summary stream not open yet; retrying", observability.ComponentKey, "logs",
				"attempt", attempt, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(logSummaryRetry):
		}
	}
}
