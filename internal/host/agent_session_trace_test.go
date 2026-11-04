package host

import (
	"context"

	"log/slog"
)

type sessionTraceRunner struct{ *memoryRunner }

func (r *sessionTraceRunner) Close(ctx context.Context) error {
	slog.Info("test native close")
	return r.memoryRunner.Close(ctx)
}
