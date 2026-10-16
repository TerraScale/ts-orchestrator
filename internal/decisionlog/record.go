package decisionlog

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Recorder accepts decisions. Implementations must not block on I/O and
// must not fail the caller: Record returns the decision's ID even when the
// record is dropped.
type Recorder interface {
	Record(ctx context.Context, decision Decision) string
}

type recorderHolder struct{ recorder Recorder }

var defaultRecorder atomic.Pointer[recorderHolder]

// SetDefault installs the process-wide recorder used by Record and returns a
// function that restores the previous one. A nil recorder restores the
// structured-log fallback.
func SetDefault(recorder Recorder) (restore func()) {
	var holder *recorderHolder
	if recorder != nil {
		holder = &recorderHolder{recorder: recorder}
	}
	previous := defaultRecorder.Swap(holder)
	return func() { defaultRecorder.CompareAndSwap(holder, previous) }
}

// Default returns the installed recorder, or nil when records go to the log.
func Default() Recorder {
	if holder := defaultRecorder.Load(); holder != nil {
		return holder.recorder
	}
	return nil
}

// Record journals one decision with the process-wide recorder and returns
// its ID, so a caller can link later decisions to it with ParentID. It never
// blocks on the network and never fails; see the package documentation.
func Record(ctx context.Context, decision Decision) string {
	if recorder := Default(); recorder != nil {
		return recorder.Record(ctx, decision)
	}
	return LogRecorder{}.Record(ctx, decision)
}

// LogRecorder writes decisions to the default structured logger. It is the
// fallback before a Journal is installed, and the recorder of processes
// without a regional stream (one-shot CLI commands, hosts).
type LogRecorder struct {
	Logger *slog.Logger
}

// Record logs the decision and returns its ID.
func (recorder LogRecorder) Record(ctx context.Context, decision Decision) string {
	decision = decision.Normalize(time.Now())
	logger := recorder.Logger
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []slog.Attr{slog.String(observability.ComponentKey, "decision"), slog.Bool(observability.EventKey, true),
		slog.String("decision_id", decision.ID),
		slog.String("kind", string(decision.Kind)), slog.String("actor", decision.Actor.Slice),
		slog.String("subject", decision.Subject.String()), slog.String("status", string(decision.Status))}
	if decision.Region != "" {
		attrs = append(attrs, slog.String("region", decision.Region))
	}
	if decision.Reason != "" {
		attrs = append(attrs, slog.String("reason", decision.Reason))
	}
	if decision.ParentID != "" {
		attrs = append(attrs, slog.String("parent_id", decision.ParentID))
	}
	logger.LogAttrs(ctx, slog.LevelInfo, decision.Summary, attrs...)
	return decision.ID
}

// Discard drops every decision. Tests use it to silence the fallback log.
type Discard struct{}

// Record returns a fresh ID and keeps nothing.
func (Discard) Record(_ context.Context, decision Decision) string {
	if decision.ID != "" {
		return decision.ID
	}
	return NewID()
}
