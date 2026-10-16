package app

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// hostMetricHistory isolates replayed regional resources from member snapshots.
type hostMetricHistory struct {
	local, shared  *observability.History
	stream         atomic.Pointer[observability.HostMetricStream]
	failures       atomic.Uint64
	droppedSamples atomic.Uint64
}

func (h *hostMetricHistory) Range(query observability.HistoryQuery) observability.HistoryResult {
	if !observability.IsHostMetric(query.Metric) {
		return h.local.Range(query)
	}
	stream := h.stream.Load()
	pending := stream == nil || !stream.CaughtUp()
	result := h.shared.Range(query)
	result.Pending = pending || !stream.CaughtUp()
	result.Incomplete = h.shared.Stats().Dropped > 0
	if stream != nil {
		result.Incomplete = result.Incomplete || stream.ArchiveIncomplete() || stream.ReplayFailures() > 0
	}
	return result
}

func (h *hostMetricHistory) Latest(metric string, labels map[string]string) map[string]float64 {
	if observability.IsHostMetric(metric) {
		return h.shared.Latest(metric, labels)
	}
	return h.local.Latest(metric, labels)
}

func (h *hostMetricHistory) Metrics() []string {
	names := append(h.local.Metrics(), h.shared.Metrics()...)
	slices.Sort(names)
	return slices.Compact(names)
}

func (h *hostMetricHistory) writeMetrics(w io.Writer) {
	ready := false
	stream := h.stream.Load()
	if stream != nil {
		ready = stream.CaughtUp()
	}
	var replayDropped uint64
	if h.shared != nil {
		replayDropped = h.shared.Stats().Dropped
	}
	var replayFailures uint64
	var archiveIncomplete bool
	if stream != nil {
		replayFailures = stream.ReplayFailures()
		archiveIncomplete = stream.ArchiveIncomplete()
	}
	ready = ready && !archiveIncomplete && replayDropped == 0 && replayFailures == 0
	fmt.Fprintf(w, "ts_orch_host_history_replay_ready %g\nts_orch_host_history_failures_total %d\nts_orch_host_history_dropped_samples_total %d\nts_orch_host_history_replay_dropped_samples_total %d\nts_orch_host_history_archive_incomplete %g\n",
		observability.Bool(ready), h.failures.Load()+replayFailures, h.droppedSamples.Load(), replayDropped, observability.Bool(archiveIncomplete))
}

// withoutHostMetricSamples keeps member snapshots from masking regional replay.
func withoutHostMetricSamples(collect func(context.Context) []observability.Sample) func(context.Context) []observability.Sample {
	return func(ctx context.Context) []observability.Sample {
		samples := collect(ctx)
		return slices.DeleteFunc(samples, func(sample observability.Sample) bool {
			return observability.IsHostMetric(sample.Metric)
		})
	}
}

func (t *hostTelemetry) archiveBatch(at time.Time) observability.HostMetricBatch {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.current() {
		return observability.HostMetricBatch{}
	}
	samples := hostLoadSamples(t.load)
	samples = slices.DeleteFunc(samples, func(sample observability.Sample) bool {
		return !observability.IsHostMetric(sample.Metric)
	})
	// Keep the same series first when a region exceeds archive capacity.
	slices.SortFunc(samples, func(a, b observability.Sample) int {
		if order := strings.Compare(a.Labels[0].Value, b.Labels[0].Value); order != 0 {
			return order
		}
		if order := cmp.Compare(len(a.Labels), len(b.Labels)); order != 0 {
			return order
		}
		if len(a.Labels) >= 2 {
			if order := strings.Compare(a.Labels[1].Value, b.Labels[1].Value); order != 0 {
				return order
			}
		}
		return strings.Compare(a.Metric, b.Metric)
	})
	return observability.HostMetricBatch{Version: observability.HostMetricBatchVersion, At: at.UTC().Truncate(observability.HostMetricInterval),
		Epoch: t.epoch, Samples: samples}
}

type hostMetricPublisher interface {
	Publish(context.Context, observability.HostMetricBatch) (bool, error)
}

// publishHostMetricBatch never feeds replay into scaling or lifecycle evidence.
func publishHostMetricBatch(ctx context.Context, publisher hostMetricPublisher, load *hostTelemetry,
	batch observability.HostMetricBatch,
) (uint64, bool, error) {
	bounded, dropped, err := observability.BoundHostMetricBatch(batch)
	if err != nil {
		return 0, false, err
	}
	if err := load.fencer.Guard(ctx, bounded.Epoch); err != nil {
		return 0, false, err
	}
	confirmed, err := publisher.Publish(ctx, bounded)
	return dropped, confirmed, err
}

func (h *hostMetricHistory) run(ctx context.Context, js jetstream.JetStream, cell string, replicas int,
	load *hostTelemetry, events *observability.EventBus,
) {
	for attempt := 1; ctx.Err() == nil; attempt++ {
		openCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		stream, err := observability.OpenHostMetricStream(openCtx, js, cell, replicas)
		cancel()
		if err == nil {
			h.stream.Store(stream)
			if load != nil {
				go h.publish(ctx, stream, load, events)
			}
			_ = stream.Tail(ctx, h.shared)
			return
		}
		h.failures.Add(1)
		if attempt == 1 || attempt%12 == 0 {
			events.Publish(observability.Event{Level: "WARN", Component: "observability",
				Message: "Shared host metric history is unavailable", Attrs: map[string]string{"error": err.Error()}})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(journalOpenRetry):
		}
	}
}

func (h *hostMetricHistory) publish(ctx context.Context, stream hostMetricPublisher, load *hostTelemetry,
	events *observability.EventBus,
) {
	ticker := time.NewTicker(observability.DefaultHistoryInterval)
	defer ticker.Stop()
	var state hostMetricPublication
	for ctx.Err() == nil {
		h.publishStep(ctx, stream, load, events, &state, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type hostMetricPublication struct {
	published             time.Time
	pending               observability.HostMetricBatch
	failing, limited, gap bool
}

func (h *hostMetricHistory) publishStep(ctx context.Context, stream hostMetricPublisher, load *hostTelemetry,
	events *observability.EventBus, state *hostMetricPublication, at time.Time,
) {
	slot := at.UTC().Truncate(observability.HostMetricInterval)
	if !slot.After(state.published) {
		return
	}
	current := load.archiveBatch(slot)
	if len(current.Samples) == 0 {
		return
	}
	hadPending := !state.pending.At.IsZero()
	if state.pending.At != slot || state.pending.Epoch != current.Epoch {
		// An abandoned lost-ACK batch may exist in the store; coverage is uncertain.
		state.gap = state.gap || hadPending
		current.Incomplete = state.gap
		state.pending = current
	}
	publishCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	dropped, confirmed, err := publishHostMetricBatch(publishCtx, stream, load, state.pending)
	cancel()
	if err != nil {
		h.failures.Add(1)
		if !state.failing {
			events.Publish(observability.Event{Level: "WARN", Component: "observability",
				Message: "Host metric batch was not retained", Attrs: map[string]string{"error": err.Error()}})
		}
		state.failing = true
		return
	}
	if confirmed {
		if state.pending.Incomplete {
			state.gap = false
		}
		h.droppedSamples.Add(dropped)
		if dropped > 0 && !state.limited {
			events.Publish(observability.Event{Level: "WARN", Component: "observability",
				Message: "Host metric archive omitted samples at capacity", Attrs: map[string]string{"dropped_samples": fmt.Sprint(dropped)}})
		} else if dropped == 0 && state.limited {
			events.Publish(observability.Event{Level: "INFO", Component: "observability", Message: "Host metric archive fits all current samples"})
		}
		state.limited = dropped > 0
	} else {
		// A competing writer's batch cannot confirm an earlier failed attempt.
		state.gap = state.gap || hadPending
	}
	state.published, state.pending = slot, observability.HostMetricBatch{}
	if state.failing {
		events.Publish(observability.Event{Level: "INFO", Component: "observability", Message: "Host metric retention resumed"})
	}
	state.failing = false
}
