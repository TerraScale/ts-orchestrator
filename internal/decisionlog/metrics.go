package decisionlog

import (
	"sync/atomic"

	"github.com/VictoriaMetrics/metrics"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// Metrics is the decision journal's metric set.
var Metrics = metrics.NewSet()

var (
	recordedTotal  = Metrics.NewCounter(observability.MetricPrefix + "decisions_recorded_total")
	publishedTotal = Metrics.NewCounter(observability.MetricPrefix + "decisions_published_total")
	droppedSeries  = func(reason string) *metrics.Counter {
		return Metrics.NewCounter(observability.Series(observability.MetricPrefix+"decisions_dropped_total",
			"reason", reason))
	}
	// droppedQueueFull counts records refused because the publish queue
	// was full; droppedPublish counts records the stream never accepted.
	droppedQueueFull = droppedSeries("queue_full")
	droppedPublish   = droppedSeries("publish_failed")
	publishRetries   = Metrics.NewCounter(observability.MetricPrefix + "decisions_publish_retries_total")
	ingestedTotal    = Metrics.NewCounter(observability.MetricPrefix + "decisions_ingested_total")
	queueDepth       atomic.Int64
	_                = Metrics.NewGauge(observability.MetricPrefix+"decisions_queue_depth", func() float64 {
		return float64(queueDepth.Load())
	})
)
