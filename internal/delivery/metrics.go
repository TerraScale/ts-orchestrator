package delivery

import (
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
)

// Metrics is the delivery slice's metric set. Pending intents are visible as
// the TS_DELIVERY_WORKER consumer's num_pending in the NATS view.
var Metrics = metrics.NewSet()

var (
	intentsAcknowledged = Metrics.NewCounter(observability.Series(
		observability.MetricPrefix+"delivery_intents_total", "result", "acknowledged"))
	intentsDeferred = Metrics.NewCounter(observability.Series(
		observability.MetricPrefix+"delivery_intents_total", "result", "deferred"))
	transportRetries = Metrics.NewCounter(observability.MetricPrefix + "delivery_transport_retries_total")
	lastAcknowledged atomic.Int64
)

func recordAcknowledged() {
	intentsAcknowledged.Inc()
	lastAcknowledged.Store(time.Now().UnixNano())
}

// View returns this process's delivery processing counters.
func View() observability.DeliveryView {
	view := observability.DeliveryView{Acknowledged: intentsAcknowledged.Get(), Deferred: intentsDeferred.Get(),
		TransportRetries: transportRetries.Get()}
	if at := lastAcknowledged.Load(); at > 0 {
		view.LastAckAt = time.Unix(0, at).UTC()
	}
	return view
}
