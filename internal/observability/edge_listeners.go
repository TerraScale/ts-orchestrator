package observability

import (
	"io"
	"sync/atomic"
)

// Zero means no local edge, so workers do not report nonexistent listeners.
var edgeListeners [4]atomic.Int32
var edgeProtocols = [...]string{"http", "https", "postgres", "wire"}

func SetEdgeListenerReady(protocol string, ready bool) {
	for i, name := range edgeProtocols {
		if name == protocol {
			state := int32(1)
			if ready {
				state = 2
			}
			edgeListeners[i].Store(state)
		}
	}
}

// WriteEdgeListenerMetrics adds four fixed protocol series to host scrapes.
func WriteEdgeListenerMetrics(w io.Writer) {
	for i, name := range edgeProtocols {
		if state := edgeListeners[i].Load(); state != 0 {
			WriteGauge(w, Series("ts_orch_edge_listener_ready", "protocol", name), float64(state-1))
		}
	}
}
