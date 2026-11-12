package observability

import (
	"io"
	"strconv"
	"sync"
	"sync/atomic"
)

// Zero means no local edge, so workers do not report nonexistent listeners.
var edgeListeners [4]atomic.Int32
var edgeProtocols = [...]string{"http", "https", "postgres", "terrabase"}

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

type edgeResponseKey struct {
	protocol string
	code     int
}

var edgeResponses sync.Map

func RecordEdgeResponse(protocol string, code int) {
	if (protocol != "http" && protocol != "https") || code < 100 || code > 999 {
		return
	}
	key := edgeResponseKey{protocol, code}
	counter, ok := edgeResponses.Load(key)
	if !ok {
		counter, _ = edgeResponses.LoadOrStore(key, new(atomic.Uint64))
	}
	counter.(*atomic.Uint64).Add(1)
}

func WriteEdgeResponseMetrics(w io.Writer) {
	edgeResponses.Range(func(key, value any) bool {
		response := key.(edgeResponseKey)
		WriteCounter(w, Series("ts_orch_edge_responses_total", "protocol", response.protocol, "code", strconv.Itoa(response.code)), float64(value.(*atomic.Uint64).Load()))
		return true
	})
}

func WriteEdgeListenerMetrics(w io.Writer) {
	for i, name := range edgeProtocols {
		if state := edgeListeners[i].Load(); state != 0 {
			WriteGauge(w, Series("ts_orch_edge_listener_ready", "protocol", name), float64(state-1))
		}
	}
}
