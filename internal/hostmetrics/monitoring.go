package hostmetrics

import (
	"context"
	"net/http"
	"time"
)

func serveMonitoring(w http.ResponseWriter, r *http.Request) bool {
	address := ""
	switch r.URL.Path {
	case "/orchestrator/metrics":
		address = "127.0.0.1:9097"
	case "/monitoring/prometheus/metrics":
		address = "127.0.0.1:9090"
	case "/monitoring/alertmanager/metrics":
		address = "127.0.0.1:9093"
	case "/monitoring/relay/metrics":
		address = "127.0.0.1:9094"
	default:
		return false
	}
	select {
	case serviceSlots <- struct{}{}:
		defer func() { <-serviceSlots }()
	default:
		http.Error(w, "local metrics proxy busy", http.StatusServiceUnavailable)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	proxyService(ctx, w, address)
	return true
}
