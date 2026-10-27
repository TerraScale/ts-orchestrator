package edge

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// NetBird's combined server keeps all streaming and authenticated endpoints;
// only the upstream web application's paths are served by the edge itself.
func netbirdBackend(r *http.Request) bool {
	if isGRPC(r) {
		return true
	}
	for _, prefix := range []string{"/api", "/oauth2", "/relay", "/ws-proxy"} {
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			return true
		}
	}
	return false
}

func (e *Edge) reconcileNetBirdDashboard(ctx context.Context) {
	for {
		wait := 15 * time.Second
		if _, serves := e.port(netbirdHost); serves {
			if err := e.netbirdDashboard.Reconcile(ctx); err != nil {
				if ctx.Err() == nil {
					slog.WarnContext(ctx, "NetBird dashboard reconcile", "error", err)
				}
			} else {
				wait = 10 * time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
