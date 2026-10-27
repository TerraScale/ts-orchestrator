package edge

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetBirdDashboardPreservesBackendRoutes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer backend.Close()
	e := New(t.TempDir())
	e.SetRoutes(map[string]int{netbirdHost: backend.Listener.Addr().(*net.TCPAddr).Port}, nil)
	for _, target := range []string{"/api", "/api/peers", "/oauth2", "/oauth2/.well-known/openid-configuration", "/relay", "/relay/peer", "/ws-proxy", "/ws-proxy/management", "/ws-proxy/signal"} {
		w := httptest.NewRecorder()
		e.serveHTTPS(w, httptest.NewRequest(http.MethodGet, "https://"+netbirdHost+target, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("backend %s status %d", target, w.Code)
		}
	}
	for _, target := range []string{"/", "/peers", "/nb-auth", "/nb-silent-auth", "/_next/static/app.js"} {
		w := httptest.NewRecorder()
		e.serveHTTPS(w, httptest.NewRequest(http.MethodGet, "https://"+netbirdHost+target, nil))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "dashboard is preparing") {
			t.Errorf("UI %s status %d", target, w.Code)
		}
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Error("UI missing edge security headers")
		}
	}
	for _, target := range []string{"/management.ManagementService/Sync", "/signalexchange.SignalExchange/Connect"} {
		r := httptest.NewRequest(http.MethodPost, "https://"+netbirdHost+target, nil)
		r.ProtoMajor = 2
		r.Header.Set("Content-Type", "application/grpc+proto")
		if !netbirdBackend(r) {
			t.Errorf("gRPC %s routed to UI", target)
		}
	}
}
