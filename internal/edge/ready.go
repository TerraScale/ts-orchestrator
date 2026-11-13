package edge

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"
)

type ReadinessRoute struct {
	Host string
	Port int
	Path string
}

func (e *Edge) SetReadinessRoutes(routes []ReadinessRoute) { e.readyRoutes.Store(&routes) }

func listenerBit(protocol string) uint32 {
	return map[string]uint32{"http": 1, "https": 2, "postgres": 4, "terrabase": 8}[protocol]
}

func (e *Edge) ServeReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	inventory := e.Inventory(r.Context())
	missing := []string{}
	if e.listeners.Load() != 15 {
		missing = append(missing, "listeners unavailable")
	}
	if len(e.servedNames()) == 0 || e.readyRoutes.Load() == nil {
		missing = append(missing, "routes unavailable")
	}
	if e.bootstrapErr != nil {
		missing = append(missing, "bootstrap unavailable")
	}
	if e.bootstrap != nil {
		held, err := e.bootstrap.Ingress(r.Context())
		if err != nil || held != nil {
			missing = append(missing, "ingress unavailable")
		}
	}
	if router := e.regional.Load(); router != nil {
		router.ingressMu.Lock()
		draining := router.held != nil
		router.ingressMu.Unlock()
		if draining {
			missing = append(missing, "node draining")
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if routes := e.readyRoutes.Load(); routes != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for _, route := range *routes {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(route.Port))+route.Path, nil)
			if err != nil {
				missing = append(missing, "backend readiness route invalid")
				break
			}
			req.Host = route.Host
			response, err := client.Do(req)
			if err != nil {
				missing = append(missing, "backend unavailable")
				break
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				missing = append(missing, "backend not ready")
				break
			}
		}
	}
	for _, port := range *e.postgres.Load() {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			missing = append(missing, "postgres backend unavailable")
			break
		}
		conn.Close()
	}

	missing = append(missing, inventory.Errors...)
	ready := len(missing) == 0 && len(inventory.MissingNames) == 0
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(struct {
		Ready        bool     `json:"ready"`
		Missing      []string `json:"missing"`
		MissingNames []string `json:"missing_names"`
	}{ready, missing, inventory.MissingNames})
}
