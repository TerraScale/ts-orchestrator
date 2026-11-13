package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type ReadinessRoute struct {
	Host string
	Port int
	Path string
}

func (e *Edge) SetReadinessRoutes(routes []ReadinessRoute) {
	e.readyRoutes.Store(&routes)
}

func listenerBit(protocol string) uint32 {
	return map[string]uint32{"http": 1, "https": 2, "postgres": 4, "terrabase": 8}[protocol]
}

func (e *Edge) serveReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_, missing, missingNames := e.readiness()
	if len(missing) > 0 || len(missingNames) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(struct {
		Ready        bool     `json:"ready"`
		Missing      []string `json:"missing"`
		MissingNames []string `json:"missing_names"`
	}{len(missing) == 0 && len(missingNames) == 0, missing, missingNames})
}

func (e *Edge) readiness() (bool, []string, []string) {
	verdict := e.readyStatus.Load()
	missing := []string{}
	if verdict == nil || !verdict.ok || time.Since(verdict.at) > 10*time.Second {
		missing = append(missing, "edge readiness unavailable")
	}
	missing = append(missing, verdict.conditions...)
	missingNames := []string{}
	for _, name := range e.servedNames() {
		if e.certMissing(name) {
			missingNames = append(missingNames, name)
		}
	}
	return len(missing) == 0 && len(missingNames) == 0, missing, missingNames
}

func (e *Edge) certMissing(name string) bool {
	if _, err := e.certs.load(name); err == nil {
		return false
	}
	seen, _ := e.certSeen.Load(name)
	grace, ok := seen.(time.Time)
	if !ok || time.Since(grace) < issueTTL {
		return false
	}
	return true
}

func (e *Edge) ready(ctx context.Context) ([]string, error) {
	conditions := []string{}
	if e.listeners.Load() != 15 {
		conditions = append(conditions, "listeners unavailable")
	}
	if e.bootstrapErr != nil {
		return conditions, e.bootstrapErr
	}
	held, err := e.bootstrap.Ingress(ctx)
	if err != nil {
		return conditions, err
	}
	if held != nil {
		conditions = append(conditions, "ingress held")
	} else if router := e.regional.Load(); router != nil {
		router.ingressMu.Lock()
		draining := router.held != nil
		router.ingressMu.Unlock()
		if draining {
			conditions = append(conditions, "node draining")
		}
	}
	web, postgres := *e.routes.Load(), *e.postgres.Load()
	if len(web)+len(postgres) == 0 {
		conditions = append(conditions, "routes unavailable")
	}
	for _, name := range e.servedNames() {
		if _, err := e.certs.load(name); err != nil && !e.certMissing(name) {
			conditions = append(conditions, "certificate "+name+" invalid")
		}
	}
	routes := *e.readyRoutes.Load()
	if len(routes) == 0 {
		conditions = append(conditions, "readiness routes unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, route := range routes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(route.Port))+route.Path, nil)
		if err != nil {
			return conditions, err
		}
		req.Host = route.Host
		resp, err := client.Do(req)
		if err != nil {
			conditions = append(conditions, "backend unavailable")
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conditions = append(conditions, "backend not ready")
		}
	}
	for _, port := range postgres {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			conditions = append(conditions, "postgres backend unavailable")
			continue
		}
		conn.Close()
	}
	return conditions, nil
}

type readinessVerdict struct {
	ok         bool
	at         time.Time
	conditions []string
}

func (e *Edge) reconcileReadiness(ctx context.Context) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		conditions, err := e.ready(bounded)
		if err != nil {
			conditions = append(conditions, err.Error())
		}
		cancel()
		ok := len(conditions) == 0
		previous := e.readyStatus.Swap(&readinessVerdict{ok, time.Now(), conditions})
		if previous == nil || previous.ok != ok {
			slog.InfoContext(ctx, "edge readiness changed", "ready", ok)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (e *Edge) serveCertificateMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	e.certs.cache.failures.Range(func(key, value any) bool {
		name, variant := certificateVariant(key.(string))
		observability.WriteCounter(w, observability.Series("ts_orch_edge_certificate_order_failures_total", "name", name, "variant", variant), float64(value.(*atomic.Uint64).Load()))
		return true
	})
	e.certs.cache.memory.Range(func(key, value any) bool {
		name, variant := certificateVariant(key.(string))
		remaining := time.Until(value.(cachedCertificate).cert.Leaf.NotAfter).Seconds()
		_, _ = fmt.Fprintf(w, "%s %g\n", observability.Series("ts_orch_edge_certificate_expiry_seconds", "name", name, "variant", variant), remaining)
		return true
	})
	names := map[string]bool{}
	e.certs.cache.unsupported.Range(func(key, _ any) bool { names[certificateName(key.(string))] = true; return true })
	_, _ = fmt.Fprintf(w, "ts_orch_edge_certificate_blocked_names %d\n", len(names))
	count := 0
	e.certs.cache.unsupported.Range(func(_, _ any) bool { count++; return true })
	_, _ = io.WriteString(w, fmt.Sprintf("ts_orch_edge_certificate_unsupported %d\n", count))
}
