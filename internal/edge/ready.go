package edge

import (
	"context"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
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
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	verdict := e.readyStatus.Load()
	if verdict == nil || !verdict.ok || time.Since(verdict.at) > 10*time.Second {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (e *Edge) ready(ctx context.Context) error {
	if e.listeners.Load() != 15 {
		return fmt.Errorf("listeners unavailable")
	}
	if e.bootstrapErr != nil {
		return e.bootstrapErr
	}
	held, err := e.bootstrap.Ingress(ctx)
	if err != nil {
		return err
	}
	if held != nil {
		return fmt.Errorf("ingress held")
	}
	if router := e.regional.Load(); router != nil {
		router.ingressMu.Lock()
		draining := router.held != nil
		router.ingressMu.Unlock()
		if draining {
			return fmt.Errorf("node draining")
		}
	}
	web, postgres := *e.routes.Load(), *e.postgres.Load()
	if len(web)+len(postgres) == 0 {
		return fmt.Errorf("routes unavailable")
	}
	for _, names := range []map[string]int{web, postgres} {
		for name := range names {
			seen, _ := e.certSeen.Load(name)
			if _, err := e.certs.load(name); err != nil && seen != nil && time.Since(seen.(time.Time)) >= issueTTL {
				return err
			}
		}
	}
	routes := *e.readyRoutes.Load()
	if len(routes) == 0 {
		return fmt.Errorf("readiness routes unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, route := range routes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(route.Port))+route.Path, nil)
		if err != nil {
			return err
		}
		req.Host = route.Host
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("local backend unavailable")
		}
	}
	for _, port := range postgres {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return err
		}
		conn.Close()
	}
	return nil
}

type readinessVerdict struct {
	ok bool
	at time.Time
}

func (e *Edge) reconcileReadiness(ctx context.Context) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := e.ready(bounded)
		cancel()
		previous := e.readyStatus.Swap(&readinessVerdict{err == nil, time.Now()})
		if previous == nil || previous.ok != (err == nil) {
			slog.InfoContext(ctx, "edge readiness changed", "ready", err == nil)
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
