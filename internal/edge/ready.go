package edge

import (
	"context"
	"fmt"
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
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := e.ready(ctx); err != nil {
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
	for name := range web {
		if _, err := e.certs.load(ctx, name); err != nil {
			return err
		}
	}
	for name := range postgres {
		if _, err := e.certs.load(ctx, name); err != nil {
			return err
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
