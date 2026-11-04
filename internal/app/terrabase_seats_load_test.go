package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

// fakeEdge is an OCI flexible load balancer in memory: the lb.API the
// reconciler drives, and the proxy it is. It routes round-robin to
// backends that are not drained and whose /readyz passed, marks a backend
// unhealthy after three failed checks, and keeps checking drained ones.
type fakeEdge struct {
	mu       sync.Mutex
	tags     ociresource.Tags
	backends map[string]*edgeBackend
	targets  map[string]string
	next     int
}

type edgeBackend struct {
	drain    bool
	healthy  bool
	failures int
}

// route says where the backend ip:port listens on this machine.
func (e *fakeEdge) route(backend, addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.targets[backend] = addr
}

func (e *fakeEdge) serving() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, backend := range e.backends {
		if !backend.drain && backend.healthy {
			n++
		}
	}
	return n
}

func (e *fakeEdge) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var parts []string
	for key, backend := range e.backends {
		parts = append(parts, fmt.Sprintf("%s drain=%v healthy=%v", key, backend.drain, backend.healthy))
	}
	slices.Sort(parts)
	return fmt.Sprint(parts)
}

func (e *fakeEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	keys := make([]string, 0, len(e.backends))
	for key, backend := range e.backends {
		if !backend.drain && backend.healthy {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	var target string
	if len(keys) > 0 {
		target = e.targets[keys[e.next%len(keys)]]
		e.next++
	}
	e.mu.Unlock()
	if target == "" {
		http.Error(w, "no healthy backend", http.StatusServiceUnavailable)
		return
	}
	httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: target}).ServeHTTP(w, r)
}

func (e *fakeEdge) check(ctx context.Context) {
	client := &http.Client{Timeout: 200 * time.Millisecond}
	for ctx.Err() == nil {
		time.Sleep(50 * time.Millisecond)
		e.mu.Lock()
		keys := make([]string, 0, len(e.backends))
		for key := range e.backends {
			keys = append(keys, key)
		}
		e.mu.Unlock()
		for _, key := range keys {
			e.mu.Lock()
			target := e.targets[key]
			e.mu.Unlock()
			response, err := client.Get("http://" + target + "/readyz")
			ok := err == nil && response.StatusCode == http.StatusOK
			if err == nil {
				response.Body.Close()
			}
			e.mu.Lock()
			if backend := e.backends[key]; backend != nil {
				if ok {
					backend.healthy, backend.failures = true, 0
				} else if backend.failures++; backend.failures >= 3 {
					backend.healthy = false
				}
			}
			e.mu.Unlock()
		}
	}
}

func (e *fakeEdge) GetLoadBalancer(context.Context, string) (lb.LoadBalancer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return lb.LoadBalancer{ID: publicLBID, Tags: e.tags}, nil
}

func (e *fakeEdge) ListBackends(context.Context, string, string) ([]lb.Backend, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []lb.Backend
	for key, backend := range e.backends {
		ip, port, _ := net.SplitHostPort(key)
		number, _ := strconv.Atoi(port)
		// OCI reports every managed backend at weight 1, never as a backup.
		out = append(out, lb.Backend{IP: ip, Port: number, Drain: backend.drain}.Shaped(1, false))
	}
	return out, nil
}

func (e *fakeEdge) set(backend lb.Backend, drain bool) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := backend.IP + ":" + strconv.Itoa(backend.Port)
	if e.backends[key] == nil {
		e.backends[key] = &edgeBackend{}
	}
	e.backends[key].drain = drain
	return "wr", nil
}

func (e *fakeEdge) CreateBackend(_ context.Context, _, _ string, backend lb.Backend) (string, error) {
	return e.set(backend, backend.Drain)
}

func (e *fakeEdge) UpdateBackend(_ context.Context, _, _ string, backend lb.Backend) (string, error) {
	return e.set(backend, backend.Drain)
}

func (e *fakeEdge) DeleteBackend(_ context.Context, _, _, name string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.backends, name)
	return "wr", nil
}

func (e *fakeEdge) UnhealthyBackends(context.Context, string, string) (map[string]bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]bool{}
	for key, backend := range e.backends {
		if !backend.healthy {
			out[key] = true
		}
	}
	return out, nil
}

func (e *fakeEdge) UpdateTags(_ context.Context, _, _ string, tags ociresource.Tags) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tags = tags
	return "wr", nil
}

func (e *fakeEdge) WaitWorkRequest(context.Context, string) error { return nil }

var _ lb.API = (*fakeEdge)(nil)
