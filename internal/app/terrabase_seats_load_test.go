package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// TestTerraBaseReleaseUnderLoadServesNoErrors is the TS-571 acceptance in
// process: clients send requests through a load balancer while a release
// restarts both seats, and not one request fails. The load balancer is
// driven by the real public_lb publisher and lb reconciler and routes like
// OCI's: never to a drained backend, and only to backends whose /readyz
// passes. Members finish in-flight requests when stopped, like TerraBase on
// SIGTERM, and serve again only after a catch-up delay. Hosts restart a
// member only when the seat records permit it, and the real seat controller
// drives the records. The same release without seat rollouts, every host
// restarting at once, does fail requests, so the test sees downtime.
func TestTerraBaseReleaseUnderLoadServesNoErrors(t *testing.T) {
	for _, seated := range []bool{true, false} {
		t.Run(map[bool]string{true: "seat rollout", false: "all at once"}[seated], func(t *testing.T) {
			failures, served := releaseUnderLoad(t, seated)
			t.Logf("served %d requests, %d failed", served, failures)
			if served < 100 {
				t.Fatalf("the load reached only %d requests", served)
			}
			if seated && failures != 0 {
				t.Fatalf("%d of %d requests failed during a seat rollout", failures, served)
			}
			if !seated && failures == 0 {
				t.Fatal("restarting every member at once failed no request: the test cannot see downtime")
			}
		})
	}
}

// leaderFence always holds a live lease.
type leaderFence struct{}

func (leaderFence) Current() authority.Snapshot {
	return authority.Snapshot{Leader: true, Ready: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}
func (leaderFence) Guard(context.Context, uint64) error { return nil }

func releaseUnderLoad(t *testing.T, seated bool) (failures, served int64) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	seats := []string{"gru-1-db-1", "gru-1-db-2"}
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	public := OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"}

	edge := newFakeEdge()
	members := map[string]*loadMember{}
	for i, node := range seats {
		member := &loadMember{}
		members[node] = member
		member.start(t, "127.0.0.1:0", 1)
		edge.route(fmt.Sprintf("10.251.0.2%d:9465", i+1), member.addr)
	}
	defer func() {
		for _, member := range members {
			member.stop()
		}
	}()
	go edge.check(ctx)
	proxy := &http.Server{Handler: edge}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve(listener) }()
	defer proxy.Close()

	// Seat records, the public_lb publisher and its reconciler.
	records := testSeatStore(t)
	key, err := (OciReconcileConfig{PublicLB: &public}).publicLBKey("GRU")
	if err != nil {
		t.Fatal(err)
	}
	desiredStore := ociresource.NewMemoryStore()
	owner := ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
	edge.tags = owner.Stamp(key, 0, "")
	publish := publicLBPass(desiredStore, leaderFence{}, key, public, func() map[string]WorkloadProfile { return profiles }, records.Drained)
	balancer := &ociresource.Controller[lb.Spec, lb.Observed]{Region: "GRU", Resource: lb.Reconciler{API: edge}, Store: desiredStore,
		Ownership: owner, Authority: leaderFence{}}
	wake := make(chan struct{}, 1)
	reconcile := func() {
		if err := publish.Run(ctx, 1); err != nil && ctx.Err() == nil {
			t.Logf("publish: %v", err)
		}
		if _, err := balancer.Reconcile(ctx, 1); err != nil && ctx.Err() == nil {
			t.Logf("reconcile: %v", err)
		}
	}
	reconcile()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-ticker.C:
			case <-wake:
			}
			reconcile()
		}
	}()

	hosts := &loadHosts{desired: map[string]uint64{}, reports: map[string]host.Report{}}
	for _, node := range seats {
		hosts.desired[node] = 1
		hosts.report(node, 1, "running")
		go hosts.run(ctx, t, node, members[node], records, seated)
	}
	if seated {
		controller := &seatrollout.Controller{Store: records, Fencer: leaderFence{}, Hosts: hosts,
			Seats:    func() ([]seatrollout.Member, error) { return terraBaseSeatMembers(profiles, &public) },
			Backends: lbSeatBackends(edge, public),
			Wake: func() {
				select {
				case wake <- struct{}{}:
				default:
				}
			},
			DrainGrace: 200 * time.Millisecond, Settle: 200 * time.Millisecond, Interval: 30 * time.Millisecond}
		go func() { _ = controller.Run(ctx) }()
	}

	await := func(what string, done func() bool) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); !done(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: edge %s, hosts %v", what, edge, hosts)
			}
		}
	}
	await("both seats serve", func() bool { return edge.serving() == 2 })

	// The load: clients send requests through the load balancer until told
	// to stop, and every answer other than 200 is a failure.
	stop := make(chan struct{})
	var clients sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second}
	for range 8 {
		clients.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				response, err := client.Get("http://" + listener.Addr().String() + "/work")
				if err == nil {
					_, _ = io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				atomic.AddInt64(&served, 1)
				if err != nil || response.StatusCode != http.StatusOK {
					atomic.AddInt64(&failures, 1)
				}
			}
		})
	}
	time.Sleep(300 * time.Millisecond)
	hosts.release(2)
	await("every seat runs the release and serves again", func() bool {
		drained, _ := records.Drained(ctx)
		return hosts.running(2) && len(drained) == 0 && edge.serving() == 2
	})
	time.Sleep(300 * time.Millisecond)
	close(stop)
	clients.Wait()
	return failures, served
}

func testSeatStore(t *testing.T) *seatrollout.Store {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := seatrollout.Open(t.Context(), js, 1, leaderFence{})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// loadMember is a TerraBase member: /work answers after a short request
// time, /readyz answers 200 once the member has caught up, and stopping it
// finishes the requests in flight, as TerraBase does on SIGTERM.
type loadMember struct {
	addr   string
	server *http.Server
	ready  atomic.Bool
}

func (m *loadMember) start(t *testing.T, addr string, generation uint64) {
	var listener net.Listener
	var err error
	for range 50 {
		if listener, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Errorf("member %s generation %d: %v", addr, generation, err)
		return
	}
	m.addr = listener.Addr().String()
	m.ready.Store(false)
	m.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" && !m.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/work" {
			time.Sleep(20 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = m.server.Serve(listener) }()
	time.AfterFunc(300*time.Millisecond, func() { m.ready.Store(true) })
}

func (m *loadMember) stop() {
	m.ready.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = m.server.Shutdown(ctx)
}

// loadHosts holds each seat's desired generation and report, and runs each
// seat's host: it restarts the member into a new generation only when the
// seat records permit it (or always, without seat rollouts).
type loadHosts struct {
	mu      sync.Mutex
	desired map[string]uint64
	reports map[string]host.Report
}

func (h *loadHosts) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []host.Desired
	for node, generation := range h.desired {
		out = append(out, host.Desired{Node: node, Role: role, Digest: "d" + strconv.FormatUint(generation, 10), Generation: generation})
	}
	return out, nil
}

func (h *loadHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []host.HostStatus
	for _, report := range h.reports {
		out = append(out, host.HostStatus{Reports: []host.Report{report}})
	}
	return out, nil
}

func (h *loadHosts) report(node string, generation uint64, state string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reports[node] = host.Report{Node: node, Role: terrabase.Role, Digest: "d" + strconv.FormatUint(generation, 10),
		Generation: generation, State: state, ObservedAt: time.Now()}
}

func (h *loadHosts) release(generation uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for node := range h.desired {
		h.desired[node] = generation
	}
}

func (h *loadHosts) running(generation uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, report := range h.reports {
		if report.Generation != generation || report.State != "running" {
			return false
		}
	}
	return true
}

func (h *loadHosts) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return fmt.Sprint(h.reports)
}

func (h *loadHosts) run(ctx context.Context, t *testing.T, node string, member *loadMember, records *seatrollout.Store, seated bool) {
	running := uint64(1)
	for ctx.Err() == nil {
		time.Sleep(30 * time.Millisecond)
		h.mu.Lock()
		desired := h.desired[node]
		h.mu.Unlock()
		if desired == running {
			h.report(node, running, map[bool]string{true: "running", false: "starting"}[member.ready.Load()])
			continue
		}
		if seated {
			granted, err := records.Granted(ctx, node, host.Desired{Role: terrabase.Role, Generation: desired})
			if err != nil || !granted {
				h.report(node, desired, "waiting")
				continue
			}
		}
		addr := member.addr
		member.stop()
		member.start(t, addr, desired)
		running = desired
		h.report(node, running, "starting")
	}
}

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

func newFakeEdge() *fakeEdge {
	return &fakeEdge{backends: map[string]*edgeBackend{}, targets: map[string]string{}}
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
		out = append(out, lb.Backend{IP: ip, Port: number, Drain: backend.drain})
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
