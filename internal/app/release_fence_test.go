package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func fenceKV(t *testing.T) jetstream.KeyValue {
	t.Helper()
	kv, _, _ := fenceBroker(t)
	return kv
}

func fenceBroker(t *testing.T) (jetstream.KeyValue, *nats.Conn, jetstream.JetStream) {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "TS_RELEASE_CHANNEL"})
	if err != nil {
		t.Fatal(err)
	}
	return kv, conn, js
}

// fenceLB is a load balancer whose backends report healthy unless listed in
// down. It fails the test when a set has no backend in rotation.
type fenceLB struct {
	t    *testing.T
	mu   sync.Mutex
	sets map[string][]lb.Backend
	down map[string]bool
	log  []string
	ids  []string // the load balancer of each update
}

func (f *fenceLB) ListBackends(_ context.Context, _, set string) ([]lb.Backend, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sets[set]), nil
}

func (f *fenceLB) UnhealthyBackends(_ context.Context, _, set string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	unhealthy := map[string]bool{}
	for _, backend := range f.sets[set] {
		if f.down[backend.Name()] {
			unhealthy[backend.Name()] = true
		}
	}
	return unhealthy, nil
}

func (f *fenceLB) UpdateBackend(_ context.Context, id, set string, backend lb.Backend) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ids = append(f.ids, id)
	if !backend.Serving() {
		// Taking a backend out must leave another node's healthy one.
		alternative := false
		for _, other := range f.sets[set] {
			alternative = alternative || other.IP != backend.IP && other.Serving() && !f.down[other.Name()]
		}
		if !alternative {
			f.t.Errorf("took %s out of %s without a healthy backend on another node", backend.Name(), set)
		}
	}
	serving, state := 0, "active"
	for i, current := range f.sets[set] {
		if current.Name() == backend.Name() {
			// The fence drains, then sets the drained backend offline.
			switch {
			case backend.Serving():
			case current.Drain:
				state = "offline"
			default:
				state = "drain"
			}
			f.sets[set][i] = backend
		}
		if f.sets[set][i].Serving() {
			serving++
		}
	}
	f.log = append(f.log, set+" "+backend.Name()+" "+state)
	if serving == 0 {
		f.t.Errorf("set %s has no backend in rotation after %s", set, f.log[len(f.log)-1])
	}
	return "wr", nil
}

func (f *fenceLB) WaitWorkRequest(context.Context, string) error { return nil }
func (f *fenceLB) GetLoadBalancer(context.Context, string) (lb.LoadBalancer, error) {
	return lb.LoadBalancer{}, nil
}
func (f *fenceLB) CreateBackend(_ context.Context, _, set string, backend lb.Backend) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets[set] = append(f.sets[set], backend)
	f.log = append(f.log, set+" "+backend.Name()+" created")
	return "wr", nil
}

func (f *fenceLB) DeleteBackend(_ context.Context, _, set, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets[set] = slices.DeleteFunc(f.sets[set], func(b lb.Backend) bool { return b.Name() == name })
	f.log = append(f.log, set+" "+name+" deleted")
	return "wr", nil
}
func (f *fenceLB) UpdateTags(context.Context, string, string, ociresource.Tags) (string, error) {
	return "", errors.New("unused")
}

// fenceCell has one desired replica of role per node at release. A node
// restarts into it as soon as the restart gate grants it; until then it
// serves the previous release. Nodes in broken fail the release.
type fenceCell struct {
	t           *testing.T
	gate        func(context.Context, string, host.Desired) (bool, error)
	lb          *fenceLB
	nodes       []string
	release     uint64
	role        string
	environment string
	digests     map[uint64]string
	broken      map[string]bool
	// stalled nodes restart but report nothing, like a replica the
	// reconciler is about to withdraw.
	stalled map[string]bool
	// unfenced lets nodes restart while their backends serve: the cell's
	// fence moved or was dropped.
	unfenced bool
	// restarted, when set, runs as a node first restarts; it may change
	// nodes (the cell lock is held).
	restarted func(node string)
	mu        sync.Mutex
	restarts  []string
}

func (c *fenceCell) ListDesired(context.Context, string) ([]host.Desired, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var desired []host.Desired
	for _, node := range c.nodes {
		desired = append(desired, host.Desired{Node: node, Role: c.role, Generation: c.release << 24})
	}
	return desired, nil
}

func (c *fenceCell) ListHosts(ctx context.Context) ([]host.HostStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var statuses []host.HostStatus
	for _, node := range c.nodes {
		desired := host.Desired{Node: node, Role: c.role, Generation: c.release << 24}
		granted, err := c.gate(ctx, node, desired)
		if err != nil {
			return nil, err
		}
		report := host.Report{Node: node, Role: c.role, Environment: c.environment, Generation: (c.release - 1) << 24, State: "running",
			ObservedAt: time.Now()}
		if granted {
			if !slices.Contains(c.restarts, node) {
				c.restarts = append(c.restarts, node)
				if c.restarted != nil {
					defer c.restarted(node)
				}
				// A node restarts only while none of its backends serves.
				c.lb.mu.Lock()
				for set, backends := range c.lb.sets {
					for _, backend := range backends {
						if !c.unfenced && backend.IP == fenceAddresses[node] && backend.Serving() {
							c.t.Errorf("%s restarted while its %s backend serves", node, set)
						}
					}
				}
				c.lb.mu.Unlock()
			}
			if c.stalled[node] {
				continue
			}
			report.Generation, report.State = desired.Generation, "running"
			if c.broken[node] {
				report.State = "failed"
			}
		}
		report.Digest = c.digests[releaseOf(report.Generation)]
		statuses = append(statuses, host.HostStatus{Reports: []host.Report{report}})
	}
	return statuses, nil
}

// fenceLease is the leader's lease; Guard fails once lost.
type fenceLease struct {
	mu   sync.Mutex
	lost bool
	// lose, when set, loses the lease after that many guards.
	lose, guards int
	netbird      authority.LogEntry
}

func (l *fenceLease) Current() authority.Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: !l.lost, Epoch: 3, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (l *fenceLease) Guard(_ context.Context, epoch uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.guards++
	if l.lose > 0 && l.guards >= l.lose {
		l.lost = true
	}
	if l.lost || epoch != 3 {
		return authority.ErrFenced
	}
	return nil
}

var fenceAddresses = map[string]string{"gru-1-ctl-1": "10.0.0.11", "gru-1-ctl-2": "10.0.0.12", "gru-1-ctl-3": "10.0.0.13"}

func newFenceTest(t *testing.T) (*releaseFence, *fenceCell, *fenceLB, jetstream.KeyValue, delivery.Intent) {
	t.Helper()
	kv := fenceKV(t)
	return newFenceTestWithStore(t, kv)
}

func newFenceTestWithStore(t *testing.T, kv jetstream.KeyValue) (*releaseFence, *fenceCell, *fenceLB, jetstream.KeyValue, delivery.Intent) {
	t.Helper()
	balancer := &fenceLB{t: t, down: map[string]bool{}, sets: map[string][]lb.Backend{}}
	for _, node := range []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"} {
		balancer.sets["terrabase"] = append(balancer.sets["terrabase"], lb.Backend{IP: fenceAddresses[node], Port: 9465})
		// gru-1-ctl-1's ts-auth backend is out of rotation already.
		balancer.sets["ts-auth"] = append(balancer.sets["ts-auth"],
			lb.Backend{IP: fenceAddresses[node], Port: 8080}.Fenced(node == "gru-1-ctl-1", node == "gru-1-ctl-1"))
	}
	spec := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x",
		BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465, MinServing: 1}, {Name: "ts-auth", Port: 8080, MinServing: 1}}}
	cell := &fenceCell{t: t, gate: releaseGate(kv), lb: balancer, nodes: []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}, release: 7, role: "ts-auth",
		broken: map[string]bool{}}
	fence := &releaseFence{kv: kv, hosts: cell, fencer: &fenceLease{},
		spec: func() (*cellspec.ReleaseFence, map[string]string) { return spec, fenceAddresses },
		open: func(context.Context) (lb.API, error) { return balancer, nil },
		sleep: func(ctx context.Context, _ time.Duration) error {
			time.Sleep(time.Millisecond)
			return ctx.Err()
		}}
	return fence, cell, balancer, kv, delivery.Intent{Role: "ts-auth", Generation: 7}
}

func TestReleaseFenceRestartsOneFencedNodeAtATime(t *testing.T) {
	fence, cell, balancer, kv, intent := newFenceTest(t)
	ctx := t.Context()
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	// Sequenced: no node restarts before the leader permits it.
	if granted, err := cell.gate(ctx, "gru-1-ctl-1", host.Desired{Role: "ts-auth", Generation: 7 << 24}); err != nil || granted {
		t.Fatalf("an unpermitted node may restart: %v %v", granted, err)
	}
	if err := fence.sequence(ctx, intent, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cell.restarts, []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}) {
		t.Fatalf("restarts %q", cell.restarts)
	}
	want := []string{
		"terrabase 10.0.0.11:9465 drain", "terrabase 10.0.0.11:9465 offline", "terrabase 10.0.0.11:9465 active",
		"terrabase 10.0.0.12:9465 drain", "ts-auth 10.0.0.12:8080 drain", "terrabase 10.0.0.12:9465 offline",
		"ts-auth 10.0.0.12:8080 offline", "terrabase 10.0.0.12:9465 active", "ts-auth 10.0.0.12:8080 active",
		"terrabase 10.0.0.13:9465 drain", "ts-auth 10.0.0.13:8080 drain", "terrabase 10.0.0.13:9465 offline",
		"ts-auth 10.0.0.13:8080 offline", "terrabase 10.0.0.13:9465 active", "ts-auth 10.0.0.13:8080 active",
	}
	if !slices.Equal(balancer.log, want) {
		t.Fatalf("load balancer\n%s\nwant\n%s", strings.Join(balancer.log, "\n"), strings.Join(want, "\n"))
	}
	// The out-of-rotation backend stays out; the release is open again.
	if balancer.sets["ts-auth"][0].Serving() {
		t.Fatal("the fence returned a backend it never took out")
	}
	keys, err := kv.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for key := range keys.Keys() {
		t.Errorf("left %s", key)
	}
}

// A leader that loses its lease stops changing the load balancer and
// permits no node.
func TestReleaseFenceStopsOnALostLease(t *testing.T) {
	fence, cell, balancer, _, intent := newFenceTest(t)
	ctx := t.Context()
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	// The third guard of the sequence is the one before its first load
	// balancer change: the lease, sequence and fence record pass first.
	lease := fence.fencer.(*fenceLease)
	lease.lose = lease.guards + 3
	if err := fence.sequence(ctx, intent, nil); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("sequence after the lease was lost: %v", err)
	}
	if len(balancer.log) != 0 || len(cell.restarts) != 0 {
		t.Fatalf("a deposed leader went on: load balancer %q, restarts %q", balancer.log, cell.restarts)
	}
}
