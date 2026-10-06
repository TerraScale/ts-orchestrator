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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func fenceKV(t *testing.T) jetstream.KeyValue {
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
	return kv
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
func (f *fenceLB) CreateBackend(context.Context, string, string, lb.Backend) (string, error) {
	return "", errors.New("unused")
}
func (f *fenceLB) DeleteBackend(context.Context, string, string, string) (string, error) {
	return "", errors.New("unused")
}
func (f *fenceLB) UpdateTags(context.Context, string, string, ociresource.Tags) (string, error) {
	return "", errors.New("unused")
}

// fenceCell has one desired replica of role per node at release. A node
// restarts into it as soon as the restart gate grants it; until then it
// serves the previous release. Nodes in broken fail the release.
type fenceCell struct {
	t       *testing.T
	gate    func(context.Context, string, host.Desired) (bool, error)
	lb      *fenceLB
	nodes   []string
	release uint64
	broken  map[string]bool
	// unfenced lets nodes restart while their backends serve: the cell's
	// fence moved or was dropped.
	unfenced bool
	mu       sync.Mutex
	restarts []string
}

func (c *fenceCell) ListDesired(context.Context, string) ([]host.Desired, error) {
	var desired []host.Desired
	for _, node := range c.nodes {
		desired = append(desired, host.Desired{Node: node, Role: "ts-auth", Generation: c.release << 24})
	}
	return desired, nil
}

func (c *fenceCell) ListHosts(ctx context.Context) ([]host.HostStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var statuses []host.HostStatus
	for _, node := range c.nodes {
		desired := host.Desired{Node: node, Role: "ts-auth", Generation: c.release << 24}
		granted, err := c.gate(ctx, node, desired)
		if err != nil {
			return nil, err
		}
		report := host.Report{Node: node, Role: "ts-auth", Generation: (c.release - 1) << 24, State: "running",
			ObservedAt: time.Now()}
		if granted {
			if !slices.Contains(c.restarts, node) {
				c.restarts = append(c.restarts, node)
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
			report.Generation, report.State = desired.Generation, "running"
			if c.broken[node] {
				report.State = "failed"
			}
		}
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
}

func (l *fenceLease) Current() authority.Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	return authority.Snapshot{Ready: true, Leader: !l.lost, Epoch: 3, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
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

var fenceAddresses = map[string]string{"ctl-1": "10.0.0.11", "ctl-2": "10.0.0.12", "ctl-3": "10.0.0.13"}

func newFenceTest(t *testing.T) (*releaseFence, *fenceCell, *fenceLB, jetstream.KeyValue, delivery.Intent) {
	t.Helper()
	kv := fenceKV(t)
	balancer := &fenceLB{t: t, down: map[string]bool{}, sets: map[string][]lb.Backend{}}
	for _, node := range []string{"ctl-1", "ctl-2", "ctl-3"} {
		balancer.sets["terrabase"] = append(balancer.sets["terrabase"], lb.Backend{IP: fenceAddresses[node], Port: 9465})
		// ctl-1's ts-auth backend is out of rotation already.
		balancer.sets["ts-auth"] = append(balancer.sets["ts-auth"],
			lb.Backend{IP: fenceAddresses[node], Port: 8080}.Fenced(node == "ctl-1", node == "ctl-1"))
	}
	spec := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x",
		BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465}, {Name: "ts-auth", Port: 8080}}}
	cell := &fenceCell{t: t, gate: releaseGate(kv), lb: balancer, nodes: []string{"ctl-1", "ctl-2", "ctl-3"}, release: 7,
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
	if granted, err := cell.gate(ctx, "ctl-1", host.Desired{Role: "ts-auth", Generation: 7 << 24}); err != nil || granted {
		t.Fatalf("an unpermitted node may restart: %v %v", granted, err)
	}
	if err := fence.sequence(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cell.restarts, []string{"ctl-1", "ctl-2", "ctl-3"}) {
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

func TestReleaseFenceKeepsTheLastHealthyBackend(t *testing.T) {
	fence, _, balancer, _, intent := newFenceTest(t)
	balancer.down["10.0.0.12:9465"], balancer.down["10.0.0.13:9465"] = true, true
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := fence.sequence(ctx, intent); err == nil || !strings.Contains(err.Error(), "last healthy") {
		t.Fatalf("fenced the last healthy backend: %v", err)
	}
	if len(balancer.log) != 0 {
		t.Fatalf("changed the load balancer: %q", balancer.log)
	}
}

func TestReleaseFenceLeavesAFailedNodeFencedAndANewLeaderReturnsIt(t *testing.T) {
	fence, cell, balancer, kv, intent := newFenceTest(t)
	ctx := t.Context()
	cell.broken["ctl-1"] = true
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := fence.sequence(ctx, intent); err == nil || !strings.Contains(err.Error(), "stay fenced") {
		t.Fatalf("a failed node: %v", err)
	}
	if balancer.sets["terrabase"][0].Serving() || !slices.Equal(cell.restarts, []string{"ctl-1"}) {
		t.Fatalf("after the failure: %+v, restarts %q", balancer.sets["terrabase"][0], cell.restarts)
	}
	if _, err := kv.Get(ctx, fencedKey("ctl-1")); err != nil {
		t.Fatalf("the fence of ctl-1 is not recorded: %v", err)
	}
	// The node serves after all (a rollback, say): the next sequence of the
	// release, here by a new leader, returns its backends and goes on.
	cell.broken["ctl-1"] = false
	if err := fence.sequence(ctx, intent); err != nil {
		t.Fatal(err)
	}
	for _, backend := range balancer.sets["terrabase"] {
		if !backend.Serving() {
			t.Errorf("%s stays out of rotation", backend.Name())
		}
	}
}

func TestReleaseFenceWithoutASpecRestartsEveryNode(t *testing.T) {
	fence, cell, balancer, _, intent := newFenceTest(t)
	fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return nil, nil }
	ctx := t.Context()
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if granted, err := cell.gate(ctx, "ctl-2", host.Desired{Role: "ts-auth", Generation: 7 << 24}); err != nil || !granted {
		t.Fatalf("an unsequenced release is held: %v %v", granted, err)
	}
	if err := fence.sequence(ctx, intent); err != nil || len(balancer.log) != 0 {
		t.Fatalf("sequence %v, load balancer %q", err, balancer.log)
	}
}

// A fence a deposed leader left part-way is finished before the node may
// restart.
func TestReleaseFenceFinishesAPartWayFence(t *testing.T) {
	fence, cell, balancer, kv, intent := newFenceTest(t)
	ctx := t.Context()
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	// Recorded, but the load balancer never changed.
	if _, err := kv.Put(ctx, fencedKey("ctl-1"), []byte(`{"load_balancer_id":"ocid1.loadbalancer.oc1..x","phase":"fencing",`+
		`"backends":[{"set":"terrabase","ip":"10.0.0.11","port":9465}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := fence.sequence(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cell.restarts, []string{"ctl-1", "ctl-2", "ctl-3"}) || balancer.log[0] != "terrabase 10.0.0.11:9465 drain" ||
		balancer.log[1] != "terrabase 10.0.0.11:9465 offline" {
		t.Fatalf("restarts %q, load balancer %q", cell.restarts, balancer.log)
	}
}

// A failed node's backends return to the load balancer they were taken
// from, even after the spec moved to another one or dropped its fence.
func TestReleaseFenceRestoresTheRecordedLoadBalancer(t *testing.T) {
	for _, drop := range []bool{false, true} {
		fence, cell, balancer, _, intent := newFenceTest(t)
		ctx := t.Context()
		cell.broken["ctl-1"] = true
		if err := fence.prepare(ctx, intent); err != nil {
			t.Fatal(err)
		}
		if err := fence.sequence(ctx, intent); err == nil {
			t.Fatal("a failed node passed")
		}
		cell.broken["ctl-1"], cell.unfenced = false, true
		moved := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..moved",
			BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465}}}
		if drop {
			moved = nil
		}
		fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return moved, fenceAddresses }
		balancer.ids = nil
		if err := fence.sequence(ctx, intent); err != nil {
			t.Fatal(err)
		}
		if !balancer.sets["terrabase"][0].Serving() || len(balancer.ids) == 0 || balancer.ids[0] != "ocid1.loadbalancer.oc1..x" {
			t.Fatalf("drop %v: ctl-1 %+v, updates on %q", drop, balancer.sets["terrabase"][0], balancer.ids)
		}
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
	if err := fence.sequence(ctx, intent); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("sequence after the lease was lost: %v", err)
	}
	if len(balancer.log) != 0 || len(cell.restarts) != 0 {
		t.Fatalf("a deposed leader went on: load balancer %q, restarts %q", balancer.log, cell.restarts)
	}
}

// After a release failed on one node, its rollback returns that node first:
// fencing a serving node before would wait on a set whose other backend
// serves again only later in the same turn.
func TestReleaseFenceRollsBackTheFencedNodeFirst(t *testing.T) {
	fence, cell, balancer, _, intent := newFenceTest(t)
	ctx := t.Context()
	cell.nodes = []string{"ctl-1", "ctl-2"}
	balancer.sets = map[string][]lb.Backend{"terrabase": {{IP: "10.0.0.11", Port: 9465}, {IP: "10.0.0.12", Port: 9465}}}
	cell.broken["ctl-2"] = true
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := fence.sequence(ctx, intent); err == nil {
		t.Fatal("a failed node passed")
	}
	// The rollback, a newer release that ctl-2 serves.
	cell.broken["ctl-2"], cell.release, cell.restarts = false, 8, nil
	rollback := delivery.Intent{Role: "ts-auth", Generation: 8}
	if err := fence.prepare(ctx, rollback); err != nil {
		t.Fatal(err)
	}
	limited, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := fence.sequence(limited, rollback); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !slices.Equal(cell.restarts, []string{"ctl-2", "ctl-1"}) {
		t.Fatalf("rollback restarts %q", cell.restarts)
	}
	for _, backend := range balancer.sets["terrabase"] {
		if !backend.Serving() {
			t.Errorf("%s stays out of rotation", backend.Name())
		}
	}
}

// A release fence may not name the backend set the public_lb reconciler
// owns, which would return a fenced backend to rotation.
func TestReleaseFenceRefusesThePublicLBSet(t *testing.T) {
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true},
		Controller: ControllerConfig{OciReconcile: &OciReconcileConfig{Enabled: true,
			PublicLB: &OciReconcileLBConfig{LoadBalancerID: "ocid1.loadbalancer.oc1..x", BackendSet: "terrabase"}}}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	spec := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 12,
		ReleaseFence: &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x",
			BackendSets: []cellspec.FencedSet{{Name: "terrabase", Port: 9465}, {Name: "ts-auth", Port: 8080}}}}
	if err := registry.validate(spec); err == nil || !strings.Contains(err.Error(), "oci_reconcile.public_lb owns") {
		t.Fatalf("a fence over the reconciled set: %v", err)
	}
	spec.ReleaseFence.BackendSets = spec.ReleaseFence.BackendSets[1:]
	if err := registry.validate(spec); err != nil {
		t.Fatalf("a fence beside the reconciled set: %v", err)
	}
}

// A backend of the same node on another port is no alternative, a part-way
// fence resumes only beside a healthy alternative, and a node without an
// address is never restarted unfenced.
func TestReleaseFenceNeedsAnotherHealthyNode(t *testing.T) {
	for name, setup := range map[string]func(*releaseFence, *fenceLB, jetstream.KeyValue){
		"same node, other port": func(_ *releaseFence, balancer *fenceLB, _ jetstream.KeyValue) {
			balancer.sets = map[string][]lb.Backend{"terrabase": {{IP: "10.0.0.11", Port: 9465}, {IP: "10.0.0.11", Port: 9466},
				{IP: "10.0.0.12", Port: 9465}}}
			balancer.down["10.0.0.12:9465"] = true
		},
		"part-way fence": func(_ *releaseFence, balancer *fenceLB, kv jetstream.KeyValue) {
			balancer.down["10.0.0.12:9465"], balancer.down["10.0.0.13:9465"] = true, true
			if _, err := kv.Put(t.Context(), fencedKey("ctl-1"), []byte(`{"load_balancer_id":"ocid1.loadbalancer.oc1..x",`+
				`"phase":"fencing","backends":[{"set":"terrabase","ip":"10.0.0.11","port":9465}]}`)); err != nil {
				t.Fatal(err)
			}
		},
		"no address": func(fence *releaseFence, _ *fenceLB, _ jetstream.KeyValue) {
			spec, _ := fence.spec()
			fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, map[string]string{} }
		},
	} {
		fence, cell, balancer, kv, intent := newFenceTest(t)
		setup(fence, balancer, kv)
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		if err := fence.prepare(ctx, intent); err != nil {
			t.Fatal(err)
		}
		if err := fence.sequence(ctx, intent); err == nil {
			t.Errorf("%s: the release went on", name)
		}
		cancel()
		if len(balancer.log) != 0 || len(cell.restarts) != 0 {
			t.Errorf("%s: load balancer %q, restarts %q", name, balancer.log, cell.restarts)
		}
	}
}

// The alternative is checked right before each change: here the terrabase
// alternative fails while the fence waits for the ts-auth one, so ctl-1's
// terrabase backend, drained while ctl-2 still served, is not set offline.
func TestReleaseFenceChecksTheAlternativeAtEachChange(t *testing.T) {
	fence, cell, balancer, _, intent := newFenceTest(t)
	cell.nodes = []string{"ctl-1", "ctl-2"}
	balancer.sets = map[string][]lb.Backend{
		"terrabase": {{IP: "10.0.0.11", Port: 9465}, {IP: "10.0.0.12", Port: 9465}},
		"ts-auth":   {{IP: "10.0.0.11", Port: 8080}, {IP: "10.0.0.12", Port: 8080}},
	}
	balancer.down["10.0.0.12:8080"] = true
	flipped := false
	fence.sleep = func(ctx context.Context, _ time.Duration) error {
		balancer.mu.Lock()
		if !flipped {
			flipped = true
			balancer.down["10.0.0.12:8080"], balancer.down["10.0.0.12:9465"] = false, true
		}
		balancer.mu.Unlock()
		time.Sleep(time.Millisecond)
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := fence.sequence(ctx, intent); err == nil || !strings.Contains(err.Error(), "last healthy") {
		t.Fatalf("sequence: %v", err)
	}
	if slices.Contains(balancer.log, "terrabase 10.0.0.11:9465 offline") || len(cell.restarts) != 0 {
		t.Fatalf("load balancer %q, restarts %q", balancer.log, cell.restarts)
	}
}

// A resumed fence whose backend a deposed leader already drained still
// waits for a healthy alternative before it sets it offline.
func TestReleaseFenceResumesADrainedBackendOnlyBesideAnAlternative(t *testing.T) {
	fence, cell, balancer, kv, intent := newFenceTest(t)
	balancer.sets["terrabase"][0] = balancer.sets["terrabase"][0].Fenced(true, false)
	balancer.down["10.0.0.12:9465"], balancer.down["10.0.0.13:9465"] = true, true
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if _, err := kv.Put(ctx, fencedKey("ctl-1"), []byte(`{"load_balancer_id":"ocid1.loadbalancer.oc1..x","phase":"fencing",`+
		`"backends":[{"set":"terrabase","ip":"10.0.0.11","port":9465}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := fence.sequence(ctx, intent); err == nil {
		t.Fatal("the resumed fence went on")
	}
	if len(balancer.log) != 0 || len(cell.restarts) != 0 {
		t.Fatalf("load balancer %q, restarts %q", balancer.log, cell.restarts)
	}
}

// With TerraBase seats the seat controller orders TerraBase restarts, so
// the fence leaves TerraBase releases unmarked and marks the others.
func TestReleaseFenceLeavesTerraBaseToSeats(t *testing.T) {
	fence, _, _, kv, _ := newFenceTest(t)
	fence.seats = true
	ctx := t.Context()
	for _, intent := range []delivery.Intent{{Role: "terrabase", Generation: 4}, {Role: "ts-auth", Generation: 5}} {
		if err := fence.prepare(ctx, intent); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := kv.Get(ctx, sequencedKey("terrabase", 4)); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("a TerraBase release is marked under seats: %v", err)
	}
	if _, err := kv.Get(ctx, sequencedKey("ts-auth", 5)); err != nil {
		t.Fatalf("a ts-auth release is not marked: %v", err)
	}
}
