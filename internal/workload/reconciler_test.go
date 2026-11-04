package workload

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

const (
	testDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newDigest  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var (
	testNow      = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	testProfile  = placement.Resources{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 10 << 30}
	testProfiles = map[string]placement.Resources{"api": testProfile, "worker": testProfile}
)

// fakeCell emulates the host controller's per node/role generation rules.
type fakeCell struct {
	mu      sync.Mutex
	hosts   map[string]host.HostStatus
	desired map[string]host.Desired
	writes  []host.Desired
	failOn  string
}

func newFakeCell() *fakeCell {
	return &fakeCell{hosts: make(map[string]host.HostStatus), desired: make(map[string]host.Desired)}
}

func (c *fakeCell) addHost(node, domain string, live bool, mutate ...func(*host.Registration)) {
	registration := host.Registration{Cell: "gru", Node: node, FailureDomain: domain, Environment: "prod",
		Roles: []string{"api", "worker"}, Capacity: host.Capacity{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}}
	for _, change := range mutate {
		change(&registration)
	}
	expires := testNow.Add(time.Minute)
	if !live {
		expires = testNow.Add(-time.Minute)
	}
	c.hosts[node] = host.HostStatus{Registration: registration, SessionExpiresAt: expires, Verified: true}
}

func (c *fakeCell) run(node, role, state string) {
	status := c.hosts[node]
	d := c.desired[node+"/"+role]
	status.Reports = slices.DeleteFunc(status.Reports, func(r host.Report) bool { return r.Role == role })
	status.Reports = append(status.Reports, host.Report{Node: node, Role: role, Digest: d.Digest, Generation: d.Generation, State: state})
	c.hosts[node] = status
}

// runAll marks every active desired running, as a converged host would.
func (c *fakeCell) runAll() {
	for _, d := range c.desired {
		if !d.Withdrawn {
			c.run(d.Node, d.Role, "running")
		}
	}
}

func (c *fakeCell) seed(node, role, digest string, generation uint64) {
	c.desired[node+"/"+role] = host.Desired{Cell: "gru", Node: node, Environment: "prod", Role: role, Digest: digest,
		Generation: generation, AuthorityEpoch: 1, Args: []string{"--serve"}, Env: map[string]string{"A": "1"}}
}

func (c *fakeCell) ListHosts(context.Context) ([]host.HostStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []host.HostStatus
	for _, node := range sortedKeys(c.hosts) {
		result = append(result, c.hosts[node])
	}
	return result, nil
}

func (c *fakeCell) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []host.Desired
	for _, key := range sortedKeys(c.desired) {
		if role == "" || c.desired[key].Role == role {
			result = append(result, c.desired[key])
		}
	}
	return result, nil
}

func (c *fakeCell) ApplyDesired(_ context.Context, d host.Desired) (host.Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d.Node == c.failOn {
		return host.Receipt{}, errors.New("injected failure")
	}
	if current, exists := c.desired[d.Node+"/"+d.Role]; exists && d.Generation <= current.Generation {
		return host.Receipt{}, fmt.Errorf("%w: generation did not advance", host.ErrDesiredConflict)
	}
	c.desired[d.Node+"/"+d.Role] = d
	c.writes = append(c.writes, d)
	return host.Receipt{Generation: d.Generation}, nil
}

func (c *fakeCell) active(role string) []string {
	var nodes []string
	for _, d := range c.desired {
		if d.Role == role && !d.Withdrawn {
			nodes = append(nodes, d.Node)
		}
	}
	slices.Sort(nodes)
	return nodes
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

type fakeFencer struct {
	leader bool
	epoch  uint64
	fenced bool
}

func (f *fakeFencer) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: f.leader, Ready: true, Epoch: f.epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}

func (f *fakeFencer) Guard(context.Context, uint64) error {
	if f.fenced {
		return authority.ErrFenced
	}
	return nil
}

func statelessSpec(min, max int) ServiceSpec {
	return ServiceSpec{Role: "api", Environment: "prod", Kind: KindStateless, Replicas: ReplicaBounds{Min: min, Max: max}}
}

func newTestReconciler(t *testing.T, cell *fakeCell, fencer *fakeFencer, spec ServiceSpec, mutate ...func(*Config)) *Reconciler {
	t.Helper()
	config := Config{Cell: "gru", Specs: []ServiceSpec{spec}, Profiles: testProfiles, Hosts: cell, Writer: cell,
		Fencer: fencer, Now: func() time.Time { return testNow }}
	for _, change := range mutate {
		change(&config)
	}
	reconciler, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func threeHostCell() *fakeCell {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("node-b", "fd-2", true)
	cell.addHost("node-c", "fd-3", true)
	cell.addHost("node-d", "fd-1", true)
	return cell
}

func TestReconcilerReplacesReplicaOnLostHost(t *testing.T) {
	cell := threeHostCell()
	release, _ := ReleaseGeneration(3)
	for _, node := range []string{"node-a", "node-b", "node-c"} {
		cell.seed(node, "api", testDigest, release)
	}
	cell.runAll()
	cell.addHost("node-b", "fd-2", false) // session expired: host lost
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 7}, statelessSpec(1, 5))

	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); !slices.Equal(got, []string{"node-a", "node-c", "node-d"}) {
		t.Fatalf("active = %v", got)
	}
	for _, write := range cell.writes {
		if write.Generation != release+1 || write.AuthorityEpoch != 7 {
			t.Fatalf("write generation/epoch = %d/%d", write.Generation, write.AuthorityEpoch)
		}
		if write.Node == "node-d" && (write.Digest != testDigest || !slices.Equal(write.Args, []string{"--serve"}) || write.Env["A"] != "1") {
			t.Fatalf("replacement does not copy the release template: %#v", write)
		}
		if write.Node == "node-b" && !write.Withdrawn {
			t.Fatalf("lost replica not withdrawn: %#v", write)
		}
	}
	// Level-triggered: a second tick with the replacement still starting
	// must not write again.
	cell.writes = nil
	if err := reconciler.Tick(context.Background()); err != nil || len(cell.writes) != 0 {
		t.Fatalf("second tick wrote %v (%v)", cell.writes, err)
	}
}

func TestReconcilerFollowerAndFencedLeaderDoNotWrite(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	follower := newTestReconciler(t, cell, &fakeFencer{leader: false, epoch: 1}, statelessSpec(3, 5))
	if err := follower.Tick(context.Background()); err != nil || len(cell.writes) != 0 {
		t.Fatalf("follower wrote %v (%v)", cell.writes, err)
	}
	if follower.Leading() || len(follower.Last()) != 0 {
		t.Fatalf("follower leading=%v last=%#v", follower.Leading(), follower.Last())
	}
	// A demoted leader stops presenting its last results as current.
	fencer := &fakeFencer{leader: true, epoch: 1}
	demoted := newTestReconciler(t, cell, fencer, statelessSpec(1, 5))
	if err := demoted.Tick(context.Background()); err != nil || !demoted.Leading() || len(demoted.Last()) != 1 {
		t.Fatalf("leader tick: last=%#v (%v)", demoted.Last(), err)
	}
	// A re-acquired lease of a new term is not "leading" until the
	// reconciler has adopted the term.
	fencer.epoch = 2
	if demoted.Leading() {
		t.Fatal("leading with the previous term's results")
	}
	if err := demoted.Tick(context.Background()); err != nil || !demoted.Leading() {
		t.Fatalf("new term tick: leading=%v (%v)", demoted.Leading(), err)
	}
	fencer.leader = false
	if err := demoted.Tick(context.Background()); err != nil || demoted.Leading() || len(demoted.Last()) != 0 {
		t.Fatalf("demoted leader kept results: %#v (%v)", demoted.Last(), err)
	}
	fenced := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1, fenced: true}, statelessSpec(3, 5))
	if err := fenced.Tick(context.Background()); !errors.Is(err, authority.ErrFenced) || len(cell.writes) != 0 {
		t.Fatalf("fenced leader wrote %v (%v)", cell.writes, err)
	}
}

func TestReconcilerAutoscalesFromSignals(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.seed("node-b", "api", testDigest, 4)
	cell.runAll()
	spec := statelessSpec(1, 4)
	spec.Scaling = &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}},
		Tolerance: 0.1}
	spec.Rollout.MaxSurge = 4
	store := autoscale.NewWindowStore(time.Hour, 100)
	target := autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}
	store.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: testNow, Value: 0.9})
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, spec, func(c *Config) { c.Signals = store })
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) != 4 {
		t.Fatalf("active = %v, last = %#v", got, reconciler.Last()["api"])
	}
	last := reconciler.Last()["api"]
	if last.Decision == nil || last.Decision.Reason != autoscale.ReasonScaleUp || last.Target != 4 {
		t.Fatalf("decision = %#v", last)
	}
	if len(last.Readings) != 1 || last.Readings[0].Signal != autoscale.SignalCPUUtilization ||
		last.Readings[0].Value != 0.9 || last.Readings[0].Samples != 1 {
		t.Fatalf("readings behind the decision = %#v", last.Readings)
	}
	// Not converged: the decision core is not consulted while replicas start.
	if err := reconciler.Tick(context.Background()); err != nil || reconciler.Last()["api"].Decision != nil {
		t.Fatalf("autoscaled while unconverged: %#v (%v)", reconciler.Last()["api"], err)
	}
}

func TestReconcilerRetiresStaleReleaseAfterNewReleaseIsReady(t *testing.T) {
	cell := threeHostCell()
	oldRelease, _ := ReleaseGeneration(2)
	newRelease, _ := ReleaseGeneration(3)
	cell.seed("node-a", "api", testDigest, oldRelease)
	cell.seed("node-b", "api", newDigest, newRelease)
	cell.seed("node-c", "api", newDigest, newRelease)
	cell.run("node-a", "api", "running")
	cell.run("node-b", "api", "running")
	cell.run("node-c", "api", "starting")
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(2, 2))
	if err := reconciler.Tick(context.Background()); err != nil || len(cell.writes) != 0 {
		t.Fatalf("stale replica withdrawn before the new release is ready: %v (%v)", cell.writes, err)
	}
	cell.run("node-c", "api", "running")
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); !slices.Equal(got, []string{"node-b", "node-c"}) ||
		cell.writes[0].Generation != newRelease+1 {
		t.Fatalf("active = %v writes = %v", got, cell.writes)
	}
}

// countingHosts counts how often the reconciler lists host state.
type countingHosts struct {
	*fakeCell
	listed atomic.Int32
}

func (c *countingHosts) ListHosts(ctx context.Context) ([]host.HostStatus, error) {
	c.listed.Add(1)
	return c.fakeCell.ListHosts(ctx)
}
